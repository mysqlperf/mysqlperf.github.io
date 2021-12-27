---
title: "Spinning in the Cloud: How to Fix MySQL 8.0 Log Commit for Containers"
author: Sergey Glushchenko
categories: MySQL
tags:
  - cloud
  - redo log writer
  - adaptive spinning
  - MySQL 8.0
classes: wide
header:
  overlay_image: /assets/images/spinning-wheel.jpeg
  teaser: /assets/images/spinning-wheel.jpeg
  og_image: /assets/images/spinning-wheel.jpeg
---

If you are running MySQL as a Kubernetes pod or a Docker container, there is a
chance you are using CPU quota to limit its resource usage. Which is also typical for cloud environments. But do you know what
kind of issues you may see when running MySQL in environments like that?

# Experiment

I'll start MySQL as follows:

```shell
BASEDIR=/home/sergei/git/msql/bld/install/usr/local/mysql

systemd-run --scope -p CPUQuota=100% -p AllowedCPUs=0,1,2,3,4,5 \
            ${BASEDIR}/bin/mysqld --basedir=${BASEDIR} \
            --datadir=/dev/shm/data \
            --innodb-buffer-pool-size=8G -uroot
```

Here `CPUQuota=100%` and `AllowedCPUs=0,1,2,3,4,5` mean that MySQL is allowed to
run on 6 CPUs, but its CPU utilization will be capped at 100% (or 1 vCPU) by the CFS
bandwith control mechanism.

Then I'll start `sysbench` `OLTP_UPDATE_INDEX` as follows:

```shell
./src/sysbench ./src/lua/oltp_update_index.lua \
               --mysql-socket=/tmp/mysql.sock --mysql-user=root \
               --tables=10 --table-size=1000000 --threads=64 \
               --report-interval=1 --db-ps-mode=disable --time=60 run
```

The TPS I get is around 3,500:

```
SQL statistics:
    queries performed:
        read:                            0
        write:                           207800
        other:                           0
        total:                           207800
    transactions:                        207800 (3462.61 per sec.)
    queries:                             207800 (3462.61 per sec.)
    ignored errors:                      0      (0.00 per sec.)
    reconnects:                          0      (0.00 per sec.)

Throughput:
    events/s (eps):                      3462.6082
    time elapsed:                        60.0126s
    total number of events:              207800

Latency (ms):
         min:                                    0.12
         avg:                                   18.48
         max:                                  286.17
         95th percentile:                       82.96
         sum:                              3840431.03

Threads fairness:
    events (avg/stddev):           3246.8750/45.59
    execution time (avg/stddev):   60.0067/0.00
```

I am not quite happy with the performance numbers I get, time for some
profiling. Below is the most interesting part of the perf output:

```cpp
-   21.20%  connection       mysqld               [.] log_write_up_to
     log_write_up_to
     innobase_flush_logs
     plugin_foreach_with_mask
     plugin_foreach_with_mask
     ha_flush_logs
     MYSQL_BIN_LOG::fetch_and_process_flush_stage_queue
     MYSQL_BIN_LOG::process_flush_stage_queue
     MYSQL_BIN_LOG::ordered_commit
     MYSQL_BIN_LOG::commit
     ha_commit_trans
     trans_commit_stmt
     mysql_execute_command
     dispatch_sql_command
     dispatch_command
     do_command
     handle_connection
     pfs_spawn_thread
     start_thread
```

# Problem

We see that 21% of CPU time is spent in the `log_write_up_to` function which is called on
commit. We can actually annotate this function to see what exactly this time is
spent on:

```cpp
Percent│
       │     if (condition(wait)) {
       │       return (Wait_stats{waits});
       │     }
       │
       │     if (!wait) {
  0.46 │352:   test      %r13,%r13
       │     ↓ je        518
       │     /* It's still spin-delay loop. */
       │     --spins_limit;
       │       sub       $0x1,%r13
       │
       │     UT_RELAX_CPU();
 96.30 │       pause
       │     const int64_t sig_count = !wait ? 0 : os_event_reset(event);
  0.36 │361:   movq      $0x0,-0x98(%rbp)
       │       test      %r13,%r13
       │     ↓ je        582
       │     std::__uniq_ptr_impl<Log_test, std::default_delete<Log_test> >::_M_ptr() const:
       │375:   lea       log_test,%rax
  0.34 │       mov       (%rax),%r8
       │     operator()():
       │     LOG_SYNC_POINT("log_wait_for_flush_before_flushed_to_disk_lsn");
       │       test      %r8,%r8
       │       mov       %r8,-0x90(%rbp)
       │     ↓ je        423
```

The answer is simple - MySQL is spinning 21% of its CPU time.

Let me give you some background. MySQL 8.0 comes with a redesigned redo logging
subsystem. There is now a dedicated redo log writer thread which writes data from
the redo log buffer to disk and a dedicated redo log flusher thread which calls
`fsync()` on the log files.

A client thread committing a transaction now simply writes to the redo log
buffer, updates the lock-free `log.recent_written` `Link_buf` structure with the
`LSN` it has written up to, and the waits for `log.flushed_to_disk_lsn` (or
`log.write_lsn` depending on the `innodb_log_flush_at_trx_commit` setting) to bypass
the written `LSN`.

How is that waiting implemented? There are two arrays of conditional variables,
2048 elements each (there's actually a setting which is hidden under the
`ENABLE_EXPERIMENT_SYSVARS` compiler define, one could enable it, rebuild and
play with that setting) - `log.write_events` and `log.flush_events`. There are
also two notifier threads: `log_write_notifier` and `log_flush_notifier` which
fire up corresponding conditional variables when redo log block gets written or
flushed.

This scheme works fine, but there are some issues with it. Lets consider we have
a single client thread which committed a short transaction. It now has to wait
on a conditional variable to be signaled by `log_flush_notifier` which is costly
in terms of latency. It is much better to spin-wait for `log.flush_lsn` for a while
and, in case the redo log gets flushed soon, return to the client without waiting on
the conditional variable. It will save us some latency on syscalls and context switching.

The question is - for how long can we spin and when should we fall back to waiting?
The answer by the MySQL server team is - adaptive spinning. The client
thread will spin, if there are spare CPU cycles, and wait if the CPU is hogged. There are two variables to control spinning:

- `innodb_log_spin_cpu_abs_lwm` which defines the minimum amount of CPU usage
  below which threads no longer spin (default is 80%, here we look at the CPU
  utilization as reported by `top`)
  
- `innodb_log_spin_cpu_pct_hwm` which defines the maximum amount of CPU usage
  above which user threads no longer spin (default is 50%, here we take the CPU
  utilization as reported by `top` and divide it by the number of available
  CPUs)
  
OK, lets have a look at the `top` output. CPU utilization by `mysqld` is
reported between **96%** and **102%**, we maxed out our CPU quota, so there should be no
spinning!

It's time for `gdb`. CPU usage statistics are accumulated in the global variable
called `srv_cpu_usage`:

```cpp
(gdb) p srv_cpu_usage 
$1 = {n_cpu = 6, utime_abs = 83.261736069525156, stime_abs = 15.321047995993085, utime_pct = 13.876956011587525, 
  stime_pct = 2.5535079993321808}
(gdb) 
```

Lets interpet these numbers:

- mysqld sees 6 CPUs which is how many we have specified with
  `AllowedCPUs=0,1,2,3,4,5`
  
- `utime_abs + stime_abs` (sum of the user and system CPU time) is **98.5%** which
  is in line with what `top` reports

- `utime_pct + stime_pct` is **16.4%** which is simply `98.5/6`

But the `pct` values are off. MySQL considers all 6 cores at its
disposal and since they appear to be underutilized (16% is way below the 50% high water mark) it can spin
to improve latency. MySQL simply doesn't know anything about the CFS Quota I specified for it.

# Workaround

Lets verify our assumption. Here is the corresponding code in
`srv_update_cpu_usage()`:

```cpp
  cpu_set_t cs;
  CPU_ZERO(&cs);
  if (sched_getaffinity(0, sizeof(cs), &cs) != 0) {
    return;
  }

  int n_cpu = 0;
  constexpr int MAX_CPU_N = 128;
  for (int i = 0; i < MAX_CPU_N; ++i) {
    if (CPU_ISSET(i, &cs)) {
      ++n_cpu;
    }
  }
```

It simply obtains the affinity of the `mysqld` process and counts the number of CPUs in the
`cpuset`. Lets hard code `n_cpu = 1` and repeat our `sysbench` test:

```
SQL statistics:
    queries performed:
        read:                            0
        write:                           280852
        other:                           0
        total:                           280852
    transactions:                        280852 (4677.44 per sec.)
    queries:                             280852 (4677.44 per sec.)
    ignored errors:                      0      (0.00 per sec.)
    reconnects:                          0      (0.00 per sec.)

Throughput:
    events/s (eps):                      4677.4425
    time elapsed:                        60.0439s
    total number of events:              280852

Latency (ms):
         min:                                    0.11
         avg:                                   13.68
         max:                                  193.05
         95th percentile:                       86.00
         sum:                              3842379.62

Threads fairness:
    events (avg/stddev):           4388.3125/63.74
    execution time (avg/stddev):   60.0372/0.00
```

Looks much better, and the spinning has gone:

```cpp
+    2.85%  connection       libpthread-2.33.so   [.] __pthread_mutex_cond_lock
+    2.47%  connection       mysqld-1cpu          [.] ut_delay
+    1.40%  connection       mysqld-1cpu          [.] MYSQLparse
+    1.13%  connection       [kernel.kallsyms]    [k] syscall_exit_to_user_mode
+    0.95%  connection       libc-2.33.so         [.] __memmove_avx_unaligned_erms
+    0.89%  connection       libc-2.33.so         [.] malloc
+    0.87%  connection       mysqld-1cpu          [.] rec_get_offsets_func
+    0.75%  connection       mysqld-1cpu          [.] rec_init_offsets
+    0.73%  connection       mysqld-1cpu          [.] mutex_enter_inline<PolicyMutex<TTASEventMutex<GenericPolicy> > >
+    0.69%  connection       mysqld-1cpu          [.] page_cur_insert_rec_write_log
+    0.65%  connection       mysqld-1cpu          [.] ha_insert_for_fold_func
+    0.62%  connection       [kernel.kallsyms]    [k] psi_group_change
+    0.55%  connection       libpthread-2.33.so   [.] __pthread_mutex_lock
+    0.50%  connection       mysqld-1cpu          [.] buf_page_hash_get_low
```

We can get a similar effect by setting `innodb_log_spin_cpu_pct_hwm=8` (which is 50 / 6).

# Conclusion

Adaptiveness is the future of databases, and we will see lot more of it
coming. As well as more and more MySQL instances will be running in
various cloud environments.

**Adaptive MySQL code should consider taking into account cloud
environments, including the ones that use CFS bandwidth control
mechanisms.** 
{: .notice--info}

Even though the current implementation of adaptive spinning in the redo
log writer in MySQL 8.0 is not container/quota/cloud aware, a simple
workaround can be used by tuning the `innodb_log_spin_cpu_pct_hwm`
system variable.
