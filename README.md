
# Multi-Container Runtime

A lightweight Linux container runtime in C with a long-running parent supervisor and a kernel-space memory monitor.

---

## 1. Team Information

| Name | SRN |
|------|-----|
| Ankita Pramod| PES1UG24CS065 |
| Ankitha Lakshmmi Mohan | PES1UG24CS067 |

---

## 2. Build, Load, and Run Instructions

### Prerequisites

Ubuntu 22.04 or 24.04 VM with Secure Boot OFF. No WSL.

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r)
```

### Build

```bash
cd ~/OS-Jackfruit/boilerplate
make
```

This produces:
- `engine` — user-space supervisor + CLI binary
- `monitor.ko` — kernel module
- `memory_hog`, `cpu_hog`, `io_pulse` — workload binaries

### Prepare Root Filesystem

```bash
cd ~/OS-Jackfruit/boilerplate
mkdir rootfs-base
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.20.3-x86_64.tar.gz -C rootfs-base

cp -a ./rootfs-base ./rootfs-alpha
cp -a ./rootfs-base ./rootfs-beta

# Copy workload binaries into container rootfs
cp memory_hog cpu_hog io_pulse ./rootfs-alpha/
cp memory_hog cpu_hog io_pulse ./rootfs-beta/
```

### Load Kernel Module

```bash
sudo insmod monitor.ko
ls -l /dev/container_monitor   # verify device exists
sudo dmesg | tail -3           # verify "Module loaded"
```

### Start Supervisor (Terminal 1 — keep open)

```bash
sudo ./engine supervisor ./rootfs-base
```

### Launch Containers (Terminal 2)

```bash
# Start a container in background
sudo ./engine start alpha ./rootfs-alpha /cpu_hog --soft-mib 40 --hard-mib 64

# Start a container and wait for it to finish
sudo ./engine run beta ./rootfs-beta "/cpu_hog 10" --nice 5

# List all containers and their state
sudo ./engine ps

# View container log output
sudo ./engine logs alpha

# Stop a container
sudo ./engine stop alpha
```

### Memory Limit Test

```bash
# Start memory hog with tight limits — will be killed by kernel module
sudo ./engine start alpha ./rootfs-alpha /memory_hog --soft-mib 10 --hard-mib 20

# Watch kernel events in Terminal 3
sudo dmesg -w | grep container_monitor

# Check kill reason in metadata
sudo ./engine ps
```

### Unload Module and Clean Up

```bash
# Stop supervisor with Ctrl+C in Terminal 1, then:
sudo rmmod monitor
sudo dmesg | tail -5   # verify "Module unloaded"
```

---

## 3. Demo Screenshots

### Screenshot 1 — Multi-container supervision
Two containers (`alpha` and `beta`) running concurrently under one supervisor process. Terminal 1 shows the supervisor printing `started 'alpha'` and `started 'beta'` with distinct host PIDs.

### Screenshot 2 — Metadata tracking (`engine ps`)
```
ID               PID      STATE        SOFT(MiB)  HARD(MiB)  REASON
alpha            12373    running      10         20         unknown
beta             12380    running      40         64         unknown
```
`engine ps` queries the supervisor over the UNIX socket and prints live metadata for every tracked container.

### Screenshot 3 — Bounded-buffer logging
```
$ sudo ./engine logs alpha
allocation=1 chunk=8MB total=8MB
allocation=2 chunk=8MB total=16MB
...
```
Container stdout is captured through the pipe → producer thread → bounded buffer → consumer thread → log file pipeline. The log file is written entirely by the consumer thread, never directly by the container.

### Screenshot 4 — CLI and IPC
```
$ sudo ./engine start alpha ./rootfs-alpha /memory_hog --soft-mib 10 --hard-mib 20
started 'alpha'
```
The CLI client connects to `/tmp/mini_runtime.sock`, sends a binary `control_request_t`, and receives a `control_response_t` back from the supervisor. This is a separate IPC path from the logging pipes.

### Screenshot 5 — Soft-limit warning
```
[container_monitor] SOFT LIMIT container=alpha pid=12717 rss=17432576 limit=10485760
```
The kernel module's timer fires every second, checks RSS via `get_mm_rss()`, and emits this warning the first time RSS exceeds the soft limit. The `soft_warned` flag prevents repeated warnings.

### Screenshot 6 — Hard-limit enforcement
```
[container_monitor] HARD LIMIT container=alpha pid=12717 rss=25821184 limit=20971520 — sent SIGKILL
```
```
$ sudo ./engine ps
alpha  12717  killed  10  20  hard_limit_killed
```
The kernel module sent SIGKILL. The supervisor's `SIGCHLD` handler detected the kill signal with `stop_requested=0` and recorded `EXIT_REASON_HARD_LIMIT_KILLED` in metadata.

### Screenshot 7 — Scheduling experiment
```
# Experiment 1: Two CPU-bound containers at different nice values (concurrent)
alpha  nice=0   real 20.329s
beta   nice=10  real 33.307s

# Experiment 2: CPU-bound vs I/O-bound at same priority (concurrent)
alpha  cpu_hog   nice=0  real 20.047s
beta   io_pulse  nice=0  real 23.267s
```

### Screenshot 8 — Clean teardown
```
$ ps aux | grep engine
ankita  12963  grep --color=auto engine    # only grep, no engine process

$ ls /tmp/mini_runtime.sock
No such file or directory                  # socket cleaned up

[container_monitor] Module unloaded.       # kernel list fully freed
```

---

## 4. Engineering Analysis

### 4.1 Isolation Mechanisms

Each container is created with `clone()` using three namespace flags:

- `CLONE_NEWPID` — the container gets its own PID namespace. Its init process sees itself as PID 1. The host kernel still tracks it by a host PID, which is what the supervisor and kernel module use.
- `CLONE_NEWUTS` — the container gets its own hostname. We call `sethostname(container_id)` so each container has a distinct identity.
- `CLONE_NEWNS` — the container gets its own mount namespace. We then `chroot()` into the container's dedicated rootfs directory, making it impossible for the container to see the host filesystem. Inside the container, we mount a fresh `/proc` so tools like `ps` work correctly within the container's PID namespace.

`chroot` is simpler than `pivot_root` but sufficient for this project. The key difference is that `pivot_root` fully replaces the root mount point and prevents escape via `..` traversal, while `chroot` only changes the apparent root for path resolution. For a production runtime, `pivot_root` is preferred.

What the host kernel still shares with all containers: the kernel itself, the network namespace (containers share the host network stack), cgroups, and the host process scheduler. Namespace isolation is not full virtualisation — it is a view-level separation enforced by the kernel.

### 4.2 Supervisor and Process Lifecycle

A long-running supervisor is necessary because containers are child processes — when a child exits, only its parent can reap it with `waitpid()`. Without a persistent parent, exited containers become zombie processes that consume PID table entries indefinitely.

The lifecycle works as follows. The supervisor calls `clone()` to create each container child. It records a `container_record_t` for each one, storing the host PID, start time, state, memory limits, and log path. When a container exits, the kernel delivers `SIGCHLD` to the supervisor. The `sigchld_handler` calls `waitpid(-1, WNOHANG)` in a loop to reap all available children at once — looping is necessary because multiple children may exit between signal deliveries. The handler then updates the metadata state and exit reason based on whether the child exited normally, was signalled, and whether `stop_requested` was set.

Signal delivery for `stop` works by setting `stop_requested=1` on the record before calling `kill(SIGTERM)` followed by `kill(SIGKILL)`. This flag is checked in `sigchld_handler` to correctly classify the exit as `stopped` rather than `hard_limit_killed`.

### 4.3 IPC, Threads, and Synchronisation

The project uses two distinct IPC mechanisms:

**Path A — Logging (pipe-based):** Each container's stdout and stderr are redirected via `dup2()` to the write end of a pipe created before `clone()`. The supervisor holds the read end. A dedicated producer thread per container reads from this pipe and pushes `log_item_t` chunks into the shared bounded buffer. A single consumer thread drains the buffer and appends to per-container log files.

**Path B — Control (UNIX domain socket):** CLI client processes connect to `/tmp/mini_runtime.sock`, send a binary `control_request_t` struct, and receive a `control_response_t`. The supervisor's `select()` event loop accepts these connections and dispatches commands.

**Bounded buffer synchronisation:** The buffer uses a `pthread_mutex_t` to protect `head`, `tail`, `count`, and `shutting_down`. Two condition variables coordinate producers and the consumer: `not_full` (producers wait here when the buffer is full) and `not_empty` (consumer waits here when empty). Without these primitives, two producers could write to the same tail slot simultaneously, the consumer could read a partially-written item, and `count` could be corrupted by concurrent increment/decrement.

Deadlock is avoided by the `shutting_down` flag: `bounded_buffer_begin_shutdown()` broadcasts to both condition variables, ensuring all waiting threads wake up and exit rather than blocking forever.

**Metadata list synchronisation:** `supervisor_ctx_t.metadata_lock` (a `pthread_mutex_t`) protects the `containers` linked list. This is a separate lock from the buffer mutex to avoid holding both simultaneously, which would risk deadlock.

### 4.4 Memory Management and Enforcement

RSS (Resident Set Size) measures the amount of physical RAM currently mapped into a process's address space — pages that are actually in memory, not just allocated. RSS does not measure virtual memory (pages allocated but not yet touched), memory-mapped files that are not yet paged in, or shared library pages counted per-process even though they are physically shared.

Soft and hard limits implement different policies deliberately. A soft limit is a warning threshold: the process is allowed to continue running, but the operator is notified via `dmesg` that memory usage is elevated. A hard limit is an enforcement threshold: the process is killed unconditionally. This two-level design allows graceful handling — an application might respond to monitoring and free memory before hitting the hard limit.

Enforcement belongs in kernel space rather than user space for two reasons. First, a user-space monitor can be killed, paused, or delayed by the scheduler, creating a window where a process exceeds its limit with no enforcement. A kernel timer fires reliably regardless of user-space scheduling. Second, sending signals to arbitrary processes requires privileges and correct namespace handling that are natural in the kernel. The module uses `find_get_pid()` (global PID lookup, not namespace-relative `find_vpid()`) to correctly locate container processes from the init namespace.

### 4.5 Scheduling Behaviour

Linux uses the Completely Fair Scheduler (CFS), which tracks `vruntime` (virtual runtime) for each runnable process. CFS always schedules the process with the lowest `vruntime`, advancing it faster for higher-priority processes and slower for lower-priority ones. The `nice` value adjusts the weight: nice=0 gets weight 1024, nice=10 gets weight 110, meaning a nice=0 process gets approximately 9x more CPU time per scheduling period than a nice=10 process when both are runnable.

**Experiment 1 results** confirm this directly. Two identical `cpu_hog` processes running concurrently for 20 seconds of work: nice=0 completed in 20.3s (near-ideal), nice=10 completed in 33.3s — 64% longer. This matches CFS weight theory: with one CPU and unequal weights, the lower-priority process receives proportionally less time and takes longer to complete the same work.

**Experiment 2 results** show a different dynamic. The I/O-bound `io_pulse` (nice=0) took 23.3s while `cpu_hog` (nice=0) took 20.0s, despite equal priority. `io_pulse` sleeps for 200ms between iterations via `usleep()`, voluntarily yielding the CPU. Its `vruntime` falls behind during sleep, so CFS gives it scheduling priority when it wakes up. Total wall time is dominated by intentional sleep time, not CPU competition. This demonstrates that I/O-bound processes are naturally well-served by CFS: they get low latency when they need the CPU because they rarely hold it.

---

## 5. Design Decisions and Tradeoffs

### Namespace Isolation
**Choice:** `chroot` for filesystem isolation rather than `pivot_root`.
**Tradeoff:** `chroot` is simpler but allows escape via `..` traversal if the container process has sufficient privileges. `pivot_root` fully replaces the root mount and is more secure.
**Justification:** For this project's scope, `chroot` provides sufficient isolation to demonstrate the concept. It requires no additional bind-mount setup and works correctly with Alpine's rootfs layout.

### Supervisor Architecture
**Choice:** Single-threaded `select()` event loop for control connections, with per-container producer threads for logging.
**Tradeoff:** The event loop handles one control request at a time. A long-running `run` command blocks the supervisor from accepting other CLI connections during the wait. A multi-threaded connection handler would fix this but adds lock complexity.
**Justification:** For the project's interactive CLI use case, serial handling is sufficient. The logging pipeline is correctly parallelised with threads because it must handle concurrent output from multiple containers simultaneously.

### IPC and Logging
**Choice:** UNIX domain socket for control, pipes for logging — two separate IPC mechanisms.
**Tradeoff:** Two IPC paths add implementation complexity. A single socket-based approach could handle both, but mixing control and log data on one channel would require multiplexing logic.
**Justification:** Pipes are the natural fit for streaming stdout/stderr — they integrate directly with `dup2()` and provide automatic backpressure. A socket is better for structured request/response control messages. Keeping them separate makes each path simpler and independently debuggable.

### Kernel Monitor Lock
**Choice:** `mutex` rather than `spinlock` for the monitored list.
**Tradeoff:** Mutexes allow sleeping, adding overhead compared to spinlocks for very short critical sections. Spinlocks would be faster but cannot be held across sleepable calls.
**Justification:** `get_rss_bytes()` calls `get_task_mm()` which acquires `mm->mmap_lock` internally — this can sleep. Holding a spinlock across a sleepable call causes a kernel BUG. Mutex is the only correct choice on these code paths.

### Scheduling Experiments
**Choice:** `nice` values as the scheduling variable, `time` as the measurement tool.
**Tradeoff:** `nice` values are coarse — they adjust CFS weights but do not provide hard CPU bandwidth guarantees like `cgroups cpu.shares` would.
**Justification:** `nice` is supported natively via `setpriority()` in the child process, integrates directly with our `--nice` flag in `child_fn()`, requires no cgroup setup, and produces clearly observable and explainable results.

---

## 6. Scheduler Experiment Results

### Experiment 1 — CPU-bound vs CPU-bound, different priorities

Both containers ran `cpu_hog 20` (20 seconds of CPU-bound work) concurrently on the same host.

| Container | Workload | Nice | Wall time |
|-----------|----------|------|-----------|
| alpha | cpu_hog 20s | 0 | 20.329s |
| beta | cpu_hog 20s | +10 | 33.307s |

**Result:** nice=10 container took **64% longer** to complete identical work. CFS weight for nice=0 is 1024; for nice=10 it is 110. The scheduler gives alpha ~9x more CPU time per period, so beta takes proportionally longer to accumulate 20 seconds of actual CPU time.

### Experiment 2 — CPU-bound vs I/O-bound, equal priority

Both containers ran at nice=0 concurrently.

| Container | Workload | Nice | Wall time |
|-----------|----------|------|-----------|
| alpha | cpu_hog 20s | 0 | 20.047s |
| beta | io_pulse 20 iters × 200ms sleep | 0 | 23.267s |

**Result:** `cpu_hog` finished in near-ideal time. `io_pulse` took 23.3s for 20 iterations with 200ms sleep each = minimum 4s sleep + actual I/O time + scheduling latency ≈ 23s. The extra time over the CPU-hog reflects `fsync()` cost and wakeup latency. CFS correctly prioritised `io_pulse` on every wakeup (low vruntime from sleeping), giving it good responsiveness while not starving the CPU-bound workload.
