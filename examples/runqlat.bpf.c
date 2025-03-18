// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_SLOTS 32

// Map to record the enqueue (wakeup) timestamp per task PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

// Global histogram map for run queue latency (in microseconds).
// The exporter will read this map to produce the Prometheus histogram.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, u32);
    __type(value, u64);
} run_queue_latency SEC(".maps");

// Helper: compute approximate log2(x) using a simple loop.
static __always_inline u32 log2_approx(u64 x) {
    u32 i = 0;
    while (x > 1 && i < MAX_SLOTS) {
         x >>= 1;
         i++;
    }
    return i;
}

// On wakeup, record the current timestamp for the task.
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

// On sched_switch, if the incoming task has a recorded timestamp,
// compute the delay (latency) between wakeup and actual scheduling.
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    u32 pid = BPF_CORE_READ(next, pid);
    u64 *tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;
    u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &pid);

    // Convert delta from nanoseconds to microseconds.
    delta /= 1000;

    // Compute bucket index using log2_approx(delta).
    u32 bucket = log2_approx(delta);
    if (bucket >= MAX_SLOTS)
        bucket = MAX_SLOTS - 1;

    u32 key = bucket;
    u64 *count = bpf_map_lookup_elem(&run_queue_latency, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
