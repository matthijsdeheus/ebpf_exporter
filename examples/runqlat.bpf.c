// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_SLOTS 32

// Define a key structure for (cgroup_id, bucket) without padding.
struct runqlat_key_t {
    u64 cgroup_id;
    u32 bucket;
} __attribute__((packed));

// Use a HASH map keyed by the (cgroup_id, bucket) pair.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct runqlat_key_t);
    __type(value, u64);
} run_queue_latency SEC(".maps");

// Map to record the enqueue (wakeup) timestamp per task PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

// Helper: approximate log2(x) using a simple loop.
static __always_inline u32 log2_approx(u64 x) {
    u32 i = 0;
    while (x > 1 && i < MAX_SLOTS) {
         x >>= 1;
         i++;
    }
    return i;
}

// On wakeup, record the timestamp for the task.
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

// On sched_switch, compute the latency and increment the (cgroup_id, bucket) counter.
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    u32 pid = BPF_CORE_READ(next, pid);
    u64 *tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;

    u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &pid);

    // Convert delta from nanoseconds to microseconds.
    u64 delta_us = delta_ns / 1000;

    // Determine the bucket index based on the approximate log2 of delta.
    u32 bucket = log2_approx(delta_us);
    if (bucket >= MAX_SLOTS)
        bucket = MAX_SLOTS - 1;

    // Get current cgroup id.
    u64 cg_id = bpf_get_current_cgroup_id();

    struct runqlat_key_t key = {
        .cgroup_id = cg_id,
        .bucket = bucket,
    };

    // Increment the counter in the map.
    u64 init_val = 1, *valp;
    valp = bpf_map_lookup_elem(&run_queue_latency, &key);
    if (valp) {
        __sync_fetch_and_add(valp, 1);
    } else {
        bpf_map_update_elem(&run_queue_latency, &key, &init_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
