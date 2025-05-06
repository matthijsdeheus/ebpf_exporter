// Original made by Wenbo Zhang (2020) and can be found at https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.bpf.c 
// This file is adapted to work with CloudFlare ebpf-exporter
// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_SLOTS 32

// Define the (cgroup_id, bucket) key structure
struct runqlat_key_t {
    u64 cgroup_id;
    u32 bucket;
}__attribute__((packed));

// Define a HASH map with the (cgroup_id, bucket) key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct runqlat_key_t);
    __type(value, u64);
} run_queue_latency SEC(".maps");

// Map to record the wakeup timestamp for each task PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

// Helper function to approximate the base-2 logarithm of a number
// Used for calculating the index of the bucket
static __always_inline u32 log2_approx(u64 x) {
    u32 i = 0;

    while (x > 1 && i < MAX_SLOTS) {
         x >>= 1;
         i++;
    }

    return i;
}

// Attach to the sched_wakeup tracepoint
// This is called when a task is woken up
// Store the current timestamp in the start map for the task PID
SEC("tp_btf/sched_wakeup")
int handle_sched_wakeup(struct task_struct *p)
{
    //u32 pid = BPF_CORE_READ(p, pid);
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

// Attach to the sched_switch tracepoint
// This is called when a task is switched out
// Calculate the time spent in the run queue for the task and update the run_queue_latency map
SEC("tp_btf/sched_switch")
int handle_sched_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
    // Get the PID of the next task
    //u32 pid = BPF_CORE_READ(p, pid);
    u32 pid = bpf_get_current_pid_tgid();

    // Get the current timestamp
    u64 *tsp, delta_us, ts = bpf_ktime_get_ns();

    // Check if the task is in the start map
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;


    // Calculate the time spent in the run queue
    delta_us = (ts - *tsp) / 1000;

    // Remove the PID from the start map
    // This is done to avoid double counting if the task is woken up again
    bpf_map_delete_elem(&start, &pid);

    // Determine the bucket index based on the approximate log2 of delta
    u32 bucket = log2_approx(delta_us);
    if (bucket >= MAX_SLOTS)
        bucket = MAX_SLOTS - 1;

    // Get current cgroup id
    u64 cg_id = bpf_get_current_cgroup_id();

    // Build the key for the run_queue_latency map
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