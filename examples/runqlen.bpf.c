// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_SLOTS 32

// Optional: if you want to use different fields when running on the host,
// you can set this flag from user-space.
const volatile bool targ_host = false;

// Define a BPF map with the name "run_queue_length" to match the YAML configuration.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, u32);
    __type(value, u64);
} run_queue_length SEC(".maps");

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
    struct task_struct *task;
    u64 slot;
    u32 key;

    // Get the current task.
    task = (void*)bpf_get_current_task();

    // Read the number of runnable tasks.
    if (targ_host)
        slot = BPF_CORE_READ(task, se.cfs_rq, rq, nr_running);
    else
        slot = BPF_CORE_READ(task, se.cfs_rq, nr_running);

    // Subtract the currently running task if present.
    if (slot > 0)
        slot--;

    // Clamp the value to our bucket range.
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    key = slot;
    u64 *count = bpf_map_lookup_elem(&run_queue_length, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
