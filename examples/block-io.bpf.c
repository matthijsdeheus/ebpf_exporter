#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

// Max number of disks we expect to see on the host
#define MAX_DISKS 255

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

extern int LINUX_KERNEL_VERSION __kconfig;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct request *);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DISKS);
    __type(key, u32);
    __type(value, u64);
} block_io_time_microseconds_total SEC(".maps");


struct request_queue___x {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x {
    struct request_queue___x *q;
    struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request)
{
    struct request___x *r = request;

    if (bpf_core_field_exists(r->rq_disk))
        return BPF_CORE_READ(r, rq_disk);
    return BPF_CORE_READ(r, q, disk);
}

// Note the start time
static __always_inline int trace_rq_start(struct request *rq)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &rq, &ts, 0);
    return 0;
}

SEC("raw_tp/block_rq_issue")
int block_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 10, 137)) {
        return trace_rq_start((void *) ctx->args[1]);
    } else {
        return trace_rq_start((void *) ctx->args[0]);
    }
}

SEC("raw_tp/block_rq_complete")
int block_rq_complete(struct bpf_raw_tracepoint_args *ctx)
{
    u64 *tsp, delta_us, ts = bpf_ktime_get_ns();
    struct gendisk *disk;
    struct request *rq = (struct request *) ctx->args[0];
    u32 dev;
    
    // Look up start time
    tsp = bpf_map_lookup_elem(&start, &rq);
    if (!tsp) {
        return 0;
    }

    // Compute the difference in time
    delta_us = (ts - *tsp) / 1000;

    disk = get_disk(rq);
    if (disk) {
        dev = MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor));
    } else {
        dev = 0;
    }

    // Store result in per disk array
    u64 *slot = bpf_map_lookup_elem(&block_io_time_microseconds_total, &dev);
    if (slot) {
        __sync_fetch_and_add(slot, delta_us);
    } else {
        bpf_map_update_elem(&block_io_time_microseconds_total, &dev, &delta_us, BPF_ANY);
    }

    // Cleanup
    bpf_map_delete_elem(&start, &rq);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
