#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

// Max number of disks we expect to see on the host
#define MAX_DISKS 255

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

extern int LINUX_KERNEL_VERSION __kconfig;

struct start_val_t {
    u64 ts;
    u64 cg_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct request *);
    __type(value, struct start_val_t);
} start SEC(".maps");

struct io_key_t {
    u64 cg_id;
    u32 dev;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct io_key_t);
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
    struct start_val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.cg_id = bpf_get_current_cgroup_id();
    bpf_map_update_elem(&start, &rq, &val, BPF_ANY);
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
    struct request *rq = (void *)ctx->args[0];
    struct start_val_t *svp = bpf_map_lookup_elem(&start, &rq);
    if (!svp) {
        return 0;
    }
    
    u64 delta_us = (bpf_ktime_get_ns() - svp->ts) / 1000;
    u64 cg_id = svp->cg_id;

    bpf_map_delete_elem(&start, &rq);
    struct gendisk *disk = get_disk(rq);

    u32 dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
    
    struct io_key_t key = {
        .cg_id = cg_id,
        .dev = dev,
    };

    u64 *slot = bpf_map_lookup_elem(&block_io_time_microseconds_total, &key);
    if (slot) {
        __sync_fetch_and_add(slot, delta_us);
    } else {
        bpf_map_update_elem(&block_io_time_microseconds_total, &key, &delta_us, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
