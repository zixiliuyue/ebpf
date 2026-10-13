// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Day 04: Per-CPU Map 与高并发计数器
// 第一性原理与性能工程：
// 常规 Map 在多核高频并发更新时必须依赖原子指令 (__sync_fetch_and_add) 或锁，
// 这会导致跨核 CPU 缓存行失效 (Cache Line Bouncing / False Sharing)，性能急剧下降。
// Per-CPU Map 为每个逻辑 CPU 核心分配独立的内存副本，内核更新时无需任何原子锁，
// 读写仅命中本地 L1/L2 缓存，能够轻松支撑千万级 QPS。

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); // 只有一个统计维度 (全局数据包/事件总数)
    __type(key, __u32);
    __type(value, __u64);
} packet_counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&packet_counter, &key);
    if (val) {
        // 无需原子操作，直接递增当前 CPU 本地副本！
        *val += 1;
    }
    return 0;
}
