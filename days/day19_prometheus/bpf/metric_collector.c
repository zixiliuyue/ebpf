// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 19: 内核状态导出与 Prometheus 监控体系
 *
 * 核心原理解析：
 * 1. 业务无侵入的可观测性 (Zero-Instrumentation Observability):
 *    - 内核探针以纳秒级开销捕获系统行为，写入低争用的 BPF Map；
 * 2. 生产级指标导出桥梁:
 *    - 用户态 Exporter 通过 BPF 系统调用以批处理 (Batch Lookup) 或轮询方式将 Map 数据读取到内存，
 *      无缝转换为 Prometheus 黄金指标 (Prometheus Golden Metrics) 格式，供 Grafana 绘制大盘。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 指标计数 Map
// key 0: openat 调用数
// key 1: execve 调用数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} metric_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&metric_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_entry *ctx) {
    inc_stat(0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_entry *ctx) {
    inc_stat(1);
    return 0;
}
