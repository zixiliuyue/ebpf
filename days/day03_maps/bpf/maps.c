// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Day 03: BPF Maps 实战
// Google 工程规范：定义 Map 时需严谨设定类型、最大容量，并考量哈希冲突与内存开销

// 1. 哈希表 Map：用于按 PID 统计系统调用频次
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // 最多追踪 10240 个并发进程
    __type(key, __u32);        // Key: PID
    __type(value, __u64);      // Value: 调用次数
} proc_exec_counts SEC(".maps");

// 2. 数组 Map：用于存储全局配置参数 (例如开关或阈值)
// 数组 Map 的 Key 必须为整型索引 (0 ~ max_entries-1)，查询速度为 O(1)，无哈希碰撞
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} global_config SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 config_idx = 0;
    __u64 *enabled = bpf_map_lookup_elem(&global_config, &config_idx);
    // 配置检查：若全局开关未开启，直接返回
    if (!enabled || *enabled == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    // 查询当前 PID 现有计数
    __u64 *count = bpf_map_lookup_elem(&proc_exec_counts, &pid);
    if (count) {
        // 原子自增，防止并发冲突
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&proc_exec_counts, &pid, &init_count, BPF_NOEXIST);
    }

    return 0;
}
