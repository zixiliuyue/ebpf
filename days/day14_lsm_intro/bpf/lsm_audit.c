// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 14: eBPF LSM (Linux Security Modules) 架构与安全审计骨架
 *
 * 核心原理解析：
 * 1. eBPF LSM (Kernel 5.7+):
 *    - 突破传统 SELinux/AppArmor 静态复杂配置与无法动态热编程的局限；
 *    - 直接将 eBPF 程序附加到内核 LSM 关键安全检查点 (Hook Points)；
 *    - 阻断能力：与仅能旁路观测的 Kprobe/Tracepoint 不同，LSM 探针返回 0 表示放行，
 *      返回负数错误码 (如 -EPERM / -EACCES) 会直接导致内核拒绝该特权操作！
 * 2. 审计与准入控制骨架:
 *    - 挂载点 SEC("lsm/task_alloc")：在系统分配新进程/线程控制块 (task_struct) 时触发；
 *    - 本模块作为 LSM 骨架，完成零影响的准入审计计数并全量放行。
 */

#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_arm64
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// LSM 审计事件度量 Map
// 0: 放行的进程创建事件数
// 1: 拦截的违规事件数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} lsm_audit_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&lsm_audit_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("lsm/task_alloc")
int BPF_PROG(lsm_task_alloc, struct task_struct *task, unsigned long clone_flags) {
    // 审计记录进程分配操作
    inc_stat(0);

    // 返回 0: 允许内核继续执行 task_alloc
    return 0;
}
