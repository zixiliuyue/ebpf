// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 15: BPF LSM 进程执行准入拦截
 *
 * 核心原理解析：
 * 1. 运行时安全防护 (Runtime Security Enforcement):
 *    - 传统 EDR 往往依赖 auditd 或 tracepoint 异步分析，属于“亡羊补牢”式的后置告警；
 *    - eBPF LSM 挂载于内核 `bprm_check_security`，在二进制文件装载前同步触发，具备就地阻断能力！
 * 2. 经典安全基线规则：禁止从 `/tmp/` 目录执行任何二进制文件
 *    - 黑客常用落盘路径为临时目录 (如 /tmp, /dev/shm)；
 *    - 通过检查 bprm->filename 路径前缀，若发现非法执行，直接返回 -EPERM (-1) 阻止进程生成！
 */

#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_arm64
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 1

// 统计 Map
// 0: 放行执行次数
// 1: 成功阻断可疑执行次数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} exec_lsm_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&exec_lsm_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm) {
    char filename[16] = {};

    // 从内核空间安全读取被执行文件的绝对路径前缀
    if (bpf_probe_read_kernel_str(filename, sizeof(filename), bprm->filename) > 0) {
        // 匹配前缀是否为 "/tmp/"
        if (filename[0] == '/' && filename[1] == 't' && filename[2] == 'm' &&
            filename[3] == 'p' && filename[4] == '/') {
            inc_stat(1); // 记录阻断事件
            return -EPERM; // 拒绝内核继续执行该二进制，返回权限拒绝错误
        }
    }

    inc_stat(0); // 正常放行
    return 0;
}
