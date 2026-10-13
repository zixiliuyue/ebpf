// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 17: Verifier (验证器) 经典被拒剖析与防范实战
 *
 * 核心原理解析：
 * 1. eBPF Verifier (验证器) 工作模型:
 *    - 基于有向无环图 (DAG) 的抽象解释 (Abstract Interpretation) 与符号执行；
 *    - 模拟寄存器状态 (R0-R10) 的类型、范围 (min/max 边界) 与对齐方式；
 *    - 拒绝任何可能导致内核崩溃的操作（如未判空的指针访问、栈溢出、除以零、无限循环）。
 * 2. 生产级 Verifier 攻防三大防线:
 *    - 防线 1: Map 指针判空 (Null-pointer check)
 *      bpf_map_lookup_elem 返回的指针必须显式检查 `if (!val) return;` 否则直接判定 invalid mem access。
 *    - 防线 2: 安全除法运算 (Divide-by-zero guard)
 *      在执行除法前必须显式检查除数 `if (divisor == 0) return 0;`。
 *    - 防线 3: 静态边界展开循环 (Bounded Loop Unrolling)
 *      循环必须有明确编译期上限，使用 `#pragma unroll` 指导编译器展开，避免状态树爆炸。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 示例配置与统计 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} verifier_stats SEC(".maps");

// 安全计算辅助函数：规避除以零与越界风险
static __always_inline __u64 safe_divide(__u64 dividend, __u64 divisor) {
    if (divisor == 0) {
        return 0; // 显式防御分支，Verifier 能够证明除数绝对非 0
    }
    return dividend / divisor;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int tracepoint_safe_demo(struct trace_entry *ctx) {
    __u32 key = 0;

    // 1. Map 查找与强制判空
    __u64 *val = bpf_map_lookup_elem(&verifier_stats, &key);
    if (!val) {
        // 若缺少此分支，Verifier 将直接报错: R0 invalid mem access 'map_value_or_null'
        return 0;
    }

    // 2. 安全有限循环展开
    __u64 sum = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        sum += i;
    }

    // 3. 安全除法计算
    __u64 divisor = sum;
    __u64 result = safe_divide(1000, divisor);

    // 4. 原子更新结果
    __sync_fetch_and_add(val, result);

    return 0;
}
