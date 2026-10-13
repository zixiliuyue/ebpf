// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 18: BPF 尾调用 (Tail Call) 协议路由器与微内核架构
 *
 * 核心原理解析：
 * 1. 突破单程序指令与复杂度上限:
 *    - eBPF 具有严格的指令数限制与栈深度约束 (512 字节)；
 *    - 尾调用 (bpf_tail_call) 允许一个 BPF 程序跳转到另一个 BPF 程序，复用当前栈帧，
 *      实现“微内核 + 插件扩展”或“多层协议栈路由器”架构。
 * 2. PROG_ARRAY 状态机:
 *    - 内核程序数组映射表 (BPF_MAP_TYPE_PROG_ARRAY) 作为函数跳转路由表 (Jump Table)；
 *    - 如果尾调用成功，原程序永远不会返回；若未注册目标程序，则继续向下执行作为 Fallback 降级。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 跳转程序数组 (Jump Table)
// key: 协议编号 (0: HTTP, 1: DNS)
// val: 程序文件描述符
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

// 路由度量 Map
// 0: HTTP 处理器命中数
// 1: DNS 处理器命中数
// 2: 降级回退 (Fallback, 未命中已注册处理器)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} router_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&router_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

// 子处理程序 1: HTTP 专用协议解析与度量
SEC("xdp")
int handle_http(struct xdp_md *ctx) {
    inc_stat(0);
    return XDP_PASS;
}

// 子处理程序 2: DNS 专用协议解析与度量
SEC("xdp")
int handle_dns(struct xdp_md *ctx) {
    inc_stat(1);
    return XDP_PASS;
}

// 主调度路由器 (Dispatcher)
SEC("xdp")
int router_entry(struct xdp_md *ctx) {
    // 示例逻辑：根据报文长度奇偶性模拟协议选择 (实际生产中解析 L4 端口)
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end) {
        return XDP_PASS;
    }

    unsigned char *byte_ptr = data;
    __u32 proto_idx = (*byte_ptr) & 1; // 0 或 1

    // 执行尾调用跳转至专用子程序
    bpf_tail_call(ctx, &jmp_table, proto_idx);

    // 若尾调用失败（未注册或越界），执行回退降级逻辑
    inc_stat(2);
    return XDP_PASS;
}
