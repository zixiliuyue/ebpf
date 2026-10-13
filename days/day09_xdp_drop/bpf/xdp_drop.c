// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义以太网协议常量 (若 vmlinux.h 中已存在则复用)
#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1

// 统计丢包与放行计数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); // 0: 放行包数, 1: 丢弃包数
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");

// 辅助递增计数器
static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&xdp_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

// XDP 主处理函数：极速丢弃 ICMP 协议报文 (Ping 洪水防御)
// Google 生产级规则：XDP 处于网络最前线，任何报文解析必须做严格的边界检查 (Bounds Check)
SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. 验证以太网首部边界
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // 仅处理 IPv4 报文 (注意：以太网首部协议为大端网络字节序)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_stat(0);
        return XDP_PASS;
    }

    // 2. 验证 IPv4 首部边界
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // 3. 检查传输层协议：若为 ICMP 则执行 XDP_DROP
    if (ip->protocol == IPPROTO_ICMP) {
        inc_stat(1); // 记录丢弃计数
        return XDP_DROP;
    }

    // 其他合法流量无损放行
    inc_stat(0);
    return XDP_PASS;
}
