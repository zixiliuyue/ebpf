// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 10: XDP 协议解析与 XDP_TX 极速报文反射
 *
 * 核心原理解析：
 * 1. 零拷贝交换机原理 (L2/L3/L4 Swap Reflection):
 *    在 NIC 驱动层拦截到达的以太网帧，就地原地 (in-place) 交换链路层 MAC、网络层 IP、传输层端口，
 *    并返回 XDP_TX，指示网卡驱动立即从同一个物理网卡接口反射发送出去。
 * 2. 绕过整套内核网络栈：
 *    数据包完全不经过 sk_buff 分配、netif_receive_skb、路由查找、Netfilter 防火墙、TCP/IP 协议栈，
 *    能够以千万级 PPS (Packets Per Second) 速度响应，实现极低延迟 (微秒级) 的高吞吐服务 (如 DNS/Echo/BGP 探测)。
 * 3. 校验和数学不变性 (Checksum Symmetry):
 *    IPv4 首部校验和与 UDP 校验和基于 16 位反码求和 (RFC 1071)。由于加法满足交换律 (Commutative Property)，
 *    交换源 IP 与目的 IP、交换源 Port 与目的 Port 时，校验和字段的值理论上保持严格恒等，无需昂贵的全包重新计算！
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define ETH_ALEN 6
#define TARGET_ECHO_PORT 8888

// 统计状态 Map
// 0: 放行包数 (PASS)
// 1: 反射包数 (TX)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} reflect_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&reflect_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("xdp")
int xdp_reflect_echo(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. L2 以太网帧头解析与边界防御
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // 仅拦截 IPv4 协议流量
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_stat(0);
        return XDP_PASS;
    }

    // 2. L3 IPv4 首部解析与边界防御
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // 仅拦截 UDP 协议
    if (ip->protocol != IPPROTO_UDP) {
        inc_stat(0);
        return XDP_PASS;
    }

    // 3. L4 UDP 首部解析与边界防御
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) {
        return XDP_PASS;
    }

    // 4. 端口过滤：仅针对目标端口为 8888 的回显测试流量实施反射
    if (udp->dest != bpf_htons(TARGET_ECHO_PORT)) {
        inc_stat(0);
        return XDP_PASS;
    }

    // 5. 原地修改 L2: 交换源 MAC 与目的 MAC
    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // 6. 原地修改 L3: 交换源 IP 与目的 IP
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // 7. 原地修改 L4: 交换源 UDP 端口与目的 UDP 端口
    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;

    // 记录反射成功指标
    inc_stat(1);

    // XDP_TX 指令：将修改后的数据包直接从当前网卡原路送出
    return XDP_TX;
}
