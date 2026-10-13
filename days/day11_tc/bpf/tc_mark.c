// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 11: TC (Traffic Control) 出口流量染色与整形
 *
 * 核心原理解析：
 * 1. Linux TC BPF vs XDP:
 *    - XDP 仅运行于网络输入接口 (Ingress)，在分配 sk_buff 之前执行，追求极速与吞吐；
 *    - TC BPF 可同时运行于 Ingress 与 Egress (出口方向)，在 qdisc (排队规则) 层面接管流量；
 *    - TC 能够访问完整的 sk_buff 元数据，非常适合用于 QoS (服务质量保证)、限速、动态路由标记与 DSCP 染色。
 * 2. DSCP (Differentiated Services Code Point) 染色机制:
 *    - 在出口网卡上，将关键业务（如 gRPC 核心服务）的 IPv4 TOS 字段设置为 0xB8 (DSCP Expedited Forwarding)；
 *    - 交换机与路由器识别该标志后，将其推入高优先级排队通道，保障 SLA。
 * 3. 校验和增量重算 (Incremental Checksum Update):
 *    - 修改 TOS 会破坏 IPv4 首部校验和，调用内核辅助函数 `bpf_l3_csum_replace` 完成硬件友好的差量补正。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// DSCP EF (Expedited Forwarding = 46, 左移2位即 184 = 0xB8)
#define DSCP_EF_TOS 0xB8

// TC 流量度量 Map
// 0: 正常放行未染色
// 1: 成功实施 DSCP 染色
// 2: 阻断丢弃 (可扩展限速策略)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} tc_stats SEC(".maps");

static __always_inline void inc_tc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&tc_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("classifier")
int tc_egress_mark(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 1. 校验以太网头部边界
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_tc_stat(0);
        return TC_ACT_OK;
    }

    // 2. 校验 IPv4 头部边界
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    // 3. 检查 TOS 字段：如果未被标记，则实施 DSCP 染色
    if (ip->tos != DSCP_EF_TOS) {
        __u32 old_tos = ip->tos;
        __u32 new_tos = DSCP_EF_TOS;

        // 计算 IPv4 check 字段的相对字节偏移
        __u32 csum_offset = sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, check);

        // 调用内核辅助函数完成差量校验和重算
        bpf_l3_csum_replace(skb, csum_offset, old_tos, new_tos, 2);

        // 更新 IP 头部的 tos 字段 (注意：经 bpf_l3_csum_replace 后需重新计算指针或通过 helper 存入)
        // 为确保 Verifier 稳定性，使用 bpf_skb_store_bytes 写入 1 字节 TOS
        __u8 tos_byte = DSCP_EF_TOS;
        __u32 tos_offset = sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, tos);
        bpf_skb_store_bytes(skb, tos_offset, &tos_byte, sizeof(tos_byte), 0);

        inc_tc_stat(1);
    } else {
        inc_tc_stat(0);
    }

    return TC_ACT_OK;
}
