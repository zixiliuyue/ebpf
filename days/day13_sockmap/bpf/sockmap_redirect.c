// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 13: Sockmap 与 sk_msg 本地微服务通信短路零拷贝加速
 *
 * 核心原理解析：
 * 1. 痛点：微服务 Service Mesh 本地通信的 CPU 开销:
 *    Sidecar (Envoy) 与后端业务容器部署在同一 Pod 内，通过 127.0.0.1 相互调用。
 *    即便走回环设备 (Loopback)，Linux 依然会执行完整的 TCP 状态机、分段、IP 路由与两次协议栈软中断。
 * 2. Sockmap 零拷贝直通 (Socket Bypass):
 *    - 维护一个 SOCKHASH 映射表，存储参与本地通信的 TCP 套接字引用；
 *    - 在应用层调用 sendmsg() 时，BPF 程序 SEC("sk_msg") 直接拦截；
 *    - 匹配对端套接字后，调用 bpf_msg_redirect_hash()，直接将 sk_msg 的数据包
 *      推入对端套接字的接收队列 (Receive Queue)，彻底绕过 TCP/IP 协议栈！
 * 3. 性能收益:
 *    - 吞吐量提升 200%~300%，P99 延迟降低 50% 以上。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define SK_PASS 1
#define SK_DROP 0

// TCP 四元组识别键 (网络字节序)
struct sock_key {
    __u32 sip;
    __u32 dip;
    __u32 sport;
    __u32 dport;
};

// 存储活动 Socket 引用的 Sockhash
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u32); // socket 文件描述符映射
} sock_hash SEC(".maps");

// 重定向指标度量 Map
// 0: 成功短路直通重定向的消息数
// 1: 普通放行 (未命中加速表)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} sockmap_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&sockmap_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("sk_msg")
int sk_msg_redirect(struct sk_msg_md *msg) {
    // 构造对端套接字的匹配键 (发端的 remote 即收端的 local，发端的 local 即收端的 remote)
    struct sock_key lookup_key = {
        .sip   = msg->remote_ip4,
        .dip   = msg->local_ip4,
        .sport = bpf_htonl(msg->remote_port >> 16), // 修正端口字节对齐
        .dport = bpf_htonl(msg->local_port),
    };

    // 尝试直接将消息重定向至对端 Socket 的 Ingress 队列
    long ret = bpf_msg_redirect_hash(msg, &sock_hash, &lookup_key, BPF_F_INGRESS);
    if (ret == SK_PASS) {
        inc_stat(0); // 成功短路直通
        return SK_PASS;
    }

    // 若未在表中找到对端（例如刚启动或外部流量），优雅回退到正常内核路径
    inc_stat(1);
    return SK_PASS;
}
