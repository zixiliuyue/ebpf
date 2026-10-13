// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 12: BPF SockOps TCP 状态观测与动态调优
 *
 * 核心原理解析：
 * 1. SockOps (Socket Operations) 机制:
 *    - 挂载点位于 cgroup (cgroup/sock_ops)，覆盖其下所有进程创建的 TCP 套接字；
 *    - 内核在 TCP 连接状态生命周期变迁（如三次握手成功、RTT 采集、状态机切换）时触发；
 * 2. 动态套接字选项调优 (Zero-Overhead Tuning):
 *    - 在握手完成事件 (ACTIVE_ESTABLISHED_CB / PASSIVE_ESTABLISHED_CB) 中，
 *      无需用户态显式 setsockopt，即可在内核上下文直接开启 TCP_NODELAY (关闭 Nagle 算法)，
 *      显著减少小报文延迟；
 *    - 同时设置标志位启用 RTT 采样回调 (BPF_SOCK_OPS_RTT_CB_FLAG)；
 * 3. 统计度量:
 *    - 统计当前主动建连数 (Active Connect) 与被动建连数 (Passive Accept)。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define SOL_TCP 6
#define TCP_NODELAY 1

// SockOps 回调事件类型定义 (防止不同内核版本头文件缺失)
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  4
#define BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB 5
#define BPF_SOCK_OPS_RTT_CB                 7
#define BPF_SOCK_OPS_RTT_CB_FLAG            (1 << 0)

// TCP 统计指标 Map
// 0: 主动建连数 (Client)
// 1: 被动建连数 (Server)
// 2: RTT 回调次数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} sockops_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&sockops_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("sockops")
int bpf_sockops_monitor(struct bpf_sock_ops *skops) {
    // 仅拦截 IPv4 流量
    if (skops->family != AF_INET) {
        return 0;
    }

    __u32 op = skops->op;

    switch (op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
        // 主动建连 (客户端发起连接成功)
        inc_stat(0);

        // 动态调优：开启 TCP_NODELAY，禁用 Nagle 延迟确认机制
        int val = 1;
        bpf_setsockopt(skops, SOL_TCP, TCP_NODELAY, &val, sizeof(val));

        // 启用内核 RTT 采样回调
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTT_CB_FLAG);
        break;
    }
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
        // 被动建连 (服务端接受连接成功)
        inc_stat(1);

        // 同样开启 TCP_NODELAY 与 RTT 观测
        int val = 1;
        bpf_setsockopt(skops, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTT_CB_FLAG);
        break;
    }
    case BPF_SOCK_OPS_RTT_CB: {
        // RTT 采样事件：srtt_us 记录了以微秒为单位的平滑往返时间
        inc_stat(2);
        break;
    }
    default:
        break;
    }

    return 0;
}
