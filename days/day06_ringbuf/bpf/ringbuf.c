// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_arm64
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 事件结构体
struct task_switch_event {
    __u32 prev_pid;
    __u32 next_pid;
    __u64 timestamp_ns;
    char next_comm[16];
};

// 1. 核心环形缓冲区 (内存页对齐，所有 CPU 共享单个无锁 RingBuffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512 KB (必须是 4KB 页的 2 的幂次方)
} ringbuf_events SEC(".maps");

// 2. 丢包度量计数器 (Google SRE 韧性要求：显式暴露因背压丢弃的事件量)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_counter SEC(".maps");

// 挂载点：内核上下文切换 tracepoint/sched/sched_switch
// 触发频率极高，是测试 RingBuffer 吞吐与背压丢包保护的绝佳场景
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_trace, bool preempt, struct task_struct *prev, struct task_struct *next) {
    // 1. 尝试使用 zero-copy 预留空间
    struct task_switch_event *e = bpf_ringbuf_reserve(&ringbuf_events, sizeof(*e), 0);
    if (!e) {
        // 【第一性原理与 Google SRE 防线】：
        // 环形缓冲区已满，无法容纳新事件。绝不能静默丢弃！
        // 原子递增 drop_counter，通知用户态发生了背压 (Backpressure)
        __u32 key = 0;
        __u64 *drops = bpf_map_lookup_elem(&drop_counter, &key);
        if (drops) {
            __sync_fetch_and_add(drops, 1);
        }
        return 0;
    }

    // 2. 填充事件字段
    e->prev_pid = BPF_CORE_READ(prev, pid);
    e->next_pid = BPF_CORE_READ(next, pid);
    e->timestamp_ns = bpf_ktime_get_ns();
    BPF_CORE_READ_STR_INTO(&e->next_comm, next, comm);

    // 3. 提交事件 (内存屏障确保用户态可见，唤醒 epoll 等待)
    bpf_ringbuf_submit(e, 0);
    return 0;
}
