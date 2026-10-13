// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_arm64
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// USDT 静态探测事件载荷
struct usdt_query_event {
    __u32 pid;
    __u64 query_id;
    __u64 latency_us;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} usdt_events SEC(".maps");

// 挂载点：静态用户态探测点 (USDT 在内核底层作为 Uprobe 挂载至 .note.stapsdt 静态位置)
// cilium/ebpf 规范：直接使用 PT_REGS_PARM 获取 USDT 参数，规避 libbpf 弱符号 Weak Map 绑定冲突
SEC("uprobe")
int trace_usdt_query(struct pt_regs *ctx) {
    struct usdt_query_event *e = bpf_ringbuf_reserve(&usdt_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->query_id = PT_REGS_PARM1(ctx);
    e->latency_us = PT_REGS_PARM2(ctx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
