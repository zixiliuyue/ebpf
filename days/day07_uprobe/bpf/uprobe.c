// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_arm64
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 用户空间函数执行追踪载荷
struct uprobe_event {
    __u32 pid;
    __u32 uid;
    __u64 timestamp_ns;
    char comm[16];
};

// 环形事件流
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} uprobe_events SEC(".maps");

// 挂载到用户态函数入口 (由用户态指定目标 ELF 二进制路径与符号名)
SEC("uprobe")
int trace_user_function(struct pt_regs *ctx) {
    struct uprobe_event *e = bpf_ringbuf_reserve(&uprobe_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
