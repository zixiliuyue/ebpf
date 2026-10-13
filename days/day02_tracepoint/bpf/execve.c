// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 事件结构体：进程创建通知
// 按照 Google 工程规范，跨内核/用户态传输结构体必须注意内存对齐与固定宽度类型
struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[64];
};

// 定义 Ring Buffer Map，用于将事件流无锁、高吞吐地传递给用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB 环形缓冲区，必须为页大小 (4KB) 的 2 的幂次方
} events SEC(".maps");

// 挂载点：系统调用 sys_enter_execve 进入时触发
// 在现代 Linux 内核中，sys_enter_execve 是追踪新进程执行的最标准、最稳定的静态探针
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    // 在 Ring Buffer 中预留空间，避免内核栈空间 (512 字节上限) 溢出与多余拷贝
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // 缓冲区满时快速失败，保障宿主稳定性
    }

    e->pid = pid;
    e->uid = uid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取 execve 的第一个入参 filename (const char *filename)
    // ctx->args[0] 存储的是用户空间内存指针，必须通过辅助函数 bpf_probe_read_user_str 安全复制，
    // 防止访问非法地址导致内核缺页或 Crash
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // 提交到 Ring Buffer，通知用户空间读取
    bpf_ringbuf_submit(e, 0);
    return 0;
}
