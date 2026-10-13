// 为跨架构 BPF PT_REGS 宏指定目标架构寄存器映射
#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_arm64
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// VFS 读操作事件载荷 (传递给用户态分析延迟)
struct vfs_read_event {
    __u32 pid;
    __u32 uid;
    __u64 duration_ns; // 调用耗时 (纳秒)
    __s64 ret_bytes;   // 返回读取的字节数 (若为负数表示错误码)
    char comm[16];     // 进程名
};

// 暂存每个线程进入 vfs_read 的时间戳
// Key 必须为 __u64 (pid_tgid)，避免多线程并发时时间戳相互覆盖
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} start_times SEC(".maps");

// 环形缓冲区传递时延事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// 拦截 vfs_read 函数入口：记录启动时间戳
SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    // 记录时间戳，若 Map 满则放弃记录，避免阻塞内核执行
    bpf_map_update_elem(&start_times, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

// 拦截 vfs_read 函数返回：计算耗时并提交事件
SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(kretprobe_vfs_read, ssize_t ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &pid_tgid);
    if (!start_ts) {
        return 0; // 未追踪到入口或已被清理，安全跳过
    }

    __u64 duration = bpf_ktime_get_ns() - *start_ts;
    // 立即清理 Map 项，防止长时间运行导致哈希表耗尽泄漏 (Google SRE 内存安全原则)
    bpf_map_delete_elem(&start_times, &pid_tgid);

    // 仅针对耗时超过 10 微秒 (10,000 ns) 的读操作上报，防止事件风暴造成用户态拥塞
    if (duration < 10000) {
        return 0;
    }

    struct vfs_read_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // 缓冲区满，快速静默丢弃
    }

    e->pid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->duration_ns = duration;
    e->ret_bytes = ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
