// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Google 生产级 eBPF 工程实战 - Day 16: BPF LSM 关键敏感文件防篡改与动态保护
 *
 * 核心原理解析：
 * 1. 深度防御 (Defense-in-Depth):
 *    - 即使反向提权获得了 UID=0 (Root 权限)，依然无法绕过内核 LSM 的终极判定；
 * 2. LSM file_open 钩子:
 *    - 挂载点 SEC("lsm/file_open")：在任意进程调用 openat()/sys_open 打开文件句柄时同步校验；
 *    - 检查 file->f_flags 是否含有写权限 (O_WRONLY=01, O_RDWR=02, O_CREAT=0100)；
 *    - 读取目标 dentry 名称，如匹配受保护的特权凭据文件 (如 "shadow", "sudoers")，
 *      直接返回 -EACCES (-13) 强行阻断篡改尝试！
 */

#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_arm64
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EACCES 13
#define O_WRONLY 00000001
#define O_RDWR   00000002

// 文件保护审计度量 Map
// 0: 合法读写放行次数
// 1: 成功拦截的敏感文件篡改尝试
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} file_lsm_stats SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&file_lsm_stats, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    // 仅在请求写权限时触发防篡改审查
    unsigned int flags = file->f_flags;
    if ((flags & O_WRONLY) || (flags & O_RDWR)) {
        char name[16] = {};
        // 从 dentry 获取文件名
        const unsigned char *d_name = file->f_path.dentry->d_name.name;
        if (bpf_probe_read_kernel_str(name, sizeof(name), d_name) > 0) {
            // 精确匹配特权密码本 "shadow" (6 字节: 's','h','a','d','o','w')
            if (name[0] == 's' && name[1] == 'h' && name[2] == 'a' &&
                name[3] == 'd' && name[4] == 'o' && name[5] == 'w' && name[6] == '\0') {
                inc_stat(1); // 记录拦截攻击事件
                return -EACCES; // 强行返回 Permission Denied，即使 Root 也无法写入！
            }
        }
    }

    inc_stat(0); // 正常读写放行
    return 0;
}
