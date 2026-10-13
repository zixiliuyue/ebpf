package ebpfutil

import (
	"fmt"
	"golang.org/x/sys/unix"
)

// RemoveMemlockLimit 解除进程的锁页内存限制 (RLIMIT_MEMLOCK)。
//
// 背景与原理：
// 在 Linux 5.11 之前的内核版本中，eBPF 程序与 Map 的内存分配受用户进程的 RLIMIT_MEMLOCK 限制。
// 默认情况下，非 root 用户的限制通常极小 (如 64KB)，即使是 root 用户也可能因默认软限制而导致
// bpf() 系统调用返回 -EPERM 或 -ENOMEM。
// 尽管从 Linux 5.11 起内核转向基于 cgroup 的内存记账机制，不再硬性依赖 RLIMIT_MEMLOCK，
// 但在工业级与跨内核兼容的 Go Agent 中，启动时显式解除该限制仍为标准防御性实践。
func RemoveMemlockLimit() error {
	// 将软限制与硬限制均设置为无限制 (RLIM_INFINITY)
	limit := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return fmt.Errorf("设置 RLIMIT_MEMLOCK 为无限制失败: %w", err)
	}
	return nil
}
