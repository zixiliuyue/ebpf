package main

import (
	"fmt"
	"os"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// Day 01: eBPF 开发环境自检与内核准入
// 遵循 Google SRE 最佳实践：在系统启动初期执行严格的前置检查 (Preflight Check)，
// 确保内核版本、BTF (BPF Type Format) 调试信息、虚拟文件系统与权限均满足要求，
// 防止在后续复杂加载阶段遭遇难以排查的 -EPERM 或符号丢失问题。
func main() {
	fmt.Println(">>> 启动 Day 01: eBPF 运行环境与内核能力自检...")

	diag := ebpfutil.CheckEnvironment()
	fmt.Print(diag.String())

	// 解除锁页内存限制
	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		fmt.Fprintf(os.Stderr, "[警告] 解除 RLIMIT_MEMLOCK 失败: %v\n", err)
	} else {
		fmt.Println("[成功] 进程 RLIMIT_MEMLOCK 锁页内存限制已解除")
	}

	if !diag.Passed {
		fmt.Fprintf(os.Stderr, "[错误] 当前环境未能通过 eBPF 准入要求，请通过 Docker 或在具备 BTF 的 Linux 环境中运行。\n")
		os.Exit(1)
	}

	fmt.Println("[通过] 当前环境具备运行现代 CO-RE eBPF 程序的全部条件！")
}
