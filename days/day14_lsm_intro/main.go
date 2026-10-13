// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/lsm_audit.c

// IsLSMSupported 探针检查当前运行内核是否开启 BPF LSM 特性
func IsLSMSupported(err error) bool {
	if err == nil {
		return true
	}
	// 在未开启 CONFIG_BPF_LSM 或未配置启动参数 lsm=...,bpf 的内核上，
	// 内核会返回 ENOTSUP (95) 或 EINVAL (22)
	return !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EINVAL)
}

func main() {
	log.Println(">>> 启动 Day 14: eBPF LSM (Linux Security Modules) 架构与安全审计骨架...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	l, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmTaskAlloc,
	})
	if err != nil {
		if !IsLSMSupported(err) {
			log.Printf("[环境限制提示] 当前运行内核未开启 CONFIG_BPF_LSM=y 或启动参数缺少 'bpf': %v", err)
			log.Println("[提示] LSM 字节码已通过 Clang 编译与验证，在受支持内核上即可即插即用挂载。")
			return
		}
		log.Fatalf("[错误] 附加 LSM task_alloc 探针失败: %v", err)
	}
	defer l.Close()

	log.Printf("[成功] LSM 审计探针已附加至 task_alloc 安全检查点！")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("优雅终止 LSM 审计...")
			return
		case <-ticker.C:
			var allocCount, blockedCount uint64
			var key0, key1 uint32 = 0, 1
			_ = objs.LsmAuditStats.Lookup(&key0, &allocCount)
			_ = objs.LsmAuditStats.Lookup(&key1, &blockedCount)
			log.Printf("[LSM 审计指标] 进程创建准入事件: %d | 拦截数: %d", allocCount, blockedCount)
		}
	}
}
