// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/lsm_exec.c

// IsSuspiciousPath 判断执行路径是否属于受信策略拒绝的危险目录
// 纯函数设计，用于表驱动单测
func IsSuspiciousPath(path string) bool {
	// 防御性基线：禁止在 /tmp/ 下执行二进制
	return strings.HasPrefix(path, "/tmp/")
}

// IsLSMSupported 检查内核 LSM 兼容性
func IsLSMSupported(err error) bool {
	if err == nil {
		return true
	}
	return !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EINVAL)
}

func main() {
	log.Println(">>> 启动 Day 15: BPF LSM 进程执行准入拦截 (拦截 /tmp/ 二进制执行)...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	l, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmBprmCheck,
	})
	if err != nil {
		if !IsLSMSupported(err) {
			log.Printf("[环境提示] 当前内核未开启 CONFIG_BPF_LSM=y: %v", err)
			return
		}
		log.Fatalf("[错误] 挂载 LSM bprm_check_security 失败: %v", err)
	}
	defer l.Close()

	log.Println("[成功] LSM 防护策略已生效：全机拦截任何 /tmp/ 目录可执行文件！")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("优雅终止 LSM 进程拦截监控...")
			return
		case <-ticker.C:
			var passCount, blockedCount uint64
			var key0, key1 uint32 = 0, 1
			_ = objs.ExecLsmStats.Lookup(&key0, &passCount)
			_ = objs.ExecLsmStats.Lookup(&key1, &blockedCount)
			log.Printf("[安全拦截度量] 合法执行: %d | 成功拦截违规执行: %d", passCount, blockedCount)
		}
	}
}
