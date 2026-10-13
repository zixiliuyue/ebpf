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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/lsm_file_protect.c

// IsWriteOpen 判断 openat 系统调用 flags 是否包含写意图 (只写或读写)
func IsWriteOpen(flags int) bool {
	return (flags&os.O_WRONLY != 0) || (flags&os.O_RDWR != 0)
}

// IsProtectedTarget 判断目标文件名是否属于特权敏感文件
func IsProtectedTarget(filename string) bool {
	switch filename {
	case "shadow", "sudoers", "passwd":
		return true
	default:
		return false
	}
}

// IsLSMSupported 检查内核 LSM 兼容性
func IsLSMSupported(err error) bool {
	if err == nil {
		return true
	}
	return !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EINVAL)
}

func main() {
	log.Println(">>> 启动 Day 16: BPF LSM 关键敏感文件防篡改 (保护 /etc/shadow)...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	l, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmFileOpen,
	})
	if err != nil {
		if !IsLSMSupported(err) {
			log.Printf("[环境提示] 当前内核未开启 CONFIG_BPF_LSM=y: %v", err)
			return
		}
		log.Fatalf("[错误] 挂载 LSM file_open 探针失败: %v", err)
	}
	defer l.Close()

	log.Println("[成功] LSM 防篡改探针已挂载：阻止针对敏感凭据文件 (shadow) 的任何写操作！")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("优雅终止 LSM 文件防篡改监控...")
			return
		case <-ticker.C:
			var passCount, blockedCount uint64
			var key0, key1 uint32 = 0, 1
			_ = objs.FileLsmStats.Lookup(&key0, &passCount)
			_ = objs.FileLsmStats.Lookup(&key1, &blockedCount)
			log.Printf("[文件审计度量] 正常放行: %d | 拦截篡改尝试: %d", passCount, blockedCount)
		}
	}
}
