// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/sockops_monitor.c

// IPv4ToString 将大端或小端的 uint32 IP 地址转为人类可读的点分十进制字符串
func IPv4ToString(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

// OpName 映射 SockOps 回调编号为可读字符串
func OpName(op uint32) string {
	switch op {
	case 4:
		return "ACTIVE_ESTABLISHED (客户端握手成功)"
	case 5:
		return "PASSIVE_ESTABLISHED (服务端接纳连接)"
	case 7:
		return "RTT (平滑往返时间采样)"
	default:
		return fmt.Sprintf("UNKNOWN_OP(%d)", op)
	}
}

func main() {
	log.Println(">>> 启动 Day 12: BPF SockOps TCP 状态观测与动态调优...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 尝试挂载到 cgroupv2 (在支持 cgroupv2 的 Linux 环境)
	cgroupPath := "/sys/fs/cgroup"
	if _, err := os.Stat(cgroupPath); err == nil {
		cgLink, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupSockOps,
			Program: objs.BpfSockopsMonitor,
		})
		if err != nil {
			log.Printf("[提示] 挂载 cgroup %s 失败 (可能缺乏 cgroupv2 权限): %v", cgroupPath, err)
		} else {
			defer cgLink.Close()
			log.Printf("[成功] SockOps 程序已成功挂载到 cgroupv2: %s", cgroupPath)
		}
	}

	log.Println("[就绪] SockOps 监控正在运行，监听系统 TCP 连接事件与 RTT 状态...")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("优雅终止 SockOps 监控...")
			return
		case <-ticker.C:
			var activeCount, passiveCount, rttCount uint64
			var key0, key1, key2 uint32 = 0, 1, 2
			_ = objs.SockopsStats.Lookup(&key0, &activeCount)
			_ = objs.SockopsStats.Lookup(&key1, &passiveCount)
			_ = objs.SockopsStats.Lookup(&key2, &rttCount)
			log.Printf("[SockOps 统计] 主动建连: %d | 被动建连: %d | RTT采样回调: %d",
				activeCount, passiveCount, rttCount)
		}
	}
}
