// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/sockmap_redirect.c

// SockKey 对应内核四元组标识
type SockKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint32
	DstPort uint32
}

// ReverseSockKey 获取通信对端视角的对称四元组（用于 Sockmap 双向直通配对）
func ReverseSockKey(k SockKey) SockKey {
	return SockKey{
		SrcIP:   k.DstIP,
		DstIP:   k.SrcIP,
		SrcPort: k.DstPort,
		DstPort: k.SrcPort,
	}
}

// FormatSockKey 格式化打印四元组
func FormatSockKey(k SockKey) string {
	intToIP := func(ip uint32) string {
		return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	}
	return fmt.Sprintf("%s:%d -> %s:%d",
		intToIP(k.SrcIP), k.SrcPort, intToIP(k.DstIP), k.DstPort)
}

func main() {
	log.Println(">>> 启动 Day 13: Sockmap 与 sk_msg 本地微服务短路零拷贝加速...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	log.Printf("[成功] Sockmap 字节码已载入: 程序=%s, SockHash 容量=%d",
		objs.SkMsgRedirect.String(), objs.SockHash.MaxEntries())
	log.Println("[提示] 在实际生产中，sk_msg 程序通过 BPF_PROG_ATTACH 关联至 SockHash 映射表")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("优雅终止 Sockmap 监控...")
			return
		case <-ticker.C:
			var bypassCount, fallbackCount uint64
			var key0, key1 uint32 = 0, 1
			_ = objs.SockmapStats.Lookup(&key0, &bypassCount)
			_ = objs.SockmapStats.Lookup(&key1, &fallbackCount)
			log.Printf("[Sockmap 度量] 短路直通加速: %d 消息 | 回退常规路径: %d 消息",
				bypassCount, fallbackCount)
		}
	}
}
