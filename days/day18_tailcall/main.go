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
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/tailcall_router.c

// GetProtocolHandlerName 映射协议索引到可读处理器描述
func GetProtocolHandlerName(idx uint32) string {
	switch idx {
	case 0:
		return "HTTP-Dedicated-Handler (槽位 0)"
	case 1:
		return "DNS-Dedicated-Handler (槽位 1)"
	default:
		return fmt.Sprintf("Fallback-Handler (槽位 %d)", idx)
	}
}

func main() {
	log.Println(">>> 启动 Day 18: BPF 尾调用 (Tail Call) 协议路由器与微内核架构...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 动态组装跳转表 (Jump Table)
	// 将 HandleHttp 注册进槽位 0
	var key0 uint32 = 0
	if err := objs.JmpTable.Update(&key0, objs.HandleHttp, ebpf.UpdateAny); err != nil {
		log.Fatalf("注册 HTTP 尾调用处理器失败: %v", err)
	}
	// 将 HandleDns 注册进槽位 1
	var key1 uint32 = 1
	if err := objs.JmpTable.Update(&key1, objs.HandleDns, ebpf.UpdateAny); err != nil {
		log.Fatalf("注册 DNS 尾调用处理器失败: %v", err)
	}

	log.Println("[成功] 尾调用路由器已完成插件装配：槽位 0 -> HTTP，槽位 1 -> DNS")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("优雅退出尾调用路由器...")
			return
		case <-ticker.C:
			var httpCount, dnsCount, fallbackCount uint64
			var k0, k1, k2 uint32 = 0, 1, 2
			_ = objs.RouterStats.Lookup(&k0, &httpCount)
			_ = objs.RouterStats.Lookup(&k1, &dnsCount)
			_ = objs.RouterStats.Lookup(&k2, &fallbackCount)
			log.Printf("[路由分发度量] HTTP 命中: %d | DNS 命中: %d | Fallback 降级: %d",
				httpCount, dnsCount, fallbackCount)
		}
	}
}
