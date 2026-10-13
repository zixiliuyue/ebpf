// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/tc_mark.c

// ExtractDSCP 从 IPv4 的 TOS 字段中提取 DSCP (高6位) 与 ECN (低2位)
// 纯函数设计，便于单元测试与上层 QoS 策略验证
func ExtractDSCP(tos byte) (dscp uint8, ecn uint8) {
	dscp = (tos >> 2) & 0x3F
	ecn = tos & 0x03
	return dscp, ecn
}

// FormatTOSDescription 返回该 TOS 对应的标准 QoS 类别描述
func FormatTOSDescription(tos byte) string {
	dscp, ecn := ExtractDSCP(tos)
	switch dscp {
	case 46: // 0x2E, 对应 tos = 0xB8
		return fmt.Sprintf("DSCP EF (Expedited Forwarding, 极速加速通道) [ECN: %d]", ecn)
	case 0:
		return fmt.Sprintf("DSCP CS0 (Best Effort, 普通尽力而为流量) [ECN: %d]", ecn)
	default:
		return fmt.Sprintf("DSCP 类别 %d [ECN: %d]", dscp, ecn)
	}
}

func main() {
	log.Println(">>> 启动 Day 11: TC (Traffic Control) 出口流量染色与 QoS 整形...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	ifaceName := "eth0"
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Printf("[提示] 接口 %s 不可用，使用 lo 回环接口", ifaceName)
		iface, err = net.InterfaceByName("lo")
		if err != nil {
			log.Fatalf("无法找到网络接口: %v", err)
		}
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	log.Printf("[成功] TC classifier 程序已成功载入内核: %s (挂载目标网卡: %s)",
		objs.TcEgressMark.String(), iface.Name)
	log.Printf("[提示] 在生产环境中，通常配合 clsact qdisc 挂载到网卡 egress 端点")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("收到退出信号，优雅终止 TC 监控...")
			return
		case <-ticker.C:
			var normalCount, markedCount uint64
			var key0 uint32 = 0
			var key1 uint32 = 1
			_ = objs.TcStats.Lookup(&key0, &normalCount)
			_ = objs.TcStats.Lookup(&key1, &markedCount)
			log.Printf("[TC 流量指标] 正常放行: %d | 成功染色(DSCP 0xB8): %d", normalCount, markedCount)
		}
	}
}
