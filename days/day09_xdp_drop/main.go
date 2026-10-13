package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/xdp_drop.c -- -I../../headers -I../../headers/bpf

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"

	"ebpf-learning-20days/pkg/ebpfutil"
)

func main() {
	ifaceName := flag.String("iface", "lo", "需要挂载 XDP 的网络网卡名称 (例如 lo, eth0)")
	flag.Parse()

	log.Printf(">>> 启动 Day 09: XDP (eXpress Data Path) 网卡级 ICMP 丢包防御 [网卡: %s]...\n", *ifaceName)

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 失败: %v", err)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("[错误] 找不到网卡 %s: %v", *ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 XDP 对象失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 挂载 XDP 程序到目标网卡 (使用 Generic/SKB 兼容模式，确保在 Docker 虚拟网卡中也能完美运行)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropIcmp,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("[错误] 挂载 XDP 到网卡 %s 失败: %v", *ifaceName, err)
	}
	defer l.Close()

	log.Printf("[成功] XDP 过滤程序已成功挂载至 %s (XDPGenericMode)！所有 ICMP/Ping 数据包将在驱动/协议栈前置被丢弃\n", *ifaceName)
	log.Println("可在另一终端执行: ping 127.0.0.1 观察无响应现象。按 Ctrl+C 退出。")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			log.Println("\n[退出] 卸载 XDP 钩子并安全退出...")
			return
		case <-ticker.C:
			var passCount, dropCount uint64
			_ = objs.XdpStats.Lookup(uint32(0), &passCount)
			_ = objs.XdpStats.Lookup(uint32(1), &dropCount)
			fmt.Printf("\r[流量统计] 放行包数 (XDP_PASS): %-8d | 拦截丢弃包数 (XDP_DROP): %-8d", passCount, dropCount)
		}
	}
}
