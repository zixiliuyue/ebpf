// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/xdp_reflect.c

// PacketHeaders 用于纯函数构造与校验报文的通用结构
type PacketHeaders struct {
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

// BuildUDPv4Packet 构造符合以太网+IPv4+UDP标准的原始字节流
// 满足 Google 工程无外部重依赖 (Hermetic) 的纯内存单元测试需求
func BuildUDPv4Packet(p PacketHeaders) ([]byte, error) {
	buf := new(bytes.Buffer)

	// 1. 写入以太网帧头 (14 字节)
	if len(p.DstMAC) != 6 || len(p.SrcMAC) != 6 {
		return nil, fmt.Errorf("MAC 地址长度非法")
	}
	buf.Write(p.DstMAC)
	buf.Write(p.SrcMAC)
	if err := binary.Write(buf, binary.BigEndian, uint16(0x0800)); err != nil { // ETH_P_IP
		return nil, err
	}

	// 2. 写入 IPv4 头部 (20 字节，无 options)
	srcIP4 := p.SrcIP.To4()
	dstIP4 := p.DstIP.To4()
	if srcIP4 == nil || dstIP4 == nil {
		return nil, fmt.Errorf("IP 必须为有效的 IPv4 地址")
	}

	udpTotalLen := uint16(8 + len(p.Payload))
	ipTotalLen := uint16(20 + udpTotalLen)

	// Version(4) + IHL(5) = 0x45
	buf.WriteByte(0x45)
	buf.WriteByte(0x00) // DSCP/ECN
	if err := binary.Write(buf, binary.BigEndian, ipTotalLen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(0x1234)); err != nil { // ID
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(0x0000)); err != nil { // Flags + Fragment Offset
		return nil, err
	}
	buf.WriteByte(64) // TTL
	buf.WriteByte(17) // Protocol: UDP (17)
	// 校验和占位 (2 字节)
	if err := binary.Write(buf, binary.BigEndian, uint16(0x0000)); err != nil {
		return nil, err
	}
	buf.Write(srcIP4)
	buf.Write(dstIP4)

	// 3. 写入 UDP 头部 (8 字节)
	if err := binary.Write(buf, binary.BigEndian, p.SrcPort); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.DstPort); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, udpTotalLen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(0x0000)); err != nil { // Checksum optional
		return nil, err
	}

	// 4. 写入有效载荷
	buf.Write(p.Payload)

	return buf.Bytes(), nil
}

// ParseUDPv4Packet 解析以太网+IPv4+UDP报文核心字段
func ParseUDPv4Packet(data []byte) (*PacketHeaders, error) {
	if len(data) < 14+20+8 {
		return nil, fmt.Errorf("报文总长度过短: %d 字节", len(data))
	}

	dstMAC := net.HardwareAddr(data[0:6])
	srcMAC := net.HardwareAddr(data[6:12])
	etherType := binary.BigEndian.Uint16(data[12:14])
	if etherType != 0x0800 {
		return nil, fmt.Errorf("不支持的以太网类型: 0x%04x", etherType)
	}

	ipHeader := data[14 : 14+20]
	protocol := ipHeader[9]
	if protocol != 17 {
		return nil, fmt.Errorf("非 UDP 协议: %d", protocol)
	}
	srcIP := net.IP(ipHeader[12:16])
	dstIP := net.IP(ipHeader[16:20])

	udpHeader := data[34 : 34+8]
	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
	payload := data[42:]

	return &PacketHeaders{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Payload: payload,
	}, nil
}

func main() {
	log.Println(">>> 启动 Day 10: XDP L2/L3/L4 报文解析与 XDP_TX 原路极速反射...")

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
			log.Fatalf("无法找到可用的网络接口: %v", err)
		}
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpReflectEcho,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("挂载 XDP 程序到 %s 失败: %v", iface.Name, err)
	}
	defer l.Close()

	log.Printf("[成功] 已将 XDP_TX 反射程序挂载到网卡: %s (端口 8888 流量将被极速回显)", iface.Name)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("正在优雅关闭 XDP 程序...")
			return
		case <-ticker.C:
			var passCount, reflectCount uint64
			var key0 uint32 = 0
			var key1 uint32 = 1
			_ = objs.ReflectStats.Lookup(&key0, &passCount)
			_ = objs.ReflectStats.Lookup(&key1, &reflectCount)
			log.Printf("[统计度量] 正常放行: %d 包 | 原路反射: %d 包", passCount, reflectCount)
		}
	}
}
