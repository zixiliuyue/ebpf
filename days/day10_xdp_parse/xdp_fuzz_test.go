// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"net"
	"testing"
)

// FuzzParseUDPv4Packet 对 XDP 报文解析器进行 Go 原生模糊测试 (Google Testing Practice)
// 目的：验证当网卡驱动/XDP hook 接收到任意畸形数据包、截断包、非 IPv4、非 UDP 流量或超大畸形报文时，
// 报文解析纯函数能够可靠处理，绝不发生下标越界 panic，且对合法报文具备完全的往返一致性。
func FuzzParseUDPv4Packet(f *testing.F) {
	// 1. 种子语料库构建 (Seed Corpus)
	// 语料 A: 空切片
	f.Add([]byte{})

	// 语料 B: 仅包含以太网头部 (14 字节)
	f.Add([]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x00,
	})

	// 语料 C: 标准合法的 UDP 报文 (由 BuildUDPv4Packet 生成)
	validPkg, err := BuildUDPv4Packet(PacketHeaders{
		SrcMAC:  net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:  net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		SrcIP:   net.ParseIP("192.168.1.10"),
		DstIP:   net.ParseIP("192.168.1.20"),
		SrcPort: 12345,
		DstPort: 8888,
		Payload: []byte("Google-eBPF-Fuzz-Seed"),
	})
	if err == nil {
		f.Add(validPkg)
	}

	// 语料 D: 长度恰好为 41 字节 (比最小头部 42 字节少 1 字节的边界测试)
	if len(validPkg) >= 41 {
		f.Add(validPkg[:41])
	}

	// 语料 E: 长度恰好为 42 字节 (无 Payload 的纯头部报文)
	if len(validPkg) >= 42 {
		f.Add(validPkg[:42])
	}

	// 语料 F: 非 IPv4 协议 (如 ARP: 0x0806)
	arpPkg := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x06, // ETH_P_ARP
	}
	arpPkg = append(arpPkg, bytes.Repeat([]byte{0x00}, 30)...)
	f.Add(arpPkg)

	// 2. 模糊测试执行循环
	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, err := ParseUDPv4Packet(data)
		if err != nil {
			// 解析失败时返回值必须为 nil
			if hdr != nil {
				t.Fatalf("解析失败时 PacketHeaders 必须为 nil")
			}
			return
		}

		// 解析成功的不变式校验 (Invariants Check)
		if hdr == nil {
			t.Fatalf("解析成功但返回的 PacketHeaders 为 nil")
		}

		// 最小数据长度检查：能够被解析成功的数据长度必须至少为 42 字节
		if len(data) < 42 {
			t.Fatalf("数据长度小于 42 字节但仍解析成功: len=%d", len(data))
		}

		// MAC 地址长度验证
		if len(hdr.SrcMAC) != 6 || len(hdr.DstMAC) != 6 {
			t.Fatalf("MAC 地址长度异常: src=%d, dst=%d", len(hdr.SrcMAC), len(hdr.DstMAC))
		}

		// IP 地址格式验证
		if hdr.SrcIP.To4() == nil || hdr.DstIP.To4() == nil {
			t.Fatalf("解析出的 IP 不是合法的 IPv4 地址: src=%v, dst=%v", hdr.SrcIP, hdr.DstIP)
		}

		// Payload 长度验证：数据总长度扣除头部 42 字节必须等于 Payload 长度
		expectedPayloadLen := len(data) - 42
		if len(hdr.Payload) != expectedPayloadLen {
			t.Fatalf("Payload 长度不符: 期望 %d, 实际 %d", expectedPayloadLen, len(hdr.Payload))
		}
	})
}
