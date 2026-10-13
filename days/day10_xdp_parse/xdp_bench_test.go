// SPDX-License-Identifier: Apache-2.0
package main

import (
	"net"
	"testing"
)

// BenchmarkParseUDPv4Packet 针对 XDP 解析函数的高频吞吐纳秒级基准测试
// Google 生产延迟预算：网络驱动层单包解析应在数十纳秒内完成
func BenchmarkParseUDPv4Packet(b *testing.B) {
	headers := PacketHeaders{
		SrcMAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:  net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		SrcIP:   net.IPv4(192, 168, 1, 100),
		DstIP:   net.IPv4(192, 168, 1, 1),
		SrcPort: 12345,
		DstPort: 8888,
		Payload: []byte("google-sre-xdp-benchmark-payload"),
	}

	rawPkt, err := BuildUDPv4Packet(headers)
	if err != nil {
		b.Fatalf("构造基准测试数据包失败: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parsed, err := ParseUDPv4Packet(rawPkt)
		if err != nil {
			b.Fatalf("解析失败: %v", err)
		}
		if parsed.DstPort != 8888 {
			b.Fatalf("目标端口不匹配")
		}
	}
}

// BenchmarkBuildUDPv4Packet 基准测试以太网+IPv4+UDP数据包内存构造效率
func BenchmarkBuildUDPv4Packet(b *testing.B) {
	headers := PacketHeaders{
		SrcMAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:  net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(10, 0, 0, 2),
		SrcPort: 53,
		DstPort: 5353,
		Payload: []byte("test-payload"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := BuildUDPv4Packet(headers)
		if err != nil {
			b.Fatalf("构建失败: %v", err)
		}
	}
}
