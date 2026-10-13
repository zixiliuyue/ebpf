// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"runtime"
	"testing"
)

// TestExtractDSCP 表驱动验证 DSCP/ECN 解码逻辑
func TestExtractDSCP(t *testing.T) {
	tests := []struct {
		name     string
		tos      byte
		wantDSCP uint8
		wantECN  uint8
	}{
		{
			name:     "默认尽力而为流量 (Best Effort)",
			tos:      0x00,
			wantDSCP: 0,
			wantECN:  0,
		},
		{
			name:     "DSCP EF (Expedited Forwarding 46)",
			tos:      0xB8, // 46 << 2 = 184 = 0xB8
			wantDSCP: 46,
			wantECN:  0,
		},
		{
			name:     "DSCP EF 带 ECN-ECT(1)",
			tos:      0xB9, // (46 << 2) | 1
			wantDSCP: 46,
			wantECN:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDSCP, gotECN := ExtractDSCP(tt.tos)
			if gotDSCP != tt.wantDSCP || gotECN != tt.wantECN {
				t.Errorf("ExtractDSCP(0x%x) = (%d, %d), 期望 (%d, %d)",
					tt.tos, gotDSCP, gotECN, tt.wantDSCP, tt.wantECN)
			}
		})
	}
}

// 辅助函数：构造测试用的简单以太网+IPv4报文
func buildMockIPv4Packet(tos byte) []byte {
	buf := new(bytes.Buffer)
	// 1. MAC (14 字节)
	buf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	buf.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0800)) // ETH_P_IP

	// 2. IPv4 (20 字节)
	buf.WriteByte(0x45)
	buf.WriteByte(tos) // TOS 待测试字段
	_ = binary.Write(buf, binary.BigEndian, uint16(40))
	_ = binary.Write(buf, binary.BigEndian, uint16(0x1234))
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0000))
	buf.WriteByte(64) // TTL
	buf.WriteByte(6)  // TCP
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0000)) // Checksum
	buf.Write(net.ParseIP("192.168.1.1").To4())
	buf.Write(net.ParseIP("192.168.1.2").To4())

	// 3. Payload 伪数据
	buf.Write([]byte("mock-tcp-payload-data"))

	return buf.Bytes()
}

// TestKernelTcEgressMark 测试内核 TC Egress 程序对数据包的正确染色与统计
func TestKernelTcEgressMark(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("加载 BPF 对象失败: %v", err)
	}
	defer objs.Close()

	// 1. 发送未经染色的初始报文 (TOS=0x00)
	packet := buildMockIPv4Packet(0x00)
	ret, outPacket, err := objs.TcEgressMark.Test(packet)
	if err != nil {
		t.Fatalf("运行 BPF_PROG_TEST_RUN 失败: %v", err)
	}

	const TC_ACT_OK = 0
	if ret != TC_ACT_OK {
		t.Fatalf("期望 TC_ACT_OK (0), 实际得到: %d", ret)
	}

	// 验证修改后的报文 TOS 字段是否被成功置为 0xB8
	// IPv4 TOS 偏移量 = 14 (以太网头) + 1 (版本首部后第2字节) = 15
	if len(outPacket) < 16 {
		t.Fatalf("返回的数据包长度异常: %d", len(outPacket))
	}

	gotTOS := outPacket[15]
	const expectedTOS = 0xB8
	if gotTOS != expectedTOS {
		t.Errorf("TOS 染色不符合预期: 期望 0x%02x, 实际得到 0x%02x", expectedTOS, gotTOS)
	}

	// 2. 验证染色统计计数器
	var markedCount, normalCount uint64
	var key0, key1 uint32 = 0, 1
	_ = objs.TcStats.Lookup(&key1, &markedCount)
	if markedCount != 1 {
		t.Errorf("期望染色计数器为 1, 实际得到 %d", markedCount)
	}

	// 3. 再次运行已染色的报文，应当直接放行不再重复标记
	ret2, _, err := objs.TcEgressMark.Test(outPacket)
	if err != nil {
		t.Fatalf("再次运行测试失败: %v", err)
	}
	if ret2 != TC_ACT_OK {
		t.Errorf("再次运行期望放行 0, 实际得到: %d", ret2)
	}

	_ = objs.TcStats.Lookup(&key0, &normalCount)
	if normalCount != 1 {
		t.Errorf("期望未染色放行计数器为 1, 实际得到 %d", normalCount)
	}
}
