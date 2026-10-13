// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"net"
	"runtime"
	"testing"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// TestPacketBuildAndParse 表驱动验证报文编解码纯函数
func TestPacketBuildAndParse(t *testing.T) {
	tests := []struct {
		name    string
		input   PacketHeaders
		wantErr bool
	}{
		{
			name: "标准合法 UDP 报文",
			input: PacketHeaders{
				SrcMAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				DstMAC:  net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
				SrcIP:   net.ParseIP("10.0.0.1"),
				DstIP:   net.ParseIP("10.0.0.2"),
				SrcPort: 10001,
				DstPort: 8888,
				Payload: []byte("ping-pong-payload"),
			},
			wantErr: false,
		},
		{
			name: "非法 MAC 地址长度边界",
			input: PacketHeaders{
				SrcMAC: net.HardwareAddr{0x00, 0x11}, // 长度不足 6 字节
				DstMAC: net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
				SrcIP:  net.ParseIP("10.0.0.1"),
				DstIP:  net.ParseIP("10.0.0.2"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := BuildUDPv4Packet(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("BuildUDPv4Packet() 期望错误 %v, 实际得到: %v", tt.wantErr, err)
			}
			if tt.wantErr {
				return
			}

			parsed, err := ParseUDPv4Packet(raw)
			if err != nil {
				t.Fatalf("ParseUDPv4Packet() 解析失败: %v", err)
			}

			if !bytes.Equal(parsed.SrcMAC, tt.input.SrcMAC) {
				t.Errorf("SrcMAC 不匹配: 期望 %s, 实际 %s", tt.input.SrcMAC, parsed.SrcMAC)
			}
			if !parsed.SrcIP.Equal(tt.input.SrcIP) {
				t.Errorf("SrcIP 不匹配: 期望 %s, 实际 %s", tt.input.SrcIP, parsed.SrcIP)
			}
			if parsed.SrcPort != tt.input.SrcPort || parsed.DstPort != tt.input.DstPort {
				t.Errorf("端口不匹配: 期望 %d->%d, 实际 %d->%d", tt.input.SrcPort, tt.input.DstPort, parsed.SrcPort, parsed.DstPort)
			}
			if !bytes.Equal(parsed.Payload, tt.input.Payload) {
				t.Errorf("Payload 不匹配: 期望 %s, 实际 %s", tt.input.Payload, parsed.Payload)
			}
		})
	}
}

// TestKernelXdpReflectEcho 验证内核级 XDP 原路反射程序逻辑与协议字段反转
func TestKernelXdpReflectEcho(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	_ = ebpfutil.RemoveMemlockLimit()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Skipf("当前环境特权不足以加载 XDP eBPF 对象 (跳过集成测试): %v", err)
	}
	defer objs.Close()

	// 1. 构造目标端口为 8888 的回显报文 (期望触发 XDP_TX 并交换 L2/L3/L4)
	srcMAC := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}
	srcIP := net.ParseIP("192.168.10.1")
	dstIP := net.ParseIP("192.168.10.2")
	const clientPort uint16 = 54321
	const echoPort uint16 = 8888
	payload := []byte("Echo-Google-SRE-eBPF")

	inPacket, err := BuildUDPv4Packet(PacketHeaders{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: clientPort,
		DstPort: echoPort,
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("构造 UDP 报文失败: %v", err)
	}

	ret, outPacket, err := objs.XdpReflectEcho.Test(inPacket)
	if err != nil {
		t.Fatalf("运行 BPF_PROG_TEST_RUN 失败: %v", err)
	}

	const XDP_TX = 3
	if ret != XDP_TX {
		t.Fatalf("期望返回值 XDP_TX (%d), 实际得到: %d", XDP_TX, ret)
	}

	// 验证修改后的报文
	parsedOut, err := ParseUDPv4Packet(outPacket)
	if err != nil {
		t.Fatalf("解析反射后的报文失败: %v", err)
	}

	// 验证 MAC 已互换
	if !bytes.Equal(parsedOut.SrcMAC, dstMAC) || !bytes.Equal(parsedOut.DstMAC, srcMAC) {
		t.Errorf("MAC 未正确对调: 期望 Src=%s Dst=%s, 实际 Src=%s Dst=%s",
			dstMAC, srcMAC, parsedOut.SrcMAC, parsedOut.DstMAC)
	}

	// 验证 IP 已互换
	if !parsedOut.SrcIP.Equal(dstIP) || !parsedOut.DstIP.Equal(srcIP) {
		t.Errorf("IP 未正确对调: 期望 Src=%s Dst=%s, 实际 Src=%s Dst=%s",
			dstIP, srcIP, parsedOut.SrcIP, parsedOut.DstIP)
	}

	// 验证 Port 已互换
	if parsedOut.SrcPort != echoPort || parsedOut.DstPort != clientPort {
		t.Errorf("Port 未正确对调: 期望 Src=%d Dst=%d, 实际 Src=%d Dst=%d",
			echoPort, clientPort, parsedOut.SrcPort, parsedOut.DstPort)
	}

	// 验证 Payload 完好
	if !bytes.Equal(parsedOut.Payload, payload) {
		t.Errorf("Payload 被破坏: 期望 %s, 实际 %s", payload, parsedOut.Payload)
	}

	// 2. 构造非 8888 端口报文 (期望触发 XDP_PASS 放行)
	passPacket, _ := BuildUDPv4Packet(PacketHeaders{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: clientPort,
		DstPort: 9999, // 非目标端口
		Payload: payload,
	})

	retPass, _, err := objs.XdpReflectEcho.Test(passPacket)
	if err != nil {
		t.Fatalf("运行放行用例失败: %v", err)
	}

	const XDP_PASS = 2
	if retPass != XDP_PASS {
		t.Errorf("非目标端口期望放行 XDP_PASS (%d), 实际得到: %d", XDP_PASS, retPass)
	}

	// 3. 校验 Map 统计数
	var txCount, passCount uint64
	var key0, key1 uint32 = 0, 1
	_ = objs.ReflectStats.Lookup(&key0, &passCount)
	_ = objs.ReflectStats.Lookup(&key1, &txCount)

	if txCount != 1 {
		t.Errorf("反射统计计数异常: 期望 1, 实际 %d", txCount)
	}
	if passCount != 1 {
		t.Errorf("放行统计计数异常: 期望 1, 实际 %d", passCount)
	}
}
