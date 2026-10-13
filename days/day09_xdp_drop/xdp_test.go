package main

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// XDP 返回值宏常量
const (
	XDP_ABORTED = 0
	XDP_DROP    = 1
	XDP_PASS    = 2
	XDP_TX      = 3
	XDP_REDIRECT = 4
)

// buildSyntheticPacket 构造合成的以太网 + IPv4 + 传输层协议数据包
func buildSyntheticPacket(proto uint8) []byte {
	pkt := make([]byte, 14+20+8) // 以太首部 (14) + IP 首部 (20) + 载荷 (8)

	// 1. 以太网首部
	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Dst MAC
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}) // Src MAC
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)              // EtherType: IPv4

	// 2. IPv4 首部
	pkt[14] = 0x45                                              // Version 4, IHL 5 (20 bytes)
	pkt[15] = 0x00                                              // TOS
	binary.BigEndian.PutUint16(pkt[16:18], uint16(20+8))        // Total Length: 28
	binary.BigEndian.PutUint16(pkt[18:20], 0x1234)              // Identification
	pkt[22] = 64                                                // TTL
	pkt[23] = proto                                             // Protocol: 1 (ICMP), 6 (TCP), 17 (UDP)
	copy(pkt[26:30], []byte{192, 168, 1, 100})                  // Src IP
	copy(pkt[30:34], []byte{192, 168, 1, 1})                    // Dst IP

	// 3. 负载 (ICMP / TCP Header dummy)
	copy(pkt[34:42], []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return pkt
}

// TestXDPCustomPacketInKernel 使用 Linux BPF_PROG_TEST_RUN 特性，
// 在内存中直接运行 XDP 字节码并验证判定结果 (无需配置真实虚拟网卡与网络命名空间)
func TestXDPCustomPacketInKernel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的 XDP 内核执行测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects 失败: %v", err)
	}
	defer objs.Close()

	tests := []struct {
		name       string
		packet     []byte
		wantAction uint32
	}{
		{
			name:       "ICMP 报文 (应当被 XDP_DROP 丢弃)",
			packet:     buildSyntheticPacket(1), // IPPROTO_ICMP = 1
			wantAction: XDP_DROP,
		},
		{
			name:       "TCP 报文 (应当被 XDP_PASS 放行)",
			packet:     buildSyntheticPacket(6), // IPPROTO_TCP = 6
			wantAction: XDP_PASS,
		},
		{
			name:       "UDP 报文 (应当被 XDP_PASS 放行)",
			packet:     buildSyntheticPacket(17), // IPPROTO_UDP = 17
			wantAction: XDP_PASS,
		},
		{
			name: "ARP 报文 (EtherType=0x0806，非 IPv4，应当 XDP_PASS 放行)",
			packet: func() []byte {
				pkt := make([]byte, 28)
				binary.BigEndian.PutUint16(pkt[12:14], 0x0806) // EtherType: ARP
				return pkt
			}(),
			wantAction: XDP_PASS,
		},
		{
			name: "截断残缺 IP 报文 (仅 18 字节，不足 20 字节 IPv4 首部，边界检查生效应当 XDP_PASS 放行)",
			packet: func() []byte {
				pkt := make([]byte, 14+4)
				binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // EtherType: IPv4
				return pkt
			}(),
			wantAction: XDP_PASS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.XdpDropIcmp.Test(tt.packet)
			if err != nil {
				t.Fatalf("objs.XdpDropIcmp.Test 运行失败: %v", err)
			}

			if ret != tt.wantAction {
				t.Errorf("XDP 执行结果不匹配: got %d, want %d", ret, tt.wantAction)
			}
		})
	}
}
