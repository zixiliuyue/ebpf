// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime"
	"testing"
)

// TestIPv4ToString 验证 IP 地址格式化纯函数
func TestIPv4ToString(t *testing.T) {
	tests := []struct {
		name string
		ip   uint32
		want string
	}{
		{
			name: "本地回环地址 127.0.0.1",
			ip:   0x7F000001,
			want: "127.0.0.1",
		},
		{
			name: "全零地址 0.0.0.0",
			ip:   0x00000000,
			want: "0.0.0.0",
		},
		{
			name: "经典局域网地址 192.168.1.1",
			ip:   0xC0A80101,
			want: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IPv4ToString(tt.ip)
			if got != tt.want {
				t.Errorf("IPv4ToString(0x%x) = %s, 期望 %s", tt.ip, got, tt.want)
			}
		})
	}
}

// TestOpName 验证 SockOps 操作码解析纯函数
func TestOpName(t *testing.T) {
	tests := []struct {
		op   uint32
		want string
	}{
		{op: 4, want: "ACTIVE_ESTABLISHED (客户端握手成功)"},
		{op: 5, want: "PASSIVE_ESTABLISHED (服务端接纳连接)"},
		{op: 7, want: "RTT (平滑往返时间采样)"},
		{op: 999, want: "UNKNOWN_OP(999)"},
	}

	for _, tt := range tests {
		got := OpName(tt.op)
		if got != tt.want {
			t.Errorf("OpName(%d) = %s, 期望 %s", tt.op, got, tt.want)
		}
	}
}

// TestKernelSockopsLoad 验证内核装载 SockOps 程序与 Map 的合规性
func TestKernelSockopsLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("加载 SockOps BPF 对象失败: %v", err)
	}
	defer objs.Close()

	if objs.BpfSockopsMonitor == nil {
		t.Fatal("BpfSockopsMonitor 程序对象为空")
	}
	if objs.SockopsStats == nil {
		t.Fatal("SockopsStats 统计 Map 为空")
	}

	// 验证 Map 最大容量为 4
	if objs.SockopsStats.MaxEntries() != 4 {
		t.Errorf("SockopsStats 容量不符合预期: 期望 4, 实际 %d", objs.SockopsStats.MaxEntries())
	}
}
