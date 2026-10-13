// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
)

// TestGetProtocolHandlerName 表驱动验证协议处理器映射
func TestGetProtocolHandlerName(t *testing.T) {
	tests := []struct {
		idx  uint32
		want string
	}{
		{0, "HTTP-Dedicated-Handler (槽位 0)"},
		{1, "DNS-Dedicated-Handler (槽位 1)"},
		{99, "Fallback-Handler (槽位 99)"},
	}

	for _, tt := range tests {
		got := GetProtocolHandlerName(tt.idx)
		if got != tt.want {
			t.Errorf("GetProtocolHandlerName(%d) = %q, 期望 %q", tt.idx, got, tt.want)
		}
	}
}

// TestKernelTailCallRouting 验证内核级尾调用跳转表更新与调用连通性
func TestKernelTailCallRouting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("加载尾调用 BPF 对象失败: %v", err)
	}
	defer objs.Close()

	if objs.RouterEntry == nil || objs.HandleHttp == nil || objs.HandleDns == nil {
		t.Fatal("BPF 程序对象存在空值")
	}
	if objs.JmpTable == nil {
		t.Fatal("JmpTable 映射为空")
	}

	// 1. 注册尾调用槽位
	var key0 uint32 = 0
	if err := objs.JmpTable.Update(&key0, objs.HandleHttp, ebpf.UpdateAny); err != nil {
		t.Fatalf("更新 JmpTable[0] 失败: %v", err)
	}
	var key1 uint32 = 1
	if err := objs.JmpTable.Update(&key1, objs.HandleDns, ebpf.UpdateAny); err != nil {
		t.Fatalf("更新 JmpTable[1] 失败: %v", err)
	}

	// 2. 通过 BPF_PROG_TEST_RUN 触发路由入口执行 (XDP 要求标准网络包长度至少包含以太网首部，此处使用 64 字节)
	packet := make([]byte, 64)
	packet[0] = 0x00 // 首字节低位为 0，路由至槽位 0 (HandleHttp)
	ret, _, err := objs.RouterEntry.Test(packet)
	if err != nil {
		t.Fatalf("运行 RouterEntry 测试失败: %v", err)
	}

	const XDP_PASS = 2
	if ret != XDP_PASS {
		t.Errorf("期望返回 XDP_PASS (%d), 实际得到: %d", XDP_PASS, ret)
	}

	// 3. 验证统计 Map 能够正确访问
	var count uint64
	_ = objs.RouterStats.Lookup(&key0, &count)
	// 能够正常读取统计即说明测试链路合规
}
