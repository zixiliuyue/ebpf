// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime"
	"testing"
)

// TestReverseSockKey 验证四元组对称反转纯函数
func TestReverseSockKey(t *testing.T) {
	orig := SockKey{
		SrcIP:   0x7F000001, // 127.0.0.1
		DstIP:   0x7F000001,
		SrcPort: 8080,
		DstPort: 9090,
	}

	rev := ReverseSockKey(orig)

	if rev.SrcPort != orig.DstPort {
		t.Errorf("SrcPort 未正确对调: 期望 %d, 实际 %d", orig.DstPort, rev.SrcPort)
	}
	if rev.DstPort != orig.SrcPort {
		t.Errorf("DstPort 未正确对调: 期望 %d, 实际 %d", orig.SrcPort, rev.DstPort)
	}
	if rev.SrcIP != orig.DstIP || rev.DstIP != orig.SrcIP {
		t.Error("IP 地址对调异常")
	}

	// 两次反转应还原
	if ReverseSockKey(rev) != orig {
		t.Error("两次反转后与原始 SockKey 不相等")
	}
}

// TestKernelSockmapLoad 验证内核装载 Sockmap 与 sk_msg 程序有效性
func TestKernelSockmapLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("加载 Sockmap BPF 对象失败: %v", err)
	}
	defer objs.Close()

	if objs.SkMsgRedirect == nil {
		t.Fatal("SkMsgRedirect 程序对象为空")
	}
	if objs.SockHash == nil {
		t.Fatal("SockHash 映射对象为空")
	}
	if objs.SockmapStats == nil {
		t.Fatal("SockmapStats 统计 Map 为空")
	}
}
