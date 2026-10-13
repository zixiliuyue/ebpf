// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime"
	"testing"
)

// TestIsSuspiciousPath 表驱动单测验证路径准入过滤规则
func TestIsSuspiciousPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/usr/bin/ls", false},
		{"/bin/bash", false},
		{"/usr/local/bin/myagent", false},
		{"/tmp/malware.sh", true},
		{"/tmp/a.out", true},
		{"/var/tmp/script", false},
	}

	for _, tt := range tests {
		got := IsSuspiciousPath(tt.path)
		if got != tt.want {
			t.Errorf("IsSuspiciousPath(%q) = %v, 期望 %v", tt.path, got, tt.want)
		}
	}
}

// TestKernelLsmExecLoad 验证内核装载 LSM 进程拦截程序有效性
func TestKernelLsmExecLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		if !IsLSMSupported(err) {
			t.Skipf("当前 Linux 内核未开启 CONFIG_BPF_LSM=y，跳过: %v", err)
		}
		t.Fatalf("加载 LSM 进程拦截字节码失败: %v", err)
	}
	defer objs.Close()

	if objs.LsmBprmCheck == nil {
		t.Fatal("LsmBprmCheck 程序对象为空")
	}
	if objs.ExecLsmStats == nil {
		t.Fatal("ExecLsmStats 统计 Map 为空")
	}
}
