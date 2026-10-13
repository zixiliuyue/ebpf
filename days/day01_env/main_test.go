package main

import (
	"runtime"
	"testing"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// TestDay01Preflight 验证 Day 01 环境自检逻辑
func TestDay01Preflight(t *testing.T) {
	diag := ebpfutil.CheckEnvironment()

	if runtime.GOOS == "linux" {
		t.Logf("运行在 Linux 容器/宿主机中，内核版本: %s, BTF 支持: %t", diag.KernelRelease, diag.HasBTF)
		if !diag.HasBTF {
			t.Log("警告: 当前 Linux 内核未发现 BTF 文件，CO-RE 模式可能受限")
		}
	} else {
		t.Logf("非 Linux 平台 (%s)，正确识别并提示使用 Docker", diag.OS)
		if diag.Passed {
			t.Errorf("非 Linux 环境不应判定为 Passed=true")
		}
	}
}
