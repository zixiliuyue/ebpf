package ebpfutil

import (
	"runtime"
	"testing"
)

// TestProbeKernelFeatures 验证特性矩阵探测功能在不同环境下的鲁棒性
func TestProbeKernelFeatures(t *testing.T) {
	matrix := ProbeKernelFeatures()

	summary := matrix.Summary()
	if len(summary) == 0 {
		t.Fatal("特性摘要 map 不能为空")
	}

	report := matrix.String()
	if len(report) == 0 {
		t.Fatal("报告文本不能为空")
	}

	t.Logf("\n%s", report)

	// 如果是在特权 Linux 环境，核心特性应至少部分支持
	if runtime.GOOS == "linux" {
		t.Logf("Linux 运行环境探测结果: Ringbuf=%v, XDP=%v, Tracepoints=%v",
			matrix.HasRingbuf, matrix.HasXDP, matrix.HasTracepoints)
	}
}
