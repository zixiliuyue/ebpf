package ebpfutil

import (
	"strings"
	"testing"
)

// TestCheckEnvironment 验证诊断逻辑在不同环境下的鲁棒性
func TestCheckEnvironment(t *testing.T) {
	diag := CheckEnvironment()

	// 验证报告基础字段不为空
	if diag.OS == "" {
		t.Errorf("期望 OS 不为空，实际为空")
	}
	if diag.Arch == "" {
		t.Errorf("期望 Arch 不为空，实际为空")
	}

	report := diag.String()
	if !strings.Contains(report, "eBPF 运行环境诊断报告") {
		t.Errorf("诊断报告缺少标题标识")
	}

	t.Logf("\n%s", report)
}
