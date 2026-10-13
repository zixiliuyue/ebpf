package ebpfutil

import (
	"errors"
	"strings"
	"testing"
)

// TestFormatVerifierError 验证非 Verifier 错误及空错误的降级格式化
func TestFormatVerifierError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "空错误",
			err:      nil,
			contains: "",
		},
		{
			name:     "常规错误",
			err:      errors.New("permission denied"),
			contains: "通用错误 (非 Verifier 拒绝)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatVerifierError(tt.err)
			if tt.contains == "" && got != "" {
				t.Errorf("期望返回空字符串，实际得到: %s", got)
			}
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("期望包含 %q，实际为: %s", tt.contains, got)
			}
		})
	}
}
