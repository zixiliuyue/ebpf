// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestDiagnoseVerifierLog 表驱动单测验证 Verifier 经典错误诊断
func TestDiagnoseVerifierLog(t *testing.T) {
	tests := []struct {
		name          string
		logText       string
		wantIssueType string
		wantKeyword   string
	}{
		{
			name:          "Map 查询结果指针未判空",
			logText:       "0: (85) call bpf_map_lookup_elem#1\n1: (61) r1 = *(u32 *)(r0 +0)\nR0 invalid mem access 'map_value_or_null'",
			wantIssueType: "空指针解引用 (Null Pointer Dereference)",
			wantKeyword:   "判空校验",
		},
		{
			name:          "除以零错误",
			logText:       "division by zero at insn 42",
			wantIssueType: "除以零风险 (Division by Zero)",
			wantKeyword:   "除数非零",
		},
		{
			name:          "未展开循环导致指令回边",
			logText:       "back-edge from insn 10 to 4\nunbounded loop detected",
			wantIssueType: "不受限循环或未展开循环 (Unbounded Loop)",
			wantKeyword:   "pragma unroll",
		},
		{
			name:          "数据包访问越界",
			logText:       "invalid access to packet, off=14 size=20, R2(id=0,off=0,r=14)",
			wantIssueType: "报文边界越界 (Packet Bounds Check Failed)",
			wantKeyword:   "data_end",
		},
		{
			name:          "未知日志回退处理",
			logText:       "some unexpected internal verifier failure",
			wantIssueType: "未知或通用验证器拒绝",
			wantKeyword:   "详细日志",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiagnoseVerifierLog(tt.logText)
			if got.IssueType != tt.wantIssueType {
				t.Errorf("IssueType = %q, 期望 %q", got.IssueType, tt.wantIssueType)
			}
			if !strings.Contains(got.Suggestion, tt.wantKeyword) {
				t.Errorf("Suggestion = %q, 应包含关键词 %q", got.Suggestion, tt.wantKeyword)
			}
		})
	}
}

// TestKernelSafeVerifierProgLoad 验证合规安全代码能够无告警通过内核 Verifier
func TestKernelSafeVerifierProgLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("预期安全代码应当通过 Verifier，但加载失败: %v", err)
	}
	defer objs.Close()

	if objs.TracepointSafeDemo == nil {
		t.Fatal("TracepointSafeDemo 程序对象为空")
	}
	if objs.VerifierStats == nil {
		t.Fatal("VerifierStats 统计 Map 为空")
	}
}
