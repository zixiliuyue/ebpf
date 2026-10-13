// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestPrintHelp 验证 CLI 帮助文档包含所有核心子命令与 Google 工程实践标注
func TestPrintHelp(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建管道失败: %v", err)
	}
	os.Stdout = w

	printHelp()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	expectedKeywords := []string{
		"doctor",
		"top",
		"run",
		"version",
		"Google 工程实践级",
	}

	for _, kw := range expectedKeywords {
		if !strings.Contains(output, kw) {
			t.Errorf("帮助输出缺少关键字: %s\n完整输出:\n%s", kw, output)
		}
	}
}

// TestRunDoctorExecution 验证环境诊断命令能够安全执行并输出诊断报告（不抛出 panic）
func TestRunDoctorExecution(t *testing.T) {
	// 捕获可能由特权缺失引起的输出，确保其不 panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runDoctor 执行触发异常 panic: %v", r)
		}
	}()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建管道失败: %v", err)
	}
	os.Stdout = w

	runDoctor()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "eBPF 运行环境诊断报告") {
		t.Errorf("诊断输出未包含环境报告标题，输出为: %s", output)
	}
}
