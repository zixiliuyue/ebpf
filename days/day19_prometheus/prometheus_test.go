// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestFormatPrometheusMetrics 表驱动单测验证 Prometheus OpenMetrics 格式规范
func TestFormatPrometheusMetrics(t *testing.T) {
	tests := []struct {
		name        string
		openatCount uint64
		execveCount uint64
		wantLines   []string
	}{
		{
			name:        "零初始状态",
			openatCount: 0,
			execveCount: 0,
			wantLines: []string{
				"# HELP ebpf_syscall_total Total count of monitored system calls intercepted by eBPF",
				"# TYPE ebpf_syscall_total counter",
				`ebpf_syscall_total{syscall="openat"} 0`,
				`ebpf_syscall_total{syscall="execve"} 0`,
			},
		},
		{
			name:        "典型活跃业务指标",
			openatCount: 1530,
			execveCount: 42,
			wantLines: []string{
				`ebpf_syscall_total{syscall="openat"} 1530`,
				`ebpf_syscall_total{syscall="execve"} 42`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := FormatPrometheusMetrics(tt.openatCount, tt.execveCount)
			for _, line := range tt.wantLines {
				if !strings.Contains(output, line) {
					t.Errorf("输出未包含预期指标行: %q\n实际输出:\n%s", line, output)
				}
			}
		})
	}
}

// TestKernelPrometheusLoad 验证内核指标采集探针与 Map 装载有效性
func TestKernelPrometheusLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("加载 Prometheus 采集器 BPF 对象失败: %v", err)
	}
	defer objs.Close()

	if objs.TracepointOpenat == nil {
		t.Fatal("TracepointOpenat 程序对象为空")
	}
	if objs.TracepointExecve == nil {
		t.Fatal("TracepointExecve 程序对象为空")
	}
	if objs.MetricStats == nil {
		t.Fatal("MetricStats 统计 Map 为空")
	}
}
