package main

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
)

// TestAggregatePerCPU 验证多核数组求和聚合逻辑的准确性与空边界处理
func TestAggregatePerCPU(t *testing.T) {
	tests := []struct {
		name      string
		cpuValues []uint64
		wantTotal uint64
	}{
		{
			name:      "多核非零数据聚合",
			cpuValues: []uint64{10, 20, 30, 40},
			wantTotal: 100,
		},
		{
			name:      "全零核心数据",
			cpuValues: []uint64{0, 0, 0, 0},
			wantTotal: 0,
		},
		{
			name:      "单核数据",
			cpuValues: []uint64{999},
			wantTotal: 999,
		},
		{
			name:      "空数组边界",
			cpuValues: []uint64{},
			wantTotal: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AggregatePerCPU(tt.cpuValues)
			if got != tt.wantTotal {
				t.Errorf("AggregatePerCPU() = %v, want %v", got, tt.wantTotal)
			}
		})
	}
}

// BenchmarkAggregatePerCPU 基准性能测试：验证聚合 128 核服务器指标的纳秒级延迟
func BenchmarkAggregatePerCPU(b *testing.B) {
	// 模拟 128 核超大规模服务器
	cores := make([]uint64, 128)
	for i := range cores {
		cores[i] = uint64(i * 10)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AggregatePerCPU(cores)
	}
}

// TestKernelPerCPUMap 在 Linux 环境下拉起真实 Per-CPU Map 验证底层读写
func TestKernelPerCPUMap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的 Per-CPU 内核测试")
	}

	spec := &ebpf.MapSpec{
		Name:       "test_percpu_map",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatalf("创建 PerCPUArray 失败: %v", err)
	}
	defer m.Close()

	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("获取系统 CPU 核心数失败: %v", err)
	}

	// 写入初始切片 (每个核心赋不同的初值)
	initValues := make([]uint64, numCPU)
	var expectedTotal uint64
	for i := 0; i < numCPU; i++ {
		initValues[i] = uint64(i + 1)
		expectedTotal += initValues[i]
	}

	key := uint32(0)
	if err := m.Put(key, initValues); err != nil {
		t.Fatalf("m.Put 失败: %v", err)
	}

	total, perCPU, err := ReadPerCPUCounter(m, key)
	if err != nil {
		t.Fatalf("ReadPerCPUCounter 失败: %v", err)
	}

	if total != expectedTotal {
		t.Errorf("聚合值不匹配: got %d, want %d", total, expectedTotal)
	}
	if len(perCPU) != numCPU {
		t.Errorf("核心数不匹配: got %d, want %d", len(perCPU), numCPU)
	}
}
