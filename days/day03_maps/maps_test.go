package main

import (
	"errors"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
)

// TestMapInputValidation 验证用户态针对空 Map 保护的防御性编程
func TestMapInputValidation(t *testing.T) {
	if err := SetGlobalConfig(nil, 0, 1); err == nil {
		t.Error("期望空 Map 返回错误，实际返回 nil")
	}

	if _, err := GetProcessCount(nil, 100); err == nil {
		t.Error("期望空 Map 查询返回错误，实际返回 nil")
	}

	if _, err := DumpAllProcessCounts(nil); err == nil {
		t.Error("期望空 Map 遍历返回错误，实际返回 nil")
	}
}

// TestKernelMapOperations 在特权环境下拉起真实的 BPF Map 验证增删改查
func TestKernelMapOperations(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的 BPF Map 内核测试")
	}

	// 1. 创建临时的 BPF Hash Map
	hashSpec := &ebpf.MapSpec{
		Name:       "test_hash_map",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 10,
	}

	m, err := ebpf.NewMap(hashSpec)
	if err != nil {
		t.Fatalf("创建测试 Hash Map 失败: %v", err)
	}
	defer m.Close()

	// 2. 测试写入 (Put)
	testPID := uint32(10086)
	testVal := uint64(42)
	if err := m.Put(testPID, testVal); err != nil {
		t.Fatalf("Map.Put 失败: %v", err)
	}

	// 3. 测试读取 (Get)
	val, err := GetProcessCount(m, testPID)
	if err != nil {
		t.Fatalf("GetProcessCount 失败: %v", err)
	}
	if val != testVal {
		t.Errorf("查询值不匹配: got %d, want %d", val, testVal)
	}

	// 4. 测试未命中 Key (Key Not Found)
	_, err = GetProcessCount(m, 99999)
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("期望返回 ebpf.ErrKeyNotExist，实际得到: %v", err)
	}

	// 5. 测试遍历 (Iterate)
	dump, err := DumpAllProcessCounts(m)
	if err != nil {
		t.Fatalf("DumpAllProcessCounts 失败: %v", err)
	}
	if len(dump) != 1 || dump[testPID] != testVal {
		t.Errorf("Dump 数据不符合预期: %+v", dump)
	}

	// 6. 测试删除 (Delete)
	if err := m.Delete(testPID); err != nil {
		t.Fatalf("Map.Delete 失败: %v", err)
	}
	_, err = GetProcessCount(m, testPID)
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("删除后查询应返回 ErrKeyNotExist，实际得到: %v", err)
	}
}
