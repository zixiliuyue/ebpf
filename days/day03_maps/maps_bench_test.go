package main

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
)

// BenchmarkBPFHashMapOps 对内核态 BPF Hash Map 增删改查进行微基准测试
// Google 生产级测试：量化用户态通过系统调用访问 BPF Map 的开销
func BenchmarkBPFHashMapOps(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("跳过非 Linux 环境的 BPF Map 基准测试")
	}

	hashSpec := &ebpf.MapSpec{
		Name:       "bench_hash_map",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 10000,
	}

	m, err := ebpf.NewMap(hashSpec)
	if err != nil {
		b.Skipf("无法创建 BPF Map (缺少内核特权): %v", err)
	}
	defer m.Close()

	key := uint32(1)
	val := uint64(100)
	_ = m.Put(key, val)

	b.Run("MapLookup", func(b *testing.B) {
		b.ReportAllocs()
		var out uint64
		for i := 0; i < b.N; i++ {
			if err := m.Lookup(&key, &out); err != nil {
				b.Fatalf("Lookup 失败: %v", err)
			}
		}
	})

	b.Run("MapPut", func(b *testing.B) {
		b.ReportAllocs()
		var updateVal uint64 = 200
		for i := 0; i < b.N; i++ {
			if err := m.Put(&key, &updateVal); err != nil {
				b.Fatalf("Put 失败: %v", err)
			}
		}
	})
}
