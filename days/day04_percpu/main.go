package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/percpu.c -- -I../../headers -I../../headers/bpf

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// AggregatePerCPU 将来自每个逻辑 CPU 核心的指标进行汇总
// 遵循 Google 工程实践：将数据聚合算法抽取为纯函数，便于单测与基准性能测试 (Benchmark)
func AggregatePerCPU(cpuValues []uint64) uint64 {
	var total uint64
	for _, v := range cpuValues {
		total += v
	}
	return total
}

// ReadPerCPUCounter 读取指定 Key 的 Per-CPU 数组并聚合
func ReadPerCPUCounter(m *ebpf.Map, key uint32) (uint64, []uint64, error) {
	if m == nil {
		return 0, nil, errors.New("map 不能为空")
	}

	var perCPU []uint64
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0, nil, fmt.Errorf("读取 Per-CPU Map 失败: %w", err)
	}

	total := AggregatePerCPU(perCPU)
	return total, perCPU, nil
}

func main() {
	log.Println(">>> 启动 Day 04: Per-CPU Map 无锁化统计观测...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 对象失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 挂载到 sys_enter_write
	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceEnterWrite, nil)
	if err != nil {
		log.Fatalf("[错误] 挂载 sys_enter_write 失败: %v", err)
	}
	defer tp.Close()

	log.Println("[成功] Per-CPU 计数器探针已挂载，正在统计系统 write() 调用频次...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			total, perCPU, _ := ReadPerCPUCounter(objs.PacketCounter, 0)
			log.Printf("\n[退出] 最终统计 - 总调用次数: %d, 各核心分布: %v\n", total, perCPU)
			return
		case <-ticker.C:
			total, perCPU, err := ReadPerCPUCounter(objs.PacketCounter, 0)
			if err == nil {
				log.Printf("write() 总调用数: %-10d | 各 CPU 核心统计: %v", total, perCPU)
			}
		}
	}
}
