package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/maps.c -- -I../../headers -I../../headers/bpf

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

// SetGlobalConfig 设置全局配置数组 Map 中的指定项
func SetGlobalConfig(m *ebpf.Map, idx uint32, val uint64) error {
	if m == nil {
		return errors.New("map 实例不能为空")
	}
	return m.Put(idx, val)
}

// GetProcessCount 查询指定 PID 的统计值
func GetProcessCount(m *ebpf.Map, pid uint32) (uint64, error) {
	if m == nil {
		return 0, errors.New("map 实例不能为空")
	}
	var count uint64
	if err := m.Lookup(pid, &count); err != nil {
		return 0, err
	}
	return count, nil
}

// DumpAllProcessCounts 遍历 Hash Map 并导出当前所有进程的统计指标
func DumpAllProcessCounts(m *ebpf.Map) (map[uint32]uint64, error) {
	if m == nil {
		return nil, errors.New("map 实例不能为空")
	}

	result := make(map[uint32]uint64)
	var key uint32
	var val uint64

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		result[key] = val
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("遍历 Map 失败: %w", err)
	}
	return result, nil
}

func main() {
	log.Println(">>> 启动 Day 03: eBPF Maps (Hash Map & Array Map) 深度实战...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF Map 对象失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 1. 开启监控开关 (将 global_config 索引 0 置为 1)
	if err := SetGlobalConfig(objs.GlobalConfig, 0, 1); err != nil {
		log.Fatalf("[错误] 启用全局监控开关失败: %v", err)
	}
	log.Println("[成功] 全局监控开关已写入 Array Map (idx=0, val=1)")

	// 2. 挂载到 tracepoint/syscalls/sys_enter_openat
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceEnterOpenat, nil)
	if err != nil {
		log.Fatalf("[错误] 挂载 sys_enter_openat 失败: %v", err)
	}
	defer tp.Close()

	log.Println("[成功] 探针挂载就绪，正在实时统计 openat 系统调用...")
	log.Println("按 Ctrl+C 退出程序并打印汇总")

	// 3. 定时器轮询打印 Map 状态
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			log.Println("\n[退出] 正在导出最终 Map 统计数据...")
			stats, _ := DumpAllProcessCounts(objs.ProcExecCounts)
			for pid, count := range stats {
				log.Printf("PID: %-6d => openat 累计调用: %d\n", pid, count)
			}
			return
		case <-ticker.C:
			stats, err := DumpAllProcessCounts(objs.ProcExecCounts)
			if err == nil && len(stats) > 0 {
				log.Printf("当前监控进程数: %d，最近更新 Top 3:\n", len(stats))
				i := 0
				for pid, count := range stats {
					log.Printf("  PID: %-6d => 调用数: %d\n", pid, count)
					i++
					if i >= 3 {
						break
					}
				}
			}
		}
	}
}
