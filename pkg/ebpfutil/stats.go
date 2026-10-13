package ebpfutil

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const bpfStatsSysctl = "/proc/sys/kernel/bpf_stats_enabled"

// BPFStatsController 控制内核 BPF 统计全局开关
// Google SRE 生产防线：在收集探针耗时时按需开启，并在停机时恢复原始配置
type BPFStatsController struct {
	closer io.Closer
}

// EnableBPFStats 开启 Linux 内核全局 BPF 运行时统计
// 优先使用标准系统调用 BPF_ENABLE_STATS (Linux 5.8+)，若失败则尝试向 /proc/sys/kernel/bpf_stats_enabled 写入
func EnableBPFStats() (io.Closer, error) {
	// 1. 尝试使用 cilium/ebpf 的标准系统调用封装 (unix.BPF_STATS_RUN_TIME)
	closer, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err == nil {
		return closer, nil
	}

	// 2. 兼容回退：尝试通过 sysctl 文件直接写入
	data, readErr := os.ReadFile(bpfStatsSysctl)
	if readErr != nil {
		return nil, fmt.Errorf("无法通过系统调用开启统计 (%v)，且读取 %s 失败: %w", err, bpfStatsSysctl, readErr)
	}

	orig := strings.TrimSpace(string(data))
	if writeErr := os.WriteFile(bpfStatsSysctl, []byte("1\n"), 0644); writeErr != nil {
		return nil, fmt.Errorf("写入 %s 失败: %w", bpfStatsSysctl, writeErr)
	}

	return &fallbackStatsController{originalVal: orig}, nil
}

type fallbackStatsController struct {
	originalVal string
}

func (f *fallbackStatsController) Close() error {
	if f.originalVal != "" {
		_ = os.WriteFile(bpfStatsSysctl, []byte(f.originalVal+"\n"), 0644)
	}
	return nil
}

// ProgramRuntimeStats 记录单个 eBPF 探针在内核中的实际执行开销
type ProgramRuntimeStats struct {
	ID           ebpf.ProgramID
	Name         string
	Type         string
	RunCount     uint64        // 累计运行调用次数
	RuntimeNS    uint64        // 累计内核执行总耗时 (纳秒)
	AvgRuntimeNS time.Duration // 平均单次调用内核耗时
}

// InspectProgramRuntime 获取指定 eBPF 程序的运行时资源消耗 (通过 prog.Stats())
func InspectProgramRuntime(prog *ebpf.Program) (*ProgramRuntimeStats, error) {
	if prog == nil {
		return nil, fmt.Errorf("BPF Program 不能为空")
	}

	info, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("读取 BPF Info 失败: %w", err)
	}

	id, _ := info.ID()

	// 使用 cilium/ebpf 原生 ProgramInfo 获取内核运行时耗时与执行计数
	runCnt, _ := info.RunCount()
	runtimeDur, _ := info.Runtime()

	var avgDuration time.Duration
	if runCnt > 0 {
		avgDuration = time.Duration(uint64(runtimeDur) / runCnt)
	}

	return &ProgramRuntimeStats{
		ID:           id,
		Name:         info.Name,
		Type:         info.Type.String(),
		RunCount:     runCnt,
		RuntimeNS:    uint64(runtimeDur.Nanoseconds()),
		AvgRuntimeNS: avgDuration,
	}, nil
}

// String 格式化输出探针性能信息
func (s *ProgramRuntimeStats) String() string {
	return fmt.Sprintf("Prog[ID=%d, Name=%s, Type=%s]: RunCount=%d, Runtime=%d ns, AvgLatency=%v",
		s.ID, s.Name, s.Type, s.RunCount, s.RuntimeNS, s.AvgRuntimeNS)
}

// IsBPFStatsEnabled 判断当前内核是否已启用 BPF 性能统计
func IsBPFStatsEnabled() bool {
	data, err := os.ReadFile(bpfStatsSysctl)
	if err != nil {
		return false
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	return val > 0
}
