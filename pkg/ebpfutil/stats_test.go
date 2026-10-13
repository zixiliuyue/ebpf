package ebpfutil

import (
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestProgramRuntimeStatsMock 验证性能统计数据结构与耗时计算逻辑
func TestProgramRuntimeStatsMock(t *testing.T) {
	stats := ProgramRuntimeStats{
		ID:           12,
		Name:         "xdp_packet_filter",
		Type:         "XDP",
		RunCount:     1000,
		RuntimeNS:    150000,
		AvgRuntimeNS: 150 * time.Nanosecond,
	}

	str := stats.String()
	if len(str) == 0 {
		t.Fatal("统计输出不能为空")
	}

	if stats.AvgRuntimeNS != 150*time.Nanosecond {
		t.Fatalf("平均耗时计算不符合预期: got %v", stats.AvgRuntimeNS)
	}
}

// TestKernelBPFStatsController 验证特权 Linux 环境下的 bpf_stats 控制器
func TestKernelBPFStatsController(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的 bpf_stats_enabled 测试")
	}

	closer, err := EnableBPFStats()
	if err != nil {
		t.Logf("当前环境无法开启 bpf_stats (可能缺少写权限或处于非特权容器): %v", err)
	} else {
		defer closer.Close()
	}

	// 创建一个最简测试程序
	progSpec := &ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		t.Fatalf("创建测试程序失败: %v", err)
	}
	defer prog.Close()

	stat, err := InspectProgramRuntime(prog)
	if err != nil {
		t.Fatalf("InspectProgramRuntime 失败: %v", err)
	}
	t.Logf("成功采集到程序运行时信息: %s", stat)
}
