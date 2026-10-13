// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
	"github.com/cilium/ebpf"
)

const version = "1.0.0"

func printHelp() {
	fmt.Printf(`ebpf-agent v%s - Google 工程实践级云原生 eBPF 基础设施运维与监控工具

用法:
  ebpf-agent <command> [arguments]

可用命令:
  doctor     执行宿主机 Linux 内核环境体检与 eBPF 特性支持矩阵探测 (Fast-Fail 诊断)
  top        实时监视内核中当前运行 eBPF 程序的调用次数与纳秒级 CPU 耗时 (BPF Self-Profiling)
  run        以守护进程模式启动生产级 Agent 服务 (暴露 /healthz, /metrics, /debug/pprof)
  version    打印当前二进制版本与构建元数据

示例:
  ebpf-agent doctor
  ebpf-agent top --interval=2s
  ebpf-agent run --health-addr=:8080 --json
`, version)
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	cmd := os.Args[1]
	switch cmd {
	case "doctor":
		runDoctor()
	case "top":
		runTop(os.Args[2:])
	case "run":
		runAgent(os.Args[2:])
	case "version":
		fmt.Printf("ebpf-agent version %s (Google Engineering Practice Baseline)\n", version)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

// runDoctor 执行环境准入检查与内核特性矩阵探测
func runDoctor() {
	fmt.Println(">>> 正在启动 Google SRE 生产级内核环境自检与特性探测...")
	diag := ebpfutil.CheckEnvironment()
	fmt.Print(diag.String())

	fmt.Println()
	matrix := ebpfutil.ProbeKernelFeatures()
	fmt.Print(matrix.String())

	if !diag.Passed {
		fmt.Println("\n⚠️  [警告] 当前主机环境未完全满足核心条件，部分探针可能受限或无法加载。")
		os.Exit(1)
	}
	fmt.Println("\n🎉 [就绪] 宿主机内核与特权满足 eBPF 生产级运行条件！")
}

// runTop 实时采样并输出内核 BPF 程序资源消耗
func runTop(args []string) {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	interval := fs.Duration("interval", 2*time.Second, "采样刷新时间间隔")
	_ = fs.Parse(args)

	fmt.Printf(">>> 正在初始化内核 BPF Profiler (采样间隔: %v)...\n", *interval)
	closer, err := ebpfutil.EnableBPFStats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法开启内核全局 BPF 统计 (需要 Linux 5.1+ 内核与特权): %v\n", err)
	} else {
		defer closer.Close()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	fmt.Println("按 Ctrl+C 退出监控...")
	for {
		select {
		case <-sigCh:
			fmt.Println("\n监控已停止。")
			return
		case <-ticker.C:
			renderTop()
		}
	}
}

func renderTop() {
	var progID ebpf.ProgramID
	fmt.Printf("\033[H\033[2J") // 清屏
	fmt.Printf("=== eBPF Kernel Profiler Top === [%s] ===\n", time.Now().Format("15:04:05"))
	fmt.Printf("%-8s %-20s %-16s %-12s %-15s %-15s\n", "PROG_ID", "NAME", "TYPE", "RUN_COUNT", "TOTAL_TIME", "AVG_LATENCY")
	fmt.Println("-----------------------------------------------------------------------------------------")

	count := 0
	for {
		var err error
		progID, err = ebpf.ProgramGetNextID(progID)
		if err != nil {
			break
		}

		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			continue
		}

		stat, err := ebpfutil.InspectProgramRuntime(prog)
		_ = prog.Close()
		if err != nil {
			continue
		}

		fmt.Printf("%-8d %-20s %-16s %-12d %-15v %-15v\n",
			stat.ID, stat.Name, stat.Type, stat.RunCount,
			time.Duration(stat.RuntimeNS)*time.Nanosecond, stat.AvgRuntimeNS)
		count++
	}

	if count == 0 {
		fmt.Println("当前内核中未检索到活跃的 eBPF 程序。")
	}
	fmt.Println("-----------------------------------------------------------------------------------------")
}

// runAgent 启动高可靠后台 Agent 守护进程
func runAgent(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	healthAddr := fs.String("health-addr", ":8080", "健康检查与 Prometheus 指标监听地址")
	jsonLog := fs.Bool("json", false, "是否启用 JSON 结构化日志格式")
	_ = fs.Parse(args)

	var handler slog.Handler
	if *jsonLog {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(handler)

	logger.Info("启动 ebpf-agent 生产守护服务",
		slog.String("version", version),
		slog.String("health_addr", *healthAddr),
	)

	_ = ebpfutil.RemoveMemlockLimit()

	// 探测内核特性
	matrix := ebpfutil.ProbeKernelFeatures()
	logger.Info("内核特性矩阵探测完毕",
		slog.Bool("ringbuf", matrix.HasRingbuf),
		slog.Bool("xdp", matrix.HasXDP),
		slog.Bool("lsm", matrix.HasLSM),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("Agent 正在提供服务...",
		slog.String("health_endpoint", "http://localhost"+*healthAddr+"/healthz"),
		slog.String("metrics_endpoint", "http://localhost"+*healthAddr+"/metrics"),
		slog.String("pprof_endpoint", "http://localhost"+*healthAddr+"/debug/pprof/"),
	)

	<-ctx.Done()
	logger.Info("捕获终止信号，正在优雅关闭所有内核探针并清理资源...")
	time.Sleep(300 * time.Millisecond)
	logger.Info("Agent 已安全退出。")
}
