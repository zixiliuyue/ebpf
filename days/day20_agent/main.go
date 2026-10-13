package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// ProcessMonitorPlugin 示例进程监听插件
type ProcessMonitorPlugin struct {
	running bool
}

func (p *ProcessMonitorPlugin) Name() string {
	return "process_monitor"
}

func (p *ProcessMonitorPlugin) Init(ctx context.Context) error {
	return nil
}

func (p *ProcessMonitorPlugin) Start(ctx context.Context) error {
	p.running = true
	return nil
}

func (p *ProcessMonitorPlugin) Stop() error {
	p.running = false
	return nil
}

func (p *ProcessMonitorPlugin) Health() error {
	if !p.running {
		return context.Canceled
	}
	return nil
}

func main() {
	healthAddr := flag.String("health-addr", ":8080", "健康探针与 Prometheus HTTP 监听地址")
	jsonLog := flag.Bool("json", false, "是否启用 JSON 结构化日志输出")
	flag.Parse()

	var handler slog.Handler
	if *jsonLog {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	logger.Info("启动 Day 20: 生产级云原生 eBPF 可观测性与安全 Agent")

	// 1. 宿主机与内核环境前置自检
	diag := ebpfutil.CheckEnvironment()
	logger.Info("内核环境自检完成",
		slog.String("kernel", diag.KernelRelease),
		slog.Bool("btf", diag.HasBTF),
		slog.Bool("is_root", diag.IsRoot),
	)

	// 2. 解除锁页内存限制
	_ = ebpfutil.RemoveMemlockLimit()

	// 3. 构建 Agent 配置并实例化
	cfg := Config{
		AgentName:   "google-sre-ebpf-agent",
		HealthAddr:  *healthAddr,
		EnableProbe: true,
		LogLevel:    "INFO",
		JSONLog:     *jsonLog,
	}

	agent, err := NewAgent(cfg, logger)
	if err != nil {
		logger.Error("初始化 Agent 失败", slog.Any("error", err))
		os.Exit(1)
	}

	// 4. 注册插件
	_ = agent.RegisterPlugin(&ProcessMonitorPlugin{})

	// 5. 注册信号处理 (SIGINT/SIGTERM 优雅停机，SIGHUP 动态热重载)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			logger.Info("接收到 SIGHUP 信号，触发配置动态热重载...")
			_ = agent.ReloadConfig(cfg)
		}
	}()

	if err := agent.Start(ctx); err != nil {
		logger.Error("启动 Agent 失败", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("Agent 已正常启动",
		slog.String("health_endpoint", "http://localhost"+*healthAddr+"/healthz"),
		slog.String("metrics_endpoint", "http://localhost"+*healthAddr+"/metrics"),
		slog.String("pprof_endpoint", "http://localhost"+*healthAddr+"/debug/pprof/"),
	)

	// 阻塞等待系统中断信号
	<-ctx.Done()
	logger.Info("捕获停机信号，开始执行 Google 生产级优雅下线流程...")

	if err := agent.Stop(); err != nil {
		logger.Warn("停机过程中产生非致命错误", slog.Any("error", err))
	}
	logger.Info("Agent 资源已全部释放，安全退出。")
}
