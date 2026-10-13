package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config 定义 Agent 运行配置 (Google SRE 生产级配置体系)
type Config struct {
	AgentName   string `json:"agent_name"`
	HealthAddr  string `json:"health_addr"`  // 例如 ":8080"
	EnableProbe bool   `json:"enable_probe"` // 是否挂载内核探针
	LogLevel    string `json:"log_level"`    // 日志级别: "DEBUG", "INFO", "WARN", "ERROR"
	JSONLog     bool   `json:"json_log"`     // 是否启用标准 JSON 结构化输出
	PinPath     string `json:"pin_path"`     // BPF Map 持久化 Pin 挂载路径 (如 /sys/fs/bpf/myagent)
}

// Validate 校验配置合法性
func (c *Config) Validate() error {
	if c.AgentName == "" {
		return errors.New("AgentName 不能为空")
	}
	if c.HealthAddr == "" {
		return errors.New("HealthAddr 不能为空")
	}
	return nil
}

// ParseConfig 从 JSON 原始字节流反序列化并校验 Agent 配置 (Google Hermetic 解耦设计)
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("JSON 反序列化失败: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置校验不通过: %w", err)
	}
	return &cfg, nil
}

// Metrics 封装 eBPF 四大黄金指标 (Google SRE Four Golden Signals)
type Metrics struct {
	Registry       *prometheus.Registry
	EventsTotal    *prometheus.CounterVec
	EventsDropped  *prometheus.CounterVec
	LatencySeconds *prometheus.HistogramVec
	MapUtilization *prometheus.GaugeVec
}

// NewMetrics 初始化 Prometheus 指标收集器
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	eventsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ebpf_agent",
			Subsystem: "events",
			Name:      "total",
			Help:      "eBPF 内核捕获并处理的事件总数 (Traffic 黄金指标)",
		},
		[]string{"plugin", "status"},
	)

	eventsDropped := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ebpf_agent",
			Subsystem: "events",
			Name:      "dropped_total",
			Help:      "RingBuffer/Map 因拥塞丢失的事件总数 (Errors 黄金指标)",
		},
		[]string{"plugin"},
	)

	latencySeconds := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "ebpf_agent",
			Subsystem: "events",
			Name:      "latency_seconds",
			Help:      "内核事件产生到用户态消费的延迟分布 (Latency 黄金指标)",
			Buckets:   []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		},
		[]string{"plugin"},
	)

	mapUtilization := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ebpf_agent",
			Subsystem: "map",
			Name:      "utilization_ratio",
			Help:      "BPF Map 槽位当前占用率 0.0~1.0 (Saturation 黄金指标)",
		},
		[]string{"map_name"},
	)

	reg.MustRegister(eventsTotal, eventsDropped, latencySeconds, mapUtilization)

	return &Metrics{
		Registry:       reg,
		EventsTotal:    eventsTotal,
		EventsDropped:  eventsDropped,
		LatencySeconds: latencySeconds,
		MapUtilization: mapUtilization,
	}
}

// Agent 统一管理所有 eBPF 插件的生命周期、SRE 黄金指标与健康检测
type Agent struct {
	cfg     Config
	mu      sync.RWMutex
	plugins map[string]Plugin
	server  *http.Server
	cancel  context.CancelFunc
	logger  *slog.Logger
	metrics *Metrics
}

// NewAgent 构造并初始化 Agent 实例
func NewAgent(cfg Config, logger *slog.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("无效的 Agent 配置: %w", err)
	}

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	return &Agent{
		cfg:     cfg,
		plugins: make(map[string]Plugin),
		logger:  logger,
		metrics: NewMetrics(),
	}, nil
}

// GetMetrics 获取指标管理器
func (a *Agent) GetMetrics() *Metrics {
	return a.metrics
}

// RegisterPlugin 注册子插件
func (a *Agent) RegisterPlugin(p Plugin) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if p == nil {
		return errors.New("注册的插件实例不能为空")
	}
	name := p.Name()
	if _, exists := a.plugins[name]; exists {
		return fmt.Errorf("插件 %s 已重复注册", name)
	}
	a.plugins[name] = p
	a.logger.Info("插件注册成功", slog.String("plugin", name))
	return nil
}

// ReloadConfig 热重载配置 (响应 SIGHUP 信号，实现无中断平滑更新)
func (a *Agent) ReloadConfig(newCfg Config) error {
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("配置热重载校验失败: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	oldCfg := a.cfg
	a.cfg = newCfg
	a.logger.Info("Agent 配置已平滑热重载",
		slog.String("old_name", oldCfg.AgentName),
		slog.String("new_name", newCfg.AgentName),
		slog.String("log_level", newCfg.LogLevel),
	)
	return nil
}

// HealthCheckHandler 处理 HTTP /healthz 健康探针请求
func (a *Agent) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := make(map[string]string)
	hasError := false

	for name, p := range a.plugins {
		if err := p.Health(); err != nil {
			status[name] = fmt.Sprintf("unhealthy: %v", err)
			hasError = true
		} else {
			status[name] = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if hasError {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(status)
}

// Config 获取当前生效配置的只读快照 (并发安全保护)
func (a *Agent) Config() Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// Start 启动所有插件及健康检测、Prometheus 指标与 pprof 调试服务
func (a *Agent) Start(ctx context.Context) error {
	ctx, a.cancel = context.WithCancel(ctx)

	// 1. 初始化并启动所有注册的插件
	for name, p := range a.plugins {
		a.logger.Info("正在初始化插件", slog.String("plugin", name))
		if err := p.Init(ctx); err != nil {
			return fmt.Errorf("插件 %s 初始化失败: %w", name, err)
		}
		if err := p.Start(ctx); err != nil {
			return fmt.Errorf("插件 %s 启动失败: %w", name, err)
		}
	}

	// 2. 路由多路复用器挂载：健康检查、Prometheus 指标与 pprof 在线诊断
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.HealthCheckHandler)

	// 挂载 Prometheus 指标抓取路由
	mux.Handle("/metrics", promhttp.HandlerFor(a.metrics.Registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	// 挂载 pprof 性能分析探针 (Google 诊断标准)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	a.mu.RLock()
	listenAddr := a.cfg.HealthAddr
	a.mu.RUnlock()

	a.server = &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		a.logger.Info("启动管理服务",
			slog.String("addr", listenAddr),
			slog.String("endpoints", "/healthz, /metrics, /debug/pprof/"),
		)
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.logger.Error("管理服务异常退出", slog.Any("error", err))
		}
	}()

	return nil
}

// Stop 优雅关闭所有插件与网络监听，防止内核探针与内存泄漏
func (a *Agent) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var errs []error

	// 1. 关闭 HTTP 管理服务
	if a.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := a.server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("关闭 HTTP 服务失败: %w", err))
		}
	}

	// 2. 逆序停止各插件，清理 eBPF 探针
	for name, p := range a.plugins {
		a.logger.Info("正在停止插件", slog.String("plugin", name))
		if err := p.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("停止插件 %s 失败: %w", name, err))
		}
	}

	if a.cancel != nil {
		a.cancel()
	}

	if len(errs) > 0 {
		return fmt.Errorf("Agent 停止过程中出现错误: %v", errs)
	}
	a.logger.Info("Agent 已优雅退出并清理所有资源")
	return nil
}
