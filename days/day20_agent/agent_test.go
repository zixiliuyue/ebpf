package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MockPlugin 模拟测试插件
type MockPlugin struct {
	name      string
	healthErr error
	initCalls int
	stopCalls int
}

func (m *MockPlugin) Name() string { return m.name }
func (m *MockPlugin) Init(ctx context.Context) error {
	m.initCalls++
	return nil
}
func (m *MockPlugin) Start(ctx context.Context) error { return nil }
func (m *MockPlugin) Stop() error {
	m.stopCalls++
	return nil
}
func (m *MockPlugin) Health() error { return m.healthErr }

// TestConfigValidation 验证配置校验逻辑
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "合法配置",
			cfg: Config{
				AgentName:  "test-agent",
				HealthAddr: ":9090",
			},
			wantErr: false,
		},
		{
			name: "空 AgentName",
			cfg: Config{
				AgentName:  "",
				HealthAddr: ":9090",
			},
			wantErr: true,
		},
		{
			name: "空 HealthAddr",
			cfg: Config{
				AgentName:  "test-agent",
				HealthAddr: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAgentLifecycle 验证完整生命周期、插件调用、Prometheus 指标与 /healthz HTTP 端点
func TestAgentLifecycle(t *testing.T) {
	cfg := Config{
		AgentName:  "test-agent",
		HealthAddr: ":18080",
	}

	agent, err := NewAgent(cfg, nil)
	if err != nil {
		t.Fatalf("NewAgent failed: %v", err)
	}

	mockP := &MockPlugin{name: "fake_plugin"}
	if err := agent.RegisterPlugin(mockP); err != nil {
		t.Fatalf("RegisterPlugin failed: %v", err)
	}

	// 验证重复注册拦截
	if err := agent.RegisterPlugin(mockP); err == nil {
		t.Error("重复注册插件应返回错误，但返回了 nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		t.Fatalf("agent.Start failed: %v", err)
	}

	if mockP.initCalls != 1 {
		t.Errorf("Init 调用次数不符合预期: %d", mockP.initCalls)
	}

	// 1. 验证健康检查 200 OK
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	agent.HealthCheckHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("健康检查状态码期望 200, 实际得到: %d", w.Code)
	}

	// 2. 模拟插件异常，健康检查应返回 503 Service Unavailable
	mockP.healthErr = errors.New("bpf map error")
	wFail := httptest.NewRecorder()
	agent.HealthCheckHandler(wFail, req)
	if wFail.Code != http.StatusServiceUnavailable {
		t.Errorf("插件异常时期望状态码 503, 实际得到: %d", wFail.Code)
	}

	// 3. 验证 Prometheus 指标上报与采集
	metrics := agent.GetMetrics()
	metrics.EventsTotal.WithLabelValues("fake_plugin", "success").Inc()
	metrics.EventsDropped.WithLabelValues("fake_plugin").Add(5)
	metrics.LatencySeconds.WithLabelValues("fake_plugin").Observe(0.00012)
	metrics.MapUtilization.WithLabelValues("fake_map").Set(0.42)

	metricsHandler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})
	reqMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	wMetrics := httptest.NewRecorder()
	metricsHandler.ServeHTTP(wMetrics, reqMetrics)

	metricsBody := wMetrics.Body.String()
	if !strings.Contains(metricsBody, "ebpf_agent_events_total") {
		t.Error("Prometheus 暴露文本未包含 ebpf_agent_events_total")
	}
	if !strings.Contains(metricsBody, "ebpf_agent_map_utilization_ratio") {
		t.Error("Prometheus 暴露文本未包含 ebpf_agent_map_utilization_ratio")
	}

	// 4. 验证动态配置热重载 (ReloadConfig)
	newCfg := Config{
		AgentName:  "reloaded-agent",
		HealthAddr: ":18080",
		LogLevel:   "DEBUG",
	}
	if err := agent.ReloadConfig(newCfg); err != nil {
		t.Fatalf("ReloadConfig 失败: %v", err)
	}
	if agent.Config().AgentName != "reloaded-agent" {
		t.Errorf("配置热重载未更新 AgentName: %s", agent.Config().AgentName)
	}

	// 5. 验证优雅退出
	if err := agent.Stop(); err != nil {
		t.Fatalf("agent.Stop failed: %v", err)
	}
	if mockP.stopCalls != 1 {
		t.Errorf("Stop 调用次数不符合预期: %d", mockP.stopCalls)
	}
}

// TestParseConfig 针对纯函数配置解析进行表驱动测试
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		rawJSON string
		wantErr bool
	}{
		{
			name:    "合法完整 JSON",
			rawJSON: `{"agent_name": "agent-1", "health_addr": ":8080", "enable_probe": true, "log_level": "INFO"}`,
			wantErr: false,
		},
		{
			name:    "语法错误 JSON",
			rawJSON: `{"agent_name": unclosed`,
			wantErr: true,
		},
		{
			name:    "缺失必要字段 AgentName",
			rawJSON: `{"health_addr": ":8080"}`,
			wantErr: true,
		},
		{
			name:    "缺失必要字段 HealthAddr",
			rawJSON: `{"agent_name": "agent-1"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig([]byte(tt.rawJSON))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && cfg == nil {
				t.Errorf("ParseConfig() 返回空配置")
			}
		})
	}
}

// TestPprofEndpoints 验证 Google SRE 规范中的 pprof 性能分析探针路由已正确挂载并可响应
func TestPprofEndpoints(t *testing.T) {
	cfg := Config{
		AgentName:  "pprof-agent",
		HealthAddr: ":18081",
	}

	agent, err := NewAgent(cfg, nil)
	if err != nil {
		t.Fatalf("NewAgent failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		t.Fatalf("agent.Start failed: %v", err)
	}
	defer func() {
		_ = agent.Stop()
	}()

	// 验证 HTTP Server 上的 Handler 能够正确响应 /debug/pprof/ 与 /metrics
	mux := agent.server.Handler

	endpoints := []string{
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/metrics",
		"/healthz",
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("端点 %s 响应码异常，期望 200 OK，实际得到: %d", ep, w.Code)
		}
	}
}
