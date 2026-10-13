package main

import (
	"context"
)

// Plugin 定义 eBPF Agent 的可扩展插件接口 (Google 插件化架构规范)
// 所有功能模块 (系统调用监控、网络过滤、安全审计等) 均需实现该标准接口
type Plugin interface {
	// Name 返回插件唯一标识名称 (例如: "process_tracer", "xdp_firewall")
	Name() string

	// Init 初始化插件资源 (如加载 eBPF 规范、初始化 Map 等)
	Init(ctx context.Context) error

	// Start 启动插件后台事件监听或数据采集循环 (阻塞或启动 Goroutine)
	Start(ctx context.Context) error

	// Stop 优雅停止插件，卸载探针、关闭 Map 与环形缓冲区
	Stop() error

	// Health 返回插件健康状态，供 /healthz 探针查询
	Health() error
}
