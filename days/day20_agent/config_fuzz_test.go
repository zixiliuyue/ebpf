// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"testing"
)

// FuzzConfigParsing 对 Agent 的 JSON 动态配置反序列化及校验执行 Go 原生模糊测试 (Google SRE 防御性设计)
// 目的：验证在云原生动态下发或 SIGHUP 热重载不可信配置时，解析器不会发生内存溢出、panic 或死锁，
// 且只有通过严格契约校验的合法配置才能成功构建。
func FuzzConfigParsing(f *testing.F) {
	// 1. 种子语料库构建 (Seed Corpus)
	// 语料 A: 标准合法配置 JSON
	standardCfg := Config{
		AgentName:   "production-agent-01",
		HealthAddr:  ":8080",
		EnableProbe: true,
		LogLevel:    "INFO",
		JSONLog:     true,
		PinPath:     "/sys/fs/bpf/prod_agent",
	}
	standardBytes, _ := json.Marshal(standardCfg)
	f.Add(standardBytes)

	// 语料 B: 空数据
	f.Add([]byte{})

	// 语料 C: 空 JSON 对象
	f.Add([]byte("{}"))

	// 语料 D: 只有部分字段的 JSON
	f.Add([]byte(`{"agent_name": "partial-agent"}`))
	f.Add([]byte(`{"health_addr": ":9090"}`))

	// 语料 E: 语法错误的非闭合 JSON
	f.Add([]byte(`{"agent_name": "unclosed`))

	// 语料 F: 包含特殊 Unicode、换行与超长字符串的 JSON
	f.Add([]byte(`{"agent_name": "\u0000\u001f\n\t\r", "health_addr": "::1:65535", "log_level": "DEBUG"}`))

	// 2. 模糊测试执行循环
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseConfig(data)
		if err != nil {
			// 解析或校验失败时指针必须为 nil，符合 Google API 错误语义
			if cfg != nil {
				t.Fatalf("解析失败但返回的 Config 指针非空")
			}
			return
		}

		// 解析成功的不变式校验 (Invariants Check)
		if cfg == nil {
			t.Fatalf("解析成功但返回的 Config 为 nil")
		}

		// 必须满足基本契约：AgentName 与 HealthAddr 不能为空
		if cfg.AgentName == "" {
			t.Fatalf("通过校验的配置 AgentName 意外为空")
		}
		if cfg.HealthAddr == "" {
			t.Fatalf("通过校验的配置 HealthAddr 意外为空")
		}

		// 测试配置对象与 Agent 实例构造的兼容性与热重载安全性
		agent, err := NewAgent(*cfg, nil)
		if err != nil {
			t.Fatalf("有效配置无法构造 Agent: %v", err)
		}

		// 验证热重载自身不发生 panic
		_ = agent.ReloadConfig(*cfg)
	})
}
