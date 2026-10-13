// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/metric_collector.c

// FormatPrometheusMetrics 纯函数生成标准 Prometheus OpenMetrics 格式文本
func FormatPrometheusMetrics(openatCount, execveCount uint64) string {
	return fmt.Sprintf(`# HELP ebpf_syscall_total Total count of monitored system calls intercepted by eBPF
# TYPE ebpf_syscall_total counter
ebpf_syscall_total{syscall="openat"} %d
ebpf_syscall_total{syscall="execve"} %d
`, openatCount, execveCount)
}

func main() {
	log.Println(">>> 启动 Day 19: 内核状态导出与 Prometheus 监控体系...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 挂载两个核心系统调用探针
	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointOpenat, nil)
	if err != nil {
		log.Fatalf("挂载 openat tracepoint 失败: %v", err)
	}
	defer tpOpenat.Close()

	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointExecve, nil)
	if err != nil {
		log.Fatalf("挂载 execve tracepoint 失败: %v", err)
	}
	defer tpExecve.Close()

	// 注册 HTTP Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		var openatCount, execveCount uint64
		var k0, k1 uint32 = 0, 1
		_ = objs.MetricStats.Lookup(&k0, &openatCount)
		_ = objs.MetricStats.Lookup(&k1, &execveCount)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(FormatPrometheusMetrics(openatCount, execveCount)))
	})

	server := &http.Server{
		Addr:    ":9102",
		Handler: mux,
	}

	go func() {
		log.Println("[成功] Prometheus Exporter 已监听在 :9102/metrics")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("正在优雅关闭 Prometheus Exporter...")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
