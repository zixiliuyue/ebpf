// SPDX-License-Identifier: Apache-2.0
package main

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ebpf-learning-20days/pkg/ebpfutil"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I../../headers" bpf bpf/verifier_demo.c

// Diagnosis 验证器错误诊断结果
type Diagnosis struct {
	IssueType  string
	Suggestion string
}

// DiagnoseVerifierLog 专家级自动化分析 Verifier 拒绝日志原因
// 纯函数设计，便于表驱动测试与自动化 CI/CD 提示
func DiagnoseVerifierLog(logText string) Diagnosis {
	switch {
	case strings.Contains(logText, "invalid mem access 'map_value_or_null'"):
		return Diagnosis{
			IssueType:  "空指针解引用 (Null Pointer Dereference)",
			Suggestion: "bpf_map_lookup_elem 返回的指针未做判空校验，请补齐 `if (!val) return 0;`",
		}
	case strings.Contains(logText, "division by zero"):
		return Diagnosis{
			IssueType:  "除以零风险 (Division by Zero)",
			Suggestion: "在执行除法或求模运算前，显式判断除数非零 `if (divisor == 0) return 0;`",
		}
	case strings.Contains(logText, "back-edge from insn") || strings.Contains(logText, "unbounded loop"):
		return Diagnosis{
			IssueType:  "不受限循环或未展开循环 (Unbounded Loop)",
			Suggestion: "循环缺少编译期常量上限，或未添加 `#pragma unroll` 强制指令展开",
		}
	case strings.Contains(logText, "invalid access to packet"):
		return Diagnosis{
			IssueType:  "报文边界越界 (Packet Bounds Check Failed)",
			Suggestion: "直接访问报文指针未严格做 `data + sizeof(...) <= data_end` 边界验证",
		}
	default:
		return Diagnosis{
			IssueType:  "未知或通用验证器拒绝",
			Suggestion: "请启用 -v 详细日志，核对上下文寄存器类型与栈深度",
		}
	}
}

func main() {
	log.Println(">>> 启动 Day 17: Verifier (验证器) 经典被拒剖析与防范实战...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		diag := DiagnoseVerifierLog(err.Error())
		log.Fatalf("[错误] 字节码未通过 Verifier: %s\n建议: %s\n原始详情: %v",
			diag.IssueType, diag.Suggestion, err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_getpid", objs.TracepointSafeDemo, nil)
	if err != nil {
		log.Fatalf("挂载 tracepoint 失败: %v", err)
	}
	defer tp.Close()

	log.Println("[成功] 经过严苛 Verifier 静态分析的安全字节码已成功挂载！")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("优雅退出 Verifier 监控...")
			return
		case <-ticker.C:
			var key uint32 = 0
			var val uint64
			_ = objs.VerifierStats.Lookup(&key, &val)
			log.Printf("[安全计算执行度量] 累计安全增量值: %d", val)
		}
	}
}
