package ebpfutil

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// FormatVerifierError 格式化并高亮 eBPF 内核验证器 (Verifier) 输出的拒绝日志。
//
// 研发背景与第一性原理：
// Linux eBPF 验证器采用抽象解释 (Abstract Interpretation) 技术遍历所有可能的指令执行分支，
// 验证内存访问是否越界、指针运算是否合法、寄存器类型是否匹配、是否包含无限循环等。
// 当程序被内核拒绝时，原始日志长达数百甚至上千行。本工具自动提取尾部关键拒绝指令并结构化输出。
func FormatVerifierError(err error) string {
	if err == nil {
		return ""
	}

	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return fmt.Sprintf("通用错误 (非 Verifier 拒绝): %v", err)
	}

	var sb strings.Builder
	sb.WriteString("\n========== [eBPF Verifier 拒绝诊断] ==========\n")
	sb.WriteString(fmt.Sprintf("错误摘要: %v\n", err))
	sb.WriteString("----------------- 内核验证器详细执行轨迹 -----------------\n")

	// 打印全部或尾部关键 Verifier 步骤
	lines := strings.Split(fmt.Sprintf("%+v", ve), "\n")
	start := 0
	if len(lines) > 60 {
		start = len(lines) - 60
		sb.WriteString(fmt.Sprintf("... (前置 %d 行指令验证已省略，仅展示最后 60 行关键判断) ...\n", start))
	}

	for i := start; i < len(lines); i++ {
		line := lines[i]
		if strings.Contains(line, "R0") || strings.Contains(line, "invalid") || strings.Contains(line, "unbounded") {
			sb.WriteString(fmt.Sprintf(">> %s\n", line))
		} else {
			sb.WriteString(fmt.Sprintf("   %s\n", line))
		}
	}
	sb.WriteString("========================================================\n")
	return sb.String()
}
