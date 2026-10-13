package ebpfutil

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// EnvDiagnostic 记录 eBPF 运行环境的诊断结果
type EnvDiagnostic struct {
	OS            string // 操作系统 (如 linux, darwin)
	Arch          string // CPU 架构 (amd64, arm64)
	KernelRelease string // 内核版本字符串 (如 6.6.0-generic)
	HasBTF        bool   // 是否支持 /sys/kernel/btf/vmlinux
	HasDebugFS    bool   // /sys/kernel/debug 是否已挂载
	HasTraceFS    bool   // /sys/kernel/tracing 或 /sys/kernel/debug/tracing 是否可用
	IsRoot        bool   // 当前用户是否具备 root 权限 (UID == 0)
	Passed        bool   // 核心条件是否全部满足
	Issues        []string
}

// CheckEnvironment 对当前主机的内核与虚拟文件系统进行 Google SRE 风格的就绪检查。
// 该检查在 Agent 启动初期执行，若环境不满足条件则快速失败 (Fast-Fail) 并输出精准排障建议。
func CheckEnvironment() EnvDiagnostic {
	diag := EnvDiagnostic{
		OS:     runtime.GOOS,
		Arch:   runtime.GOARCH,
		IsRoot: os.Geteuid() == 0,
		Issues: make([]string, 0),
	}

	if runtime.GOOS != "linux" {
		diag.Issues = append(diag.Issues, fmt.Sprintf("当前系统为 %s，eBPF 程序必须在 Linux 内核上运行 (请使用提供的 Docker 环境)", runtime.GOOS))
		diag.Passed = false
		return diag
	}

	// 1. 获取 Linux 内核版本
	var uname unix.Utsname
	if err := unix.Uname(&uname); err == nil {
		diag.KernelRelease = string(bytes.TrimRight(uname.Release[:], "\x00"))
	} else {
		diag.Issues = append(diag.Issues, fmt.Sprintf("无法读取内核版本信息: %v", err))
	}

	// 2. 检查内核 BTF (BPF Type Format) 支持，BTF 是现代 CO-RE (Compile Once - Run Everywhere) 的基石
	btfPath := "/sys/kernel/btf/vmlinux"
	if fi, err := os.Stat(btfPath); err == nil && !fi.IsDir() {
		diag.HasBTF = true
	} else {
		diag.Issues = append(diag.Issues, "内核未启用或未挂载 /sys/kernel/btf/vmlinux (需要 Linux 5.8+ 且启用 CONFIG_DEBUG_INFO_BTF=y)")
	}

	// 3. 检查 DebugFS 与 TraceFS 是否正确挂载 (Kprobe/Tracepoint 需要依赖 tracefs)
	if _, err := os.Stat("/sys/kernel/debug"); err == nil {
		diag.HasDebugFS = true
	} else {
		diag.Issues = append(diag.Issues, "/sys/kernel/debug 未挂载，部分旧内核 Tracepoint 探测点可能不可用")
	}

	if _, err := os.Stat("/sys/kernel/tracing"); err == nil {
		diag.HasTraceFS = true
	} else if _, err := os.Stat("/sys/kernel/debug/tracing"); err == nil {
		diag.HasTraceFS = true
	} else {
		diag.Issues = append(diag.Issues, "TraceFS 路径 (/sys/kernel/tracing 或 /sys/kernel/debug/tracing) 不可访问")
	}

	// 4. 检查特权权限
	if !diag.IsRoot {
		diag.Issues = append(diag.Issues, "当前用户非 root (UID != 0)，加载 eBPF 程序通常需要 CAP_BPF、CAP_PERFMON 或 CAP_SYS_ADMIN 特权")
	}

	// 若在 Linux 下且具备 root、BTF，则视为通过核心要求
	diag.Passed = (runtime.GOOS == "linux") && diag.IsRoot && diag.HasBTF
	return diag
}

// String 格式化输出人类可读的环境检查报告
func (d EnvDiagnostic) String() string {
	var sb strings.Builder
	sb.WriteString("================= eBPF 运行环境诊断报告 =================\n")
	sb.WriteString(fmt.Sprintf("平台架构: %s/%s\n", d.OS, d.Arch))
	sb.WriteString(fmt.Sprintf("内核版本: %s\n", d.KernelRelease))
	sb.WriteString(fmt.Sprintf("Root 权限: %t\n", d.IsRoot))
	sb.WriteString(fmt.Sprintf("内核 BTF: %t (/sys/kernel/btf/vmlinux)\n", d.HasBTF))
	sb.WriteString(fmt.Sprintf("DebugFS : %t (/sys/kernel/debug)\n", d.HasDebugFS))
	sb.WriteString(fmt.Sprintf("TraceFS : %t (/sys/kernel/tracing)\n", d.HasTraceFS))
	sb.WriteString(fmt.Sprintf("综合准入: %t\n", d.Passed))
	if len(d.Issues) > 0 {
		sb.WriteString("发现的潜在问题或警告:\n")
		for i, issue := range d.Issues {
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, issue))
		}
	}
	sb.WriteString("=========================================================\n")
	return sb.String()
}
