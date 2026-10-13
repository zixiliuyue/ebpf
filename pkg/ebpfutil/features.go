package ebpfutil

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// KernelFeatureMatrix 描述当前宿主机 Linux 内核对各类 eBPF 特性的支持矩阵
// Google SRE 生产实践：在初始化挂载探针前进行能力探测，根据矩阵决定是否降级或启用特定功能
type KernelFeatureMatrix struct {
	HasRingbuf        bool // 内核是否支持 BPF RingBuffer (Linux 5.8+)
	HasPerCPUMaps     bool // 是否支持 Per-CPU 类型的 Map (Hash/Array)
	HasLSM            bool // 内核是否支持 BPF LSM 安全探针 (Linux 5.7+ 且开启 LSM BPF)
	HasXDP            bool // 是否支持 XDP 网络驱动层快速处理
	HasTC             bool // 是否支持 TC (Traffic Control) 流量调度
	HasSockops        bool // 是否支持 SockOps 协议栈行为监控
	HasSockmap        bool // 是否支持 SockMap/SkMsg 零拷贝重定向
	HasTracepoints    bool // 是否支持内核静态跟踪点
	HasProgramTestRun bool // 是否支持 BPF_PROG_TEST_RUN 内存沙箱测试
}

// ProbeKernelFeatures 探测当前运行环境的内核 eBPF 特性支持情况。
// 探测过程通过微小的临时系统调用探测完成，不产生持久性内核副作用。
func ProbeKernelFeatures() KernelFeatureMatrix {
	matrix := KernelFeatureMatrix{}

	// 1. 探测 RingBuffer (MapType RingBuf)
	if err := features.HaveMapType(ebpf.RingBuf); err == nil {
		matrix.HasRingbuf = true
	}

	// 2. 探测 PerCPU Array Map
	if err := features.HaveMapType(ebpf.PerCPUArray); err == nil {
		matrix.HasPerCPUMaps = true
	}

	// 3. 探测 LSM 程序类型
	if err := features.HaveProgramType(ebpf.LSM); err == nil {
		matrix.HasLSM = true
	}

	// 4. 探测 XDP 程序类型
	if err := features.HaveProgramType(ebpf.XDP); err == nil {
		matrix.HasXDP = true
	}

	// 5. 探测 SchedCLS / TC 流量控制
	if err := features.HaveProgramType(ebpf.SchedCLS); err == nil {
		matrix.HasTC = true
	}

	// 6. 探测 SockOps
	if err := features.HaveProgramType(ebpf.SockOps); err == nil {
		matrix.HasSockops = true
	}

	// 7. 探测 SkMsg (SockMap 重定向)
	if err := features.HaveProgramType(ebpf.SkMsg); err == nil {
		matrix.HasSockmap = true
	}

	// 8. 探测 Tracepoint
	if err := features.HaveProgramType(ebpf.TracePoint); err == nil {
		matrix.HasTracepoints = true
	}

	// 9. 探测 BPF_PROG_TEST_RUN 支持 (使用轻量级 SocketFilter 指令)
	testProgSpec := &ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	}
	if prog, err := ebpf.NewProgram(testProgSpec); err == nil {
		// 尝试执行一次 14 字节的伪数据包测试
		dummyPkt := make([]byte, 14)
		if _, _, err := prog.Test(dummyPkt); err == nil {
			matrix.HasProgramTestRun = true
		}
		_ = prog.Close()
	}

	return matrix
}

// Summary 将矩阵转换为 map 便于序列化或指标导出
func (m KernelFeatureMatrix) Summary() map[string]bool {
	return map[string]bool{
		"ringbuf":       m.HasRingbuf,
		"percpu_maps":   m.HasPerCPUMaps,
		"lsm":           m.HasLSM,
		"xdp":           m.HasXDP,
		"tc":            m.HasTC,
		"sockops":       m.HasSockops,
		"sockmap":       m.HasSockmap,
		"tracepoints":   m.HasTracepoints,
		"prog_test_run": m.HasProgramTestRun,
	}
}

// String 格式化输出人类可读的特性矩阵诊断表
func (m KernelFeatureMatrix) String() string {
	var sb strings.Builder
	sb.WriteString("================= Linux 内核 eBPF 特性支持矩阵 =================\n")
	formatLine := func(name string, supported bool, note string) {
		status := "✅ 支持"
		if !supported {
			status = "❌ 未就绪/不支持"
		}
		sb.WriteString(fmt.Sprintf("%-22s: %-12s (%s)\n", name, status, note))
	}

	formatLine("BPF RingBuffer", m.HasRingbuf, "Linux 5.8+ 高性能无锁环形缓冲区")
	formatLine("Per-CPU BPF Maps", m.HasPerCPUMaps, "CPU 隔离高并发原子计数与聚合")
	formatLine("eBPF LSM 安全探针", m.HasLSM, "Linux 5.7+ 运行时内核访问控制与防篡改")
	formatLine("XDP 网络驱动层加速", m.HasXDP, "网卡极速包过滤与微秒级防 DDoS")
	formatLine("TC 流量控制", m.HasTC, "Egress/Ingress 全双工数据包标记与重定向")
	formatLine("TCP SockOps", m.HasSockops, "TCP 握手与连接生命周期实时监控")
	formatLine("SockMap / SkMsg", m.HasSockmap, "套接字零拷贝加速与协议栈绕行")
	formatLine("Tracepoint 跟踪点", m.HasTracepoints, "稳定内核事件追踪")
	formatLine("BPF_PROG_TEST_RUN", m.HasProgramTestRun, "内核内存级确定性测试运行")
	sb.WriteString("=================================================================\n")
	return sb.String()
}
