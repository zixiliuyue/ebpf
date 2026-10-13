package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/execve.c -- -I../../headers -I../../headers/bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// ProcessEvent 对应 eBPF 内核中定义的 struct event
type ProcessEvent struct {
	PID      uint32
	UID      uint32
	Comm     [16]byte
	Filename [64]byte
}

// ParseProcessEvent 从二进制字节流反序列化为 ProcessEvent 结构体，
// 遵循 Google 软件工程实践：将纯数据解析逻辑与底层 I/O 解耦，便于进行 100% 覆盖率的单元测试。
func ParseProcessEvent(raw []byte) (*ProcessEvent, error) {
	if len(raw) < int(binary.Size(ProcessEvent{})) {
		return nil, fmt.Errorf("数据包长度不足: 期望至少 %d 字节，实际得到 %d 字节", binary.Size(ProcessEvent{}), len(raw))
	}

	var ev ProcessEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("解析 ProcessEvent 失败: %w", err)
	}
	return &ev, nil
}

// CommStr 获取清洗后的字符串命令名
func (e *ProcessEvent) CommStr() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

// FilenameStr 获取清洗后的可执行文件路径
func (e *ProcessEvent) FilenameStr() string {
	n := bytes.IndexByte(e.Filename[:], 0)
	if n == -1 {
		n = len(e.Filename)
	}
	return string(e.Filename[:n])
}

func main() {
	log.Println(">>> 启动 Day 02: Tracepoint sys_enter_execve 进程监控...")

	// 1. 生产级初始化：解除锁页内存限制
	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	// 2. 加载编译生成的 eBPF 字节码到内核
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 对象失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 3. 将 eBPF 程序挂载到内核 Tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("[错误] 挂载 Tracepoint 失败: %v", err)
	}
	defer tp.Close()

	// 4. 打开 Ring Buffer 读取器
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("[错误] 打开 Ring Buffer 失败: %v", err)
	}
	defer rd.Close()

	// 5. 监听操作系统中断信号 (SIGINT, SIGTERM)，实现 Google 生产级优雅停机
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		log.Println("\n[通知] 收到退出信号，正在关闭 RingBuffer 并安全卸载探针...")
		rd.Close()
	}()

	log.Printf("%-8s %-8s %-16s %s\n", "PID", "UID", "COMM", "FILENAME")
	log.Println("----------------------------------------------------------------------")

	// 6. 事件消费循环
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[完成] RingBuffer 已关闭，程序退出")
				return
			}
			log.Printf("[警告] 读取 RingBuffer 错误: %v", err)
			continue
		}

		event, err := ParseProcessEvent(record.RawSample)
		if err != nil {
			log.Printf("[警告] 反序列化事件失败: %v", err)
			continue
		}

		log.Printf("%-8d %-8d %-16s %s\n", event.PID, event.UID, event.CommStr(), event.FilenameStr())
	}
}
