package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/uprobe.c -- -I../../headers -I../../headers/bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// UprobeEvent 严格对齐 (4 + 4 + 8 + 16 = 32 bytes)
type UprobeEvent struct {
	PID         uint32
	UID         uint32
	TimestampNS uint64
	Comm        [16]byte
}

func (e *UprobeEvent) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:n])
}

// ParseUprobeEvent 纯函数反序列化 (Google 解耦测试规范)
func ParseUprobeEvent(data []byte) (*UprobeEvent, error) {
	const expectedSize = 32
	if len(data) < expectedSize {
		return nil, fmt.Errorf("数据包长度不足: 期望 %d, 实际得到 %d", expectedSize, len(data))
	}

	var event UprobeEvent
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.UID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.TimestampNS); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.Comm); err != nil {
		return nil, err
	}

	return &event, nil
}

// TracedTargetFunction 作为用户空间被追踪的目标测试函数
//
//go:noinline
func TracedTargetFunction() {
	time.Sleep(5 * time.Millisecond)
}

func main() {
	log.Println(">>> 启动 Day 07: Uprobe 用户态应用与 Go 原生二进制透视追踪...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 1. 获取当前可执行程序路径 (/proc/self/exe)
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("无法获取当前可执行文件路径: %v", err)
	}

	// 2. 将 Uprobe 挂载至自身二进制的 TracedTargetFunction 符号
	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		log.Fatalf("打开目标可执行文件失败: %v", err)
	}

	uprobeLink, err := ex.Uprobe("main.TracedTargetFunction", objs.TraceUserFunction, nil)
	if err != nil {
		log.Printf("[提示] 符号 main.TracedTargetFunction 在静态编译下可能被剥离，退化为系统探针模式: %v", err)
	} else {
		defer uprobeLink.Close()
		log.Println("[成功] Uprobe 探针成功注入到自身进程符号 [main.TracedTargetFunction]！")
	}

	rd, err := ringbuf.NewReader(objs.UprobeEvents)
	if err != nil {
		log.Fatalf("创建 RingBuffer Reader 失败: %v", err)
	}
	defer rd.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// 启动后台定时触发 Goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			TracedTargetFunction()
		}
	}()

	go func() {
		<-sigCh
		log.Println("\n[收到退出信号] 正在卸载 Uprobe 并退出...")
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("[读取错误] %v", err)
			continue
		}

		event, err := ParseUprobeEvent(record.RawSample)
		if err == nil {
			fmt.Printf("[Uprobe 触发] PID: %-7d | 进程: %-12s | 时间戳: %d\n",
				event.PID, event.CommString(), event.TimestampNS)
		}
	}
}
