package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/ringbuf.c -- -I../../headers -I../../headers/bpf

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

// TaskSwitchEvent 与内核 C struct task_switch_event 对齐 (4 + 4 + 8 + 16 = 32 bytes)
type TaskSwitchEvent struct {
	PrevPID     uint32
	NextPID     uint32
	TimestampNS uint64
	NextComm    [16]byte
}

func (e *TaskSwitchEvent) NextCommString() string {
	n := bytes.IndexByte(e.NextComm[:], 0)
	if n == -1 {
		return string(e.NextComm[:])
	}
	return string(e.NextComm[:n])
}

// ParseTaskSwitchEvent 纯函数反序列化 (Google 解耦测试规范)
func ParseTaskSwitchEvent(data []byte) (*TaskSwitchEvent, error) {
	const expectedSize = 32
	if len(data) < expectedSize {
		return nil, fmt.Errorf("数据包长度不足: 期望 %d, 实际得到 %d", expectedSize, len(data))
	}

	var event TaskSwitchEvent
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PrevPID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.NextPID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.TimestampNS); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.NextComm); err != nil {
		return nil, err
	}

	return &event, nil
}

func main() {
	log.Println(">>> 启动 Day 06: BPF Ring Buffer 深度剖析与丢包保护 (Backpressure Monitoring)...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 挂载 tp_btf 跟踪点 (直接通过 BTF 挂载，开销远低于传统 tracepoint)
	l, err := link.AttachTracing(link.TracingOptions{
		Program: objs.SchedSwitchTrace,
	})
	if err != nil {
		log.Fatalf("[错误] 挂载 tp_btf/sched_switch 失败: %v", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.RingbufEvents)
	if err != nil {
		log.Fatalf("[错误] 创建 RingBuffer Reader 失败: %v", err)
	}
	defer rd.Close()

	log.Println("[成功] RingBuffer 监听就绪！按 Ctrl+C 退出。")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("\n[收到退出信号] 正在优雅关闭 RingBuffer...")
		_ = rd.Close()
	}()

	var consumed uint64
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			var dropped uint64
			_ = objs.DropCounter.Lookup(uint32(0), &dropped)
			fmt.Printf("\r[SRE 统计] 成功消费事件: %-10d | 缓冲区满丢弃数 (Backpressure Drops): %-6d", consumed, dropped)
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("\n[完成] 退出循环，资源释放完毕。")
				return
			}
			log.Printf("[读取错误] %v", err)
			continue
		}

		consumed++
		if consumed%500 == 0 {
			event, err := ParseTaskSwitchEvent(record.RawSample)
			if err == nil {
				_ = event // 采样验证解析逻辑
			}
		}
	}
}
