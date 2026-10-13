package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/usdt.c -- -I../../headers -I../../headers/bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// UsdtQueryEvent 与内核 C struct usdt_query_event 严格对齐 (4 + 4(padding) + 8 + 8 = 24 bytes)
type UsdtQueryEvent struct {
	PID       uint32
	_         uint32 // 内存对齐填充
	QueryID   uint64
	LatencyUS uint64
}

// ParseUsdtQueryEvent 纯函数反序列化 (Google 解耦测试规范)
func ParseUsdtQueryEvent(data []byte) (*UsdtQueryEvent, error) {
	const expectedSize = 24
	if len(data) < expectedSize {
		return nil, fmt.Errorf("数据包长度不足: 期望 %d, 实际得到 %d", expectedSize, len(data))
	}

	var event UsdtQueryEvent
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, err
	}
	var pad uint32
	if err := binary.Read(buf, binary.LittleEndian, &pad); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.QueryID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.LatencyUS); err != nil {
		return nil, err
	}

	return &event, nil
}

func main() {
	log.Println(">>> 启动 Day 08: USDT (User Statically Defined Tracing) 静态用户态埋点...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	rd, err := ringbuf.NewReader(objs.UsdtEvents)
	if err != nil {
		log.Fatalf("创建 RingBuffer Reader 失败: %v", err)
	}
	defer rd.Close()

	log.Println("[就绪] USDT 监控探针已就绪。正在监听用户态埋点触发... 按 Ctrl+C 退出。")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("\n[收到退出信号] 正在优雅退出...")
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

		event, err := ParseUsdtQueryEvent(record.RawSample)
		if err == nil {
			fmt.Printf("[USDT 埋点拦截] PID: %-7d | QueryID: %d | 耗时: %d µs\n",
				event.PID, event.QueryID, event.LatencyUS)
		}
	}
}
