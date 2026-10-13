package main

//go:generate bpf2go -target bpfel -cc clang bpf bpf/vfs_read.c -- -I../../headers -I../../headers/bpf

import (
	"bytes"
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

// VfsReadEvent 与内核 C struct vfs_read_event 严格对齐 (28 + 16 = 44 bytes)
type VfsReadEvent struct {
	PID        uint32
	UID        uint32
	DurationNS uint64
	RetBytes   int64
	Comm       [16]byte
}

// CommString 清理 Comm 数组中的末尾空字节
func (e *VfsReadEvent) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n == -1 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:n])
}

// ParseVfsReadEvent 纯函数反序列化二进制数据 (Google 解耦测试规范)
func ParseVfsReadEvent(data []byte) (*VfsReadEvent, error) {
	// 4(PID) + 4(UID) + 8(DurationNS) + 8(RetBytes) + 16(Comm) = 40 字节
	const expectedSize = 40
	if len(data) < expectedSize {
		return nil, fmt.Errorf("数据包长度不足: 期望 %d, 实际得到 %d", expectedSize, len(data))
	}

	var event VfsReadEvent
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.UID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.DurationNS); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.RetBytes); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.Comm); err != nil {
		return nil, err
	}

	return &event, nil
}

func main() {
	log.Println(">>> 启动 Day 05: Kprobe & Kretprobe 内核函数时延与返回分析 [vfs_read]...")

	if err := ebpfutil.RemoveMemlockLimit(); err != nil {
		log.Printf("[警告] 解除 memlock 限制失败: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("[错误] 加载 eBPF 字节码失败: %v\n%s", err, ebpfutil.FormatVerifierError(err))
	}
	defer objs.Close()

	// 挂载 Kprobe (函数入口)
	kp, err := link.Kprobe("vfs_read", objs.KprobeVfsRead, nil)
	if err != nil {
		log.Fatalf("[错误] 挂载 Kprobe(vfs_read) 失败: %v", err)
	}
	defer kp.Close()

	// 挂载 Kretprobe (函数退出)
	krp, err := link.Kretprobe("vfs_read", objs.KretprobeVfsRead, nil)
	if err != nil {
		log.Fatalf("[错误] 挂载 Kretprobe(vfs_read) 失败: %v", err)
	}
	defer krp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("[错误] 创建 RingBuffer 消费者失败: %v", err)
	}
	defer rd.Close()

	log.Println("[成功] Kprobe & Kretprobe 探针挂载成功！正在监听高耗时 I/O 读取 (>10us)... 按 Ctrl+C 退出。")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("\n[收到退出信号] 正在优雅卸载探针...")
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[完成] RingBuffer 已安全关闭。")
				return
			}
			log.Printf("[读取错误] %v", err)
			continue
		}

		event, err := ParseVfsReadEvent(record.RawSample)
		if err != nil {
			log.Printf("[解析警告] 数据格式损坏: %v", err)
			continue
		}

		fmt.Printf("[I/O 时延] PID: %-7d | 进程: %-15s | 读耗时: %6.2f µs | 读取量: %-8d 字节\n",
			event.PID,
			event.CommString(),
			float64(event.DurationNS)/1000.0,
			event.RetBytes,
		)
	}
}
