// SPDX-License-Identifier: Apache-2.0
package mock

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrBufferFull 模拟内核 RingBuffer 满丢包故障
	ErrBufferFull = errors.New("bpf ringbuffer: buffer full, event dropped")
	// ErrStreamClosed 事件流已正常关闭
	ErrStreamClosed = errors.New("event stream closed")
)

// EventReader 抽象内核事件读取器接口 (统一适配真实 Ringbuf.Reader 与虚拟 MockStream)
// Google 解耦实践：用户态消费者仅面向接口编程，可在单测环境下 100% 离线确定性复现
type EventReader interface {
	// Read 从流中读取下一个事件的原始字节切片
	Read(ctx context.Context) ([]byte, error)
	// Close 关闭事件流
	Close() error
}

// FaultInjectionConfig 混沌工程故障注入配置
type FaultInjectionConfig struct {
	DropRate       float64 // 丢包概率 (0.0 ~ 1.0)
	CorruptRate    float64 // 数据畸形/截断概率 (0.0 ~ 1.0)
	SimulateDelay  time.Duration // 每次读取的人为模拟内核延迟
}

// MockStream 实现高保真、可控速率的虚拟内核事件流
type MockStream struct {
	events      [][]byte
	faultCfg    FaultInjectionConfig
	idx         int
	mu          sync.Mutex
	closed      bool
	dropCounter uint64 // 累计模拟丢包数
	readCounter uint64 // 累计成功读取数
}

// NewMockStream 创建一个离线虚拟事件流
func NewMockStream(events [][]byte, faultCfg FaultInjectionConfig) *MockStream {
	copied := make([][]byte, len(events))
	for i, e := range events {
		buf := make([]byte, len(e))
		copy(buf, e)
		copied[i] = buf
	}

	return &MockStream{
		events:   copied,
		faultCfg: faultCfg,
	}
}

// Read 读取下一个事件并支持故障注入
func (m *MockStream) Read(ctx context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrStreamClosed
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if m.faultCfg.SimulateDelay > 0 {
		time.Sleep(m.faultCfg.SimulateDelay)
	}

	// 1. 模拟 RingBuffer 丢包故障注入
	if m.faultCfg.DropRate > 0 && float64(time.Now().UnixNano()%100)/100.0 < m.faultCfg.DropRate {
		atomic.AddUint64(&m.dropCounter, 1)
		return nil, ErrBufferFull
	}

	if len(m.events) == 0 {
		return nil, fmt.Errorf("mock stream 无可用事件")
	}

	raw := m.events[m.idx%len(m.events)]
	m.idx++
	atomic.AddUint64(&m.readCounter, 1)

	// 2. 模拟字节截断损坏故障注入
	if m.faultCfg.CorruptRate > 0 && float64(time.Now().UnixNano()%100)/100.0 < m.faultCfg.CorruptRate {
		if len(raw) > 4 {
			corrupted := make([]byte, len(raw)/2)
			copy(corrupted, raw[:len(raw)/2])
			return corrupted, nil
		}
	}

	ret := make([]byte, len(raw))
	copy(ret, raw)
	return ret, nil
}

// Close 关闭虚拟流
func (m *MockStream) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// DroppedCount 获取注入的丢包总数
func (m *MockStream) DroppedCount() uint64 {
	return atomic.LoadUint64(&m.dropCounter)
}

// ReadCount 获取成功读取事件总数
func (m *MockStream) ReadCount() uint64 {
	return atomic.LoadUint64(&m.readCounter)
}
