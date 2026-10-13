// SPDX-License-Identifier: Apache-2.0
package mock

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestMockStreamDeterministic 验证无故障注入时的离线确定性
func TestMockStreamDeterministic(t *testing.T) {
	events := [][]byte{
		[]byte("event_1_payload"),
		[]byte("event_2_payload"),
		[]byte("event_3_payload"),
	}

	stream := NewMockStream(events, FaultInjectionConfig{})
	defer stream.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for i := 0; i < len(events)*2; i++ {
		data, err := stream.Read(ctx)
		if err != nil {
			t.Fatalf("读取事件失败: %v", err)
		}
		expected := string(events[i%len(events)])
		if string(data) != expected {
			t.Errorf("事件内容不匹配: got %s, want %s", string(data), expected)
		}
	}

	if stream.ReadCount() != uint64(len(events)*2) {
		t.Errorf("读取计数器不匹配: got %d", stream.ReadCount())
	}
}

// TestMockStreamFaultInjection 验证混沌工程丢包故障注入
func TestMockStreamFaultInjection(t *testing.T) {
	events := [][]byte{[]byte("sample_event")}

	// 注入 100% 丢包
	stream := NewMockStream(events, FaultInjectionConfig{
		DropRate: 1.0,
	})
	defer stream.Close()

	ctx := context.Background()
	_, err := stream.Read(ctx)
	if !errors.Is(err, ErrBufferFull) {
		t.Fatalf("期望得到 ErrBufferFull，实际得到: %v", err)
	}

	if stream.DroppedCount() != 1 {
		t.Errorf("丢包计数器应为 1，实际为 %d", stream.DroppedCount())
	}
}

// TestMockStreamClose 验证流关闭行为
func TestMockStreamClose(t *testing.T) {
	stream := NewMockStream([][]byte{[]byte("data")}, FaultInjectionConfig{})
	_ = stream.Close()

	_, err := stream.Read(context.Background())
	if !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("关闭后应返回 ErrStreamClosed，实际得到: %v", err)
	}
}
