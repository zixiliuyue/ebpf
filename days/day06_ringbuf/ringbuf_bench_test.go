package main

import (
	"encoding/binary"
	"testing"
)

// BenchmarkParseTaskSwitchEvent 针对 RingBuffer 高频事件反序列化进行纳秒级基准测试
// Google 级延迟预算：单次解析耗时应在纳秒级，避免在用户态读取死循环中阻塞 CPU
func BenchmarkParseTaskSwitchEvent(b *testing.B) {
	// 构造 32 字节标准二进制事件
	raw := make([]byte, 32)
	binary.LittleEndian.PutUint32(raw[0:4], 1234)
	binary.LittleEndian.PutUint32(raw[4:8], 5678)
	binary.LittleEndian.PutUint64(raw[8:16], 1718000000000)
	copy(raw[16:32], "systemd\x00")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		event, err := ParseTaskSwitchEvent(raw)
		if err != nil {
			b.Fatalf("解析失败: %v", err)
		}
		if event.PrevPID != 1234 {
			b.Fatalf("PrevPID 校验不匹配")
		}
	}
}

// BenchmarkNextCommString 基准测试 C 风格零结尾字符串截断开销
func BenchmarkNextCommString(b *testing.B) {
	event := TaskSwitchEvent{
		PrevPID:  100,
		NextPID:  200,
		NextComm: [16]byte{'k', 'w', 'o', 'r', 'k', 'e', 'r', 0},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		str := event.NextCommString()
		if len(str) == 0 {
			b.Fatal("字符串为空")
		}
	}
}
