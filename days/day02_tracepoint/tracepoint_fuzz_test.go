// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzParseProcessEvent 针对内核事件二进制反序列化进行 Go 原生模糊测试 (Google Testing Practice)
// 目的：验证当内核 RingBuffer 产生畸形、截断、超长或恶意构造的数据时，
// ParseProcessEvent 及其辅助字符串提取方法 (CommStr, FilenameStr) 具备严格的内存安全与鲁棒性，绝对不能 panic。
func FuzzParseProcessEvent(f *testing.F) {
	// 1. 种子语料库准备 (Seed Corpus)
	// 语料 A: 空切片
	f.Add([]byte{})

	// 语料 B: 长度截断的数据 (仅 4 字节)
	f.Add([]byte{0x01, 0x02, 0x03, 0x04})

	// 语料 C: 标准合法的 ProcessEvent 序列化字节流
	validEv := ProcessEvent{
		PID: 1337,
		UID: 1000,
	}
	copy(validEv.Comm[:], "systemd\x00")
	copy(validEv.Filename[:], "/usr/lib/systemd/systemd\x00")

	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, &validEv)
	f.Add(buf.Bytes())

	// 语料 D: 边界数据：Comm 和 Filename 没有任何 '\0' 终止符 (测试极端越界扫描)
	nonNullEv := ProcessEvent{
		PID: 9999,
		UID: 0,
	}
	for i := range nonNullEv.Comm {
		nonNullEv.Comm[i] = 'A'
	}
	for i := range nonNullEv.Filename {
		nonNullEv.Filename[i] = 'B'
	}
	bufNonNull := new(bytes.Buffer)
	_ = binary.Write(bufNonNull, binary.LittleEndian, &nonNullEv)
	f.Add(bufNonNull.Bytes())

	// 语料 E: 88 字节全零数据
	f.Add(make([]byte, binary.Size(ProcessEvent{})))

	// 语料 F: 超长数据 (带脏尾随字节)
	f.Add(append(buf.Bytes(), []byte("trailing garbage bytes")...))

	// 2. 模糊测试执行循环
	f.Fuzz(func(t *testing.T, data []byte) {
		ev, err := ParseProcessEvent(data)
		if err != nil {
			// 数据非法时必须返回显式错误，且指针必须为 nil
			if ev != nil {
				t.Fatalf("解析失败时 ProcessEvent 应当为 nil")
			}
			return
		}

		// 解析成功时必须满足 invariants (不变式)：
		if ev == nil {
			t.Fatalf("解析成功但返回的 ProcessEvent 为 nil")
		}

		// 验证字符串转换安全：即使底层没有 null 字符，也不得 panic
		comm := ev.CommStr()
		if len(comm) > len(ev.Comm) {
			t.Fatalf("CommStr 长度越界: %d > %d", len(comm), len(ev.Comm))
		}

		filename := ev.FilenameStr()
		if len(filename) > len(ev.Filename) {
			t.Fatalf("FilenameStr 长度越界: %d > %d", len(filename), len(ev.Filename))
		}
	})
}
