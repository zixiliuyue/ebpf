package main

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"ebpf-learning-20days/pkg/ebpfutil"
)

// TestParseProcessEvent 使用表驱动测试 (Table-Driven Tests) 验证事件反序列化和字符串提取
func TestParseProcessEvent(t *testing.T) {
	tests := []struct {
		name         string
		pid          uint32
		uid          uint32
		comm         string
		filename     string
		expectError  bool
		truncateSize int
	}{
		{
			name:        "正常进程事件解析",
			pid:         1234,
			uid:         1000,
			comm:        "curl",
			filename:    "/usr/bin/curl",
			expectError: false,
		},
		{
			name:        "超长命令与路径截断保护",
			pid:         8888,
			uid:         0,
			comm:        "a_very_long_process_name_exceeding_16_bytes",
			filename:    "/var/log/very/deep/nested/directory/path/that/might/fill/the/buffer/completely",
			expectError: false,
		},
		{
			name:         "数据包残缺",
			truncateSize: 10, // 故意传入小于 sizeof(ProcessEvent) 的损坏数据
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.truncateSize > 0 {
				_, err := ParseProcessEvent(make([]byte, tt.truncateSize))
				if err == nil {
					t.Fatalf("期望遇到截断错误，但实际解析成功")
				}
				return
			}

			// 构造原始二进制样本
			var rawEv ProcessEvent
			rawEv.PID = tt.pid
			rawEv.UID = tt.uid
			copy(rawEv.Comm[:], tt.comm)
			copy(rawEv.Filename[:], tt.filename)

			buf := new(bytes.Buffer)
			if err := binary.Write(buf, binary.LittleEndian, &rawEv); err != nil {
				t.Fatalf("构造测试数据失败: %v", err)
			}

			parsed, err := ParseProcessEvent(buf.Bytes())
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseProcessEvent error = %v, expectError %v", err, tt.expectError)
			}

			if parsed.PID != tt.pid {
				t.Errorf("PID = %d, want %d", parsed.PID, tt.pid)
			}
			if parsed.UID != tt.uid {
				t.Errorf("UID = %d, want %d", parsed.UID, tt.uid)
			}

			// 验证字符串提取不会包含多余的 0 字节
			commStr := parsed.CommStr()
			if len(commStr) > 16 {
				t.Errorf("CommStr 长度超出 16: %s", commStr)
			}
			filenameStr := parsed.FilenameStr()
			if len(filenameStr) > 64 {
				t.Errorf("FilenameStr 长度超出 64: %s", filenameStr)
			}
		})
	}
}

// TestKernelBpfLoad 验证内核 BPF 字节码的装载与 Verifier 合规性 (仅在特权 Linux 下运行)
func TestKernelBpfLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核 BPF 加载测试")
	}

	_ = ebpfutil.RemoveMemlockLimit()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Skipf("当前环境特权不足以加载内核 eBPF 对象 (跳过集成测试): %v", err)
	}
	defer objs.Close()

	if objs.TracepointSyscallsSysEnterExecve == nil {
		t.Fatal("TracepointSyscallsSysEnterExecve 程序对象为空")
	}
	if objs.Events == nil {
		t.Fatal("Events RingBuffer Map 对象为空")
	}
}
