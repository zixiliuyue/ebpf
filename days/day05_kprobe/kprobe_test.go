package main

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// TestParseVfsReadEvent 纯函数表驱动单元测试
func TestParseVfsReadEvent(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantErr       bool
		wantPID       uint32
		wantComm      string
		wantDuration  uint64
		wantBytesRead int64
	}{
		{
			name: "标准合法 VfsRead 事件",
			input: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(1234))
				_ = binary.Write(buf, binary.LittleEndian, uint32(1000))
				_ = binary.Write(buf, binary.LittleEndian, uint64(25000)) // 25us
				_ = binary.Write(buf, binary.LittleEndian, int64(4096))
				var comm [16]byte
				copy(comm[:], "nginx\x00")
				_ = binary.Write(buf, binary.LittleEndian, comm)
				return buf.Bytes()
			}(),
			wantErr:       false,
			wantPID:       1234,
			wantComm:      "nginx",
			wantDuration:  25000,
			wantBytesRead: 4096,
		},
		{
			name: "残缺数据包 (少于40字节)",
			input: []byte{
				0x01, 0x00, 0x00, 0x00,
			},
			wantErr: true,
		},
		{
			name:    "空切片边界",
			input:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseVfsReadEvent(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseVfsReadEvent() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if ev.PID != tt.wantPID {
					t.Errorf("PID 期望 %d, 实际得到 %d", tt.wantPID, ev.PID)
				}
				if ev.CommString() != tt.wantComm {
					t.Errorf("Comm 期望 %q, 实际得到 %q", tt.wantComm, ev.CommString())
				}
				if ev.DurationNS != tt.wantDuration {
					t.Errorf("DurationNS 期望 %d, 实际得到 %d", tt.wantDuration, ev.DurationNS)
				}
				if ev.RetBytes != tt.wantBytesRead {
					t.Errorf("RetBytes 期望 %d, 实际得到 %d", tt.wantBytesRead, ev.RetBytes)
				}
			}
		})
	}
}

// TestKernelKprobeLoad 在特权 Linux 环境下验证字节码内核装载合规性
func TestKernelKprobeLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核装载测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects 失败: %v", err)
	}
	defer objs.Close()

	if objs.KprobeVfsRead == nil {
		t.Error("KprobeVfsRead 程序对象为空")
	}
	if objs.KretprobeVfsRead == nil {
		t.Error("KretprobeVfsRead 程序对象为空")
	}
	if objs.Events == nil {
		t.Error("Events RingBuffer 对象为空")
	}
}
