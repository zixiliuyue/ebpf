package main

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// TestParseUprobeEvent 纯函数表驱动反序列化单测
func TestParseUprobeEvent(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantErr  bool
		wantPID  uint32
		wantComm string
	}{
		{
			name: "正常 Uprobe 捕获事件",
			input: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(5678))
				_ = binary.Write(buf, binary.LittleEndian, uint32(0))
				_ = binary.Write(buf, binary.LittleEndian, uint64(123456789))
				var comm [16]byte
				copy(comm[:], "my-go-service\x00")
				_ = binary.Write(buf, binary.LittleEndian, comm)
				return buf.Bytes()
			}(),
			wantErr:  false,
			wantPID:  5678,
			wantComm: "my-go-service",
		},
		{
			name:    "残缺截断数据 (小于32字节)",
			input:   []byte{0x01, 0x02, 0x03},
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
			ev, err := ParseUprobeEvent(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUprobeEvent() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if ev.PID != tt.wantPID {
					t.Errorf("PID 期望 %d, 实际得到 %d", tt.wantPID, ev.PID)
				}
				if ev.CommString() != tt.wantComm {
					t.Errorf("Comm 期望 %q, 实际得到 %q", tt.wantComm, ev.CommString())
				}
			}
		})
	}
}

// TestKernelUprobeLoad 验证 Uprobe 字节码内核装载与 Verifier 校验
func TestKernelUprobeLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核装载测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects 失败: %v", err)
	}
	defer objs.Close()

	if objs.TraceUserFunction == nil {
		t.Error("TraceUserFunction 程序对象为空")
	}
	if objs.UprobeEvents == nil {
		t.Error("UprobeEvents 环形缓冲区对象为空")
	}
}
