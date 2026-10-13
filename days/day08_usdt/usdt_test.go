package main

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// TestParseUsdtQueryEvent 纯函数表驱动单测
func TestParseUsdtQueryEvent(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantErr     bool
		wantPID     uint32
		wantQueryID uint64
		wantLatency uint64
	}{
		{
			name: "标准 USDT 查询埋点事件",
			input: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(9999))
				_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // pad
				_ = binary.Write(buf, binary.LittleEndian, uint64(10086))
				_ = binary.Write(buf, binary.LittleEndian, uint64(350))
				return buf.Bytes()
			}(),
			wantErr:     false,
			wantPID:     9999,
			wantQueryID: 10086,
			wantLatency: 350,
		},
		{
			name:    "截断残缺数据 (小于24字节)",
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
			ev, err := ParseUsdtQueryEvent(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUsdtQueryEvent() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if ev.PID != tt.wantPID {
					t.Errorf("PID 期望 %d, 实际得到 %d", tt.wantPID, ev.PID)
				}
				if ev.QueryID != tt.wantQueryID {
					t.Errorf("QueryID 期望 %d, 实际得到 %d", tt.wantQueryID, ev.QueryID)
				}
				if ev.LatencyUS != tt.wantLatency {
					t.Errorf("LatencyUS 期望 %d, 实际得到 %d", tt.wantLatency, ev.LatencyUS)
				}
			}
		})
	}
}

// TestKernelUsdtLoad 验证 USDT 字节码装载合规性
func TestKernelUsdtLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核装载测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects 失败: %v", err)
	}
	defer objs.Close()

	if objs.TraceUsdtQuery == nil {
		t.Error("TraceUsdtQuery 程序对象为空")
	}
	if objs.UsdtEvents == nil {
		t.Error("UsdtEvents 环形缓冲区对象为空")
	}
}
