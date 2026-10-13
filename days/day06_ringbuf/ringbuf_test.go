package main

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// TestParseTaskSwitchEvent 表驱动解析单元测试
func TestParseTaskSwitchEvent(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantErr      bool
		wantPrevPID  uint32
		wantNextPID  uint32
		wantNextComm string
	}{
		{
			name: "正常调度切换事件",
			input: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(1001))
				_ = binary.Write(buf, binary.LittleEndian, uint32(1002))
				_ = binary.Write(buf, binary.LittleEndian, uint64(1700000000))
				var comm [16]byte
				copy(comm[:], "kworker\x00")
				_ = binary.Write(buf, binary.LittleEndian, comm)
				return buf.Bytes()
			}(),
			wantErr:      false,
			wantPrevPID:  1001,
			wantNextPID:  1002,
			wantNextComm: "kworker",
		},
		{
			name:    "截断残缺数据 (小于32字节)",
			input:   []byte{0x01, 0x02, 0x03},
			wantErr: true,
		},
		{
			name:    "空字节边界",
			input:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseTaskSwitchEvent(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTaskSwitchEvent() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if ev.PrevPID != tt.wantPrevPID {
					t.Errorf("PrevPID 期望 %d, 实际得到 %d", tt.wantPrevPID, ev.PrevPID)
				}
				if ev.NextPID != tt.wantNextPID {
					t.Errorf("NextPID 期望 %d, 实际得到 %d", tt.wantNextPID, ev.NextPID)
				}
				if ev.NextCommString() != tt.wantNextComm {
					t.Errorf("NextComm 期望 %q, 实际得到 %q", tt.wantNextComm, ev.NextCommString())
				}
			}
		})
	}
}

// TestKernelRingbufLoad 验证内核装载合规性
func TestKernelRingbufLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核装载测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects 失败: %v", err)
	}
	defer objs.Close()

	if objs.SchedSwitchTrace == nil {
		t.Error("SchedSwitchTrace 程序对象为空")
	}
	if objs.RingbufEvents == nil {
		t.Error("RingbufEvents 环形缓冲区对象为空")
	}
	if objs.DropCounter == nil {
		t.Error("DropCounter 丢包统计 Map 为空")
	}
}
