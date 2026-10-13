// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"runtime"
	"testing"
)

// TestIsWriteOpen 表驱动验证文件写入意图判定
func TestIsWriteOpen(t *testing.T) {
	tests := []struct {
		name  string
		flags int
		want  bool
	}{
		{"只读打开 (O_RDONLY)", os.O_RDONLY, false},
		{"只写打开 (O_WRONLY)", os.O_WRONLY, true},
		{"读写打开 (O_RDWR)", os.O_RDWR, true},
		{"只写追加 (O_WRONLY|O_APPEND)", os.O_WRONLY | os.O_APPEND, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWriteOpen(tt.flags)
			if got != tt.want {
				t.Errorf("IsWriteOpen(0x%x) = %v, 期望 %v", tt.flags, got, tt.want)
			}
		})
	}
}

// TestIsProtectedTarget 验证受保护敏感文件判定
func TestIsProtectedTarget(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"shadow", true},
		{"sudoers", true},
		{"passwd", true},
		{"hosts", false},
		{"resolv.conf", false},
		{"app.log", false},
	}

	for _, tt := range tests {
		got := IsProtectedTarget(tt.filename)
		if got != tt.want {
			t.Errorf("IsProtectedTarget(%q) = %v, 期望 %v", tt.filename, got, tt.want)
		}
	}
}

// TestKernelLsmFileLoad 验证内核装载 LSM 文件防篡改程序有效性
func TestKernelLsmFileLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		if !IsLSMSupported(err) {
			t.Skipf("当前 Linux 内核未开启 CONFIG_BPF_LSM=y，跳过: %v", err)
		}
		t.Fatalf("加载 LSM 文件防篡改字节码失败: %v", err)
	}
	defer objs.Close()

	if objs.LsmFileOpen == nil {
		t.Fatal("LsmFileOpen 程序对象为空")
	}
	if objs.FileLsmStats == nil {
		t.Fatal("FileLsmStats 统计 Map 为空")
	}
}
