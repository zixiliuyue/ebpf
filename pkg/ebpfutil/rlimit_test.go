package ebpfutil

import (
	"runtime"
	"testing"
)

// TestRemoveMemlockLimit 验证锁页内存限制解除函数。
// 在 Linux 环境或具备特权的 Docker 容器中执行实际设置；在非 Linux (如本地 macOS 开发机) 下友好跳过。
func TestRemoveMemlockLimit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("RemoveMemlockLimit 仅在 Linux 系统或 Linux Docker 容器中有效，本地环境跳过")
	}

	if err := RemoveMemlockLimit(); err != nil {
		t.Fatalf("RemoveMemlockLimit 执行失败: %v", err)
	}
}
