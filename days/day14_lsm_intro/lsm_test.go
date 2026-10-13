// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestIsLSMSupported 验证内核 LSM 兼容性判断逻辑
func TestIsLSMSupported(t *testing.T) {
	if !IsLSMSupported(nil) {
		t.Error("nil 错误应当判定为支持")
	}
	if IsLSMSupported(unix.ENOTSUP) {
		t.Error("ENOTSUP 应当判定为不支持")
	}
	if IsLSMSupported(unix.EINVAL) {
		t.Error("EINVAL 应当判定为不支持")
	}
	if !IsLSMSupported(errors.New("other random error")) {
		t.Error("其他非配置错误不应误判为不支持")
	}
}

// TestKernelLsmLoad 验证内核加载 LSM 字节码程序
func TestKernelLsmLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("跳过非 Linux 环境的内核测试")
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		if !IsLSMSupported(err) {
			t.Skipf("当前 Linux 内核未开启 CONFIG_BPF_LSM=y 或启动参数无 bpf，跳过装载: %v", err)
		}
		t.Fatalf("加载 LSM 字节码失败: %v", err)
	}
	defer objs.Close()

	if objs.LsmTaskAlloc == nil {
		t.Fatal("LsmTaskAlloc 程序对象为空")
	}
	if objs.LsmAuditStats == nil {
		t.Fatal("LsmAuditStats 统计 Map 为空")
	}
}
