#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Google 生产实验演练手册: Day 16 LSM 运行时文件防篡改与访问控制演练

set -euo pipefail

echo "======================================================================"
echo "Google SRE 实验演练: Day 16 eBPF LSM 运行时关键文件只读锁定与防篡改"
echo "======================================================================"

if [[ $EUID -ne 0 ]]; then
   echo "❌ 错误: 此实验必须在 root / 特权容器中执行 (make docker-shell)"
   exit 1
fi

TEST_FILE="/tmp/protected_system_secret.conf"

cleanup() {
    echo ">>> 清理测试文件..."
    rm -f "${TEST_FILE}" 2>/dev/null || true
    echo ">>> 演练环境清理完成。"
}
trap cleanup EXIT

echo ">>> 1. 初始化敏感测试文件: ${TEST_FILE}..."
echo "initial_safe_content" > "${TEST_FILE}"

echo ">>> 2. 编译并拉起 Day 16 LSM 文件保护探针..."
cd /workspace/days/day16_lsm_file
go build -o /tmp/day16_lsm_runner .
/tmp/day16_lsm_runner &
PID=$!
sleep 2

echo ">>> 3. 测试合法只读访问 (cat 预期成功)..."
cat "${TEST_FILE}" >/dev/null && echo "✅ 只读访问正常放行"

echo ">>> 4. 模拟黑客篡改攻击 (尝试追加写入，预期被 LSM 阻断拒绝 EPERM)..."
if echo "malicious_overwrite" >> "${TEST_FILE}" 2>/dev/null; then
    echo "⚠️ 写入未被拦截 (当前内核可能未开启 CONFIG_BPF_LSM 或受限于容器命名空间)"
else
    echo "🛡️  拦截成功！系统调用被内核 LSM 拒绝: Operation not permitted (EPERM)"
fi

echo ">>> 5. 正在停止 LSM 探针 (PID: ${PID})..."
kill -SIGINT "${PID}" 2>/dev/null || true
wait "${PID}" 2>/dev/null || true

echo "======================================================================"
echo "🎉 Day 16 LSM 文件防篡改演练完成！"
echo "======================================================================"
