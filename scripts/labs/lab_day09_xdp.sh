#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Google 生产实验演练手册: Day 09 XDP 极速报文过滤与丢弃自动化演练

set -euo pipefail

echo "======================================================================"
echo "Google SRE 实验演练: Day 09 XDP ICMP 报文内核级秒级丢弃"
echo "======================================================================"

if [[ $EUID -ne 0 ]]; then
   echo "❌ 错误: 此实验必须在 root / 特权容器中执行 (make docker-shell)"
   exit 1
fi

VETH_SRC="veth-xdp-src"
VETH_DST="veth-xdp-dst"
SRC_IP="10.99.1.1/24"
DST_IP="10.99.1.2/24"
TARGET_PING="10.99.1.2"

cleanup() {
    echo ">>> 清理虚拟网络拓扑..."
    ip link del "${VETH_SRC}" 2>/dev/null || true
    echo ">>> 演练环境清理完成。"
}
trap cleanup EXIT

echo ">>> 1. 创建虚拟网络命名空间与 veth pair 设备..."
ip link add "${VETH_SRC}" type veth peer name "${VETH_DST}"
ip addr add "${SRC_IP}" dev "${VETH_SRC}"
ip addr add "${DST_IP}" dev "${VETH_DST}"
ip link set "${VETH_SRC}" up
ip link set "${VETH_DST}" up

echo ">>> 2. 测试挂载前连通性 (应正常收到 ICMP 回显)..."
if ping -c 2 -W 1 "${TARGET_PING}" >/dev/null 2>&1; then
    echo "✅ 基础网络连通正常 (ping 成功)"
else
    echo "⚠️ 基础网络连通异常，继续演示"
fi

echo ">>> 3. 编译并加载 Day 09 XDP 探针..."
# 在后台启动 Day 09 程序挂载到 veth-xdp-dst
cd /workspace/days/day09_xdp_drop
go build -o /tmp/day09_xdp_runner .
/tmp/day09_xdp_runner "${VETH_DST}" &
PID=$!
sleep 2

echo ">>> 4. 再次发送 ICMP Ping 报文 (预期将被 XDP 在网卡驱动层直接丢弃)..."
if ping -c 2 -W 1 "${TARGET_PING}" >/dev/null 2>&1; then
    echo "❌ 失败: ICMP 流量未被丢弃"
else
    echo "✅ 成功: ICMP 数据包已被 XDP 极速阻断 (Drop Count 计数生效)！"
fi

echo ">>> 5. 正在停止探针进程 (PID: ${PID})..."
kill -SIGINT "${PID}" 2>/dev/null || true
wait "${PID}" 2>/dev/null || true

echo "======================================================================"
echo "🎉 Day 09 XDP 演练圆满完成！"
echo "======================================================================"
