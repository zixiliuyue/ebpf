# Google Engineering Practice: 声明式、确定性构建 Makefile
.PHONY: help build generate test test-docker docker-build docker-shell clean test-fuzz test-least-privilege drift-check lint

# 镜像名称
IMAGE_NAME ?= ebpf-dev:latest
DOCKER_RUN = docker run --rm --privileged \
	--pid=host \
	--network=host \
	-v $(shell pwd):/workspace \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v /sys/kernel/btf:/sys/kernel/btf:ro \
	-v /sys/fs/bpf:/sys/fs/bpf \
	-w /workspace $(IMAGE_NAME)

# 最小特权模式运行容器 (Google SRE 生产基线：禁用 --privileged，采用细粒度 Capabilities)
DOCKER_RUN_LEAST_PRIVILEGE = docker run --rm \
	--cap-drop=ALL \
	--cap-add=BPF \
	--cap-add=PERFMON \
	--cap-add=NET_ADMIN \
	--cap-add=SYS_ADMIN \
	--security-opt seccomp=unconfined \
	-v $(shell pwd):/workspace \
	-v /sys/fs/bpf:/sys/fs/bpf \
	-v /sys/kernel/btf:/sys/kernel/btf:ro \
	-v /sys/kernel/debug:/sys/kernel/debug:ro \
	-w /workspace $(IMAGE_NAME)

help: ## 显示 Makefile 目标说明
	@echo "======================================================================"
	@echo "eBPF 20天学习营构建系统 (Google 工程实践级设计)"
	@echo "======================================================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

docker-build: ## 构建 eBPF 开发与测试 Docker 镜像
	docker build -t $(IMAGE_NAME) .

docker-shell: ## 启动并进入具备特权的 eBPF 交互式沙箱环境
	$(DOCKER_RUN) -it /bin/bash

generate: ## 在 Docker 环境中自动运行 bpf2go 生成内核字节码及 Go 绑定代码
	$(DOCKER_RUN) go generate ./...

drift-check: ## 检查代码生成一致性，防止提交的 Go 桩代码与 C 源码不匹配
	$(DOCKER_RUN) /bin/bash -c "go generate ./... && git diff --exit-code"

test: ## 在 Docker 容器中执行全部单元测试与集成测试
	$(DOCKER_RUN) go test -v -race -timeout 120s ./...

test-fuzz: ## 执行 Go 原生 Fuzzing 模糊测试 (冒烟探测各模块纯解析函数)
	@echo ">>> 启动 Day 02 进程事件解析 Fuzzing 测试 (5s)..."
	$(DOCKER_RUN) go test -v -fuzz=FuzzParseProcessEvent -fuzztime=5s ./days/day02_tracepoint/...
	@echo ">>> 启动 Day 10 XDP 网络报文解析 Fuzzing 测试 (5s)..."
	$(DOCKER_RUN) go test -v -fuzz=FuzzParseUDPv4Packet -fuzztime=5s ./days/day10_xdp_parse/...
	@echo ">>> 启动 Day 20 Agent 动态配置反序列化 Fuzzing 测试 (5s)..."
	$(DOCKER_RUN) go test -v -fuzz=FuzzConfigParsing -fuzztime=5s ./days/day20_agent/...

test-least-privilege: ## 以 Google SRE 最小特权模式 (非 privileged) 执行生产级回归测试
	$(DOCKER_RUN_LEAST_PRIVILEGE) go test -v ./days/day20_agent/... ./pkg/...

test-local: ## 在本地执行轻量级非特权测试 (跳过需 Linux 内核的测试)
	go test -v ./pkg/...

clean: ## 清理生成的临时二进制与中间产物
	find . -type f -name "*_bpfel.go" -delete
	find . -type f -name "*_bpfel.o" -delete
	find . -type f -name "*_bpfeb.go" -delete
	find . -type f -name "*_bpfeb.o" -delete
	rm -rf bin/

