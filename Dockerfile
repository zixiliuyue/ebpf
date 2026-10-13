# Google Engineering Practice: 生产级且自洽的 eBPF + Go 运行与研发镜像
# 遵循环境可复现、最小外部污染原则，内置 clang、llvm、bpftool 与 cilium/ebpf 代码生成器
FROM golang:1.24-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPROXY=https://proxy.golang.org,direct
# 启用 GOTOOLCHAIN=auto，确保与 cilium/ebpf v0.22+ 要求的 Go 版本自适应对齐
ENV GOTOOLCHAIN=auto

# 安装 eBPF 编译器工具链、内核调试工具与网络排错工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    bpftool \
    iproute2 \
    iputils-ping \
    curl \
    git \
    make \
    gcc \
    strace \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装 cilium/ebpf 官方专用的 bpf2go 代码生成器
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest

WORKDIR /workspace

CMD ["/bin/bash"]
