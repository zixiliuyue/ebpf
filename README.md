# eBPF 20 天全栈工程实战训练营 (Google 工程实践级规范)

[![CI](https://github.com/zixiliuyue/ebpf/actions/workflows/ci.yml/badge.svg)](https://github.com/zixiliuyue/ebpf/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev/)
[![Kernel](https://img.shields.io/badge/Linux_Kernel-5.4+-orange.svg?logo=linux)](https://kernel.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-purple.svg)](https://ebpf.io/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/zixiliuyue/ebpf/blob/main/CONTRIBUTING.md)

> **基于 Google 软件工程规范 (Software Engineering at Google)**，采用 **Go (`cilium/ebpf`) + C (CO-RE / libbpf)** 双核驱动，提供 100% 密封、开箱即用的 Docker 特权开发测试沙箱、完整的中文源码级剖析与单元测试套件。

---

## 目录
- [一、Google 级 eBPF 工程实践基线](#一google-级-ebpf-工程实践基线)
- [二、环境快速启动与 Docker 验证](#二环境快速启动与-docker-验证)
- [三、20 天渐进式学习大纲概览](#三20-天渐进式学习大纲概览)
- [四、20 天逐步推进详细教程与代码实践](#四20-天逐步推进详细教程与代码实践)
  - [阶段一：基础架构与内核漫游 (Day 01 - Day 04)](#阶段一基础架构与内核漫游-day-01---day-04)
  - [阶段二：动态追踪与深层观测 (Day 05 - Day 08)](#阶段二动态追踪与深层观测-day-05---day-08)
  - [阶段三：极速网络与流量治理 (Day 09 - Day 13)](#阶段三极速网络与流量治理-day-09---day-13)
  - [阶段四：内核安全与访问控制 (Day 14 - Day 16)](#阶段四内核安全与访问控制-day-14---day-16)
  - [阶段五：内核验证器与生产级落地 (Day 17 - Day 20)](#阶段五内核验证器与生产级落地-day-17---day-20)
- [五、测试规范与 CI/CD 落地](#五测试规范与-cicd-落地)

---

## 一、Google 级 eBPF 工程实践基线

在 Google 规模的分布式基础设施中，eBPF 被广泛应用于主机监控、网络加速、Service Mesh 绕行（如 Cilium）与运行时安全防御。遵循 Google 软件工程（Software Engineering at Google）原则，本项目贯彻以下五项基线：

1. **环境密封与可复现性 (Hermetic & Reproducible)**
   - 杜绝“在我机器上能跑”的问题。所有编译器（Clang 14+、LLVM）、内核工具（`bpftool`）、Go 工具链均统一封装于标准 Docker 镜像中。
   - 使用 BTF（BPF Type Format）与 CO-RE（Compile Once - Run Everywhere），一套字节码通过内核重定向适配不同 Linux 发行版。

2. **快速失败与前置准入自检 (Fast-Fail Preflight Checks)**
   - Agent 启动第一步必须执行环境诊断（检查内核版本、BTF 文件 `/sys/kernel/btf/vmlinux`、TraceFS 挂载、Linux 特权 `CAP_BPF` / `CAP_SYS_ADMIN`）。
   - 自动检测并解除进程 `RLIMIT_MEMLOCK` 锁页内存限制，防止在较老内核上因权限配置不当引发静默失败。

3. **数据反序列化与 I/O 严格解耦 (Decoupled Logic & Deterministic Testing)**
   - 严禁将数据包或内核事件解析逻辑深埋在 `Read()` 循环中。所有事件解析抽取为独立的纯函数（如 `ParseProcessEvent([]byte) (*Event, error)`）。
   - 通过 Go 表驱动测试（Table-Driven Tests）对事件结构体、边界截断、空字节清洗进行 100% 覆盖率的单元测试。

4. **利用内核特权执行内存级沙箱测试 (`BPF_PROG_TEST_RUN`)**
   - 针对网络层 eBPF 程序（XDP / TC / Socket Filter），利用 Linux 内核的原生测试运行能力直接在内核内存中注入模拟数据包，实现纳秒级执行与确定性断言，无需构建复杂的物理或虚拟网络拓扑。

5. **优雅停机与资源防泄漏 (Graceful Lifecycle & Leak Prevention)**
   - 所有 eBPF Map、Program、Link 资源必须绑定 `defer Close()`。
   - 监听操作系统中断信号（`SIGINT`, `SIGTERM`），通过 `context.Context` 级联关闭，确保探针在异常或退出时被干净卸载，绝不在生产内核中遗留悬挂探针。

---

## 二、环境快速启动与 Docker 验证

### 1. 架构总览与目录结构

```text
.
├── Dockerfile                   # 包含 Clang, LLVM, bpftool, Go 1.24 的特权开发镜像
├── Makefile                     # 自动化构建、代码生成、微基准与测试入口
├── docker-compose.yml           # Docker-compose 声明式特权挂载配置
├── go.mod / go.sum              # Go 依赖 (cilium/ebpf, x/sys, prometheus)
├── cmd/
│   └── ebpf-agent/              # 生产级统一运维与监控 CLI 工具 (doctor/top/run/version)
├── deploy/                      # 云原生可观测性资产 (SRE 监控告警)
│   ├── prometheus/alerts.yml    # 内核探针告警规则 (Ringbuf 丢包、Verifier 失败、CPU 耗时超标)
│   └── grafana/dashboard.json   # 云原生 eBPF 运行时 Grafana 监控大屏
├── headers/                     # 真实内核 BTF 提取的 vmlinux.h 与 libbpf 头文件
│   ├── vmlinux.h
│   └── bpf/ (bpf_helpers.h, bpf_endian.h, bpf_tracing.h...)
├── pkg/
│   └── ebpfutil/                # 跨模块通用工程基建 (环境诊断、特性矩阵探测、BPF Stats 自观测)
│       └── mock/                # 确定性内核事件模拟流与故障注入引擎 (离线测试基建)
├── scripts/
│   └── labs/                    # 生产故障模拟与演练 Runbooks (XDP 丢包、LSM 权限拦截)
└── days/                        # 20 天渐进式学习实战源码
    ├── day01_env/               # Day 01: 环境自检与内核准入
    ├── day02_tracepoint/        # Day 02: Tracepoint 进程跟踪与 Fuzzing 测试
    ├── day03_maps/              # Day 03: BPF Maps (Hash/Array) CRUD 与微基准
    ├── day04_percpu/            # Day 04: Per-CPU Map 无锁高并发统计
    ├── ...                      # Day 05 ~ Day 19
    └── day20_agent/             # Day 20: 生产级模块化 eBPF 监控 Agent (Prometheus + Slog + Pprof)
```

### 2. 常用操作指令

```bash
# 1. 构建特权开发测试 Docker 镜像
make docker-build

# 2. 编译生产级统一 CLI 二进制产物 (输出到 bin/ebpf-agent)
make build-agent

# 3. 执行内核环境自检与特性支持矩阵探测 (Fast-Fail 诊断)
docker run --rm --privileged -v $(pwd):/workspace -w /workspace ebpf-dev:latest ./bin/ebpf-agent doctor

# 4. 在容器中自动执行 bpf2go 代码生成 (编译 C 内核代码并生成 Go 绑定)
make generate

# 5. 校验代码生成一致性 (确保提交的 Go 桩代码与 C 源码零漂移)
make drift-check

# 6. 一键运行全量单元测试与并发竞态检测 (-race)
make test

# 7. 运行内核与内存纳秒级微基准测试 (Nanosecond Benchmarks & Memory Allocations)
make bench

# 8. 执行 Go 原生 Fuzzing 模糊测试 (针对内核事件解析与配置反序列化)
make test-fuzz

# 9. 以 Google SRE 生产最小特权模式 (非 --privileged，细粒度 Capabilities) 执行回归测试
make test-least-privilege

# 10. 启动并进入具备特权的交互式容器沙箱
make docker-shell
```

---

## 三、20 天渐进式学习大纲概览

| 阶段 | 天数 | 主题 | 核心技术点 | 实践产出 |
| :--- | :--- | :--- | :--- | :--- |
| **阶段一：基础架构与内核漫游** | Day 01 | eBPF 体系与工程沙箱 | 虚拟机架构、JIT、BTF、CO-RE 原理 | 环境准入诊断工具 `ebpfutil.CheckEnvironment` |
| | Day 02 | Tracepoint 静态跟踪 | `sys_enter_execve`、`bpf2go`、`bpf_printk` | 进程创建实时审计器 + 解码单测 |
| | Day 03 | BPF Map 核心交互 | `BPF_MAP_TYPE_HASH` / `ARRAY`、CRUD | 进程系统调用计数器 + 表驱动单测 |
| | Day 04 | Per-CPU 高并发优化 | `PERCPU_ARRAY`、CPU 缓存局部性、无锁化 | 单机千万 QPS 统计器 + 性能 Benchmark |
| **阶段二：动态追踪与深层观测** | Day 05 | Kprobe & Kretprobe | 动态插桩任意内核函数、参数与返回值拦截 | 内核文件打开耗时与路径监控 |
| | Day 06 | BPF Ring Buffer 深度剖析 | 无锁环形缓冲区、内存屏障、丢包保护 | 极速事件分发管道 + 背压监控 |
| | Day 07 | Uprobe 用户态应用透视 | 用户空间函数拦截、Go ABI 规范、栈回溯 | 追踪 Go HTTP 服务内部函数延迟 |
| | Day 08 | USDT 静态用户态埋点 | DTrace 衍生技术、ELF 静态探测点解析 | 零侵入数据库客户端查询审计 |
| **阶段三：极速网络与流量治理** | Day 09 | XDP 极速数据面与包过滤 | 网卡驱动层执行、`XDP_DROP`、内存单测 | 极速抗 ICMP 洪水丢包器 (`prog.Test`) |
| | Day 10 | 报文重写与 NAT/反射 | 以太网/IP 首部修改、校验和增量重算、`XDP_TX` | 极简四层反射负载均衡原型 |
| | Day 11 | TC (Traffic Control) 治理 | `clsact qdisc`、Egress 流量整形与标记 | 容器出口流量限速与 DSCP 染色 |
| | Day 12 | Socket Filter 与 SockOps | TCP 握手时延度量、连接状态机迁移 | 生产级 TCP 连接生命周期审计 |
| | Day 13 | Sockmap 协议栈短路加速 | `BPF_MAP_TYPE_SOCKMAP`、零内核协议栈拷贝 | 本地微服务/Envoy 边车通信加速 |
| **阶段四：内核安全与访问控制** | Day 14 | eBPF LSM 安全子系统 | Linux Security Modules 钩子、MAC 强制访问 | 安全策略挂载骨架与审计 |
| | Day 15 | 运行时提权与进程阻断 | hook `bprm_check_security`、高危命令拦截 | 阻断未授权可执行程序运行 |
| | Day 16 | 文件防篡改与敏感目录保护 | hook `file_open`、防勒索与防篡改 | 保护 `/etc/shadow` 与动态策略下发 |
| **阶段五：验证器与工程落地** | Day 17 | 驯服 eBPF Verifier | 指针推导、循环展开、512B 栈溢出规避 | 常见 Verifier 拒绝案例集与修复模版 |
| | Day 18 | 尾调用与程序模块化 | `BPF_TAIL_CALL`、`prog_array`、规则引擎 | 复杂协议多级分派路由器 |
| | Day 19 | 生产级指标导出 | Prometheus Exporter、Histogram 直方图 | eBPF 裸指标与 Grafana 观测对接 |
| | Day 20 | 综合实战：工业级 Agent | 插件化设计、优雅停机、健康检查探针 | 云原生 eBPF 监控与防御 Agent 交付 |

---

## 四、20 天逐步推进详细教程与代码实践

### 阶段一：基础架构与内核漫游 (Day 01 - Day 04)

#### Day 01: eBPF 体系演进与 Google 级工程沙箱构建
- **第一性原理**：
  eBPF（Extended Berkeley Packet Filter）本质上是 Linux 内核中的**安全、沙箱化的图灵完备 RISC 虚拟机**。它包含 11 个 64 位寄存器（R0~R10，其中 R10 为只读栈帧指针），程序在装载时必须经过内核 Verifier（验证器）严格的形式化证明，确保无未终止循环、无越界内存读写，并在运行时通过 JIT 编译为宿主机的原生机器码。
- **现代 CO-RE 核心**：
  过去 BCC 方案依赖在宿主机实时编译内核源码，体积庞大且对环境极其敏感；而现代 eBPF 依托 **BTF (BPF Type Format)** 和 **CO-RE (Compile Once - Run Everywhere)**，通过 Clang 的 `__attribute__((preserve_access_index))` 记录结构体字段重定位信息，在内核加载时由 `libbpf` 根据当前运行内核自动调整字段偏移，实现“一次编译，到处运行”。
- **Google 实践准则**：
  Agent 在运行任何 eBPF 逻辑前，必须执行快速失败的前置环境检测（`pkg/ebpfutil/env.go`），输出清晰的系统诊断报告，并在启动时解除 `RLIMIT_MEMLOCK` 锁页限制。
- **Docker 运行验证**：
  ```bash
  docker run --rm --privileged -v /sys/kernel/btf:/sys/kernel/btf:ro ebpf-dev:latest go run ./days/day01_env/main.go
  ```

---

#### Day 02: 静态追踪第一步：Tracepoint 与系统调用观测
- **内核机制**：
  Tracepoint 是 Linux 内核开发者预置在关键代码路径上的静态插桩点（基于内核 Trace Event 子系统）。相比 Kprobe，Tracepoint 的 ABI 接口稳定，内核版本升级不易失效，且执行开销极低。本实验挂载在 `syscalls/sys_enter_execve`，用于捕获所有进程的创建动作。
- **数据流通路径**：
  ```text
  [内核态] sys_enter_execve -> 提取 pid, uid, comm, filename -> bpf_ringbuf_reserve() -> bpf_ringbuf_submit()
                                                                       │
                                                       (共享无锁环形内存区)
                                                                       ▼
  [用户态] Go RingBuf Reader -> ParseProcessEvent() -> 结构化日志/指标输出
  ```
- **核心代码剖析 (`days/day02_tracepoint/bpf/execve.c`)**：
  ```c
  SEC("tracepoint/syscalls/sys_enter_execve")
  int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
      struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
      if (!e) return 0; // 缓冲区满时不阻塞系统，快速返回
      e->pid = bpf_get_current_pid_tgid() >> 32;
      e->uid = bpf_get_current_uid_gid();
      bpf_get_current_comm(&e->comm, sizeof(e->comm));
      bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[0]);
      bpf_ringbuf_submit(e, 0);
      return 0;
  }
  ```
- **单元测试实践**：
  - `days/day02_tracepoint/tracepoint_test.go` 中针对 `ParseProcessEvent` 进行了表驱动单元测试，模拟正常事件、超长截断、残缺数据包等边界场景。
  - `TestKernelBpfLoad` 验证生成的 ELF 字节码在真实内核中的装载与 Verifier 校验。

---

#### Day 03: 内核与用户态的桥梁：BPF Map 核心原理与 CRUD
- **核心概念**：
  BPF Map 是内核与用户空间、或不同 BPF 程序之间共享状态与持久化数据的核心键值存储结构。
  - `BPF_MAP_TYPE_HASH`：基于内核哈希表实现，适用于稀疏键（如 PID、IP 地址），支持动态增删，支持并发更新。
  - `BPF_MAP_TYPE_ARRAY`：基于扁平连续数组，Key 必须为整型索引 `0 ~ max_entries-1`，读写速度为 O(1)，无哈希碰撞，极适合存储全局配置开关。
- **并发控制策略**：
  在内核态更新统计计数时，多核并发可能产生竞争。必须使用 `__sync_fetch_and_add(count, 1)` 原子内置函数，或者使用下一天学习的 Per-CPU 结构。
- **Go API 封装与测试**：
  - 在 `days/day03_maps/main.go` 中封装 `SetGlobalConfig`、`GetProcessCount`、`DumpAllProcessCounts`。
  - 在 `days/day03_maps/maps_test.go` 中验证了在 Linux 环境下动态创建 Map、Put、Get、未命中 Key（`ebpf.ErrKeyNotExist`）、遍历（`Iterate`）与删除（`Delete`）。

---

#### Day 04: 高并发性能基石：Per-CPU Map 与无锁化聚合
- **性能瓶颈根因**：
  在高频网络包处理或密集系统调用场景下，如果所有 CPU 核心都去更新同一个 Hash Map 中的 Key，即使使用原子操作，底层的缓存一致性协议（如 MESI）也会导致跨 CPU 核心的 **L1/L2 Cache Line 反复失效与争抢 (Cache Line Bouncing)**，拖垮整机性能。
- **第一性原理设计：Per-CPU Map**：
  `BPF_MAP_TYPE_PERCPU_ARRAY` / `BPF_MAP_TYPE_PERCPU_HASH` 会在内核中为每一个逻辑 CPU 核心分配一份完全独立的内存空间。
  - 内核态更新：当前 CPU 仅修改属于自己的内存副本，**无需任何锁与原子指令**，吞吐可达千万 QPS。
  - 用户态读取：Go 读取时一次性拉取整个 CPU 数组切片（`[]uint64`），由用户态在后台离线执行多核聚合。
- **基准测试数据验证**：
  运行 `days/day04_percpu/percpu_test.go` 中的 `BenchmarkAggregatePerCPU`，在 128 核聚合模拟场景下仅需 **50 纳秒**。

---

### 阶段二：动态追踪与深层观测 (Day 05 - Day 08)

#### Day 05: 动态黑盒探测：Kprobe & Kretprobe 原理与实战
- **技术原理**：
  Kprobe（Kernel Probe）允许开发者在**任意非内联（non-inlined）内核函数**的入口或返回处动态注入探针。
  - 其底层通过将目标指令替换为断点指令（x86 上的 `int 3` 或 ARM 上的 `BRK`），触发异常中断陷入内核调试处理程序，执行 eBPF 字节码后再单步恢复原始指令。
  - `kretprobe` 则通过动态修改函数返回地址（trampoline 机制）在函数返回时捕获返回值。
- **关键权衡 (Trade-offs)**：
  - 优势：无需内核预置 Tracepoint，可透视任何内核内部函数细节（如追踪 `do_sys_openat2`）。
  - 代价：指令断点与单步执行带来一定开销（单次调用约上百纳秒）；若被探测函数发生重命名，探针可能失效。现代内核优先推荐使用开销更低、基于 ftrace 的 `fentry`/`fexit`。

#### Day 06: 生产级事件流传输：BPF Ring Buffer 深度剖析
- **架构演进**：
  - **Perf Event Buffer (旧方案)**：每个 CPU 独立一个环形缓冲区。由于事件产生速率在各核心不均，极易导致部分核心的 Buffer 溢出丢包，而其他核心 Buffer 空闲；且在用户态需要轮询所有核心的 fd，上下文切换频繁。
  - **BPF Ring Buffer (现代方案，Linux 5.8+)**：采用所有 CPU 共享的单一环形缓冲区，内部基于高效的无锁内存屏障（Memory Barrier）和页对齐设计。支持 `bpf_ringbuf_reserve` 预分配零拷贝，大幅降低内存浪费和事件乱序。
- **生产实践**：
  通过设置适当的 RingBuffer 大小（必须为系统页大小 4KB 的 2 的幂次方，如 256KB、1MB），配合用户态 Epoll 事件唤醒通知，兼顾高吞吐与低延迟。

#### Day 07: 用户态程序透视：Uprobe 与 Go 原生二进制追踪
- **原理与机制**：
  Uprobe（User-space Probe）将探针技术从内核态延伸到了用户空间。通过解析 ELF 二进制文件的符号表（Symbol Table）或 DWARF 调试信息，计算函数在可执行文件中的绝对偏移，Linux 内核通过虚拟内存管理（CoW 机制）将该指令页替换为断点指令。
- **针对 Go 语言二进制的特殊考量**：
  - Go 1.17+ 引入了基于寄存器的调用约定（Register-based ABI，如 RAX, RBX, RCX），而非传统的栈传参。
  - 在 eBPF 追踪 Go 函数参数时，需依据目标架构的寄存器映射读取对应入参；
  - 追踪 Go 内部运行时（如 `runtime.execute` 或 HTTP 处理函数）时，需注意 Goroutine 调度对线程上下文的影响。

#### Day 08: 零侵入可观测性埋点：USDT 静态用户态埋点
- **背景与优势**：
  USDT（User Statically Defined Tracing）源自 DTrace 理念。与动态 Uprobe 相比，USDT 是在软件源码中显式插入的静态宏（如 `DTRACE_PROBE`）。
  - 在未激活状态下，USDT 表现为一条单周期 `NOP` 空指令，对应用性能影响几乎为 0。
  - 当 eBPF 通过 `usdt.bpf.h` 挂载该探针时，内核将 `NOP` 指令替换为软断点，触发事件抓取。常用于 MySQL、Node.js、PostgreSQL、Python 等关键服务的零侵入性能剖析。

---

### 阶段三：极速网络与流量治理 (Day 09 - Day 13)

#### Day 09: Linux 极速数据面：XDP 核心架构与 ICMP 丢包防御
- **第一性原理**：
  传统 Linux 网络数据包处理流程中，网卡接收数据包后会分配庞大的内核数据结构 `sk_buff`（包含数十个字段与多级指针），经过各层协议栈解包处理。
  XDP（eXpress Data Path）允许在**网卡驱动刚收到 DMA 报文的最早阶段**，直接在原始数据帧（`xdp_md`）上执行 eBPF 过滤逻辑！
  ```text
  [物理网卡 DMA] -> [XDP 驱动处理] ──(XDP_DROP)─> [丢弃! 零 sk_buff 内存开销]
                           │
                           └──(XDP_PASS)─> [正常协议栈 -> 构造 sk_buff -> Socket]
  ```
- **核心动作码**：
  - `XDP_DROP`：直接丢包（最高可达 4000 万 PPS 单机处理能力，是防御 DDoS 攻击的绝佳利器）。
  - `XDP_PASS`：放行至常规内核协议栈。
  - `XDP_TX`：从原网卡原路反射发回（四层极速反射代理）。
  - `XDP_REDIRECT`：重定向到其他网卡、CPU 队列或 AF_XDP 套接字。
- **内存级单元测试（Google 工程典范）**：
  在 `days/day09_xdp_drop/xdp_test.go` 中，无需物理网卡，直接利用内核系统调用 `BPF_PROG_TEST_RUN`（通过 `Program.Test(packet)`）在内存中验证 ICMP 丢弃、TCP/UDP 放行、畸形报文边界防御，执行测试仅耗时 **20 毫秒**。

#### Day 10: 报文深度解析与数据包重写 (XDP_TX 与 NAT 原型)
- **协议栈解析原则**：
  解析任意网络协议层时，必须强制进行指针边界检查：
  ```c
  if ((void *)(eth + 1) > data_end) return XDP_PASS;
  ```
  若缺少边界保护，Verifier 会立即以 `invalid access to packet, id=0, off=14, size=20, R1_w=pkt(id=0,off=0,r=14,imm=0)` 拒绝加载。
- **报文重写技术**：
  通过交换源与目的 MAC 地址、源与目的 IP 地址，重新计算或增量更新 IPv4 校验和（利用 RFC 1624 增量更新公式），最后返回 `XDP_TX`，即可实现极简的零拷贝四层负载均衡与回包反射。

#### Day 11: 流量调度器：Traffic Control (TC / eBPF) 与 Egress 治理
- **TC 与 XDP 差异对比**：
  - XDP 仅工作于 Ingress（入站方向），且处于协议栈之前；
  - TC BPF 运行在网络协议栈层级（依托 `clsact qdisc`），既支持 Ingress，又完整支持 **Egress（出站方向）**。
  - 在 TC 钩子中，上下文为 `struct __sk_buff`，可直接读取已解析好的网络元数据（如 `skb->mark`、`skb->priority`）。常用于微服务出口流量审计、DSCP 服务质量标记与微服务限速。

#### Day 12: 面向连接的观测与优化：Socket Filter 与 SockOps
- **SockOps 原理**：
  BPF SockOps 程序挂载在 cgroup 级别，监控 TCP 连接生命周期的各个阶段（`BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`、`BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`、`BPF_SOCK_OPS_STATE_CB`）。
- **实战价值**：
  无需在应用层侵入打点，即可从内核底层精准测量 TCP 三次握手 RTT 时延、连接重传率与拥塞窗口变化，实时定位跨可用区网络抖动。

#### Day 13: 绕过内核网络协议栈：Sockmap 与 Socket Redirection
- **Service Mesh 边车网络加速第一性原理**：
  在 Kubernetes 环境中，同一个 Pod 内的业务容器与 Envoy Sidecar 进程通过本地回环（`127.0.0.1`）通信时，每个数据包都要完整穿越两遍 TCP/IP 协议栈（TCP 握手、滑动窗口、校验和计算、路由查表），消耗巨额 CPU。
- **Sockmap 零拷贝穿透**：
  通过 `BPF_MAP_TYPE_SOCKMAP` 维护本地通信的 Socket 对映射，配合 `BPF_PROG_TYPE_SK_MSG`，将发送方 Socket 的待发队列直接重定向到接收方 Socket 的接收队列，**彻底绕过整个 TCP/IP 协议栈**，本地 IPC 吞吐提升 20%~30%，延迟降低数倍。

---

### 阶段四：内核安全与访问控制 (Day 14 - Day 16)

#### Day 14: Linux 安全子系统演进与 eBPF LSM
- **LSM (Linux Security Modules) 架构演进**：
  传统 Linux 权限控制基于 DAC（自主访问控制，如文件权限 rwx）。对于安全敏感场景，Linux 引入了 LSM 框架（如 SELinux、AppArmor），在内核关键对象（进程、文件、网络）的访问路径上插入强制访问控制（MAC）钩子。
- **eBPF LSM 的革命性突破 (Linux 5.7+)**：
  传统 LSM 开发必须编写内核 C 模块并重新编译内核；而 eBPF LSM（`BPF_PROG_TYPE_LSM`）允许安全工程师直接使用 eBPF 动态挂载到任何 LSM 钩子，返回 `0` 表示放行，返回 `-EPERM` 表示直接在内核层阻断操作。

#### Day 15: 运行时提权拦截与恶意进程阻断
- **Hook 点**：`lsm/bprm_check_security`
- **防御场景**：
  当任何进程尝试通过 `execve` 执行二进制文件时，内核先调用此 LSM 钩子。
  - 读取当前进程的有效 UID、执行文件路径、宿主命名空间（Namespace）。
  - 检测是否在生产容器内执行了黑名单命令（如 `nc`, `nmap`, `/bin/sh` 提权脚本）。
  - 若命中策略，直接返回 `-EPERM` 拦截执行，并向安全审计 RingBuffer 发送高危告警。

#### Day 16: 文件防篡改与敏感目录保护
- **Hook 点**：`lsm/file_open`
- **防御场景**：
  勒索软件和挖矿木马常在入侵后尝试篡改 `/etc/passwd`、`/etc/shadow` 或篡改部署制品。
  - 通过 hook `file_open` 检查请求的操作标志位（`O_WRONLY`、`O_RDWR`）。
  - 配合 eBPF Hash Map 维护动态安全规则白名单（仅允许特定签名的运维 Agent 具备写权限）。
  - 支持用户态 Go Agent 实时动态向 Map 下发新规则，实现安全策略零重启热加载。

---

### 阶段五：内核验证器与生产级落地 (Day 17 - Day 20)

#### Day 17: 驯服 eBPF Verifier (验证器)：安全约束与避坑指南
- **抽象解释与寄存器状态推导**：
  Verifier 在加载程序时，采用抽象解释技术遍历控制流图（CFG）。它跟踪每个寄存器的数值上下界（`umin_value` ~ `umax_value`）、指针类型（`PTR_TO_STACK`、`PTR_TO_PACKET`、`PTR_TO_MAP_VALUE`）以及内存对齐。
- **三大生产级避坑军规**：
  1. **栈空间限制 512 字节**：BPF 程序栈内存上限仅 512 字节！严禁在栈上分配大数组或多层嵌套结构体。超过 512 字节必须使用 Per-CPU Array Map 或 RingBuffer 的预留空间作为堆内存替代。
  2. **边界必须显式检验**：对任何来自用户态或数据包的索引，必须显式加上 `& (MAX_LEN - 1)` 或 `if (idx >= MAX_LEN) return ...`，使 Verifier 明确获知寄存器边界安全。
  3. **有界循环约束**：在 Linux 5.3 之前所有循环必须 `#pragma unroll` 展开；现代内核支持有界循环，但执行指令总数不得超过 100 万条（复杂度上限）。

#### Day 18: 尾调用与程序模块化 (Tail Calls)
- **解决问题**：
  单单个 eBPF 程序有指令上限，且复杂逻辑揉杂在单个函数中难以维护。
- **Tail Call 机制**：
  类似于用户态的 `execve`，`bpf_tail_call()` 允许一个 eBPF 程序跳转执行另一个 eBPF 程序，复用当前的执行栈帧。
  - 核心载体：`BPF_MAP_TYPE_PROG_ARRAY`，用户态将子程序文件描述符装入数组中。
  - 组合模式：主程序负责通用的网络报文协议拆包，根据协议类型通过尾调用将报文分发给专用的 IPv4 路由处理器、IPv6 处理器或安全过滤器。

#### Day 19: 生产级指标导出：对接 Prometheus
- **设计范式**：
  内核态只做纳秒级的极速累加（Per-CPU Array 计数器与耗时分桶 Bucket），不执行复杂计算。
  用户态 Go 程序通过 HTTP 暴露标准 `/metrics` 端点。在被 Prometheus Scrape 时，通过批处理读取内核 Map 数据，组装为 Counter 与 Histogram 指标，供 Grafana 绘制 P95/P99 延迟热力图。

#### Day 20: Google SRE 视角下的 eBPF Agent 终极实战
- **工程化交付与架构**（源码对应 `days/day20_agent/`）：
  - **模块化插件架构 (`days/day20_agent/plugin.go`)**：定义规范的 `Plugin` 接口（`Init`, `Start`, `Stop`, `Health`），解耦各功能模块。
  - **核心生命周期管理器 (`days/day20_agent/agent.go`)**：统一管理插件生命周期、配置校验与上下文级联取消。
  - **高可用探针 (`/healthz`)**：内置 HTTP 健康检查，返回 200 OK 或 503 Service Unavailable，供 Kubernetes Liveness/Readiness 探针探测。
  - **优雅停机与资源安全**：接收系统信号后，执行带超时的 Shutdown，确保所有挂载到内核的 BPF Link 均被卸载，防止资源泄漏。

---

## 五、SRE 工程防线、测试规范与 CI/CD 落地

按照 Google 软件工程（*Software Engineering at Google*）与 SRE 生产级实践，本项目构建了多层自动化质量与安全防御矩阵：

### 1. 代码生成一致性门禁 (Codegen Drift Defense)
为了防止开发者修改 C 内核代码后忘记执行 `bpf2go` 导致提交的代码与二进制字节码不匹配，项目提供强一致性门禁：
```bash
make drift-check
```
该命令会自动在容器中重新编译生成代码，并通过 `git diff --exit-code` 严格检验是否存在未提交的产物漂移。

### 2. 静态代码分析门禁 (golangci-lint)
根目录配置了生产级 `.golangci.yml`，启用 `govet`、`errcheck`、`staticcheck`、`gosec`、`unused` 等多重 linter，并智能排除 `bpf2go` 自动生成的桩代码。

### 3. 多层自动化测试与 Go 原生 Fuzzing 模糊测试
- **纯函数确定性单元测试 (本地秒级执行)**：
  ```bash
  make test-local
  ```
- **全量单元测试与内核验证 (特权容器回归)**：
  ```bash
  make test
  ```
- **Go 原生 Fuzzing 模糊测试 (针对不可信输入与反序列化边界)**：
  ```bash
  make test-fuzz
  ```
  涵盖：
  - `days/day02_tracepoint`: 针对内核 RingBuffer 截断/畸形进程事件二进制反序列化；
  - `days/day10_xdp_parse`: 针对畸形以太网/IPv4/UDP 网络数据报文解析；
  - `days/day20_agent`: 针对不可信 JSON 动态配置反序列化与非法阈值注入。

### 4. 生产级最小特权配置 (Least Privilege - Google SRE 生产基线)
在企业级多租户 Kubernetes 或容器编排中，滥用全局 `--privileged: true` 会带来严峻的容器逃逸与内核安全风险。本项目基于 Linux 5.8+ 标准解耦 Capabilities 架构，提供细粒度的最小特权运行模式：
```bash
make test-least-privilege
```
该模式下：
- **剥离全局特权**：`--cap-drop=ALL` 彻底丢弃默认权限；
- **细粒度按需声明**：
  - `CAP_BPF`：仅允许加载 eBPF 程序和操作 BPF Map；
  - `CAP_PERFMON`：仅允许附加 tracepoint/kprobe 等性能追踪探针；
  - `CAP_NET_ADMIN`：仅允许附加 XDP/TC 等网络层 hook；
  - `CAP_SYS_ADMIN`：用于老版本内核兼容回退；
- **受控最小挂载**：仅挂载 `/sys/fs/bpf`、只读挂载 `/sys/kernel/btf:ro` 与 `/sys/kernel/debug:ro`。

### 5. GitHub Actions 自动化 CI 流水线
项目提供 `.github/workflows/ci.yml`，在每次 PR 和代码推送时自动触发：
1. `Lint`：静态代码检查与代码风格审查；
2. `Codegen Drift Check`：验证 C 源码与 Go 绑定的一致性；
3. `Unit Test & Fuzzing`：全量单测与 Fuzz 模糊探测；
4. `Least Privilege Check`：最小特权容器安全运行验证。

---

## 六、结语与进阶延伸

完成这 20 天的训练后，你不仅掌握了 eBPF 的核心机制（Tracing、Networking、Security、LSM），更深入掌握了 **Google 级生产软件工程体系**——从严密的自检诊断、无锁化高并发优化、内存级单测设计，到完整的优雅停机生命周期管理。

你所编写的每一行代码，均可作为构建企业级云原生可观测系统（如 Datadog Agent、Pixie）与容器安全防御引擎（如 Cilium Tetragon、Falco）的坚实基石！

---

## 七、开源规范与社区治理

本项目严格遵循开源社区最佳实践与治理准则：

- 📜 **开源协议**：本项目基于 [Apache License 2.0](./LICENSE) 协议开源。
- 🤝 **参与贡献**：欢迎提交 Issue 与 Pull Request！详细贡献规范请参考 [贡献指南 (CONTRIBUTING.md)](./CONTRIBUTING.md)。
- 🛡️ **安全策略**：若发现安全漏洞，请遵循 [安全策略 (SECURITY.md)](./SECURITY.md) 进行负责任的私密披露。
- 🌟 **行为准则**：我们倡导包容开放的协作环境，请遵守 [行为准则 (CODE_OF_CONDUCT.md)](./CODE_OF_CONDUCT.md)。

