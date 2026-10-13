# Contributing to eBPF Practical Engineering Course

感谢您对本项目的关注与支持！我们欢迎并鼓励任何形式的社区贡献，包括但不限于报告 Bug、改进文档、优化 eBPF 内核代码或补充 Go 用户态功能。

为了保证项目的工程质量与严谨性（遵循 Google 工程实践），请在提交代码前仔细阅读本指南。

---

## 目录

- [行为准则](#行为准则)
- [开发环境准备](#开发环境准备)
- [开发与工作流规范](#开发与工作流规范)
  - [分支管理](#分支管理)
  - [代码风格](#代码风格)
  - [eBPF 与 Go 桩代码生成](#ebpf-与-go-桩代码生成)
  - [提交信息规范 (Commit Message)](#提交信息规范-commit-message)
- [测试与质量验证](#测试与质量验证)
  - [单元测试与竞态检测](#单元测试与竞态检测)
  - [代码漂移检测](#代码漂移检测)
  - [模糊测试 (Fuzzing)](#模糊测试-fuzzing)
  - [静态代码检查 (Linter)](#静态代码检查-linter)
- [Pull Request 提交流程](#pull-request-提交流程)

---

## 行为准则

参与本项目即代表您同意遵守我们的 [行为准则 (CODE_OF_CONDUCT.md)](./CODE_OF_CONDUCT.md)。请始终保持友好、尊重与专业。

---

## 开发环境准备

由于 eBPF 程序依赖较新的 Linux 内核特性（BPF CO-RE、BTF、BTF-powered tracing 等），推荐使用我们预配置的 Docker 开发沙箱：

1. **克隆代码库**：
   ```bash
   git clone https://github.com/zixiliuyue/ebpf.git
   cd ebpf
   ```

2. **构建并启动容器开发沙箱**：
   ```bash
   # 构建包含 clang-14, llvm, libbpf-dev, golang 的集成镜像
   make docker-build

   # 启动特权/沙箱容器并进入交互环境
   make docker-shell
   ```

---

## 开发与工作流规范

### 分支管理
- 主分支为 `main`，始终保持稳定可发布状态。
- 新增功能或修复问题请基于 `main` 分支拉出特性分支：
  - 功能特性：`feat/<feature-name>`
  - 缺陷修复：`fix/<bug-summary>`
  - 文档更新：`docs/<doc-title>`

### 代码风格
- **Go 代码**：
  - 必须通过 `golangci-lint run ./...` 检查。
  - 遵循标准格式化工具规范（`gofmt` / `goimports`）。
  - 所有导出的函数、结构体、字段必须附带详尽的中文注释，说明意图与边界条件。
- **C / eBPF 内核代码**：
  - 遵循 Linux 内核 C 编码风格（或 `clang-format -style=LLVM`）。
  - eBPF 辅助函数、Map 定义与 hook 点需标明内核版本兼容性与 BPF 验证器约束。

### eBPF 与 Go 桩代码生成
本项目采用 `cilium/ebpf` 的 `bpf2go` 工具自动生成 Go 桩代码。
如果您修改了任何 `*.bpf.c` 文件，请重新执行：
```bash
make generate
```
并确保生成的 `*_bpfel.go` 文件一同纳入 Git 版本追踪。

### 提交信息规范 (Commit Message)
所有提交必须遵循 Conventional Commits 规范，中文详细描述，推荐格式如下：

```text
【类型】简短描述（不超过50字）

【详细说明】
* 背景：说明为什么要做这个改动
* 变更内容：
  * 修改点1
  * 修改点2
* 影响范围：
  * 涉及模块/服务
  * 是否影响接口/数据结构
* 风险评估：
  * 潜在风险点
  * 是否需要回滚方案

【测试说明】
* 测试方式：
* 测试结果：
```
类型包括：`feat`、`fix`、`perf`、`refactor`、`docs`、`test`、`chore`。

---

## 测试与质量验证

在提交 PR 之前，请在本地容器环境中执行完整的质量门禁验证：

```bash
# 1. 运行全量单元测试与并发竞态检测 (-race)
make test-race

# 2. 运行内核代码与 Go 桩代码零漂移检查
make drift-check

# 3. 运行静态代码检查
make lint

# 4. 运行 Go 原生模糊测试 (Fuzzing)
make test-fuzz
```

所有 PR 在合并前必须通过 GitHub Actions CI 的全量自动化流水线。

---

## Pull Request 提交流程

1. 保持 PR 聚焦，单次提交尽量只解决一个明确的问题（外科手术式改动）。
2. 填写完整的 PR 模板，详细说明改动动机、实现思路以及测试验证结果。
3. 确保 CI 流水线全部绿色（通过）。
4. 代码审查者给出 Review 意见后，及时响应并更新提交。
