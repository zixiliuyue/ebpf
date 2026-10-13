# Security Policy

## Supported Versions

我们优先维护 `main` 分支的最新代码并提供安全补丁。

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0.0 | :x:                |

---

## 漏洞报告与负责任的披露 (Reporting a Vulnerability)

我们极其重视 eBPF 程序与内核交互时的安全性与稳定性（特别是内存越界访问、BPF 提权、拒绝服务以及并发安全隐患）。

如果您在本项目中发现了任何潜在的安全漏洞，请**不要**直接公开发布 GitHub Public Issue。

请按以下方式联系核心维护团队：

1. **通过 GitHub 私密安全公告 (Private Vulnerability Reporting)**：
   访问仓库的 Security 选项卡并点击 "Report a vulnerability"。
2. **通过电子邮件**：
   发送邮件至仓库维护者邮箱，邮件标题注明 `[SECURITY] eBPF Project Vulnerability Report`。

### 报告时请提供以下信息：
- 受到影响的模块或目录（例如 `days/day16_lsm` 或 `days/day20_agent`）。
- 详细的漏洞描述与触发条件。
- 概念验证代码（PoC）或复现步骤（含使用的内核版本与环境）。
- 您对漏洞危害的评估建议。

### 我们的响应承诺：
- 我们将在 **48 小时** 内确认收到您的漏洞报告并开始评估。
- 在漏洞确认后，我们将尽快在私密分支准备修复补丁，并在 **14 天** 内发布安全更新公告。
- 修复发布后，我们会在 Release Notes 和安全公告中对负责任报告漏洞的研究员予以鸣谢（若您同意公开）。
