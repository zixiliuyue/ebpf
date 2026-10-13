## 变更描述 (Description)

<!-- 请简述本次 PR 解决的问题或引入的新功能 -->

## 关联 Issue (Related Issues)

<!-- 例如 Fixes #123, Closes #456 -->

## 变更类型 (Type of Change)

- [ ] 🐛 Bug 修复 (Non-breaking bug fix)
- [ ] ✨ 新功能 (Non-breaking new feature)
- [ ] 📝 文档更新 (Documentation only)
- [ ] 🎨 代码重构/性能优化 (Refactor or performance improvement)
- [ ] 🧪 测试用例补充 (Adding missing tests)
- [ ] ⚙️ CI/CD 或工程配置更新 (CI/CD or tooling changes)

## 验证与测试清单 (Verification Checklist)

提交 PR 前，请确保已在本地通过以下门禁检查：

- [ ] `make test-race`：所有单元测试通过，且无并发竞态检测警告
- [ ] `make drift-check`：eBPF C 源码与 Go 桩代码保持同步且零漂移
- [ ] `make lint`：通过 `golangci-lint` 检查
- [ ] `make test-fuzz`：模糊测试通过
- [ ] 代码中新增导出的函数、类型与重要分支已补充详尽的中文注释
