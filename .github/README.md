# 工作流说明

- `CI`：提交和合并请求触发格式、静态检查、测试及打包验证，也支持从 Actions 页面手动运行。失败时应修复对应检查，不要关闭检查来掩盖错误。
- `Docs`：始终构建文档并检查死链接。分支仓库默认不部署 Pages；需要发布时，先在仓库 Settings → Pages 中选择 GitHub Actions，再将 Actions 仓库变量 `ENABLE_GITHUB_PAGES` 设为 `true`。
- `CD`：推送 `v*` 标签或手动触发时构建发布包。向 `GunduLabs/packages` 分发的任务仅在上游仓库执行；当前仓库仍可发布自己的 GitHub Release。
- `Audit`：定时或手动检查依赖安全公告。

本地复现主要检查：`just fmt-check`、`just lint`、`just test`、`just build-docs`。这些命令需要对应的 Rust、系统开发库及 Bun 依赖。
