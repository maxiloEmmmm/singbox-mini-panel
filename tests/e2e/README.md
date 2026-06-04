# E2E

这个目录用于放闭环 Web 测试脚本。

当前约定：

- `npm run check` 做轻量类型检查，不构建。
- `npm run verify` 做轻量验证，不构建、不启动服务。
- `npm run verify:web` 要求已有 Web 服务。
- 可通过 `WEB_BASE_URL` 覆盖探测地址。
- Obscura CDP 测试后续放在 `tests/e2e/obscura/`。

修改后执行：

```bash
npm run verify
```

已有 Web 服务时执行：

```bash
npm run verify:web
```

需要完整生产构建验证时执行：

```bash
npm run verify:full
```
