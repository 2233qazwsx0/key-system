# 卡密系统

## 架构

```
loadstring(game:HttpGet("https://your-worker.workers.dev/loader"))()
  ↓
Loader（采集HWID + 输入卡密）
  ↓ POST /api/verify
Workers 查 D1（验证卡密 + HWID）
  ↓ 返回 token
Loader GET /api/script?token=xxx
  ↓
Workers 验证 token → R2 读主脚本 → 返回
  ↓
loadstring(主脚本)() → WindUI 运行
```

## 技术栈

- Cloudflare Workers
- D1（卡密存储）
- R2（主脚本存储）

## 部署

1. `wrangler deploy`
2. 配置 D1、R2 绑定
3. 设置 ADMIN_KEY 环境变量

## 管理后台

访问 `https://your-worker.workers.dev/admin/`，输入 admin key