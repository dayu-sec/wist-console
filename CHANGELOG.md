# CHANGELOG

## 0.1.0 · 2026-11-02

首个骨架：计算区运维台的 BFF。

- `GET /api/health`：聚合证据 / atlas / 采集量 / 设备状态的就绪度（后两者显式 `not_configured`）；
- `GET /api/evidence`、`GET /api/evidence/{id}`、`POST /api/evidence/{id}:presign`：
  透传证据服务，状态码与 JSON 原样返回；
- 到证据服务的身份（租户 / scope / 敏感度）只来自配置，URL 里的 `tenant` 被丢弃；
- 入口身份：`ingress` 模式要求操作者头，`dev` 仅用于本机；
- 不缓存正文、不代理正文、不自己做授权判断。
