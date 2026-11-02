# wist-console

计算区运维台的 **BFF**。浏览器只跟它说话：到证据服务的 mTLS / 租户 / scope / 敏感度
全在这里，页面不持有任何凭据。

设计：`wist-design/doc/design/console/console-architecture.md`
前端：[`wist-console-web`](https://github.com/dayu-sec/wist-console-web)
部署：[`wist-console-stack`](https://github.com/dayu-sec/wist-console-stack)

## 接口

```text
GET  /api/health
     → { status, sources: { evidence|atlas|pipeline|devices: { status, detail? } } }

GET  /api/evidence?kind=&subject_id=&since=&limit=&cursor=
     → 透传证据服务的 { artifacts, next_cursor }

GET  /api/evidence/{artifact_id}
     → 透传证据服务的索引行

POST /api/evidence/{artifact_id}:presign
     → 透传证据服务的 { artifact_id, url, expires_in_seconds, expires_at }
```

## 三条纪律

1. **浏览器不持凭据**：`evidence.tenant` / `scopes` / `max_sensitivity` 只来自配置；
   URL 里带的 `tenant` 参数会被丢掉。
2. **不做二次判断**：证据服务回 `404` 就回 `404`（不区分「不存在」和「无权看」），
   BFF 不自己拼授权结论。
3. **不落正文**：预签名 URL 直接透传，BFF 不缓存、不代理正文；需要流式读时另开
   `/api/evidence/{id}/content`（P1），不在这个骨架上顺手加。

## 入口身份

`auth.mode = "ingress"`（默认）要求请求带 `x-console-operator`（由 VPN / 堡垒机 / 反代注入）；
`auth.mode = "dev"` 只用于本机联调。**不建议**把 `dev` 暴露到任何共享网络。

## 运行

```bash
cargo run -- console.example.toml
# 或 WIST_CONSOLE_CONFIG=/etc/wist-console/console.toml wist-console
```

端口：容器内 `8080`（由 console-web 的 nginx 反代 `/api`）。

## 构建

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
docker build -t wist-console:dev .
```
