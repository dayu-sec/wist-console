# wist-console

计算区运维台的 **BFF**。浏览器只跟它说话：到证据服务的 mTLS / 租户 / scope / 敏感度
全在这里，页面不持有任何凭据。

设计：`wist-design/doc/design/console/console-architecture.md`
前端：[`wist-console-web`](https://github.com/dayu-sec/wist-console-web)
部署：[`wist-console-stack`](https://github.com/dayu-sec/wist-console-stack)

## 接口

```text
GET  /api/health
     → { status, sources: { evidence|atlas|metrics|devices: { status, detail? } },
         interfaces: [{ id, label, covers, url?, status, detail?, latency_ms?, checked_at_ms? }] }

GET  /api/evidence?kind=&subject_id=&since=&limit=&cursor=
     → 透传证据服务的 { artifacts, next_cursor }

GET  /api/evidence/{artifact_id}
     → 透传证据服务的索引行

GET  /api/evidence/{artifact_id}/content
     → 代理读正文（本地文件模式没有预签名时走这条）

POST /api/evidence/{artifact_id}:presign
     → 透传证据服务的 { artifact_id, url, expires_in_seconds, expires_at }

GET  /api/integration
     → { evidence: { write_url, auth, allowed_kinds, ... },
         warp_parse: { connector, sink_group, env } }
```

`sources` 是「这个域接没接上」；`interfaces` 是「这条接口此刻通不通」——逐条探活
（`evidence_read` / `evidence_write` / `atlas`），带延迟、检查时间与 `covers`（这次到底验到了哪一层）。
三个探活并发发，一个上游挂掉不会拖长另外两个；没配地址的接口返回 `not_configured`，并说明缺哪个配置项。

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
```

镜像是**打包预编译二进制**（与 `wist-gateway` 同构，不在镜像里编译）：

```bash
# Linux 开发机：先编原生二进制再打包
cargo build --release --locked --target aarch64-unknown-linux-gnu
mkdir -p docker/arm64 && cp target/aarch64-unknown-linux-gnu/release/wist-console docker/arm64/
docker build -t wist-console:dev docker
```

日常直接用 CI 产物：`ghcr.io/dayu-sec/wist-console:v0.1.2-alpha`。
镜像以 `10001:10001` 运行；挂进来的配置 0644，`sec-value.yml` 0640 且属主为 10001。
