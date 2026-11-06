# wist-console

计算区运维台的 **BFF**。浏览器只跟它说话：到证据服务的 mTLS / 租户 / scope / 敏感度
全在这里，页面不持有任何凭据。

设计：`wist-design/doc/design/console/console-architecture.md`
前端：[`wist-console-web`](https://github.com/dayu-sec/wist-console-web)
部署：[`wist-console-stack`](https://github.com/dayu-sec/wist-console-stack)

## 接口

```text
POST /api/login
     体：{ token } 或 `Authorization: Bearer wcr_…`
     → { credential_id, subject, roles, audience, expires_at }
     契约由 `wist-cred-peer`（≥0.5）统一：401 `credential_missing` / `credential_invalid`，
     403 `role_required`，503 `credential_store_unavailable`。
     其它接口仍然每请求带 Bearer —— 登录只负责"先确认这串是谁"，不换 session。

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

GET  /api/metrics
     → { generated_at_ms, window_seconds, source, totals, agents: [...], catalog: [...] }
     读的是**本栈** VictoriaMetrics（数据面把 agent 采集指标镜像进来），不是网关栈那份。

GET  /api/metrics/agents/{agent_id}/history?window_seconds=&step_seconds=
     → { agent_id, window_seconds, step_seconds, labels, series: [{ metric, title, unit, points }] }
     窗口 5m–24h、步长 10–900s（越界自动夹紧）；单位已在 BFF 换算成 percent / milliseconds / bytes。
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

## 运行指标

两份 VictoriaMetrics **互不聚合**（谁写谁查）：

- 网关栈那份：`WPARSE_VM_ENDPOINT`，给控制面观测页，含引擎 / 管道统计（`wparse_*`）；
- 本栈那份（`[metrics] base_url`）：数据面用 `CONSOLE_VM_ENDPOINT` 把 **同一批 agent 采集指标**
  再写一份，给星象台的「运行指标」页。

所以本栈的序列数少于网关栈是正常的 —— 差值正是只写网关栈的引擎统计。指标名 / label 键 /
单位换算全部取自 `wist-metrics` 的 `names` 常量表，读侧不再手写名字（历史上曾因此整页空白）。
没配 `[metrics]` 时这一域回 `503 metrics_not_configured`（「没接入」，不是故障）。

## 入口身份

`auth.mode = "cred"`（默认）：请求带 `Authorization: Bearer wcr_…`，摘要由 `wist-cred` 通过
mTLS 推到 `credentials.listen_addr`（默认 `3103`），BFF 用 `wist-cred-peer` 验；没有 token → 401，
角色不够 → 403。
`auth.mode = "ingress"`：交给入口（VPN / 堡垒机 / 反代）认证，再把操作员写在 `x-console-operator` 里。
**没有「不校验」这一档** —— 一个计算区界面不该默认谁都能进。

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
