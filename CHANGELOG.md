# CHANGELOG

## 0.1.11 · 2026-11-05

- **接入 `wist-cred-peer` 做认证与授权，删掉 `dev`（不校验）模式**。
  `auth.mode = "cred"`（默认）：浏览器带 `Authorization: Bearer wcr_…`，BFF 用摘要表验；
  `cred` 通过 mTLS 把 `{digest, subject, roles, expires_at, signature}` 推到
  `credentials.listen_addr`（默认 3103），**只落 sha256**，重启不丢、撤销不复活。
- 401 / 403 分开：没带 token → `console_credential_missing`；不认识 / 过期 / 撤销 →
  `console_credential_invalid`（对外不区分原因）；角色不够 → `console_role_required`。
- `auth.mode = "ingress"` 保留：入口已经做了认证、并能保证头不被伪造时可用。
- 配置 fail-closed：`mode = "cred"` 但缺 `[credentials]`、`cred.toml` 读不到、
  `required_roles` 不在 `[verify].roles` 里 —— 都在**启动期**报错，不带病运行。
- **资产读接口收进 BFF**：新增 `GET /api/atlas/{*path}` → `{atlas.base_url}/api/{path}`。
  以前 `/atlas/api/*` 由 nginx 直连 atlas-web，等于给令牌认证留了个后门；
  现在与其它接口同一道门。只放行 GET，`/internal/*` 与路径穿越一律 400。

## 0.1.10 · 2026-11-05

- 新增 `[metrics] base_url`（VictoriaMetrics）：`/api/health` 多一条「运行指标存储」探活，
  `sources.metrics` 从 `not_configured` 变成真实状态。
- `[atlas]` 新增 `sink_url`（**数据面视角**的写端点），`/api/integration` 多一块 `atlas` 接入示例
  （两字段 `{cust_id, content}`，`content` 是 DSNAP 记录），`warp_parse.env` 相应多一个 `ATLAS_SINK_URL`。
- atlas 的 `/healthz` 现在也带 `probe` 块，接口可用性页会像证据写端点一样显示
  「写探针 N 秒前成功」——两条写链路同一套判据。

## 0.1.9 · 2026-11-05

- `/api/integration` 改成**三字段契约**：示例记录是 `{cust_id, cmd_id, content}`，
  连接器不再带 `username` / `password`，`env` 只剩 `EVIDENCE_SINK_URL`；
  sink 分组名改成 `evidence-uplink`（与 `wist-console-stack` 的示例对齐）。
- 「接口可用性」的写端点检查会读证据服务 `/healthz` 的 `probe` 块，直接显示
  「写探针 12 秒前成功（3 ms）」，而不是只说「端口通」。

## 0.1.8 · 2026-11-04

- 代理读正文的响应补 `cache-control: no-store` 与 `x-content-type-options: nosniff`：
  证据正文不能被浏览器 / 中间代理缓存。

## 0.1.7 · 2026-11-04

- 新增 `GET /api/evidence/{artifact_id}/content`：代理读正文。
  证据服务 `objects.kind = file` 时不签发预签名 URL（`:presign` 回 501），页面改用这条拿原文；
  BFF 依旧不缓存、不落盘，浏览器依旧不持任何凭据。

## 0.1.6 · 2026-11-04

- 接口可用性变成**可观测的功能**：`/api/health.interfaces[]` 每条多一个 `covers`，
  写明这一次探活验到了哪一层（页面直接展示，不让「绿」含糊）。
- 证据读端点改用**真读**探活（`GET /internal/evidence?limit=1`，带服务身份）：
  鉴权、租户/敏感度闸与 PG 索引都会被验到；不再只戳 `/healthz`。
- 写端点探活只验端口就绪，**不发测试写入**（不往证据库塞垃圾）。

## 0.1.5 · 2026-11-04

- `/api/health` 新增 `interfaces`：逐条探活 `evidence_read` / `evidence_write` / `atlas`，
  回状态、延迟（`latency_ms`）与最近检查时间（`checked_at_ms`）。三个探活**并发**发，
  一个上游挂掉不会把另外两条的延迟一起拖长。
- 新增配置项 `integration.sink_health_url`：**BFF 视角**的写端点探活地址。
  它与 `integration.sink_url` 不是一回事 —— 后者是给数据面看的（BFF 到不了）。
  没配时写端点显示 `not_configured` 并说明缺哪个配置项。
- `sources.atlas` 不再单独发一次探测：直接复用 `interfaces` 里那次结果。

## 0.1.4 · 2026-11-02

- 新增 `GET /api/integration`：给「数据面接入」页返回写端点、认证方式、允许的 kind，
  以及两份可直接 copy 的 wparse 配置（连接器 + sink 分组）。**不返回站点 token**。

## 0.1.3 · 2026-11-02

- `/api/health` 的数据源键 `pipeline` 改名 `metrics`（运行指标），与前端路由 `#/metrics` 对齐。

## 0.1.2 · 2026-11-02

- 镜像构建改用 `wist-gateway` 的同一套做法：release 流水线按平台**原生**编译二进制，
  镜像只打包 `docker/amd64` / `docker/arm64`，不再在镜像内编译。
- 运行镜像改为 `ubuntu:24.04` + `busybox-static`，uid 固定 10001。
- GitHub Release 附带三个平台的原生二进制 tarball。

## 0.1.1 · 2026-11-02

- 修正运行时镜像：`busybox:stable` 需要 glibc 2.38，bookworm 只有 2.36，容器健康检查会
  直接报 `GLIBC_2.38 not found`；改用静态的 `busybox:stable-musl`。

## 0.1.0 · 2026-11-02

首个骨架：计算区运维台的 BFF。

- `GET /api/health`：聚合证据 / atlas / 采集量 / 设备状态的就绪度（后两者显式 `not_configured`）；
- `GET /api/evidence`、`GET /api/evidence/{id}`、`POST /api/evidence/{id}:presign`：
  透传证据服务，状态码与 JSON 原样返回；
- 到证据服务的身份（租户 / scope / 敏感度）只来自配置，URL 里的 `tenant` 被丢弃；
- 入口身份：`ingress` 模式要求操作者头，`dev` 仅用于本机；
- 不缓存正文、不代理正文、不自己做授权判断。
