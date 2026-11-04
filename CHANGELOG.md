# CHANGELOG

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
