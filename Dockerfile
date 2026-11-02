# wist-console — 计算区运维台的 BFF
#
# 与 `wist-atlas` 同构：镜像内多阶段构建；运行时只装二进制与 CA。
FROM rust:1.99-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY README.md LICENSE ./
RUN cargo build --release --locked

FROM busybox:stable-musl AS busybox

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin wist

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/target/release/wist-console /usr/local/bin/wist-console
COPY --from=busybox /bin/busybox /bin/busybox

# 配置与密钥由 stack 挂载到 /etc/wist-console（0640，属主=wist）。
ENV WIST_CONSOLE_CONFIG=/etc/wist-console/console.toml \
    WIST_CONSOLE_SEC_FILE=/etc/wist-console/.wist/sec-value.yml

USER wist
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/bin/busybox", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["wist-console"]
