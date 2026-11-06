# ===========================================================================
# wist-field-api — 运行镜像（多架构）
#
# 与 `wist-gateway` 同一套做法：二进制由 release 流水线按平台**原生**编译，
# build context（本目录）按 `amd64/` `arm64/` 提供，镜像只负责打包。
# ===========================================================================
FROM ubuntu:24.04

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-field-api"
LABEL org.opencontainers.image.description="Compute-zone read API: evidence / atlas / metrics aggregation"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# 运行时只需要根证书与静态 busybox（供编排做健康检查）；uid 固定 10001。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates busybox-static \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -s /usr/sbin/nologin wist

COPY ${TARGETARCH}/wist-field-api /usr/local/bin/wist-field-api

# 配置与密钥由 stack 挂载到 /etc/wist-field-api。
ENV WIST_FIELD_CONFIG=/etc/wist-field-api/field-api.toml \
    WIST_FIELD_SEC_FILE=/etc/wist-field-api/.wist/sec-value.yml

USER 10001:10001
EXPOSE 8080

# 健康检查由编排（compose）定义；镜像里只提供 /bin/busybox。
ENTRYPOINT ["wist-field-api"]
