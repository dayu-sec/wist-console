//! HTTP 面：浏览器 → BFF。
//!
//! 两条纪律：
//! 1. **浏览器不持凭据**：到证据服务的身份（租户 / scope / 敏感度）只来自配置；
//! 2. **不做二次判断**：证据服务回什么就回什么（404 保持 404），BFF 只负责转发与聚合。

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use crate::config::{AuthMode, Config};
use crate::upstream::{EvidenceClient, UpstreamResponse};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub evidence: Arc<EvidenceClient>,
    pub http: reqwest::Client,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/health", get(health))
        .route("/api/evidence", get(list_evidence))
        .route("/api/integration", get(integration))
        .route(
            "/api/evidence/{artifact_id}",
            get(get_evidence).post(presign_evidence),
        )
        // 代理读正文：预签名不可用的部署（证据服务 objects.kind = file）走这条。
        .route(
            "/api/evidence/{artifact_id}/content",
            get(get_evidence_content),
        )
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// 聚合各数据源的就绪度。`not_configured` 不是错误 —— 是「这个域还没接」。
///
/// `interfaces` 是给「接口可用性」页用的：每个条目要么是一次真请求的结果，
/// 要么是「没配地址」。`covers` 写清楚这一次请求到底验到了哪一层——
/// 运维看「绿」时需要知道它绿的是什么。
#[derive(serde::Serialize)]
struct Health {
    status: &'static str,
    sources: serde_json::Value,
    interfaces: serde_json::Value,
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }

    let write_url = state.config.integration.sink_health_url.clone();
    let atlas_url = state
        .config
        .atlas
        .as_ref()
        .map(|atlas| format!("{}/healthz", atlas.base_url.trim_end_matches('/')));
    let metrics_url = state
        .config
        .metrics
        .as_ref()
        .map(|metrics| format!("{}/health", metrics.base_url.trim_end_matches('/')));

    // 并发探活：一个上游挂掉不该把另外两个的延迟一起拖长。
    let (read_iface, write_iface, atlas_iface, metrics_iface) = tokio::join!(
        probe_evidence_read(&state),
        probe_opt(
            &state.http,
            "evidence_write",
            "证据写端点",
            "BFF → 证据写监听：端口就绪 + 服务自报的写探针（每 5 分钟一笔真写入）。\n数据面到该地址的网络可达性只能由数据面自己验证。",
            write_url,
            "未配置 integration.sink_health_url（BFF 视角的探活地址）",
        ),
        probe_opt(
            &state.http,
            "atlas",
            "资产拓扑 API",
            "BFF → 资产拓扑：`/healthz` 进程就绪 + 服务自报的写探针\n（转换 → 落库 → 物化 一整条；与 evidence 的 `probe` 块同一形状）。",
            atlas_url,
            "未配置 atlas.base_url",
        ),
        probe_opt(
            &state.http,
            "metrics",
            "运行指标存储",
            "BFF → VictoriaMetrics：`/health` 可查询。只证明存储活着，\n不代表数据面正在上报（那是数据面自己的事）。",
            metrics_url,
            "未配置 metrics.base_url",
        ),
    );

    // `sources` 由同一次探活派生，不再重复发请求。
    let evidence = source_from(&read_iface);
    let atlas = source_from(&atlas_iface);
    let metrics = source_from(&metrics_iface);
    let interfaces = vec![read_iface, write_iface, atlas_iface, metrics_iface];

    Json(Health {
        status: "ok",
        interfaces: json!(interfaces),
        sources: json!({
            "evidence": evidence,
            "atlas": atlas,
            "metrics": metrics,
            "devices": {
                "status": "not_configured",
                "detail": "containment_capabilities 尚未上报",
            },
        }),
    })
    .into_response()
}

/// 展示给运维的「数据面接入」：写端点 + 可直接 copy 的 wparse 配置。
///
/// **不回传站点 token**，只回占位符。
async fn integration(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let sink_base = state
        .config
        .integration
        .sink_url
        .clone()
        .unwrap_or_else(|| "http://<证据服务内网地址>:18800".to_string());
    let sink_base = sink_base.trim_end_matches('/').to_string();
    let write_url = format!("{sink_base}/internal/evidence");

    // 连接器只负责 POST，**不做字段映射**；发出去的就是 OML 的输出。
    // 三字段（cust_id / cmd_id / content）+ 证据服务 `auth = "none"`：不需要 token。
    let connector = format!(
        r#"[[connectors]]
allow_override = ["endpoint", "headers", "fmt", "batch_size", "timeout_secs", "max_retries"]
id = "evidence_sink"
type = "http"

[connectors.params]
endpoint = "{write_url}"
method = "POST"
fmt = "json"
batch_size = 1
timeout_secs = 5
max_retries = 3
compression = "none"

[connectors.params.headers]
Content-Type = "application/json"
"#
    );

    let sink_group = format!(
        r#"[sink_group]
name = "evidence-uplink"
oml = ["evidence_uplink"]
tags = ["biz:evidence"]
batch_size = 1
batch_timeout_ms = 300

[[sink_group.sinks]]
name = "evidence"
connect = "evidence_sink"
tags = ["sink:evidence"]

[sink_group.sinks.params]
endpoint = "{write_url}"
batch_size = 1
"#
    );

    // 环境变量只给**数据面能看到的**地址；atlas 没配写地址就不出现在 env 里。
    let atlas_base = state.config.atlas.as_ref().and_then(|atlas| {
        atlas
            .sink_url
            .as_ref()
            .map(|sink_url| sink_url.trim_end_matches('/').to_string())
    });
    let mut env = serde_json::Map::new();
    env.insert("EVIDENCE_SINK_URL".to_string(), json!(sink_base));
    if let Some(atlas_base) = atlas_base.as_ref() {
        env.insert("ATLAS_SINK_URL".to_string(), json!(atlas_base));
    }

    let atlas = atlas_base.map(|base| {
        json!({
            "write_url": format!("{base}/internal/atlas"),
            "auth": "none",
            // `cust_id` 是 atlas 的租户 UUID（不是客户号）：一个 wparse 可以写多个租户。
            "customer": "<atlas 租户 UUID>",
            // 资产拓扑写端点：只有两个字段 —— 证据服务的 `cmd_id` 是它自己的幂等键，
            // atlas 写的是状态快照，幂等键在快照的 `snap_id` 里。
            "record": {
                "cust_id": "<atlas 租户 UUID>",
                "content": { "schema": "v1", "biz": "agent-discovery", "body": "<DSNAP 快照 JSON 字符串>" },
            },
        })
    });

    Json(json!({
        "evidence": {
            "write_url": write_url,
            "auth": "none",
            // `tenant` 就是客户 id：租户与客户已经合并成一个维度。
            "customer": state.config.evidence.tenant,
            "allowed_kinds": state.config.integration.allowed_kinds,
            "record": {
                "cust_id": state.config.evidence.tenant,
                "cmd_id": "cmd-20261105-001",
                "content": { "summary": { "overall": "warn" }, "findings": [] },
            },
        },
        // 资产拓扑写端点：只有两个字段（证据服务的 `cmd_id` 是它自己的幂等键）。
        "atlas": atlas,
        "warp_parse": {
            "connector": connector,
            "sink_group": sink_group,
            "env": env,
        },
    }))
    .into_response()
}

async fn list_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let query = query
        .map(|raw| strip_tenant(&raw))
        .filter(|raw| !raw.is_empty());
    match state.evidence.list(query.as_deref()).await {
        Ok(response) => passthrough(response),
        Err(err) => upstream_failed(err),
    }
}

async fn get_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(artifact_id): Path<String>,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let Some(artifact_id) = valid_artifact_id(&artifact_id) else {
        return not_found();
    };
    match state.evidence.get(artifact_id).await {
        Ok(response) => passthrough(response),
        Err(err) => upstream_failed(err),
    }
}

/// `POST /api/evidence/{artifact_id}:presign`。
///
/// 与证据服务同一条路由技巧：`{artifact_id}` 会把 `art_x:presign` 整段吃下来。
/// `GET /api/evidence/{artifact_id}/content`：原文代理读。
///
/// 本地文件存储（`objects.kind = file`）不签发预签名 URL，页面就用这条拿正文：
/// BFF 带自己的身份去证据服务取原文，浏览器始终不碰任何凭据。
async fn get_evidence_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(artifact_id): Path<String>,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let Some(artifact_id) = valid_artifact_id(&artifact_id) else {
        return not_found();
    };
    match state.evidence.content(artifact_id).await {
        Ok(response) => passthrough_uncached(response),
        Err(err) => upstream_failed(err),
    }
}

async fn presign_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let Some(artifact_id) = raw.strip_suffix(":presign") else {
        return not_found();
    };
    let Some(artifact_id) = valid_artifact_id(artifact_id) else {
        return not_found();
    };
    match state.evidence.presign(artifact_id).await {
        Ok(response) => passthrough(response),
        Err(err) => upstream_failed(err),
    }
}

/// 入口身份：`ingress` 模式下必须带操作者头（由 VPN / 堡垒机 / 反代注入）。
fn require_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, OperatorError> {
    if state.config.auth.mode == AuthMode::Dev {
        return Ok(None);
    }
    let name = &state.config.auth.operator_header;
    let value = headers
        .get(name.as_str())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match value {
        Some(operator) => Ok(Some(operator.to_string())),
        None => Err(OperatorError {
            header: name.clone(),
        }),
    }
}

/// 小结构而不是 `Response`：后者会把 `Result` 撑到上百字节（clippy::result_large_err）。
struct OperatorError {
    header: String,
}

impl OperatorError {
    fn into_response(self) -> Response {
        error_response(
            StatusCode::UNAUTHORIZED,
            "console_operator_missing",
            format!("missing ingress operator header {}", self.header),
        )
    }
}

fn valid_artifact_id(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains("..") {
        return None;
    }
    Some(trimmed)
}

/// 租户永远来自配置；浏览器带的 `tenant` 参数一律丢掉。
fn strip_tenant(query: &str) -> String {
    query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.starts_with("tenant="))
        .collect::<Vec<_>>()
        .join("&")
}

fn passthrough(response: UpstreamResponse) -> Response {
    let mut builder = Response::new(axum::body::Body::from(response.body));
    *builder.status_mut() = response.status;
    builder.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    builder
}

/// 正文透传：多带两条头。
/// - `no-store`：证据正文不能被浏览器 / 中间代理缓存（它有过期与保密要求）；
/// - `nosniff`：正文是 JSON 文件，不能让浏览器猜成 HTML。
fn passthrough_uncached(response: UpstreamResponse) -> Response {
    let mut builder = passthrough(response);
    builder
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    builder.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    builder
}

fn upstream_failed(message: String) -> Response {
    error_response(StatusCode::BAD_GATEWAY, "console_upstream_failed", message)
}

/// 没配地址的接口直接标 `not_configured`；这是「还没接」，不是故障。
async fn probe_opt(
    http: &reqwest::Client,
    id: &str,
    label: &str,
    covers: &str,
    target: Option<String>,
    missing_detail: &str,
) -> serde_json::Value {
    match target {
        Some(url) => probe(http, id, label, covers, &url).await,
        None => entry(
            id,
            label,
            covers,
            None,
            "not_configured",
            Some(missing_detail.to_string()),
            None,
        ),
    }
}

/// 单接口探活：状态 + 延迟 + 检查时间。错误信息截断，避免把整段 reqwest 报错塞进页面。
async fn probe(
    http: &reqwest::Client,
    id: &str,
    label: &str,
    covers: &str,
    url: &str,
) -> serde_json::Value {
    let started = std::time::Instant::now();
    let result = http
        .get(url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(response) if response.status().is_success() => {
            // 证据服务的 `/healthz` 会带 `probe` 块（每 5 分钟一条真实写入的结果），
            // 有就翻成一句人话，没有就留空。
            let detail = write_probe_detail(response).await;
            entry(id, label, covers, Some(url), "ok", detail, Some(latency_ms))
        }
        Ok(response) => entry(
            id,
            label,
            covers,
            Some(url),
            "unavailable",
            Some(format!("HTTP {}", response.status().as_u16())),
            Some(latency_ms),
        ),
        Err(err) => entry(
            id,
            label,
            covers,
            Some(url),
            "unavailable",
            Some(truncate(&err.to_string())),
            Some(latency_ms),
        ),
    }
}

/// 读端点用**真读**探活（`limit=1`）：鉴权、租户/敏感度闸、PG 索引都会走到，
/// 比只戳 `/healthz` 有意义——读端点挂了，证据页就是空的。
async fn probe_evidence_read(state: &AppState) -> serde_json::Value {
    const COVERS: &str = "BFF → 证据服务：带服务身份真读一次 `GET /internal/evidence?limit=1`，\
覆盖鉴权、租户与敏感度闸、PG 索引。这一条挂了，证据页就是空的。";
    let url = format!(
        "{}/internal/evidence?limit=1",
        state.config.evidence.base_url.trim_end_matches('/')
    );
    let started = std::time::Instant::now();
    let result = state.evidence.list(Some("limit=1")).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(response) if response.status.is_success() => entry(
            "evidence_read",
            "证据读端点",
            COVERS,
            Some(&url),
            "ok",
            None,
            Some(latency_ms),
        ),
        Ok(response) => entry(
            "evidence_read",
            "证据读端点",
            COVERS,
            Some(&url),
            "unavailable",
            Some(format!("HTTP {}", response.status.as_u16())),
            Some(latency_ms),
        ),
        Err(err) => entry(
            "evidence_read",
            "证据读端点",
            COVERS,
            Some(&url),
            "unavailable",
            Some(truncate(&err)),
            Some(latency_ms),
        ),
    }
}

/// 探活结果统一形状：没配地址时不计延迟/时间（那不是一次检查）。
/// `{"probe":{...}}` → 「写探针 12 秒前成功（3 ms）」。
/// 不是证据服务的健康响应 / 没开探针时返回 `None`。
async fn write_probe_detail(response: reqwest::Response) -> Option<String> {
    let body: serde_json::Value = response.json().await.ok()?;
    let probe = body.get("probe")?;
    let last_ok = probe.get("last_ok").and_then(serde_json::Value::as_bool);
    let failures = probe
        .get("consecutive_failures")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    match last_ok {
        Some(false) => return Some(format!("写探针失败（连续 {failures} 次）")),
        None => return Some("写探针还没跑过".to_string()),
        Some(true) => {}
    }
    let checked_at_ms = probe
        .get("last_at_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let latency_ms = probe
        .get("last_latency_ms")
        .and_then(serde_json::Value::as_u64);
    let age_secs = (now_ms().saturating_sub(checked_at_ms)) / 1000;
    match latency_ms {
        Some(latency_ms) => Some(format!("写探针 {age_secs} 秒前成功（{latency_ms} ms）")),
        None => Some(format!("写探针 {age_secs} 秒前成功")),
    }
}

fn entry(
    id: &str,
    label: &str,
    covers: &str,
    url: Option<&str>,
    status: &str,
    detail: Option<String>,
    latency_ms: Option<u64>,
) -> serde_json::Value {
    let mut value = json!({
        "id": id,
        "label": label,
        "covers": covers,
        "status": status,
    });
    if let Some(url) = url {
        value["url"] = json!(url);
    }
    if let Some(detail) = detail {
        value["detail"] = json!(detail);
    }
    if let Some(latency_ms) = latency_ms {
        value["latency_ms"] = json!(latency_ms);
        value["checked_at_ms"] = json!(now_ms());
    }
    value
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn truncate(text: &str) -> String {
    let mut out: String = text.chars().take(180).collect();
    if out.len() < text.len() {
        out.push('…');
    }
    out
}

/// 接口探活结果 → 数据源就绪度（只取状态与详情，丢掉延迟这类接口级字段）。
fn source_from(probe: &serde_json::Value) -> serde_json::Value {
    match probe.get("detail") {
        Some(detail) => json!({ "status": probe["status"], "detail": detail }),
        None => json!({ "status": probe["status"] }),
    }
}

fn not_found() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "evidence_not_found",
        "artifact not found",
    )
}

fn error_response(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}
