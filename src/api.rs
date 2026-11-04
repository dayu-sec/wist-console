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
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// 聚合各数据源的就绪度。`not_configured` 不是错误 —— 是「这个域还没接」。
#[derive(serde::Serialize)]
struct Health {
    status: &'static str,
    sources: serde_json::Value,
    /// 逐个接口的可用性（写端点 / 读端点 / atlas）：状态 + 延迟 + 最近检查时间。
    interfaces: serde_json::Value,
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }

    let evidence = match state.evidence.list(Some("limit=1")).await {
        Ok(response) if response.status.is_success() => json!({ "status": "ok" }),
        Ok(response) => json!({
            "status": "unavailable",
            "detail": format!("证据服务回了 {}", response.status.as_u16()),
        }),
        Err(err) => json!({ "status": "unavailable", "detail": err }),
    };

    let read_url = Some(format!(
        "{}/healthz",
        state.config.evidence.base_url.trim_end_matches('/')
    ));
    let write_url = state.config.integration.sink_health_url.clone();
    let atlas_url = state
        .config
        .atlas
        .as_ref()
        .map(|atlas| format!("{}/healthz", atlas.base_url.trim_end_matches('/')));

    // 并发探活：一个上游挂掉不该把另外两个的延迟一起拖长。
    let (read_iface, write_iface, atlas_iface) = tokio::join!(
        probe_opt(
            &state.http,
            "evidence_read",
            "证据读端点（元数据 / 预签名）",
            read_url,
            "未配置 evidence.base_url",
        ),
        probe_opt(
            &state.http,
            "evidence_write",
            "证据写端点（数据面 sink）",
            write_url,
            "未配置 integration.sink_health_url（BFF 视角的探活地址）",
        ),
        probe_opt(
            &state.http,
            "atlas",
            "资产拓扑 API",
            atlas_url,
            "未配置 atlas.base_url",
        ),
    );

    // `sources.atlas` 不再单独发一次请求：直接由刚才那次探活的结果派生。
    let atlas = source_from(&atlas_iface);
    let interfaces = vec![read_iface, write_iface, atlas_iface];

    Json(Health {
        status: "ok",
        interfaces: json!(interfaces),
        sources: json!({
            "evidence": evidence,
            "atlas": atlas,
            "metrics": {
                "status": "not_configured",
                "detail": "运行指标还没有平台侧聚合（VM 在各网关栈里）",
            },
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

    // 注意：`format!` 里的 `{{` / `}}` 是转义的大括号，`${{...}}` 才是字面量 `${...}`。
    let connector = format!(
        r#"[[connectors]]
allow_override = ["endpoint", "username", "password", "headers", "fmt", "batch_size", "timeout_secs", "max_retries"]
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
username = "${{EVIDENCE_SINK_TOKEN}}"
password = ""

[connectors.params.headers]
Content-Type = "application/json"
"#
    );

    let sink_group = format!(
        r#"[sink_group]
name = "agent-ivsrep-evidence"
oml = ["agent_uplink_ivsrep"]
tags = ["biz:agent-ivsrep"]
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

    Json(json!({
        "evidence": {
            "write_url": write_url,
            "auth": "basic",
            "username_is_token": true,
            "tenant": state.config.evidence.tenant,
            "allowed_kinds": state.config.integration.allowed_kinds,
            "frame_marker": "IVSREP",
        },
        "warp_parse": {
            "connector": connector,
            "sink_group": sink_group,
            "env": {
                "EVIDENCE_SINK_URL": sink_base,
                "EVIDENCE_SINK_TOKEN": "<站点 token：与证据服务 sec-value.yml 一致>",
            },
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

fn upstream_failed(message: String) -> Response {
    error_response(StatusCode::BAD_GATEWAY, "console_upstream_failed", message)
}

/// 没配地址的接口直接标 `not_configured`；这是「还没接」，不是故障。
async fn probe_opt(
    http: &reqwest::Client,
    id: &str,
    label: &str,
    target: Option<String>,
    missing_detail: &str,
) -> serde_json::Value {
    match target {
        Some(url) => probe(http, id, label, &url).await,
        None => json!({
            "id": id,
            "label": label,
            "status": "not_configured",
            "detail": missing_detail,
        }),
    }
}

/// 单接口探活：状态 + 延迟 + 检查时间。错误信息截断，避免把整段 reqwest 报错塞进页面。
async fn probe(http: &reqwest::Client, id: &str, label: &str, url: &str) -> serde_json::Value {
    let started = std::time::Instant::now();
    let result = http
        .get(url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    let checked_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    match result {
        Ok(response) if response.status().is_success() => json!({
            "id": id,
            "label": label,
            "url": url,
            "status": "ok",
            "latency_ms": latency_ms,
            "checked_at_ms": checked_at_ms,
        }),
        Ok(response) => json!({
            "id": id,
            "label": label,
            "url": url,
            "status": "unavailable",
            "detail": format!("HTTP {}", response.status().as_u16()),
            "latency_ms": latency_ms,
            "checked_at_ms": checked_at_ms,
        }),
        Err(err) => json!({
            "id": id,
            "label": label,
            "url": url,
            "status": "unavailable",
            "detail": truncate(&err.to_string()),
            "latency_ms": latency_ms,
            "checked_at_ms": checked_at_ms,
        }),
    }
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
