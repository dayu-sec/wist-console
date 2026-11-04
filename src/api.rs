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

    let atlas = match &state.config.atlas {
        None => json!({ "status": "not_configured", "detail": "未配置 atlas.base_url" }),
        Some(atlas) => {
            let url = format!("{}/healthz", atlas.base_url.trim_end_matches('/'));
            match state.http.get(&url).send().await {
                Ok(response) if response.status().is_success() => json!({ "status": "ok" }),
                Ok(response) => json!({
                    "status": "unavailable",
                    "detail": format!("atlas 回了 {}", response.status().as_u16()),
                }),
                Err(err) => json!({ "status": "unavailable", "detail": format!("{err}") }),
            }
        }
    };

    Json(Health {
        status: "ok",
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
