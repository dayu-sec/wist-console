//! BFF 契约测试：身份头、透传语义、健康聚合。
//!
//! 上游是**进程内真 HTTP**（同一个 axum），不 mock：要验的正是"头有没有真的带上"。

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, RawQuery};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use wist_console::api::{self, AppState};
use wist_console::config::{
    AtlasConfig, AuthConfig, AuthMode, Config, EvidenceConfig, IntegrationConfig, ServerConfig,
};
use wist_console::upstream::EvidenceClient;

fn config(base_url: String, mode: AuthMode) -> Config {
    Config {
        server: ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
        },
        auth: AuthConfig {
            mode,
            operator_header: "x-console-operator".to_string(),
        },
        evidence: EvidenceConfig {
            base_url,
            tenant: "t-001".to_string(),
            scopes: vec!["evidence:read".to_string()],
            max_sensitivity: "paths".to_string(),
            timeout_secs: 5,
        },
        atlas: None,
        integration: IntegrationConfig {
            sink_url: None,
            sink_health_url: None,
            allowed_kinds: vec!["investigation_report".to_string()],
        },
    }
}

fn state(config: Config) -> AppState {
    let evidence = EvidenceClient::new(&config.evidence).expect("evidence client");
    AppState {
        config: Arc::new(config),
        evidence: Arc::new(evidence),
        http: reqwest::Client::new(),
    }
}

async fn stub_list(headers: HeaderMap, RawQuery(query): RawQuery) -> axum::Json<Value> {
    axum::Json(json!({
        "artifacts": [],
        "next_cursor": null,
        "seen_query": query,
        "seen_tenant": headers.get("x-evidence-tenant").and_then(|v| v.to_str().ok()),
        "seen_scopes": headers.get("x-evidence-scopes").and_then(|v| v.to_str().ok()),
        "seen_sensitivity": headers.get("x-evidence-max-sensitivity").and_then(|v| v.to_str().ok()),
    }))
}

async fn stub_get(Path(artifact_id): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({ "artifact_id": artifact_id, "kind": "investigation_report" }))
}

async fn stub_presign(Path(raw): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({
        "artifact_id": raw.trim_end_matches(":presign"),
        "url": "memory://objects/x?expires=1",
        "expires_in_seconds": 60,
        "expires_at": "2026-11-02T00:00:00Z",
    }))
}

async fn spawn_stub() -> String {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/internal/evidence", get(stub_list))
        .route(
            "/internal/evidence/{artifact_id}",
            get(stub_get).post(stub_presign),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let address = listener.local_addr().expect("stub addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("oneshot");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn list_is_passed_through_and_tenant_is_stripped() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence?tenant=t-999&kind=investigation_report")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // 浏览器传的 tenant 必须被丢掉；真正生效的是配置里的身份。
    assert_eq!(body["seen_query"], "kind=investigation_report");
    assert_eq!(body["seen_tenant"], "t-001");
    assert_eq!(body["seen_scopes"], "evidence:read");
    assert_eq!(body["seen_sensitivity"], "paths");
}

#[tokio::test]
async fn missing_operator_header_is_401() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "console_operator_missing");
}

#[tokio::test]
async fn dev_mode_does_not_require_an_operator() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Dev)));
    let request = Request::builder()
        .uri("/api/evidence")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn presign_is_passed_through() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .method("POST")
        .uri("/api/evidence/art_01ABC:presign")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["artifact_id"], "art_01ABC");
    assert_eq!(body["expires_in_seconds"], 60);
}

#[tokio::test]
async fn health_reports_unconfigured_domains() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sources"]["evidence"]["status"], "ok");
    assert_eq!(body["sources"]["atlas"]["status"], "not_configured");
    assert_eq!(body["sources"]["metrics"]["status"], "not_configured");
    assert_eq!(body["sources"]["devices"]["status"], "not_configured");

    // 接口可用性：读端点探活打的是证据服务的 `/healthz`（不要求身份），
    // 写端点与 atlas 没配地址时显式 `not_configured`。
    let interfaces = body["interfaces"].as_array().expect("interfaces array");
    assert_eq!(interfaces.len(), 3, "{body}");
    assert_eq!(interfaces[0]["id"], "evidence_read");
    assert_eq!(interfaces[0]["status"], "ok", "{body}");
    assert!(interfaces[0]["latency_ms"].is_u64());
    assert!(interfaces[0]["checked_at_ms"].is_u64());
    assert_eq!(interfaces[1]["id"], "evidence_write");
    assert_eq!(interfaces[1]["status"], "not_configured");
    assert_eq!(interfaces[2]["id"], "atlas");
    assert_eq!(interfaces[2]["status"], "not_configured");
}

#[tokio::test]
async fn interfaces_are_probed_when_configured() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig {
        base_url: base.clone(),
    });
    cfg.integration.sink_health_url = Some(format!("{base}/healthz"));
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for entry in body["interfaces"].as_array().expect("interfaces array") {
        assert_eq!(entry["status"], "ok", "{body}");
        assert!(entry["latency_ms"].is_u64(), "{body}");
    }
}

#[tokio::test]
async fn integration_page_shows_the_sink_contract() {
    let base = spawn_stub().await;
    let mut cfg = config(base, AuthMode::Ingress);
    cfg.integration.sink_url = Some("http://10.0.0.5:18800".to_string());
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/integration")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["evidence"]["write_url"],
        "http://10.0.0.5:18800/internal/evidence"
    );
    assert_eq!(body["evidence"]["auth"], "basic");
    assert_eq!(body["evidence"]["tenant"], "t-001");
    let connector = body["warp_parse"]["connector"].as_str().unwrap();
    assert!(connector.contains("evidence_sink"));
    assert!(connector.contains("http://10.0.0.5:18800/internal/evidence"));
    // token 只能是占位符，不能把真值回传给浏览器。
    assert!(connector.contains("${EVIDENCE_SINK_TOKEN}"));
}

#[tokio::test]
async fn atlas_is_probed_when_configured() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig { base_url: base });
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sources"]["atlas"]["status"], "ok");
}
