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
    AtlasConfig, AuthConfig, AuthMode, Config, EvidenceConfig, IntegrationConfig, MetricsConfig,
    ServerConfig,
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
        credentials: None,
        evidence: EvidenceConfig {
            base_url,
            tenant: "t-001".to_string(),
            scopes: vec!["evidence:read".to_string()],
            max_sensitivity: "paths".to_string(),
            timeout_secs: 5,
        },
        atlas: None,
        metrics: None,
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
        credentials: None,
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

/// 代理读正文：证据服务直接把原文交回来（本地文件模式没有签名 URL）。
async fn stub_content(Path(artifact_id): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({ "artifact_id": artifact_id, "body": "original-report" }))
}

async fn spawn_stub() -> String {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // VictoriaMetrics 的健康端点（console 的 metrics 探活用）。
        .route("/health", get(|| async { "OK" }))
        // atlas 的读接口（console 以 `/api/atlas/*` 代理过去）。
        .route(
            "/api/hosts",
            get(|| async { axum::Json(json!({ "status": "ok", "data": { "hosts": [] } })) }),
        )
        .route("/internal/evidence", get(stub_list))
        .route(
            "/internal/evidence/{artifact_id}",
            get(stub_get).post(stub_presign),
        )
        .route(
            "/internal/evidence/{artifact_id}/content",
            get(stub_content),
        )
        // 证据服务开了写探针时的 /healthz 形状。
        .route(
            "/probe-healthz",
            get(|| async {
                axum::Json(json!({
                    "status": "ok",
                    "probe": {
                        "last_ok": true,
                        "last_at_ms": 1_700_000_000_000u64,
                        "last_latency_ms": 3,
                        "consecutive_failures": 0,
                        "purged_total": 7
                    }
                }))
            }),
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
async fn cred_mode_rejects_a_missing_bearer_token() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Cred)));
    let request = Request::builder()
        .uri("/api/evidence")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    // 没有「不校验」这一档：cred 模式下没 token 就是 401，且原因与「token 不认识」分开。
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "console_credential_missing");
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
    let app = api::router(state(config(base.clone(), AuthMode::Ingress)));
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

    // 接口可用性：读端点探的是一次**真实读**（鉴权 + PG 索引都会走到），
    // 写端点与 atlas 没配地址时显式 `not_configured`。
    let interfaces = body["interfaces"].as_array().expect("interfaces array");
    assert_eq!(interfaces.len(), 4, "{body}");
    assert_eq!(interfaces[0]["id"], "evidence_read");
    assert_eq!(interfaces[0]["status"], "ok", "{body}");
    assert!(interfaces[0]["latency_ms"].is_u64());
    assert!(interfaces[0]["checked_at_ms"].is_u64());
    // 读端点探的是一次真读（不是只戳 /healthz），且告诉页面这一次验到了哪一层。
    assert_eq!(
        interfaces[0]["url"],
        format!("{base}/internal/evidence?limit=1")
    );
    assert!(!interfaces[0]["covers"].as_str().unwrap_or("").is_empty());
    assert_eq!(interfaces[1]["id"], "evidence_write");
    assert_eq!(interfaces[1]["status"], "not_configured");
    assert_eq!(interfaces[2]["id"], "atlas");
    assert_eq!(interfaces[2]["status"], "not_configured");
    assert_eq!(interfaces[3]["id"], "metrics");
    assert_eq!(interfaces[3]["status"], "not_configured");
}

#[tokio::test]
async fn interfaces_are_probed_when_configured() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig {
        base_url: base.clone(),
        sink_url: None,
    });
    cfg.integration.sink_health_url = Some(format!("{base}/healthz"));
    cfg.metrics = Some(MetricsConfig {
        base_url: base.clone(),
    });
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
    assert_eq!(body["evidence"]["auth"], "none");
    // 租户就是客户：这一格现在给的是客户 id。
    assert_eq!(body["evidence"]["customer"], "t-001");
    assert_eq!(body["evidence"]["record"]["cust_id"], "t-001");
    assert_eq!(body["evidence"]["record"]["cmd_id"], "cmd-20261105-001");

    let connector = body["warp_parse"]["connector"].as_str().unwrap();
    assert!(connector.contains("evidence_sink"));
    assert!(connector.contains("http://10.0.0.5:18800/internal/evidence"));
    // 认证放宽后连接器不应再带用户名/口令，也不该出现 token 占位符。
    assert!(!connector.contains("username"), "{connector}");
    assert!(!connector.contains("EVIDENCE_SINK_TOKEN"), "{connector}");

    let sink_group = body["warp_parse"]["sink_group"].as_str().unwrap();
    assert!(sink_group.contains("evidence_uplink"), "{sink_group}");
    assert_eq!(
        body["warp_parse"]["env"]["EVIDENCE_SINK_URL"],
        "http://10.0.0.5:18800"
    );
}

#[tokio::test]
async fn atlas_is_probed_when_configured() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig {
        base_url: base,
        sink_url: None,
    });
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

#[tokio::test]
async fn content_is_proxied_through_the_bff() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/art_01ABC/content")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // 原文由 BFF 从证据服务取回、原样交出；浏览器不碰预签名 URL。
    assert_eq!(body["artifact_id"], "art_01ABC");
    assert_eq!(body["body"], "original-report");
}

#[tokio::test]
async fn content_requires_the_operator_header() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/art_01ABC/content")
        .body(Body::empty())
        .unwrap();
    let (status, _) = call(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn proxied_content_is_not_cacheable() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/art_01ABC/content")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    // 证据正文不能进浏览器 / 中间代理的缓存。
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
}

#[tokio::test]
async fn write_interface_reports_the_probe() {
    // 证据服务的 /healthz 带 probe 块时，接口可用性那一行要能看出「真的写进去了」。
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.integration.sink_health_url = Some(format!("{base}/probe-healthz"));
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let write = body["interfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .find(|entry| entry["id"] == "evidence_write")
        .expect("evidence_write entry");
    let detail = write["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("写探针"), "{detail}");
    assert!(detail.contains("成功"), "{detail}");
}

#[tokio::test]
async fn atlas_reads_go_through_the_bff() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig {
        base_url: base,
        sink_url: None,
    });
    let app = api::router(state(cfg));

    // 没有身份 → 401：资产数据面与其它 /api/* 是同一道门。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/atlas/hosts")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // 有身份 → 透传 atlas 的响应，并加 no-store。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/atlas/hosts")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["hosts"].as_array().unwrap().len(), 0);

    // 写端点前缀（/internal/*）不经过 BFF 暴露给浏览器。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/atlas/internal/atlas")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "atlas_path_invalid");
}
