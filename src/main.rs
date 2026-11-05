//! `wist-console` 进程入口。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use wist_console::api::{self, AppState};
use wist_console::config::{AuthMode, Config};
use wist_console::credentials;
use wist_console::upstream::EvidenceClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config_path = std::env::args().nth(1);
    let config = Config::load(config_path.as_deref().map(Path::new))?;

    // 凭据运行时：启动期就把 mTLS 建好（证书缺失 / 链不对 → 直接拒启，
    // 不出现「业务面只认凭据、凭据 listener 起不来」的半启用状态）。
    let credentials = match (&config.credentials, config.auth.mode) {
        (Some(credentials_config), AuthMode::Cred) => Some(Arc::new(
            credentials::build(credentials_config)
                .map_err(|err| anyhow::anyhow!("credentials: {err}"))?,
        )),
        _ => None,
    };
    if let Some(runtime) = credentials.as_ref() {
        credentials::spawn_listener(Arc::clone(runtime));
    }

    let evidence = EvidenceClient::new(&config.evidence)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.evidence.timeout_secs))
        .build()?;

    log::info!(
        "wist-console starting: listen={} auth={:?} evidence={} atlas={}",
        config.server.listen_addr,
        config.auth.mode,
        config.evidence.base_url,
        config
            .atlas
            .as_ref()
            .map(|atlas| atlas.base_url.as_str())
            .unwrap_or("(none)")
    );

    let state = AppState {
        config: Arc::new(config.clone()),
        evidence: Arc::new(evidence),
        http,
        credentials,
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&config.server.listen_addr)
        .await
        .with_context(|| format!("bind {}", config.server.listen_addr))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
