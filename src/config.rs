//! 分层配置：主配置 + `${VAR}` 展开（与 center / evidence 同口径，fail-closed）。
//!
//! 这个服务**不持有**证据桶凭据；它持有的只有「到证据服务的身份」——
//! 租户、scope、敏感度上限。这三项决定 BFF 能要到什么，所以它们只出现在配置里，
//! **不接受**浏览器传参。

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use orion_sec::sec::NoSecConv;
use orion_sec::{SecFileFmt, load_sec_dict, load_secfile_by};
use orion_variate::vars::{EnvChecker, EnvDict, EnvEvaluable, ValueType};
use serde::Deserialize;

const SEC_FILE_ENV: &str = "WIST_CONSOLE_SEC_FILE";
const CONFIG_ENV: &str = "WIST_CONSOLE_CONFIG";

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub evidence: EvidenceConfig,
    pub atlas: Option<AtlasConfig>,
    pub integration: IntegrationConfig,
}

/// 展示给运维的「数据面接入」信息。
///
/// 这里**只放公开信息**（写端点、允许的 kind）；站点 token 永远不出现在响应里。
#[derive(Debug, Clone)]
pub struct IntegrationConfig {
    /// 数据面能看到的证据写端点（`http://<内网地址>:<端口>/internal/evidence`）。
    /// 没配就不展示 URL，只展示占位符。
    pub sink_url: Option<String>,
    pub allowed_kinds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
}

/// `ingress`：入口（VPN / 堡垒机 / 反代）必须注入操作者头；`dev`：本机联调不校验。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Ingress,
    Dev,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub operator_header: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceConfig {
    pub base_url: String,
    pub tenant: String,
    pub scopes: Vec<String>,
    pub max_sensitivity: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct AtlasConfig {
    pub base_url: String,
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => match std::env::var_os(CONFIG_ENV).filter(|value| !value.is_empty()) {
                Some(value) => PathBuf::from(value),
                None => PathBuf::from("console.toml"),
            },
        };
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read config {}", path.display()))?;
        let raw: RawConfig =
            toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
        let env = secret_dict()?;
        raw.resolve(&env)
    }
}

fn expand(env: &EnvDict, value: &str) -> anyhow::Result<String> {
    let expanded: String = value.to_string().env_eval(env);
    if expanded.needs_env_eval() {
        bail!(
            "unresolved environment variable(s) in {value:?}: {}",
            expanded.list_env_vars().join(", ")
        );
    }
    Ok(expanded)
}

fn secret_dict() -> anyhow::Result<EnvDict> {
    let mut dict = match std::env::var_os(SEC_FILE_ENV).filter(|path| !path.is_empty()) {
        Some(path) => load_sec_file(Path::new(&path))?,
        None => load_sec_dict().map_err(|err| anyhow::anyhow!("failed to load secrets: {err}"))?,
    };
    for (key, value) in std::env::vars() {
        dict.insert(key, ValueType::from(value.as_str()));
    }
    Ok(dict)
}

fn load_sec_file(path: &Path) -> anyhow::Result<EnvDict> {
    if !path.exists() {
        bail!(
            "secrets file not found: {} ({SEC_FILE_ENV})",
            path.display()
        );
    }
    let space = load_secfile_by(path.to_path_buf(), SecFileFmt::Yaml)
        .map_err(|err| anyhow::anyhow!("failed to load secrets {}: {err}", path.display()))?;
    let mut dict = EnvDict::new();
    for (key, value) in space.no_sec() {
        dict.insert(key, value);
    }
    Ok(dict)
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    server: RawServer,
    #[serde(default)]
    auth: RawAuth,
    evidence: RawEvidence,
    #[serde(default)]
    atlas: Option<RawAtlas>,
    #[serde(default)]
    integration: RawIntegration,
}

#[derive(Debug, Deserialize)]
struct RawIntegration {
    #[serde(default)]
    sink_url: String,
    #[serde(default = "default_integration_kinds")]
    allowed_kinds: Vec<String>,
}

impl Default for RawIntegration {
    fn default() -> Self {
        Self {
            sink_url: String::new(),
            allowed_kinds: default_integration_kinds(),
        }
    }
}

fn default_integration_kinds() -> Vec<String> {
    vec!["investigation_report".to_string()]
}

#[derive(Debug, Deserialize)]
struct RawServer {
    #[serde(default = "default_listen")]
    listen_addr: String,
}

impl Default for RawServer {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}

#[derive(Debug, Deserialize)]
struct RawAuth {
    #[serde(default = "default_auth_mode")]
    mode: String,
    #[serde(default = "default_operator_header")]
    operator_header: String,
}

impl Default for RawAuth {
    fn default() -> Self {
        Self {
            mode: default_auth_mode(),
            operator_header: default_operator_header(),
        }
    }
}

fn default_auth_mode() -> String {
    "ingress".to_string()
}

fn default_operator_header() -> String {
    "x-console-operator".to_string()
}

#[derive(Debug, Deserialize)]
struct RawEvidence {
    base_url: String,
    tenant: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_max_sensitivity")]
    max_sensitivity: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

fn default_scopes() -> Vec<String> {
    vec!["evidence:read".to_string()]
}

fn default_max_sensitivity() -> String {
    "paths".to_string()
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Deserialize)]
struct RawAtlas {
    base_url: String,
}

impl RawConfig {
    fn resolve(self, env: &EnvDict) -> anyhow::Result<Config> {
        let mode = match self.auth.mode.trim() {
            "ingress" => AuthMode::Ingress,
            "dev" => AuthMode::Dev,
            other => bail!("auth.mode must be ingress|dev, got {other:?}"),
        };
        if self.auth.operator_header.trim().is_empty() {
            bail!("auth.operator_header must not be empty");
        }
        if self.evidence.tenant.trim().is_empty() {
            bail!("evidence.tenant must not be empty");
        }
        if self.evidence.scopes.is_empty() {
            bail!("evidence.scopes must list at least one scope");
        }
        if self.evidence.timeout_secs == 0 {
            bail!("evidence.timeout_secs must be > 0");
        }
        let expires = self.evidence.max_sensitivity.trim().to_ascii_lowercase();
        if !matches!(
            expires.as_str(),
            "metrics"
                | "paths"
                | "commandlines"
                | "identities"
                | "secret_metadata"
                | "security_posture"
        ) {
            bail!(
                "evidence.max_sensitivity must be one of metrics|paths|commandlines|identities|secret_metadata|security_posture, got {:?}",
                self.evidence.max_sensitivity
            );
        }

        Ok(Config {
            server: ServerConfig {
                listen_addr: self.server.listen_addr,
            },
            auth: AuthConfig {
                mode,
                operator_header: self.auth.operator_header,
            },
            evidence: EvidenceConfig {
                base_url: expand(env, &self.evidence.base_url)?,
                tenant: self.evidence.tenant,
                scopes: self.evidence.scopes,
                max_sensitivity: expires,
                timeout_secs: self.evidence.timeout_secs,
            },
            atlas: match self.atlas {
                Some(atlas) => Some(AtlasConfig {
                    base_url: expand(env, &atlas.base_url)?,
                }),
                None => None,
            },
            integration: IntegrationConfig {
                sink_url: if self.integration.sink_url.trim().is_empty() {
                    None
                } else {
                    Some(expand(env, &self.integration.sink_url)?)
                },
                allowed_kinds: self.integration.allowed_kinds,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> anyhow::Result<Config> {
        let raw: RawConfig = toml::from_str(raw)?;
        raw.resolve(&EnvDict::new())
    }

    #[test]
    fn defaults_are_ingress_and_read_only() {
        let config = parse(
            r#"
            [evidence]
            base_url = "http://127.0.0.1:8443"
            tenant = "t-001"
            "#,
        )
        .expect("minimal config should parse");
        assert_eq!(config.auth.mode, AuthMode::Ingress);
        assert_eq!(config.auth.operator_header, "x-console-operator");
        assert_eq!(config.evidence.scopes, vec!["evidence:read"]);
        assert_eq!(config.evidence.max_sensitivity, "paths");
        assert!(config.atlas.is_none());
    }

    #[test]
    fn unknown_auth_mode_is_rejected() {
        let error = parse(
            r#"
            [auth]
            mode = "open"
            [evidence]
            base_url = "http://x"
            tenant = "t-001"
            "#,
        )
        .expect_err("unknown auth mode must fail");
        assert!(error.to_string().contains("auth.mode must be ingress|dev"));
    }

    #[test]
    fn unknown_sensitivity_is_rejected() {
        let error = parse(
            r#"
            [evidence]
            base_url = "http://x"
            tenant = "t-001"
            max_sensitivity = "everything"
            "#,
        )
        .expect_err("unknown sensitivity must fail");
        assert!(error.to_string().contains("max_sensitivity"));
    }

    #[test]
    fn unresolved_placeholder_is_rejected() {
        let error = parse(
            r#"
            [evidence]
            base_url = "${SEC_EVIDENCE_URL}"
            tenant = "t-001"
            "#,
        )
        .expect_err("unresolved env must fail");
        assert!(
            error
                .to_string()
                .contains("unresolved environment variable")
        );
    }
}
