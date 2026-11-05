//! 访问凭据（`wist-cred`）：本服务是验证方（X）。
//!
//! 两张面，两个职责：
//!
//! | 面 | 做什么 |
//! |---|---|
//! | mTLS 收数监听（`credentials.listen_addr`，默认 `3103`） | 收 cred 推来的 `{digest, subject, roles, expires_at, signature}`，只落 sha256 |
//! | 业务监听（`server.listen_addr`） | 校验 `Authorization: Bearer wcr_…` → 角色 → 401 / 403 |
//!
//! **材料只读 `cred.toml`**：identity（服务器证书 / 私钥 / 客户端 CA）与 verify（audience /
//! 签发方白名单 / 签名要求 / 角色词汇表）都由接入命令写入。本服务只在主配置里写一句
//! `credentials.file = <那个文件>`，不把里面的值再抄一遍 —— 抄一遍就一定会漂。
//!
//! 与 `wist-center` 的接入（`src/credentials.rs`）是同一套做法：
//! 启动期就把 TLS 建好，证书缺失 / 链不对就**拒绝启动**，不会出现
//! 「业务面只认凭据、凭据 listener 起不来」的半启用状态。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use wist_cred_peer::{Config as PeerConfig, Peer};

use crate::config::CredentialsConfig;

/// `cred.toml` 的结构（由接入命令写入，**只读**）。
#[derive(Debug, Deserialize)]
struct CredFile {
    identity: IdentitySection,
    #[serde(default)]
    verify: VerifySection,
}

#[derive(Debug, Deserialize)]
struct IdentitySection {
    /// 由 CA-S 签的服务器证书。
    cert: PathBuf,
    /// 本机生成的私钥（0600）。
    key: PathBuf,
    /// CA-I 公开证书：用来验 cred 出示的客户端证书。
    client_ca: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct VerifySection {
    /// 本服务的名字；凭据的 `audience` 不等于它就拒。
    #[serde(default)]
    audience: String,
    /// 签发方身份白名单（客户端证书的 `id`），通常就是 `wist-cred`。
    #[serde(default)]
    allowed_issuers: Vec<String>,
    /// 记录必须带签发方 Ed25519 签名。
    #[serde(default)]
    require_signature: bool,
    /// 签发方公钥（一行一把，轮换期可两把）。
    #[serde(default)]
    issuer_public_key_file: Option<PathBuf>,
    /// 本服务认的角色词汇表（cred 侧只能在里面选）。
    #[serde(default)]
    roles: Vec<String>,
}

/// 装配好的凭据运行时。
pub struct CredentialRuntime {
    peer: Arc<Peer>,
    listen: SocketAddr,
    tls: rustls::ServerConfig,
    /// 进入 console 需要的角色（console 自己的决定，不来自 cred.toml）。
    required_roles: Vec<String>,
}

impl std::fmt::Debug for CredentialRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRuntime")
            .field("audience", &self.peer.config().audience)
            .field("listen", &self.listen)
            .field("registered", &self.peer.registered())
            .field("required_roles", &self.required_roles)
            .finish()
    }
}

impl CredentialRuntime {
    /// 校验一次 bearer token：`Ok` 带主体与角色，`Err` 带对外错误码。
    pub fn verify(&self, token: &str) -> Result<Caller, VerifyError> {
        let credential = match self.peer.verify(token) {
            Ok(credential) => credential,
            Err(err) => {
                // 对外不区分原因（不做 token 枚举接口），但**日志里要能看出是哪一种**：
                // 大半夜查「令牌突然全失效」时，`token_expired` 和 `invalid_token` 是两个故事。
                // 摘要表读失败（磁盘 / 权限）不是「令牌不对」，不能让所有人去重新登录。
                if matches!(err, wist_auth::credential::CredentialError::Store(_)) {
                    log::error!("event=ConsoleCredentialStore code={} {err:?}", err.code());
                    return Err(VerifyError::StoreUnavailable);
                }
                log::debug!("event=ConsoleCredentialRejected code={}", err.code());
                return Err(VerifyError::Invalid);
            }
        };
        // 认证通过、授权不足是 403；对外不区分具体失败原因（不做 token 枚举接口）。
        if !credential
            .roles
            .iter()
            .any(|role| self.required_roles.iter().any(|required| required == role))
        {
            log::warn!(
                "event=ConsoleForbidden subject={} credential_id={} roles={:?} required={:?}",
                credential.subject,
                credential.credential_id,
                credential.roles,
                self.required_roles,
            );
            return Err(VerifyError::RoleRequired);
        }
        Ok(Caller {
            subject: credential.subject.clone(),
            roles: credential.roles.clone(),
        })
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }
}

#[derive(Debug, Clone)]
pub struct Caller {
    pub subject: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// 没带 token / token 不认识 / 过期 / 撤销 / audience 不符。
    Invalid,
    /// token 本身有效，但角色不够。
    RoleRequired,
    /// 摘要表读不了（磁盘 / 权限）—— 这是服务端故障，不是「令牌不对」。
    StoreUnavailable,
}

/// 按主配置装配。启用但材料不成立 → 启动期直接失败（fail-fast）。
pub fn build(config: &CredentialsConfig) -> Result<CredentialRuntime, String> {
    let file = &config.file;
    let text = std::fs::read_to_string(file)
        .map_err(|err| format!("read credentials.file {}: {err}", file.display()))?;
    let cred: CredFile = toml::from_str(&text)
        .map_err(|err| format!("parse credentials.file {}: {err}", file.display()))?;

    // cred.toml 里的相对路径按**该文件所在目录**解（接入命令就是按这个约定写的）。
    let base = file.parent().unwrap_or_else(|| Path::new("."));
    let cert = base.join(&cred.identity.cert);
    let key = base.join(&cred.identity.key);
    let client_ca = base.join(&cred.identity.client_ca);

    if cred.verify.audience.trim().is_empty() {
        return Err(format!(
            "{}: [verify].audience is missing (re-run the join command)",
            file.display()
        ));
    }
    if cred.verify.allowed_issuers.is_empty() {
        return Err(format!(
            "{}: [verify].allowed_issuers is empty — nothing could ever push credentials",
            file.display()
        ));
    }
    if cred.verify.roles.is_empty() {
        return Err(format!(
            "{}: [verify].roles is empty — every role would be dropped",
            file.display()
        ));
    }
    for required in &config.required_roles {
        if !cred.verify.roles.iter().any(|role| role == required) {
            return Err(format!(
                "credentials.required_roles contains {required:?}, which is not listed in \
                 [verify].roles of {}",
                file.display()
            ));
        }
    }

    let listen: SocketAddr = config
        .listen_addr
        .parse()
        .map_err(|err| format!("credentials.listen_addr {:?}: {err}", config.listen_addr))?;

    let client_ca_pem = std::fs::read_to_string(&client_ca)
        .map_err(|err| format!("read {}: {err}", client_ca.display()))?;
    // 严格 mTLS：cred 必须出示 CA-I 签的客户端证书，否则连不上来。
    let tls = wist_pki::tls::server_config_mtls(&cert, &key, &client_ca_pem, false)?;

    let mut peer_config = PeerConfig::new(cred.verify.audience.clone(), &config.store_path)
        .known_roles(cred.verify.roles.iter().cloned())
        .require_signature(cred.verify.require_signature);
    for issuer in &cred.verify.allowed_issuers {
        peer_config = peer_config.allow_issuer(issuer.clone());
    }
    if let Some(path) = &cred.verify.issuer_public_key_file {
        let path = base.join(path);
        for key in load_issuer_keys(&path, cred.verify.require_signature)? {
            peer_config = peer_config.issuer_public_key(key);
        }
    }

    let peer = Peer::open(peer_config).map_err(|err| err.to_string())?;
    if peer.rejected_on_load() > 0 {
        // 磁盘上的记录被改过 / 签名密钥换过：已被丢弃，但必须让运维看见。
        log::error!(
            "credentials: {} authorization record(s) were rejected on load \
             (invalid signature, missing key, or malformed entry)",
            peer.rejected_on_load()
        );
    }
    if peer.registered() == 0 {
        // 一个都没登记：不是“正常但为空”，而是“还没人推过来”。
        // 最常见的两个原因：peer 没配 endpoint（接入时漏了 `--advertise`），
        // 或 cred 到不了这个 listener（端口只绑了回环）。
        log::warn!(
            "credentials: 0 credentials registered for audience {:?}; \
             no one has pushed yet — check the peer's endpoint (`--advertise`) and \
             that wist-cred can reach {} with a CA-S signed server certificate",
            peer.config().audience,
            listen
        );
    }

    Ok(CredentialRuntime {
        peer,
        listen,
        tls,
        required_roles: config.required_roles.clone(),
    })
}

/// 起收数监听（mTLS）。与业务监听并行跑，互不影响。
pub fn spawn_listener(runtime: Arc<CredentialRuntime>) {
    let listen = runtime.listen;
    let app = runtime.peer.router();
    let tls = runtime.tls.clone();
    tokio::spawn(async move {
        if let Err(err) = wist_cred_peer::serve_router(app, listen, tls).await {
            // 这个 listener 挂了只影响「新凭据能不能推进来」，已登记的摘要仍然有效；
            // 所以记错误而不是把整个进程带下去。
            log::error!("credentials listener on {listen} stopped: {err}");
        }
    });
    log::info!("credentials listener on {listen} (mTLS, push-only)");
}

/// 读签发方公钥：一行一把（轮换期可同时信任新旧两把）。
fn load_issuer_keys(path: &Path, required: bool) -> Result<Vec<Vec<u8>>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if !required => {
            log::warn!(
                "credentials: issuer public key {} is not readable ({err}); \
                 signature verification is disabled, so this is not fatal",
                path.display()
            );
            return Ok(Vec::new());
        }
        Err(err) => return Err(format!("read {}: {err}", path.display())),
    };
    let mut keys = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let bytes = hex::decode(line)
            .map_err(|err| format!("{}: issuer public key is not hex: {err}", path.display()))?;
        if bytes.len() != 32 {
            return Err(format!(
                "{}: issuer public key must be 32 bytes, got {}",
                path.display(),
                bytes.len()
            ));
        }
        keys.push(bytes);
    }
    if keys.is_empty() && required {
        return Err(format!("{} contains no public key", path.display()));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_keys_are_one_per_line() {
        let dir = std::env::temp_dir().join(format!(
            "wist-console-cred-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("issuer-signing.pub");
        std::fs::write(&path, format!("{}\n{}\n", "aa".repeat(32), "bb".repeat(32)))
            .expect("write key");
        let keys = load_issuer_keys(&path, true).expect("load");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], vec![0xaa; 32]);

        std::fs::write(&path, "\n").expect("write empty");
        assert!(load_issuer_keys(&path, true).is_err());
        assert!(
            load_issuer_keys(&path, false)
                .expect("tolerated")
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_cred_file_is_reported_with_the_path() {
        let config = CredentialsConfig {
            file: PathBuf::from("/nonexistent/cred.toml"),
            listen_addr: "0.0.0.0:3103".to_string(),
            store_path: PathBuf::from("state/credentials.json"),
            required_roles: vec!["read".to_string()],
        };
        let error = build(&config).expect_err("missing file must fail");
        assert!(error.contains("/nonexistent/cred.toml"), "{error}");
    }
}
