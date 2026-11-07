//! 运行指标：读计算区**自己那份** VictoriaMetrics。
//!
//! 数据面（wparse）把 agent 采集指标镜像进来（网关栈的 `CONSOLE_VM_ENDPOINT`），
//! 网关栈那份 VM 只服务控制面观测页 —— 两份存储互不聚合（谁写谁查）。
//! 所以这里**看不到**引擎 / 管道统计（`wparse_*` 只写网关栈），这是刻意的边界。
//!
//! 两条纪律：
//! 1. 指标名只从 `wist-metrics` 的常量表取：读侧手写名字曾经把整页刷成静默空白；
//! 2. 单位在 BFF 换算成页面口径（百分比 / 毫秒 / 字节），前端只画图不做算术。

use std::collections::BTreeMap;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wist_metrics::names::{agent as agent_metric, label, ratio_to_percent, seconds_to_millis};
use wist_metrics::spec::METRIC_SPECS;

use crate::api::{AppState, authorize, error_response, now_ms};

/// 「有没有在跳」的观察窗口（秒）：这段时间里一个样本都没有 = 采集静默。
const SAMPLE_WINDOW_SECONDS: i64 = 300;
/// 单次查询超时。VM 就在栈内网，慢到这个程度说明它自己有问题。
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);

/// 趋势窗口与步长的上下界（秒）：页面给几个档，但不接受任意值 —— `[1s]` 这种
/// 步长会把 VM 抽干，`[7d]` 这种窗口又会把响应撑到几 MB。
const MIN_WINDOW_SECONDS: i64 = 300;
const MAX_WINDOW_SECONDS: i64 = 86_400;
const MIN_STEP_SECONDS: i64 = 10;
const MAX_STEP_SECONDS: i64 = 900;
/// 单个序列最多取多少个点（VM 默认上限 10k，这里留足余量又不让响应过大）。
const MAX_POINTS: i64 = 2_000;

/// 选择类 label（由网关下发、贴在全部序列上）。只有这些算「这台 agent 的身份」；
/// `target_kind` / `outcome` 之类是**某条指标自己的**属性，混进身份会让同一台机器裂成多行。
/// 名单与数据面 `adm.oml` 的选择类 label 一致。
const SELECTION_LABELS: &[&str] = &[
    "env", "cluster", "app", "role", "shard", "tier", "region", "zone",
];

#[derive(Debug, Default, Clone, Serialize)]
pub struct HostMetrics {
    pub hostname: Option<String>,
    pub ip_addresses: Vec<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub kernel: Option<String>,
    pub load_1m: Option<f64>,
    pub load_5m: Option<f64>,
    pub load_15m: Option<f64>,
    pub memory_total_bytes: Option<f64>,
    pub memory_available_bytes: Option<f64>,
    /// 已换算成百分比（VM 里存的是 0~1 的 ratio）。
    pub memory_usage_percent: Option<f64>,
    /// 系统盘（`disk_role=system`）使用率，百分比。
    pub disk_usage_percent: Option<f64>,
    pub disk_total_bytes: Option<f64>,
    pub disk_available_bytes: Option<f64>,
    /// 最紧张的挂载点（可能不是系统盘根分区），百分比。
    pub filesystem_usage_percent: Option<f64>,
    pub filesystem_mount: Option<String>,
    pub uptime_seconds: Option<f64>,
    /// 采集到的进程数（`process_pid` 的序列数）。
    pub processes: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
pub struct AgentRow {
    pub agent_id: String,
    /// 选择类 label（`env` / `cluster` / …），按名字排序。
    pub labels: BTreeMap<String, String>,
    /// 这台 agent 在存储里的序列总数（含 `system_*` / `process_*`）。
    pub series: u64,
    /// 观察窗口内 `agent_cpu_ratio` 的样本数：`0` = 采集静默。
    pub samples: u64,
    pub cpu_percent: Option<f64>,
    pub cpu_cores: Option<f64>,
    pub memory_bytes: Option<f64>,
    pub admin_latency_ms: Option<f64>,
    /// 采集记账：窗口内每批按 `target_kind` × `outcome` 报的目标数（按 outcome 汇总）。
    pub collect_targets: Option<f64>,
    pub collect_dropped: Option<f64>,
    pub uplink_failed_total: Option<f64>,
    pub discovery_policy_version: Option<f64>,
    /// 主机侧（`system_*` / `process_*`）：**宿主**的资源，不是 agent 进程自己的。
    /// 老 agentd 只报自观测时这里会是空值，页面显示「—」。
    pub host: HostMetrics,
}

#[derive(Debug, Serialize)]
pub struct CatalogEntry {
    pub name: String,
    /// 名字前缀（`agent` / `system` / `process` / …），页面按它分组。
    pub group: String,
    pub series: u64,
}

#[derive(Debug, Serialize)]
pub struct HistorySeries {
    /// 规范指标名（`agent_cpu_ratio` …），只用于排查，页面标题看 `title`。
    pub metric: String,
    /// 页面标题：由后端按常量表给出，前端不再自己认名字。
    pub title: &'static str,
    /// 页面口径：`percent` / `bytes` / `count` / `milliseconds`。
    pub unit: &'static str,
    /// `(unix 毫秒, 值)`，按时间升序。
    pub points: Vec<(i64, f64)>,
}

#[derive(Debug, Serialize)]
pub struct AgentHistory {
    pub agent_id: String,
    pub window_seconds: i64,
    pub step_seconds: i64,
    pub labels: BTreeMap<String, String>,
    pub series: Vec<HistorySeries>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    window_seconds: Option<i64>,
    step_seconds: Option<i64>,
}

/// `GET /api/metrics` — 概览：存储里有什么、谁在报、当前值是多少。
pub async fn overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = authorize(&state, &headers) {
        return response;
    }
    let Some(config) = metrics_config(&state) else {
        return not_configured();
    };
    match collect_overview(&state.http, &config).await {
        Ok(value) => Json(value).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, "metrics_unavailable", err),
    }
}

/// `GET /api/metrics/agents/{agent_id}/history?window_seconds=&step_seconds=` — 单台 agent 的趋势。
pub async fn agent_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Response {
    if let Some(response) = authorize(&state, &headers) {
        return response;
    }
    let Some(config) = metrics_config(&state) else {
        return not_configured();
    };

    let (window, step) = history_window(query.window_seconds, query.step_seconds);
    match collect_history(&state.http, &config, &agent_id, window, step).await {
        Ok(history) => Json(history).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, "metrics_unavailable", err),
    }
}

fn metrics_config(state: &AppState) -> Option<String> {
    state
        .config
        .metrics
        .as_ref()
        .map(|metrics| metrics.base_url.trim_end_matches('/').to_string())
}

fn not_configured() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "metrics_not_configured",
        "未配置 metrics.base_url（field-api.toml 的 [metrics] 段）：这个计算区还没有指标存储",
    )
}

/// 主机侧要展示的 fact（**用 fact_key 查 spec 表**，不手写指标名）。
/// `host.disk.*` 与 `host.filesystem.*` 不在同一个维度上：前者是整盘汇总，后者逐挂载点。
const HOST_FACTS: &[&str] = &[
    "host.info",
    "host.loadavg.1m",
    "host.loadavg.5m",
    "host.loadavg.15m",
    "host.memory.total_bytes",
    "host.memory.available_bytes",
    "host.memory.usage_ratio",
    "host.disk.system.usage_ratio",
    "host.disk.system.total_bytes",
    "host.disk.system.available_bytes",
    "host.filesystem.usage_ratio",
    "host.uptime.seconds",
    "process.pid",
];

fn spec_name(fact_key: &str) -> Option<&'static str> {
    METRIC_SPECS
        .iter()
        .find(|spec| spec.fact_key == fact_key)
        .map(|spec| spec.name)
}

/// 指标名 → fact_key 的反查（解析查询结果时用，避免在匹配分支里写死名字）。
fn fact_key(name: &str) -> Option<&'static str> {
    METRIC_SPECS
        .iter()
        .find(|spec| spec.name == name)
        .map(|spec| spec.fact_key)
}

fn names_for(facts: &[&str]) -> String {
    facts
        .iter()
        .filter_map(|fact| spec_name(fact))
        .collect::<Vec<_>>()
        .join("|")
}

async fn collect_overview(http: &reqwest::Client, base_url: &str) -> Result<Value, String> {
    let self_metrics = format!(
        "{{__name__=~\"{}\"}}",
        agent_metric::ALL_SELF_METRICS.join("|")
    );
    // 主机侧单独一条查询：`system_*` / `process_*` 与 agent 自观测是两套序列。
    let host_metrics = format!("{{__name__=~\"{}\"}}", names_for(HOST_FACTS));
    // 目录与「每台 agent 有多少序列」都是一次全量计数：计算区的 VM 只收数据面镜像，
    // 规模是「几百到几千条序列」，与网关栈那份相比更小，不做额外分页。
    let catalog_expr = "count by (__name__) ({__name__=~\".+\"})".to_string();
    let per_agent_expr = format!("count by ({}) ({{__name__=~\".+\"}})", label::AGENT);
    let samples_expr = format!(
        "sum by ({}) (count_over_time({}[{}s]))",
        label::AGENT,
        agent_metric::CPU_RATIO,
        SAMPLE_WINDOW_SECONDS
    );

    // 四个查询并发：页面的四块信息互不依赖，串行只会把首页拖慢四倍。
    let (catalog, per_agent, values, host_values, samples) = tokio::join!(
        query(http, base_url, &catalog_expr),
        query(http, base_url, &per_agent_expr),
        query(http, base_url, &self_metrics),
        query(http, base_url, &host_metrics),
        query(http, base_url, &samples_expr),
    );
    // 任一失败就整页失败：半页数据比一句明确的报错更容易误导人。
    let mut catalog = catalog?;
    let per_agent = per_agent?;
    let values = values?;
    let host_values = host_values?;
    let samples = samples?;

    let mut entries: Vec<CatalogEntry> = catalog
        .drain(..)
        .filter_map(|item| {
            let name = item["metric"]["__name__"].as_str()?.to_string();
            let series = scalar(&item)? as u64;
            Some(CatalogEntry {
                group: name.split('_').next().unwrap_or(&name).to_string(),
                name,
                series,
            })
        })
        .collect();
    entries.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then(right.series.cmp(&left.series))
            .then(left.name.cmp(&right.name))
    });
    let total_series: u64 = entries.iter().map(|entry| entry.series).sum();

    let mut agents: BTreeMap<String, AgentRow> = BTreeMap::new();
    for item in &per_agent {
        let Some(agent_id) = item["metric"][label::AGENT].as_str() else {
            // 没有 `agent` 的序列（非 agent 写入的点）不属于任何一台机器。
            continue;
        };
        let row = agents.entry(agent_id.to_string()).or_default();
        row.agent_id = agent_id.to_string();
        row.series = scalar(item).unwrap_or(0.0) as u64;
    }
    for item in &samples {
        let Some(agent_id) = item["metric"][label::AGENT].as_str() else {
            continue;
        };
        if let Some(row) = agents.get_mut(agent_id) {
            row.samples = scalar(item).unwrap_or(0.0) as u64;
        }
    }
    for item in &values {
        let metric = &item["metric"];
        let Some(agent_id) = metric[label::AGENT].as_str() else {
            continue;
        };
        let name = metric["__name__"].as_str().unwrap_or_default();
        let value = scalar(item);
        let row = agents.entry(agent_id.to_string()).or_default();
        row.agent_id = agent_id.to_string();
        for key in SELECTION_LABELS {
            if let Some(found) = metric.get(*key).and_then(Value::as_str) {
                row.labels.insert((*key).to_string(), found.to_string());
            }
        }
        match name {
            agent_metric::CPU_RATIO => row.cpu_percent = value.map(ratio_to_percent),
            agent_metric::CPU_CORES => row.cpu_cores = value,
            agent_metric::MEMORY_BYTES => row.memory_bytes = value,
            agent_metric::ADMIN_LATENCY_SECONDS => {
                row.admin_latency_ms = value.map(seconds_to_millis).map(|ms| ms as f64);
            }
            agent_metric::COLLECT_TARGETS => {
                // 同一条指标按 `target_kind` × `outcome` 展开：这里按 outcome 汇总，
                // 保留「成功 / 丢弃」两个页面真正会看的数。
                if let Some(value) = value {
                    let dropped =
                        metric.get(label::OUTCOME).and_then(Value::as_str) == Some("dropped");
                    *row.collect_targets.get_or_insert(0.0) += value;
                    if dropped {
                        *row.collect_dropped.get_or_insert(0.0) += value;
                    }
                }
            }
            agent_metric::UPLINK_METRICS_FAILED_TOTAL => row.uplink_failed_total = value,
            agent_metric::DISCOVERY_POLICY_VERSION => row.discovery_policy_version = value,
            _ => {}
        }
    }

    // 主机侧（`system_*` / `process_*`）：按 fact_key 反查后再分支，不在代码里写指标名。
    for item in &host_values {
        let metric = &item["metric"];
        let Some(agent_id) = metric[label::AGENT].as_str() else {
            continue;
        };
        let name = metric["__name__"].as_str().unwrap_or_default();
        let value = scalar(item);
        let row = agents.entry(agent_id.to_string()).or_default();
        row.agent_id = agent_id.to_string();
        match fact_key(name) {
            Some("host.info") => {
                if let Some(found) = metric.get(label::HOST_NAME).and_then(Value::as_str) {
                    row.host.hostname = Some(found.to_string());
                }
                if let Some(found) = metric.get(label::HOST_IP).and_then(Value::as_str)
                    && !row.host.ip_addresses.iter().any(|ip| ip == found)
                {
                    row.host.ip_addresses.push(found.to_string());
                }
                row.host.os = metric
                    .get(label::OS)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or(row.host.os.clone());
                row.host.arch = metric
                    .get(label::ARCH)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or(row.host.arch.clone());
                row.host.kernel = metric
                    .get(label::KERNEL)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or(row.host.kernel.clone());
            }
            Some("host.loadavg.1m") => row.host.load_1m = value,
            Some("host.loadavg.5m") => row.host.load_5m = value,
            Some("host.loadavg.15m") => row.host.load_15m = value,
            Some("host.memory.total_bytes") => row.host.memory_total_bytes = value,
            Some("host.memory.available_bytes") => row.host.memory_available_bytes = value,
            Some("host.memory.usage_ratio") => {
                row.host.memory_usage_percent = value.map(ratio_to_percent)
            }
            Some("host.disk.system.usage_ratio") => {
                // `system_disk_usage_ratio` 按 `disk_role` 分两条序列（system / data）。
                if metric.get(label::DISK_ROLE).and_then(Value::as_str) == Some("system") {
                    row.host.disk_usage_percent = value.map(ratio_to_percent);
                }
            }
            Some("host.disk.system.total_bytes") => {
                if metric.get(label::DISK_ROLE).and_then(Value::as_str) == Some("system") {
                    row.host.disk_total_bytes = value;
                }
            }
            Some("host.disk.system.available_bytes") => {
                if metric.get(label::DISK_ROLE).and_then(Value::as_str) == Some("system") {
                    row.host.disk_available_bytes = value;
                }
            }
            Some("host.filesystem.usage_ratio") => {
                // 逐挂载点：只留最紧张的那个（页面一行装不下全部）。
                if let Some(ratio) = value
                    && let Some(mount) = metric.get(label::MOUNTPOINT).and_then(Value::as_str)
                {
                    let percent = ratio_to_percent(ratio);
                    if row
                        .host
                        .filesystem_usage_percent
                        .is_none_or(|current| percent > current)
                    {
                        row.host.filesystem_usage_percent = Some(percent);
                        row.host.filesystem_mount = Some(mount.to_string());
                    }
                }
            }
            Some("host.uptime.seconds") => row.host.uptime_seconds = value,
            Some("process.pid") => *row.host.processes.get_or_insert(0.0) += 1.0,
            _ => {}
        }
    }

    Ok(json!({
        "generated_at_ms": now_ms(),
        "window_seconds": SAMPLE_WINDOW_SECONDS,
        "source": { "base_url": base_url },
        "totals": {
            "names": entries.len(),
            "series": total_series,
            "agents": agents.len(),
        },
        "agents": agents.into_values().collect::<Vec<_>>(),
        "catalog": entries,
    }))
}

/// 趋势图的一行：(fact_key 或指标名, 标题, 单位, 换算)。
/// 抽出来是为了过 clippy 的 `type_complexity`。
type SeriesPlan = (&'static str, &'static str, &'static str, fn(f64) -> f64);

async fn collect_history(
    http: &reqwest::Client,
    base_url: &str,
    agent_id: &str,
    window: i64,
    step: i64,
) -> Result<AgentHistory, String> {
    let expr = format!(
        "{{{}=\"{}\", __name__=~\"{}\"}}",
        label::AGENT,
        escape_promql(agent_id),
        agent_metric::HISTORY.join("|")
    );
    // 主机侧要 `max by (__name__)`：挂载点会展开成多条序列，图上只要一条（最紧张的那个）。
    // 磁盘带 `disk_role=system` 过滤，挂载点则没这个 label，所以拆两条。
    let agent = escape_promql(agent_id);
    let host_load_mem = format!(
        "max by (__name__) ({{{}=\"{}\", __name__=~\"{}\"}})",
        label::AGENT,
        agent,
        names_for(&["host.loadavg.1m", "host.memory.usage_ratio"])
    );
    let host_disk = format!(
        "max by (__name__) ({{{}=\"{}\", __name__=~\"{}\", {}=\"system\"}})",
        label::AGENT,
        agent,
        names_for(&["host.disk.system.usage_ratio"]),
        label::DISK_ROLE
    );
    let host_filesystem = format!(
        "max by (__name__) ({{{}=\"{}\", __name__=~\"{}\"}})",
        label::AGENT,
        agent,
        names_for(&["host.filesystem.usage_ratio"])
    );
    let (self_result, load_mem, disk, filesystem) = tokio::join!(
        query_range(http, base_url, &expr, window, step),
        query_range(http, base_url, &host_load_mem, window, step),
        query_range(http, base_url, &host_disk, window, step),
        query_range(http, base_url, &host_filesystem, window, step),
    );

    let mut labels = BTreeMap::new();
    let mut by_name: BTreeMap<String, Vec<(i64, f64)>> = BTreeMap::new();
    for result in [self_result?, load_mem?, disk?, filesystem?] {
        for item in &result {
            let metric = &item["metric"];
            if labels.is_empty() {
                for key in SELECTION_LABELS {
                    if let Some(found) = metric.get(*key).and_then(Value::as_str) {
                        labels.insert((*key).to_string(), found.to_string());
                    }
                }
            }
            let Some(name) = metric["__name__"].as_str() else {
                continue;
            };
            by_name.insert(name.to_string(), points(item));
        }
    }

    // 先主机（页面就是为它加的），再 agent 自观测；每张图的名称/单位/换算出后端定。
    let plan: Vec<SeriesPlan> = vec![
        ("host.loadavg.1m", "1 分钟负载", "count", |value| value),
        (
            "host.memory.usage_ratio",
            "主机内存使用率",
            "percent",
            ratio_to_percent,
        ),
        (
            "host.disk.system.usage_ratio",
            "系统盘使用率",
            "percent",
            ratio_to_percent,
        ),
        (
            "host.filesystem.usage_ratio",
            "最紧张挂载点使用率",
            "percent",
            ratio_to_percent,
        ),
        (
            agent_metric::MEMORY_BYTES,
            "Agent 常驻内存",
            "bytes",
            |value| value,
        ),
        (
            agent_metric::CPU_RATIO,
            "Agent CPU（单核比例换算）",
            "percent",
            ratio_to_percent,
        ),
        (
            agent_metric::CPU_CORES,
            "Agent 逻辑核数",
            "count",
            |value| value,
        ),
        (
            agent_metric::ADMIN_LATENCY_SECONDS,
            "管理面往返时延",
            "milliseconds",
            |value| seconds_to_millis(value) as f64,
        ),
    ];
    let mut series = Vec::new();
    for (key, title, unit, convert) in plan {
        // 前四项是 fact_key（主机侧），后四项直接是指标名（agent 自观测）。
        let name = spec_name(key).unwrap_or(key);
        let points = by_name.remove(name).unwrap_or_default();
        if points.is_empty() {
            continue;
        }
        series.push(HistorySeries {
            metric: name.to_string(),
            title,
            unit,
            points: points
                .into_iter()
                .map(|(at, value)| (at, convert(value)))
                .collect(),
        });
    }

    Ok(AgentHistory {
        agent_id: agent_id.to_string(),
        window_seconds: window,
        step_seconds: step,
        labels,
        series,
    })
}

fn history_window(window: Option<i64>, step: Option<i64>) -> (i64, i64) {
    let window = window
        .unwrap_or(3_600)
        .clamp(MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS);
    let mut step = step.unwrap_or(30).clamp(MIN_STEP_SECONDS, MAX_STEP_SECONDS);
    // 窗口拉长后固定步长会撞上点数上限：按窗口放宽步长，宁可粗一点也不截断曲线。
    // 用向上取整：`window / MAX_POINTS` 向下取整时点数会略微超限。
    let floor_step = (window + MAX_POINTS - 1) / MAX_POINTS;
    step = step.max(floor_step.max(MIN_STEP_SECONDS));
    (window, step)
}

/// GET `/api/v1/query`，返回 `data.result`。
async fn query(http: &reqwest::Client, base_url: &str, expr: &str) -> Result<Vec<Value>, String> {
    let url = format!("{base_url}/api/v1/query");
    let payload = get_json(http, &url, &[("query", expr)]).await?;
    Ok(payload["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

/// GET `/api/v1/query_range`，返回 `data.result`。
async fn query_range(
    http: &reqwest::Client,
    base_url: &str,
    expr: &str,
    window: i64,
    step: i64,
) -> Result<Vec<Value>, String> {
    let url = format!("{base_url}/api/v1/query_range");
    let now = (now_ms() / 1000) as i64;
    let start = (now - window).to_string();
    let end = now.to_string();
    let step = step.to_string();
    let payload = get_json(
        http,
        &url,
        &[
            ("query", expr),
            ("start", start.as_str()),
            ("end", end.as_str()),
            ("step", step.as_str()),
        ],
    )
    .await?;
    Ok(payload["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

async fn get_json(
    http: &reqwest::Client,
    url: &str,
    params: &[(&str, &str)],
) -> Result<Value, String> {
    let response = http
        .get(url)
        .query(params)
        .timeout(QUERY_TIMEOUT)
        .send()
        .await
        .map_err(|err| format!("victoria metrics 请求失败：{err}"))?;
    if !response.status().is_success() {
        return Err(format!("victoria metrics 返回 HTTP {}", response.status()));
    }
    response
        .json()
        .await
        .map_err(|err| format!("victoria metrics 响应不是 JSON：{err}"))
}

/// 即时查询的标量值。VM 把值放在 `[时间戳, "值"]` 里，`NaN` / `Inf` 视为缺失。
fn scalar(item: &Value) -> Option<f64> {
    item["value"]
        .as_array()?
        .get(1)?
        .as_str()?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

/// 区间查询的点列 `[(unix 毫秒, 值)]`，跳过非有限值（VM 的时间序列会带 `NaN`）。
fn points(item: &Value) -> Vec<(i64, f64)> {
    item["values"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|point| {
                    let pair = point.as_array()?;
                    let at = pair.first()?.as_f64()?;
                    let value = pair.get(1)?.as_str()?.parse::<f64>().ok()?;
                    value
                        .is_finite()
                        .then(|| ((at * 1000.0).round() as i64, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// PromQL / MetricsQL 字符串字面量转义：`agent` id 来自 URL，不能直接拼进表达式。
fn escape_promql(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 主机侧的 fact_key 必须都能在 `wist-metrics` 的 spec 表里解析出指标名。
    /// 改名/删 spec 时这里先红，而不是页面上静默少几列。
    #[test]
    fn every_host_fact_resolves_to_a_metric_name() {
        for fact in HOST_FACTS {
            assert!(spec_name(fact).is_some(), "{fact} 不在 METRIC_SPECS 里");
        }
        // 反查也要能回来（解析查询结果时靠它分支）。
        for fact in HOST_FACTS {
            let name = spec_name(fact).expect("resolved");
            assert_eq!(fact_key(name), Some(*fact), "{fact} → {name} 反查不一致");
        }
    }

    #[test]
    fn window_and_step_are_clamped() {
        assert_eq!(history_window(None, None), (3_600, 30));
        assert_eq!(history_window(Some(1), Some(1)), (300, 10));
        assert_eq!(history_window(Some(999_999), Some(9_999)), (86_400, 900));
        // 长窗口 + 小步长：步长被放宽到点数上限以内。
        let (window, step) = history_window(Some(86_400), Some(10));
        assert!(window / step <= MAX_POINTS, "{window}/{step}");
    }

    #[test]
    fn promql_literals_are_escaped() {
        assert_eq!(escape_promql(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn scalar_ignores_non_finite_values() {
        assert_eq!(scalar(&json!({ "value": [1, "2.5"] })), Some(2.5));
        assert_eq!(scalar(&json!({ "value": [1, "NaN"] })), None);
        assert_eq!(scalar(&json!({})), None);
    }
}
