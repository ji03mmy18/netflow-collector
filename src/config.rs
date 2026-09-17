use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct FilterEntry {
    pub cidr: String,
    pub direction: Option<String>,
}

/// Optional `[highlighted_ports]` section in the TOML config.
#[derive(Debug, Deserialize)]
pub struct HighlightedPortsConfig {
    /// "extend" (default) — add to built-in list; "override" — replace built-in list entirely.
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

fn default_mode() -> String {
    "extend".to_string()
}

/// Optional `[live]` section for live monitor settings.
#[derive(Debug, Deserialize)]
pub struct LiveConfig {
    #[serde(default = "default_live_lines")]
    pub lines: usize,
}

fn default_live_lines() -> usize {
    10
}

/// `[database]` section — required when using `--db-store`, `--migrate` or a recompute mode.
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
}

impl DatabaseConfig {
    pub fn connection_string(&self) -> String {
        format!(
            "host={} port={} user={} password={} dbname={}",
            self.host, self.port, self.user, self.password, self.dbname
        )
    }
}

/// `[netflow]` — how much of the exporter's own metadata we trust.
#[derive(Debug, Deserialize, Clone)]
pub struct NetflowConfig {
    /// The intranet boundary that splits `intra_*` from `ext_*`.
    ///
    /// Required by `--db-store` and `--recompute-5m`; both read it from here so
    /// that a recompute always classifies traffic the same way the live
    /// collector did.  Changing it changes what every subsequent statistic
    /// means, so the collector records the value it used and warns if it moves.
    pub intra_cidr: Option<String>,

    /// Sampling divisor applied to every byte count.  Cisco does not reliably
    /// populate the v5 header field on all platforms, so this is configured
    /// rather than read from the packet.  1 = no sampling.
    #[serde(default = "default_sampling_interval")]
    pub sampling_interval: i32,

    /// Watchdog on the exporter's clock.  `ts` is derived from the packet, which
    /// means trusting the switch's NTP.  When `|received_at - ts|` exceeds this,
    /// the record falls back to the collector's own receive time — a broken
    /// switch clock then degrades the data to the old behaviour instead of
    /// silently scattering it into buckets hours away.
    ///
    /// With active/inactive timeout both at 1s the normal skew is a tight 0–2s
    /// band, so this threshold has enormous headroom.
    #[serde(default = "default_clock_skew_threshold")]
    pub clock_skew_threshold_seconds: i64,
}

fn default_sampling_interval() -> i32 {
    1
}

fn default_clock_skew_threshold() -> i64 {
    60
}

impl Default for NetflowConfig {
    fn default() -> Self {
        Self {
            intra_cidr: None,
            sampling_interval: default_sampling_interval(),
            clock_skew_threshold_seconds: default_clock_skew_threshold(),
        }
    }
}

/// `[stats]` — in-memory aggregation behaviour.
#[derive(Debug, Deserialize, Clone)]
pub struct StatsConfig {
    /// How often pending bucket deltas are flushed to the database.
    ///
    /// This is independent of the 5-minute bucket width: the bucket is a data
    /// model decision (what curves you want to plot), the flush interval is an
    /// operational one (freshness vs. write churn).  Flushing every 60s into a
    /// 300s bucket costs nothing in storage — the same row is just updated 5
    /// times instead of once — and caps both query staleness and crash exposure
    /// at one minute.
    #[serde(default = "default_flush_seconds")]
    pub flush_seconds: u64,
}

fn default_flush_seconds() -> u64 {
    60
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            flush_seconds: default_flush_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// The one IP list: it decides what is printed, what is stored, and what is
    /// counted.  `direction` selects which side of a flow has to match.
    #[serde(default)]
    pub filters: Vec<FilterEntry>,
    pub highlighted_ports: Option<HighlightedPortsConfig>,
    pub database: Option<DatabaseConfig>,
    pub live: Option<LiveConfig>,
    pub netflow: Option<NetflowConfig>,
    pub stats: Option<StatsConfig>,
}

impl Config {
    pub fn netflow(&self) -> NetflowConfig {
        self.netflow.clone().unwrap_or_default()
    }

    pub fn stats(&self) -> StatsConfig {
        self.stats.clone().unwrap_or_default()
    }

}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
