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

/// `[database]` section — required when using `--db-store` or `--migrate`.
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

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub filters: Vec<FilterEntry>,
    pub highlighted_ports: Option<HighlightedPortsConfig>,
    pub database: Option<DatabaseConfig>,
    pub live: Option<LiveConfig>,
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
