use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::Path;
use tracing::Level;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub listen_host:  String,
    pub listen_port:  u16,
    pub connect_ip:   String,
    pub connect_port: u16,
    pub fake_sni:     String,
    pub bypass_method: BypassMethod,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: u32,
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
    #[serde(default = "default_log_level", rename = "log_level")]
    pub log_level_str: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BypassMethod {
    WrongSeq,
}

fn default_worker_threads() -> u32  { 4 }
fn default_connection_timeout() -> u64 { 10 }
fn default_log_level() -> String { "info".to_string() }

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read config file: {}", path.display()))?;
        let config: AppConfig =
            serde_json::from_str(&contents).context("Invalid config file format")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.listen_port == 0 {
            bail!("listen_port cannot be 0");
        }
        if self.connect_port == 0 {
            bail!("connect_port cannot be 0");
        }
        self.connect_ip
            .parse::<Ipv4Addr>()
            .context("connect_ip is not a valid IPv4 address")?;
        if self.fake_sni.is_empty() {
            bail!("fake_sni cannot be empty");
        }
        if self.fake_sni.len() > 200 {
            bail!("fake_sni is too long (max 200 bytes)");
        }
        if self.worker_threads == 0 || self.worker_threads > 64 {
            bail!("worker_threads must be between 1 and 64");
        }
        if self.connection_timeout_secs == 0 || self.connection_timeout_secs > 300 {
            bail!("connection_timeout_secs must be between 1 and 300");
        }
        Ok(())
    }

    pub fn log_level(&self) -> Level {
        match self.log_level_str.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info"  => Level::INFO,
            "warn"  => Level::WARN,
            "error" => Level::ERROR,
            _       => Level::INFO,
        }
    }
}