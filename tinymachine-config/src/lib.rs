//! TinyMachine Configuration — TOML config parsing + kernel cmdline parsing
//!
//! In binary mode, config is loaded from TOML files.
//! In unikernel mode, config is loaded from kernel cmdline (`tinymachine.*` params).

pub mod cmdline;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from config operations
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

/// Top-level TinyMachine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TinyMachineConfig {
    /// Template storage directory
    #[serde(default = "default_template_dir")]
    pub template_dir: PathBuf,
    /// Fork engine settings
    #[serde(default)]
    pub fork: ForkConfig,
    /// Pool settings
    #[serde(default)]
    pub pool: PoolConfig,
    /// Orchestrator settings
    #[serde(default)]
    pub orchestrator: OrchestratorConfig,
    /// CLI settings
    #[serde(default)]
    pub cli: CliConfig,
}

impl Default for TinyMachineConfig {
    fn default() -> Self {
        Self {
            template_dir: default_template_dir(),
            fork: ForkConfig::default(),
            pool: PoolConfig::default(),
            orchestrator: OrchestratorConfig::default(),
            cli: CliConfig::default(),
        }
    }
}

fn default_template_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".tinymachine").join("templates")
}

/// Fork engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkConfig {
    /// Number of VCPUs per sandbox
    #[serde(default = "default_vcpus")]
    pub vcpus: u64,
    /// Memory per sandbox in MB
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    /// Timeout in ms for guest execution
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for ForkConfig {
    fn default() -> Self {
        Self {
            vcpus: default_vcpus(),
            memory_mb: default_memory_mb(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

fn default_vcpus() -> u64 { 1 }
fn default_memory_mb() -> u64 { 128 }
fn default_timeout_ms() -> u64 { 5000 }

/// Pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Minimum warm forks
    #[serde(default = "default_pool_min")]
    pub min: usize,
    /// Maximum warm forks
    #[serde(default = "default_pool_max")]
    pub max: usize,
    /// Idle timeout in seconds
    #[serde(default = "default_pool_timeout")]
    pub idle_timeout_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min: default_pool_min(),
            max: default_pool_max(),
            idle_timeout_secs: default_pool_timeout(),
        }
    }
}

fn default_pool_min() -> usize { 3 }
fn default_pool_max() -> usize { 20 }
fn default_pool_timeout() -> u64 { 60 }

/// Orchestrator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Listen address
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Listen port
    #[serde(default = "default_listen_port")]
    pub port: u16,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            port: default_listen_port(),
        }
    }
}

fn default_listen_addr() -> String { "127.0.0.1".into() }
fn default_listen_port() -> u16 { 8080 }

/// CLI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Default execution timeout in ms
    #[serde(default = "default_cli_timeout")]
    pub exec_timeout_ms: u64,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            exec_timeout_ms: default_cli_timeout(),
        }
    }
}

fn default_cli_timeout() -> u64 { 10000 }

impl TinyMachineConfig {
    /// Load config from a TOML file
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: TinyMachineConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load config from default locations
    pub fn load_default() -> Result<Self> {
        let paths: Vec<PathBuf> = vec![
            PathBuf::from("tinymachine.toml"),
            PathBuf::from("/etc/tinymachine/config.toml"),
        ]
        .into_iter()
        .chain(dirs_config_dir().map(|p| p.join("config.toml")))
        .collect();

        for path in &paths {
            // Open directly instead of path.exists() + load() to
            // avoid TOCTOU race. If the file doesn't exist, try next path.
            match Self::load(path) {
                Ok(config) => return Ok(config),
                Err(ConfigError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(Self::default())
    }

    fn validate(&self) -> Result<()> {
        if self.fork.vcpus == 0 {
            return Err(ConfigError::Validation("fork.vcpus must be > 0".into()));
        }
        if self.fork.memory_mb < 16 {
            return Err(ConfigError::Validation("fork.memory_mb must be >= 16".into()));
        }
        if self.pool.max < self.pool.min {
            return Err(ConfigError::Validation(
                "pool.max must be >= pool.min".into(),
            ));
        }
        if self.pool.max > 1000 {
            return Err(ConfigError::Validation(
                "pool.max must be <= 1000".into(),
            ));
        }
        Ok(())
    }
}

fn dirs_config_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config").join("tinymachine"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TinyMachineConfig::default();
        assert_eq!(config.fork.vcpus, 1);
        assert_eq!(config.fork.memory_mb, 128);
        assert_eq!(config.pool.min, 3);
        assert_eq!(config.orchestrator.port, 8080);
    }

    #[test]
    fn test_config_roundtrip() {
        let config = TinyMachineConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: TinyMachineConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.fork.vcpus, config.fork.vcpus);
        assert_eq!(parsed.orchestrator.port, config.orchestrator.port);
    }

    #[test]
    fn test_validation() {
        let mut config = TinyMachineConfig::default();
        config.fork.vcpus = 0;
        assert!(config.validate().is_err());

        config.fork.vcpus = 1;
        config.pool.max = 1;
        config.pool.min = 5;
        assert!(config.validate().is_err());
    }
}
