//! Kernel cmdline config parser — for unikernel mode.
//!
//! In unikernel mode, there's no TOML parser or config file. Config is passed
//! via kernel cmdline as `tinyos.key=value` pairs. The orchestrator embeds
//! these params when booting the unikernel, and the guest reads `/proc/cmdline`.
//!
//! # Format
//! ```text
//! console=ttyS0 tinyos.agent_id=my-agent tinyos.log_level=debug tinyos.enable_network=true
//! ```
//!
//! Only `tinyos.*` parameters are parsed. All other kernel parameters are ignored.

use tracing::warn;

use crate::{ConfigError, TinyMachineConfig};

/// Configuration values that can be passed via kernel command line.
///
/// All fields use `Option` to distinguish "not set" from "set to default".
/// When merged or applied, `None` means "keep existing value".
#[derive(Debug, Clone, Default)]
pub struct CmdlineConfig {
    pub agent_id: Option<String>,
    pub log_level: Option<String>,
    pub orchestrator_addr: Option<String>,
    pub max_forks: Option<u32>,
    pub default_tier: Option<String>,
    pub memory_limit_mb: Option<u64>,
    pub cpu_cores: Option<u32>,
    pub enable_network: Option<bool>,
    pub enable_gpu: Option<bool>,
    pub proxy_addr: Option<String>,
}

impl CmdlineConfig {
    pub fn default_max_forks() -> u32 { 100 }
    pub fn default_memory_limit_mb() -> u64 { 512 }
    pub fn default_cpu_cores() -> u32 { 1 }

    /// Parse raw `/proc/cmdline` content (a single line of space-separated key=value pairs).
    ///
    /// Only processes parameters with the `tinyos.` prefix. All other parameters
    /// (kernel boot params like `console=ttyS0`, `acpi=off`, etc.) are silently ignored.
    ///
    /// # Errors
    /// Returns `ConfigError::Validation` if a tinyos.* parameter cannot be parsed
    /// (e.g. invalid boolean value, non-numeric integer).
    pub fn parse(cmdline: &str) -> Result<Self, ConfigError> {
        let mut config = CmdlineConfig::default();

        for token in tokenize_cmdline(cmdline) {
            if token.starts_with('#') {
                continue;
            }

            if !token.starts_with("tinyos.") {
                continue;
            }

            let inner = token.strip_prefix("tinyos.").unwrap();
            let (key, value) = match inner.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => {
                    warn!("cmdline: ignoring key without '=': {token}");
                    continue;
                }
            };

            config.set(key, value)?;
        }

        Ok(config)
    }

    fn set(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        match key {
            "agent_id" => self.agent_id = Some(value.to_string()),
            "log_level" => self.log_level = Some(value.to_string()),
            "orchestrator_addr" => self.orchestrator_addr = Some(value.to_string()),
            "max_forks" => {
                let n: u32 = value.parse().map_err(|e| {
                    ConfigError::Validation(format!("cmdline: max_forks='{value}' is not a valid u32: {e}"))
                })?;
                self.max_forks = Some(n);
            }
            "default_tier" => self.default_tier = Some(value.to_string()),
            "memory_limit_mb" => {
                let n: u64 = value.parse().map_err(|e| {
                    ConfigError::Validation(format!("cmdline: memory_limit_mb='{value}' is not a valid u64: {e}"))
                })?;
                self.memory_limit_mb = Some(n);
            }
            "cpu_cores" => {
                let n: u32 = value.parse().map_err(|e| {
                    ConfigError::Validation(format!("cmdline: cpu_cores='{value}' is not a valid u32: {e}"))
                })?;
                self.cpu_cores = Some(n);
            }
            "enable_network" => {
                let b = parse_bool(value).map_err(|e| {
                    ConfigError::Validation(format!("cmdline: enable_network='{value}' is not a valid bool: {e}"))
                })?;
                self.enable_network = Some(b);
            }
            "enable_gpu" => {
                let b = parse_bool(value).map_err(|e| {
                    ConfigError::Validation(format!("cmdline: enable_gpu='{value}' is not a valid bool: {e}"))
                })?;
                self.enable_gpu = Some(b);
            }
            "proxy_addr" => self.proxy_addr = Some(value.to_string()),
            _ => {
                warn!("cmdline: unknown tinyos parameter: tinyos.{key}");
            }
        }
        Ok(())
    }

    /// Read and parse `/proc/cmdline`.
    ///
    /// This is the primary entry point for unikernel mode. In a unikernel,
    /// config is read from `/proc/cmdline` rather than a TOML file.
    ///
    /// # Errors
    /// Returns `ConfigError::Io` if `/proc/cmdline` cannot be read,
    /// or `ConfigError::Validation` if parsing fails.
    pub fn from_proc_cmdline() -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string("/proc/cmdline")
            .map_err(ConfigError::Io)?;
        Self::parse(&content)
    }

    /// Serialize config back to cmdline fragment (without kernel params).
    ///
    /// The orchestrator calls this when booting a unikernel: it appends the
    /// returned string to the kernel cmdline (e.g. via PVH boot protocol).
    ///
    /// Only `Some(...)` fields are serialized. `None` fields are skipped.
    pub fn to_cmdline(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        if let Some(v) = &self.agent_id {
            parts.push(format!("tinyos.agent_id={}", quote_if_needed(v)));
        }
        if let Some(v) = &self.log_level {
            parts.push(format!("tinyos.log_level={}", quote_if_needed(v)));
        }
        if let Some(v) = &self.orchestrator_addr {
            parts.push(format!("tinyos.orchestrator_addr={}", quote_if_needed(v)));
        }
        if let Some(v) = &self.max_forks {
            parts.push(format!("tinyos.max_forks={v}"));
        }
        if let Some(v) = &self.default_tier {
            parts.push(format!("tinyos.default_tier={}", quote_if_needed(v)));
        }
        if let Some(v) = &self.memory_limit_mb {
            parts.push(format!("tinyos.memory_limit_mb={v}"));
        }
        if let Some(v) = &self.cpu_cores {
            parts.push(format!("tinyos.cpu_cores={v}"));
        }
        if let Some(v) = &self.enable_network {
            parts.push(format!("tinyos.enable_network={v}"));
        }
        if let Some(v) = &self.enable_gpu {
            parts.push(format!("tinyos.enable_gpu={v}"));
        }
        if let Some(v) = &self.proxy_addr {
            parts.push(format!("tinyos.proxy_addr={}", quote_if_needed(v)));
        }

        parts.join(" ")
    }

    /// Extract cmdline-relevant fields from a TOML-based `TinyMachineConfig`.
    ///
    /// This maps the nested TOML structure to the flat cmdline key-value format.
    /// Orchestrator uses this when converting its TOML config to cmdline for
    /// unikernel booting.
    pub fn from_config(config: &TinyMachineConfig) -> Self {
        CmdlineConfig {
            agent_id: None,
            log_level: None,
            orchestrator_addr: Some(config.orchestrator.listen_addr.clone()),
            max_forks: Some(config.pool.max as u32),
            default_tier: None,
            memory_limit_mb: Some(config.fork.memory_mb),
            cpu_cores: Some(config.fork.vcpus as u32),
            enable_network: None,
            enable_gpu: None,
            proxy_addr: Some(format!("{}:{}", config.orchestrator.listen_addr, config.orchestrator.port)),
        }
    }

    /// Merge another config into this one.
    ///
    /// For each field, if `other` has a `Some(...)` value, it overrides `self`.
    /// `None` fields in `other` leave `self` unchanged.
    pub fn merge(&mut self, other: Self) {
        if let Some(v) = other.agent_id { self.agent_id = Some(v); }
        if let Some(v) = other.log_level { self.log_level = Some(v); }
        if let Some(v) = other.orchestrator_addr { self.orchestrator_addr = Some(v); }
        if let Some(v) = other.max_forks { self.max_forks = Some(v); }
        if let Some(v) = other.default_tier { self.default_tier = Some(v); }
        if let Some(v) = other.memory_limit_mb { self.memory_limit_mb = Some(v); }
        if let Some(v) = other.cpu_cores { self.cpu_cores = Some(v); }
        if let Some(v) = other.enable_network { self.enable_network = Some(v); }
        if let Some(v) = other.enable_gpu { self.enable_gpu = Some(v); }
        if let Some(v) = other.proxy_addr { self.proxy_addr = Some(v); }
    }
}

/// Apply cmdline config values to a `TinyMachineConfig`, overriding matching fields.
///
/// Called during startup in binary mode when the user wants cmdline overrides
/// on top of a TOML config file (e.g. `tinyos --cmdline-override 'tinyos.max_forks=200'`).
impl From<CmdlineConfig> for TinyMachineConfig {
    fn from(cc: CmdlineConfig) -> Self {
        let mut config = TinyMachineConfig::default();

        if let Some(v) = &cc.log_level {
            let _ = v; // log level is handled by tracing, not TinyMachineConfig
        }
        if let Some(v) = cc.max_forks {
            config.pool.max = v as usize;
        }
        if let Some(v) = cc.memory_limit_mb {
            config.fork.memory_mb = v;
        }
        if let Some(v) = cc.cpu_cores {
            config.fork.vcpus = v as u64;
        }
        if let Some(v) = cc.orchestrator_addr {
            // orchestrator_addr is a Unix socket path; in TOML config,
            // we map listen_addr to it. But listen_addr might be an IP.
            // For simplicity, just store as-is; consumer interprets.
            config.orchestrator.listen_addr = v;
        }
        if let Some(v) = cc.proxy_addr {
            if let Some((addr, port_str)) = v.split_once(':') {
                config.orchestrator.listen_addr = addr.to_string();
                if let Ok(port) = port_str.parse::<u16>() {
                    config.orchestrator.port = port;
                }
            }
        }

        config
    }
}

impl TinyMachineConfig {
    /// Load config: try kernel cmdline first (unikernel mode), fall back to TOML.
    ///
    /// In unikernel mode, `/proc/cmdline` exists and contains `tinyos.*` params.
    /// In binary mode, `/proc/cmdline` may still exist (Linux) but won't have
    /// `tinyos.*` params, so we fall back to TOML file loading.
    pub fn from_maybe_cmdline() -> Result<Self, ConfigError> {
        // Try reading /proc/cmdline — this always exists on Linux but may not
        // contain tinyos.* parameters. If it does, use cmdline config.
        if let Ok(content) = std::fs::read_to_string("/proc/cmdline") {
            let cmdline_config = CmdlineConfig::parse(&content)?;
            // If at least one tinyos.* param was found, use cmdline mode
            let has_tinyos_params = content.contains("tinyos.");
            if has_tinyos_params {
                let mut config: TinyMachineConfig = cmdline_config.into();
                // Apply defaults for unset fields
                if config.fork.memory_mb == 0 {
                    config.fork.memory_mb = CmdlineConfig::default_memory_limit_mb();
                }
                if config.fork.vcpus == 0 {
                    config.fork.vcpus = CmdlineConfig::default_cpu_cores() as u64;
                }
                if config.pool.max == 0 {
                    config.pool.max = CmdlineConfig::default_max_forks() as usize;
                }
                return Ok(config);
            }
        }

        // No tinyos params found — fall back to TOML
        Self::load_default()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Tokenize a cmdline string into individual tokens, handling quoted strings.
///
/// Supports:
/// - Space-separated tokens
/// - Double-quoted strings (`"value with spaces"`)
/// - Single-quoted strings (`'value with spaces'`)
/// - Comments (tokens starting with `#`)
fn tokenize_cmdline(cmdline: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_double_quote = false;
    let mut in_single_quote = false;
    let mut in_comment = false;

    for ch in cmdline.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
            }
            continue;
        }

        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            if !in_double_quote {
                // End of quoted string — flush
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            continue;
        }

        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            if !in_single_quote && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }

        if in_double_quote || in_single_quote {
            current.push(ch);
            continue;
        }

        if ch == '#' {
            in_comment = true;
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }

        if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Quote a string value if it contains spaces or special characters.
fn quote_if_needed(value: &str) -> String {
    if value.contains(char::is_whitespace) || value.contains('"') || value.contains('\'') {
        // Escape any double quotes inside
        let escaped = value.replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

/// Parse a boolean value from a string.
///
/// Accepts: `true`, `false`, `1`, `0`, `yes`, `no`
fn parse_bool(value: &str) -> Result<bool, &'static str> {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err("expected true/false/1/0/yes/no"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_cmdline() {
        let cmdline = "console=ttyS0 acpi=off tinyos.agent_id=my-agent tinyos.log_level=debug tinyos.orchestrator_addr=/tmp/tinyos.sock tinyos.max_forks=100 tinyos.default_tier=kvmfork tinyos.memory_limit_mb=512 tinyos.cpu_cores=2 tinyos.enable_network=true tinyos.enable_gpu=false tinyos.proxy_addr=127.0.0.1:8080";
        let config = CmdlineConfig::parse(cmdline).unwrap();

        assert_eq!(config.agent_id.as_deref(), Some("my-agent"));
        assert_eq!(config.log_level.as_deref(), Some("debug"));
        assert_eq!(config.orchestrator_addr.as_deref(), Some("/tmp/tinyos.sock"));
        assert_eq!(config.max_forks, Some(100));
        assert_eq!(config.default_tier.as_deref(), Some("kvmfork"));
        assert_eq!(config.memory_limit_mb, Some(512));
        assert_eq!(config.cpu_cores, Some(2));
        assert_eq!(config.enable_network, Some(true));
        assert_eq!(config.enable_gpu, Some(false));
        assert_eq!(config.proxy_addr.as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_parse_partial_cmdline() {
        let cmdline = "tinyos.agent_id=my-agent tinyos.cpu_cores=4 tinyos.enable_network=false";
        let config = CmdlineConfig::parse(cmdline).unwrap();

        assert_eq!(config.agent_id.as_deref(), Some("my-agent"));
        assert_eq!(config.log_level, None);
        assert_eq!(config.max_forks, None);
        assert_eq!(config.cpu_cores, Some(4));
        assert_eq!(config.enable_network, Some(false));
        assert_eq!(config.enable_gpu, None);
        assert_eq!(config.memory_limit_mb, None);
    }

    #[test]
    fn test_parse_empty_cmdline() {
        let config = CmdlineConfig::parse("").unwrap();
        assert_eq!(config.agent_id, None);
        assert_eq!(config.log_level, None);
        assert_eq!(config.max_forks, None);
    }

    #[test]
    fn test_parse_only_kernel_params() {
        let cmdline = "console=ttyS0 acpi=off noapic nolapic lpj=10000000 loglevel=3";
        let config = CmdlineConfig::parse(cmdline).unwrap();
        assert_eq!(config.agent_id, None);
        assert_eq!(config.log_level, None);
        assert_eq!(config.max_forks, None);
    }

    #[test]
    fn test_to_cmdline_roundtrip() {
        let original = CmdlineConfig {
            agent_id: Some("test-agent".into()),
            log_level: Some("warn".into()),
            orchestrator_addr: Some("/run/tinyos.sock".into()),
            max_forks: Some(50),
            default_tier: Some("wasm".into()),
            memory_limit_mb: Some(1024),
            cpu_cores: Some(8),
            enable_network: Some(true),
            enable_gpu: Some(true),
            proxy_addr: Some("0.0.0.0:9090".into()),
        };

        let serialized = original.to_cmdline();
        let parsed = CmdlineConfig::parse(&serialized).unwrap();

        assert_eq!(parsed.agent_id, original.agent_id);
        assert_eq!(parsed.log_level, original.log_level);
        assert_eq!(parsed.orchestrator_addr, original.orchestrator_addr);
        assert_eq!(parsed.max_forks, original.max_forks);
        assert_eq!(parsed.default_tier, original.default_tier);
        assert_eq!(parsed.memory_limit_mb, original.memory_limit_mb);
        assert_eq!(parsed.cpu_cores, original.cpu_cores);
        assert_eq!(parsed.enable_network, original.enable_network);
        assert_eq!(parsed.enable_gpu, original.enable_gpu);
        assert_eq!(parsed.proxy_addr, original.proxy_addr);
    }

    #[test]
    fn test_merge_config() {
        let mut base = CmdlineConfig {
            agent_id: Some("base-agent".into()),
            log_level: Some("info".into()),
            max_forks: Some(50),
            ..CmdlineConfig::default()
        };

        let override_cfg = CmdlineConfig {
            max_forks: Some(200),
            cpu_cores: Some(4),
            enable_gpu: Some(true),
            ..CmdlineConfig::default()
        };

        base.merge(override_cfg);

        assert_eq!(base.agent_id.as_deref(), Some("base-agent"));
        assert_eq!(base.log_level.as_deref(), Some("info"));
        assert_eq!(base.max_forks, Some(200));
        assert_eq!(base.cpu_cores, Some(4));
        assert_eq!(base.enable_gpu, Some(true));
        assert_eq!(base.enable_network, None);
    }

    #[test]
    fn test_tokenize_quoted_strings() {
        let cmdline = r#"tinyos.agent_id="my agent" tinyos.log_level='debug mode' tinyos.cpu_cores=2"#;
        let config = CmdlineConfig::parse(cmdline).unwrap();
        assert_eq!(config.agent_id.as_deref(), Some("my agent"));
        assert_eq!(config.log_level.as_deref(), Some("debug mode"));
        assert_eq!(config.cpu_cores, Some(2));
    }

    #[test]
    fn test_tokenize_comments() {
        let cmdline = "tinyos.agent_id=visible # this is a comment\ntinyos.log_level=debug";
        let config = CmdlineConfig::parse(cmdline).unwrap();
        assert_eq!(config.agent_id.as_deref(), Some("visible"));
        assert_eq!(config.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn test_parse_bool_variants() {
        assert_eq!(parse_bool("true"), Ok(true));
        assert_eq!(parse_bool("false"), Ok(false));
        assert_eq!(parse_bool("1"), Ok(true));
        assert_eq!(parse_bool("0"), Ok(false));
        assert_eq!(parse_bool("yes"), Ok(true));
        assert_eq!(parse_bool("no"), Ok(false));
        assert_eq!(parse_bool("TRUE"), Ok(true));
        assert_eq!(parse_bool("FALSE"), Ok(false));
        assert!(parse_bool("maybe").is_err());
    }

    #[test]
    fn test_from_config_mapping() {
        let mut config = TinyMachineConfig::default();
        config.orchestrator.listen_addr = "192.168.1.1".into();
        config.orchestrator.port = 9999;
        config.fork.memory_mb = 256;
        config.fork.vcpus = 4;
        config.pool.max = 50;

        let cmdline = CmdlineConfig::from_config(&config);
        assert_eq!(cmdline.orchestrator_addr.as_deref(), Some("192.168.1.1"));
        assert_eq!(cmdline.proxy_addr.as_deref(), Some("192.168.1.1:9999"));
        assert_eq!(cmdline.memory_limit_mb, Some(256));
        assert_eq!(cmdline.cpu_cores, Some(4));
        assert_eq!(cmdline.max_forks, Some(50));
    }

    #[test]
    fn test_invalid_values() {
        assert!(CmdlineConfig::parse("tinyos.max_forks=not_a_number").is_err());
        assert!(CmdlineConfig::parse("tinyos.enable_network=maybe").is_err());
        assert!(CmdlineConfig::parse("tinyos.cpu_cores=-1").is_err());
    }

    #[test]
    fn test_unknown_param_is_ignored() {
        let cmdline = "tinyos.unknown_param=foo tinyos.agent_id=bar";
        let config = CmdlineConfig::parse(cmdline).unwrap();
        assert_eq!(config.agent_id.as_deref(), Some("bar"));
        assert_eq!(config.log_level, None);
    }

    #[test]
    fn test_from_maybe_cmdline_falls_back_to_default() {
        // When /proc/cmdline exists but has no tinyos.* params,
        // from_maybe_cmdline should fall back to loading default TOML config.
        // We can test the logic by checking the behavior: it should return
        // a valid TinyMachineConfig with defaults.
        let config = TinyMachineConfig::from_maybe_cmdline().unwrap();
        assert_eq!(config.fork.vcpus, 1);
        assert_eq!(config.fork.memory_mb, 128);
        assert_eq!(config.pool.min, 3);
    }

    #[test]
    fn test_quote_if_needed() {
        assert_eq!(quote_if_needed("simple"), "simple");
        assert_eq!(quote_if_needed("with spaces"), r#""with spaces""#);
        assert_eq!(quote_if_needed(""), "");
    }
}
