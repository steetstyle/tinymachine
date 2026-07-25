//! Configuration trait for TinyMachine components.
//!
//! The [`Config`] trait provides a uniform interface for loading and
//! validating configuration from TOML files (in binary mode) or kernel
//! cmdline parameters (in unikernel mode).
//!
//! Any component that has a config struct can implement `Config` to
//! get automatic `load` and `validate` methods.
//!
//! # Examples
//!
//! ```
//! use tinymachine_api::Config;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct MyConfig {
//!     timeout_ms: u64,
//! }
//!
//! impl Config for MyConfig {
//!     fn load(path: &std::path::Path) -> tinymachine_api::Result<Self> {
//!         let content = std::fs::read_to_string(path)
//!             .map_err(|e| tinymachine_api::ApiError::Config(e.to_string()))?;
//!         let config: Self = serde_json::from_str(&content)
//!             .map_err(|e| tinymachine_api::ApiError::Config(e.to_string()))?;
//!         config.validate()?;
//!         Ok(config)
//!     }
//!
//!     fn validate(&self) -> tinymachine_api::Result<()> {
//!         if self.timeout_ms == 0 {
//!             return Err(tinymachine_api::ApiError::Config(
//!                 "timeout_ms must be > 0".into()
//!             ));
//!         }
//!         Ok(())
//!     }
//! }
//! ```

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Result;

/// Configuration trait for TinyMachine components.
///
/// Implementing this trait provides a standard way to load configuration
/// from a file path and validate it after deserialization.
///
/// # Type bounds
///
/// Types implementing `Config` must be `DeserializeOwned` (for loading)
/// and `Serialize` (for round-tripping).
pub trait Config: DeserializeOwned + Serialize {
    /// Load configuration from the given file path.
    ///
    /// Implementations should:
    /// 1. Read the file at `path`.
    /// 2. Deserialize (e.g. from TOML or JSON).
    /// 3. Call `self.validate()`.
    /// 4. Return the validated config or an error.
    ///
    /// # Errors
    ///
    /// Returns `ApiError::Config` on I/O errors, parse errors, or
    /// validation failures.
    fn load(path: &Path) -> Result<Self>;

    /// Validate the configuration after loading.
    ///
    /// Returns `Ok(())` if all fields pass validation, or
    /// `ApiError::Config` with a description of what is invalid.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// fn validate(&self) -> tinymachine_api::Result<()> {
    ///     if self.port == 0 {
    ///         return Err(ApiError::Config("port must be > 0".into()));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    fn validate(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::path::Path;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestConfig {
        name: String,
        count: u64,
    }

    impl Config for TestConfig {
        fn load(path: &Path) -> Result<Self> {
            let content = std::fs::read_to_string(path)
                .map_err(|e| crate::ApiError::Config(e.to_string()))?;
            // Use JSON for serialization (serde_json is already a dependency)
            let config: Self = serde_json::from_str(&content)
                .map_err(|e| crate::ApiError::Config(e.to_string()))?;
            config.validate()?;
            Ok(config)
        }

        fn validate(&self) -> Result<()> {
            if self.name.is_empty() {
                return Err(crate::ApiError::Config("name must not be empty".into()));
            }
            Ok(())
        }
    }

    #[test]
    fn test_config_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_tinymachine_api_config.json");

        let config = TestConfig {
            name: "test".into(),
            count: 42,
        };
        let json_str = serde_json::to_string(&config).unwrap();
        std::fs::write(&path, &json_str).unwrap();

        let loaded = TestConfig::load(&path).unwrap();
        assert_eq!(loaded, config);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_config_validation_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_tinymachine_api_config_invalid.json");

        let config = TestConfig {
            name: "".into(),
            count: 0,
        };
        let json_str = serde_json::to_string(&config).unwrap();
        std::fs::write(&path, &json_str).unwrap();

        let result = TestConfig::load(&path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name must not be empty"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_config_file_not_found() {
        let result = TestConfig::load(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::ApiError::Config(_)));
    }
}
