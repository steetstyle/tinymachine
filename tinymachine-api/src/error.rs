//! Unified error types for the TinyMachine API layer.
//!
//! Every crate in the TinyMachine workspace uses `ApiError` (via `tinymachine_api::Result<T>`)
//! for all fallible operations at the boundary between components.
//!
//! # Examples
//!
//! ```
//! use tinymachine_api::{ApiError, Result};
//!
//! fn example() -> Result<String> {
//!     Err(ApiError::Sandbox("VM creation failed".into()))
//! }
//! ```

use std::path::PathBuf;

use thiserror::Error;

/// Unified error type for all TinyMachine API operations.
///
/// Each variant carries a human-readable message. Downstream crates
/// should map their own concrete error types into `ApiError` via `From` impls.
#[derive(Error, Debug)]
pub enum ApiError {
    /// Sandbox (fork / wasm) operation failed.
    #[error("Sandbox error: {0}")]
    Sandbox(String),

    /// LLM provider communication failed.
    #[error("Provider error: {0}")]
    Provider(String),

    /// Channel (CLI / Web / IPC) operation failed.
    #[error("Channel error: {0}")]
    Channel(String),

    /// Tool execution failed.
    #[error("Tool error: {0}")]
    Tool(String),

    /// Memory (store / recall / search) operation failed.
    #[error("Memory error: {0}")]
    Memory(String),

    /// Configuration load / validation failed.
    #[error("Config error: {0}")]
    Config(String),

    /// Requested resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// An unsupported variant or feature was requested.
    #[error("Unsupported: {0}")]
    Unsupported(String),

    /// An internal invariant was violated.
    #[error("Internal error: {0}")]
    Internal(String),

    /// A resource limit (timeout / memory / file descriptors) was exceeded.
    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    /// Template or snapshot not found in registry.
    #[error("Template not found: {lang}/{variant}")]
    TemplateNotFound {
        /// Language name (e.g. "python", "node")
        lang: String,
        /// Variant name (e.g. "minimal", "numpy")
        variant: String,
    },

    /// Policy engine rejected an operation (UOps violation).
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Snapshot path is invalid or missing.
    #[error("Snapshot path error: {0}")]
    SnapshotPath(String),
}

/// Convenience alias for `Result<T, ApiError>`.
pub type Result<T> = std::result::Result<T, ApiError>;

impl ApiError {
    /// Create a `Sandbox` variant from a displayable value.
    pub fn sandbox(msg: impl std::fmt::Display) -> Self {
        Self::Sandbox(msg.to_string())
    }

    /// Create a `NotFound` variant for a missing resource.
    pub fn not_found(resource: impl std::fmt::Display) -> Self {
        Self::NotFound(resource.to_string())
    }

    /// Create a `PolicyViolation` variant.
    pub fn policy_violation(reason: impl std::fmt::Display) -> Self {
        Self::PolicyViolation(reason.to_string())
    }

    /// Create a `TemplateNotFound` variant.
    pub fn template_not_found(
        lang: impl Into<String>,
        variant: impl Into<String>,
    ) -> Self {
        Self::TemplateNotFound {
            lang: lang.into(),
            variant: variant.into(),
        }
    }

    /// Create a `SnapshotPath` variant for invalid paths.
    pub fn snapshot_path(path: impl Into<PathBuf>) -> Self {
        Self::SnapshotPath(path.into().display().to_string())
    }
}

impl From<String> for ApiError {
    fn from(s: String) -> Self {
        Self::Internal(s)
    }
}

impl From<&str> for ApiError {
    fn from(s: &str) -> Self {
        Self::Internal(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ApiError::Sandbox("oops".into());
        assert_eq!(err.to_string(), "Sandbox error: oops");
    }

    #[test]
    fn test_convenience_constructors() {
        let err = ApiError::sandbox("vm init");
        assert!(matches!(err, ApiError::Sandbox(_)));

        let err = ApiError::not_found("template");
        assert!(matches!(err, ApiError::NotFound(_)));

        let err = ApiError::template_not_found("python", "minimal");
        assert!(matches!(err, ApiError::TemplateNotFound { .. }));
    }

    #[test]
    fn test_from_string() {
        let err: ApiError = "something broke".into();
        assert!(matches!(err, ApiError::Internal(_)));
    }

    #[test]
    fn test_type_alias() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }
}
