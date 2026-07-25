//! # TinyMachine API — Core Execution Traits & Types
//!
//! This crate defines the foundational abstractions for code execution
//! in TinyMachine. It contains no runtime logic — only traits, types,
//! error definitions, and a factory function.
//!
//! ## Modules
//!
//! | Module | Key Types | Purpose |
//! |--------|-----------|---------|
//! | [`sandbox`] | [`SandboxBackend`], [`ExecutionTier`] | Sandbox execution abstraction |
//! | [`config`] | [`Config`] | Configuration loading & validation |
//! | [`variant`] | [`Variant`] | Template variant selection |
//! | [`error`] | [`ApiError`], [`Result`] | Unified error handling |
//!
//! ## Trait overview
//!
//! ```
//! use tinymachine_api::{
//!     SandboxBackend, ExecutionTier, create_backend,
//!     Config, Variant,
//!     ApiError, Result,
//! };
//! ```

#![deny(missing_docs)]
#![deny(unsafe_code)] // This crate is safe Rust — no `unsafe` blocks allowed.

pub mod sandbox;
pub mod config;
pub mod variant;
pub mod error;

// ─── Re-exports ───────────────────────────────────────────────────────

pub use sandbox::{SandboxBackend, ExecutionTier, create_backend, register_backend, BackendType};
pub use config::Config;
pub use variant::Variant;
pub use error::{ApiError, Result};
