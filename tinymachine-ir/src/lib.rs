//! # TinyMachine IR — Language-Agnostic Intermediate Representation
//!
//! This crate defines a language-agnostic IR ([`IrProgram`]) and parser trait
//! ([`IrParser`]) for analyzing agent code across multiple languages.
//!
//! ## Architecture
//!
//! ```text
//! Python source ──→ PythonParser ──→ IrProgram ──→ ProfilerVisitor
//! JS source     ──→ JsParser     ──→ IrProgram ──→ UOpsVisitor
//! ```
//!
//! The IR keeps only the information needed for:
//! - Import detection (module resolution)
//! - Function/method call detection
//! - String literal extraction (URLs, file paths)
//! - Numeric literal extraction (array dimensions)
//!
//! ## Feature flags
//!
//! - `python` (default): Enable Python frontend via `rustpython-parser`.

pub mod types;
pub mod parser;
pub mod walk;

#[cfg(feature = "python")]
pub mod python;

pub use types::*;
pub use parser::{IrParser, IrParseError};
pub use walk::IrVisitor;
