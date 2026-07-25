//! Language-agnostic parser trait.
//!
//! Each language frontend implements `IrParser` to convert language-specific
//! ASTs into TinyMachine IR ([`IrProgram`]).
//!
//! # Adding a new language
//!
//! 1. Add the language's parser as a dependency (e.g. `boa_parser` for JS).
//! 2. Create a new module (e.g. `js.rs`) with a struct implementing `IrParser`.
//! 3. Feature-gate it behind a cargo feature flag.
//! 4. Register it in the crate's dispatch logic.

use crate::types::IrProgram;

/// Error returned when parsing fails.
#[derive(Debug, Clone)]
pub struct IrParseError {
    /// Human-readable error message.
    pub message: String,
    /// Source language that was being parsed.
    pub language: String,
}

impl std::fmt::Display for IrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] parse error: {}", self.language, self.message)
    }
}

impl std::error::Error for IrParseError {}

/// The parser trait — implemented by each language frontend.
///
/// # Example
///
/// ```ignore
/// use tinymachine_ir::{IrParser, IrProgram};
/// use tinymachine_ir::python::PythonParser;
///
/// let program = PythonParser::parse("import numpy; x = np.ones((3, 3))")?;
/// assert!(!program.body.is_empty());
/// ```
pub trait IrParser {
    /// Parse source code into a language-agnostic IR program.
    ///
    /// Returns `Err(IrParseError)` if the source code has syntax errors
    /// or if parsing is not supported for this language.
    fn parse(code: &str) -> Result<IrProgram, IrParseError>;
}
