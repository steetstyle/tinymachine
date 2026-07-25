//! Language-agnostic IR types for TinyMachine profiler and UOps analyzer.
//!
//! These types represent parsed code in a language-independent way.
//! Each language frontend (Python, JavaScript, etc.) maps its native AST
//! to these types. The profiler and UOps analyzer then walk the IR
//! without knowing which language the original code was written in.
//!
//! # Design
//!
//! The IR covers only node types that are useful for:
//! - Import detection (module resolution)
//! - Function/method call detection (network, file, process, GPU)
//! - String literal extraction (URLs, paths)
//! - Numeric literal extraction (array dimensions)

use std::fmt;

/// A complete program — a list of top-level statements.
#[derive(Debug, Clone, PartialEq)]
pub struct IrProgram {
    pub body: Vec<IrStmt>,
}

impl IrProgram {
    /// Create an empty program.
    pub fn empty() -> Self {
        Self { body: Vec::new() }
    }
}

// ─── Statements ───────────────────────────────────────────────────────

/// A statement — something that "does" something (not a value).
#[derive(Debug, Clone, PartialEq)]
pub enum IrStmt {
    /// `import module` or `import module as alias`
    Import {
        module: String,
        alias: Option<String>,
    },
    /// `from module import name` or `from module import name as alias`
    ImportFrom {
        module: String,
        symbol: String,
        alias: Option<String>,
    },
    /// An expression used as a statement (e.g. `foo()`)
    Expr {
        expr: IrExpr,
    },
    /// Assignment: `target = value`
    Assign {
        targets: Vec<IrExpr>,
        value: IrExpr,
    },
    /// Augmented assignment: `target += value`
    AugAssign {
        target: IrExpr,
        op: IrOperator,
        value: IrExpr,
    },
    /// Function definition (sync or async — profiler treats both the same)
    FunctionDef {
        name: String,
        body: Vec<IrStmt>,
    },
    /// `return value` (or bare `return`)
    Return {
        value: Option<IrExpr>,
    },
    /// `del target`
    Delete {
        targets: Vec<IrExpr>,
    },
    /// `for target in iter: body`
    For {
        target: IrExpr,
        iter: IrExpr,
        body: Vec<IrStmt>,
    },
    /// `while test: body`
    While {
        test: IrExpr,
        body: Vec<IrStmt>,
    },
    /// `if test: body else: orelse`
    If {
        test: IrExpr,
        body: Vec<IrStmt>,
        orelse: Vec<IrStmt>,
    },
    /// `with items: body`
    With {
        items: Vec<IrWithItem>,
        body: Vec<IrStmt>,
    },
    /// `try: body except ...: handlers else: orelse finally: finalbody`
    Try {
        body: Vec<IrStmt>,
        handlers: Vec<IrExceptHandler>,
        orelse: Vec<IrStmt>,
        finalbody: Vec<IrStmt>,
    },
    /// `raise exc` (or bare `raise`)
    Raise {
        exc: Option<IrExpr>,
    },
    /// `class name(bases): body`
    ClassDef {
        name: String,
        body: Vec<IrStmt>,
    },
    /// `assert test, msg`
    Assert {
        test: IrExpr,
        msg: Option<IrExpr>,
    },
    /// `break`
    Break,
    /// `continue`
    Continue,
    /// `pass`
    Pass,
}

impl IrStmt {
    /// Walk all child statements recursively.
    pub fn children_mut(&mut self) -> Vec<&mut Vec<IrStmt>> {
        use IrStmt::*;
        match self {
            FunctionDef { body, .. } | ClassDef { body, .. } => vec![body],
            For { body, .. } | While { body, .. } => vec![body],
            If { body, orelse, .. } => vec![body, orelse],
            With { body, .. } => vec![body],
            Try { body, handlers, orelse, finalbody, .. } => {
                let mut v = vec![body, orelse, finalbody];
                for h in handlers.iter_mut() {
                    v.push(&mut h.body);
                }
                v
            }
            _ => vec![],
        }
    }
}

// ─── Expressions ──────────────────────────────────────────────────────

/// An expression — something that produces a value.
///
/// Recursive fields (containing another `IrExpr`) are `Box`ed to avoid
/// infinite size. Collections like `Vec<IrExpr>` are fine because `Vec`
/// is heap-allocated.
#[derive(Debug, Clone, PartialEq)]
pub enum IrExpr {
    /// Boolean operation: `a and b`
    BoolOp {
        op: IrBoolOp,
        values: Vec<IrExpr>,
    },
    /// Binary operation: `a + b`
    BinOp {
        left: Box<IrExpr>,
        op: IrOperator,
        right: Box<IrExpr>,
    },
    /// Unary operation: `-a`, `not a`
    UnaryOp {
        op: IrUnaryOp,
        operand: Box<IrExpr>,
    },
    /// A literal constant: `None`, `True`, `"hello"`, `42`
    Constant(IrConstant),
    /// Attribute access: `obj.attr`
    Attribute {
        value: Box<IrExpr>,
        attr: String,
    },
    /// Subscript: `obj[key]`
    Subscript {
        value: Box<IrExpr>,
        slice: Box<IrExpr>,
    },
    /// Starred expression: `*args`
    Starred {
        value: Box<IrExpr>,
    },
    /// A simple variable name: `foo`
    Name(String),
    /// List literal: `[1, 2, 3]`
    List(Vec<IrExpr>),
    /// Tuple literal: `(1, 2, 3)`
    Tuple(Vec<IrExpr>),
    /// Dict literal: `{k: v}`
    Dict {
        keys: Vec<IrExpr>,
        values: Vec<IrExpr>,
    },
    /// Set literal: `{1, 2, 3}`
    Set(Vec<IrExpr>),
    /// Function/method call: `func(args)`
    Call {
        func: Box<IrExpr>,
        args: Vec<IrExpr>,
        keywords: Vec<IrKeyword>,
    },
    /// Conditional expression: `a if test else b`
    IfExp {
        test: Box<IrExpr>,
        body: Box<IrExpr>,
        orelse: Box<IrExpr>,
    },
    /// Lambda: `lambda args: body`
    Lambda {
        args: Vec<String>,
        body: Box<IrExpr>,
    },
    /// Comparison: `a == b`, `a < b < c`
    Compare {
        left: Box<IrExpr>,
        ops: Vec<IrCmpOp>,
        comparators: Vec<IrExpr>,
    },
}

// ─── Constants ─────────────────────────────────────────────────────────

/// A literal constant value.
#[derive(Debug, Clone, PartialEq)]
pub enum IrConstant {
    /// The `None` value
    NoneValue,
    /// Boolean: `True` / `False`
    Bool(bool),
    /// String literal: `"hello"`
    Str(String),
    /// Integer literal: `42`
    Int(i64),
    /// Float literal: `3.14`
    Float(f64),
    /// Ellipsis: `...`
    Ellipsis,
}

impl IrConstant {
    /// Extract the string value if this is a `Str` constant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            IrConstant::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Extract the integer value if this is an `Int` constant.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            IrConstant::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Extract the float value if this is a `Float` constant.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            IrConstant::Float(f) => Some(*f),
            _ => None,
        }
    }
}

// ─── Operators ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IrOperator {
    Add,
    Sub,
    Mult,
    Div,
    FloorDiv,
    Mod,
    Pow,
    LShift,
    RShift,
    BitOr,
    BitXor,
    BitAnd,
    MatMult,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IrBoolOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IrUnaryOp {
    Not,
    USub,
    UAdd,
    Invert,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IrCmpOp {
    Eq,
    NotEq,
    Lt,
    LtE,
    Gt,
    GtE,
    Is,
    IsNot,
    In,
    NotIn,
}

// ─── Helper types ──────────────────────────────────────────────────────

/// A keyword argument in a function call: `name=value`.
#[derive(Debug, Clone, PartialEq)]
pub struct IrKeyword {
    /// `None` for `**kwargs` unpacking
    pub arg: Option<String>,
    pub value: IrExpr,
}

/// A `with` item: `context_expr as optional_vars`
#[derive(Debug, Clone, PartialEq)]
pub struct IrWithItem {
    pub context_expr: IrExpr,
    pub optional_vars: Option<IrExpr>,
}

/// An `except` handler clause.
#[derive(Debug, Clone, PartialEq)]
pub struct IrExceptHandler {
    /// The exception type (e.g. `ValueError`), or `None` for bare `except:`
    pub type_: Option<IrExpr>,
    /// The variable name to bind to, or `None` if not captured
    pub name: Option<String>,
    pub body: Vec<IrStmt>,
}

// ─── Display ──────────────────────────────────────────────────────────

impl fmt::Display for IrConstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrConstant::NoneValue => write!(f, "None"),
            IrConstant::Bool(b) => write!(f, "{b}"),
            IrConstant::Str(s) => write!(f, "\"{}\"", s.escape_default()),
            IrConstant::Int(n) => write!(f, "{n}"),
            IrConstant::Float(n) => write!(f, "{n}"),
            IrConstant::Ellipsis => write!(f, "..."),
        }
    }
}

// ─── Helpers for building common patterns ─────────────────────────────

impl IrExpr {
    /// Build `name(...)` expression.
    pub fn call(name: &str, args: Vec<IrExpr>) -> Self {
        IrExpr::Call {
            func: Box::new(IrExpr::Name(name.to_string())),
            args,
            keywords: vec![],
        }
    }

    /// Build `object.method(...)` expression.
    pub fn method_call(object: &str, method: &str, args: Vec<IrExpr>) -> Self {
        IrExpr::Call {
            func: Box::new(IrExpr::Attribute {
                value: Box::new(IrExpr::Name(object.to_string())),
                attr: method.to_string(),
            }),
            args,
            keywords: vec![],
        }
    }

    /// Build `a.b.c. ... .method(...)` chain.
    pub fn chain_call(parts: &[&str], args: Vec<IrExpr>) -> Self {
        if parts.is_empty() {
            return IrExpr::Name("".to_string());
        }
        let mut expr = IrExpr::Name(parts[0].to_string());
        for part in &parts[1..] {
            expr = IrExpr::Attribute {
                value: Box::new(expr),
                attr: part.to_string(),
            };
        }
        IrExpr::Call {
            func: Box::new(expr),
            args,
            keywords: vec![],
        }
    }

    /// Get the string value if this expression is a `Constant(Str(...))`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            IrExpr::Constant(IrConstant::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get the integer value if this expression is a `Constant(Int(...))`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            IrExpr::Constant(IrConstant::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// Try to resolve as a simple attribute chain: `a.b.c` → ["a", "b", "c"].
    /// Returns `None` if the expression is not a simple chain of names/attributes.
    pub fn resolve_attr_chain(&self) -> Option<Vec<String>> {
        match self {
            IrExpr::Name(n) => Some(vec![n.clone()]),
            IrExpr::Attribute { value, attr } => {
                let mut chain = value.resolve_attr_chain()?;
                chain.push(attr.clone());
                Some(chain)
            }
            _ => None,
        }
    }
}
