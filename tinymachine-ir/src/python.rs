//! Python frontend — converts Python source code to [`IrProgram`].
//!
//! Uses [`rustpython_parser`] to parse Python source into its AST,
//! then converts it to the language-agnostic TinyMachine IR.

use crate::parser::{IrParseError, IrParser};
use crate::types::*;

use rustpython_parser::{self as rp, Parse};

/// Parser for Python source code.
pub struct PythonParser;

impl IrParser for PythonParser {
    fn parse(code: &str) -> Result<IrProgram, IrParseError> {
        let body = rp::ast::Suite::parse(code, "<tinyos>")
            .map_err(|e| IrParseError {
                message: format!("{e}"),
                language: "python".to_string(),
            })?;

        let body: Vec<IrStmt> = body
            .into_iter()
            .filter_map(convert_stmt)
            .collect();

        Ok(IrProgram { body })
    }
}

// ─── Statement converter ──────────────────────────────────────────────

fn convert_stmt(stmt: rp::ast::Stmt) -> Option<IrStmt> {
    use rp::ast::Stmt::*;
    match stmt {
        Import(import) => {
            import.names.into_iter().next().map(|alias| {
                IrStmt::Import {
                    module: alias.name.to_string(),
                    alias: alias.asname.map(|a| a.to_string()),
                }
            })
        }
        ImportFrom(import_from) => {
            let module = import_from
                .module
                .map(|m| m.to_string())
                .unwrap_or_default();
            import_from.names.into_iter().next().map(|alias| {
                IrStmt::ImportFrom {
                    module: module.clone(),
                    symbol: alias.name.to_string(),
                    alias: alias.asname.map(|a| a.to_string()),
                }
            })
        }
        Expr(expr_stmt) => {
            let expr = convert_expr(*expr_stmt.value)?;
            Some(IrStmt::Expr { expr })
        }
        Assign(assign) => {
            let targets: Vec<IrExpr> = assign
                .targets
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            if targets.is_empty() {
                return None;
            }
            let value = convert_expr(*assign.value)?;
            Some(IrStmt::Assign { targets, value })
        }
        AugAssign(aug) => {
            let target = convert_expr(*aug.target)?;
            let value = convert_expr(*aug.value)?;
            let op = convert_operator(aug.op);
            Some(IrStmt::AugAssign { target, op, value })
        }
        FunctionDef(func) => {
            let body: Vec<IrStmt> = func
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::FunctionDef {
                name: func.name.to_string(),
                body,
            })
        }
        AsyncFunctionDef(func) => {
            let body: Vec<IrStmt> = func
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::FunctionDef {
                name: func.name.to_string(),
                body,
            })
        }
        Return(ret) => {
            let value = ret.value.and_then(|v| convert_expr(*v));
            Some(IrStmt::Return { value })
        }
        Delete(del) => {
            let targets: Vec<IrExpr> = del
                .targets
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            if targets.is_empty() {
                return None;
            }
            Some(IrStmt::Delete { targets })
        }
        For(for_loop) => {
            let target = convert_expr(*for_loop.target)?;
            let iter = convert_expr(*for_loop.iter)?;
            let body: Vec<IrStmt> = for_loop
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::For { target, iter, body })
        }
        AsyncFor(for_loop) => {
            let target = convert_expr(*for_loop.target)?;
            let iter = convert_expr(*for_loop.iter)?;
            let body: Vec<IrStmt> = for_loop
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::For { target, iter, body })
        }
        While(while_loop) => {
            let test = convert_expr(*while_loop.test)?;
            let body: Vec<IrStmt> = while_loop
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::While { test, body })
        }
        If(if_stmt) => {
            let test = convert_expr(*if_stmt.test)?;
            let body: Vec<IrStmt> = if_stmt
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            let orelse: Vec<IrStmt> = if_stmt
                .orelse
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::If { test, body, orelse })
        }
        With(with) => {
            let items: Vec<IrWithItem> = with
                .items
                .into_iter()
                .filter_map(|item| {
                    let context_expr = convert_expr(item.context_expr)?;
                    let optional_vars = item
                        .optional_vars
                        .and_then(|v| convert_expr(*v));
                    Some(IrWithItem {
                        context_expr,
                        optional_vars,
                    })
                })
                .collect();
            let body: Vec<IrStmt> = with
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::With { items, body })
        }
        AsyncWith(with) => {
            let items: Vec<IrWithItem> = with
                .items
                .into_iter()
                .filter_map(|item| {
                    let context_expr = convert_expr(item.context_expr)?;
                    let optional_vars = item
                        .optional_vars
                        .and_then(|v| convert_expr(*v));
                    Some(IrWithItem {
                        context_expr,
                        optional_vars,
                    })
                })
                .collect();
            let body: Vec<IrStmt> = with
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::With { items, body })
        }
        Try(try_stmt) => {
            let body: Vec<IrStmt> = try_stmt
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            let handlers: Vec<IrExceptHandler> = try_stmt
                .handlers
                .into_iter()
                .filter_map(|h| {
                    use rp::ast::ExceptHandler as EH;
                    match h {
                        EH::ExceptHandler(inner) => {
                            let type_ = inner.type_.and_then(|t| convert_expr(*t));
                            let name = inner.name.map(|n: rp::ast::Identifier| n.to_string());
                            let body: Vec<IrStmt> = inner
                                .body
                                .into_iter()
                                .filter_map(convert_stmt)
                                .collect();
                            Some(IrExceptHandler { type_, name, body })
                        }
                    }
                })
                .collect();
            let orelse: Vec<IrStmt> = try_stmt
                .orelse
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            let finalbody: Vec<IrStmt> = try_stmt
                .finalbody
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::Try {
                body,
                handlers,
                orelse,
                finalbody,
            })
        }
        Raise(raise) => {
            let exc = raise.exc.and_then(|e| convert_expr(*e));
            Some(IrStmt::Raise { exc })
        }
        ClassDef(class) => {
            let body: Vec<IrStmt> = class
                .body
                .into_iter()
                .filter_map(convert_stmt)
                .collect();
            Some(IrStmt::ClassDef {
                name: class.name.to_string(),
                body,
            })
        }
        Assert(assert) => {
            let test = convert_expr(*assert.test)?;
            let msg = assert.msg.and_then(|m| convert_expr(*m));
            Some(IrStmt::Assert { test, msg })
        }
        Break(_) => Some(IrStmt::Break),
        Continue(_) => Some(IrStmt::Continue),
        Pass(_) => Some(IrStmt::Pass),
        // Nodes we don't care about
        _ => None,
    }
}

// ─── Expression converter ─────────────────────────────────────────────

fn convert_expr(expr: rp::ast::Expr) -> Option<IrExpr> {
    use rp::ast::Expr::*;
    match expr {
        BoolOp(bool_op) => {
            let op = convert_bool_op(bool_op.op);
            let values: Vec<IrExpr> = bool_op
                .values
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            Some(IrExpr::BoolOp { op, values })
        }
        BinOp(bin_op) => {
            let left = convert_expr(*bin_op.left)?;
            let right = convert_expr(*bin_op.right)?;
            let op = convert_operator(bin_op.op);
            Some(IrExpr::BinOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            })
        }
        UnaryOp(unary) => {
            let operand = convert_expr(*unary.operand)?;
            let op = convert_unary_op(unary.op);
            Some(IrExpr::UnaryOp {
                op,
                operand: Box::new(operand),
            })
        }
        Constant(constant) => {
            let c = convert_constant(constant.value)?;
            Some(IrExpr::Constant(c))
        }
        Attribute(attr) => {
            let value = convert_expr(*attr.value)?;
            Some(IrExpr::Attribute {
                value: Box::new(value),
                attr: attr.attr.to_string(),
            })
        }
        Subscript(sub) => {
            let value = convert_expr(*sub.value)?;
            let slice = convert_expr(*sub.slice)?;
            Some(IrExpr::Subscript {
                value: Box::new(value),
                slice: Box::new(slice),
            })
        }
        Starred(starred) => {
            let value = convert_expr(*starred.value)?;
            Some(IrExpr::Starred {
                value: Box::new(value),
            })
        }
        Name(name) => Some(IrExpr::Name(name.id.to_string())),
        List(list) => {
            let elts: Vec<IrExpr> = list
                .elts
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            Some(IrExpr::List(elts))
        }
        Tuple(tuple) => {
            let elts: Vec<IrExpr> = tuple
                .elts
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            Some(IrExpr::Tuple(elts))
        }
        Dict(dict) => {
            let keys: Vec<IrExpr> = dict
                .keys
                .into_iter()
                .filter_map(|k| k.and_then(convert_expr))
                .collect();
            let values: Vec<IrExpr> = dict
                .values
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            Some(IrExpr::Dict { keys, values })
        }
        Set(set) => {
            let elts: Vec<IrExpr> = set
                .elts
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            Some(IrExpr::Set(elts))
        }
        Call(call) => {
            let func = convert_expr(*call.func)?;
            let args: Vec<IrExpr> = call
                .args
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            let keywords: Vec<IrKeyword> = call
                .keywords
                .into_iter()
                .filter_map(|kw| {
                    let value = convert_expr(kw.value)?;
                    Some(IrKeyword {
                        arg: kw.arg.map(|a| a.to_string()),
                        value,
                    })
                })
                .collect();
            Some(IrExpr::Call {
                func: Box::new(func),
                args,
                keywords,
            })
        }
        IfExp(if_exp) => {
            let test = convert_expr(*if_exp.test)?;
            let body = convert_expr(*if_exp.body)?;
            let orelse = convert_expr(*if_exp.orelse)?;
            Some(IrExpr::IfExp {
                test: Box::new(test),
                body: Box::new(body),
                orelse: Box::new(orelse),
            })
        }
        Lambda(lambda) => {
            let args: Vec<String> = lambda
                .args
                .args
                .iter()
                .map(|a| a.def.arg.to_string())
                .collect();
            let body = convert_expr(*lambda.body)?;
            Some(IrExpr::Lambda {
                args,
                body: Box::new(body),
            })
        }
        Compare(compare) => {
            let left = convert_expr(*compare.left)?;
            let ops: Vec<IrCmpOp> = compare.ops.into_iter().map(convert_cmp_op).collect();
            let comparators: Vec<IrExpr> = compare
                .comparators
                .into_iter()
                .filter_map(convert_expr)
                .collect();
            Some(IrExpr::Compare {
                left: Box::new(left),
                ops,
                comparators,
            })
        }
        _ => None,
    }
}

// ─── Constant converter ───────────────────────────────────────────────

fn convert_constant(val: rp::ast::Constant) -> Option<IrConstant> {
    match val {
        rp::ast::Constant::None => Some(IrConstant::NoneValue),
        rp::ast::Constant::Bool(b) => Some(IrConstant::Bool(b)),
        rp::ast::Constant::Str(s) => Some(IrConstant::Str(s)),
        rp::ast::Constant::Int(bigint) => {
            let n = i64::try_from(bigint).unwrap_or(0);
            Some(IrConstant::Int(n))
        }
        rp::ast::Constant::Float(f) => Some(IrConstant::Float(f)),
        rp::ast::Constant::Ellipsis => Some(IrConstant::Ellipsis),
        _ => None,
    }
}

// ─── Operator converters ──────────────────────────────────────────────

fn convert_operator(op: rp::ast::Operator) -> IrOperator {
    use rp::ast::Operator::*;
    match op {
        Add => IrOperator::Add,
        Sub => IrOperator::Sub,
        Mult => IrOperator::Mult,
        Div => IrOperator::Div,
        FloorDiv => IrOperator::FloorDiv,
        Mod => IrOperator::Mod,
        Pow => IrOperator::Pow,
        LShift => IrOperator::LShift,
        RShift => IrOperator::RShift,
        BitOr => IrOperator::BitOr,
        BitXor => IrOperator::BitXor,
        BitAnd => IrOperator::BitAnd,
        MatMult => IrOperator::MatMult,
    }
}

fn convert_bool_op(op: rp::ast::BoolOp) -> IrBoolOp {
    match op {
        rp::ast::BoolOp::And => IrBoolOp::And,
        rp::ast::BoolOp::Or => IrBoolOp::Or,
    }
}

fn convert_unary_op(op: rp::ast::UnaryOp) -> IrUnaryOp {
    use rp::ast::UnaryOp::*;
    match op {
        Not => IrUnaryOp::Not,
        USub => IrUnaryOp::USub,
        UAdd => IrUnaryOp::UAdd,
        Invert => IrUnaryOp::Invert,
    }
}

fn convert_cmp_op(op: rp::ast::CmpOp) -> IrCmpOp {
    match op {
        rp::ast::CmpOp::Eq => IrCmpOp::Eq,
        rp::ast::CmpOp::NotEq => IrCmpOp::NotEq,
        rp::ast::CmpOp::Lt => IrCmpOp::Lt,
        rp::ast::CmpOp::LtE => IrCmpOp::LtE,
        rp::ast::CmpOp::Gt => IrCmpOp::Gt,
        rp::ast::CmpOp::GtE => IrCmpOp::GtE,
        rp::ast::CmpOp::Is => IrCmpOp::Is,
        rp::ast::CmpOp::IsNot => IrCmpOp::IsNot,
        rp::ast::CmpOp::In => IrCmpOp::In,
        rp::ast::CmpOp::NotIn => IrCmpOp::NotIn,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IrVisitor;

    #[test]
    fn test_parse_empty() {
        let program = PythonParser::parse("").unwrap();
        assert!(program.body.is_empty());
    }

    #[test]
    fn test_parse_import() {
        let program = PythonParser::parse("import numpy").unwrap();
        assert_eq!(program.body.len(), 1);
        assert!(matches!(
            program.body[0],
            IrStmt::Import { ref module, alias: None } if module == "numpy"
        ));
    }

    #[test]
    fn test_parse_import_as() {
        let program = PythonParser::parse("import numpy as np").unwrap();
        assert!(matches!(
            program.body[0],
            IrStmt::Import { ref module, ref alias }
                if module == "numpy" && alias.as_deref() == Some("np")
        ));
    }

    #[test]
    fn test_parse_from_import() {
        let program = PythonParser::parse("from torch import nn").unwrap();
        assert!(matches!(
            program.body[0],
            IrStmt::ImportFrom { ref module, ref symbol, alias: None }
                if module == "torch" && symbol == "nn"
        ));
    }

    #[test]
    fn test_parse_syntax_error() {
        let result = PythonParser::parse("x = ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_call_detection() {
        let program = PythonParser::parse("requests.get('https://example.com')").unwrap();
        assert_eq!(program.body.len(), 1);
        assert!(matches!(program.body[0], IrStmt::Expr { .. }));
    }

    #[test]
    fn test_walk_visits_all_nodes() {
        struct TestVisitor {
            imports: Vec<String>,
            calls: Vec<String>,
        }

        impl IrVisitor for TestVisitor {
            fn visit_import(&mut self, module: &str, _alias: Option<&str>) {
                self.imports.push(module.to_string());
            }
            fn visit_import_from(&mut self, module: &str, _symbol: &str, _alias: Option<&str>) {
                self.imports.push(module.to_string());
            }
            fn visit_call(&mut self, func: &IrExpr, _args: &[IrExpr]) {
                if let Some(chain) = func.resolve_attr_chain() {
                    self.calls.push(chain.join("."));
                }
            }
        }

        let code = "\
import numpy as np
import torch
from flask import Flask

app = Flask(__name__)
x = np.ones((3, 3))
result = requests.get('https://example.com')
";

        let program = PythonParser::parse(code).unwrap();
        let mut v = TestVisitor {
            imports: vec![],
            calls: vec![],
        };
        v.walk_program(&program);

        assert_eq!(v.imports.len(), 3);
        assert!(v.imports.contains(&"numpy".to_string()));
        assert!(v.imports.contains(&"torch".to_string()));
        assert!(v.imports.contains(&"flask".to_string()));
        assert!(v.calls.contains(&"Flask".to_string()));
        assert!(v.calls.contains(&"np.ones".to_string()));
        assert!(v.calls.contains(&"requests.get".to_string()));
    }

    #[test]
    fn test_extract_url_from_call() {
        let code = "requests.get('https://api.example.com/v1/status')";
        let program = PythonParser::parse(code).unwrap();

        struct UrlFinder {
            urls: Vec<String>,
        }

        impl IrVisitor for UrlFinder {
            fn visit_call(&mut self, func: &IrExpr, args: &[IrExpr]) {
                if let Some(chain) = func.resolve_attr_chain() {
                    if chain == ["requests", "get"] || chain == ["requests", "post"] {
                        for arg in args {
                            if let Some(s) = arg.as_str() {
                                if s.starts_with("http://") || s.starts_with("https://") {
                                    self.urls.push(s.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut v = UrlFinder { urls: vec![] };
        v.walk_program(&program);
        assert_eq!(v.urls.len(), 1);
        assert!(v.urls[0].contains("api.example.com"));
    }

    #[test]
    fn test_no_false_positive_in_string() {
        // String-matching would catch "import numpy" inside this string.
        // AST should NOT.
        let code = "code = \"import numpy\"";
        let program = PythonParser::parse(code).unwrap();

        struct ImportFinder {
            imports: Vec<String>,
        }

        impl IrVisitor for ImportFinder {
            fn visit_import(&mut self, module: &str, _alias: Option<&str>) {
                self.imports.push(module.to_string());
            }
        }

        let mut v = ImportFinder { imports: vec![] };
        v.walk_program(&program);
        assert!(
            v.imports.is_empty(),
            "AST should not detect import inside string literal"
        );
    }
}
