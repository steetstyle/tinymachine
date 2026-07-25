//! Default recursive walker (Visitor pattern).
//!
//! [`IrVisitor`] provides a default no-op walk over all nodes.
//! Implement only the `visit_*` methods you care about; the rest
//! are automatically called during `walk_program()`.

use crate::types::*;

/// A visitor that walks the entire IR tree.
///
/// # Default behavior
///
/// All `visit_*` methods are no-ops by default.
/// The `walk_*` methods recursively visit child nodes.
/// Override `visit_*` to inspect specific node types,
/// and override `walk_*` to change traversal order.
///
/// # Example
///
/// ```ignore
/// use tinymachine_ir::*;
///
/// struct ImportCounter { count: usize }
///
/// impl IrVisitor for ImportCounter {
///     fn visit_import(&mut self, module: &str, alias: Option<&str>) {
///         self.count += 1;
///     }
/// }
/// ```
pub trait IrVisitor {
    // ── Statement visitors ───────────────────────────────────────────

    /// Called for every statement node.
    fn visit_stmt(&mut self, _stmt: &IrStmt) {}

    /// Called for `import module` or `import module as alias`.
    fn visit_import(&mut self, _module: &str, _alias: Option<&str>) {}

    /// Called for `from module import symbol` or `from module import symbol as alias`.
    fn visit_import_from(&mut self, _module: &str, _symbol: &str, _alias: Option<&str>) {}

    /// Called for expression statements: `foo()`, `1 + 1`, etc.
    fn visit_expr_stmt(&mut self, _expr: &IrExpr) {}

    /// Called for assignments: `target = value`.
    fn visit_assign(&mut self, _targets: &[IrExpr], _value: &IrExpr) {}

    /// Called for function definitions.
    fn visit_function_def(&mut self, _name: &str) {}

    /// Called for `return value` statements.
    fn visit_return(&mut self, _value: Option<&IrExpr>) {}

    /// Called for `delete` statements.
    fn visit_delete(&mut self, _targets: &[IrExpr]) {}

    /// Called for `for` loops.
    fn visit_for(&mut self, _target: &IrExpr, _iter: &IrExpr) {}

    /// Called for `while` loops.
    fn visit_while(&mut self, _test: &IrExpr) {}

    /// Called for `class` definitions.
    fn visit_class_def(&mut self, _name: &str) {}

    /// Called for `raise` statements.
    fn visit_raise(&mut self, _exc: Option<&IrExpr>) {}

    /// Called for `assert` statements.
    fn visit_assert(&mut self, _test: &IrExpr, _msg: Option<&IrExpr>) {}

    /// Called for `break` statements.
    fn visit_break(&mut self) {}

    /// Called for `continue` statements.
    fn visit_continue(&mut self) {}

    /// Called for `pass` statements.
    fn visit_pass(&mut self) {}

    // ── Expression visitors ──────────────────────────────────────────

    /// Called for every expression node.
    fn visit_expr(&mut self, _expr: &IrExpr) {}

    /// Called for all literal constants.
    fn visit_constant(&mut self, _c: &IrConstant) {}

    /// Called for string literals specifically.
    fn visit_str(&mut self, _s: &str) {}

    /// Called for integer literals.
    fn visit_int(&mut self, _n: i64) {}

    /// Called for calls: `func(args)`.
    fn visit_call(&mut self, _func: &IrExpr, _args: &[IrExpr]) {}

    /// Called for attribute access: `obj.attr`.
    fn visit_attribute(&mut self, _value: &IrExpr, _attr: &str) {}

    /// Called for subscript: `obj[key]`.
    fn visit_subscript(&mut self, _value: &IrExpr, _slice: &IrExpr) {}

    /// Called for simple variable names.
    fn visit_name(&mut self, _id: &str) {}

    /// Called for binary operations: `a + b`.
    fn visit_binop(&mut self, _left: &IrExpr, _op: IrOperator, _right: &IrExpr) {}

    /// Called for unary operations: `-a`, `not a`.
    fn visit_unaryop(&mut self, _op: IrUnaryOp, _operand: &IrExpr) {}

    // ── Walk methods (override to change traversal) ──────────────────

    /// Walk an entire program (list of statements).
    fn walk_program(&mut self, program: &IrProgram) {
        self.walk_stmts(&program.body);
    }

    /// Walk a list of statements.
    fn walk_stmts(&mut self, stmts: &[IrStmt]) {
        for stmt in stmts {
            self.walk_stmt(stmt);
        }
    }

    /// Walk a single statement, dispatching to specific visit_* methods.
    fn walk_stmt(&mut self, stmt: &IrStmt) {
        self.visit_stmt(stmt);
        match stmt {
            IrStmt::Import { module, alias } => {
                self.visit_import(module, alias.as_deref());
            }
            IrStmt::ImportFrom { module, symbol, alias } => {
                self.visit_import_from(module, symbol, alias.as_deref());
            }
            IrStmt::Expr { expr } => {
                self.visit_expr_stmt(expr);
                self.walk_expr(expr);
            }
            IrStmt::Assign { targets, value } => {
                self.visit_assign(targets, value);
                for t in targets {
                    self.walk_expr(t);
                }
                self.walk_expr(value);
            }
            IrStmt::AugAssign { target, value, .. } => {
                self.walk_expr(target);
                self.walk_expr(value);
            }
            IrStmt::FunctionDef { name, body } => {
                self.visit_function_def(name);
                self.walk_stmts(body);
            }
            IrStmt::Return { value } => {
                self.visit_return(value.as_ref());
                if let Some(v) = value {
                    self.walk_expr(v);
                }
            }
            IrStmt::Delete { targets } => {
                self.visit_delete(targets);
                for t in targets {
                    self.walk_expr(t);
                }
            }
            IrStmt::For { target, iter, body } => {
                self.visit_for(target, iter);
                self.walk_expr(target);
                self.walk_expr(iter);
                self.walk_stmts(body);
            }
            IrStmt::While { test, body } => {
                self.visit_while(test);
                self.walk_expr(test);
                self.walk_stmts(body);
            }
            IrStmt::If { test, body, orelse } => {
                self.walk_expr(test);
                self.walk_stmts(body);
                self.walk_stmts(orelse);
            }
            IrStmt::With { items, body } => {
                for item in items {
                    self.walk_expr(&item.context_expr);
                    if let Some(ref v) = item.optional_vars {
                        self.walk_expr(v);
                    }
                }
                self.walk_stmts(body);
            }
            IrStmt::Try { body, handlers, orelse, finalbody } => {
                self.walk_stmts(body);
                for handler in handlers {
                    if let Some(ref t) = handler.type_ {
                        self.walk_expr(t);
                    }
                    self.walk_stmts(&handler.body);
                }
                self.walk_stmts(orelse);
                self.walk_stmts(finalbody);
            }
            IrStmt::Raise { exc } => {
                self.visit_raise(exc.as_ref());
                if let Some(ref e) = exc {
                    self.walk_expr(e);
                }
            }
            IrStmt::ClassDef { name, body } => {
                self.visit_class_def(name);
                self.walk_stmts(body);
            }
            IrStmt::Assert { test, msg } => {
                self.visit_assert(test, msg.as_ref());
                self.walk_expr(test);
                if let Some(ref m) = msg {
                    self.walk_expr(m);
                }
            }
            IrStmt::Break => self.visit_break(),
            IrStmt::Continue => self.visit_continue(),
            IrStmt::Pass => self.visit_pass(),
        }
    }

    /// Walk a single expression, dispatching to specific visit_* methods.
    fn walk_expr(&mut self, expr: &IrExpr) {
        self.visit_expr(expr);
        match expr {
            IrExpr::BoolOp { values, .. } => {
                for v in values {
                    self.walk_expr(v);
                }
            }
            IrExpr::BinOp { left, right, .. } => {
                self.visit_binop(left, IrOperator::Add, right);
                self.walk_expr(left);
                self.walk_expr(right);
            }
            IrExpr::UnaryOp { op, operand } => {
                self.visit_unaryop(*op, operand);
                self.walk_expr(operand);
            }
            IrExpr::Constant(c) => {
                self.visit_constant(c);
                if let IrConstant::Str(s) = c {
                    self.visit_str(s);
                }
                if let IrConstant::Int(n) = c {
                    self.visit_int(*n);
                }
            }
            IrExpr::Attribute { value, attr } => {
                self.visit_attribute(value, attr);
                self.walk_expr(value);
            }
            IrExpr::Subscript { value, slice } => {
                self.visit_subscript(value, slice);
                self.walk_expr(value);
                self.walk_expr(slice);
            }
            IrExpr::Starred { value } => {
                self.walk_expr(value);
            }
            IrExpr::Name(id) => {
                self.visit_name(id);
            }
            IrExpr::List(elts) | IrExpr::Tuple(elts) | IrExpr::Set(elts) => {
                for e in elts {
                    self.walk_expr(e);
                }
            }
            IrExpr::Dict { keys, values } => {
                for k in keys {
                    self.walk_expr(k);
                }
                for v in values {
                    self.walk_expr(v);
                }
            }
            IrExpr::Call { func, args, .. } => {
                self.visit_call(func, args);
                self.walk_expr(func);
                for arg in args {
                    self.walk_expr(arg);
                }
            }
            IrExpr::IfExp { test, body, orelse } => {
                self.walk_expr(test);
                self.walk_expr(body);
                self.walk_expr(orelse);
            }
            IrExpr::Lambda { args: _, body } => {
                self.walk_expr(body);
            }
            IrExpr::Compare { left, comparators, .. } => {
                self.walk_expr(left);
                for c in comparators {
                    self.walk_expr(c);
                }
            }
        }
    }
}
