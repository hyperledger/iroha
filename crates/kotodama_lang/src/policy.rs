//! Compile-time enforcement for Kotodama's on-chain safety profile.
//!
//! The on-chain profile permits every scalar key with canonical Norito bytes and forbids aggregate,
//! optional, result, JSON, secret, and state-map keys. Runtime iteration orders the encoded key
//! bytes, so peers do not depend on host locale, hash iteration order, or numeric representation.
use super::semantic::{
    self, ExprKind, Type, TypedBlock, TypedExpr, TypedFunction, TypedItem, TypedProgram,
    TypedStatement,
};
use std::collections::HashSet;
/// Violation emitted when on-chain policy checks fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    /// Human-readable description of the violation.
    pub message: String,
}
/// Run the on-chain profile enforcement against a typed Kotodama program.
pub fn enforce_on_chain_profile(program: &TypedProgram) -> Result<(), Vec<PolicyError>> {
    crate::session::run_with_compiler_stack(move || enforce_on_chain_profile_inline(program))
        .unwrap_or_else(|_| {
            Err(vec![PolicyError {
                message: "compiler could not allocate the bounded stack required to enforce the on-chain profile"
                    .into(),
            }])
        })
}
fn enforce_on_chain_profile_inline(program: &TypedProgram) -> Result<(), Vec<PolicyError>> {
    let mut checker = Checker::default();
    checker.check_states(program);
    for item in &program.items {
        checker.visit_item(item);
    }
    if checker.errors.is_empty() {
        Ok(())
    } else {
        Err(checker.errors)
    }
}
#[derive(Default)]
struct Checker {
    errors: Vec<PolicyError>,
    /// Avoid emitting duplicate messages for the same origin/type combination.
    seen: HashSet<(String, String)>,
}
impl Checker {
    fn check_states(&mut self, program: &TypedProgram) {
        for state in &program.states {
            let origin = format!("state `{}`", state.name);
            self.visit_type(&state.ty, &origin);
        }
    }
    fn visit_item(&mut self, item: &TypedItem) {
        match item {
            TypedItem::Function(func) => self.visit_function(func),
        }
    }
    fn visit_function(&mut self, func: &TypedFunction) {
        for parameter in &func.param_types {
            let origin = format!("parameter `{}` of function `{}`", parameter.name, func.name);
            self.visit_type(&parameter.ty, &origin);
        }
        self.visit_block(&func.body, func.name.as_str());
        if let Some(ret_ty) = &func.ret_ty {
            let origin = format!("function `{}` return type", func.name);
            self.visit_type(ret_ty, &origin);
        }
    }
    fn visit_block(&mut self, block: &TypedBlock, func_name: &str) {
        for stmt in &block.statements {
            self.visit_statement(stmt, func_name);
        }
        if let Some(tail) = &block.tail {
            let origin = format!("tail expression in `{func_name}`");
            self.visit_expr(tail, &origin);
        }
    }
    fn visit_statement(&mut self, stmt: &TypedStatement, func_name: &str) {
        match stmt.kind() {
            TypedStatement::Let { name, value } => {
                let origin = format!("binding `{name}` in `{func_name}`");
                self.visit_expr(value, &origin);
            }
            TypedStatement::Expr(expr) => {
                let origin = format!("expression in `{func_name}`");
                self.visit_expr(expr, &origin);
            }
            TypedStatement::Return(Some(expr)) => {
                let origin = format!("return in `{func_name}`");
                self.visit_expr(expr, &origin);
            }
            TypedStatement::Return(None) | TypedStatement::Break | TypedStatement::Continue => {}
            TypedStatement::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let cond_origin = format!("condition in `{func_name}`");
                self.visit_expr(cond, &cond_origin);
                self.visit_block(then_branch, func_name);
                if let Some(b) = else_branch {
                    self.visit_block(b, func_name);
                }
            }
            TypedStatement::IfLet {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                let origin = format!("if let value in `{func_name}`");
                self.visit_expr(value, &origin);
                self.visit_block(then_branch, func_name);
                if let Some(block) = else_branch {
                    self.visit_block(block, func_name);
                }
            }
            TypedStatement::While { cond, body } => {
                let origin = format!("while condition in `{func_name}`");
                self.visit_expr(cond, &origin);
                self.visit_block(body, func_name);
            }
            TypedStatement::For {
                line: _,
                init,
                cond,
                step,
                body,
            } => {
                if let Some(init_stmt) = init.as_deref() {
                    self.visit_statement(init_stmt, func_name);
                }
                if let Some(cond_expr) = cond {
                    let origin = format!("for condition in `{func_name}`");
                    self.visit_expr(cond_expr, &origin);
                }
                if let Some(step_stmt) = step.as_deref() {
                    self.visit_statement(step_stmt, func_name);
                }
                self.visit_block(body, func_name);
            }
            TypedStatement::ForEachMap { map, body, .. } => {
                let origin = format!("map iteration in `{func_name}`");
                self.visit_expr(map, &origin);
                self.visit_block(body, func_name);
            }
            TypedStatement::MapSet { map, key, value } => {
                let origin = format!("map assignment in `{func_name}`");
                self.visit_expr(map, &origin);
                self.visit_expr(key, &origin);
                self.visit_expr(value, &origin);
            }
        }
    }
    fn visit_expr(&mut self, expr: &TypedExpr, origin: &str) {
        self.visit_type(&expr.ty, origin);
        match expr.kind() {
            ExprKind::Binary { left, right, .. } => {
                self.visit_expr(left, origin);
                self.visit_expr(right, origin);
            }
            ExprKind::Unary { expr: inner, .. }
            | ExprKind::NumericCast { expr: inner }
            | ExprKind::NumericTryCast { expr: inner }
            | ExprKind::OptionSome { value: inner }
            | ExprKind::ResultOk { value: inner }
            | ExprKind::ResultErr { error: inner }
            | ExprKind::Propagate { value: inner } => self.visit_expr(inner, origin),
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.visit_expr(cond, origin);
                self.visit_expr(then_expr, origin);
                self.visit_expr(else_expr, origin);
            }
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.visit_expr(condition, origin);
                self.visit_block(then_branch, origin);
                self.visit_block(else_branch, origin);
            }
            ExprKind::IfLet {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                self.visit_expr(value, origin);
                self.visit_block(then_branch, origin);
                self.visit_block(else_branch, origin);
            }
            ExprKind::Match { value, arms } => {
                self.visit_expr(value, origin);
                for arm in arms {
                    self.visit_block(&arm.body, origin);
                }
            }
            ExprKind::Call { args, .. }
            | ExprKind::NamedCall { args, .. }
            | ExprKind::Tuple(args)
            | ExprKind::List(args) => {
                for arg in args {
                    self.visit_expr(arg, origin);
                }
            }
            ExprKind::JsonObject(entries) => {
                for (_, value) in entries {
                    self.visit_expr(value, origin);
                }
            }
            ExprKind::JsonArray(elements) => {
                for element in elements {
                    self.visit_expr(element, origin);
                }
            }
            ExprKind::ListComprehension {
                expression,
                source,
                condition,
                ..
            } => {
                self.visit_expr(source, origin);
                self.visit_expr(expression, origin);
                if let Some(condition) = condition {
                    self.visit_expr(condition, origin);
                }
            }
            ExprKind::StructLiteral { fields, .. } => {
                for (_, value) in fields {
                    self.visit_expr(value, origin);
                }
            }
            ExprKind::Member { object, .. } => self.visit_expr(object, origin),
            ExprKind::Index { target, index } => {
                self.visit_expr(target, origin);
                self.visit_expr(index, origin);
            }
            ExprKind::VariantCode(_)
            | ExprKind::IntLiteral(_)
            | ExprKind::DecimalLiteral { .. }
            | ExprKind::OptionNone
            | ExprKind::Bool(_)
            | ExprKind::String(_)
            | ExprKind::Bytes(_)
            | ExprKind::Ident(_) => {}
        }
    }
    fn visit_type(&mut self, ty: &Type, origin: &str) {
        let resolved = semantic::resolve_struct_type(ty);
        match &resolved {
            Type::StateMap(key, value) => {
                self.check_map_key(origin, key, value);
                self.visit_type(key, origin);
                self.visit_type(value, origin);
            }
            Type::Secret(inner) | Type::Option(inner) | Type::List(inner, _) => {
                self.visit_type(inner, origin);
            }
            Type::Result(ok, error) => {
                self.visit_type(ok, origin);
                self.visit_type(error, origin);
            }
            Type::Tuple(elems) => {
                for elem in elems {
                    self.visit_type(elem, origin);
                }
            }
            Type::Struct { fields, .. } => {
                for (_name, field_ty) in fields.iter() {
                    self.visit_type(field_ty, origin);
                }
            }
            _ => {}
        }
    }
    fn check_map_key(&mut self, origin: &str, key: &Type, value: &Type) {
        if is_allowed_map_key_type(key) {
            return;
        }
        let key_name = display_type(key);
        let value_name = display_type(value);
        let map_desc = format!("StateMap<{key_name}, {value_name}>");
        if self.seen.insert((origin.to_string(), map_desc.clone())) {
            let message = format!(
                "on-chain profile forbids map with key type `{key_name}` in {origin}. Supported key types are int, decimal, quantity, bool, string, bytes, and typed Iroha IDs."
            );
            self.errors.push(PolicyError { message });
        }
    }
}
fn is_allowed_map_key_type(ty: &Type) -> bool {
    semantic::is_supported_durable_key_type(ty)
}
fn display_type(ty: &Type) -> String {
    match semantic::resolve_struct_type(ty) {
        Type::Int => "int".to_string(),
        Type::Decimal => "decimal".to_string(),
        Type::Quantity => "quantity".to_string(),
        Type::Bool => "bool".to_string(),
        Type::String => "string".to_string(),
        Type::Bytes => "bytes".to_string(),
        Type::AccountId => "AccountId".to_string(),
        Type::AssetDefinitionId => "AssetDefinitionId".to_string(),
        Type::AssetId => "AssetId".to_string(),
        Type::NftId => "NftId".to_string(),
        Type::DomainId => "DomainId".to_string(),
        Type::Name => "Name".to_string(),
        Type::DataSpaceId => "DataSpaceId".to_string(),
        Type::AxtDescriptor => "AxtDescriptor".to_string(),
        Type::AxtAnchoredSpendV1 => "AxtAnchoredSpendV1".to_string(),
        Type::ProofBlob => "ProofBlob".to_string(),
        Type::SoracloudRequest => "SoracloudRequest".to_string(),
        Type::SoracloudResponse => "SoracloudResponse".to_string(),
        Type::Json => "Json".to_string(),
        Type::Unit => "()".to_string(),
        Type::Enum(descriptor) => descriptor.identity.clone(),
        Type::ErrorEnum(descriptor) => descriptor.identity.clone(),
        Type::Secret(inner) => format!("Secret<{}>", display_type(&inner)),
        Type::StateMap(k, v) => format!("StateMap<{}, {}>", display_type(&k), display_type(&v)),
        Type::StateCursor(key) => format!("StateCursor<{}>", display_type(&key)),
        Type::Option(inner) => format!("Option<{}>", display_type(&inner)),
        Type::Result(ok, err) => format!("Result<{}, {}>", display_type(&ok), display_type(&err)),
        Type::List(element, capacity) => {
            format!("List<{}, {capacity}>", display_type(&element))
        }
        Type::Tuple(elems) => {
            let parts: Vec<String> = elems.iter().map(display_type).collect();
            format!("({})", parts.join(", "))
        }
        Type::Struct { name, .. } => format!("struct {name}"),
        Type::ContractRef(contract) => format!("contract {}", contract.interface.seiyaku_name),
        Type::NamedStruct(name) => name,
    }
}
#[cfg(test)]
mod tests {
    use super::{
        semantic::{ExprKind, Type, TypedExpr, TypedStatement},
        *,
    };
    use crate::parser::parse_test_fragment as parse;

    #[test]
    fn public_policy_check_handoffs_from_a_small_caller() {
        let depth = crate::source::MAX_NESTING_DEPTH - 2;
        let expression = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let source =
            format!("module StackMargin {{ fn value() {{ let nested = {expression}; }} }}");
        std::thread::Builder::new()
            .name("kotodama-small-policy-caller".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let program = crate::parser::parse(&source)
                    .expect("boundary-depth policy fixture must parse");
                let typed = semantic::analyze(&program)
                    .expect("boundary-depth policy fixture must type-check");
                enforce_on_chain_profile(&typed)
                    .expect("on-chain policy must use the bounded compiler worker");
                drop(typed);
                drop(program);
            })
            .expect("spawn small policy caller")
            .join()
            .expect("public policy checking must not consume the caller stack");
    }

    #[test]
    fn map_key_violation_reports_origin() {
        let mut checker = Checker::default();
        let stmt = TypedStatement::Expr(TypedExpr {
            expr: ExprKind::Ident("bad_map".into()),
            ty: Type::StateMap(Box::new(Type::Json), Box::new(Type::Int)),
        });
        checker.visit_statement(&stmt, "foo");
        let errors = checker.errors;
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].message,
            "on-chain profile forbids map with key type `Json` in expression in `foo`. Supported key types are int, decimal, quantity, bool, string, bytes, and typed Iroha IDs."
        );
    }
    #[test]
    fn every_canonical_scalar_map_key_is_allowed() {
        for ty in [
            Type::Int,
            Type::Decimal,
            Type::Quantity,
            Type::Bool,
            Type::String,
            Type::Bytes,
            Type::AccountId,
            Type::AssetDefinitionId,
            Type::AssetId,
            Type::NftId,
            Type::DomainId,
            Type::Name,
            Type::DataSpaceId,
        ] {
            assert!(is_allowed_map_key_type(&ty), "rejected {ty:?}");
        }
    }
    #[test]
    fn invalid_map_key_in_function_parameter_is_rejected() {
        for parameter_type in ["StateMap<Json, int>", "Option<StateMap<Json, int>>"] {
            let program = parse(&format!(
                "module Demo {{ fn consume({parameter_type} value) {{ return; }} }}"
            ))
            .expect("parse private map parameter");
            let typed =
                semantic::analyze(&program).expect("semantic analysis permits ephemeral maps");
            let errors = enforce_on_chain_profile(&typed)
                .expect_err("the on-chain profile must inspect nested parameter types");
            assert_eq!(errors.len(), 1);
            assert!(errors[0].message.contains("key type `Json`"));
            assert!(errors[0].message.contains("parameter `value`"));
        }
    }
    #[test]
    fn wrapped_map_types_are_checked_recursively() {
        let invalid_map = Type::StateMap(Box::new(Type::Json), Box::new(Type::Int));
        let wrapped = [
            Type::Secret(Box::new(invalid_map.clone())),
            Type::Option(Box::new(invalid_map.clone())),
            Type::Result(Box::new(Type::Int), Box::new(invalid_map.clone())),
            Type::List(Box::new(invalid_map), 1),
        ];
        for ty in wrapped {
            let mut checker = Checker::default();
            checker.visit_type(&ty, "wrapped test type");
            assert_eq!(checker.errors.len(), 1, "missed nested map in {ty:?}");
        }
    }
}
