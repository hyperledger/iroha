//! Static confidentiality policy for Kotodama zero-knowledge contracts.
//!
//! `Secret<T>` is a nominal type: ordinary operations never unwrap it.  The
//! only expressions that may consume a secret are the small, explicit set of
//! cryptographic declassifiers below.  This module also performs a final walk
//! over typed programs so future type-checker changes cannot accidentally turn
//! a rejected secret flow into an accepted one.
use crate::{
    ast::FunctionKind,
    semantic::{
        ExprKind, SemanticError, Type, TypedBlock, TypedExpr, TypedFunction, TypedItem,
        TypedProgram, TypedStatement,
    },
};
use kotodama_surface::builtins::{Builtin, BuiltinAccess};
use std::collections::HashSet;
fn error(code: &'static str, message: impl Into<String>) -> SemanticError {
    SemanticError {
        code,
        message: message.into(),
    }
}
/// Return whether a type contains confidential data, including through a
/// tuple, list, map, or user-defined product type.
pub(crate) fn type_contains_secret(ty: &Type) -> bool {
    match ty {
        Type::Secret(_) => true,
        Type::StateMap(key, value) => type_contains_secret(key) || type_contains_secret(value),
        Type::Option(inner) | Type::List(inner, _) => type_contains_secret(inner),
        Type::Result(ok, err) => type_contains_secret(ok) || type_contains_secret(err),
        Type::Tuple(items) => items.iter().any(type_contains_secret),
        Type::Struct { fields, .. } => fields
            .iter()
            .any(|(_, field_ty)| type_contains_secret(field_ty)),
        _ => false,
    }
}
/// Return whether this is one of the exact V1 private-input representations.
pub(crate) fn is_secret_numeric(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Secret(inner)
            if matches!(inner.as_ref(), Type::Int | Type::Decimal | Type::Quantity)
    )
}
/// Reject a secret-dependent branch, assertion, or loop condition.
pub(crate) fn reject_secret_control_flow(expr: &TypedExpr) -> Result<(), SemanticError> {
    if expression_contains_secret(expr) {
        return Err(error(
            "E_SECRET_CONTROL_FLOW",
            "Secret<T> cannot influence control flow; commit or prove the private predicate instead",
        ));
    }
    Ok(())
}
/// Reject ordinary arithmetic, comparison, equality, or casts on secrets.
pub(crate) fn reject_secret_ordinary_operation(
    operands: &[&TypedExpr],
) -> Result<(), SemanticError> {
    if operands.iter().any(|expr| expression_contains_secret(expr)) {
        return Err(error(
            "E_SECRET_ARITHMETIC",
            "ordinary arithmetic and comparisons cannot consume Secret<T>; use an approved proof or commitment operation",
        ));
    }
    Ok(())
}
/// Reject secret-derived map and durable-state keys.
pub(crate) fn reject_secret_key(expr: &TypedExpr) -> Result<(), SemanticError> {
    if expression_contains_secret(expr) {
        return Err(error(
            "E_SECRET_STATE_KEY",
            "Secret<T> cannot be used as a map, durable-state, or host lookup key",
        ));
    }
    Ok(())
}
/// Reject a secret-derived durable-state value before ordinary assignability
/// diagnostics can hide the security-relevant reason.
pub(crate) fn reject_secret_state_value(expr: &TypedExpr) -> Result<(), SemanticError> {
    if expression_contains_secret(expr) {
        return Err(error(
            "E_SECRET_STATE_WRITE",
            "Secret<T> cannot be persisted in seiyaku state",
        ));
    }
    Ok(())
}
/// Check secret arguments before a builtin's ordinary signature validation.
///
/// The accepted declassifiers deliberately require all scalar operands to be
/// secret.  Besides matching the VM's equal-tag rule, this prevents an
/// accidentally public salt or blinding factor from making a commitment easy
/// to brute force. The V1 source commitment surface is Secret-only.
pub(crate) fn validate_builtin_call(
    builtin: Builtin,
    args: &[TypedExpr],
) -> Result<(), SemanticError> {
    let secret_args = args
        .iter()
        .filter(|arg| type_contains_secret(&arg.ty))
        .count();
    if secret_args == 0 {
        return Ok(());
    }
    match builtin {
        Builtin::Valcom => {
            if args.iter().all(|arg| is_secret_numeric(&arg.ty)) {
                return Ok(());
            }
            Err(error(
                "E_SECRET_MIXED_COMMITMENT",
                format!(
                    "`{}` cannot mix public and secret operands; use secret blinding/domain inputs or commit public data separately",
                    builtin.source_name()
                ),
            ))
        }
        Builtin::Poseidon2 | Builtin::Poseidon6 | Builtin::Pubkgen => Err(error(
            "E_SECRET_FULL_WIDTH_CRYPTO_REQUIRED",
            format!(
                "`{}` has only a scalar-register implementation and cannot consume Secret<T>; use `crypto::valcom` until a full-width proof representation is available",
                builtin.source_name()
            ),
        )),
        Builtin::DebugPrint | Builtin::DebugLog | Builtin::Info => Err(error(
            "E_SECRET_LOG",
            format!("Secret<T> cannot be passed to `{}`", builtin.source_name()),
        )),
        Builtin::Assert | Builtin::Require => Err(error(
            "E_SECRET_CONTROL_FLOW",
            format!("Secret<T> cannot influence `{}`", builtin.source_name()),
        )),
        Builtin::AssertEq => Err(error(
            "E_SECRET_ARITHMETIC",
            "ordinary equality cannot consume Secret<T>; prove or commit the private predicate instead",
        )),
        Builtin::StateGet
        | Builtin::StateSet
        | Builtin::StateDel
        | Builtin::StateHas
        | Builtin::StateLen
        | Builtin::StateCount
        | Builtin::Contains
        | Builtin::GetOrInsert
        | Builtin::StateMapRemove
        | Builtin::KeysTake2
        | Builtin::ValuesTake2
        | Builtin::KeysValuesTake2 => Err(error(
            "E_SECRET_STATE_SINK",
            format!(
                "Secret<T> cannot be passed to state operation `{}`",
                builtin.source_name()
            ),
        )),
        Builtin::GetPrivateInput => Err(error(
            "E_SECRET_PRIVATE_INPUT_INDEX",
            "the private-input index must be public",
        )),
        other => {
            let spec = other.spec();
            let effects = spec.effects;
            let host_visible = effects.host_side_effects
                || effects.emits_instructions
                || effects.mutates_durable_state
                || !matches!(spec.access, BuiltinAccess::None);
            if host_visible {
                Err(error(
                    "E_SECRET_HOST_SINK",
                    format!(
                        "Secret<T> cannot be passed to host, ledger, query, or state operation `{}`",
                        other.name()
                    ),
                ))
            } else {
                Err(error(
                    "E_SECRET_UNAPPROVED_OPERATION",
                    format!(
                        "`{}` is not approved to consume Secret<T>; use crypto::valcom",
                        other.source_name()
                    ),
                ))
            }
        }
    }
}
/// Apply the defense-in-depth secret-flow validation pass to a typed program.
pub(crate) fn validate_program(
    program: &TypedProgram,
    zk_enabled: bool,
) -> Result<(), SemanticError> {
    let functions = program
        .items
        .iter()
        .map(|item| match item {
            TypedItem::Function(function) => function.name.clone(),
        })
        .collect::<HashSet<_>>();
    let uses_secret = program
        .states
        .iter()
        .any(|state| type_contains_secret(&state.ty))
        || program.items.iter().any(|item| match item {
            TypedItem::Function(function) => function_contains_secret(function),
        });
    if uses_secret && !zk_enabled {
        return Err(error(
            "E_SECRET_REQUIRES_ZK",
            "Secret<T> is available only when compiler build configuration enables ZK mode",
        ));
    }
    for state in &program.states {
        if type_contains_secret(&state.ty) {
            return Err(error(
                "E_SECRET_STATE_TYPE",
                format!(
                    "state `{}` cannot contain Secret<T>; private inputs are execution-local",
                    state.name
                ),
            ));
        }
    }
    for item in &program.items {
        match item {
            TypedItem::Function(function) => validate_function(function, &functions)?,
        }
    }
    Ok(())
}
fn is_runtime_entrypoint(function: &TypedFunction) -> bool {
    !matches!(function.modifiers.kind, FunctionKind::Private)
}
fn validate_function(
    function: &TypedFunction,
    functions: &HashSet<String>,
) -> Result<(), SemanticError> {
    let public = is_runtime_entrypoint(function);
    if public
        && let Some(param) = function
            .param_types
            .iter()
            .find(|param| type_contains_secret(&param.ty))
    {
        return Err(error(
            "E_SECRET_PUBLIC_PARAMETER",
            format!(
                "externally callable `{}` cannot accept secret parameter `{}`; obtain private inputs with `crypto::private_input`",
                function.name, param.name
            ),
        ));
    }
    if public && function.ret_ty.as_ref().is_some_and(type_contains_secret) {
        return Err(error(
            "E_SECRET_PUBLIC_RETURN",
            format!(
                "externally callable `{}` cannot return Secret<T>; return an approved commitment or proof result",
                function.name
            ),
        ));
    }
    validate_block(&function.body, public, functions)
}
fn validate_block(
    block: &TypedBlock,
    public_return: bool,
    functions: &HashSet<String>,
) -> Result<(), SemanticError> {
    for statement in &block.statements {
        validate_statement(statement, public_return, functions)?;
    }
    if let Some(tail) = &block.tail {
        validate_expr(tail, functions)?;
        if public_return && type_contains_secret(&tail.ty) {
            return Err(error(
                "E_SECRET_PUBLIC_RETURN",
                "a public tail expression cannot return Secret<T>; return an approved commitment or proof result",
            ));
        }
    }
    Ok(())
}
fn validate_statement(
    statement: &TypedStatement,
    public_return: bool,
    functions: &HashSet<String>,
) -> Result<(), SemanticError> {
    match statement.kind() {
        TypedStatement::Let { value, .. } | TypedStatement::Expr(value) => {
            validate_expr(value, functions)
        }
        TypedStatement::Return(Some(value)) => {
            validate_expr(value, functions)?;
            if public_return && type_contains_secret(&value.ty) {
                return Err(error(
                    "E_SECRET_PUBLIC_RETURN",
                    "a kotoage/view/hajimari/kaizen declaration cannot return Secret<T>; return an approved commitment or proof result",
                ));
            }
            Ok(())
        }
        TypedStatement::Return(None) | TypedStatement::Break | TypedStatement::Continue => Ok(()),
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            reject_secret_control_flow(cond)?;
            validate_expr(cond, functions)?;
            validate_block(then_branch, public_return, functions)?;
            if let Some(branch) = else_branch {
                validate_block(branch, public_return, functions)?;
            }
            Ok(())
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            reject_secret_control_flow(value)?;
            validate_expr(value, functions)?;
            validate_block(then_branch, public_return, functions)?;
            if let Some(branch) = else_branch {
                validate_block(branch, public_return, functions)?;
            }
            Ok(())
        }
        TypedStatement::While { cond, body } => {
            reject_secret_control_flow(cond)?;
            validate_expr(cond, functions)?;
            validate_block(body, public_return, functions)
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init) = init.as_deref() {
                validate_statement(init, public_return, functions)?;
            }
            if let Some(cond) = cond {
                reject_secret_control_flow(cond)?;
                validate_expr(cond, functions)?;
            }
            if let Some(step) = step.as_deref() {
                validate_statement(step, public_return, functions)?;
            }
            validate_block(body, public_return, functions)
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            if type_contains_secret(&map.ty) {
                return Err(error(
                    "E_SECRET_CONTROL_FLOW",
                    "Secret<T> cannot determine map iteration",
                ));
            }
            validate_expr(map, functions)?;
            validate_block(body, public_return, functions)
        }
        TypedStatement::MapSet { map, key, value } => {
            validate_expr(map, functions)?;
            reject_secret_key(key)?;
            validate_expr(key, functions)?;
            reject_secret_state_value(value)?;
            validate_expr(value, functions)
        }
    }
}
fn validate_expr(expr: &TypedExpr, functions: &HashSet<String>) -> Result<(), SemanticError> {
    match expr.kind() {
        ExprKind::Binary { left, right, .. } => {
            reject_secret_ordinary_operation(&[left, right])?;
            validate_expr(left, functions)?;
            validate_expr(right, functions)
        }
        ExprKind::Unary { expr: inner, .. }
        | ExprKind::NumericCast { expr: inner }
        | ExprKind::NumericTryCast { expr: inner } => {
            reject_secret_ordinary_operation(&[inner])?;
            validate_expr(inner, functions)
        }
        ExprKind::OptionSome { value }
        | ExprKind::ResultOk { value }
        | ExprKind::ResultErr { error: value } => validate_expr(value, functions),
        ExprKind::Propagate { value } => {
            reject_secret_control_flow(value)?;
            validate_expr(value, functions)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            reject_secret_control_flow(cond)?;
            validate_expr(cond, functions)?;
            validate_expr(then_expr, functions)?;
            validate_expr(else_expr, functions)
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            reject_secret_control_flow(condition)?;
            validate_expr(condition, functions)?;
            validate_block(then_branch, false, functions)?;
            validate_block(else_branch, false, functions)
        }
        ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            reject_secret_control_flow(value)?;
            validate_expr(value, functions)?;
            validate_block(then_branch, false, functions)?;
            validate_block(else_branch, false, functions)
        }
        ExprKind::Match { value, arms } => {
            reject_secret_control_flow(value)?;
            validate_expr(value, functions)?;
            for arm in arms {
                validate_block(&arm.body, false, functions)?;
            }
            Ok(())
        }
        ExprKind::Call { target: name, args }
        | ExprKind::NamedCall {
            target: name, args, ..
        } => {
            for arg in args {
                validate_expr(arg, functions)?;
            }
            if let Some(builtin) = name.builtin() {
                validate_builtin_call(builtin, args)
            } else if name
                .user_name()
                .is_some_and(|name| functions.contains(name))
                || !args.iter().any(|arg| type_contains_secret(&arg.ty))
            {
                Ok(())
            } else {
                Err(error(
                    "E_SECRET_UNKNOWN_CALL",
                    format!("unknown call `{name}` cannot consume Secret<T>"),
                ))
            }
        }
        ExprKind::Tuple(items) | ExprKind::List(items) => {
            // Packing is allowed only because the aggregate type recursively retains
            // Secret<T>; all externally visible sinks inspect nested types.
            for item in items {
                validate_expr(item, functions)?;
            }
            Ok(())
        }
        ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            validate_expr(source, functions)?;
            validate_expr(expression, functions)?;
            if let Some(condition) = condition {
                reject_secret_control_flow(condition)?;
                validate_expr(condition, functions)?;
            }
            Ok(())
        }
        ExprKind::StructLiteral { fields, .. } => {
            for (_, value) in fields {
                validate_expr(value, functions)?;
            }
            Ok(())
        }
        ExprKind::JsonObject(entries) => {
            for (_, value) in entries {
                validate_expr(value, functions)?;
            }
            Ok(())
        }
        ExprKind::JsonArray(items) => {
            for item in items {
                validate_expr(item, functions)?;
            }
            Ok(())
        }
        ExprKind::Member { object, .. } => validate_expr(object, functions),
        ExprKind::Index { target, index } => {
            validate_expr(target, functions)?;
            reject_secret_key(index)?;
            validate_expr(index, functions)
        }
        ExprKind::VariantCode(_)
        | ExprKind::IntLiteral(_)
        | ExprKind::DecimalLiteral { .. }
        | ExprKind::OptionNone
        | ExprKind::Bool(_)
        | ExprKind::String(_)
        | ExprKind::Bytes(_)
        | ExprKind::Ident(_) => Ok(()),
    }
}
fn expression_contains_secret(expr: &TypedExpr) -> bool {
    if type_contains_secret(&expr.ty) {
        return true;
    }
    match expr.kind() {
        ExprKind::Binary { left, right, .. } => {
            expression_contains_secret(left) || expression_contains_secret(right)
        }
        ExprKind::Unary { expr, .. }
        | ExprKind::NumericCast { expr }
        | ExprKind::NumericTryCast { expr }
        | ExprKind::OptionSome { value: expr }
        | ExprKind::ResultOk { value: expr }
        | ExprKind::ResultErr { error: expr }
        | ExprKind::Propagate { value: expr } => expression_contains_secret(expr),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expression_contains_secret(cond)
                || expression_contains_secret(then_expr)
                || expression_contains_secret(else_expr)
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            expression_contains_secret(condition)
                || block_contains_secret(then_branch)
                || block_contains_secret(else_branch)
        }
        ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            expression_contains_secret(value)
                || block_contains_secret(then_branch)
                || block_contains_secret(else_branch)
        }
        ExprKind::Match { value, arms } => {
            expression_contains_secret(value)
                || arms.iter().any(|arm| block_contains_secret(&arm.body))
        }
        ExprKind::Call { target: name, args }
        | ExprKind::NamedCall {
            target: name, args, ..
        } => {
            match name.builtin() {
                // Approved cryptographic calls explicitly declassify to their
                // public result type.
                Some(
                    Builtin::Poseidon2 | Builtin::Poseidon6 | Builtin::Pubkgen | Builtin::Valcom,
                ) => false,
                // Other builtins may not hide a secret dependency behind a
                // public result (and are rejected as sinks separately).
                Some(_) => args.iter().any(expression_contains_secret),
                // User-defined helpers are checked body-by-body.  Their
                // declared public result is usable only after that validation
                // proves every secret path ends in an approved declassifier.
                None => false,
            }
        }
        ExprKind::Tuple(items) | ExprKind::List(items) => {
            items.iter().any(expression_contains_secret)
        }
        ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            expression_contains_secret(source)
                || expression_contains_secret(expression)
                || condition.as_deref().is_some_and(expression_contains_secret)
        }
        ExprKind::StructLiteral { fields, .. } => fields
            .iter()
            .any(|(_, value)| expression_contains_secret(value)),
        ExprKind::JsonObject(entries) => entries
            .iter()
            .any(|(_, value)| expression_contains_secret(value)),
        ExprKind::JsonArray(items) => items.iter().any(expression_contains_secret),
        ExprKind::Member { object, .. } => expression_contains_secret(object),
        ExprKind::Index { target, index } => {
            expression_contains_secret(target) || expression_contains_secret(index)
        }
        ExprKind::VariantCode(_)
        | ExprKind::IntLiteral(_)
        | ExprKind::DecimalLiteral { .. }
        | ExprKind::OptionNone
        | ExprKind::Bool(_)
        | ExprKind::String(_)
        | ExprKind::Bytes(_)
        | ExprKind::Ident(_) => false,
    }
}
fn function_contains_secret(function: &TypedFunction) -> bool {
    function
        .param_types
        .iter()
        .any(|param| type_contains_secret(&param.ty))
        || function.ret_ty.as_ref().is_some_and(type_contains_secret)
        || block_contains_secret(&function.body)
}
fn block_contains_secret(block: &TypedBlock) -> bool {
    block.statements.iter().any(statement_contains_secret)
        || block
            .tail
            .as_ref()
            .is_some_and(|tail| expression_contains_secret(tail))
}
fn statement_contains_secret(statement: &TypedStatement) -> bool {
    match statement.kind() {
        TypedStatement::Let { value, .. } | TypedStatement::Expr(value) => {
            expression_contains_secret(value)
        }
        TypedStatement::Return(value) => value.as_ref().is_some_and(expression_contains_secret),
        TypedStatement::Break | TypedStatement::Continue => false,
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            expression_contains_secret(cond)
                || block_contains_secret(then_branch)
                || else_branch.as_ref().is_some_and(block_contains_secret)
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            expression_contains_secret(value)
                || block_contains_secret(then_branch)
                || else_branch.as_ref().is_some_and(block_contains_secret)
        }
        TypedStatement::While { cond, body } => {
            expression_contains_secret(cond) || block_contains_secret(body)
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            init.as_deref().is_some_and(statement_contains_secret)
                || cond.as_ref().is_some_and(expression_contains_secret)
                || step.as_deref().is_some_and(statement_contains_secret)
                || block_contains_secret(body)
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            expression_contains_secret(map) || block_contains_secret(body)
        }
        TypedStatement::MapSet { map, key, value } => {
            expression_contains_secret(map)
                || expression_contains_secret(key)
                || expression_contains_secret(value)
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        parser::parse_test_fragment as parse,
        semantic::{SemanticContext, SemanticError, Type, analyze},
    };
    fn analyze_error(source: &str) -> SemanticError {
        let program = parse(source).expect("secret-flow fixture should parse");
        SemanticContext::with_zk_enabled(true)
            .analyze(&program)
            .expect_err("secret-flow fixture should fail semantic analysis")
    }
    #[test]
    fn commitments_are_the_explicit_declassification_boundary() {
        let source = include_str!("../fixtures/koto_v1/secret/001.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline");
        let program = parse(source).expect("commitment fixture should parse");
        SemanticContext::with_zk_enabled(true)
            .analyze(&program)
            .expect("approved commitment should accept secret inputs");
    }
    #[test]
    fn secret_requires_zk_build_configuration() {
        let program = parse("fn keep(Secret<int> value) -> Secret<int> { return value; }")
            .expect("secret-flow fixture should parse");
        let error = analyze(&program).expect_err("ZK-disabled secret type must fail");
        assert_eq!(error.code, "E_SECRET_REQUIRES_ZK");
    }
    #[test]
    fn secret_detection_recurses_through_lists() {
        let ty = Type::List(
            Box::new(Type::Option(Box::new(Type::Secret(Box::new(Type::Int))))),
            1,
        );
        assert!(super::type_contains_secret(&ty));
    }
    #[test]
    fn public_secret_return_is_rejected() {
        let error = analyze_error(
            include_str!("../fixtures/koto_v1/secret/002.ko")
                .strip_suffix('\n')
                .expect("fixture sentinel newline"),
        );
        assert_eq!(error.code, "E_SECRET_PUBLIC_RETURN");
    }
    #[test]
    fn secret_control_flow_is_rejected() {
        let error = analyze_error(
            include_str!("../fixtures/koto_v1/secret/003.ko")
                .strip_suffix('\n')
                .expect("fixture sentinel newline"),
        );
        assert_eq!(error.code, "E_SECRET_ARITHMETIC");
    }
    #[test]
    fn secret_logs_and_host_writes_are_rejected() {
        let log_error = analyze_error(
            include_str!("../fixtures/koto_v1/secret/004.ko")
                .strip_suffix('\n')
                .expect("fixture sentinel newline"),
        );
        assert_eq!(log_error.code, "E_SECRET_LOG");
        let host_error = analyze_error(
            include_str!("../fixtures/koto_v1/secret/005.ko")
                .strip_suffix('\n')
                .expect("fixture sentinel newline"),
        );
        assert_eq!(host_error.code, "E_SECRET_STATE_SINK");
    }
    #[test]
    fn secret_state_keys_and_values_are_rejected() {
        let key_error = analyze_error(
            include_str!("../fixtures/koto_v1/secret/006.ko")
                .strip_suffix('\n')
                .expect("fixture sentinel newline"),
        );
        assert_eq!(key_error.code, "E_SECRET_STATE_KEY");
        let value_error = analyze_error(
            include_str!("../fixtures/koto_v1/secret/007.ko")
                .strip_suffix('\n')
                .expect("fixture sentinel newline"),
        );
        assert_eq!(value_error.code, "E_SECRET_STATE_WRITE");
    }
    #[test]
    fn commitment_operands_cannot_mix_public_and_secret_values() {
        let error = analyze_error(
            include_str!("../fixtures/koto_v1/secret/008.ko")
                .strip_suffix('\n')
                .expect("fixture sentinel newline"),
        );
        assert_eq!(error.code, "E_SECRET_MIXED_COMMITMENT");
    }
    #[test]
    fn user_helper_named_like_crypto_builtin_is_not_a_declassifier() {
        let source = r#"module SecretNames {
            fn poseidon2(Secret<int> value) -> Secret<int> { value }
            fn leak() {
                let Secret<int> value = crypto::private_input(0);
                debug::info(poseidon2(value));
            }
        }"#;
        let error = analyze_error(source);
        assert_eq!(error.code, "E_SECRET_LOG");
    }
    #[test]
    fn flat_crypto_spellings_are_rejected() {
        for (call, code) in [
            ("poseidon2(left: 1, right: 2)", "E_INTERNAL_BUILTIN"),
            (
                "poseidon6(a: 1, b: 2, c: 3, d: 4, e: 5, f: 6)",
                "E_INTERNAL_BUILTIN",
            ),
            ("pubkgen(1)", "E_INTERNAL_BUILTIN"),
            ("valcom(left: 1, right: 2)", "E_NON_CANONICAL_BUILTIN"),
        ] {
            let source = format!("seiyaku Privacy {{ fn rejected() {{ let _value = {call}; }} }}");
            let error = analyze_error(&source);
            assert_eq!(error.code, code, "{call}");
            if code == "E_INTERNAL_BUILTIN" {
                assert!(
                    error.message.contains("compiler-internal"),
                    "{call}: {error:?}"
                );
            } else {
                assert!(
                    error.message.contains("non-canonical builtin spelling")
                        && error.message.contains("crypto::"),
                    "{call}: {error:?}"
                );
            }
        }
    }
}
