//! Stack-safe typed-HIR equality, cloning and type rendering.
//!
//! The explicit work lists preserve nominal type identities and ordered active
//! fields without recursive traversal of nested expression/statement trees.

use super::*;

impl std::fmt::Debug for Type {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&render_source_type_name(self))
    }
}
impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        while let Some((left, right)) = pending.pop() {
            match (left, right) {
                (Self::Int, Self::Int)
                | (Self::Decimal, Self::Decimal)
                | (Self::Quantity, Self::Quantity)
                | (Self::Bool, Self::Bool)
                | (Self::String, Self::String)
                | (Self::Bytes, Self::Bytes)
                | (Self::DataSpaceId, Self::DataSpaceId)
                | (Self::AxtDescriptor, Self::AxtDescriptor)
                | (Self::AxtAnchoredSpendV1, Self::AxtAnchoredSpendV1)
                | (Self::ProofBlob, Self::ProofBlob)
                | (Self::SoracloudRequest, Self::SoracloudRequest)
                | (Self::SoracloudResponse, Self::SoracloudResponse)
                | (Self::AccountId, Self::AccountId)
                | (Self::AssetDefinitionId, Self::AssetDefinitionId)
                | (Self::AssetId, Self::AssetId)
                | (Self::NftId, Self::NftId)
                | (Self::DomainId, Self::DomainId)
                | (Self::Name, Self::Name)
                | (Self::Json, Self::Json)
                | (Self::Unit, Self::Unit) => {}
                (Self::Enum(left), Self::Enum(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (Self::ErrorEnum(left), Self::ErrorEnum(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (Self::Secret(left), Self::Secret(right))
                | (Self::StateCursor(left), Self::StateCursor(right))
                | (Self::Option(left), Self::Option(right)) => {
                    pending.push((left, right));
                }
                (Self::StateMap(left_key, left_value), Self::StateMap(right_key, right_value))
                | (Self::Result(left_key, left_value), Self::Result(right_key, right_value)) => {
                    pending.push((left_value, right_value));
                    pending.push((left_key, right_key));
                }
                (
                    Self::List(left_element, left_capacity),
                    Self::List(right_element, right_capacity),
                ) => {
                    if left_capacity != right_capacity {
                        return false;
                    }
                    pending.push((left_element, right_element));
                }
                (Self::Tuple(left), Self::Tuple(right)) => {
                    if left.len() != right.len() {
                        return false;
                    }
                    pending.extend(left.iter().zip(right).rev());
                }
                (
                    Self::Struct {
                        name: left_name,
                        fields: left_fields,
                    },
                    Self::Struct {
                        name: right_name,
                        fields: right_fields,
                    },
                ) => {
                    if left_name != right_name || left_fields.len() != right_fields.len() {
                        return false;
                    }
                    for ((left_name, left_ty), (right_name, right_ty)) in
                        left_fields.iter().zip(right_fields.iter()).rev()
                    {
                        if left_name != right_name {
                            return false;
                        }
                        pending.push((left_ty, right_ty));
                    }
                }
                (Self::ContractRef(left), Self::ContractRef(right)) if left == right => {}
                (Self::NamedStruct(left), Self::NamedStruct(right)) => {
                    if left != right {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
}
impl Eq for Type {}
impl Clone for Type {
    fn clone(&self) -> Self {
        enum Pending<'a> {
            Type(&'a Type),
            Secret,
            StateMap,
            StateCursor,
            Option,
            Result,
            List(u8),
            Tuple(usize),
        }

        let mut pending = vec![Pending::Type(self)];
        let mut values = Vec::new();
        while let Some(operation) = pending.pop() {
            match operation {
                Pending::Type(ty) => match ty {
                    Self::ContractRef(contract) => {
                        values.push(Self::ContractRef(Arc::clone(contract)))
                    }
                    Self::Int => values.push(Self::Int),
                    Self::Decimal => values.push(Self::Decimal),
                    Self::Quantity => values.push(Self::Quantity),
                    Self::Bool => values.push(Self::Bool),
                    Self::String => values.push(Self::String),
                    Self::Bytes => values.push(Self::Bytes),
                    Self::DataSpaceId => values.push(Self::DataSpaceId),
                    Self::AxtDescriptor => values.push(Self::AxtDescriptor),
                    Self::AxtAnchoredSpendV1 => values.push(Self::AxtAnchoredSpendV1),
                    Self::ProofBlob => values.push(Self::ProofBlob),
                    Self::SoracloudRequest => values.push(Self::SoracloudRequest),
                    Self::SoracloudResponse => values.push(Self::SoracloudResponse),
                    Self::AccountId => values.push(Self::AccountId),
                    Self::AssetDefinitionId => values.push(Self::AssetDefinitionId),
                    Self::AssetId => values.push(Self::AssetId),
                    Self::NftId => values.push(Self::NftId),
                    Self::DomainId => values.push(Self::DomainId),
                    Self::Name => values.push(Self::Name),
                    Self::Json => values.push(Self::Json),
                    Self::Unit => values.push(Self::Unit),
                    Self::Enum(descriptor) => {
                        values.push(Self::Enum(Arc::clone(descriptor)));
                    }
                    Self::ErrorEnum(descriptor) => {
                        values.push(Self::ErrorEnum(Arc::clone(descriptor)));
                    }
                    Self::Secret(inner) => {
                        pending.push(Pending::Secret);
                        pending.push(Pending::Type(inner));
                    }
                    Self::StateMap(key, value) => {
                        pending.push(Pending::StateMap);
                        pending.push(Pending::Type(value));
                        pending.push(Pending::Type(key));
                    }
                    Self::StateCursor(inner) => {
                        pending.push(Pending::StateCursor);
                        pending.push(Pending::Type(inner));
                    }
                    Self::Option(inner) => {
                        pending.push(Pending::Option);
                        pending.push(Pending::Type(inner));
                    }
                    Self::Result(ok, error) => {
                        pending.push(Pending::Result);
                        pending.push(Pending::Type(error));
                        pending.push(Pending::Type(ok));
                    }
                    Self::List(element, capacity) => {
                        pending.push(Pending::List(*capacity));
                        pending.push(Pending::Type(element));
                    }
                    Self::Tuple(items) => {
                        pending.push(Pending::Tuple(items.len()));
                        pending.extend(items.iter().rev().map(Pending::Type));
                    }
                    Self::Struct { name, fields } => values.push(Self::Struct {
                        name: name.clone(),
                        fields: Arc::clone(fields),
                    }),
                    Self::NamedStruct(name) => values.push(Self::NamedStruct(name.clone())),
                },
                Pending::Secret => {
                    let inner = values.pop().expect("visited secret type child");
                    values.push(Self::Secret(Box::new(inner)));
                }
                Pending::StateMap => {
                    let value = values.pop().expect("visited state-map value type");
                    let key = values.pop().expect("visited state-map key type");
                    values.push(Self::StateMap(Box::new(key), Box::new(value)));
                }
                Pending::StateCursor => {
                    let inner = values.pop().expect("visited cursor key type");
                    values.push(Self::StateCursor(Box::new(inner)));
                }
                Pending::Option => {
                    let inner = values.pop().expect("visited option type child");
                    values.push(Self::Option(Box::new(inner)));
                }
                Pending::Result => {
                    let error = values.pop().expect("visited result error type");
                    let ok = values.pop().expect("visited result success type");
                    values.push(Self::Result(Box::new(ok), Box::new(error)));
                }
                Pending::List(capacity) => {
                    let element = values.pop().expect("visited list element type");
                    values.push(Self::List(Box::new(element), capacity));
                }
                Pending::Tuple(len) => {
                    let start = values.len().saturating_sub(len);
                    let items = values.split_off(start);
                    values.push(Self::Tuple(items));
                }
            }
        }
        values.pop().expect("type traversal produces one root")
    }
}

impl std::fmt::Debug for ExprKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VariantCode(value) => formatter.debug_tuple("VariantCode").field(value).finish(),
            Self::IntLiteral(value) => formatter.debug_tuple("IntLiteral").field(value).finish(),
            Self::DecimalLiteral { value, spelling } => formatter
                .debug_struct("DecimalLiteral")
                .field("value", value)
                .field("spelling", spelling)
                .finish(),
            Self::Bool(value) => formatter.debug_tuple("Bool").field(value).finish(),
            Self::String(value) => formatter.debug_tuple("String").field(value).finish(),
            Self::Bytes(value) => formatter.debug_tuple("Bytes").field(value).finish(),
            Self::Ident(value) => formatter.debug_tuple("Ident").field(value).finish(),
            other => formatter.write_str(match other {
                Self::Binary { .. } => "Binary(..)",
                Self::Unary { .. } => "Unary(..)",
                Self::NumericCast { .. } => "NumericCast(..)",
                Self::NumericTryCast { .. } => "NumericTryCast(..)",
                Self::Conditional { .. } => "Conditional(..)",
                Self::If { .. } => "If(..)",
                Self::IfLet { .. } => "IfLet(..)",
                Self::Match { .. } => "Match(..)",
                Self::OptionSome { .. } => "OptionSome(..)",
                Self::OptionNone => "OptionNone",
                Self::ResultOk { .. } => "ResultOk(..)",
                Self::ResultErr { .. } => "ResultErr(..)",
                Self::Propagate { .. } => "Propagate(..)",
                Self::Call { .. } => "Call(..)",
                Self::NamedCall { .. } => "NamedCall(..)",
                Self::StructLiteral { .. } => "StructLiteral(..)",
                Self::Tuple(_) => "Tuple(..)",
                Self::List(_) => "List(..)",
                Self::ListComprehension { .. } => "ListComprehension(..)",
                Self::JsonObject(_) => "JsonObject(..)",
                Self::JsonArray(_) => "JsonArray(..)",
                Self::Member { .. } => "Member(..)",
                Self::Index { .. } => "Index(..)",
                Self::VariantCode(_)
                | Self::IntLiteral(_)
                | Self::DecimalLiteral { .. }
                | Self::Bool(_)
                | Self::String(_)
                | Self::Bytes(_)
                | Self::Ident(_) => unreachable!("scalar expressions were rendered above"),
            }),
        }
    }
}

enum TypedEq<'a> {
    Type(&'a Type, &'a Type),
    Expr(&'a TypedExpr, &'a TypedExpr),
    Kind(&'a ExprKind, &'a ExprKind),
    Statement(&'a TypedStatement, &'a TypedStatement),
    Block(&'a TypedBlock, &'a TypedBlock),
    MatchArm(&'a TypedMatchArm, &'a TypedMatchArm),
}

#[allow(clippy::too_many_lines)]
fn typed_semantic_eq(initial: TypedEq<'_>) -> bool {
    let mut pending = vec![initial];
    while let Some(comparison) = pending.pop() {
        match comparison {
            TypedEq::Type(left, right) => {
                if left != right {
                    return false;
                }
            }
            TypedEq::Expr(left, right) => {
                pending.push(TypedEq::Type(&left.ty, &right.ty));
                pending.push(TypedEq::Kind(&left.expr, &right.expr));
            }
            TypedEq::Kind(left, right) => match (left, right) {
                (
                    ExprKind::Binary {
                        op: left_op,
                        left,
                        right,
                    },
                    ExprKind::Binary {
                        op: right_op,
                        left: other_left,
                        right: other_right,
                    },
                ) => {
                    if left_op != right_op {
                        return false;
                    }
                    pending.push(TypedEq::Expr(right, other_right));
                    pending.push(TypedEq::Expr(left, other_left));
                }
                (
                    ExprKind::Unary {
                        op: left_op,
                        expr: left_expr,
                    },
                    ExprKind::Unary {
                        op: right_op,
                        expr: right_expr,
                    },
                ) => {
                    if left_op != right_op {
                        return false;
                    }
                    pending.push(TypedEq::Expr(left_expr, right_expr));
                }
                (ExprKind::NumericCast { expr: left }, ExprKind::NumericCast { expr: right })
                | (
                    ExprKind::NumericTryCast { expr: left },
                    ExprKind::NumericTryCast { expr: right },
                ) => pending.push(TypedEq::Expr(left, right)),
                (
                    ExprKind::Conditional {
                        cond: left_cond,
                        then_expr: left_then,
                        else_expr: left_else,
                    },
                    ExprKind::Conditional {
                        cond: right_cond,
                        then_expr: right_then,
                        else_expr: right_else,
                    },
                ) => {
                    pending.push(TypedEq::Expr(left_else, right_else));
                    pending.push(TypedEq::Expr(left_then, right_then));
                    pending.push(TypedEq::Expr(left_cond, right_cond));
                }
                (
                    ExprKind::If {
                        condition: left_condition,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    ExprKind::If {
                        condition: right_condition,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    pending.push(TypedEq::Block(left_else, right_else));
                    pending.push(TypedEq::Block(left_then, right_then));
                    pending.push(TypedEq::Expr(left_condition, right_condition));
                }
                (
                    ExprKind::IfLet {
                        pattern: left_pattern,
                        value: left_value,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    ExprKind::IfLet {
                        pattern: right_pattern,
                        value: right_value,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    if left_pattern != right_pattern {
                        return false;
                    }
                    pending.push(TypedEq::Block(left_else, right_else));
                    pending.push(TypedEq::Block(left_then, right_then));
                    pending.push(TypedEq::Expr(left_value, right_value));
                }
                (
                    ExprKind::Match {
                        value: left_value,
                        arms: left_arms,
                    },
                    ExprKind::Match {
                        value: right_value,
                        arms: right_arms,
                    },
                ) => {
                    if left_arms.len() != right_arms.len() {
                        return false;
                    }
                    pending.extend(
                        left_arms
                            .iter()
                            .zip(right_arms)
                            .rev()
                            .map(|(left, right)| TypedEq::MatchArm(left, right)),
                    );
                    pending.push(TypedEq::Expr(left_value, right_value));
                }
                (ExprKind::OptionSome { value: left }, ExprKind::OptionSome { value: right })
                | (ExprKind::ResultOk { value: left }, ExprKind::ResultOk { value: right })
                | (ExprKind::ResultErr { error: left }, ExprKind::ResultErr { error: right })
                | (ExprKind::Propagate { value: left }, ExprKind::Propagate { value: right }) => {
                    pending.push(TypedEq::Expr(left, right))
                }
                (ExprKind::OptionNone, ExprKind::OptionNone) => {}
                (
                    ExprKind::Call {
                        target: left_name,
                        args: left_args,
                    },
                    ExprKind::Call {
                        target: right_name,
                        args: right_args,
                    },
                ) => {
                    if left_name != right_name || left_args.len() != right_args.len() {
                        return false;
                    }
                    pending.extend(
                        left_args
                            .iter()
                            .zip(right_args)
                            .rev()
                            .map(|(left, right)| TypedEq::Expr(left, right)),
                    );
                }
                (
                    ExprKind::NamedCall {
                        target: left_name,
                        args: left_args,
                        evaluation_order: left_order,
                    },
                    ExprKind::NamedCall {
                        target: right_name,
                        args: right_args,
                        evaluation_order: right_order,
                    },
                ) => {
                    if left_name != right_name
                        || left_order != right_order
                        || left_args.len() != right_args.len()
                    {
                        return false;
                    }
                    pending.extend(
                        left_args
                            .iter()
                            .zip(right_args)
                            .rev()
                            .map(|(left, right)| TypedEq::Expr(left, right)),
                    );
                }
                (
                    ExprKind::StructLiteral {
                        name: left_name,
                        fields: left_fields,
                    },
                    ExprKind::StructLiteral {
                        name: right_name,
                        fields: right_fields,
                    },
                ) => {
                    if left_name != right_name || left_fields.len() != right_fields.len() {
                        return false;
                    }
                    for ((left_name, left), (right_name, right)) in
                        left_fields.iter().zip(right_fields).rev()
                    {
                        if left_name != right_name {
                            return false;
                        }
                        pending.push(TypedEq::Expr(left, right));
                    }
                }
                (ExprKind::Tuple(left), ExprKind::Tuple(right))
                | (ExprKind::List(left), ExprKind::List(right))
                | (ExprKind::JsonArray(left), ExprKind::JsonArray(right)) => {
                    if left.len() != right.len() {
                        return false;
                    }
                    pending.extend(
                        left.iter()
                            .zip(right)
                            .rev()
                            .map(|(left, right)| TypedEq::Expr(left, right)),
                    );
                }
                (
                    ExprKind::ListComprehension {
                        expression: left_expression,
                        item: left_item,
                        source: left_source,
                        condition: left_condition,
                    },
                    ExprKind::ListComprehension {
                        expression: right_expression,
                        item: right_item,
                        source: right_source,
                        condition: right_condition,
                    },
                ) => {
                    if left_item != right_item
                        || left_condition.is_some() != right_condition.is_some()
                    {
                        return false;
                    }
                    if let (Some(left), Some(right)) = (left_condition, right_condition) {
                        pending.push(TypedEq::Expr(left, right));
                    }
                    pending.push(TypedEq::Expr(left_source, right_source));
                    pending.push(TypedEq::Expr(left_expression, right_expression));
                }
                (ExprKind::JsonObject(left), ExprKind::JsonObject(right)) => {
                    if left.len() != right.len() {
                        return false;
                    }
                    for ((left_name, left), (right_name, right)) in left.iter().zip(right).rev() {
                        if left_name != right_name {
                            return false;
                        }
                        pending.push(TypedEq::Expr(left, right));
                    }
                }
                (
                    ExprKind::Member {
                        object: left_object,
                        field: left_field,
                    },
                    ExprKind::Member {
                        object: right_object,
                        field: right_field,
                    },
                ) => {
                    if left_field != right_field {
                        return false;
                    }
                    pending.push(TypedEq::Expr(left_object, right_object));
                }
                (
                    ExprKind::Index {
                        target: left_target,
                        index: left_index,
                    },
                    ExprKind::Index {
                        target: right_target,
                        index: right_index,
                    },
                ) => {
                    pending.push(TypedEq::Expr(left_index, right_index));
                    pending.push(TypedEq::Expr(left_target, right_target));
                }
                (ExprKind::VariantCode(left), ExprKind::VariantCode(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (ExprKind::IntLiteral(left), ExprKind::IntLiteral(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (
                    ExprKind::DecimalLiteral {
                        value: left_value,
                        spelling: left_spelling,
                    },
                    ExprKind::DecimalLiteral {
                        value: right_value,
                        spelling: right_spelling,
                    },
                ) => {
                    if left_value != right_value || left_spelling != right_spelling {
                        return false;
                    }
                }
                (ExprKind::Bool(left), ExprKind::Bool(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (ExprKind::String(left), ExprKind::String(right))
                | (ExprKind::Ident(left), ExprKind::Ident(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (ExprKind::Bytes(left), ExprKind::Bytes(right)) => {
                    if left != right {
                        return false;
                    }
                }
                _ => return false,
            },
            TypedEq::Statement(left, right) => match (left, right) {
                (
                    TypedStatement::Let {
                        name: left_name,
                        value: left_value,
                    },
                    TypedStatement::Let {
                        name: right_name,
                        value: right_value,
                    },
                ) => {
                    if left_name != right_name {
                        return false;
                    }
                    pending.push(TypedEq::Expr(left_value, right_value));
                }
                (TypedStatement::Expr(left), TypedStatement::Expr(right)) => {
                    pending.push(TypedEq::Expr(left, right));
                }
                (TypedStatement::Return(left), TypedStatement::Return(right)) => {
                    match (left, right) {
                        (Some(left), Some(right)) => pending.push(TypedEq::Expr(left, right)),
                        (None, None) => {}
                        _ => return false,
                    }
                }
                (TypedStatement::Break, TypedStatement::Break)
                | (TypedStatement::Continue, TypedStatement::Continue) => {}
                (
                    TypedStatement::If {
                        cond: left_cond,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    TypedStatement::If {
                        cond: right_cond,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    match (left_else, right_else) {
                        (Some(left), Some(right)) => pending.push(TypedEq::Block(left, right)),
                        (None, None) => {}
                        _ => return false,
                    }
                    pending.push(TypedEq::Block(left_then, right_then));
                    pending.push(TypedEq::Expr(left_cond, right_cond));
                }
                (
                    TypedStatement::IfLet {
                        pattern: left_pattern,
                        value: left_value,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    TypedStatement::IfLet {
                        pattern: right_pattern,
                        value: right_value,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    if left_pattern != right_pattern {
                        return false;
                    }
                    match (left_else, right_else) {
                        (Some(left), Some(right)) => pending.push(TypedEq::Block(left, right)),
                        (None, None) => {}
                        _ => return false,
                    }
                    pending.push(TypedEq::Block(left_then, right_then));
                    pending.push(TypedEq::Expr(left_value, right_value));
                }
                (
                    TypedStatement::While {
                        cond: left_cond,
                        body: left_body,
                    },
                    TypedStatement::While {
                        cond: right_cond,
                        body: right_body,
                    },
                ) => {
                    pending.push(TypedEq::Block(left_body, right_body));
                    pending.push(TypedEq::Expr(left_cond, right_cond));
                }
                (
                    TypedStatement::For {
                        line: left_line,
                        init: left_init,
                        cond: left_cond,
                        step: left_step,
                        body: left_body,
                    },
                    TypedStatement::For {
                        line: right_line,
                        init: right_init,
                        cond: right_cond,
                        step: right_step,
                        body: right_body,
                    },
                ) => {
                    if left_line != right_line
                        || left_init.is_some() != right_init.is_some()
                        || left_cond.is_some() != right_cond.is_some()
                        || left_step.is_some() != right_step.is_some()
                    {
                        return false;
                    }
                    pending.push(TypedEq::Block(left_body, right_body));
                    if let (Some(left), Some(right)) = (left_step, right_step) {
                        pending.push(TypedEq::Statement(left, right));
                    }
                    if let (Some(left), Some(right)) = (left_cond, right_cond) {
                        pending.push(TypedEq::Expr(left, right));
                    }
                    if let (Some(left), Some(right)) = (left_init, right_init) {
                        pending.push(TypedEq::Statement(left, right));
                    }
                }
                (
                    TypedStatement::ForEachMap {
                        key: left_key,
                        value: left_value,
                        map: left_map,
                        body: left_body,
                    },
                    TypedStatement::ForEachMap {
                        key: right_key,
                        value: right_value,
                        map: right_map,
                        body: right_body,
                    },
                ) => {
                    if left_key != right_key || left_value != right_value {
                        return false;
                    }
                    pending.push(TypedEq::Block(left_body, right_body));
                    pending.push(TypedEq::Expr(left_map, right_map));
                }
                (
                    TypedStatement::MapSet {
                        map: left_map,
                        key: left_key,
                        value: left_value,
                    },
                    TypedStatement::MapSet {
                        map: right_map,
                        key: right_key,
                        value: right_value,
                    },
                ) => {
                    pending.push(TypedEq::Expr(left_value, right_value));
                    pending.push(TypedEq::Expr(left_key, right_key));
                    pending.push(TypedEq::Expr(left_map, right_map));
                }
                _ => return false,
            },
            TypedEq::Block(left, right) => {
                if left.statements.len() != right.statements.len() {
                    return false;
                }
                match (&left.tail, &right.tail) {
                    (Some(left), Some(right)) => pending.push(TypedEq::Expr(left, right)),
                    (None, None) => {}
                    _ => return false,
                }
                pending.extend(
                    left.statements
                        .iter()
                        .zip(&right.statements)
                        .rev()
                        .map(|(left, right)| TypedEq::Statement(left, right)),
                );
            }
            TypedEq::MatchArm(left, right) => {
                if left.pattern != right.pattern {
                    return false;
                }
                pending.push(TypedEq::Block(&left.body, &right.body));
            }
        }
    }
    true
}

impl PartialEq for ExprKind {
    fn eq(&self, other: &Self) -> bool {
        typed_semantic_eq(TypedEq::Kind(self, other))
    }
}

enum TypedCloneTask<'a> {
    Expr(&'a TypedExpr),
    Kind(&'a ExprKind),
    Statement(&'a TypedStatement),
    Block(&'a TypedBlock),
    MatchArm(&'a TypedMatchArm),
    BuildExpr(&'a Type),
    BuildKind(TypedKindClone<'a>),
    BuildStatement(TypedStatementClone<'a>),
    BuildBlock {
        statement_count: usize,
        has_tail: bool,
        provenance: &'a crate::semantic::TypedBlockProvenance,
    },
    BuildMatchArm(&'a TypedSumPattern),
}

enum TypedKindClone<'a> {
    Binary(BinaryOp),
    Unary(UnaryOp),
    NumericCast,
    NumericTryCast,
    Conditional,
    If,
    IfLet(&'a TypedSumPattern),
    Match(usize),
    OptionSome,
    ResultOk,
    ResultErr,
    Propagate,
    Call(&'a super::CallTarget, usize),
    NamedCall(&'a super::CallTarget, usize, &'a [usize]),
    StructLiteral(&'a str, &'a [(String, TypedExpr)]),
    Tuple(usize),
    List(usize),
    ListComprehension { item: &'a str, has_condition: bool },
    JsonObject(&'a [(String, TypedExpr)]),
    JsonArray(usize),
    Member(&'a str),
    Index,
}

enum TypedStatementClone<'a> {
    Let(&'a str),
    Expr,
    Return(bool),
    If(bool),
    IfLet(&'a TypedSumPattern, bool),
    While,
    For {
        line: usize,
        has_init: bool,
        has_cond: bool,
        has_step: bool,
    },
    ForEachMap {
        key: &'a str,
        value: &'a Option<String>,
    },
    MapSet,
}

#[expect(
    clippy::large_enum_variant,
    reason = "the explicit clone stack moves each value once; boxing would allocate per statement"
)]
enum TypedCloneValue {
    Expr(TypedExpr),
    Kind(ExprKind),
    Statement(TypedStatement),
    Block(TypedBlock),
    MatchArm(TypedMatchArm),
}

fn pop_cloned_expr(values: &mut Vec<TypedCloneValue>) -> TypedExpr {
    match values.pop().expect("typed clone expression result") {
        TypedCloneValue::Expr(value) => value,
        _ => unreachable!("typed clone traversal preserves expression result kinds"),
    }
}

fn pop_cloned_kind(values: &mut Vec<TypedCloneValue>) -> ExprKind {
    match values.pop().expect("typed clone expression-kind result") {
        TypedCloneValue::Kind(value) => value,
        _ => unreachable!("typed clone traversal preserves expression-kind result kinds"),
    }
}

fn pop_cloned_statement(values: &mut Vec<TypedCloneValue>) -> TypedStatement {
    match values.pop().expect("typed clone statement result") {
        TypedCloneValue::Statement(value) => value,
        _ => unreachable!("typed clone traversal preserves statement result kinds"),
    }
}

fn pop_cloned_block(values: &mut Vec<TypedCloneValue>) -> TypedBlock {
    match values.pop().expect("typed clone block result") {
        TypedCloneValue::Block(value) => value,
        _ => unreachable!("typed clone traversal preserves block result kinds"),
    }
}

fn pop_cloned_exprs(values: &mut Vec<TypedCloneValue>, len: usize) -> Vec<TypedExpr> {
    let start = values
        .len()
        .checked_sub(len)
        .expect("typed clone visited every expression child");
    values
        .split_off(start)
        .into_iter()
        .map(|value| match value {
            TypedCloneValue::Expr(value) => value,
            _ => unreachable!("typed clone traversal preserves expression child kinds"),
        })
        .collect()
}

fn pop_cloned_statements(values: &mut Vec<TypedCloneValue>, len: usize) -> Vec<TypedStatement> {
    let start = values
        .len()
        .checked_sub(len)
        .expect("typed clone visited every statement child");
    values
        .split_off(start)
        .into_iter()
        .map(|value| match value {
            TypedCloneValue::Statement(value) => value,
            _ => unreachable!("typed clone traversal preserves statement child kinds"),
        })
        .collect()
}

fn pop_cloned_match_arms(values: &mut Vec<TypedCloneValue>, len: usize) -> Vec<TypedMatchArm> {
    let start = values
        .len()
        .checked_sub(len)
        .expect("typed clone visited every match-arm child");
    values
        .split_off(start)
        .into_iter()
        .map(|value| match value {
            TypedCloneValue::MatchArm(value) => value,
            _ => unreachable!("typed clone traversal preserves match-arm child kinds"),
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn clone_typed_semantic(initial: TypedCloneTask<'_>) -> TypedCloneValue {
    let mut pending = vec![initial];
    let mut values = Vec::new();
    while let Some(operation) = pending.pop() {
        match operation {
            TypedCloneTask::Expr(expr) => {
                pending.push(TypedCloneTask::BuildExpr(&expr.ty));
                pending.push(TypedCloneTask::Kind(&expr.expr));
            }
            TypedCloneTask::Kind(kind) => match kind {
                ExprKind::Binary { op, left, right } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Binary(*op)));
                    pending.push(TypedCloneTask::Expr(right));
                    pending.push(TypedCloneTask::Expr(left));
                }
                ExprKind::Unary { op, expr } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Unary(*op)));
                    pending.push(TypedCloneTask::Expr(expr));
                }
                ExprKind::NumericCast { expr } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::NumericCast));
                    pending.push(TypedCloneTask::Expr(expr));
                }
                ExprKind::NumericTryCast { expr } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::NumericTryCast));
                    pending.push(TypedCloneTask::Expr(expr));
                }
                ExprKind::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Conditional));
                    pending.push(TypedCloneTask::Expr(else_expr));
                    pending.push(TypedCloneTask::Expr(then_expr));
                    pending.push(TypedCloneTask::Expr(cond));
                }
                ExprKind::If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::If));
                    pending.push(TypedCloneTask::Block(else_branch));
                    pending.push(TypedCloneTask::Block(then_branch));
                    pending.push(TypedCloneTask::Expr(condition));
                }
                ExprKind::IfLet {
                    pattern,
                    value,
                    then_branch,
                    else_branch,
                } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::IfLet(pattern)));
                    pending.push(TypedCloneTask::Block(else_branch));
                    pending.push(TypedCloneTask::Block(then_branch));
                    pending.push(TypedCloneTask::Expr(value));
                }
                ExprKind::Match { value, arms } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Match(arms.len())));
                    for arm in arms.iter().rev() {
                        pending.push(TypedCloneTask::MatchArm(arm));
                    }
                    pending.push(TypedCloneTask::Expr(value));
                }
                ExprKind::OptionSome { value } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::OptionSome));
                    pending.push(TypedCloneTask::Expr(value));
                }
                ExprKind::OptionNone => values.push(TypedCloneValue::Kind(ExprKind::OptionNone)),
                ExprKind::ResultOk { value } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::ResultOk));
                    pending.push(TypedCloneTask::Expr(value));
                }
                ExprKind::ResultErr { error } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::ResultErr));
                    pending.push(TypedCloneTask::Expr(error));
                }
                ExprKind::Propagate { value } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Propagate));
                    pending.push(TypedCloneTask::Expr(value));
                }
                ExprKind::Call { target: name, args } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Call(
                        name,
                        args.len(),
                    )));
                    pending.extend(args.iter().rev().map(TypedCloneTask::Expr));
                }
                ExprKind::NamedCall {
                    target: name,
                    args,
                    evaluation_order,
                } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::NamedCall(
                        name,
                        args.len(),
                        evaluation_order,
                    )));
                    pending.extend(args.iter().rev().map(TypedCloneTask::Expr));
                }
                ExprKind::StructLiteral { name, fields } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::StructLiteral(
                        name, fields,
                    )));
                    pending.extend(
                        fields
                            .iter()
                            .rev()
                            .map(|(_, expr)| TypedCloneTask::Expr(expr)),
                    );
                }
                ExprKind::Tuple(items) => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Tuple(
                        items.len(),
                    )));
                    pending.extend(items.iter().rev().map(TypedCloneTask::Expr));
                }
                ExprKind::List(items) => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::List(items.len())));
                    pending.extend(items.iter().rev().map(TypedCloneTask::Expr));
                }
                ExprKind::ListComprehension {
                    expression,
                    item,
                    source,
                    condition,
                } => {
                    pending.push(TypedCloneTask::BuildKind(
                        TypedKindClone::ListComprehension {
                            item,
                            has_condition: condition.is_some(),
                        },
                    ));
                    if let Some(condition) = condition {
                        pending.push(TypedCloneTask::Expr(condition));
                    }
                    pending.push(TypedCloneTask::Expr(source));
                    pending.push(TypedCloneTask::Expr(expression));
                }
                ExprKind::JsonObject(entries) => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::JsonObject(
                        entries,
                    )));
                    pending.extend(
                        entries
                            .iter()
                            .rev()
                            .map(|(_, expr)| TypedCloneTask::Expr(expr)),
                    );
                }
                ExprKind::JsonArray(items) => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::JsonArray(
                        items.len(),
                    )));
                    pending.extend(items.iter().rev().map(TypedCloneTask::Expr));
                }
                ExprKind::Member { object, field } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Member(field)));
                    pending.push(TypedCloneTask::Expr(object));
                }
                ExprKind::Index { target, index } => {
                    pending.push(TypedCloneTask::BuildKind(TypedKindClone::Index));
                    pending.push(TypedCloneTask::Expr(index));
                    pending.push(TypedCloneTask::Expr(target));
                }
                ExprKind::VariantCode(value) => {
                    values.push(TypedCloneValue::Kind(ExprKind::VariantCode(*value)));
                }
                ExprKind::IntLiteral(value) => {
                    values.push(TypedCloneValue::Kind(ExprKind::IntLiteral(value.clone())));
                }
                ExprKind::DecimalLiteral { value, spelling } => {
                    values.push(TypedCloneValue::Kind(ExprKind::DecimalLiteral {
                        value: value.clone(),
                        spelling: spelling.clone(),
                    }));
                }
                ExprKind::Bool(value) => {
                    values.push(TypedCloneValue::Kind(ExprKind::Bool(*value)));
                }
                ExprKind::String(value) => {
                    values.push(TypedCloneValue::Kind(ExprKind::String(value.clone())));
                }
                ExprKind::Bytes(value) => {
                    values.push(TypedCloneValue::Kind(ExprKind::Bytes(value.clone())));
                }
                ExprKind::Ident(value) => {
                    values.push(TypedCloneValue::Kind(ExprKind::Ident(value.clone())));
                }
            },
            TypedCloneTask::Statement(statement) => match statement {
                TypedStatement::Let { name, value } => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::Let(
                        name,
                    )));
                    pending.push(TypedCloneTask::Expr(value));
                }
                TypedStatement::Expr(expr) => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::Expr));
                    pending.push(TypedCloneTask::Expr(expr));
                }
                TypedStatement::Return(value) => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::Return(
                        value.is_some(),
                    )));
                    if let Some(value) = value {
                        pending.push(TypedCloneTask::Expr(value));
                    }
                }
                TypedStatement::Break => {
                    values.push(TypedCloneValue::Statement(TypedStatement::Break));
                }
                TypedStatement::Continue => {
                    values.push(TypedCloneValue::Statement(TypedStatement::Continue));
                }
                TypedStatement::If {
                    cond,
                    then_branch,
                    else_branch,
                } => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::If(
                        else_branch.is_some(),
                    )));
                    if let Some(else_branch) = else_branch {
                        pending.push(TypedCloneTask::Block(else_branch));
                    }
                    pending.push(TypedCloneTask::Block(then_branch));
                    pending.push(TypedCloneTask::Expr(cond));
                }
                TypedStatement::IfLet {
                    pattern,
                    value,
                    then_branch,
                    else_branch,
                } => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::IfLet(
                        pattern,
                        else_branch.is_some(),
                    )));
                    if let Some(else_branch) = else_branch {
                        pending.push(TypedCloneTask::Block(else_branch));
                    }
                    pending.push(TypedCloneTask::Block(then_branch));
                    pending.push(TypedCloneTask::Expr(value));
                }
                TypedStatement::While { cond, body } => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::While));
                    pending.push(TypedCloneTask::Block(body));
                    pending.push(TypedCloneTask::Expr(cond));
                }
                TypedStatement::For {
                    line,
                    init,
                    cond,
                    step,
                    body,
                } => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::For {
                        line: *line,
                        has_init: init.is_some(),
                        has_cond: cond.is_some(),
                        has_step: step.is_some(),
                    }));
                    pending.push(TypedCloneTask::Block(body));
                    if let Some(step) = step {
                        pending.push(TypedCloneTask::Statement(step));
                    }
                    if let Some(cond) = cond {
                        pending.push(TypedCloneTask::Expr(cond));
                    }
                    if let Some(init) = init {
                        pending.push(TypedCloneTask::Statement(init));
                    }
                }
                TypedStatement::ForEachMap {
                    key,
                    value,
                    map,
                    body,
                } => {
                    pending.push(TypedCloneTask::BuildStatement(
                        TypedStatementClone::ForEachMap { key, value },
                    ));
                    pending.push(TypedCloneTask::Block(body));
                    pending.push(TypedCloneTask::Expr(map));
                }
                TypedStatement::MapSet { map, key, value } => {
                    pending.push(TypedCloneTask::BuildStatement(TypedStatementClone::MapSet));
                    pending.push(TypedCloneTask::Expr(value));
                    pending.push(TypedCloneTask::Expr(key));
                    pending.push(TypedCloneTask::Expr(map));
                }
            },
            TypedCloneTask::Block(block) => {
                pending.push(TypedCloneTask::BuildBlock {
                    statement_count: block.statements.len(),
                    has_tail: block.tail.is_some(),
                    provenance: &block.provenance,
                });
                if let Some(tail) = &block.tail {
                    pending.push(TypedCloneTask::Expr(tail));
                }
                pending.extend(block.statements.iter().rev().map(TypedCloneTask::Statement));
            }
            TypedCloneTask::MatchArm(arm) => {
                pending.push(TypedCloneTask::BuildMatchArm(&arm.pattern));
                pending.push(TypedCloneTask::Block(&arm.body));
            }
            TypedCloneTask::BuildExpr(ty) => {
                let expr = pop_cloned_kind(&mut values);
                values.push(TypedCloneValue::Expr(TypedExpr {
                    expr,
                    ty: ty.clone(),
                }));
            }
            TypedCloneTask::BuildKind(kind) => {
                let kind = match kind {
                    TypedKindClone::Binary(op) => {
                        let right = pop_cloned_expr(&mut values);
                        let left = pop_cloned_expr(&mut values);
                        ExprKind::Binary {
                            op,
                            left: Box::new(left),
                            right: Box::new(right),
                        }
                    }
                    TypedKindClone::Unary(op) => ExprKind::Unary {
                        op,
                        expr: Box::new(pop_cloned_expr(&mut values)),
                    },
                    TypedKindClone::NumericCast => ExprKind::NumericCast {
                        expr: Box::new(pop_cloned_expr(&mut values)),
                    },
                    TypedKindClone::NumericTryCast => ExprKind::NumericTryCast {
                        expr: Box::new(pop_cloned_expr(&mut values)),
                    },
                    TypedKindClone::Conditional => {
                        let else_expr = pop_cloned_expr(&mut values);
                        let then_expr = pop_cloned_expr(&mut values);
                        let cond = pop_cloned_expr(&mut values);
                        ExprKind::Conditional {
                            cond: Box::new(cond),
                            then_expr: Box::new(then_expr),
                            else_expr: Box::new(else_expr),
                        }
                    }
                    TypedKindClone::If => {
                        let else_branch = pop_cloned_block(&mut values);
                        let then_branch = pop_cloned_block(&mut values);
                        let condition = pop_cloned_expr(&mut values);
                        ExprKind::If {
                            condition: Box::new(condition),
                            then_branch,
                            else_branch,
                        }
                    }
                    TypedKindClone::IfLet(pattern) => {
                        let else_branch = pop_cloned_block(&mut values);
                        let then_branch = pop_cloned_block(&mut values);
                        let value = pop_cloned_expr(&mut values);
                        ExprKind::IfLet {
                            pattern: pattern.clone(),
                            value: Box::new(value),
                            then_branch,
                            else_branch,
                        }
                    }
                    TypedKindClone::Match(arm_count) => {
                        let arms = pop_cloned_match_arms(&mut values, arm_count);
                        let value = pop_cloned_expr(&mut values);
                        ExprKind::Match {
                            value: Box::new(value),
                            arms,
                        }
                    }
                    TypedKindClone::OptionSome => ExprKind::OptionSome {
                        value: Box::new(pop_cloned_expr(&mut values)),
                    },
                    TypedKindClone::ResultOk => ExprKind::ResultOk {
                        value: Box::new(pop_cloned_expr(&mut values)),
                    },
                    TypedKindClone::ResultErr => ExprKind::ResultErr {
                        error: Box::new(pop_cloned_expr(&mut values)),
                    },
                    TypedKindClone::Propagate => ExprKind::Propagate {
                        value: Box::new(pop_cloned_expr(&mut values)),
                    },
                    TypedKindClone::Call(name, len) => ExprKind::Call {
                        target: name.to_owned(),
                        args: pop_cloned_exprs(&mut values, len),
                    },
                    TypedKindClone::NamedCall(name, len, evaluation_order) => ExprKind::NamedCall {
                        target: name.to_owned(),
                        args: pop_cloned_exprs(&mut values, len),
                        evaluation_order: evaluation_order.to_vec(),
                    },
                    TypedKindClone::StructLiteral(name, fields) => {
                        let expressions = pop_cloned_exprs(&mut values, fields.len());
                        ExprKind::StructLiteral {
                            name: name.to_owned(),
                            fields: fields
                                .iter()
                                .zip(expressions)
                                .map(|((name, _), expr)| (name.clone(), expr))
                                .collect(),
                        }
                    }
                    TypedKindClone::Tuple(len) => {
                        ExprKind::Tuple(pop_cloned_exprs(&mut values, len))
                    }
                    TypedKindClone::List(len) => ExprKind::List(pop_cloned_exprs(&mut values, len)),
                    TypedKindClone::ListComprehension {
                        item,
                        has_condition,
                    } => {
                        let condition =
                            has_condition.then(|| Box::new(pop_cloned_expr(&mut values)));
                        let source = pop_cloned_expr(&mut values);
                        let expression = pop_cloned_expr(&mut values);
                        ExprKind::ListComprehension {
                            expression: Box::new(expression),
                            item: item.to_owned(),
                            source: Box::new(source),
                            condition,
                        }
                    }
                    TypedKindClone::JsonObject(entries) => {
                        let expressions = pop_cloned_exprs(&mut values, entries.len());
                        ExprKind::JsonObject(
                            entries
                                .iter()
                                .zip(expressions)
                                .map(|((name, _), expr)| (name.clone(), expr))
                                .collect(),
                        )
                    }
                    TypedKindClone::JsonArray(len) => {
                        ExprKind::JsonArray(pop_cloned_exprs(&mut values, len))
                    }
                    TypedKindClone::Member(field) => ExprKind::Member {
                        object: Box::new(pop_cloned_expr(&mut values)),
                        field: field.to_owned(),
                    },
                    TypedKindClone::Index => {
                        let index = pop_cloned_expr(&mut values);
                        let target = pop_cloned_expr(&mut values);
                        ExprKind::Index {
                            target: Box::new(target),
                            index: Box::new(index),
                        }
                    }
                };
                values.push(TypedCloneValue::Kind(kind));
            }
            TypedCloneTask::BuildStatement(statement) => {
                let statement = match statement {
                    TypedStatementClone::Let(name) => TypedStatement::Let {
                        name: name.to_owned(),
                        value: pop_cloned_expr(&mut values),
                    },
                    TypedStatementClone::Expr => TypedStatement::Expr(pop_cloned_expr(&mut values)),
                    TypedStatementClone::Return(has_value) => {
                        TypedStatement::Return(has_value.then(|| pop_cloned_expr(&mut values)))
                    }
                    TypedStatementClone::If(has_else) => {
                        let else_branch = has_else.then(|| pop_cloned_block(&mut values));
                        let then_branch = pop_cloned_block(&mut values);
                        let cond = pop_cloned_expr(&mut values);
                        TypedStatement::If {
                            cond,
                            then_branch,
                            else_branch,
                        }
                    }
                    TypedStatementClone::IfLet(pattern, has_else) => {
                        let else_branch = has_else.then(|| pop_cloned_block(&mut values));
                        let then_branch = pop_cloned_block(&mut values);
                        let value = pop_cloned_expr(&mut values);
                        TypedStatement::IfLet {
                            pattern: pattern.clone(),
                            value,
                            then_branch,
                            else_branch,
                        }
                    }
                    TypedStatementClone::While => {
                        let body = pop_cloned_block(&mut values);
                        let cond = pop_cloned_expr(&mut values);
                        TypedStatement::While { cond, body }
                    }
                    TypedStatementClone::For {
                        line,
                        has_init,
                        has_cond,
                        has_step,
                    } => {
                        let body = pop_cloned_block(&mut values);
                        let step = has_step.then(|| Box::new(pop_cloned_statement(&mut values)));
                        let cond = has_cond.then(|| pop_cloned_expr(&mut values));
                        let init = has_init.then(|| Box::new(pop_cloned_statement(&mut values)));
                        TypedStatement::For {
                            line,
                            init,
                            cond,
                            step,
                            body,
                        }
                    }
                    TypedStatementClone::ForEachMap { key, value } => {
                        let body = pop_cloned_block(&mut values);
                        let map = pop_cloned_expr(&mut values);
                        TypedStatement::ForEachMap {
                            key: key.to_owned(),
                            value: value.clone(),
                            map,
                            body,
                        }
                    }
                    TypedStatementClone::MapSet => {
                        let value = pop_cloned_expr(&mut values);
                        let key = pop_cloned_expr(&mut values);
                        let map = pop_cloned_expr(&mut values);
                        TypedStatement::MapSet {
                            map,
                            key,
                            value: Box::new(value),
                        }
                    }
                };
                values.push(TypedCloneValue::Statement(statement));
            }
            TypedCloneTask::BuildBlock {
                statement_count,
                has_tail,
                provenance,
            } => {
                let tail = has_tail.then(|| Box::new(pop_cloned_expr(&mut values)));
                let statements = pop_cloned_statements(&mut values, statement_count);
                values.push(TypedCloneValue::Block(TypedBlock {
                    statements,
                    tail,
                    provenance: provenance.clone(),
                }));
            }
            TypedCloneTask::BuildMatchArm(pattern) => {
                let body = pop_cloned_block(&mut values);
                values.push(TypedCloneValue::MatchArm(TypedMatchArm {
                    pattern: pattern.clone(),
                    body,
                }));
            }
        }
    }
    assert_eq!(values.len(), 1, "typed clone traversal produces one root");
    values.pop().expect("typed clone traversal root")
}

impl Clone for ExprKind {
    fn clone(&self) -> Self {
        match clone_typed_semantic(TypedCloneTask::Kind(self)) {
            TypedCloneValue::Kind(value) => value,
            _ => unreachable!("expression-kind clone produces an expression kind"),
        }
    }
}

impl std::fmt::Debug for TypedStatement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Let { .. } => "Let(..)",
            Self::Expr(_) => "Expr(..)",
            Self::Return(_) => "Return(..)",
            Self::Break => "Break",
            Self::Continue => "Continue",
            Self::If { .. } => "If(..)",
            Self::IfLet { .. } => "IfLet(..)",
            Self::While { .. } => "While(..)",
            Self::For { .. } => "For(..)",
            Self::ForEachMap { .. } => "ForEachMap(..)",
            Self::MapSet { .. } => "MapSet(..)",
        })
    }
}
impl PartialEq for TypedStatement {
    fn eq(&self, other: &Self) -> bool {
        typed_semantic_eq(TypedEq::Statement(self, other))
    }
}
impl Clone for TypedStatement {
    fn clone(&self) -> Self {
        match clone_typed_semantic(TypedCloneTask::Statement(self)) {
            TypedCloneValue::Statement(value) => value,
            _ => unreachable!("statement clone produces a statement"),
        }
    }
}

fn core_query_view_name(ty: &Type) -> Option<&str> {
    let Type::Struct { name, .. } = ty else {
        return None;
    };
    let source_name = name.strip_prefix("kotodama::")?;
    let builtin = match source_name {
        "AccountView" => Builtin::QueryGetAccount,
        "AssetView" => Builtin::QueryGetAsset,
        "AssetDefinitionView" => Builtin::QueryGetAssetDefinition,
        "DomainView" => Builtin::QueryGetDomain,
        "NftView" => Builtin::QueryGetNft,
        _ => return None,
    };
    (core_query_view_type(builtin).as_ref() == Some(ty)).then_some(source_name)
}
pub(crate) fn type_name(ty: &Type) -> String {
    match ty {
        Type::Int => "int".into(),
        Type::Decimal => "decimal".into(),
        Type::Quantity => "quantity".into(),
        Type::Bool => "bool".into(),
        Type::String => "string".into(),
        Type::Bytes => "bytes".into(),
        Type::DataSpaceId => "DataSpaceId".into(),
        Type::AxtDescriptor => "AxtDescriptor".into(),
        Type::AxtAnchoredSpendV1 => "AxtAnchoredSpendV1".into(),
        Type::ProofBlob => "ProofBlob".into(),
        Type::SoracloudRequest => "SoracloudRequest".into(),
        Type::SoracloudResponse => "SoracloudResponse".into(),
        Type::AccountId => "AccountId".into(),
        Type::AssetDefinitionId => "AssetDefinitionId".into(),
        Type::AssetId => "AssetId".into(),
        Type::NftId => "NftId".into(),
        Type::DomainId => "DomainId".into(),
        Type::Name => "Name".into(),
        Type::Json => "Json".into(),
        Type::Unit => "()".into(),
        Type::Enum(descriptor) => descriptor.identity.clone(),
        Type::ErrorEnum(descriptor) => descriptor.identity.clone(),
        Type::Secret(inner) => format!("Secret<{}>", type_name(inner)),
        Type::StateMap(k, v) => format!("StateMap<{}, {}>", type_name(k), type_name(v)),
        Type::StateCursor(key) => format!("StateCursor<{}>", type_name(key)),
        Type::Option(inner) => format!("Option<{}>", type_name(inner)),
        Type::Result(ok, err) => format!("Result<{}, {}>", type_name(ok), type_name(err)),
        Type::List(element, capacity) => {
            format!("List<{}, {capacity}>", type_name(element))
        }
        Type::Tuple(ts) => {
            let parts: Vec<String> = ts.iter().map(type_name).collect();
            format!("({})", parts.join(", "))
        }
        Type::Struct { .. } if state_page_components(ty).is_some() => {
            let (key, value, capacity) =
                state_page_components(ty).expect("checked StatePage shape");
            format!(
                "StatePage<{}, {}, {capacity}>",
                type_name(key),
                type_name(value)
            )
        }
        Type::Struct { name, .. } => query_page_view_type(ty)
            .and_then(core_query_view_name)
            .map_or_else(
                || core_query_view_name(ty).map_or_else(|| format!("struct {name}"), str::to_owned),
                |view_name| format!("{QUERY_PAGE_TYPE_NAME}<{view_name}>"),
            ),
        Type::ContractRef(contract) => format!("contract {}", contract.interface.seiyaku_name),
        Type::NamedStruct(s) => s.clone(),
    }
}
/// Render `ty` as a valid source annotation.
///
/// ABI descriptors derive their canonical names from their exact recursive
/// schemas at the compiler boundary; this helper deliberately renders ordinary
/// structs without the schema-only `struct ` prefix.
pub fn render_type_name(ty: &Type) -> String {
    // The renderer and structural equality checks traverse explicit work lists.
    render_source_type_name(ty)
}
pub(super) fn render_source_type_name(ty: &Type) -> String {
    enum Pending<'a> {
        Type(&'a Type),
        Text(&'static str),
        Owned(String),
    }

    let mut rendered = String::new();
    let mut pending = vec![Pending::Type(ty)];
    while let Some(part) = pending.pop() {
        match part {
            Pending::Text(text) => rendered.push_str(text),
            Pending::Owned(text) => rendered.push_str(&text),
            Pending::Type(ty) => match ty {
                Type::Int => rendered.push_str("int"),
                Type::Decimal => rendered.push_str("decimal"),
                Type::Quantity => rendered.push_str("quantity"),
                Type::Bool => rendered.push_str("bool"),
                Type::String => rendered.push_str("string"),
                Type::Bytes => rendered.push_str("bytes"),
                Type::DataSpaceId => rendered.push_str("DataSpaceId"),
                Type::AxtDescriptor => rendered.push_str("AxtDescriptor"),
                Type::AxtAnchoredSpendV1 => rendered.push_str("AxtAnchoredSpendV1"),
                Type::ProofBlob => rendered.push_str("ProofBlob"),
                Type::SoracloudRequest => rendered.push_str("SoracloudRequest"),
                Type::SoracloudResponse => rendered.push_str("SoracloudResponse"),
                Type::AccountId => rendered.push_str("AccountId"),
                Type::AssetDefinitionId => rendered.push_str("AssetDefinitionId"),
                Type::AssetId => rendered.push_str("AssetId"),
                Type::NftId => rendered.push_str("NftId"),
                Type::DomainId => rendered.push_str("DomainId"),
                Type::Name => rendered.push_str("Name"),
                Type::Json => rendered.push_str("Json"),
                Type::Unit => rendered.push_str("()"),
                Type::Enum(descriptor) => rendered.push_str(
                    descriptor
                        .identity
                        .rsplit("::")
                        .next()
                        .unwrap_or(&descriptor.identity),
                ),
                Type::ErrorEnum(descriptor) => rendered.push_str(
                    descriptor
                        .identity
                        .rsplit("::")
                        .next()
                        .unwrap_or(&descriptor.identity),
                ),
                Type::Secret(inner) => {
                    rendered.push_str("Secret<");
                    pending.push(Pending::Text(">"));
                    pending.push(Pending::Type(inner));
                }
                Type::StateMap(key, value) => {
                    rendered.push_str("StateMap<");
                    pending.push(Pending::Text(">"));
                    pending.push(Pending::Type(value));
                    pending.push(Pending::Text(", "));
                    pending.push(Pending::Type(key));
                }
                Type::StateCursor(inner) => {
                    rendered.push_str("StateCursor<");
                    pending.push(Pending::Text(">"));
                    pending.push(Pending::Type(inner));
                }
                Type::Option(inner) => {
                    rendered.push_str("Option<");
                    pending.push(Pending::Text(">"));
                    pending.push(Pending::Type(inner));
                }
                Type::Result(ok, error) => {
                    rendered.push_str("Result<");
                    pending.push(Pending::Text(">"));
                    pending.push(Pending::Type(error));
                    pending.push(Pending::Text(", "));
                    pending.push(Pending::Type(ok));
                }
                Type::List(element, capacity) => {
                    rendered.push_str("List<");
                    pending.push(Pending::Text(">"));
                    pending.push(Pending::Owned(format!(", {capacity}")));
                    pending.push(Pending::Type(element));
                }
                Type::Tuple(items) => {
                    rendered.push('(');
                    pending.push(Pending::Text(")"));
                    for (index, item) in items.iter().enumerate().rev() {
                        pending.push(Pending::Type(item));
                        if index > 0 {
                            pending.push(Pending::Text(", "));
                        }
                    }
                }
                Type::Struct { name, .. } => {
                    if let Some((key, value, capacity)) = state_page_components(ty) {
                        rendered.push_str("StatePage<");
                        pending.push(Pending::Owned(format!(", {capacity}>")));
                        pending.push(Pending::Type(value));
                        pending.push(Pending::Text(", "));
                        pending.push(Pending::Type(key));
                        continue;
                    }
                    let name = query_page_view_type(ty)
                        .and_then(core_query_view_name)
                        .map_or_else(
                            || core_query_view_name(ty).map_or_else(|| name.clone(), str::to_owned),
                            |view| format!("QueryPage<{view}>"),
                        );
                    rendered.push_str(&name);
                }
                Type::ContractRef(contract) => rendered.push_str(&contract.interface.seiyaku_name),
                Type::NamedStruct(name) => rendered.push_str(name),
            },
        }
    }
    rendered
}
