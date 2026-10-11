//! Site-specific wording for common type errors.
//!
//! Messages name operators by their source symbols and types in source syntax.
//! Help text is chosen per operator row so that each rejected combination
//! points at the explicit conversion or operand order the numeric table
//! actually defines (`specs/kotodama_numeric_v1.md`).
use super::{Type, render_type_name, resolve_struct_type};
use crate::ast::{AssignOp, BinaryOp};

/// Source spelling of a binary operator.
pub(crate) const fn binary_symbol(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::And => "&&",
        BinaryOp::Or => "||",
        BinaryOp::Eq => "==",
        BinaryOp::Ne => "!=",
        BinaryOp::Lt => "<",
        BinaryOp::Le => "<=",
        BinaryOp::Gt => ">",
        BinaryOp::Ge => ">=",
    }
}

/// Source spelling of a compound assignment operator.
pub(crate) const fn assign_symbol(op: AssignOp) -> &'static str {
    match op {
        AssignOp::Set => "=",
        AssignOp::Add => "+=",
        AssignOp::Sub => "-=",
        AssignOp::Mul => "*=",
        AssignOp::Div => "/=",
        AssignOp::Mod => "%=",
    }
}

/// A type in source syntax, quoted for a diagnostic.
pub(crate) fn quoted(ty: &Type) -> String {
    format!("`{}`", render_type_name(ty))
}

/// Message for an arithmetic operator the numeric table does not define.
pub(crate) fn operator_message(symbol: &str, left: &Type, right: &Type) -> String {
    format!(
        "operator `{symbol}` is not defined for {} and {}",
        quoted(left),
        quoted(right)
    )
}

/// Help for one rejected arithmetic row of the numeric operator table.
pub(crate) fn operator_help(op: BinaryOp, left: &Type, right: &Type) -> String {
    let left = resolve_struct_type(left);
    let right = resolve_struct_type(right);
    let symbol = binary_symbol(op);
    let numeric = |ty: &Type| matches!(ty, Type::Int | Type::Decimal | Type::Quantity);
    match (op, &left, &right) {
        (BinaryOp::Mod, Type::Quantity | Type::Decimal, _)
        | (BinaryOp::Mod, _, Type::Quantity | Type::Decimal) => {
            "`%` is defined only for `int`. For `decimal` and `quantity`, divide with an explicit \
             rounding mode, for example `value.div_round(divisor: d, scale: 6, mode: Rounding::floor)`."
                .to_owned()
        }
        (BinaryOp::Mul | BinaryOp::Div, Type::Decimal | Type::Int, Type::Quantity) => format!(
            "Scaling keeps the `quantity` on the left: `quantity {symbol} decimal` is defined, \
             `{} {symbol} quantity` is not. Swap the operands{}.",
            render_type_name(&left),
            if left == Type::Int {
                " and convert a runtime `int` factor with `decimal::from_int(value)`; an exact literal such as `q * 2` converts automatically"
            } else {
                ""
            }
        ),
        (BinaryOp::Mul | BinaryOp::Div, Type::Quantity, Type::Int) => format!(
            "Convert the `int` factor to a decimal first: `quantity {symbol} decimal::from_int(count)`. \
             Exact literal factors such as `q {symbol} 2` convert automatically."
        ),
        (BinaryOp::Mul, Type::Quantity, Type::Quantity) => {
            "Two quantities cannot be multiplied; turn one side into a ratio with \
             `decimal::from_quantity(value)` so the row is `quantity * decimal`."
                .to_owned()
        }
        (BinaryOp::Add | BinaryOp::Sub, Type::Quantity, Type::Int | Type::Decimal)
        | (BinaryOp::Add | BinaryOp::Sub, Type::Int | Type::Decimal, Type::Quantity) => {
            let other = if left == Type::Quantity { &right } else { &left };
            format!(
                "`quantity` adds and subtracts only with `quantity`. Convert the {} operand with \
                 `quantity::{}(value)?`, which fails for negative or out-of-range values.",
                quoted(other),
                if *other == Type::Int {
                    "try_from_int"
                } else {
                    "try_from_decimal"
                }
            )
        }
        _ if numeric(&left) && numeric(&right) => format!(
            "Arithmetic follows the exact numeric operator table; convert one operand explicitly \
             (`decimal::from_int`, `decimal::from_quantity`, `quantity::try_from_int`) so both \
             sides form a defined `{symbol}` row."
        ),
        _ => format!(
            "`{symbol}` needs numeric operands (`int`, `decimal` or `quantity`); found {} and {}.",
            quoted(&left),
            quoted(&right)
        ),
    }
}

/// Help for reading a field a struct does not declare: the closest declared
/// field when one is similar, otherwise the declared fields.
pub(crate) fn unknown_field_help(struct_name: &str, field: &str, declared: &[&str]) -> String {
    if let Some(suggestion) = crate::diagnostic::suggest::closest(field, declared.iter().copied()) {
        return format!("did you mean `{suggestion}`?");
    }
    if declared.is_empty() {
        return format!("struct `{struct_name}` declares no fields.");
    }
    let fields = declared
        .iter()
        .map(|field| format!("`{field}`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("struct `{struct_name}` declares {fields}; read one of those fields.")
}

/// Help for a source call to a public function of the seiyaku.
///
/// Public functions are entry points the runtime dispatches with an argument
/// record; source code reaches shared logic through a private `fn` instead.
pub(crate) fn runtime_entrypoint_call_help(name: &str) -> String {
    let kotoage = crate::glossary::by_spelling("kotoage").map_or_else(
        || "kotoage".to_owned(),
        crate::glossary::BrandedKeyword::label,
    );
    format!(
        "A {kotoage}, `view fn`, or lifecycle hook is invoked by the runtime with an argument \
         record, never from source. Move the body of `{name}` into a private `fn`, call that \
         helper here, and have `{name}` call it too."
    )
}

/// Concept words newcomers use as argument labels, mapped to the canonical
/// builtin parameter names. A synonym is suggested only when the callee
/// declares the canonical name.
const LABEL_SYNONYMS: &[(&str, &str)] = &[
    ("from", "source"),
    ("sender", "source"),
    ("to", "destination"),
    ("recipient", "destination"),
    ("receiver", "destination"),
    ("asset", "asset_definition"),
    ("definition", "asset_definition"),
    ("value", "amount"),
    ("quantity", "amount"),
];

/// Every argument label that names no declared parameter, in source order.
pub(crate) fn unknown_labels<'name>(
    labels: &'name [Option<String>],
    parameters: &[String],
) -> Vec<&'name str> {
    let mut unknown = Vec::new();
    for label in labels.iter().flatten() {
        if !parameters.iter().any(|parameter| parameter == label)
            && !unknown.contains(&label.as_str())
        {
            unknown.push(label.as_str());
        }
    }
    unknown
}

/// Message for one or more unknown argument labels.
pub(crate) fn unknown_labels_message(call: &str, unknown: &[&str]) -> String {
    let quoted = unknown
        .iter()
        .map(|label| format!("`{label}`"))
        .collect::<Vec<_>>();
    match quoted.as_slice() {
        [one] => format!("call `{call}` has no parameter named {one}"),
        [init @ .., last] => {
            format!(
                "call `{call}` has no parameters named {} or {last}",
                init.join(", ")
            )
        }
        [] => format!("call `{call}` has an unknown parameter label"),
    }
}

/// Suggest a declared parameter for each unknown label and list the declared names.
pub(crate) fn unknown_labels_help(call: &str, unknown: &[&str], parameters: &[String]) -> String {
    let mut parts = Vec::new();
    for label in unknown {
        let suggestion = LABEL_SYNONYMS
            .iter()
            .find(|(word, canonical)| {
                word == label && parameters.iter().any(|parameter| parameter == canonical)
            })
            .map(|(_, canonical)| (*canonical).to_owned())
            .or_else(|| {
                crate::diagnostic::suggest::closest(label, parameters.iter().map(String::as_str))
                    .map(str::to_owned)
            });
        if let Some(suggestion) = suggestion {
            parts.push(format!("`{label}:` is spelled `{suggestion}:`"));
        }
    }
    let declared = parameters
        .iter()
        .map(|parameter| format!("`{parameter}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let listing = if parameters.is_empty() {
        format!("`{call}` takes no labeled parameters.")
    } else {
        format!("`{call}` declares {declared}.")
    };
    if parts.is_empty() {
        listing
    } else {
        format!("{}. {listing}", parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_symbols_match_source_spelling() {
        assert_eq!(binary_symbol(BinaryOp::Mul), "*");
        assert_eq!(binary_symbol(BinaryOp::Ge), ">=");
        assert_eq!(assign_symbol(AssignOp::Add), "+=");
        assert_eq!(assign_symbol(AssignOp::Mod), "%=");
    }

    #[test]
    fn rejected_numeric_rows_receive_row_specific_help() {
        assert_eq!(
            operator_message("*", &Type::Int, &Type::Quantity),
            "operator `*` is not defined for `int` and `quantity`"
        );
        let help = operator_help(BinaryOp::Mul, &Type::Decimal, &Type::Quantity);
        assert!(help.contains("quantity * decimal"), "{help}");
        let help = operator_help(BinaryOp::Mul, &Type::Quantity, &Type::Int);
        assert!(help.contains("decimal::from_int(count)"), "{help}");
        let help = operator_help(BinaryOp::Add, &Type::Int, &Type::Quantity);
        assert!(help.contains("try_from_int"), "{help}");
        let help = operator_help(BinaryOp::Mod, &Type::Quantity, &Type::Quantity);
        assert!(help.contains("div_round"), "{help}");
        let help = operator_help(BinaryOp::Add, &Type::String, &Type::Int);
        assert!(help.contains("`string`"), "{help}");
    }

    #[test]
    fn unknown_fields_suggest_a_close_field_or_list_the_declared_ones() {
        assert_eq!(
            unknown_field_help("Account", "totl", &["total", "count"]),
            "did you mean `total`?"
        );
        assert_eq!(
            unknown_field_help("Point", "yy", &["x", "y"]),
            "struct `Point` declares `x`, `y`; read one of those fields."
        );
        assert_eq!(
            unknown_field_help("Unit", "x", &[]),
            "struct `Unit` declares no fields."
        );
    }

    #[test]
    fn runtime_entrypoint_calls_point_at_a_private_helper() {
        let help = runtime_entrypoint_call_help("quote");
        assert!(help.contains("kotoage (言挙げ)"), "{help}");
        assert!(
            help.contains("body of `quote` into a private `fn`"),
            "{help}"
        );
    }

    #[test]
    fn unknown_labels_are_all_reported_with_suggestions() {
        let parameters = [
            "source",
            "destination",
            "asset_definition",
            "amount",
            "dataspace",
        ]
        .map(str::to_owned);
        let labels = [
            Some("from".to_owned()),
            Some("to".to_owned()),
            Some("amount".to_owned()),
            Some("dataspac".to_owned()),
        ];
        let unknown = unknown_labels(&labels, &parameters);
        assert_eq!(unknown, ["from", "to", "dataspac"]);
        assert_eq!(
            unknown_labels_message("ledger::asset::transfer", &unknown),
            "call `ledger::asset::transfer` has no parameters named `from`, `to` or `dataspac`"
        );
        let help = unknown_labels_help("ledger::asset::transfer", &unknown, &parameters);
        assert!(help.contains("`from:` is spelled `source:`"), "{help}");
        assert!(help.contains("`to:` is spelled `destination:`"), "{help}");
        assert!(
            help.contains("`dataspac:` is spelled `dataspace:`"),
            "{help}"
        );
        assert!(help.contains("declares `source`, `destination`"), "{help}");
    }
}
