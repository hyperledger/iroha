//! Generated Kotodama V1 source policy and the reserved-name predicates.
//!
//! The tables between the `GENERATED` markers are rendered by
//! `scripts/regenerate_kotodama_syntax.py` from the canonical syntax
//! description. The compiler, editor tooling and contract admission all
//! consult the same predicates, so a declaration the compiler rejects as
//! reserved is also rejected when an artifact's source metadata is admitted.

use crate::builtins::Builtin;

// BEGIN GENERATED: kotodama-v1-semantic-policy
/// Canonical source-level type spellings offered by language tooling.
pub const V1_SOURCE_TYPE_NAMES: &[&str] = &[
    "int",
    "decimal",
    "quantity",
    "bool",
    "string",
    "bytes",
    "Json",
    "AccountId",
    "AssetDefinitionId",
    "AssetId",
    "DomainId",
    "Name",
    "NftId",
    "DataSpaceId",
    "Option",
    "Result",
    "List",
    "ListError",
    "NumericError",
    "StateMap",
    "StateCursor",
    "StatePage",
    "Secret",
    "AccountView",
    "AssetView",
    "AssetDefinitionView",
    "DomainView",
    "NftView",
    "QueryPage",
];
/// Compiler-owned non-keyword names forbidden for source declarations.
pub const V1_DECLARATION_RESERVED_EXTRA_NAMES: &[&str] = &[
    "AxtDescriptor",
    "AxtAnchoredSpendV1",
    "ProofBlob",
    "SoracloudRequest",
    "SoracloudResponse",
    "state_map_get",
    "__kotodama_state_page",
    "__kotodama_state_take",
    "__kotodama_list_len",
    "__kotodama_list_get",
    "__kotodama_list_set",
    "__kotodama_list_push",
    "__kotodama_list_try_set",
    "__kotodama_list_try_push",
    "__kotodama_list_pop",
    "__kotodama_list_contains",
    "__kotodama_list_take",
    "__kotodama_list_enumerate",
    "__kotodama_decimal_div_round",
    "__kotodama_decimal_mul_div_round",
    "__kotodama_quantity_mul_div_round",
    "__kotodama_quantity_div_round",
    "__kotodama_quantity_ratio_round",
    "__kotodama_decimal_to_int_trunc",
    "__kotodama_decimal_to_int_round",
    "__kotodama_option_ok_or",
    "__kotodama_result_or_err",
];
/// Exact identifier spellings forbidden in every source position.
pub const V1_FORBIDDEN_SOURCE_IDENTIFIERS: &[&str] = &["Amount"];
/// Exact canonical scalar types permitted as durable `StateMap` keys.
pub const V1_STATE_MAP_KEY_TYPE_NAMES: &[&str] = &[
    "int",
    "decimal",
    "quantity",
    "bool",
    "string",
    "bytes",
    "DataSpaceId",
    "AccountId",
    "AssetDefinitionId",
    "AssetId",
    "NftId",
    "DomainId",
    "Name",
];
/// Canonical bounded `StateMap` scan provenance in manifest order.
pub const V1_DYNAMIC_ACCESS_BOUND_KINDS: &[&str] = &["page", "take"];
/// Maximum keys advertised by one bounded dynamic-access hint.
pub const V1_DYNAMIC_ACCESS_MAX_KEYS: u32 = 64;
/// Canonical prefix for a direct durable `StateMap` hint base.
pub const V1_DYNAMIC_ACCESS_BASE_PREFIX: &str = "state:";
/// Canonical validation policy for the `StateMap` base identifier.
pub const V1_DYNAMIC_ACCESS_BASE_IDENTIFIER_POLICY: &str = "state_declaration_identifier";
/// Dynamic hints may refer only to a directly declared top-level `StateMap`.
pub const V1_DYNAMIC_ACCESS_REQUIRES_DECLARED_STATE_MAP: bool = true;
/// Dynamic hints are advisory and never scheduler-authoritative in V1.
pub const V1_DYNAMIC_ACCESS_SCHEDULER_AUTHORITATIVE: bool = false;
/// Retired pre-release numeric type spellings that remain reserved in V1.
///
/// Keeping these names unavailable to source-unit identities and declared
/// types prevents authenticated metadata from reinterpreting a known retired
/// type spelling. Except for exact spellings in
/// `V1_FORBIDDEN_SOURCE_IDENTIFIERS`, they remain ordinary names in value and
/// function namespaces, including entrypoints.
pub const V1_RETIRED_NUMERIC_TYPE_NAMES: &[&str] = &[
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "num",
    "Int",
    "Integer",
    "float",
    "f32",
    "f64",
    "Decimal",
    "Fixed",
    "FixedPoint",
    "Amount",
    "amount",
    "money",
    "Quantity",
    "number",
];
/// Canonical active-only sum constructor and pattern paths.
pub const V1_SUM_PATHS: &[&str] = &["Option::some", "Option::none", "Result::ok", "Result::err"];
/// Canonical explicit exact-decimal rounding modes.
pub const V1_ROUNDING_PATHS: &[&str] = &[
    "Rounding::toward_zero",
    "Rounding::away_from_zero",
    "Rounding::floor",
    "Rounding::ceil",
    "Rounding::nearest_even",
    "Rounding::nearest_away",
    "Rounding::nearest_toward_zero",
];
/// Canonical bounded-list member API.
pub const V1_LIST_MEMBER_NAMES: &[&str] = &[
    "len",
    "get",
    "set",
    "push",
    "try_set",
    "try_push",
    "pop",
    "contains",
    "take",
    "enumerate",
];
// END GENERATED: kotodama-v1-semantic-policy
/// Prefix reserved for linker-synthesised symbols.
pub const LINKED_SYMBOL_PREFIX: &str = "__kotodama_link_";
/// Return whether a source declaration collides with compiler-owned names.
///
/// Only names source code can refer to are reserved: types, keywords handled
/// by the lexer, compiler-owned extras and unnamespaced source builtins such
/// as `require`. Compiler-internal lowering spellings (`min`, `authority`,
/// `mint_asset`, ...) are not source names. All source functions may use them:
/// typed calls retain separate user, builtin and compiler-intrinsic identities.
pub fn is_reserved_source_declaration(name: &str, is_function: bool) -> bool {
    name.starts_with(LINKED_SYMBOL_PREFIX)
        || V1_SOURCE_TYPE_NAMES.contains(&name)
        || V1_DECLARATION_RESERVED_EXTRA_NAMES.contains(&name)
        || V1_FORBIDDEN_SOURCE_IDENTIFIERS.contains(&name)
        || is_compile_time_nominal_type(name)
        || (is_function && Builtin::from_source_name(name).is_some())
}
/// Return whether `name` is a compiler-owned compile-time value type such as
/// `Mintable`, whose values (`Mintable::Once`) are builtin arguments.
///
/// The set is derived from the builtin registry, so a declaration can never
/// shadow the namespace of a nominal value the compiler folds.
pub fn is_compile_time_nominal_type(name: &str) -> bool {
    Builtin::all()
        .any(|builtin| builtin.is_compile_time_nominal() && builtin.signature().return_type == name)
}
/// Return whether a declared source type collides with an active or retired
/// compiler-owned type spelling.
///
/// Retired scalar spellings remain forbidden in type position. Except for the
/// exact globally forbidden source identifiers, names such as `amount`, `money`,
/// and `number` remain ordinary parameters, locals, functions, and entrypoints.
pub fn is_reserved_source_type_declaration(name: &str) -> bool {
    is_reserved_source_declaration(name, false) || V1_RETIRED_NUMERIC_TYPE_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_source_visible_builtin_names_are_reserved_for_functions() {
        assert!(is_reserved_source_declaration("require", true));
        assert!(!is_reserved_source_declaration("require", false));
        for name in [
            "min",
            "max",
            "authority",
            "chain_id",
            "mint_asset",
            "burn_asset",
            "grant_role",
            "register_account",
            "info",
            "name",
            "is_some",
            "expect",
        ] {
            assert!(!is_reserved_source_declaration(name, true), "{name}");
        }
    }

    #[test]
    fn compile_time_nominal_types_are_reserved() {
        for name in ["NumericSpec", "Mintable", "SignatureScheme"] {
            assert!(is_compile_time_nominal_type(name), "{name}");
            assert!(is_reserved_source_declaration(name, false), "{name}");
            assert!(is_reserved_source_type_declaration(name), "{name}");
        }
        assert!(!is_compile_time_nominal_type("Rounding"));
        assert!(!is_compile_time_nominal_type("Vault"));
    }

    #[test]
    fn retired_numeric_type_names_are_reserved_only_as_types() {
        assert!(!V1_RETIRED_NUMERIC_TYPE_NAMES.is_empty());
        for &name in V1_RETIRED_NUMERIC_TYPE_NAMES {
            assert!(is_reserved_source_type_declaration(name), "{name}");
            if V1_FORBIDDEN_SOURCE_IDENTIFIERS.contains(&name) {
                continue;
            }
            assert!(!is_reserved_source_declaration(name, true), "{name}");
            assert!(!is_reserved_source_declaration(name, false), "{name}");
        }
    }

    #[test]
    fn linked_symbol_prefix_is_always_reserved() {
        let name = format!("{LINKED_SYMBOL_PREFIX}p0_m0_f0");
        assert!(is_reserved_source_declaration(&name, true));
        assert!(is_reserved_source_declaration(&name, false));
        assert!(is_reserved_source_type_declaration(&name));
    }

    #[test]
    fn source_type_names_are_always_reserved() {
        for &name in V1_SOURCE_TYPE_NAMES {
            assert!(is_reserved_source_declaration(name, true), "{name}");
            assert!(is_reserved_source_declaration(name, false), "{name}");
            assert!(is_reserved_source_type_declaration(name), "{name}");
        }
    }

    #[test]
    fn amount_is_always_reserved() {
        assert_eq!(V1_FORBIDDEN_SOURCE_IDENTIFIERS, &["Amount"]);
        assert!(is_reserved_source_declaration("Amount", true));
        assert!(is_reserved_source_declaration("Amount", false));
        assert!(is_reserved_source_type_declaration("Amount"));
    }

    #[test]
    fn ordinary_names_are_not_reserved() {
        for name in ["amount", "total", "__kotodama_user_binding"] {
            assert!(!is_reserved_source_declaration(name, true), "{name}");
            assert!(!is_reserved_source_declaration(name, false), "{name}");
        }
    }
}
