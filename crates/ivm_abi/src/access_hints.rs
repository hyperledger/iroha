//! Canonical validation for Kotodama V1 dynamic state-access hints.
//!
//! Dynamic hints are advisory scheduler metadata. They do not authorize an
//! access, but every producer and consumer must agree on one exact wire
//! vocabulary so malformed metadata cannot be interpreted differently.
use core::fmt;
use iroha_data_model::smart_contract::{
    entrypoint::is_canonical_kotodama_identifier, manifest::DynamicAccessHint,
};
// BEGIN GENERATED: kotodama-v1-dynamic-access-policy
/// Maximum number of keys a single V1 dynamic-access hint may cover.
pub const DYNAMIC_ACCESS_HINT_MAX_KEYS_V1: u32 = 64;
/// Exact Kotodama V1 `StateMap` key-type vocabulary, in ABI descriptor order.
pub const DYNAMIC_ACCESS_HINT_KEY_TYPES_V1: &[&str] = &[
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
/// Exact V1 sources of a statically proven dynamic-access bound.
pub const DYNAMIC_ACCESS_HINT_BOUND_KINDS_V1: &[&str] = &["page", "take"];
/// Exact keywords and compiler-reserved state declaration names.
pub const DYNAMIC_ACCESS_HINT_RESERVED_STATE_IDENTIFIERS_V1: &[&str] = &[
    "as",
    "permission",
    "authorize",
    "break",
    "const",
    "continue",
    "else",
    "enum",
    "error",
    "export",
    "false",
    "fn",
    "for",
    "hajimari",
    "if",
    "import",
    "in",
    "include",
    "kaizen",
    "kotoage",
    "let",
    "match",
    "module",
    "return",
    "seiyaku",
    "state",
    "struct",
    "event",
    "emit",
    "trigger",
    "true",
    "var",
    "view",
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
/// Exact compiler-owned prefixes forbidden for state declarations.
pub const DYNAMIC_ACCESS_HINT_RESERVED_STATE_PREFIXES_V1: &[&str] = &["__kotodama_link_"];
// END GENERATED: kotodama-v1-dynamic-access-policy
/// Reason a dynamic-access hint is outside the canonical V1 domain.
#[allow(
    clippy::enum_variant_names,
    reason = "the public V1 validation errors retain their explicit invalid-field names"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicAccessHintV1Error {
    /// `base_key` was not exactly `state:` plus one state declaration identifier.
    BaseKey,
    /// `key_type` was not an active V1 `StateMap` key type.
    KeyType,
    /// `bound_kind` was not an active V1 bound source.
    BoundKind,
    /// `max_keys` was outside `1..=64`.
    MaxKeys,
}
impl fmt::Display for DynamicAccessHintV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BaseKey => {
                "base_key must be `state:` followed by one canonical state declaration identifier"
            }
            Self::KeyType => "key_type must be an active Kotodama V1 StateMap key type",
            Self::BoundKind => "bound_kind must be exactly `page` or `take`",
            Self::MaxKeys => "max_keys must be in 1..=64",
        })
    }
}
impl std::error::Error for DynamicAccessHintV1Error {}
/// Return whether `name` is one canonical V1 state declaration identifier.
#[must_use]
pub fn is_canonical_dynamic_state_identifier_v1(name: &str) -> bool {
    let mut bytes = name.bytes();
    let has_identifier_shape = matches!(bytes.next(), Some(first) if first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
    has_identifier_shape
        && is_canonical_kotodama_identifier(name)
        && !DYNAMIC_ACCESS_HINT_RESERVED_STATE_IDENTIFIERS_V1.contains(&name)
        && !DYNAMIC_ACCESS_HINT_RESERVED_STATE_PREFIXES_V1
            .iter()
            .any(|prefix| name.starts_with(prefix))
}
/// Extract the state declaration name from a canonical V1 dynamic base key.
pub fn dynamic_access_hint_state_name_v1(base_key: &str) -> Result<&str, DynamicAccessHintV1Error> {
    let Some(name) = base_key.strip_prefix("state:") else {
        return Err(DynamicAccessHintV1Error::BaseKey);
    };
    if !is_canonical_dynamic_state_identifier_v1(name) {
        return Err(DynamicAccessHintV1Error::BaseKey);
    }
    Ok(name)
}
/// Return whether `key_type` is an exact active V1 `StateMap` key type.
#[must_use]
pub fn is_dynamic_access_hint_key_type_v1(key_type: &str) -> bool {
    use crate::entrypoint::{
        MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH, MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES,
    };
    let mut remaining = key_type;
    let mut tuple_children = [0usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH];
    let mut depth = 0usize;
    let mut nodes = 0usize;
    loop {
        nodes += 1;
        if nodes > MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES
            || depth + 1 > MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH
        {
            return false;
        }
        if let Some(tail) = remaining.strip_prefix('(') {
            tuple_children[depth] = 0;
            depth += 1;
            remaining = tail;
            continue;
        }
        let end = remaining.find([',', ')']).unwrap_or(remaining.len());
        if !DYNAMIC_ACCESS_HINT_KEY_TYPES_V1.contains(&&remaining[..end]) {
            return false;
        }
        remaining = &remaining[end..];
        loop {
            if depth == 0 {
                return remaining.is_empty();
            }
            tuple_children[depth - 1] += 1;
            if let Some(tail) = remaining.strip_prefix(", ") {
                remaining = tail;
                break;
            }
            if tuple_children[depth - 1] < 2 {
                return false;
            }
            let Some(tail) = remaining.strip_prefix(')') else {
                return false;
            };
            depth -= 1;
            remaining = tail;
        }
    }
}
/// Return whether `bound_kind` is an exact active V1 bound source.
#[must_use]
pub fn is_dynamic_access_hint_bound_kind_v1(bound_kind: &str) -> bool {
    DYNAMIC_ACCESS_HINT_BOUND_KINDS_V1.contains(&bound_kind)
}
/// Validate one dynamic state-access hint against the complete nominal V1
/// surface. This intentionally performs no trimming or alias conversion.
pub fn validate_dynamic_access_hint_v1(
    hint: &DynamicAccessHint,
) -> Result<(), DynamicAccessHintV1Error> {
    dynamic_access_hint_state_name_v1(&hint.base_key)?;
    if !is_dynamic_access_hint_key_type_v1(&hint.key_type) {
        return Err(DynamicAccessHintV1Error::KeyType);
    }
    if !is_dynamic_access_hint_bound_kind_v1(&hint.bound_kind) {
        return Err(DynamicAccessHintV1Error::BoundKind);
    }
    if !(1..=DYNAMIC_ACCESS_HINT_MAX_KEYS_V1).contains(&hint.max_keys) {
        return Err(DynamicAccessHintV1Error::MaxKeys);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tuple_keys_require_exact_scalar_grammar_and_shared_bounds() {
        for valid in [
            "(AccountId, int)",
            "(int, (Name, bytes))",
            "((bool, string), quantity)",
        ] {
            assert!(is_dynamic_access_hint_key_type_v1(valid), "{valid}");
        }
        for invalid in [
            "()",
            "(int)",
            "(int,)",
            "(int,bool)",
            "(int,  bool)",
            "(int, bool) ",
            "(Json, int)",
            "(Option<int>, int)",
            "(Unit::Kind, int)",
            "(int, bool), int",
        ] {
            assert!(!is_dynamic_access_hint_key_type_v1(invalid), "{invalid}");
        }
        let at_limit = format!("({})", vec!["int"; 255].join(", "));
        assert!(is_dynamic_access_hint_key_type_v1(&at_limit));
        let too_wide = format!("({})", vec!["int"; 256].join(", "));
        assert!(!is_dynamic_access_hint_key_type_v1(&too_wide));
    }
    fn hint(base_key: &str, key_type: &str, bound_kind: &str, max_keys: u32) -> DynamicAccessHint {
        DynamicAccessHint {
            base_key: base_key.to_owned(),
            key_type: key_type.to_owned(),
            bound_kind: bound_kind.to_owned(),
            max_keys,
        }
    }
    #[test]
    fn exact_v1_domain_is_accepted_without_poisoning_business_names() {
        assert!(
            !DYNAMIC_ACCESS_HINT_RESERVED_STATE_IDENTIFIERS_V1.contains(&"amount"),
            "ordinary business identifiers must remain legal state names"
        );
        assert!(
            !DYNAMIC_ACCESS_HINT_RESERVED_STATE_IDENTIFIERS_V1.contains(&"Amount"),
            "globally forbidden source identifiers must not become ABI tombstones"
        );
        assert!(!is_canonical_dynamic_state_identifier_v1("Amount"));
        for key_type in DYNAMIC_ACCESS_HINT_KEY_TYPES_V1 {
            for bound_kind in DYNAMIC_ACCESS_HINT_BOUND_KINDS_V1 {
                validate_dynamic_access_hint_v1(&hint(
                    "state:amount",
                    key_type,
                    bound_kind,
                    DYNAMIC_ACCESS_HINT_MAX_KEYS_V1,
                ))
                .expect("ordinary state name and every active V1 value must validate");
            }
        }
    }
    #[test]
    fn base_key_requires_one_canonical_state_declaration_identifier() {
        for valid in [
            "state:is_some",
            "state:unwrap_or",
            "state:expect",
            "state:anyone",
        ] {
            assert_eq!(
                validate_dynamic_access_hint_v1(&hint(valid, "int", "page", 1)),
                Ok(()),
                "contextual method or policy name {valid} remains a valid state identifier"
            );
        }
        for invalid in [
            "",
            "state:",
            "state:*",
            "state:Orders/child",
            "state: Orders",
            "state:Orders ",
            "state:1Orders",
            "state:注文",
            "state:state",
            "state:int",
            "state:Amount",
            "state:__kotodama_link_x",
            "State:Orders",
            "ledger:Orders",
        ] {
            assert_eq!(
                validate_dynamic_access_hint_v1(&hint(invalid, "int", "page", 1)),
                Err(DynamicAccessHintV1Error::BaseKey),
                "{invalid:?} must reject"
            );
        }
    }
    #[test]
    fn aliases_unknown_values_and_out_of_range_bounds_reject() {
        for invalid in ["Int", "Numeric", "Amount", "json", "AccountID", " int"] {
            assert_eq!(
                validate_dynamic_access_hint_v1(&hint("state:Orders", invalid, "page", 1)),
                Err(DynamicAccessHintV1Error::KeyType),
                "{invalid:?} must reject"
            );
        }
        for invalid in ["", "loop", "Take", "page ", "range", "bounded"] {
            assert_eq!(
                validate_dynamic_access_hint_v1(&hint("state:Orders", "int", invalid, 1)),
                Err(DynamicAccessHintV1Error::BoundKind),
                "{invalid:?} must reject"
            );
        }
        for invalid in [0, DYNAMIC_ACCESS_HINT_MAX_KEYS_V1 + 1, u32::MAX] {
            assert_eq!(
                validate_dynamic_access_hint_v1(&hint("state:Orders", "int", "take", invalid)),
                Err(DynamicAccessHintV1Error::MaxKeys),
                "{invalid} must reject"
            );
        }
    }
}
