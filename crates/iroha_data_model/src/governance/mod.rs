//! Canonical governance and SORA Parliament data model.
//!
//! The module exposes closed V1 identifiers, lifecycle states, aggregate
//! decision arithmetic, and certificate bindings. Ledger events live in the
//! canonical [`crate::events::data::governance`] module.
/// Canonical governance and Parliament wire types.
pub mod types {
    pub use crate::parliament_types::*;
}
/// Block-start anchors of governance transitions, shared by the Parliament ballot and SCCP.
pub mod anchor;
/// Exact frozen economics for the existing public standalone conviction ballot.
pub mod conviction;
pub use anchor::GovernanceAnchorV1;
/// Maximum encoded length of a canonical V1 governance selector.
pub const GOVERNANCE_SELECTOR_V1_MAX_BYTES: usize = 128;
/// OpenAPI/SDK grammar for canonical V1 governance selectors.
///
/// Selectors are one RFC 3986 unreserved path segment. A leading dot is deliberately excluded so
/// intermediaries cannot reinterpret a selector as a relative-path segment.
pub const GOVERNANCE_SELECTOR_V1_PATTERN: &str = "^[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,127}$";
/// Decode a governance selector that aliases an exact typed proposal identifier.
///
/// Typed proposal identifiers admit exactly 32 bytes of hexadecimal, with ASCII hex digits in
/// either case and an optional `0x` or `0X` prefix. Other standalone referendum selectors and
/// malformed hexadecimal aliases return `None`.
#[must_use]
pub fn decode_governance_proposal_selector_alias_v1(value: &str) -> Option<[u8; 32]> {
    let unprefixed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if unprefixed.len() != 64 || !unprefixed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut proposal_id = [0_u8; 32];
    hex::decode_to_slice(unprefixed, &mut proposal_id).ok()?;
    Some(proposal_id)
}
/// Return whether `value` is a canonical V1 governance selector.
///
/// The accepted alphabet is RFC 3986 unreserved ASCII (`ALPHA`, `DIGIT`,
/// `-`, `.`, `_`, `~`), bounded to 128 bytes. The first byte may not be `.`;
/// this rejects both dot segments and leading-dot normalization aliases.
#[must_use]
pub fn is_valid_governance_selector_v1(value: &str) -> bool {
    fn is_unreserved_without_dot(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~')
    }
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > GOVERNANCE_SELECTOR_V1_MAX_BYTES {
        return false;
    }
    is_unreserved_without_dot(bytes[0])
        && bytes[1..]
            .iter()
            .copied()
            .all(|byte| is_unreserved_without_dot(byte) || byte == b'.')
}
#[cfg(test)]
mod tests {
    use super::{
        GOVERNANCE_SELECTOR_V1_MAX_BYTES, decode_governance_proposal_selector_alias_v1,
        is_valid_governance_selector_v1,
    };

    #[test]
    fn proposal_selector_alias_accepts_case_and_prefix_variants() {
        let expected = [0xab_u8; 32];
        let lowercase = "ab".repeat(32);
        let uppercase = lowercase.to_ascii_uppercase();
        let mixed = "aB".repeat(32);
        for alias in [
            lowercase,
            uppercase.clone(),
            mixed,
            format!("0x{uppercase}"),
            format!("0X{}", "Ab".repeat(32)),
        ] {
            assert_eq!(
                decode_governance_proposal_selector_alias_v1(&alias),
                Some(expected),
                "alias {alias:?}"
            );
        }
    }

    #[test]
    fn proposal_selector_alias_rejects_malformed_lengths_and_characters() {
        for malformed in [
            "ab".repeat(31),
            "ab".repeat(33),
            format!("0x{}", "ab".repeat(31)),
            format!("0X{}", "ab".repeat(33)),
            format!("{}g", "ab".repeat(31)),
            format!("0x{} ", "ab".repeat(31)),
            format!("0x0x{}", "ab".repeat(31)),
        ] {
            assert_eq!(
                decode_governance_proposal_selector_alias_v1(&malformed),
                None,
                "malformed alias {malformed:?}"
            );
        }
    }

    #[test]
    fn governance_selector_v1_accepts_only_bounded_unreserved_path_segments() {
        let maximum = "a".repeat(GOVERNANCE_SELECTOR_V1_MAX_BYTES);
        let overlong = "a".repeat(GOVERNANCE_SELECTOR_V1_MAX_BYTES + 1);
        for valid in [
            "a",
            "referendum-1",
            "A9_selector~with.dots",
            maximum.as_str(),
        ] {
            assert!(is_valid_governance_selector_v1(valid), "{valid:?}");
        }
        for invalid in [
            "",
            ".",
            "..",
            ".hidden",
            "a/b",
            "a%2Fb",
            "has space",
            "投票",
            overlong.as_str(),
        ] {
            assert!(!is_valid_governance_selector_v1(invalid), "{invalid:?}");
        }
    }
}
