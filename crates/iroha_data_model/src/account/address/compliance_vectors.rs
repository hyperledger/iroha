//! ADDR-2 compliance vector generator shared by the example binary and CLI tooling.
use crate::account::{
    AccountAddress, AccountAddressError, AccountId, MultisigMember, MultisigPolicy,
    MultisigPolicyError,
};
use hex::encode_upper;
use iroha_crypto::{Algorithm, KeyPair, PublicKey};
use norito::json::{Map, Value};
macro_rules! json_obj {
    ({ $( $key:literal : $value:expr ),* $(,)? }) => {{
        let mut map = Map::new();
        $( map.insert($key.to_string(), Value::from($value)); )*
        Value::Object(map)
    }};
}
const NETWORK_PREFIX: u16 = 753;
const I105_CHECKSUM_MUTATION_CANDIDATES: &str = "ｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉ";
struct PositiveEncodings {
    canonical_hex: String,
    canonical_bytes: Vec<u8>,
    i105: String,
}
struct SingleCase {
    value: Value,
    address: AccountAddress,
    encodings: PositiveEncodings,
}
struct MultisigCase {
    value: Value,
    encodings: PositiveEncodings,
}
struct MultisigFixture {
    case_id: &'static str,
    note: &'static str,
    members: &'static [(u8, u16)],
    threshold: u16,
}
const MULTISIG_FIXTURES: &[MultisigFixture] = &[
    MultisigFixture {
        case_id: "addr-multisig-council-threshold3",
        note: "Domainless multisig with three members (weights 2,1,1) requiring weight ≥3.",
        members: &[(0x21, 2), (0x36, 1), (0x4B, 1)],
        threshold: 3,
    },
    MultisigFixture {
        case_id: "addr-multisig-wonderland-threshold2",
        note: "Domainless two-member multisig with weights 1 and 2 requiring weight ≥2.",
        members: &[(0x10, 1), (0x11, 2)],
        threshold: 2,
    },
    MultisigFixture {
        case_id: "addr-multisig-default-quorum3",
        note: "Domainless multisig fixture with four members (weight 1 each) requiring weight ≥3.",
        members: &[(0xA0, 1), (0xA1, 1), (0xA2, 1), (0xA3, 1)],
        threshold: 3,
    },
];
fn ed25519_pk_with(seed_byte: u8) -> PublicKey {
    let seed = vec![seed_byte; 32];
    let (public_key, _) = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .expect("fixed account-address compliance Ed25519 seed must derive")
        .into_parts();
    public_key
}
fn canonical_hex(address: &AccountAddress) -> String {
    address
        .canonical_hex()
        .expect("canonical encoding must succeed")
}
fn canonical_bytes(hex_value: &str) -> Vec<u8> {
    let body = hex_value.strip_prefix("0x").unwrap_or(hex_value);
    hex::decode(body).expect("canonical hex should decode")
}
fn checked_public_key_bytes(public_key: &PublicKey) -> (Algorithm, &[u8]) {
    public_key
        .try_to_bytes()
        .expect("compliance vector public key must be well-formed")
}
fn checked_public_key_multihash(public_key: &PublicKey) -> String {
    public_key
        .try_to_multihash_string()
        .expect("compliance vector public key must format as a multihash")
}
fn checked_public_key_prefixed(public_key: &PublicKey) -> String {
    public_key
        .try_to_prefixed_string()
        .expect("compliance vector public key must format as a prefixed multihash")
}
fn controller_single_value(public_key: &PublicKey) -> Value {
    let (algorithm, payload) = checked_public_key_bytes(public_key);
    assert_eq!(algorithm, Algorithm::Ed25519, "expected ed25519 key");
    json_obj!({
        "kind": "single",
        "curve": "ed25519",
        "public_key_hex": encode_upper(payload),
        "public_key_multihash": checked_public_key_multihash(public_key),
        "public_key_prefixed": checked_public_key_prefixed(public_key),
    })
}
fn controller_multisig_value(policy: &MultisigPolicy) -> Value {
    let members: Vec<Value> = policy
        .members()
        .iter()
        .map(|member| {
            let (algorithm, payload) = checked_public_key_bytes(member.public_key());
            json_obj!({
                "curve": format!("{algorithm:?}").to_lowercase(),
                "weight": member.weight(),
                "public_key_hex": encode_upper(payload),
                "public_key_multihash": checked_public_key_multihash(member.public_key()),
                "public_key_prefixed": checked_public_key_prefixed(member.public_key()),
            })
        })
        .collect();
    let ctap2 = policy.encode_ctap2();
    let digest = policy.digest_blake2b256();
    json_obj!({
        "kind": "multisig",
        "version": policy.version(),
        "threshold": policy.threshold(),
        "members": Value::Array(members),
        "ctap2_cbor_hex": format!("0x{}", encode_upper(&ctap2)),
        "digest_blake2b256_hex": format!("0x{}", encode_upper(digest)),
    })
}
fn encodings(address: &AccountAddress) -> PositiveEncodings {
    let canonical_hex = canonical_hex(address);
    let canonical_bytes = canonical_bytes(&canonical_hex);
    let i105 = address
        .to_i105_for_discriminant(NETWORK_PREFIX)
        .expect("I105 encoding must succeed");
    PositiveEncodings {
        canonical_hex,
        canonical_bytes,
        i105,
    }
}
fn build_single_case(case_id: &str, seed: u8, note: &str) -> SingleCase {
    let public_key = ed25519_pk_with(seed);
    let account = AccountId::new(public_key.clone());
    let address = AccountAddress::from_account_id(&account).expect("single-key encoding succeeds");
    let encodings = encodings(&address);
    let value = json_obj!({
        "case_id": case_id,
        "category": "single",
        "note": note,
        "input": json_obj!({
            "seed_byte": seed,
        }),
        "controller": controller_single_value(&public_key),
        "encodings": json_obj!({
            "canonical_hex": encodings.canonical_hex.clone(),
            "i105": json_obj!({
                "prefix": NETWORK_PREFIX,
                "string": encodings.i105.clone(),
            })
        })
    });
    SingleCase {
        value,
        address,
        encodings,
    }
}
fn build_multisig_cases() -> Vec<MultisigCase> {
    MULTISIG_FIXTURES
        .iter()
        .map(|fixture| {
            let members = fixture
                .members
                .iter()
                .map(|(seed, weight)| {
                    MultisigMember::new(ed25519_pk_with(*seed), *weight)
                        .expect("multisig member must construct")
                })
                .collect::<Vec<_>>();
            let policy = MultisigPolicy::new(fixture.threshold, members).expect("policy");
            let account = AccountId::new_multisig(policy.clone());
            let address =
                AccountAddress::from_account_id(&account).expect("multisig encoding succeeds");
            let encodings = encodings(&address);
            let member_keys_hex: Vec<String> = policy
                .members()
                .iter()
                .map(|member| {
                    let (_, payload) = checked_public_key_bytes(member.public_key());
                    encode_upper(payload)
                })
                .collect();
            let member_weights: Vec<u16> = policy
                .members()
                .iter()
                .map(MultisigMember::weight)
                .collect();
            let value = json_obj!({
                "case_id": fixture.case_id,
                "category": "multisig",
                "note": fixture.note,
                "input": json_obj!({
                    "member_keys_hex": Value::Array(
                        member_keys_hex
                            .iter()
                            .cloned()
                            .map(Value::from)
                            .collect()
                    ),
                    "member_weights": Value::Array(
                        member_weights
                            .iter()
                            .copied()
                            .map(Value::from)
                            .collect()
                    ),
                    "threshold": fixture.threshold,
                }),
                "controller": controller_multisig_value(&policy),
                "encodings": json_obj!({
                    "canonical_hex": encodings.canonical_hex.clone(),
                    "i105": json_obj!({
                        "prefix": NETWORK_PREFIX,
                        "string": encodings.i105.clone(),
                    })
                })
            });
            MultisigCase { value, encodings }
        })
        .collect()
}
fn error_to_json(err: &AccountAddressError) -> Value {
    match err {
        AccountAddressError::ChecksumMismatch => {
            json_obj!({ "kind": "ChecksumMismatch" })
        }
        AccountAddressError::UnexpectedNetworkPrefix { expected, found } => json_obj!({
            "kind": "UnexpectedNetworkPrefix",
            "expected": *expected,
            "found": *found,
        }),
        AccountAddressError::InvalidI105Char(ch) => json_obj!({
            "kind": "InvalidI105Char",
            "char": ch.to_string(),
        }),
        AccountAddressError::InvalidHexAddress => {
            json_obj!({ "kind": "InvalidHexAddress" })
        }
        AccountAddressError::UnsupportedAddressFormat => {
            json_obj!({ "kind": "UnsupportedAddressFormat" })
        }
        AccountAddressError::InvalidLength => {
            json_obj!({ "kind": "InvalidLength" })
        }
        AccountAddressError::UnexpectedTrailingBytes => {
            json_obj!({ "kind": "UnexpectedTrailingBytes" })
        }
        AccountAddressError::InvalidMultisigPolicy(inner) => json_obj!({
            "kind": "InvalidMultisigPolicy",
            "policy_error": policy_error_to_string(*inner),
        }),
        other => panic!("unhandled error variant in generator: {other}"),
    }
}
fn policy_error_to_string(err: MultisigPolicyError) -> &'static str {
    match err {
        MultisigPolicyError::EmptyMembers => "EmptyMembers",
        MultisigPolicyError::TooManyMembers(_) => "TooManyMembers",
        MultisigPolicyError::NonCanonicalMemberOrder => "NonCanonicalMemberOrder",
        MultisigPolicyError::ZeroThreshold => "ZeroThreshold",
        MultisigPolicyError::MemberWeightZero => "MemberWeightZero",
        MultisigPolicyError::DuplicateMember => "DuplicateMember",
        MultisigPolicyError::ThresholdExceedsTotal { .. } => "ThresholdExceedsTotal",
        MultisigPolicyError::UnsupportedVersion(_) => "UnsupportedVersion",
        MultisigPolicyError::MalformedPublicKey => "MalformedPublicKey",
    }
}
fn mutate_last_char(input: &str, replacement: char) -> String {
    let mut chars: Vec<char> = input.chars().collect();
    let last = chars
        .last_mut()
        .expect("address strings are non-empty for compliance vectors");
    if *last == replacement {
        *last = if replacement == 'ア' { 'イ' } else { 'ア' };
    } else {
        *last = replacement;
    }
    chars.into_iter().collect()
}
fn find_i105_checksum_mismatch(
    input: &str,
    expected_prefix: Option<u16>,
) -> (String, AccountAddressError) {
    for candidate in I105_CHECKSUM_MUTATION_CANDIDATES.chars() {
        let mutated = mutate_last_char(input, candidate);
        if let Err(err) = AccountAddress::from_i105_for_discriminant(&mutated, expected_prefix)
            && matches!(err, AccountAddressError::ChecksumMismatch)
        {
            return (mutated, err);
        }
    }
    panic!("failed to derive deterministic I105 checksum-mismatch vector");
}
fn find_i105_checksum_mismatch_any(input: &str) -> (String, AccountAddressError) {
    let mut preferred_candidates: Vec<char> = input.chars().collect();
    preferred_candidates.sort_unstable();
    preferred_candidates.dedup();
    for candidate in preferred_candidates
        .into_iter()
        .chain(I105_CHECKSUM_MUTATION_CANDIDATES.chars())
    {
        let mutated = mutate_last_char(input, candidate);
        if let Err(err) = AccountAddress::from_i105(&mutated)
            && matches!(err, AccountAddressError::ChecksumMismatch)
        {
            return (mutated, err);
        }
    }
    panic!("failed to derive deterministic i105 checksum-mismatch vector");
}
fn find_i105_invalid_char(input: &str) -> (String, AccountAddressError) {
    let candidates = ['0', 'O', 'I', 'l', '+', '/'];
    for candidate in candidates {
        let mutated = mutate_last_char(input, candidate);
        if let Err(err) = AccountAddress::from_i105(&mutated) {
            return (mutated, err);
        }
    }
    panic!("failed to derive deterministic I105 invalid-character vector");
}
fn canonical_with_trailing_zero(encodings: &PositiveEncodings) -> String {
    format!("{}00", encodings.canonical_hex)
}
fn canonical_invalid_hex(encodings: &PositiveEncodings) -> String {
    let mut chars: Vec<char> = encodings.canonical_hex.chars().collect();
    let last = chars
        .last_mut()
        .expect("canonical hex must contain at least one digit");
    *last = 'G';
    chars.into_iter().collect()
}
/// Build the canonical ADDR-2 JSON bundle consumed by SDK/tests.
#[allow(clippy::too_many_lines)]
pub fn compliance_vectors_json() -> Value {
    let single_default = build_single_case(
        "addr-single-default-ed25519",
        0x0C,
        "Domainless address using a deterministic Ed25519 key derived from seed byte 0x0c.",
    );
    let single_treasury = build_single_case(
        "addr-single-treasury-ed25519",
        0x01,
        "Domainless address using a second deterministic Ed25519 key derived from seed byte 0x01.",
    );
    let multisig_cases = build_multisig_cases();
    let mut positive_cases = vec![single_default.value.clone(), single_treasury.value.clone()];
    positive_cases.extend(multisig_cases.iter().map(|case| case.value.clone()));
    let (i105_checksum, err_checksum) =
        find_i105_checksum_mismatch(&single_default.encodings.i105, Some(NETWORK_PREFIX));
    let i105_wrong_prefix = single_default
        .address
        .to_i105_for_discriminant(NETWORK_PREFIX + 1)
        .expect("I105 encoding must succeed");
    let err_prefix =
        AccountAddress::from_i105_for_discriminant(&i105_wrong_prefix, Some(NETWORK_PREFIX))
            .unwrap_err();
    let (i105_bad_char, err_bad_char) = find_i105_invalid_char(&single_default.encodings.i105);
    let (i105_bad_checksum, err_bad_checksum) =
        find_i105_checksum_mismatch_any(&single_default.encodings.i105);
    let canonical_invalid = canonical_invalid_hex(&single_default.encodings);
    let err_invalid_hex = AccountAddress::parse_encoded(&canonical_invalid, None).unwrap_err();
    let canonical_trailing = canonical_with_trailing_zero(&single_default.encodings);
    let err_trailing = AccountAddress::parse_encoded(&canonical_trailing, None).unwrap_err();
    let primary_multisig = multisig_cases
        .first()
        .expect("multisig fixtures must include at least one case");
    let mut multisig_truncated = primary_multisig.encodings.canonical_bytes.clone();
    multisig_truncated.truncate(multisig_truncated.len().saturating_sub(4));
    let multisig_truncated_hex = format!("0x{}", encode_upper(&multisig_truncated));
    let err_multisig_truncated =
        AccountAddress::parse_encoded(&multisig_truncated_hex, None).unwrap_err();
    let negative_cases = vec![
        json_obj!({
            "case_id": "i105-checksum-mismatch",
            "format": "i105",
            "note": "Checksum tampering on the I105 alias for the first domainless vector.",
            "input": i105_checksum,
            "expected_prefix": NETWORK_PREFIX,
            "expected_error": error_to_json(&err_checksum),
        }),
        json_obj!({
            "case_id": "i105-prefix-mismatch",
            "format": "i105",
            "note": "Encoded with prefix NETWORK_PREFIX + 1 while validators expect NETWORK_PREFIX.",
            "input": i105_wrong_prefix,
            "expected_prefix": NETWORK_PREFIX,
            "expected_error": error_to_json(&err_prefix),
        }),
        json_obj!({
            "case_id": "i105-invalid-character",
            "format": "i105",
            "note": "Introduces a glyph outside the canonical I105 alphabet.",
            "input": i105_bad_char,
            "expected_error": error_to_json(&err_bad_char),
        }),
        json_obj!({
            "case_id": "i105-checksum-mismatch-default-sentinel",
            "format": "i105",
            "note": "Checksum bytes replaced to trigger canonical I105 verification failure.",
            "input": i105_bad_checksum,
            "expected_error": error_to_json(&err_bad_checksum),
        }),
        json_obj!({
            "case_id": "canonical-invalid-hex",
            "format": "canonical_hex",
            "note": "Invalid hex digit injected into canonical representation.",
            "input": canonical_invalid,
            "expected_error": error_to_json(&err_invalid_hex),
        }),
        json_obj!({
            "case_id": "canonical-trailing-bytes",
            "format": "canonical_hex",
            "note": "Extra zero byte appended past the canonical payload.",
            "input": canonical_trailing,
            "expected_error": error_to_json(&err_trailing),
        }),
        json_obj!({
            "case_id": "canonical-multisig-truncated",
            "format": "canonical_hex",
            "note": "Canonical multisig payload truncated after removing final member bytes.",
            "input": multisig_truncated_hex,
            "expected_error": error_to_json(&err_multisig_truncated),
        }),
    ];
    json_obj!({
        "format_version": 1,
        "default_network_prefix": NETWORK_PREFIX,
        "cases": json_obj!({
            "positive": Value::Array(positive_cases),
            "negative": Value::Array(negative_cases),
        })
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ed25519_pk_with_uses_checked_seed_derivation() {
        assert_eq!(
            ed25519_pk_with(0x42)
                .try_algorithm()
                .expect("compliance vector key algorithm"),
            Algorithm::Ed25519
        );
    }
    #[test]
    fn compliance_vectors_build_with_checked_public_key_payloads() {
        let Value::Object(root) = compliance_vectors_json() else {
            panic!("compliance vectors root must be an object");
        };
        let Some(Value::Object(cases)) = root.get("cases") else {
            panic!("compliance vectors must contain cases");
        };
        let Some(Value::Array(positive)) = cases.get("positive") else {
            panic!("compliance vectors must contain positive cases");
        };
        assert!(!positive.is_empty());
        assert!(
            positive.iter().all(|case| {
                case.get("selector").is_none()
                    && case
                        .get("input")
                        .and_then(Value::as_object)
                        .is_some_and(|input| {
                            !input.contains_key("raw_domain")
                                && !input.contains_key("normalized_domain")
                        })
            }),
            "first-release vectors must not expose retired domain-selector metadata"
        );
        let public_key = ed25519_pk_with(0x0C);
        let Some(controller) = positive
            .iter()
            .find_map(|case| case.get("controller").and_then(Value::as_object))
        else {
            panic!("positive vector must include controller details");
        };
        let expected_multihash = checked_public_key_multihash(&public_key);
        let expected_prefixed = checked_public_key_prefixed(&public_key);
        assert_eq!(
            controller
                .get("public_key_multihash")
                .and_then(Value::as_str),
            Some(expected_multihash.as_str())
        );
        assert_eq!(
            controller
                .get("public_key_prefixed")
                .and_then(Value::as_str),
            Some(expected_prefixed.as_str())
        );
    }
}
