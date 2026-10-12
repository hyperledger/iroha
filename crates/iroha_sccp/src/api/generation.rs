//! Current SCCP committee discovery records; decoding supplies no committee authority.

use iroha_data_model::sccp::generation::{
    SccpGenerationCauseV1, SccpGenerationEndV1, SccpGenerationMemberV1,
};
use norito::codec::{Decode, Encode};

/// Committed generation metadata and its current inclusive liability predicate (§6).
/// Keys must be authenticated through signed genesis and native certificate handoffs.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGenerationV1")]
pub struct SccpGenerationV1 {
    /// Nonzero generation, matching the map key.
    pub generation: u64,
    /// SCCP root of `keys` in their canonical order.
    pub committee_root: [u8; 32],
    /// Compressed BLS-normal keys; signer bit `i` refers to `keys[i]`.
    pub keys: Vec<[u8; 48]>,
    /// Original slashable bindings in the same order, with explicit unresolved entries.
    pub members: Vec<Option<SccpGenerationMemberV1>>,
    /// Authenticated genesis, ordinary rotation or degraded-boundary recovery.
    pub cause: SccpGenerationCauseV1,
    /// First height governed by this generation.
    pub start_height: u64,
    /// Certified time of creation; ordinary rotation uses its handoff block's time.
    pub start_timestamp_ms: u64,
    /// Liability clock at creation.
    pub start_lc: u64,
    /// Immutable destination trust duration captured at creation.
    pub validity_ms: u64,
    /// Saturating sum of creation time and validity.
    pub deadline_ms: u64,
    /// Immutable evidence grace period captured at creation.
    pub grace_ms: u64,
    /// Maximum extension while authenticated destination progress is missing.
    pub progress_cap_ms: u64,
    /// Saturating sum of `start_lc`, `validity_ms` and `grace_ms`.
    pub liable_until_lc: u64,
    /// First post-execution liability clock at which all destinations cleared the deadline.
    #[norito(required)]
    pub dest_cleared_lc: Option<u64>,
    /// End and successor, absent for the current open generation.
    #[norito(required)]
    pub end: Option<SccpGenerationEndV1>,
    /// Liability at the committed view's current generation and liability clock.
    pub liable: bool,
}

/// Scalar current-generation discovery metadata, without a second owned key graph.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpCurrentGenerationV1")]
pub struct SccpCurrentGenerationV1 {
    /// Nonzero generation named by the committed World.
    pub generation: u64,
    /// Root of the generation's canonical BLS keys.
    pub committee_root: [u8; 32],
    /// First governed height.
    pub start_height: u64,
    /// Inclusive destination trust deadline.
    pub deadline_ms: u64,
}

/// Exact finality-domain identifiers of this first release.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpFinalityConstantsV1")]
pub struct SccpFinalityConstantsV1 {
    /// Exact `X_MAGIC` prefix of the fixed 221-byte header.
    pub x_layout_id: [u8; 16],
    /// Current IETF min-pk consensus signature domain.
    pub dst_sig: [u8; 43],
    /// Domain of the outer certified result.
    pub result_tag: [u8; 24],
    /// Domain of the canonical result-body digest.
    pub result_body_tag: [u8; 29],
}
// All copies are evaluated at compile time; a changed domain length cannot become a
// runtime capabilities panic or silently truncate the protocol identifier.
const fn fixed_domain<const N: usize>(source: &[u8]) -> [u8; N] {
    assert!(source.len() == N);
    let mut result = [0; N];
    let mut index = 0;
    while index < N {
        result[index] = source[index];
        index += 1;
    }
    result
}
const CURRENT_FINALITY: SccpFinalityConstantsV1 = SccpFinalityConstantsV1 {
    x_layout_id: fixed_domain(crate::v1::finality::X_MAGIC),
    dst_sig: *crate::v1::finality::DST_SIG,
    result_tag: fixed_domain(crate::v1::finality::RESULT_TAG),
    result_body_tag: fixed_domain(crate::v1::finality::RESULT_BODY_TAG),
};
impl SccpFinalityConstantsV1 {
    /// Exact identifiers implemented by the certificate verifier.
    #[must_use]
    pub const fn current() -> Self {
        CURRENT_FINALITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finality_constants_match_the_current_relation_and_roundtrip_strictly() {
        use crate::v1::finality::{DST_SIG, RESULT_BODY_TAG, RESULT_TAG, X_MAGIC};
        use norito::codec::{DecodeAll, Encode};
        let constants = SccpFinalityConstantsV1::current();
        assert_eq!(constants.x_layout_id.as_slice(), X_MAGIC);
        assert_eq!(&constants.dst_sig, DST_SIG);
        assert_eq!(constants.result_tag.as_slice(), RESULT_TAG);
        assert_eq!(constants.result_body_tag.as_slice(), RESULT_BODY_TAG);
        assert_eq!(
            SccpFinalityConstantsV1::decode_all(&mut constants.encode().as_slice()).unwrap(),
            constants
        );
        let mut json = norito::json::to_value(&constants).unwrap();
        assert_eq!(
            norito::json::from_value::<SccpFinalityConstantsV1>(json.clone()).unwrap(),
            constants
        );
        json.as_object_mut()
            .unwrap()
            .insert("domain_separator".into(), norito::json::Value::from(0));
        assert!(norito::json::from_value::<SccpFinalityConstantsV1>(json).is_err());
        let current = SccpCurrentGenerationV1 {
            generation: 1,
            committee_root: [7; 32],
            start_height: 1,
            deadline_ms: 1000,
        };
        assert_eq!(
            SccpCurrentGenerationV1::decode_all(&mut current.encode().as_slice()).unwrap(),
            current
        );
    }
}
