//! Committed SCCP forgery evidence observations and bounded audit pages.

use iroha_data_model::{
    block::consensus::EvidencePenaltyStatus,
    sccp::native::{SccpForgeryOffenderV1, SccpForgeryRuleV1},
};
use norito::codec::{Decode, Encode};

/// Maximum number of records in one evidence page.
pub const MAX_EVIDENCE_PAGE: usize = 64;

/// Original committed attribution and the consensus penalty lifecycle of a forgery report.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpForgeryEvidenceStatusV1")]
pub struct SccpForgeryEvidenceStatusV1 {
    /// Deterministic original certificate evidence id, before the generic Hash marker.
    pub evidence_id: [u8; 32],
    /// Independently retained signing generation.
    pub generation: u64,
    /// Height claimed by the offending signed certificate.
    pub height: u64,
    /// First mismatch authenticated at original admission.
    pub rule: SccpForgeryRuleV1,
    /// Newly attributed slashable members, in original signer order.
    pub offenders: Vec<SccpForgeryOffenderV1>,
    /// Pending or canonically applied; this is independent of the signed height.
    pub penalty_status: EvidencePenaltyStatus,
    /// Original carrier height, from which penalty delay is measured.
    pub recorded_at_height: u64,
}

/// At most 64 original evidence records, ordered by their retained evidence key.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpForgeryEvidencePageV1")]
pub struct SccpForgeryEvidencePageV1 {
    /// Committed forgery reports only; native consensus reports have their own route.
    pub records: Vec<SccpForgeryEvidenceStatusV1>,
    /// Exclusive cursor of the next page, absent once no further forgery reports remain.
    #[norito(required)]
    pub next_after: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn penalty_lifecycle_and_pagination_have_exact_json_and_binary_roundtrips() {
        for penalty_status in [
            EvidencePenaltyStatus::Pending,
            EvidencePenaltyStatus::Applied { height: 12 },
        ] {
            let status = SccpForgeryEvidenceStatusV1 {
                evidence_id: [7; 32],
                generation: 2,
                height: 99,
                rule: SccpForgeryRuleV1::E2,
                offenders: Vec::new(),
                penalty_status,
                recorded_at_height: 8,
            };
            let value = SccpForgeryEvidencePageV1 {
                records: vec![status],
                next_after: Some([7; 32]),
            };
            let json = norito::json::to_json(&value).unwrap();
            assert_eq!(
                norito::json::from_json::<SccpForgeryEvidencePageV1>(&json).unwrap(),
                value
            );
            assert_eq!(
                norito::decode_from_bytes::<SccpForgeryEvidencePageV1>(
                    &norito::to_bytes(&value).unwrap()
                )
                .unwrap(),
                value
            );
            assert!(
                norito::json::from_json::<SccpForgeryEvidencePageV1>("{\"records\":[]}").is_err()
            );
        }
    }
}
