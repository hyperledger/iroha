//! Quarantined-revision reconciliation and authenticated forged-mint evidence (§4.10).
//!
//! The public view includes the proven ids. Core retains those ids separately from the
//! fixed-size accounting record so proving one mint never copies the revision's history.

use std::collections::BTreeSet;

use super::{bounded_bytes::impl_sccp_bounded_bytes, inbound::SccpSourceProofBytesV1};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Canonical outbound payload preimage needed to authenticate a finalized mint's amount.
/// In particular, TON's finalization event contains only the message id and nonce.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
)]
#[norito(decode_from_slice)]
#[norito(validate = "Self::checked")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::reconciliation::SccpForgedMintPayloadV1")]
pub struct SccpForgedMintPayloadV1 {
    /// Canonical SCCP §3.2 payload, bounded before allocation in the core proof path.
    #[norito(json = "crate::json_helpers::base64_vec")]
    bytes: Vec<u8>,
}
impl_sccp_bounded_bytes!(SccpForgedMintPayloadV1, 4096, "SCCP forged-mint payload");

/// Source-chain finalization proof and the payload whose message id that event commits to.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::reconciliation::SccpForgedMintProofV1")]
pub struct SccpForgedMintProofV1 {
    /// Light-client proof of the registered deployment's finalization event.
    pub source: SccpSourceProofBytesV1,
    /// Canonical outbound payload preimage; its amount is never trusted before id binding.
    pub payload: SccpForgedMintPayloadV1,
}

/// Immutable pro-rata rate fixed at the end of a reconciliation window.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::reconciliation::SccpReconciliationRatioV1")]
pub struct SccpReconciliationRatioV1 {
    /// Backing remaining after reserving pending refunds (`B`).
    pub backing: u128,
    /// Total priced supply (`B + F`), or one when both are zero.
    pub denominator: u128,
}

/// Fixed-size accounting of the single reconciliation window of a quarantined revision.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::reconciliation::SccpReconciliationStateV1")]
pub struct SccpReconciliationStateV1 {
    /// Executing ledger time at Parliament enactment.
    pub opened_at_ms: u64,
    /// First ledger time at which further forged-mint proofs are refused.
    pub closes_at_ms: u64,
    /// Checked sum of distinct authenticated forged mint amounts (`F`).
    pub forged_supply: u128,
    /// Fixed backing and denominator (`B`, `B + F`), or `(0, 1)` for empty backing/supply.
    #[norito(required)]
    pub rho: Option<SccpReconciliationRatioV1>,
    /// Saturating face amount of claims that actually left Pending (`S`).
    pub settled_face: u128,
}

/// Public reconciliation record; absence means a quarantined revision is Held.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::reconciliation::SccpReconciliationV1")]
pub struct SccpReconciliationV1 {
    /// Window and immutable settlement rate; `rho = None` means Reconciling.
    pub state: SccpReconciliationStateV1,
    /// Distinct authenticated finalized ids counted in the window.
    pub proven_ids: BTreeSet<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};

    #[test]
    fn reconciliation_records_and_proof_roundtrip() {
        let proof = SccpForgedMintProofV1 {
            source: SccpSourceProofBytesV1::new(vec![1, 2, 3]).unwrap(),
            payload: SccpForgedMintPayloadV1::new(vec![4; 4096]).unwrap(),
        };
        roundtrip(&proof);
        assert_rejects_unknown_field(&proof, &[]);
        let mut record = SccpReconciliationV1 {
            state: SccpReconciliationStateV1 {
                opened_at_ms: 0,
                closes_at_ms: u64::MAX,
                forged_supply: u128::MAX,
                rho: None,
                settled_face: 0,
            },
            proven_ids: BTreeSet::from([[3; 32], [5; 32]]),
        };
        roundtrip(&record);
        assert_rejects_unknown_field(&record, &[]);
        record.state.rho = Some(SccpReconciliationRatioV1 {
            backing: u128::MAX - 1,
            denominator: u128::MAX,
        });
        record.state.settled_face = u128::MAX;
        roundtrip(&record);
    }

    #[test]
    fn forged_payload_rejects_empty_and_oversized_values() {
        assert!(SccpForgedMintPayloadV1::new(vec![]).is_err());
        assert!(SccpForgedMintPayloadV1::new(vec![0; 4097]).is_err());
        assert!(SccpForgedMintPayloadV1::new(vec![0; 1]).is_ok());
        assert!(norito::json::from_json::<SccpForgedMintPayloadV1>(r#"{"bytes":""}"#).is_err());
    }
}
