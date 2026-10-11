//! SCCP v1 inbound records and source proofs (`specs/sccp.md` §4.12, §4.16).
//!
//! An inbound message is proven once ([`SccpInboundRecordV1`] with a `Pending` status) and
//! settled separately, so a proven burn never becomes unprovable. Inbound and void proofs travel
//! as [`SccpSourceProofBytesV1`]: an opaque headered Norito frame of the per-chain proof that
//! only `iroha_sccp::light_client` decodes.

use super::{bounded_bytes::impl_sccp_bounded_bytes, outbound::SccpStatusHeightV1};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, bridge::SccpNetworkV1};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Largest source proof (8 MiB), equal to the default `[zk.sccp]` per-proof byte limit.
pub const SCCP_SOURCE_PROOF_MAX_BYTES_V1: usize = 8 * 1024 * 1024;

/// Opaque inbound or void proof (`SccpSourceProofV1` frame), `1..=8 MiB`.
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
#[norito_schema(name = "iroha_data_model::sccp::inbound::SccpSourceProofBytesV1")]
pub struct SccpSourceProofBytesV1 {
    /// Headered Norito frame of `iroha_sccp::light_client::SccpSourceProofV1`.
    #[norito(json = "crate::json_helpers::base64_vec")]
    bytes: Vec<u8>,
}

impl_sccp_bounded_bytes!(
    SccpSourceProofBytesV1,
    SCCP_SOURCE_PROOF_MAX_BYTES_V1,
    "SCCP source proof"
);

/// Position of the burn event on the source chain.
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
#[norito_schema(name = "iroha_data_model::sccp::inbound::SccpSourceLocatorV1")]
pub struct SccpSourceLocatorV1 {
    /// Source block height (TON: masterchain or shard seqno as the verifier normalizes it).
    pub source_height: u64,
    /// Source block hash.
    pub block_hash: [u8; 32],
    /// Index of the transaction or log carrying the event within the block.
    pub index_in_block: u32,
}

/// Why a proven inbound message is not yet settled (§4.12.3, §4.12.5).
///
/// Every reason is a hold that `SettleSccpV1::Inbound` retries; none is permanent. A recipient
/// that can never be credited bounces instead (`SccpBounceReasonV1`).
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
#[norito(tag = "reason", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::inbound::SccpPendingReasonV1")]
pub enum SccpPendingReasonV1 {
    /// SCCP `enabled` is false.
    #[codec(index = 0)]
    #[norito(rename = "disabled")]
    Disabled,
    /// The revision is neither `Bidirectional` nor `InboundOnly` (it is `Paused`).
    #[codec(index = 1)]
    #[norito(rename = "revision_not_settleable")]
    RevisionNotSettleable,
    /// `liability(r) < amount`: the external side released more than Taira locked.
    #[codec(index = 2)]
    #[norito(rename = "liability_shortfall")]
    LiabilityShortfall,
    /// The release movement refuses the credit now (the recipient's incoming transfer control,
    /// holding limit or custody, or the XOR definition's transfer and usage policy).
    #[codec(index = 3)]
    #[norito(rename = "credit_refused")]
    CreditRefused,
    /// A self-claim fee is due and the Nexus fee sink does not resolve to an account that can
    /// receive it.
    #[codec(index = 4)]
    #[norito(rename = "fee_sink_unavailable")]
    FeeSinkUnavailable,
    /// The message bounces, and the executing block already holds its maximum of SCCP leaves.
    #[codec(index = 5)]
    #[norito(rename = "block_leaves_full")]
    BlockLeavesFull,
}

/// Payload of [`SccpInboundStatusV1::Pending`].
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
#[norito_schema(name = "iroha_data_model::sccp::inbound::SccpPendingStatusV1")]
pub struct SccpPendingStatusV1 {
    /// Latest reason settlement could not complete.
    pub reason: SccpPendingReasonV1,
}

/// Payload of [`SccpInboundStatusV1::Bounced`].
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
#[norito_schema(name = "iroha_data_model::sccp::inbound::SccpBounceStatusV1")]
pub struct SccpBounceStatusV1 {
    /// Outbound message that returns the value to the source-chain sender.
    pub bounce_message_id: [u8; 32],
}

/// Lifecycle of one inbound record (§4.12).
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
#[norito(tag = "status", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::inbound::SccpInboundStatusV1")]
pub enum SccpInboundStatusV1 {
    /// Proven, settlement retried by `SettleSccpV1::Inbound`.
    #[codec(index = 0)]
    #[norito(rename = "pending")]
    Pending(SccpPendingStatusV1),
    /// Released to the recipient.
    #[codec(index = 1)]
    #[norito(rename = "released")]
    Released(SccpStatusHeightV1),
    /// Returned to the source-chain sender by an outbound bounce.
    #[codec(index = 2)]
    #[norito(rename = "bounced")]
    Bounced(SccpBounceStatusV1),
}

impl SccpInboundStatusV1 {
    /// Build a `Pending` status.
    #[must_use]
    pub const fn pending(reason: SccpPendingReasonV1) -> Self {
        Self::Pending(SccpPendingStatusV1 { reason })
    }

    /// Return whether the record still waits for settlement.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }
}

/// Stored inbound message (`sccp_inbound_messages[message_id]`, §4.12.1).
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
#[norito_schema(name = "iroha_data_model::sccp::inbound::SccpInboundRecordV1")]
pub struct SccpInboundRecordV1 {
    /// External source network.
    pub network: SccpNetworkV1,
    /// Route revision whose deployment emitted the burn.
    pub revision: u32,
    /// Canonical §3.2 payload.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub payload: Vec<u8>,
    /// Source-chain position of the burn event.
    pub source_locator: SccpSourceLocatorV1,
    /// Taira height at which the proof was accepted.
    pub proven_at_height: u64,
    /// Self-claim fee charged once at release, strictly below the amount. Only a fee-exempt
    /// self-claim of the recipient sets it (§4.12.4); it is 0 for relayed proofs and for
    /// recipients that paid the ordinary fee.
    #[norito(json = "crate::json_helpers::u128_string")]
    pub fee_due: u128,
    /// Lifecycle status.
    pub status: SccpInboundStatusV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};
    use norito::{codec::DecodeAll as _, core::DecodeFromSlice as _};

    const REASONS: [SccpPendingReasonV1; 6] = [
        SccpPendingReasonV1::Disabled,
        SccpPendingReasonV1::RevisionNotSettleable,
        SccpPendingReasonV1::LiabilityShortfall,
        SccpPendingReasonV1::CreditRefused,
        SccpPendingReasonV1::FeeSinkUnavailable,
        SccpPendingReasonV1::BlockLeavesFull,
    ];

    fn statuses() -> [SccpInboundStatusV1; 5] {
        [
            SccpInboundStatusV1::pending(SccpPendingReasonV1::Disabled),
            SccpInboundStatusV1::pending(SccpPendingReasonV1::RevisionNotSettleable),
            SccpInboundStatusV1::pending(SccpPendingReasonV1::LiabilityShortfall),
            SccpInboundStatusV1::Released(SccpStatusHeightV1 { height: 5 }),
            SccpInboundStatusV1::Bounced(SccpBounceStatusV1 {
                bounce_message_id: [6; 32],
            }),
        ]
    }

    fn record(status: SccpInboundStatusV1) -> SccpInboundRecordV1 {
        SccpInboundRecordV1 {
            network: SccpNetworkV1::BscMainnet,
            revision: 2,
            payload: vec![2, 1, 0, 0, 0, 2],
            source_locator: SccpSourceLocatorV1 {
                source_height: 70_000_000,
                block_hash: [7; 32],
                index_in_block: 12,
            },
            proven_at_height: 44,
            fee_due: 10_000_000,
            status,
        }
    }

    #[test]
    fn binary_and_json_roundtrip() {
        for status in statuses() {
            roundtrip(&status);
            roundtrip(&record(status));
        }
        for reason in REASONS {
            roundtrip(&reason);
            let status = SccpInboundStatusV1::pending(reason);
            assert!(status.is_pending());
            roundtrip(&status);
            roundtrip(&record(status));
        }
        roundtrip(&SccpSourceProofBytesV1::new(vec![0x4e, 0x52, 0x54]).expect("bounded"));
        assert_rejects_unknown_field(&record(statuses()[0]), &[]);
        assert_rejects_unknown_field(&record(statuses()[0]), &["source_locator"]);
        assert_rejects_unknown_field(&SccpSourceProofBytesV1::new(vec![1]).expect("bounded"), &[]);
    }

    #[test]
    fn status_helpers() {
        let [disabled, not_settleable, shortfall, released, bounced] = statuses();
        for status in [disabled, not_settleable, shortfall] {
            assert!(status.is_pending());
        }
        assert!(!released.is_pending());
        assert!(!bounced.is_pending());
        assert_eq!(
            disabled,
            SccpInboundStatusV1::Pending(SccpPendingStatusV1 {
                reason: SccpPendingReasonV1::Disabled
            })
        );
    }

    #[test]
    fn source_proof_bounds_hold_at_every_boundary() {
        assert_eq!(SCCP_SOURCE_PROOF_MAX_BYTES_V1, 8_388_608);
        assert_eq!(
            SccpSourceProofBytesV1::MAX_BYTES,
            SCCP_SOURCE_PROOF_MAX_BYTES_V1
        );
        assert!(SccpSourceProofBytesV1::new(Vec::new()).is_err());
        let max = SccpSourceProofBytesV1::new(vec![0xab; SCCP_SOURCE_PROOF_MAX_BYTES_V1])
            .expect("maximum fits");
        assert_eq!(max.len(), SCCP_SOURCE_PROOF_MAX_BYTES_V1);
        assert!(!max.is_empty());
        assert!(SccpSourceProofBytesV1::new(vec![0; SCCP_SOURCE_PROOF_MAX_BYTES_V1 + 1]).is_err());

        // An over-long or empty value forged past the constructor fails every decoder.
        for forged in [
            SccpSourceProofBytesV1 {
                bytes: vec![0; SCCP_SOURCE_PROOF_MAX_BYTES_V1 + 1],
            },
            SccpSourceProofBytesV1 { bytes: Vec::new() },
        ] {
            let encoded = forged.encode();
            assert!(SccpSourceProofBytesV1::decode_all(&mut encoded.as_slice()).is_err());
            assert!(SccpSourceProofBytesV1::decode_from_slice(&encoded).is_err());
            let framed = norito::to_bytes(&forged).expect("frame");
            assert!(norito::decode_from_bytes::<SccpSourceProofBytesV1>(&framed).is_err());
            let json = norito::json::to_json(&forged).expect("json");
            assert!(norito::json::from_json::<SccpSourceProofBytesV1>(&json).is_err());
        }

        let small = SccpSourceProofBytesV1::new(vec![1, 2, 3]).expect("bounded");
        assert_eq!(small.as_bytes(), &[1, 2, 3]);
        let json = norito::json::to_json(&small).expect("json");
        assert_eq!(json, "{\"bytes\":\"AQID\"}");
        assert_eq!(small.into_bytes(), vec![1, 2, 3]);
    }
}
