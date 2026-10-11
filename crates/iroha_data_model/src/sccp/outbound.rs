//! SCCP v1 outbound records, voids and refunds (`specs/sccp.md` §4.4, §4.16).
//!
//! `RecordSccpMessage` locks XOR in the route escrow and stores one
//! [`SccpOutboundMessageRecordV1`] per message. Taira never observes a mint, so a minted record
//! stays [`SccpOutboundStatusV1::Recorded`]; a record leaves that state only through a proven
//! void on the destination, after which its amount is refunded or stranded.

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, bridge::SccpNetworkV1,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// How a destination voided a nonce (§4.16, §5.1.8).
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
#[norito(tag = "kind", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::outbound::SccpVoidKindV1")]
pub enum SccpVoidKindV1 {
    /// `voidExpired`: the mint deadline passed.
    #[codec(index = 0)]
    #[norito(rename = "expired")]
    Expired,
    /// `voidFrozen`: the destination's current and previous rosters expired.
    #[codec(index = 1)]
    #[norito(rename = "frozen")]
    Frozen,
}

/// A status that only records the Taira height at which it was reached.
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
#[norito_schema(name = "iroha_data_model::sccp::outbound::SccpStatusHeightV1")]
pub struct SccpStatusHeightV1 {
    /// Taira height of the transition.
    pub height: u64,
}

/// Payload of [`SccpOutboundStatusV1::Voided`].
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
#[norito_schema(name = "iroha_data_model::sccp::outbound::SccpVoidStatusV1")]
pub struct SccpVoidStatusV1 {
    /// Void kind proven by the destination event.
    pub kind: SccpVoidKindV1,
    /// Taira height at which the void was proven.
    pub proven_at_height: u64,
    /// Whether the refund waits for `SettleSccpV1::Refund` (SCCP disabled, the revision
    /// paused, the credit refused by the release movement now, or the void's inline release
    /// budget spent, §4.16).
    pub refund_pending: bool,
}

/// Lifecycle of one outbound record (§4.4, §4.16).
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
#[norito_schema(name = "iroha_data_model::sccp::outbound::SccpOutboundStatusV1")]
pub enum SccpOutboundStatusV1 {
    /// Recorded; minted or still mintable (Taira cannot tell).
    #[codec(index = 0)]
    #[norito(rename = "recorded")]
    Recorded,
    /// Voided on the destination and proven on Taira.
    #[codec(index = 1)]
    #[norito(rename = "voided")]
    Voided(SccpVoidStatusV1),
    /// Refunded to the sender.
    #[codec(index = 2)]
    #[norito(rename = "refunded")]
    Refunded(SccpStatusHeightV1),
    /// Moved to the route's `stranded` balance (sender is the escrow or can never be credited).
    #[codec(index = 3)]
    #[norito(rename = "stranded")]
    Stranded(SccpStatusHeightV1),
}

impl SccpOutboundStatusV1 {
    /// Return whether the record is still `Recorded`.
    #[must_use]
    pub const fn is_recorded(&self) -> bool {
        matches!(self, Self::Recorded)
    }

    /// Return whether the record is voided with its refund waiting for settlement.
    #[must_use]
    pub const fn is_refund_pending(&self) -> bool {
        matches!(
            self,
            Self::Voided(SccpVoidStatusV1 {
                refund_pending: true,
                ..
            })
        )
    }
}

/// Stored outbound message (`sccp_outbound_messages[message_id]`, §4.4 step 13).
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
#[norito_schema(name = "iroha_data_model::sccp::outbound::SccpOutboundMessageRecordV1")]
pub struct SccpOutboundMessageRecordV1 {
    /// External target network.
    pub network: SccpNetworkV1,
    /// Route revision the message was recorded on.
    pub revision: u32,
    /// Dense per-revision nonce, starting at 0.
    pub nonce: u64,
    /// Recording Taira height.
    pub height: u64,
    /// Leaf index within that block.
    pub commitment_index: u32,
    /// Destination-time mint deadline.
    pub deadline_ms: u64,
    /// Sender account (the route escrow for a bounce).
    pub sender: AccountId,
    /// Amount in Taira units (equal to token units).
    #[norito(json = "crate::json_helpers::u128_string")]
    pub amount: u128,
    /// Canonical §3.2 payload.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub payload: Vec<u8>,
    /// §3.4 transfer leaf.
    pub leaf: [u8; 32],
    /// Lifecycle status.
    pub status: SccpOutboundStatusV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};
    use iroha_crypto::{Algorithm, KeyPair};

    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("deterministic Ed25519 seed");
        AccountId::new(key_pair.public_key().clone())
    }

    fn statuses() -> [SccpOutboundStatusV1; 6] {
        [
            SccpOutboundStatusV1::Recorded,
            SccpOutboundStatusV1::Voided(SccpVoidStatusV1 {
                kind: SccpVoidKindV1::Expired,
                proven_at_height: 10,
                refund_pending: false,
            }),
            SccpOutboundStatusV1::Voided(SccpVoidStatusV1 {
                kind: SccpVoidKindV1::Frozen,
                proven_at_height: 11,
                refund_pending: true,
            }),
            SccpOutboundStatusV1::Refunded(SccpStatusHeightV1 { height: 12 }),
            SccpOutboundStatusV1::Stranded(SccpStatusHeightV1 { height: 13 }),
            SccpOutboundStatusV1::Recorded,
        ]
    }

    fn record(status: SccpOutboundStatusV1) -> SccpOutboundMessageRecordV1 {
        SccpOutboundMessageRecordV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            nonce: 0,
            height: 7,
            commitment_index: 2,
            deadline_ms: 1_758_604_800_000,
            sender: account(1),
            amount: u128::MAX,
            payload: vec![0x02, 0x01, 0xaa],
            leaf: [9; 32],
            status,
        }
    }

    #[test]
    fn binary_and_json_roundtrip() {
        for kind in [SccpVoidKindV1::Expired, SccpVoidKindV1::Frozen] {
            roundtrip(&kind);
        }
        for status in statuses() {
            roundtrip(&status);
            roundtrip(&record(status));
        }
        assert_rejects_unknown_field(&record(SccpOutboundStatusV1::Recorded), &[]);
        assert_rejects_unknown_field(&statuses()[1], &["detail"]);
    }

    #[test]
    fn amount_is_a_decimal_string_and_payload_is_base64() {
        let json = norito::json::to_json(&record(SccpOutboundStatusV1::Recorded)).expect("json");
        assert!(
            json.contains(&format!("\"amount\":\"{}\"", u128::MAX)),
            "{json}"
        );
        assert!(json.contains("\"payload\":\"AgGq\""), "{json}");
    }

    #[test]
    fn status_predicates() {
        let [recorded, voided, pending, refunded, stranded, _] = statuses();
        assert!(recorded.is_recorded());
        for status in [voided, pending, refunded, stranded] {
            assert!(!status.is_recorded());
        }
        assert!(pending.is_refund_pending());
        for status in [recorded, voided, refunded, stranded] {
            assert!(!status.is_refund_pending());
        }
    }
}
