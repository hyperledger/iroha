//! SCCP v1 block leaves and destination control messages (`specs/sccp.md` §3.4, §4.5,
//! §4.14.6).
//!
//! A block commits its SCCP messages as leaves in `commitment_index` order. A leaf is either a
//! transfer (an outbound record) or a control (the complete destination pause state after a certified change).
//! `sccp_block_leaves[(height, commitment_index)]` stores a [`SccpLeafRefV1`] that points at
//! the record whose stored leaf hash enters the block root.
//!
//! The Iroha schema style admits only single-field tuple variants, so each leaf kind carries a
//! payload struct.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, bridge::SccpNetworkV1};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// First control nonce of every route revision (`next_control_nonce` starts at 1).
pub const SCCP_FIRST_CONTROL_NONCE_V1: u64 = 1;

/// Transfer leaf reference: the outbound record keyed by `message_id`.
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
#[norito_schema(name = "iroha_data_model::sccp::control::SccpTransferLeafRefV1")]
pub struct SccpTransferLeafRefV1 {
    /// Key of `sccp_outbound_messages`.
    pub message_id: [u8; 32],
}

/// Control leaf reference: the key of `sccp_control_messages`.
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
#[norito_schema(name = "iroha_data_model::sccp::control::SccpControlLeafRefV1")]
pub struct SccpControlLeafRefV1 {
    /// External network the control targets.
    pub network: SccpNetworkV1,
    /// Route revision whose deployment receives the control.
    pub revision: u32,
    /// Control nonce, `≥ 1` and strictly increasing per `(network, revision)`.
    pub control_nonce: u64,
}

/// One entry of `sccp_block_leaves` (§4.5).
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
#[norito(tag = "leaf", content = "reference")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::control::SccpLeafRefV1")]
pub enum SccpLeafRefV1 {
    /// Outbound transfer (§4.4).
    #[codec(index = 0)]
    #[norito(rename = "transfer")]
    Transfer(SccpTransferLeafRefV1),
    /// Destination control message (§4.14.6).
    #[codec(index = 1)]
    #[norito(rename = "control")]
    Control(SccpControlLeafRefV1),
}

impl SccpLeafRefV1 {
    /// Build a transfer leaf reference.
    #[must_use]
    pub const fn transfer(message_id: [u8; 32]) -> Self {
        Self::Transfer(SccpTransferLeafRefV1 { message_id })
    }

    /// Build a control leaf reference.
    #[must_use]
    pub const fn control(network: SccpNetworkV1, revision: u32, control_nonce: u64) -> Self {
        Self::Control(SccpControlLeafRefV1 {
            network,
            revision,
            control_nonce,
        })
    }
}

/// Stored destination control message (`sccp_control_messages`, §4.14.6).
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
#[norito_schema(name = "iroha_data_model::sccp::control::SccpControlRecordV1")]
pub struct SccpControlRecordV1 {
    /// Enacting authority: 1 for Parliament, 2 for fast pause.
    pub track: u8,
    /// Parliament pause flag after the change.
    pub parliament_paused: bool,
    /// Active fast-pause expiry after the change, or zero when none is active.
    pub fast_pause_until_ms: u64,
    /// Exact enacting certificate identity; never a proposal identifier.
    pub certificate_id: [u8; 32],
    /// Effect preimage hash authenticated by that certificate.
    pub effect_hash: [u8; 32],
    /// Taira height that recorded the control.
    pub height: u64,
    /// Leaf index within that block.
    pub commitment_index: u32,
    /// §3.4 control leaf.
    pub leaf: [u8; 32],
}

impl SccpControlRecordV1 {
    /// Check the native control fields and the bounded block-leaf index.
    ///
    /// This is structural validation; the recorder and native proof reader must
    /// separately bind the exact certificate authority, route, and leaf hash.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        matches!(self.track, 1 | 2)
            && (self.track != 2 || self.fast_pause_until_ms != 0)
            && self.certificate_id != [0; 32]
            && self.effect_hash != [0; 32]
            && self.commitment_index < super::params::SCCP_MESSAGES_MAX_PER_BLOCK_V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};

    #[test]
    fn binary_and_json_roundtrip() {
        let transfer = SccpLeafRefV1::transfer([7; 32]);
        let control = SccpLeafRefV1::control(SccpNetworkV1::TonMainnet, 2, u64::MAX);
        roundtrip(&transfer);
        roundtrip(&control);
        roundtrip(&SccpControlRecordV1 {
            track: 1,
            parliament_paused: true,
            fast_pause_until_ms: 0,
            height: 99,
            commitment_index: 511,
            leaf: [3; 32],
            certificate_id: [4; 32],
            effect_hash: [0x45; 32],
        });
        assert_rejects_unknown_field(&control, &["reference"]);
        assert_rejects_unknown_field(&transfer, &[]);
    }

    #[test]
    fn constructors_build_the_expected_variants() {
        assert_eq!(
            SccpLeafRefV1::transfer([1; 32]),
            SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 {
                message_id: [1; 32]
            })
        );
        assert_eq!(
            SccpLeafRefV1::control(SccpNetworkV1::BscMainnet, 3, 1),
            SccpLeafRefV1::Control(SccpControlLeafRefV1 {
                network: SccpNetworkV1::BscMainnet,
                revision: 3,
                control_nonce: 1,
            })
        );
        assert_eq!(SCCP_FIRST_CONTROL_NONCE_V1, 1);
    }

    #[test]
    fn json_tags_are_snake_case() {
        let json = norito::json::to_json(&SccpLeafRefV1::transfer([0; 32])).expect("json");
        assert!(json.contains("\"leaf\":\"transfer\""), "{json}");
        let json = norito::json::to_json(&SccpLeafRefV1::control(
            SccpNetworkV1::EthereumMainnet,
            1,
            1,
        ))
        .expect("json");
        assert!(json.contains("\"leaf\":\"control\""), "{json}");
    }
    #[test]
    fn native_control_fields_are_bounded_and_both_tracks_roundtrip() {
        let mut record = SccpControlRecordV1 {
            track: 1,
            parliament_paused: false,
            fast_pause_until_ms: 0,
            certificate_id: [3; 32],
            effect_hash: [4; 32],
            height: 7,
            commitment_index: 511,
            leaf: [5; 32],
        };
        assert!(record.is_well_formed());
        roundtrip(&record);
        record.track = 2;
        assert!(!record.is_well_formed());
        record.fast_pause_until_ms = 1;
        assert!(record.is_well_formed());
        roundtrip(&record);
        for invalid_track in [0, 3, u8::MAX] {
            let invalid = SccpControlRecordV1 {
                track: invalid_track,
                ..record
            };
            assert!(!invalid.is_well_formed());
        }
        for invalid in [
            SccpControlRecordV1 {
                certificate_id: [0; 32],
                ..record
            },
            SccpControlRecordV1 {
                effect_hash: [0; 32],
                ..record
            },
            SccpControlRecordV1 {
                commitment_index: 512,
                ..record
            },
        ] {
            assert!(!invalid.is_well_formed());
        }
        assert_rejects_unknown_field(&record, &[]);
        for retired in ["paused", "proposal_id"] {
            let mut value = norito::json::to_value(&record).expect("record JSON");
            value
                .as_object_mut()
                .expect("object")
                .insert(retired.into(), norito::json::Value::Bool(true));
            let text = norito::json::to_json(&value).expect("JSON");
            assert!(norito::json::from_json::<SccpControlRecordV1>(&text).is_err());
        }
    }
}
