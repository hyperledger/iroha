//! SCCP v1 block leaves and destination control messages (`specs/sccp.md` §3.4, §4.5,
//! §4.14.6).
//!
//! A block commits its SCCP messages as leaves in `commitment_index` order. A leaf is either a
//! transfer (an outbound record) or a control (the combined Parliament and fast-pause state).
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
    /// Enacting track: 1 for Parliament, 2 for the fast-pause panel.
    pub track: u8,
    /// Parliament pause flag after the enacting effect.
    pub parliament_paused: bool,
    /// Active destination fast-pause expiry, or zero when that part is not held.
    pub fast_pause_until_ms: u64,
    /// Content identifier of the exact enacting certificate, never the proposal id.
    pub certificate_id: [u8; 32],
    /// Effect hash carried by that certificate.
    pub effect_hash: [u8; 32],
    /// Taira height that recorded the control.
    pub height: u64,
    /// Leaf index within that block.
    pub commitment_index: u32,
    /// §3.4 control leaf.
    pub leaf: [u8; 32],
}

impl SccpControlRecordV1 {
    /// Whether the stored scalar fields satisfy the current control shape (§3.4).
    ///
    /// The key supplies target/revision/nonce. This structural check authenticates neither
    /// the certificate nor the leaf; Core recomputes the leaf from the complete effect.
    #[must_use]
    pub fn has_valid_shape(&self) -> bool {
        matches!(self.track, 1 | 2)
            && (self.track != 2 || self.fast_pause_until_ms != 0)
            && self.certificate_id != [0; 32]
            && self.effect_hash != [0; 32]
            && self.height != 0
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
            effect_hash: [5; 32],
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
    fn record() -> SccpControlRecordV1 {
        SccpControlRecordV1 {
            track: 1,
            parliament_paused: true,
            fast_pause_until_ms: 0,
            certificate_id: [1; 32],
            effect_hash: [2; 32],
            height: 7,
            commitment_index: 0,
            leaf: [3; 32],
        }
    }

    #[test]
    fn current_control_requires_every_field_and_rejects_retired_layout() {
        // Exact old five-field wire shape exists only as adversarial bytes in this test.
        #[derive(Encode, norito::NoritoSchema)]
        #[norito_schema(name = "test::RetiredControlShape")]
        struct RetiredControlShape {
            paused: bool,
            height: u64,
            commitment_index: u32,
            leaf: [u8; 32],
            proposal_id: [u8; 32],
        }

        let row = record();
        roundtrip(&row);
        assert_rejects_unknown_field(&row, &[]);
        for key in [
            "track",
            "parliament_paused",
            "fast_pause_until_ms",
            "certificate_id",
            "effect_hash",
            "height",
            "commitment_index",
            "leaf",
        ] {
            let mut raw = norito::json::to_value(&row).unwrap();
            let norito::json::Value::Object(fields) = &mut raw else {
                unreachable!()
            };
            fields.remove(key);
            assert!(
                norito::json::from_json::<SccpControlRecordV1>(
                    &norito::json::to_json(&raw).unwrap()
                )
                .is_err(),
                "missing {key}"
            );
        }
        let mut raw = norito::json::to_value(&row).unwrap();
        let norito::json::Value::Object(fields) = &mut raw else {
            unreachable!()
        };
        let paused = fields.remove("parliament_paused").unwrap();
        let proposal = fields.remove("certificate_id").unwrap();
        for key in ["track", "fast_pause_until_ms", "effect_hash"] {
            fields.remove(key);
        }
        fields.insert("paused".into(), paused);
        fields.insert("proposal_id".into(), proposal);
        assert!(
            norito::json::from_json::<SccpControlRecordV1>(&norito::json::to_json(&raw).unwrap())
                .is_err()
        );
        let bytes = norito::to_bytes(&RetiredControlShape {
            paused: true,
            height: 7,
            commitment_index: 0,
            leaf: [3; 32],
            proposal_id: [1; 32],
        })
        .unwrap();
        assert!(norito::decode_canonical::<SccpControlRecordV1>(&bytes).is_err());
    }

    #[test]
    fn current_control_shape_requires_cause_and_fast_track_expiry() {
        let original = record();
        assert!(original.has_valid_shape());
        let mut fast = original;
        fast.track = 2;
        assert!(!fast.has_valid_shape());
        fast.fast_pause_until_ms = 10;
        assert!(fast.has_valid_shape());
        for track in [0, 3, u8::MAX] {
            let mut row = original;
            row.track = track;
            assert!(!row.has_valid_shape());
        }
        let mut row = original;
        row.certificate_id = [0; 32];
        assert!(!row.has_valid_shape());
        let mut row = original;
        row.effect_hash = [0; 32];
        assert!(!row.has_valid_shape());
        let mut row = original;
        row.height = 0;
        assert!(!row.has_valid_shape());
        let mut row = original;
        row.commitment_index = 512;
        assert!(!row.has_valid_shape());
        row.commitment_index = 511;
        assert!(row.has_valid_shape());
    }
}
