//! SCCP v1 instructions (`specs/sccp.md` §4).
//!
//! These are the wire structs of the SCCP v1 instructions. Core enforces every SCCP rule;
//! the default executor only allows visitors through. Per-chain proofs, advances and evidence
//! are the bounded opaque wrappers of [`crate::sccp`], decoded by `iroha_sccp::light_client`.

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceProofBytesV1,
        light_client::{SccpLcAdvanceBytesV1, SccpLcEvidenceBytesV1},
        native::SccpAnchorWitnessV1,
        params::SccpParametersV1,
    },
};
use iroha_primitives::numeric::Numeric;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Authenticated Global signed-genesis only: install SCCP parameters, route escrows and registry.
///
/// The same genesis execution's post-execution finalizer installs generation one from the
/// reconciled original height context before sealing the atomic output (§4.1, G1). This DATA
/// never grants authority to pre-authored transaction keys or to a later initialization block.
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::InitializeSccpV1")]
pub struct InitializeSccpV1 {
    /// Complete SCCP parameters; every §4.1 rule must hold.
    pub parameters: SccpParametersV1,
    /// Fresh nonzero randomness per Taira genesis (§4.18).
    pub reset_nonce: [u8; 32],
}
impl crate::seal::Instruction for InitializeSccpV1 {}

/// Accept a seat or reserve position in the currently drawn pause panel (§4.14.7).
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
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::sccp::AcceptSccpPausePanelSeatV1")]
#[derive(Copy)]
pub struct AcceptSccpPausePanelSeatV1 {
    /// Exact sequence of the seated panel.
    pub panel_seq: u64,
}
impl crate::seal::Instruction for AcceptSccpPausePanelSeatV1 {}

/// Endorse one current-head emergency pause as an eligible panel seat holder (§4.14.7).
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
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::sccp::EndorseSccpFastPauseV1")]
#[derive(Copy)]
pub struct EndorseSccpFastPauseV1 {
    /// Live chain network identity; a signature never crosses resets.
    pub network_id: crate::NetworkId,
    /// External route whose transfer activity is paused.
    pub network: SccpNetworkV1,
    /// Exact primary or backup panel identifier.
    pub panel_id: [u8; 32],
    /// Current `FastHold` subject revision, used as the endorsement nonce.
    pub head: u64,
    /// Nonzero public incident digest.
    pub incident_digest: [u8; 32],
}
impl crate::seal::Instruction for EndorseSccpFastPauseV1 {}

/// Lock XOR and record an outbound message to an external network (§4.4).
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::RecordSccpMessage")]
pub struct RecordSccpMessage {
    /// External target network.
    pub network: SccpNetworkV1,
    /// Revision the wallet verified; must be the route's `Bidirectional` revision.
    pub expected_revision: u32,
    /// XOR amount (§0); `taira_units(amount)` must be exact.
    pub amount: Numeric,
    /// Recipient bytes of the target's codec (§3.1).
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub recipient: Vec<u8>,
}
impl crate::seal::Instruction for RecordSccpMessage {}

/// Prove an inbound burn, then attempt settlement (§4.12.1).
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::SubmitSccpInboundMessageV1")]
pub struct SubmitSccpInboundMessageV1 {
    /// External source network.
    pub network: SccpNetworkV1,
    /// Route revision whose deployment emitted the burn.
    pub revision: u32,
    /// Canonical §3.2 payload.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub payload: Vec<u8>,
    /// Per-chain source proof.
    pub proof: SccpSourceProofBytesV1,
}
impl crate::seal::Instruction for SubmitSccpInboundMessageV1 {}

/// Prove a captured deployment finalized an unrecorded payload during its reconciliation window.
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::ProveSccpForgedMintV1")]
#[norito(decode_from_slice)]
pub struct ProveSccpForgedMintV1 {
    /// External destination network.
    pub network: SccpNetworkV1,
    /// Quarantined route revision with an open reconciliation window.
    pub revision: u32,
    /// Authenticated finalization event and its message-id-bound payload preimage.
    pub proof: crate::sccp::reconciliation::SccpForgedMintProofV1,
}
impl crate::seal::Instruction for ProveSccpForgedMintV1 {}

/// `SettleSccpV1::Inbound` target.
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
#[norito_schema(name = "iroha_data_model::isi::sccp::SccpSettleInboundV1")]
pub struct SccpSettleInboundV1 {
    /// Pending inbound message.
    pub message_id: [u8; 32],
}

/// `SettleSccpV1::Refund` target.
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
#[norito_schema(name = "iroha_data_model::isi::sccp::SccpSettleRefundV1")]
pub struct SccpSettleRefundV1 {
    /// External network.
    pub network: SccpNetworkV1,
    /// Route revision.
    pub revision: u32,
    /// Voided outbound nonce.
    pub nonce: u64,
}

/// What `SettleSccpV1` retries.
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
#[norito(tag = "target", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::SccpSettleTargetV1")]
pub enum SccpSettleTargetV1 {
    /// A `Pending` inbound settlement.
    #[codec(index = 0)]
    #[norito(rename = "inbound")]
    Inbound(SccpSettleInboundV1),
    /// A pending outbound refund.
    #[codec(index = 1)]
    #[norito(rename = "refund")]
    Refund(SccpSettleRefundV1),
}

/// Retry a pending inbound settlement or outbound refund without a proof (§4.12.1).
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::SettleSccpV1")]
pub struct SettleSccpV1 {
    /// Record to settle.
    pub target: SccpSettleTargetV1,
}
impl crate::seal::Instruction for SettleSccpV1 {}

impl SettleSccpV1 {
    /// Retry the inbound settlement of `message_id`.
    #[must_use]
    pub const fn inbound(message_id: [u8; 32]) -> Self {
        Self {
            target: SccpSettleTargetV1::Inbound(SccpSettleInboundV1 { message_id }),
        }
    }

    /// Retry the refund of outbound `(network, revision, nonce)`.
    #[must_use]
    pub const fn refund(network: SccpNetworkV1, revision: u32, nonce: u64) -> Self {
        Self {
            target: SccpSettleTargetV1::Refund(SccpSettleRefundV1 {
                network,
                revision,
                nonce,
            }),
        }
    }
}

/// Prove destination voids of outbound nonces and attempt refunds (§4.16).
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::SubmitSccpOutboundVoidV1")]
pub struct SubmitSccpOutboundVoidV1 {
    /// External network of the destination.
    pub network: SccpNetworkV1,
    /// Route revision whose deployment emitted the void.
    pub revision: u32,
    /// Per-chain source proof of the void event.
    pub proof: SccpSourceProofBytesV1,
}
impl crate::seal::Instruction for SubmitSccpOutboundVoidV1 {}

/// Permissionlessly advance a light client (§4.13.2).
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::AdvanceSccpLightClientV1")]
pub struct AdvanceSccpLightClientV1 {
    /// Source chain.
    pub network: SccpNetworkV1,
    /// Compare-and-swap guard on the light client's `state_hash`.
    #[norito(required)]
    pub expected_state_hash: Option<[u8; 32]>,
    /// Per-chain advance (including `Backfill`).
    pub advance: SccpLcAdvanceBytesV1,
}
impl crate::seal::Instruction for AdvanceSccpLightClientV1 {}

/// Freeze a light client with two conflicting quorum-valid records (§4.13.2).
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
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sccp::ReportSccpLightClientEquivocationV1")]
pub struct ReportSccpLightClientEquivocationV1 {
    /// Source chain.
    pub network: SccpNetworkV1,
    /// First record.
    pub a: SccpLcEvidenceBytesV1,
    /// Conflicting record.
    pub b: SccpLcEvidenceBytesV1,
}
impl crate::seal::Instruction for ReportSccpLightClientEquivocationV1 {}

/// Submit an exact native `CommitQC` certificate claiming an SCCP result Taira never made.
///
/// These fixed-size originals are DATA. Core must enforce §§3.8 and 4.9: active live-network
/// header, retained generation and liability, exact quorum BLS verification, first E1–E4
/// mismatch, immutable offender attribution and deduplication. A transaction carries no other
/// instruction; execution failure makes its block invalid (R-EX), not an ordinary paid failure.
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
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::sccp::SubmitSccpForgeryEvidenceV1")]
pub struct SubmitSccpForgeryEvidenceV1 {
    /// Exact 116-byte `QC_FIXED`, including its signer mask and result-body digest.
    pub qc: [u8; 116],
    /// Exact 221-byte SCCP finality header X; never reconstructed from untrusted fields.
    pub header: [u8; 221],
    /// Original compressed BLS aggregate signature; syntax alone is not verification.
    pub aggregate_signature: [u8; 96],
    /// Original anchor witness, required only for a height in a completed anchor chunk.
    #[norito(required)]
    pub anchor: Option<SccpAnchorWitnessV1>,
}
impl crate::seal::Instruction for SubmitSccpForgeryEvidenceV1 {}

impl_aos_decode_from_slice!(SubmitSccpForgeryEvidenceV1 {
    qc: [u8; 116],
    header: [u8; 221],
    aggregate_signature: [u8; 96],
    anchor: Option<SccpAnchorWitnessV1>,
});

impl_aos_decode_from_slice!(InitializeSccpV1 {
    parameters: SccpParametersV1,
    reset_nonce: [u8; 32],
});
impl_aos_decode_from_slice!(RecordSccpMessage {
    network: SccpNetworkV1,
    expected_revision: u32,
    amount: Numeric,
    recipient: Vec<u8>,
});
impl_aos_decode_from_slice!(SubmitSccpInboundMessageV1 {
    network: SccpNetworkV1,
    revision: u32,
    payload: Vec<u8>,
    proof: SccpSourceProofBytesV1,
});
impl_aos_decode_from_slice!(SettleSccpV1 {
    target: SccpSettleTargetV1,
});
impl_aos_decode_from_slice!(SubmitSccpOutboundVoidV1 {
    network: SccpNetworkV1,
    revision: u32,
    proof: SccpSourceProofBytesV1,
});
impl_aos_decode_from_slice!(AdvanceSccpLightClientV1 {
    network: SccpNetworkV1,
    expected_state_hash: Option<[u8; 32]>,
    advance: SccpLcAdvanceBytesV1,
});
impl_aos_decode_from_slice!(ReportSccpLightClientEquivocationV1 {
    network: SccpNetworkV1,
    a: SccpLcEvidenceBytesV1,
    b: SccpLcEvidenceBytesV1,
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        isi::test_support::assert_slice_roundtrip,
        sccp::test_support::{assert_rejects_unknown_field, roundtrip},
    };
    use norito::{codec::DecodeAll, core::DecodeFromSlice as _};

    const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
    const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;

    fn proof() -> SccpSourceProofBytesV1 {
        SccpSourceProofBytesV1::new(vec![0x4e, 0x52, 0x54, 0x30, 0x01]).expect("bounded")
    }

    fn check<T>(value: &T)
    where
        T: Clone
            + Encode
            + DecodeAll
            + norito::NoritoSerialize
            + for<'a> norito::NoritoDeserialize<'a>
            + for<'a> norito::core::DecodeFromSlice<'a>
            + norito::json::JsonSerialize
            + norito::json::JsonDeserialize
            + PartialEq
            + core::fmt::Debug,
    {
        roundtrip(value);
        assert_slice_roundtrip(value.clone());
        assert_rejects_unknown_field(value, &[]);
    }

    #[test]
    fn every_instruction_roundtrips() {
        check(&AcceptSccpPausePanelSeatV1 {
            panel_seq: u64::MAX,
        });
        check(&EndorseSccpFastPauseV1 {
            network_id: crate::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                crate::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::new([7; 32])
            )),
            network: ETH,
            panel_id: [8; 32],
            head: u64::MAX,
            incident_digest: [9; 32],
        });
        let evidence = SubmitSccpForgeryEvidenceV1 {
            qc: [0xa1; 116],
            header: [0xb2; 221],
            aggregate_signature: [0xc3; 96],
            anchor: Some(SccpAnchorWitnessV1 {
                core_hash: [1; 32],
                result: [0; 32],
                path: [[2; 32]; 12],
            }),
        };
        check(&evidence);
        check(&SubmitSccpForgeryEvidenceV1 {
            anchor: None,
            ..evidence
        });
        check(&InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x5a; 32],
        });
        check(&RecordSccpMessage {
            network: ETH,
            expected_revision: 1,
            amount: Numeric::new(1_500_000_000_u64, 9),
            recipient: vec![0x22; 20],
        });
        check(&SubmitSccpInboundMessageV1 {
            network: TON,
            revision: 2,
            payload: vec![2, 1, 0, 0, 0, 4],
            proof: proof(),
        });
        check(&SettleSccpV1::inbound([6; 32]));
        check(&SettleSccpV1::refund(ETH, 1, 7));
        check(&SubmitSccpOutboundVoidV1 {
            network: ETH,
            revision: 1,
            proof: proof(),
        });
        check(&AdvanceSccpLightClientV1 {
            network: ETH,
            expected_state_hash: Some([8; 32]),
            advance: SccpLcAdvanceBytesV1::new(vec![1; 64]).expect("bounded"),
        });
        check(&AdvanceSccpLightClientV1 {
            network: ETH,
            expected_state_hash: None,
            advance: SccpLcAdvanceBytesV1::new(vec![1]).expect("bounded"),
        });
        check(&ReportSccpLightClientEquivocationV1 {
            network: TON,
            a: SccpLcEvidenceBytesV1::new(vec![1, 2]).expect("bounded"),
            b: SccpLcEvidenceBytesV1::new(vec![3, 4]).expect("bounded"),
        });
    }

    #[test]
    fn instruction_ids_are_the_sccp_module_paths() {
        let ids = [
            crate::isi::Instruction::id(&InitializeSccpV1 {
                parameters: SccpParametersV1::taira_default(),
                reset_nonce: [1; 32],
            }),
            crate::isi::Instruction::id(&SettleSccpV1::inbound([0; 32])),
            crate::isi::Instruction::id(&RecordSccpMessage {
                network: ETH,
                expected_revision: 1,
                amount: Numeric::from(1_u64),
                recipient: vec![1; 20],
            }),
        ];
        assert_eq!(
            ids,
            [
                "iroha_data_model::isi::sccp::InitializeSccpV1",
                "iroha_data_model::isi::sccp::SettleSccpV1",
                "iroha_data_model::isi::sccp::RecordSccpMessage",
            ]
        );
    }

    #[test]
    fn settle_constructors_build_each_target() {
        assert_eq!(
            SettleSccpV1::inbound([3; 32]).target,
            SccpSettleTargetV1::Inbound(SccpSettleInboundV1 {
                message_id: [3; 32]
            })
        );
        assert_eq!(
            SettleSccpV1::refund(TON, 2, 9).target,
            SccpSettleTargetV1::Refund(SccpSettleRefundV1 {
                network: TON,
                revision: 2,
                nonce: 9,
            })
        );
        let json = norito::json::to_json(&SettleSccpV1::refund(TON, 2, 9)).expect("json");
        assert!(json.contains("\"target\":\"refund\""), "{json}");
    }

    #[test]
    fn instructions_reject_out_of_bounds_wrappers_and_trailing_bytes() {
        let valid = SubmitSccpOutboundVoidV1 {
            network: ETH,
            revision: 1,
            proof: proof(),
        };
        let mut json = norito::json::to_value(&valid).expect("value");
        json.as_object_mut()
            .expect("object")
            .insert("proof".to_owned(), norito::json!({ "bytes": "" }));
        let empty = norito::json::to_json(&json).expect("json");
        assert!(norito::json::from_json::<SubmitSccpOutboundVoidV1>(&empty).is_err());

        let mut encoded = valid.encode();
        encoded.push(0);
        assert!(SubmitSccpOutboundVoidV1::decode_from_slice(&encoded).is_err());
        assert!(SubmitSccpOutboundVoidV1::decode_all(&mut encoded.as_slice()).is_err());

        let evidence = ReportSccpLightClientEquivocationV1 {
            network: ETH,
            a: SccpLcEvidenceBytesV1::new(vec![1]).expect("bounded"),
            b: SccpLcEvidenceBytesV1::new(vec![2]).expect("bounded"),
        };
        let mut json = norito::json::to_value(&evidence).expect("value");
        json.as_object_mut().expect("object").remove("b");
        let missing = norito::json::to_json(&json).expect("json");
        assert!(norito::json::from_json::<ReportSccpLightClientEquivocationV1>(&missing).is_err());
    }
}
