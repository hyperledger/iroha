//! Instructions of the global chain's AMX two-phase commit (`specs/sumeragi.md` §11).
//!
//! The global chain executes them natively over its AMX World state
//! ([`crate::sumeragi_amx::SumeragiAmxState`]); every record they create is a World write of the
//! executing block, so participants can prove it against the block's certified result.

use super::*;
use crate::sumeragi_amx::{AmxHandoffProofV1, AmxRecordProofV1, AmxTransactionV1};
use iroha_model_base::topology::DataSpaceId;

isi! {
    /// Register a participant dataspace and anchor its foreign-committee tracker at an
    /// independently authenticated epoch context of its consensus instance (§11.7).
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::RegisterAmxDataspaceV1")]
    pub struct RegisterAmxDataspaceV1 {
        /// The dataspace.
        pub dataspace: DataSpaceId,
        /// Consensus instance id `I_J` of the dataspace.
        #[norito(
            with = "crate::json_helpers::fixed_bytes_hex",
            bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
        )]
        pub instance: [u8; 32],
        /// Canonical Norito frame of the trusted `ValidatorEpochContextV1` (its signed genesis
        /// context, or a context its governance certified).
        #[norito(
            with = "crate::json_helpers::base64_vec",
            bounded_with = "crate::json_helpers::base64_vec::serialize_bounded"
        )]
        pub anchor: Vec<u8>,
    }
}

isi! {
    /// Record `Begin{x, participants, d}` of an AMX transaction (§11.2).
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::BeginAmxV1")]
    pub struct BeginAmxV1 {
        /// The transaction `X`.
        pub transaction: AmxTransactionV1,
    }
}

isi! {
    /// Record Abort for an existing unresolved AMX obligation whose signed boundary is due.
    /// The executing Global block's authenticated time and height determine eligibility.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::ExpireAmxV1")]
    pub struct ExpireAmxV1 {
        /// Exact transaction identity of the existing Global Begin.
        #[norito(
            with = "crate::json_helpers::fixed_bytes_hex",
            bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
        )]
        pub tx: [u8; 32],
    }
}

isi! {
    /// Relay a participant's `Prepared` record proof (§11.4).
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::RelayAmxPreparedV1")]
    pub struct RelayAmxPreparedV1 {
        /// The record proof.
        pub proof: AmxRecordProofV1,
    }
}

isi! {
    /// Relay a handoff proof of a participant's consensus instance (§11.7).
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::RelayAmxHandoffV1")]
    pub struct RelayAmxHandoffV1 {
        /// The participant whose instance hands off.
        pub dataspace: DataSpaceId,
        /// The handoff proof.
        pub proof: AmxHandoffProofV1,
    }
}

isi! {
    /// Install a native participant only within its independently authenticated signed genesis.
    /// The root's signed parent network and this signed global chain label derive the sole
    /// trusted global instance; later callers cannot replace its epoch anchor.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::RegisterAmxParticipantV1")]
    pub struct RegisterAmxParticipantV1 {
        /// Full identifier of the executing private dataspace root.
        pub dataspace: DataSpaceId,
        /// Global chain label authenticated by this private root's signed genesis.
        pub global_chain_id: iroha_model_base::chain::ChainId,
        /// Complete canonical `SignedBlockWire` of global genesis, with its result-only certificate.
        #[norito(with = "crate::json_helpers::base64_vec",
                 bounded_with = "crate::json_helpers::base64_vec::serialize_bounded")]
        pub global_genesis: Vec<u8>,
        /// Canonical H2 successor whose exact quorum binds the original genesis result.
        #[norito(with = "crate::json_helpers::base64_vec",
                 bounded_with = "crate::json_helpers::base64_vec::serialize_bounded")]
        pub global_successor: Vec<u8>,
    }
}
isi! {
    /// Prepare the executing dataspace's exact native transfer leg against a global Begin proof.
    /// The outer authority must hold the source owner's current exact `CanPrepareAmx` permission.
    /// The current native host supports ordinary non-retail numeric transfers. Enrolled-wallet
    /// and registered retail monetary legs record No without monetary/maintenance effects;
    /// a relayer cannot manufacture the customer's original signed fee assessment.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::PrepareAmxV1")]
    pub struct PrepareAmxV1 {
        /// Exact executing participant, used also for native admission routing.
        pub dataspace: DataSpaceId,
        /// Complete transaction whose local payload is an `AmxTransferLegV1` frame.
        pub transaction: AmxTransactionV1,
        /// Global chain's certified Begin record for this same transaction.
        pub begin: AmxRecordProofV1,
    }
}
isi! {
    /// Apply or release retained native AMX escrow only with the global decision proof.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::SettleAmxV1")]
    pub struct SettleAmxV1 {
        /// Exact executing participant, used also for native admission routing.
        pub dataspace: DataSpaceId,
        /// Authenticated global Commit or Abort decision.
        pub decision: AmxRecordProofV1,
    }
}
isi! {
    /// Advance a native participant's global tracker by one authenticated epoch handoff.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sumeragi_amx::RelayGlobalAmxHandoffV1")]
    pub struct RelayGlobalAmxHandoffV1 {
        /// Exact executing participant, used also for native admission routing.
        pub dataspace: DataSpaceId,
        /// Global chain's certified epoch boundary.
        pub proof: AmxHandoffProofV1,
    }
}

impl RegisterAmxDataspaceV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.register_dataspace.v1";
}
impl BeginAmxV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.begin.v1";
}
impl ExpireAmxV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.expire.v1";
}
impl crate::seal::Instruction for ExpireAmxV1 {}

impl RelayAmxPreparedV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.relay_prepared.v1";
}
impl RelayAmxHandoffV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.relay_handoff.v1";
}

impl crate::seal::Instruction for RegisterAmxDataspaceV1 {}
impl crate::seal::Instruction for BeginAmxV1 {}
impl crate::seal::Instruction for RelayAmxPreparedV1 {}
impl crate::seal::Instruction for RelayAmxHandoffV1 {}

impl RegisterAmxParticipantV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.register_participant.v1";
}
impl crate::seal::Instruction for RegisterAmxParticipantV1 {}

impl PrepareAmxV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.prepare.v1";
}
impl crate::seal::Instruction for PrepareAmxV1 {}

impl SettleAmxV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.settle.v1";
}
impl crate::seal::Instruction for SettleAmxV1 {}

impl RelayGlobalAmxHandoffV1 {
    /// Stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.sumeragi.amx.relay_global_handoff.v1";
}
impl crate::seal::Instruction for RelayGlobalAmxHandoffV1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi_amx::{AmxLegV1, AmxTransactionV1};

    #[test]
    fn sumeragi_amx_instructions_decode_through_the_default_registry() {
        let registry = crate::instruction_registry::default();
        let begin = BeginAmxV1 {
            transaction: AmxTransactionV1 {
                legs: vec![
                    AmxLegV1 {
                        dataspace: DataSpaceId::new(1),
                        payload: vec![1],
                    },
                    AmxLegV1 {
                        dataspace: DataSpaceId::new(2),
                        payload: vec![2],
                    },
                ],
                deadline: 9,
                expires_at_ms: 1_000_000,
                nonce: [3; 32],
            },
        };
        let register = RegisterAmxDataspaceV1 {
            dataspace: DataSpaceId::new(1),
            instance: [4; 32],
            anchor: vec![5, 6],
        };
        for (wire_id, instruction) in [
            (BeginAmxV1::WIRE_ID, InstructionBox::from(begin.clone())),
            (
                ExpireAmxV1::WIRE_ID,
                InstructionBox::from(ExpireAmxV1 { tx: [9; 32] }),
            ),
            (
                RegisterAmxDataspaceV1::WIRE_ID,
                InstructionBox::from(register.clone()),
            ),
        ] {
            assert!(registry.contains(wire_id), "{wire_id}");
            let bytes = norito::encode_canonical(&instruction).expect("encode");
            let decoded: InstructionBox = norito::decode_canonical(&bytes).expect("decode");
            assert_eq!(decoded, instruction);
        }
        assert!(registry.contains(RelayAmxPreparedV1::WIRE_ID));
        assert!(registry.contains(RelayAmxHandoffV1::WIRE_ID));
        let block = crate::sumeragi_amx::AmxCertifiedBlockV1 {
            consensus_header: vec![1],
            commit_qc: vec![2],
            result_preimage: vec![3],
        };
        let proof = AmxRecordProofV1 {
            block: block.clone(),
            record: crate::sumeragi_amx::AmxRecordV1::Decision(
                crate::sumeragi_amx::AmxDecisionV1 {
                    tx: [4; 32],
                    outcome: crate::sumeragi_amx::AmxOutcomeV1::Abort,
                },
            ),
            write: crate::sumeragi_amx::AmxWriteProofV1 {
                present: [0; 32],
                siblings: Vec::new(),
            },
        };
        for (wire_id, instruction) in [
            (
                RegisterAmxParticipantV1::WIRE_ID,
                InstructionBox::from(RegisterAmxParticipantV1 {
                    dataspace: DataSpaceId::new(u64::MAX),
                    global_chain_id: "signed-parent".into(),
                    global_genesis: vec![5],
                    global_successor: vec![6],
                }),
            ),
            (
                PrepareAmxV1::WIRE_ID,
                InstructionBox::from(PrepareAmxV1 {
                    dataspace: DataSpaceId::new(u64::MAX),
                    transaction: begin.transaction.clone(),
                    begin: proof.clone(),
                }),
            ),
            (
                SettleAmxV1::WIRE_ID,
                InstructionBox::from(SettleAmxV1 {
                    dataspace: DataSpaceId::new(u64::MAX),
                    decision: proof,
                }),
            ),
            (
                RelayGlobalAmxHandoffV1::WIRE_ID,
                InstructionBox::from(RelayGlobalAmxHandoffV1 {
                    dataspace: DataSpaceId::new(u64::MAX),
                    proof: AmxHandoffProofV1 { block },
                }),
            ),
        ] {
            assert!(registry.contains(wire_id), "{wire_id}");
            assert_eq!(
                norito::decode_canonical::<InstructionBox>(
                    &norito::encode_canonical(&instruction).unwrap()
                )
                .unwrap(),
                instruction
            );
            assert_eq!(
                norito::json::from_str::<InstructionBox>(
                    &norito::json::to_json(&instruction).unwrap()
                )
                .unwrap(),
                instruction
            );
        }
        let json = norito::json::to_json(&begin).expect("json");
        assert_eq!(
            norito::json::from_str::<BeginAmxV1>(&json).expect("json decode"),
            begin
        );
    }
}
