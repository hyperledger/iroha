//! Typed governance instructions.
//!
//! These canonical data-model types are serialized into transactions and are executed by the
//! corresponding core governance paths. They also define the exact CLI and Torii draft surfaces;
//! endpoint-local aliases are not part of the instruction format.
#[cfg(not(feature = "governance"))]
pub use self::at_window_placeholder::AtWindow;
#[cfg(feature = "governance")]
pub use crate::governance::types::AtWindow;
#[cfg(test)]
use crate::governance::types::GlobalDataTriggerPermissionGovernanceActionV1;
pub use crate::parliament_types::VotingMode;
use crate::{
    governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, ContractEmergencyHoldProposalV1,
        ContractLifecycleGovernanceProposalV1, GlobalDataTriggerPermissionGovernanceProposalV1,
    },
    isi::sorafs::SorafsProviderGovernanceActionV1,
    prelude::*,
    runtime::RuntimeUpgradeManifest,
    smart_contract::manifest::ManifestProvenance,
    validation_fee::{ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1},
};
use iroha_primitives::numeric::Quantity;
use norito::codec::{Decode, Encode};
use std::{string::String, vec::Vec};

/// Attempt-based SORA Parliament instruction surface.
pub mod parliament;
pub use parliament::*;

#[cfg(not(feature = "governance"))]
mod at_window_placeholder {
    use super::*;
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Encode,
        Decode,
        iroha_schema::IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// Inclusive governance enactment window expressed in block heights.
    pub struct AtWindow {
        /// Lower bound (inclusive) of the enactment window.
        pub lower: u64,
        /// Upper bound (inclusive) of the enactment window.
        pub upper: u64,
    }
}
/// Propose deployment of an IVM bytecode (`.to`) by hash
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeDeployContract")]
pub struct ProposeDeployContract {
    /// Canonical public contract address targeted by the proposal.
    pub contract_address: crate::smart_contract::ContractAddress,
    /// Blake2b-32 hash of the compiled `.to` bytecode slated for deployment.
    pub code_hash: ContractCodeHash,
    /// Blake2b-32 hash of the ABI surface expected by the host.
    pub abi_hash: ContractAbiHash,
    /// Exact first-release ABI version; admission currently requires version one.
    pub abi_version: AbiVersion,
    /// Optional manifest provenance to attest the contract manifest on enactment.
    pub manifest_provenance: Option<ManifestProvenance>,
}
impl crate::seal::Instruction for ProposeDeployContract {}
/// Propose one owner-consented contract lifecycle transition through Parliament.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeContractLifecycleGovernance")]
pub struct ProposeContractLifecycleGovernance {
    /// Complete compare-and-swap lifecycle proposal.
    pub proposal: ContractLifecycleGovernanceProposalV1,
}
impl crate::seal::Instruction for ProposeContractLifecycleGovernance {}
/// Propose one non-consensual, time-bounded emergency contract hold.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeContractEmergencyHold")]
pub struct ProposeContractEmergencyHold {
    /// Complete emergency-containment proposal.
    pub proposal: ContractEmergencyHoldProposalV1,
}
impl crate::seal::Instruction for ProposeContractEmergencyHold {}
/// Propose granting or revoking one exact account's global data-trigger capability.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance"
)]
pub struct ProposeGlobalDataTriggerPermissionGovernance {
    /// Complete exact-account permission proposal.
    pub proposal: GlobalDataTriggerPermissionGovernanceProposalV1,
}
impl crate::seal::Instruction for ProposeGlobalDataTriggerPermissionGovernance {}
/// Propose a runtime upgrade manifest through governance.
///
/// Ledger admission requires an exact `CanProposeRuntimeUpgrade` permission whose ABI version and
/// hash match the manifest; contract-deployment permissions do not authorize runtime upgrades.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeRuntimeUpgradeProposal")]
pub struct ProposeRuntimeUpgradeProposal {
    /// Canonical runtime-upgrade manifest payload.
    pub manifest: RuntimeUpgradeManifest,
}
impl crate::seal::Instruction for ProposeRuntimeUpgradeProposal {}
/// Propose one SCCP v1 governance decision to the SORA Parliament (`specs/sccp.md` §4.14.3).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeSccpRouteGovernance")]
pub struct ProposeSccpRouteGovernance {
    /// Complete network-bound SCCP v1 proposal: base revisions and 1..=16 ordered actions.
    pub proposal: crate::sccp::governance::SccpGovernanceProposalV1,
}
impl crate::seal::Instruction for ProposeSccpRouteGovernance {}
/// Propose one closed `SoraFS` provider-owner transition through governance.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeSorafsProviderGovernance")]
pub struct ProposeSorafsProviderGovernance {
    /// Exact compare-and-set owner transition to execute if enacted.
    pub action: SorafsProviderGovernanceActionV1,
}
impl crate::seal::Instruction for ProposeSorafsProviderGovernance {}
/// Propose one validation-fee policy through SORA Parliament.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeValidationFeePolicy")]
pub struct ProposeValidationFeePolicy {
    /// Complete policy to append if Parliament certifies it.
    pub policy: ValidationFeePolicyV1,
}
impl crate::seal::Instruction for ProposeValidationFeePolicy {}
/// Propose one exact validation-fee payout lifecycle through SORA Parliament.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::ProposeValidationFeePayoutLifecycle")]
pub struct ProposeValidationFeePayoutLifecycle {
    /// Exact treasury payout binding authorized by this lifecycle.
    ///
    /// Consensus derives the non-zero lifecycle seal from this complete
    /// binding before accepting the proposal.
    pub payout_binding: ValidationFeeTreasuryPayoutBindingV1,
}
impl crate::seal::Instruction for ProposeValidationFeePayoutLifecycle {}
/// Cast a ZK ballot (default voting mode)
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::CastZkBallot")]
pub struct CastZkBallot {
    /// Canonical V1 election/referendum selector.
    pub election_id: String,
    /// Base64-encoded proof bytes (envelope routing determines backend)
    pub proof_b64: String,
    /// Closed V1 JSON public-input object encoded as UTF-8 for Norito.
    ///
    /// The object accepts only `root_hint`, `owner`, `amount`, `duration_blocks`, `direction`, and
    /// `nullifier`; `amount` is an exact canonical non-negative [`Quantity`] string.
    pub public_inputs_json: String,
}
impl crate::seal::Instruction for CastZkBallot {}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::governance::BallotProof")]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
/// Canonical V1 ZK ballot proof envelope.
///
/// Opaque container for the ballot proof and minimal public context.
pub struct BallotProof {
    /// Proof backend tag (e.g., "halo2/ipa" or "halo2/pasta/tiny-add").
    pub backend: iroha_schema::Ident,
    /// Opaque proof envelope bytes (ZK1 or H2* container).
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub envelope_bytes: Vec<u8>,
    /// Optional eligibility root hint (32-byte) to bind verification to a known root.
    /// JSON uses a lowercase hex string (optional 0x or blake2b32: prefix).
    #[norito(json = "crate::json_helpers::fixed_bytes_hex::option")]
    pub root_hint: Option<[u8; 32]>,
    /// Optional owner account id (when the circuit commits to it in public inputs).
    pub owner: Option<crate::account::AccountId>,
    /// Optional nullifier hint (32-byte) derived from the proof's commitment.
    /// JSON uses a lowercase hex string (optional 0x or blake2b32: prefix).
    #[norito(json = "crate::json_helpers::fixed_bytes_hex::option")]
    pub nullifier: Option<[u8; 32]>,
    /// Optional exact lock amount hint.
    pub amount: Option<Quantity>,
    /// Optional lock duration hint in blocks.
    pub duration_blocks: Option<u64>,
    /// Optional direction hint (Aye/Nay/Abstain).
    pub direction: Option<String>,
}
/// Cast one immutable public standalone ballot.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::CastPlainBallot")]
pub struct CastPlainBallot {
    /// Canonical V1 selector of the referendum this ballot targets.
    pub referendum_id: String,
    /// Account submitting the ballot.
    pub owner: AccountId,
    /// Quadratic voting credit amount committed by the ballot.
    pub amount: Quantity,
    /// Duration of the lock in blocks.
    pub duration_blocks: u64,
    /// 0=Aye, 1=Nay, 2=Abstain
    pub direction: u8,
}
impl crate::seal::Instruction for CastPlainBallot {}
/// Increase the bond or extend the lock of an existing public standalone ballot.
///
/// The original ballot's choice is retained from finalized state and is not a field of this
/// instruction. A second `CastPlainBallot` never acts as a conviction update.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::UpdatePlainConviction")]
#[norito(deny_unknown_fields)]
pub struct UpdatePlainConviction {
    /// Canonical V1 selector of the referendum whose existing ballot is updated.
    pub referendum_id: String,
    /// Owner of the existing ballot; must equal the transaction authority.
    pub owner: AccountId,
    /// New total bond, in the asset's exact smallest units.
    pub amount: Quantity,
    /// New requested lock duration in blocks.
    pub duration_blocks: u64,
}
impl crate::seal::Instruction for UpdatePlainConviction {}
/// Bond the configured citizenship amount to join the citizen registry.
///
/// Ordinary execution is owner-authorized. The authenticated initial genesis may instead seed an
/// exact citizen from that citizen's prefunded balance; the exception is unavailable once any
/// block has been committed.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::RegisterCitizen")]
pub struct RegisterCitizen {
    /// Account receiving citizenship.
    pub owner: AccountId,
    /// Amount to bond (must meet or exceed the configured floor).
    pub amount: Quantity,
}
impl crate::seal::Instruction for RegisterCitizen {}
/// Unbond and remove a citizen from the registry.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::UnregisterCitizen")]
pub struct UnregisterCitizen {
    /// Account to remove from the registry.
    pub owner: AccountId,
}
impl crate::seal::Instruction for UnregisterCitizen {}
/// Slash a governance bond lock for a referendum.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::SlashGovernanceLock")]
pub struct SlashGovernanceLock {
    /// Canonical V1 selector of the referendum whose lock is being slashed.
    pub referendum_id: String,
    /// Account whose bond lock will be reduced.
    pub owner: AccountId,
    /// Exact amount to slash from the lock.
    pub amount: Quantity,
    /// Human-readable reason recorded with the slash event.
    pub reason: String,
}
impl crate::seal::Instruction for SlashGovernanceLock {}
/// Restitute a previously slashed governance bond lock.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::governance::RestituteGovernanceLock")]
pub struct RestituteGovernanceLock {
    /// Canonical V1 selector of the referendum whose lock is being restored.
    pub referendum_id: String,
    /// Account receiving the restitution.
    pub owner: AccountId,
    /// Exact amount to restore to the lock.
    pub amount: Quantity,
    /// Human-readable reason recorded with the restitution event.
    pub reason: String,
}
impl crate::seal::Instruction for RestituteGovernanceLock {}
fn governance_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_governance_decode_from_slice {
    ($ty:ty { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = governance_decode_flags();
                let mut offset = 0usize;
                $(
                    let $field = super::decode_aos_canonical_field::<$field_ty>(
                        super::read_aos_field(bytes, &mut offset, flags)?,
                        flags,
                    )?;
                )+
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field),+ }, offset))
            }
        }
    };
}
impl_governance_decode_from_slice!(ProposeDeployContract {
    contract_address: crate::smart_contract::ContractAddress,
    code_hash: ContractCodeHash,
    abi_hash: ContractAbiHash,
    abi_version: AbiVersion,
    manifest_provenance: Option<ManifestProvenance>,
});
impl_governance_decode_from_slice!(ProposeContractLifecycleGovernance {
    proposal: ContractLifecycleGovernanceProposalV1,
});
impl_governance_decode_from_slice!(ProposeContractEmergencyHold {
    proposal: ContractEmergencyHoldProposalV1,
});
impl_governance_decode_from_slice!(ProposeGlobalDataTriggerPermissionGovernance {
    proposal: GlobalDataTriggerPermissionGovernanceProposalV1,
});
impl_governance_decode_from_slice!(ProposeRuntimeUpgradeProposal {
    manifest: RuntimeUpgradeManifest,
});
impl_governance_decode_from_slice!(ProposeSccpRouteGovernance {
    proposal: crate::sccp::governance::SccpGovernanceProposalV1,
});
impl_governance_decode_from_slice!(ProposeSorafsProviderGovernance {
    action: SorafsProviderGovernanceActionV1,
});
impl_governance_decode_from_slice!(ProposeValidationFeePolicy {
    policy: ValidationFeePolicyV1,
});
impl_governance_decode_from_slice!(ProposeValidationFeePayoutLifecycle {
    payout_binding: ValidationFeeTreasuryPayoutBindingV1,
});
impl_governance_decode_from_slice!(CastZkBallot {
    election_id: String,
    proof_b64: String,
    public_inputs_json: String,
});
impl_governance_decode_from_slice!(CastPlainBallot {
    referendum_id: String,
    owner: AccountId,
    amount: Quantity,
    duration_blocks: u64,
    direction: u8,
});
impl_governance_decode_from_slice!(UpdatePlainConviction {
    referendum_id: String,
    owner: AccountId,
    amount: Quantity,
    duration_blocks: u64,
});
impl_governance_decode_from_slice!(SlashGovernanceLock {
    referendum_id: String,
    owner: AccountId,
    amount: Quantity,
    reason: String,
});
impl_governance_decode_from_slice!(RestituteGovernanceLock {
    referendum_id: String,
    owner: AccountId,
    amount: Quantity,
    reason: String,
});
impl_governance_decode_from_slice!(RegisterCitizen {
    owner: AccountId,
    amount: Quantity,
});
impl_governance_decode_from_slice!(UnregisterCitizen { owner: AccountId });
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{
        assert_registry_decodes_registered_type as assert_registry_decodes, assert_slice_roundtrip,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_primitives::numeric::Numeric;
    use norito::core::DecodeFromSlice;
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked governance fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn window() -> AtWindow {
        AtWindow {
            lower: 10,
            upper: 20,
        }
    }

    fn assert_exact_json<T: norito::json::JsonSerialize>(value: &T) {
        let legacy = norito::json::to_json(value).expect("serialize legacy JSON");
        assert_eq!(
            norito::json::to_json_bounded(value, legacy.len()).expect("serialize at exact bound"),
            legacy
        );
        assert_eq!(
            norito::json::to_json_bounded(value, legacy.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
    }
    fn contract_address() -> crate::smart_contract::ContractAddress {
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address")
    }
    fn runtime_manifest() -> RuntimeUpgradeManifest {
        RuntimeUpgradeManifest {
            name: "runtime-upgrade".to_string(),
            description: "isi roundtrip".to_string(),
            abi_version: 1,
            abi_hash: crate::abi_v1_fixture::abi_v1_hash(),
            added_syscalls: Vec::new(),
            added_pointer_types: Vec::new(),
            start_height: 100,
            end_height: 200,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        }
    }
    fn sccp_governance_proposal() -> crate::sccp::governance::SccpGovernanceProposalV1 {
        use crate::sccp::{
            governance::{
                SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
                SccpSetParametersActionV1,
            },
            params::SccpParametersV1,
        };
        SccpGovernanceProposalV1 {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(Hash::new(
                    b"SCCP governance instruction fixture network",
                )),
            ),
            base_revisions: vec![(SccpGovernanceSubjectV1::Parameters, 0).into()],
            actions: vec![SccpGovernanceActionV1::SetParameters(
                SccpSetParametersActionV1 {
                    next: SccpParametersV1::taira_default(),
                },
            )],
        }
    }
    fn sorafs_provider_action() -> SorafsProviderGovernanceActionV1 {
        SorafsProviderGovernanceActionV1::Establish(
            crate::isi::sorafs::EstablishSorafsProviderOwnerV1 {
                provider_id: crate::sorafs::capacity::ProviderId::new([0x51; 32]),
                owner: account(1),
            },
        )
    }
    #[derive(Encode)]
    struct ForgedCastPlainBallot {
        referendum_id: String,
        owner: AccountId,
        amount: Numeric,
        duration_blocks: u64,
        direction: u8,
    }
    #[derive(Encode)]
    struct LegacyProposeDeployContract {
        contract_address: crate::smart_contract::ContractAddress,
        code_hash_hex: String,
        abi_hash_hex: String,
        abi_version: String,
        window: Option<AtWindow>,
        mode: Option<VotingMode>,
        manifest_provenance: Option<ManifestProvenance>,
    }
    #[derive(Encode)]
    struct LegacyProposeRuntimeUpgradeProposal {
        manifest: RuntimeUpgradeManifest,
        window: Option<AtWindow>,
        mode: Option<VotingMode>,
    }
    #[derive(Encode)]
    struct LegacyProposeSorafsProviderGovernance {
        action: SorafsProviderGovernanceActionV1,
        window: Option<AtWindow>,
        mode: Option<VotingMode>,
    }
    fn assert_legacy_instruction_payload_rejected<T: Encode>(type_name: &str, value: &T) {
        let registry = crate::instruction_registry::default();
        let wire_id = registry
            .wire_id(type_name)
            .expect("current governance instruction has a canonical wire identifier");
        let bare = value.encode();
        let framed = crate::isi::frame_instruction_payload(wire_id, &bare)
            .expect("frame forged legacy governance instruction");
        assert!(
            crate::isi::decode_instruction_from_pair(wire_id, &framed).is_err(),
            "retired governance layout decoded under {wire_id}"
        );
    }
    #[test]
    fn governance_amount_rejects_negative_numeric_payload() {
        let encoded = ForgedCastPlainBallot {
            referendum_id: "referendum-1".to_owned(),
            owner: account(1),
            amount: Numeric::new(-1_i32, 0),
            duration_blocks: 100,
            direction: 0,
        }
        .encode();
        assert!(CastPlainBallot::decode_from_slice(&encoded).is_err());
    }
    #[test]
    fn conviction_update_rejects_cast_payload_with_direction() {
        assert_legacy_instruction_payload_rejected(
            std::any::type_name::<UpdatePlainConviction>(),
            &CastPlainBallot {
                referendum_id: "referendum-1".to_owned(),
                owner: account(1),
                amount: 2_000_u64.into(),
                duration_blocks: 200,
                direction: 1,
            },
        );
    }
    #[test]
    fn direct_update_plain_conviction_golden_is_canonical() {
        use base64::Engine as _;
        use std::io::Write as _;

        let value = UpdatePlainConviction {
            referendum_id: "referendum-1".to_owned(),
            owner: account(1),
            amount: 2_000_u64.into(),
            duration_blocks: 200,
        };
        let (bare_payload, header_flags) = norito::codec::encode_with_header_flags(&value);
        let concrete_frame = norito::core::frame_bare_with_header_flags::<UpdatePlainConviction>(
            &bare_payload,
            header_flags,
        )
        .expect("frame direct conviction update");
        let concrete_decoded: UpdatePlainConviction =
            norito::decode_from_bytes(&concrete_frame).expect("decode direct conviction frame");
        assert_eq!(concrete_decoded, value);
        assert_eq!(
            norito::core::to_bytes(&concrete_decoded).expect("re-encode direct conviction frame"),
            concrete_frame
        );

        let boxed: InstructionBox = value.clone().into();
        let (wire_id, registered_frame) =
            crate::isi::framed_instruction_payload(&boxed).expect("registered direct instruction");
        assert_eq!(
            wire_id,
            "iroha.instruction.v1::governance::UpdatePlainConviction"
        );
        assert_eq!(registered_frame, concrete_frame);
        let registered_decoded = crate::isi::decode_instruction_from_pair(wire_id, &concrete_frame)
            .expect("decode registered direct instruction");
        assert_eq!(
            registered_decoded
                .as_any()
                .downcast_ref::<UpdatePlainConviction>()
                .expect("direct instruction type"),
            &value
        );

        let (instruction_box_pair, pair_flags) = norito::codec::encode_with_header_flags(&boxed);
        assert_eq!(pair_flags, header_flags);
        let pair_decoded = {
            let _guard = norito::core::DecodeFlagsGuard::enter(pair_flags);
            let (decoded, used) = InstructionBox::decode_from_slice(&instruction_box_pair)
                .expect("decode bare InstructionBox pair");
            assert_eq!(used, instruction_box_pair.len());
            decoded
        };
        assert_eq!(
            pair_decoded
                .as_any()
                .downcast_ref::<UpdatePlainConviction>()
                .expect("bare pair direct instruction"),
            &value
        );
        let (reencoded_pair, reencoded_pair_flags) =
            norito::codec::encode_with_header_flags(&pair_decoded);
        assert_eq!(reencoded_pair_flags, pair_flags);
        assert_eq!(reencoded_pair, instruction_box_pair);

        let standalone_instruction_box_frame = norito::core::frame_bare_with_header_flags::<
            InstructionBox,
        >(&instruction_box_pair, pair_flags)
        .expect("frame standalone InstructionBox");
        let standalone_decoded: InstructionBox =
            norito::decode_from_bytes(&standalone_instruction_box_frame)
                .expect("decode standalone InstructionBox");
        assert_eq!(
            standalone_decoded
                .as_any()
                .downcast_ref::<UpdatePlainConviction>()
                .expect("standalone direct instruction"),
            &value
        );
        assert_eq!(
            norito::core::to_bytes(&standalone_decoded).expect("re-encode standalone box"),
            standalone_instruction_box_frame
        );

        assert!(
            crate::isi::decode_instruction_from_pair(
                std::any::type_name::<UpdatePlainConviction>(),
                &concrete_frame
            )
            .is_err(),
            "Rust type name is not a decode alias"
        );
        let mut trailing_frame = concrete_frame.clone();
        trailing_frame.push(0);
        assert!(
            crate::isi::decode_instruction_from_pair(wire_id, &trailing_frame).is_err(),
            "trailing concrete frame byte must be rejected"
        );
        let mut trailing_pair = instruction_box_pair.clone();
        trailing_pair.push(0);
        let guard = norito::core::DecodeFlagsGuard::enter(pair_flags);
        assert!(
            InstructionBox::decode_from_slice(&trailing_pair).is_err(),
            "trailing InstructionBox pair byte must be rejected"
        );
        drop(guard);
        assert_legacy_instruction_payload_rejected(
            std::any::type_name::<UpdatePlainConviction>(),
            &CastPlainBallot {
                referendum_id: value.referendum_id.clone(),
                owner: value.owner.clone(),
                amount: value.amount.clone(),
                duration_blocks: value.duration_blocks,
                direction: 1,
            },
        );

        let schema_name = <UpdatePlainConviction as norito::NoritoSchema>::frame_name();
        assert_eq!(
            schema_name,
            "iroha_data_model::isi::governance::UpdatePlainConviction"
        );
        let expected = norito::json!({
            "version": 1,
            "inputs": {
                "referendum_id": (value.referendum_id.clone()),
                "owner": (value.owner.to_string()),
                "amount": (value.amount.to_string()),
                "duration_blocks": (value.duration_blocks),
            },
            "wire_id": wire_id,
            "concrete_schema_name": schema_name,
            "concrete_schema_hash": (hex::encode(
                norito::schema::identity::frame_hash::<UpdatePlainConviction>()
            )),
            "header_flags": header_flags,
            "framed_instruction_base64": (base64::engine::general_purpose::STANDARD
                .encode(&concrete_frame)),
            "framed_instruction_len": (u64::try_from(concrete_frame.len())
                .expect("direct conviction frame length fits u64")),
            "bare_payload_hex": (hex::encode(&bare_payload)),
            "concrete_frame_hex": (hex::encode(&concrete_frame)),
            "instruction_box_pair_hex": (hex::encode(&instruction_box_pair)),
            "standalone_instruction_box_frame_hex": (hex::encode(
                &standalone_instruction_box_frame
            )),
        });
        let canonical = format!(
            "{}\n",
            norito::json::to_string_pretty(&expected).expect("render direct conviction golden")
        );
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("canonical repository root");
        if std::env::var("IROHA_WRITE_DIRECT_CONVICTION_GOLDEN_V1")
            .ok()
            .as_deref()
            == Some("1")
        {
            let target = repo_root.join("target");
            assert!(
                target
                    .symlink_metadata()
                    .expect("repository target directory")
                    .file_type()
                    .is_dir(),
                "golden export target must be a real repository directory"
            );
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(target.join("update_plain_conviction_instruction_v1.json"))
                .expect("fresh target-only direct conviction golden output");
            output
                .write_all(canonical.as_bytes())
                .expect("write direct conviction golden output");
            output
                .sync_all()
                .expect("flush direct conviction golden output");
            return;
        }
        let fixture_path = repo_root
            .join("fixtures/governance/plain_v1/update_plain_conviction_instruction_v1.json");
        let fixture = std::fs::read_to_string(fixture_path)
            .expect("read checked-in direct conviction golden");
        let decoded: norito::json::Value =
            norito::json::from_str(&fixture).expect("decode direct conviction golden JSON");
        assert_eq!(decoded, expected);
        assert_eq!(
            fixture, canonical,
            "direct conviction golden bytes are canonical"
        );
    }

    #[test]
    fn encode_roundtrip_basic() {
        let p = ProposeDeployContract {
            contract_address: contract_address(),
            code_hash: ContractCodeHash::new([0xaa; 32]),
            abi_hash: ContractAbiHash::new([0xbb; 32]),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        };
        let enc = norito::codec::Encode::encode(&p);
        let mut cur = enc.as_slice();
        let dec = ProposeDeployContract::decode(&mut cur).unwrap();
        assert_eq!(p, dec);
    }
    #[test]
    fn retired_proposal_control_and_string_hash_layouts_fail_closed() {
        assert_legacy_instruction_payload_rejected(
            std::any::type_name::<ProposeDeployContract>(),
            &LegacyProposeDeployContract {
                contract_address: contract_address(),
                code_hash_hex: "aa".repeat(32),
                abi_hash_hex: "bb".repeat(32),
                abi_version: "1".to_owned(),
                window: Some(window()),
                mode: Some(VotingMode::Zk),
                manifest_provenance: None,
            },
        );
        assert_legacy_instruction_payload_rejected(
            std::any::type_name::<ProposeRuntimeUpgradeProposal>(),
            &LegacyProposeRuntimeUpgradeProposal {
                manifest: runtime_manifest(),
                window: Some(window()),
                mode: Some(VotingMode::Plain),
            },
        );
        assert_legacy_instruction_payload_rejected(
            std::any::type_name::<ProposeSorafsProviderGovernance>(),
            &LegacyProposeSorafsProviderGovernance {
                action: sorafs_provider_action(),
                window: Some(window()),
                mode: Some(VotingMode::Zk),
            },
        );
    }

    #[test]
    fn voting_mode_json_is_canonical_and_rejects_aliases() {
        assert_exact_json(&VotingMode::Zk);
        assert_exact_json(&VotingMode::Plain);
        assert_eq!(
            norito::json::to_json(&VotingMode::Zk).expect("serialize Zk voting mode"),
            "\"Zk\""
        );
        assert_eq!(
            norito::json::to_json(&VotingMode::Plain).expect("serialize Plain voting mode"),
            "\"Plain\""
        );
        assert_eq!(
            norito::json::from_str::<VotingMode>("\"Zk\"").expect("decode canonical Zk"),
            VotingMode::Zk
        );
        assert_eq!(
            norito::json::from_str::<VotingMode>("\"Plain\"").expect("decode canonical Plain"),
            VotingMode::Plain
        );
        for alias in ["zk", "plain", "PLAIN", " Zk", "Zk ", "Quadratic"] {
            let json = format!("\"{alias}\"");
            assert!(
                norito::json::from_str::<VotingMode>(&json).is_err(),
                "noncanonical voting mode alias must reject: {alias:?}"
            );
        }
    }
    #[test]
    fn runtime_upgrade_proposal_roundtrip() {
        let ins = ProposeRuntimeUpgradeProposal {
            manifest: runtime_manifest(),
        };
        let enc = norito::codec::Encode::encode(&ins);
        let mut cur = enc.as_slice();
        let dec = ProposeRuntimeUpgradeProposal::decode(&mut cur).unwrap();
        assert_eq!(ins, dec);
    }
    #[test]
    fn sccp_route_governance_proposal_roundtrip() {
        let ins = ProposeSccpRouteGovernance {
            proposal: sccp_governance_proposal(),
        };
        let enc = norito::codec::Encode::encode(&ins);
        let mut cur = enc.as_slice();
        let dec = ProposeSccpRouteGovernance::decode(&mut cur).unwrap();
        assert_eq!(ins, dec);
    }
    #[test]
    fn sorafs_provider_governance_proposal_roundtrip() {
        let instruction = ProposeSorafsProviderGovernance {
            action: sorafs_provider_action(),
        };
        let encoded = instruction.encode();
        let decoded = ProposeSorafsProviderGovernance::decode(&mut encoded.as_slice())
            .expect("decode SoraFS provider-governance proposal");
        assert_eq!(instruction, decoded);
    }
    #[test]
    fn at_window_roundtrip() {
        let win = AtWindow { lower: 1, upper: 2 };
        let enc = norito::codec::Encode::encode(&win);
        let mut cur = enc.as_slice();
        let dec = AtWindow::decode(&mut cur).unwrap();
        assert_eq!(win, dec);
    }
    #[test]
    fn at_window_decodes_from_slice_via_norito() {
        let window = AtWindow {
            lower: 10,
            upper: 42,
        };
        let bytes = norito::codec::Encode::encode(&window);
        let (decoded, used) = <AtWindow as DecodeFromSlice>::decode_from_slice(&bytes)
            .expect("decode_from_slice should succeed");
        assert_eq!(decoded, window);
        assert_eq!(used, bytes.len());
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn governance_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(ProposeDeployContract {
            contract_address: contract_address(),
            code_hash: ContractCodeHash::new([0xaa; 32]),
            abi_hash: ContractAbiHash::new([0xbb; 32]),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        });
        assert_slice_roundtrip(ProposeRuntimeUpgradeProposal {
            manifest: runtime_manifest(),
        });
        assert_slice_roundtrip(ProposeSccpRouteGovernance {
            proposal: sccp_governance_proposal(),
        });
        assert_slice_roundtrip(ProposeSorafsProviderGovernance {
            action: sorafs_provider_action(),
        });
        assert_slice_roundtrip(ProposeGlobalDataTriggerPermissionGovernance {
            proposal: GlobalDataTriggerPermissionGovernanceProposalV1 {
                authority: account(2),
                action: GlobalDataTriggerPermissionGovernanceActionV1::Grant,
            },
        });
        assert_slice_roundtrip(CastZkBallot {
            election_id: "referendum-1".to_owned(),
            proof_b64: "AQID".to_owned(),
            public_inputs_json: "{\"vote\":\"aye\"}".to_owned(),
        });
        assert_slice_roundtrip(CastPlainBallot {
            referendum_id: "referendum-1".to_owned(),
            owner: account(1),
            amount: 1_000_u64.into(),
            duration_blocks: 100,
            direction: 0,
        });
        assert_slice_roundtrip(UpdatePlainConviction {
            referendum_id: "referendum-1".to_owned(),
            owner: account(1),
            amount: 2_000_u64.into(),
            duration_blocks: 200,
        });
        assert_slice_roundtrip(SlashGovernanceLock {
            referendum_id: "referendum-1".to_owned(),
            owner: account(1),
            amount: 100_u64.into(),
            reason: "misconduct".to_owned(),
        });
        assert_slice_roundtrip(RestituteGovernanceLock {
            referendum_id: "referendum-1".to_owned(),
            owner: account(1),
            amount: 50_u64.into(),
            reason: "appeal accepted".to_owned(),
        });
        assert_slice_roundtrip(RegisterCitizen {
            owner: account(1),
            amount: 2_000_u64.into(),
        });
        assert_slice_roundtrip(UnregisterCitizen { owner: account(1) });
    }
    #[test]
    fn governance_default_registry_decodes_canonical_wire_ids() {
        let registry = crate::isi::registry::default();
        assert_registry_decodes(
            &registry,
            ProposeDeployContract {
                contract_address: contract_address(),
                code_hash: ContractCodeHash::new([0xaa; 32]),
                abi_hash: ContractAbiHash::new([0xbb; 32]),
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            },
        );
        assert_registry_decodes(
            &registry,
            ProposeRuntimeUpgradeProposal {
                manifest: runtime_manifest(),
            },
        );
        assert_registry_decodes(
            &registry,
            ProposeSorafsProviderGovernance {
                action: sorafs_provider_action(),
            },
        );
        assert_registry_decodes(
            &registry,
            ProposeGlobalDataTriggerPermissionGovernance {
                proposal: GlobalDataTriggerPermissionGovernanceProposalV1 {
                    authority: account(2),
                    action: GlobalDataTriggerPermissionGovernanceActionV1::Revoke,
                },
            },
        );
        assert_registry_decodes(
            &registry,
            CastPlainBallot {
                referendum_id: "referendum-1".to_owned(),
                owner: account(1),
                amount: 1_000_u64.into(),
                duration_blocks: 100,
                direction: 0,
            },
        );
        assert_registry_decodes(
            &registry,
            UpdatePlainConviction {
                referendum_id: "referendum-1".to_owned(),
                owner: account(1),
                amount: 2_000_u64.into(),
                duration_blocks: 200,
            },
        );
        assert_registry_decodes(
            &registry,
            RegisterCitizen {
                owner: account(1),
                amount: 2_000_u64.into(),
            },
        );
    }
}

#[cfg(test)]
mod frame_owner_identity_tests {
    //! Frame roots observed in the original codec before the identity cutover.

    #[test]
    fn captured_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<super::CastPlainBallot>(
            "iroha_data_model::isi::governance::CastPlainBallot",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<super::CastZkBallot>(
            "iroha_data_model::isi::governance::CastZkBallot",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::ProposeContractEmergencyHold,
        >("iroha_data_model::isi::governance::ProposeContractEmergencyHold");
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::ProposeContractLifecycleGovernance,
        >("iroha_data_model::isi::governance::ProposeContractLifecycleGovernance");
        crate::frame_owner_identity_tests::assert_bidirectional::<super::ProposeDeployContract>(
            "iroha_data_model::isi::governance::ProposeDeployContract",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::ProposeGlobalDataTriggerPermissionGovernance,
        >("iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance");
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::ProposeRuntimeUpgradeProposal,
        >("iroha_data_model::isi::governance::ProposeRuntimeUpgradeProposal");
        crate::frame_owner_identity_tests::assert_bidirectional::<super::ProposeSccpRouteGovernance>(
            "iroha_data_model::isi::governance::ProposeSccpRouteGovernance",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::ProposeSorafsProviderGovernance,
        >("iroha_data_model::isi::governance::ProposeSorafsProviderGovernance");
        crate::frame_owner_identity_tests::assert_bidirectional::<
            super::ProposeValidationFeePayoutLifecycle,
        >("iroha_data_model::isi::governance::ProposeValidationFeePayoutLifecycle");
        crate::frame_owner_identity_tests::assert_bidirectional::<super::ProposeValidationFeePolicy>(
            "iroha_data_model::isi::governance::ProposeValidationFeePolicy",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<super::RegisterCitizen>(
            "iroha_data_model::isi::governance::RegisterCitizen",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<super::RestituteGovernanceLock>(
            "iroha_data_model::isi::governance::RestituteGovernanceLock",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<super::SlashGovernanceLock>(
            "iroha_data_model::isi::governance::SlashGovernanceLock",
        );
        crate::frame_owner_identity_tests::assert_bidirectional::<super::UnregisterCitizen>(
            "iroha_data_model::isi::governance::UnregisterCitizen",
        );
    }
}
