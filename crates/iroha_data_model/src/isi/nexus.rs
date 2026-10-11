use super::*;
use crate::{
    account::AccountId,
    asset::AssetDefinitionId,
    nexus::{FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramRevision, ProofBlob},
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Persist a proof-backed cross-lane sponsor-vault spend allocation.
    ///
    /// Execution requires the sponsor or its delegated program manager, rejects source heights
    /// beyond the executing block, and permits at most one unexpired lease for each
    /// program/revision/asset/source-dataspace route.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation")]
    pub struct RegisterVerifiedFeeSponsorVaultAllocation {
        /// Exact sponsor program authorized to spend the allocation.
        pub program_id: FeeSponsorProgramId,
        /// Immutable program revision bound by the source proof.
        pub program_revision: u64,
        /// Canonical fee asset allocated by the source vault.
        pub asset_definition_id: AssetDefinitionId,
        /// Maximum amount authorized by this spend lease.
        pub verified_allocation: Quantity,
        /// Dataspace containing the authoritative source vault.
        pub source_dataspace_id: DataSpaceId,
        /// Monotonic source consensus height bound by the proof.
        pub source_height: u64,
        /// Source state root committing the vault and budget state.
        pub source_state_root: iroha_crypto::Hash,
        /// Consensus height after which the spend lease expires.
        pub expires_at_height: u64,
        /// Globally unique proof-bound spend lease identifier.
        pub lease_id: iroha_crypto::Hash,
        /// Manifest root committed by the balance proof.
        pub manifest_root: [u8; 32],
        /// FASTPQ/AXT proof blob used to verify the allocation claim.
        pub proof_blob: ProofBlob,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Create a staged sponsor-owned fee sponsor program.
    ///
    /// Ordinary execution requires the sponsor or its delegated manager. The authenticated
    /// initial genesis may compose the sponsor-owned record before any block is committed.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::CreateFeeSponsorProgram")]
    pub struct CreateFeeSponsorProgram {
        /// Initial fail-closed lifecycle record to persist.
        pub program: FeeSponsorProgram,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Stage one immutable fee sponsor program revision.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::StageFeeSponsorProgramRevision")]
    pub struct StageFeeSponsorProgramRevision {
        /// Immutable revision to validate and stage.
        pub revision: FeeSponsorProgramRevision,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Schedule a staged sponsor-program revision for activation.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::ActivateFeeSponsorProgramRevision")]
    pub struct ActivateFeeSponsorProgramRevision {
        /// Program whose staged revision will become active.
        pub program_id: FeeSponsorProgramId,
        /// Exact staged revision number.
        pub revision: u64,
        /// Earliest consensus height at which activation may take effect.
        ///
        /// Inclusion after this lower bound activates at the executing height, subject to every
        /// spend lease from an older revision having expired. A future lower bound schedules
        /// activation; it does not cause the chain to produce a block.
        pub activate_at_height: u64,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Pause an active fee sponsor program.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::PauseFeeSponsorProgram")]
    pub struct PauseFeeSponsorProgram {
        /// Program to pause.
        pub program_id: FeeSponsorProgramId,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Begin the fail-closed drain phase for a fee sponsor program.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::BeginCloseFeeSponsorProgram")]
    pub struct BeginCloseFeeSponsorProgram {
        /// Program that must stop accepting new sponsorship.
        pub program_id: FeeSponsorProgramId,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Permanently close a fully drained fee sponsor program.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::CloseFeeSponsorProgram")]
    pub struct CloseFeeSponsorProgram {
        /// Program to convert into a permanent tombstone.
        pub program_id: FeeSponsorProgramId,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Enroll an exact canonical account identity in a fee sponsor program.
    ///
    /// The beneficiary may be registered by its first sponsored transaction. Enrollment
    /// does not register the account or grant permission to execute its instructions.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::EnrollFeeSponsorBeneficiary")]
    pub struct EnrollFeeSponsorBeneficiary {
        /// Program granting eligibility.
        pub program_id: FeeSponsorProgramId,
        /// Canonical beneficiary identity to enroll, whether or not its account exists yet.
        pub beneficiary: AccountId,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Remove an exact canonical account from a fee sponsor program.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::UnenrollFeeSponsorBeneficiary")]
    pub struct UnenrollFeeSponsorBeneficiary {
        /// Program revoking eligibility.
        pub program_id: FeeSponsorProgramId,
        /// Canonical beneficiary account to remove.
        pub beneficiary: AccountId,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[getset(get = "pub")]
    /// Transfer assets into a program-isolated fee vault allocation.
    ///
    /// During authenticated initial genesis, funding may debit only the exact sponsor's prefunded
    /// balance. Later execution retains the ordinary sponsor/manager and asset-debit checks.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::FundFeeSponsorProgram")]
    pub struct FundFeeSponsorProgram {
        /// Program receiving the allocation.
        pub program_id: FeeSponsorProgramId,
        /// Canonical asset definition to allocate.
        pub asset_definition_id: AssetDefinitionId,
        /// Positive amount transferred into protocol custody.
        pub amount: Quantity,
    }
}
iroha_data_model_derive::model_single! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[derive(getset::Getters)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[getset(get = "pub")]
    /// Withdraw assets from a paused or closing program vault allocation.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::nexus::WithdrawFeeSponsorProgram")]
    pub struct WithdrawFeeSponsorProgram {
        /// Program whose allocation is reduced.
        pub program_id: FeeSponsorProgramId,
        /// Canonical asset definition to withdraw.
        pub asset_definition_id: AssetDefinitionId,
        /// Positive amount released from protocol custody.
        pub amount: Quantity,
    }
}
impl PartialOrd for RegisterVerifiedFeeSponsorVaultAllocation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for RegisterVerifiedFeeSponsorVaultAllocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.encode().cmp(&other.encode())
    }
}
macro_rules! impl_instruction_ord {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl PartialOrd for $ty {
                fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                    Some(self.cmp(other))
                }
            }
            impl Ord for $ty {
                fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                    self.encode().cmp(&other.encode())
                }
            }
        )+
    };
}
impl_instruction_ord!(
    CreateFeeSponsorProgram,
    StageFeeSponsorProgramRevision,
    ActivateFeeSponsorProgramRevision,
    PauseFeeSponsorProgram,
    BeginCloseFeeSponsorProgram,
    CloseFeeSponsorProgram,
    EnrollFeeSponsorBeneficiary,
    UnenrollFeeSponsorBeneficiary,
    FundFeeSponsorProgram,
    WithdrawFeeSponsorProgram,
);
impl crate::seal::Instruction for RegisterVerifiedFeeSponsorVaultAllocation {}
impl crate::seal::Instruction for CreateFeeSponsorProgram {}
impl crate::seal::Instruction for StageFeeSponsorProgramRevision {}
impl crate::seal::Instruction for ActivateFeeSponsorProgramRevision {}
impl crate::seal::Instruction for PauseFeeSponsorProgram {}
impl crate::seal::Instruction for BeginCloseFeeSponsorProgram {}
impl crate::seal::Instruction for CloseFeeSponsorProgram {}
impl crate::seal::Instruction for EnrollFeeSponsorBeneficiary {}
impl crate::seal::Instruction for UnenrollFeeSponsorBeneficiary {}
impl crate::seal::Instruction for FundFeeSponsorProgram {}
impl crate::seal::Instruction for WithdrawFeeSponsorProgram {}

impl_aos_decode_from_slice!(RegisterVerifiedFeeSponsorVaultAllocation {
    program_id: FeeSponsorProgramId,
    program_revision: u64,
    asset_definition_id: AssetDefinitionId,
    verified_allocation: Quantity,
    source_dataspace_id: DataSpaceId,
    source_height: u64,
    source_state_root: iroha_crypto::Hash,
    expires_at_height: u64,
    lease_id: iroha_crypto::Hash,
    manifest_root: [u8; 32],
    proof_blob: ProofBlob,
});
impl_aos_decode_from_slice!(CreateFeeSponsorProgram {
    program: FeeSponsorProgram
});
impl_aos_decode_from_slice!(StageFeeSponsorProgramRevision {
    revision: FeeSponsorProgramRevision
});
impl_aos_decode_from_slice!(ActivateFeeSponsorProgramRevision {
    program_id: FeeSponsorProgramId,
    revision: u64,
    activate_at_height: u64,
});
impl_aos_decode_from_slice!(PauseFeeSponsorProgram {
    program_id: FeeSponsorProgramId
});
impl_aos_decode_from_slice!(BeginCloseFeeSponsorProgram {
    program_id: FeeSponsorProgramId
});
impl_aos_decode_from_slice!(CloseFeeSponsorProgram {
    program_id: FeeSponsorProgramId
});
impl_aos_decode_from_slice!(EnrollFeeSponsorBeneficiary {
    program_id: FeeSponsorProgramId,
    beneficiary: AccountId,
});
impl_aos_decode_from_slice!(UnenrollFeeSponsorBeneficiary {
    program_id: FeeSponsorProgramId,
    beneficiary: AccountId,
});
impl_aos_decode_from_slice!(FundFeeSponsorProgram {
    program_id: FeeSponsorProgramId,
    asset_definition_id: AssetDefinitionId,
    amount: Quantity,
});
impl_aos_decode_from_slice!(WithdrawFeeSponsorProgram {
    program_id: FeeSponsorProgramId,
    asset_definition_id: AssetDefinitionId,
    amount: Quantity,
});
#[cfg(test)]
mod tests {

    mod generated_identity;

    use super::*;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use crate::{
        block::BlockHeader,
        nexus::{
            FeeSponsorAssetBudget, FeeSponsorEligibility, FeeSponsorProgram, FeeSponsorProgramId,
            FeeSponsorProgramRevision, FeeSponsorRule, FeeSponsorRuleEffect,
        },
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_primitives::numeric::{Numeric, Quantity};
    use norito::codec::{Decode, Encode};
    use std::num::NonZeroU64;
    #[derive(Encode)]
    struct ForgedRegisterVerifiedFeeSponsorVaultAllocation {
        program_id: FeeSponsorProgramId,
        program_revision: u64,
        asset_definition_id: AssetDefinitionId,
        verified_allocation: Numeric,
        source_dataspace_id: DataSpaceId,
        source_height: u64,
        source_state_root: iroha_crypto::Hash,
        expires_at_height: u64,
        lease_id: iroha_crypto::Hash,
        manifest_root: [u8; 32],
        proof_blob: ProofBlob,
    }
    fn sample_header(height: u64) -> BlockHeader {
        let mut header = BlockHeader::new(
            NonZeroU64::new(height).expect("nonzero height"),
            None,
            None,
            1_700_000_000_000,
            0,
        );
        // This fixed codec specimen is independent of changing network policy defaults.
        header.set_confidential_features(Some(
            crate::confidential::ConfidentialFeatureDigest::new(
                None,
                None,
                None,
                Some(1),
                Some([
                    0x93, 0x76, 0x91, 0x34, 0xd0, 0xa3, 0x4d, 0x4c, 0x93, 0x7a, 0x95, 0xbb, 0xc3,
                    0x40, 0x05, 0x77, 0x1b, 0x9d, 0x82, 0xef, 0x0f, 0xcf, 0xdf, 0xf0, 0x69, 0x57,
                    0xf2, 0x07, 0xe2, 0x16, 0x89, 0x6f,
                ]),
            ),
        ));
        header
    }
    fn sample_proof_blob(seed: u8) -> ProofBlob {
        ProofBlob {
            payload: vec![seed, seed.wrapping_add(1)],
            expiry_slot: None,
        }
    }
    fn sponsor_account_id() -> AccountId {
        let sponsor_keypair = KeyPair::try_from_seed(vec![0xAB; 32], Algorithm::Ed25519)
            .expect("derive checked Nexus sponsor fixture keypair");
        AccountId::new(sponsor_keypair.public_key().clone())
    }
    fn sample_fee_budget_instruction() -> RegisterVerifiedFeeSponsorVaultAllocation {
        RegisterVerifiedFeeSponsorVaultAllocation {
            program_id: sample_fee_sponsor_program().id,
            program_revision: 1,
            asset_definition_id: sample_fee_asset_id(),
            verified_allocation: Quantity::from(10_u32),
            source_dataspace_id: DataSpaceId::new(2),
            source_height: 8,
            source_state_root: iroha_crypto::Hash::new(b"source-state-root"),
            expires_at_height: 108,
            lease_id: iroha_crypto::Hash::new(b"spend-lease"),
            manifest_root: [0x11; 32],
            proof_blob: sample_proof_blob(0x02),
        }
    }
    fn sample_fee_asset_id() -> AssetDefinitionId {
        "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
            .parse()
            .expect("canonical asset definition id")
    }
    fn sample_fee_sponsor_program() -> FeeSponsorProgram {
        let program_id = FeeSponsorProgramId::new(
            sponsor_account_id(),
            "default".parse().expect("program name"),
        );
        FeeSponsorProgram::new(program_id, sponsor_account_id())
    }
    fn sample_fee_sponsor_revision(program_id: FeeSponsorProgramId) -> FeeSponsorProgramRevision {
        FeeSponsorProgramRevision {
            program_id,
            revision: 1,
            eligibility: FeeSponsorEligibility::EnrolledOnly,
            rules: vec![FeeSponsorRule::new(
                "allow_transfer".parse().expect("rule name"),
                FeeSponsorRuleEffect::Allow,
            )],
            asset_budgets: vec![FeeSponsorAssetBudget {
                asset_definition_id: sample_fee_asset_id(),
                per_transaction: Quantity::from(1_u32),
                per_block: Quantity::from(10_u32),
                per_program_epoch: Quantity::from(100_u32),
                per_beneficiary_epoch: Quantity::from(5_u32),
                reserve_floor: "0.1".parse().expect("reserve floor"),
                epoch_length_blocks: NonZeroU64::new(100).expect("nonzero epoch"),
            }],
        }
    }
    #[test]
    fn register_verified_fee_sponsor_allocation_order_uses_canonical_encoding() {
        let left = sample_fee_budget_instruction();
        let right = RegisterVerifiedFeeSponsorVaultAllocation {
            proof_blob: sample_proof_blob(0x03),
            ..left.clone()
        };
        assert_eq!(
            left.partial_cmp(&right),
            Some(left.encode().cmp(&right.encode()))
        );
        assert_eq!(left.cmp(&right), left.encode().cmp(&right.encode()));
    }
    #[test]
    fn nexus_verified_payload_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(sample_fee_budget_instruction());
        let program = sample_fee_sponsor_program();
        let id = program.id.clone();
        let beneficiary = sponsor_account_id();
        assert_slice_roundtrip(CreateFeeSponsorProgram {
            program: program.clone(),
        });
        assert_slice_roundtrip(StageFeeSponsorProgramRevision {
            revision: sample_fee_sponsor_revision(id.clone()),
        });
        assert_slice_roundtrip(ActivateFeeSponsorProgramRevision {
            program_id: id.clone(),
            revision: 1,
            activate_at_height: 10,
        });
        assert_slice_roundtrip(PauseFeeSponsorProgram {
            program_id: id.clone(),
        });
        assert_slice_roundtrip(BeginCloseFeeSponsorProgram {
            program_id: id.clone(),
        });
        assert_slice_roundtrip(CloseFeeSponsorProgram {
            program_id: id.clone(),
        });
        assert_slice_roundtrip(EnrollFeeSponsorBeneficiary {
            program_id: id.clone(),
            beneficiary: beneficiary.clone(),
        });
        assert_slice_roundtrip(UnenrollFeeSponsorBeneficiary {
            program_id: id.clone(),
            beneficiary: beneficiary.clone(),
        });
        assert_slice_roundtrip(FundFeeSponsorProgram {
            program_id: id.clone(),
            asset_definition_id: sample_fee_asset_id(),
            amount: Quantity::from(10_u32),
        });
        assert_slice_roundtrip(WithdrawFeeSponsorProgram {
            program_id: id,
            asset_definition_id: sample_fee_asset_id(),
            amount: Quantity::from(1_u32),
        });
    }

    #[test]
    fn withdrawal_json_rejects_caller_selected_destination() {
        let program = sample_fee_sponsor_program();
        let mut value = norito::json::to_value(&WithdrawFeeSponsorProgram {
            program_id: program.id,
            asset_definition_id: sample_fee_asset_id(),
            amount: Quantity::from(1_u32),
        })
        .expect("serialize withdrawal");
        value.as_object_mut().expect("withdrawal object").insert(
            "destination".to_owned(),
            norito::json::to_value(&sponsor_account_id()).expect("serialize forged account"),
        );
        assert!(
            norito::json::from_value::<WithdrawFeeSponsorProgram>(value).is_err(),
            "caller-selected withdrawal destinations are not part of the first-release wire"
        );
    }
    #[test]
    fn negative_numeric_payload_cannot_decode_as_verified_nexus_balance() {
        let valid = sample_fee_budget_instruction();
        let forged = ForgedRegisterVerifiedFeeSponsorVaultAllocation {
            program_id: valid.program_id,
            program_revision: valid.program_revision,
            asset_definition_id: valid.asset_definition_id,
            verified_allocation: Numeric::new(-1_i32, 0),
            source_dataspace_id: valid.source_dataspace_id,
            source_height: valid.source_height,
            source_state_root: valid.source_state_root,
            expires_at_height: valid.expires_at_height,
            lease_id: valid.lease_id,
            manifest_root: [0x11; 32],
            proof_blob: sample_proof_blob(0x02),
        };
        let encoded = forged.encode();
        assert!(
            RegisterVerifiedFeeSponsorVaultAllocation::decode(&mut encoded.as_slice()).is_err(),
            "a signed negative payload must not cross the verified-allocation boundary"
        );
    }
    #[test]
    fn nexus_verified_payload_registry_decodes_stable_ids() {
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<RegisterVerifiedFeeSponsorVaultAllocation>(
                "nexus::RegisterVerifiedFeeSponsorVaultAllocation",
            )
            .register_with_id_slice::<CreateFeeSponsorProgram>("nexus::CreateFeeSponsorProgram")
            .register_with_id_slice::<StageFeeSponsorProgramRevision>(
                "nexus::StageFeeSponsorProgramRevision",
            )
            .register_with_id_slice::<ActivateFeeSponsorProgramRevision>(
                "nexus::ActivateFeeSponsorProgramRevision",
            )
            .register_with_id_slice::<PauseFeeSponsorProgram>("nexus::PauseFeeSponsorProgram")
            .register_with_id_slice::<BeginCloseFeeSponsorProgram>(
                "nexus::BeginCloseFeeSponsorProgram",
            )
            .register_with_id_slice::<CloseFeeSponsorProgram>("nexus::CloseFeeSponsorProgram")
            .register_with_id_slice::<EnrollFeeSponsorBeneficiary>(
                "nexus::EnrollFeeSponsorBeneficiary",
            )
            .register_with_id_slice::<UnenrollFeeSponsorBeneficiary>(
                "nexus::UnenrollFeeSponsorBeneficiary",
            )
            .register_with_id_slice::<FundFeeSponsorProgram>("nexus::FundFeeSponsorProgram")
            .register_with_id_slice::<WithdrawFeeSponsorProgram>(
                "nexus::WithdrawFeeSponsorProgram",
            );
        assert_registry_decodes(
            &registry,
            "nexus::RegisterVerifiedFeeSponsorVaultAllocation",
            sample_fee_budget_instruction(),
        );
        let program = sample_fee_sponsor_program();
        let id = program.id.clone();
        let beneficiary = sponsor_account_id();
        assert_registry_decodes(
            &registry,
            "nexus::CreateFeeSponsorProgram",
            CreateFeeSponsorProgram { program },
        );
        assert_registry_decodes(
            &registry,
            "nexus::StageFeeSponsorProgramRevision",
            StageFeeSponsorProgramRevision {
                revision: sample_fee_sponsor_revision(id.clone()),
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::ActivateFeeSponsorProgramRevision",
            ActivateFeeSponsorProgramRevision {
                program_id: id.clone(),
                revision: 1,
                activate_at_height: 10,
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::PauseFeeSponsorProgram",
            PauseFeeSponsorProgram {
                program_id: id.clone(),
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::BeginCloseFeeSponsorProgram",
            BeginCloseFeeSponsorProgram {
                program_id: id.clone(),
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::CloseFeeSponsorProgram",
            CloseFeeSponsorProgram {
                program_id: id.clone(),
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::EnrollFeeSponsorBeneficiary",
            EnrollFeeSponsorBeneficiary {
                program_id: id.clone(),
                beneficiary: beneficiary.clone(),
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::UnenrollFeeSponsorBeneficiary",
            UnenrollFeeSponsorBeneficiary {
                program_id: id.clone(),
                beneficiary: beneficiary.clone(),
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::FundFeeSponsorProgram",
            FundFeeSponsorProgram {
                program_id: id.clone(),
                asset_definition_id: sample_fee_asset_id(),
                amount: Quantity::from(10_u32),
            },
        );
        assert_registry_decodes(
            &registry,
            "nexus::WithdrawFeeSponsorProgram",
            WithdrawFeeSponsorProgram {
                program_id: id,
                asset_definition_id: sample_fee_asset_id(),
                amount: Quantity::from(1_u32),
            },
        );
    }
}
