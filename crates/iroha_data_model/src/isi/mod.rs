//! This library contains basic Iroha Special Instructions.
//!
//! Instructions implement the [`crate::isi::Instruction`] trait and are often stored in
//! trait objects for dynamic dispatch. The [`crate::isi::InstructionBox`] type alias is a
//! convenient way to work with `Box<dyn Instruction>` allowing heterogeneous
//! instruction collections.
//!
//! Dev note: Box naming
//! - `InstructionBox` is a newtype wrapper around `Box<dyn Instruction>`. It is a
//!   heap-allocated trait object used to store heterogeneous instructions,
//!   implement shared traits (e.g., serialization, ordering), and support
//!   registry-based deserialization.
//! - Types like `RegisterBox`, `RevokeBox`, `SetKeyValueBox`, `MintBox`, etc. are
//!   enums that "box together" a family of related generic instructions into a
//!   closed, visitable set. Despite the name, they are not heap boxes; they are
//!   plain tagged unions that implement [`crate::isi::Instruction`].
#![cfg_attr(test, allow(clippy::needless_pass_by_value))]
use super::prelude::*;
use crate::{Level, Registered, seal};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use derive_more::{Constructor, Display};
use iroha_schema::{IntoSchema, Metadata as SchemaMetadata, UnnamedFieldsMeta};
use norito::codec::{Decode, Encode};
use rustc_hash::FxHashMap as HashMap;
#[cfg(test)]
use std::cell::RefCell;
use std::{
    any::Any,
    cmp::Ordering,
    fmt::Debug,
    format,
    string::String,
    sync::{Arc, OnceLock, RwLock},
    vec::Vec,
};
/// Consensus key lifecycle instructions.
pub mod consensus_keys;
/// Domain endorsement management instructions.
pub mod endorsement;
/// Governance instruction module
#[cfg(feature = "governance")]
pub mod governance;
/// Ministry agenda intake instructions.
pub mod ministry;
/// Owned trait-object wrapper for any [`crate::isi::Instruction`].
///
/// This newtype wraps `Box<dyn Instruction>` to allow implementing blanket traits
/// (e.g., `Send`/`Sync`) and to provide a stable, crate-owned type across the
/// codebase while preserving existing ergonomics via `Deref` to `dyn Instruction`.
///
/// # Examples
/// ```rust
/// use iroha_data_model::prelude::*;
///
/// let instruction: InstructionBox =
///     InstructionBox::from(Log::new(Level::INFO, "trait objects".into()));
/// ```
#[repr(transparent)]
pub struct InstructionBox(Box<dyn Instruction>);
impl norito::NoritoSchema for InstructionBox {
    fn nominal_name() -> String {
        "iroha_data_model::isi::InstructionBox".to_owned()
    }
    fn frame_name() -> String {
        // The root codec writes the registry wire ID and framed payload pair.
        // Containers still compose the nominal instruction identity above.
        <(String, Vec<u8>) as norito::NoritoSchema>::frame_name()
    }
}
impl core::ops::Deref for InstructionBox {
    type Target = dyn Instruction;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}
impl core::fmt::Display for InstructionBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InstructionBox")
    }
}
impl core::fmt::Debug for InstructionBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("InstructionBox")
            .field(&Instruction::id(&**self))
            .finish()
    }
}
impl Clone for InstructionBox {
    fn clone(&self) -> Self {
        // Use the object-safe clone-on-trait mechanism.
        self.0.dyn_box_clone()
    }
}
impl PartialEq for InstructionBox {
    fn eq(&self, other: &Self) -> bool {
        Instruction::id(&**self) == Instruction::id(&**other)
            && self.dyn_encode() == other.dyn_encode()
    }
}
impl Eq for InstructionBox {}
impl PartialOrd for InstructionBox {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for InstructionBox {
    fn cmp(&self, other: &Self) -> Ordering {
        let id_cmp = Instruction::id(&**self).cmp(Instruction::id(&**other));
        if id_cmp != Ordering::Equal {
            return id_cmp;
        }
        self.dyn_encode().cmp(&other.dyn_encode())
    }
}

macro_rules! impl_direct_instruction_box {
    ($($instruction:ty),+ $(,)?) => {
        $(
            impl From<$instruction> for InstructionBox {
                fn from(instruction: $instruction) -> Self {
                    InstructionBox(Box::new(instruction))
                }
            }
        )+
    };
}
// Allow direct boxing of standalone instructions that are not part of a grouped enum.
impl_direct_instruction_box!(crate::isi::zk::VerifyProof);
impl_direct_instruction_box!(crate::isi::zk::PruneProofs);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyProtocolActivationV1);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyExact12QualificationV1);
impl_direct_instruction_box!(crate::isi::privacy::SchedulePrivacyConsensusPolicyTighteningV1);
impl_direct_instruction_box!(crate::isi::privacy::SchedulePrivacyProtocolLimitsTighteningV1);
impl_direct_instruction_box!(crate::isi::privacy::TransitionPrivacyProtocolLifecycleV1);
impl_direct_instruction_box!(crate::isi::privacy::PublishPrivacyRootV1);
impl_direct_instruction_box!(crate::isi::privacy::BootstrapPrivacyOrchardPoolV1);
impl_direct_instruction_box!(crate::isi::privacy::BootstrapPrivacyProofManagedPoolV1);
impl_direct_instruction_box!(crate::isi::privacy::BootstrapPrivacyPgcAccountsV1);
impl_direct_instruction_box!(crate::isi::privacy::BootstrapPrivacyZkAmsRegistryV1);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyZkAcePolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RotatePrivacyZkAcePolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RevokePrivacyZkAcePolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyBootleLanternIssuerPolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RotatePrivacyBootleLanternIssuerPolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RevokePrivacyBootleLanternIssuerPolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyVegaIssuerV1);
impl_direct_instruction_box!(crate::isi::privacy::RotatePrivacyVegaIssuerV1);
impl_direct_instruction_box!(crate::isi::privacy::RevokePrivacyVegaIssuerV1);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyZkX509TrustAnchorV1);
impl_direct_instruction_box!(crate::isi::privacy::RotatePrivacyZkX509TrustAnchorV1);
impl_direct_instruction_box!(crate::isi::privacy::RevokePrivacyZkX509TrustAnchorV1);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyZkX509CertificatePolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RotatePrivacyZkX509CertificatePolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RevokePrivacyZkX509CertificatePolicyV1);
impl_direct_instruction_box!(crate::isi::privacy::RegisterPrivacyZkX509CrlV1);
impl_direct_instruction_box!(crate::isi::privacy::RotatePrivacyZkX509CrlV1);
impl_direct_instruction_box!(crate::isi::privacy::RevokePrivacyZkX509CrlV1);
impl_direct_instruction_box!(crate::isi::privacy::SubmitPrivacyProofV1);
impl_direct_instruction_box!(crate::isi::private_settlement::ActivatePrivateSettlementPoolV1);
impl_direct_instruction_box!(crate::isi::private_settlement::RotatePrivateSettlementPoolPolicyV1);
impl_direct_instruction_box!(
    crate::isi::private_settlement::RegisterAtomicPrivateSettlementPrepareV1
);
impl_direct_instruction_box!(crate::isi::private_settlement::AbortAtomicPrivateSettlementV1);
impl_direct_instruction_box!(crate::isi::private_settlement::FinalizeAtomicPrivateSettlementV1);
impl_direct_instruction_box!(crate::isi::bridge::SubmitBridgeProof);
impl_direct_instruction_box!(crate::isi::bridge::RecordBridgeReceipt);
impl_direct_instruction_box!(crate::isi::asset_alias::SetAssetDefinitionAlias);
impl_direct_instruction_box!(crate::isi::asset_transfer_control::SetAssetTransferAvailability);
impl_direct_instruction_box!(crate::isi::asset_transfer_control::SetAssetTransferBlacklist);
impl_direct_instruction_box!(crate::isi::asset_transfer_control::SetAssetTransferControl);
impl_direct_instruction_box!(crate::isi::asset_transfer_control::SetAssetHoldingLimit);
impl_direct_instruction_box!(crate::isi::retail_daily_limit::ActivateRetailDailyLimitV1);
impl_direct_instruction_box!(crate::isi::retail_daily_limit::BindRetailIdentityV1);
impl_direct_instruction_box!(crate::isi::retail_daily_limit::RetailMonetaryMovementV1);
impl_direct_instruction_box!(
    crate::isi::sumeragi_amx::RegisterAmxDataspaceV1,
    crate::isi::sumeragi_amx::BeginAmxV1,
    crate::isi::sumeragi_amx::RelayAmxPreparedV1,
    crate::isi::sumeragi_amx::RelayAmxHandoffV1,
    crate::isi::sumeragi_amx::RegisterAmxParticipantV1,
    crate::isi::sumeragi_amx::PrepareAmxV1,
    crate::isi::sumeragi_amx::SettleAmxV1,
    crate::isi::sumeragi_amx::RelayGlobalAmxHandoffV1,
);
impl_direct_instruction_box!(
    crate::isi::private_dataspace::RegisterPrivateDataspace,
    crate::isi::private_dataspace::AnchorPrivateDataspace,
);
// Allow direct boxing of ZK asset and voting instructions
impl_direct_instruction_box!(crate::isi::zk::RegisterZkAsset);
impl_direct_instruction_box!(crate::isi::zk::ScheduleConfidentialPolicyTransition);
impl_direct_instruction_box!(crate::isi::zk::CancelConfidentialPolicyTransition);
impl_direct_instruction_box!(crate::isi::zk::CreateElection);
impl_direct_instruction_box!(crate::isi::zk::SubmitBallot);
impl_direct_instruction_box!(crate::isi::zk::FinalizeElection);
impl_direct_instruction_box!(crate::isi::staking::ActivatePublicLaneValidator);
impl_direct_instruction_box!(crate::isi::staking::ExitPublicLaneValidator);
impl_direct_instruction_box!(crate::isi::staking::RebindPublicLaneValidatorPeer);
impl_direct_instruction_box!(crate::isi::kaigi::CreateKaigi);
impl_direct_instruction_box!(crate::isi::kaigi::JoinKaigi);
impl_direct_instruction_box!(crate::isi::kaigi::LeaveKaigi);
impl_direct_instruction_box!(crate::isi::kaigi::EndKaigi);
impl_direct_instruction_box!(crate::isi::kaigi::RecordKaigiUsage);
impl_direct_instruction_box!(crate::isi::kaigi::SetKaigiRelayManifest);
impl_direct_instruction_box!(crate::isi::kaigi::RegisterKaigiRelay);
impl_direct_instruction_box!(crate::isi::kaigi::UnregisterKaigiRelay);
impl_direct_instruction_box!(crate::isi::kaigi::ReportKaigiRelayHealth);
impl_direct_instruction_box!(crate::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation);
macro_rules! impl_nexus_program_instruction_box {
    ($($ty:ident),+ $(,)?) => {
        $(
            impl From<crate::isi::nexus::$ty> for InstructionBox {
                fn from(i: crate::isi::nexus::$ty) -> Self {
                    InstructionBox(Box::new(i))
                }
            }
        )+
    };
}
impl_nexus_program_instruction_box!(
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
impl_direct_instruction_box!(crate::isi::identifier::RegisterIdentifierPolicy);
impl_direct_instruction_box!(crate::isi::identifier::ActivateIdentifierPolicy);
impl_direct_instruction_box!(crate::isi::identifier::ClaimIdentifier);
impl_direct_instruction_box!(crate::isi::identifier::RevokeIdentifier);
impl_direct_instruction_box!(crate::isi::soracloud::DeploySoracloudService);
impl_direct_instruction_box!(crate::isi::soracloud::UpgradeSoracloudService);
impl_direct_instruction_box!(crate::isi::soracloud::DeploySoracloudAppInfra);
impl_direct_instruction_box!(crate::isi::soracloud::UpgradeSoracloudAppInfra);
impl_direct_instruction_box!(crate::isi::soracloud::RollbackSoracloudService);
impl_direct_instruction_box!(crate::isi::soracloud::SetSoracloudServiceConfig);
impl_direct_instruction_box!(crate::isi::soracloud::DeleteSoracloudServiceConfig);
impl_direct_instruction_box!(crate::isi::soracloud::SetSoracloudServiceSecret);
impl_direct_instruction_box!(crate::isi::soracloud::DeleteSoracloudServiceSecret);
impl_direct_instruction_box!(crate::isi::soracloud::MutateSoracloudState);
impl_direct_instruction_box!(crate::isi::soracloud::RegisterSoracloudFhePolicy);
impl_direct_instruction_box!(crate::isi::soracloud::RotateSoracloudFhePolicy);
impl_direct_instruction_box!(crate::isi::soracloud::RevokeSoracloudFhePolicy);
impl_direct_instruction_box!(crate::isi::soracloud::RunSoracloudFheJob);
impl_direct_instruction_box!(crate::isi::soracloud::RecordSoracloudDecryptionRequest);
impl_direct_instruction_box!(crate::isi::soracloud::JoinSoracloudHfSharedLease);
impl_direct_instruction_box!(crate::isi::soracloud::LeaveSoracloudHfSharedLease);
impl_direct_instruction_box!(crate::isi::soracloud::RenewSoracloudHfSharedLease);
impl_direct_instruction_box!(crate::isi::soracloud::AdvertiseSoracloudInrouHost);
impl_direct_instruction_box!(crate::isi::soracloud::WithdrawSoracloudInrouHost);
impl_direct_instruction_box!(crate::isi::soracloud::ReconcileSoracloudInrouPlacements);
impl_direct_instruction_box!(crate::isi::soracloud::DeploySoracloudAgentApartment);
impl_direct_instruction_box!(crate::isi::soracloud::RenewSoracloudAgentLease);
impl_direct_instruction_box!(crate::isi::soracloud::RestartSoracloudAgentApartment);
impl_direct_instruction_box!(crate::isi::soracloud::RevokeSoracloudAgentPolicy);
impl_direct_instruction_box!(crate::isi::soracloud::RequestSoracloudAgentWalletSpend);
impl_direct_instruction_box!(crate::isi::soracloud::ApproveSoracloudAgentWalletSpend);
impl_direct_instruction_box!(crate::isi::soracloud::EnqueueSoracloudAgentMessage);
impl_direct_instruction_box!(crate::isi::soracloud::AcknowledgeSoracloudAgentMessage);
impl_direct_instruction_box!(crate::isi::soracloud::AllowSoracloudAgentAutonomyArtifact);
impl_direct_instruction_box!(crate::isi::soracloud::RunSoracloudAgentAutonomy);
impl_direct_instruction_box!(crate::isi::soracloud::RecordSoracloudAgentAutonomyExecution);
impl_direct_instruction_box!(crate::isi::soracloud::StartSoracloudTrainingJob);
impl_direct_instruction_box!(crate::isi::soracloud::CheckpointSoracloudTrainingJob);
impl_direct_instruction_box!(crate::isi::soracloud::RetrySoracloudTrainingJob);
impl_direct_instruction_box!(crate::isi::soracloud::RegisterSoracloudModelArtifact);
impl_direct_instruction_box!(crate::isi::soracloud::RegisterSoracloudModelWeight);
impl_direct_instruction_box!(crate::isi::soracloud::PromoteSoracloudModelWeight);
impl_direct_instruction_box!(crate::isi::soracloud::RollbackSoracloudModelWeight);
impl_direct_instruction_box!(crate::isi::soracloud::RegisterSoracloudUploadedModelBundle);
impl_direct_instruction_box!(crate::isi::soracloud::FinalizeSoracloudUploadedModelBundle);
impl_direct_instruction_box!(crate::isi::soracloud::AdvanceSoracloudRollout);
impl_direct_instruction_box!(crate::isi::soracloud::SetSoracloudRuntimeState);
impl_direct_instruction_box!(crate::isi::soracloud::SetSoracloudInrouReplicaRuntimeState);
impl_direct_instruction_box!(crate::isi::soracloud::ClearSoracloudInrouReplicaRuntimeState);
impl_direct_instruction_box!(crate::isi::soracloud::ReportSoracloudServiceLeaseUsage);
impl_direct_instruction_box!(crate::isi::soracloud::RecordSoracloudMailboxMessage);
impl_direct_instruction_box!(crate::isi::soracloud::RecordSoracloudRuntimeReceipt);
impl_direct_instruction_box!(crate::isi::soracloud::ApplySoracloudOrderedMailboxResult);
// Allow direct boxing of runtime upgrade instructions
impl_direct_instruction_box!(crate::isi::runtime_upgrade::ProposeRuntimeUpgrade);
impl_direct_instruction_box!(crate::isi::runtime_upgrade::ActivateRuntimeUpgrade);
impl_direct_instruction_box!(crate::isi::runtime_upgrade::CancelRuntimeUpgrade);
// Allow direct boxing of verifying-keys registry instructions
impl_direct_instruction_box!(crate::isi::verifying_keys::RegisterVerifyingKey);
impl_direct_instruction_box!(crate::isi::verifying_keys::UpdateVerifyingKey);
// Allow direct boxing of consensus key lifecycle instructions.
impl_direct_instruction_box!(crate::isi::register::RegisterCommitteePeerWithPop);
impl_direct_instruction_box!(crate::isi::consensus_keys::RegisterConsensusKey);
impl_direct_instruction_box!(crate::isi::consensus_keys::RotateConsensusKey);
impl_direct_instruction_box!(crate::isi::consensus_keys::DisableConsensusKey);
impl_direct_instruction_box!(crate::isi::consensus_keys::ApplyThresholdKeyLifecycleCertificateV1);
// Domain endorsement management instructions.
impl_direct_instruction_box!(crate::isi::endorsement::RegisterDomainCommittee);
impl_direct_instruction_box!(crate::isi::endorsement::SetDomainEndorsementPolicy);
impl_direct_instruction_box!(crate::isi::endorsement::SubmitDomainEndorsement);
// Allow direct boxing of social incentive instructions.
impl_direct_instruction_box!(crate::isi::social::ClaimTwitterFollowReward);
impl_direct_instruction_box!(crate::isi::social::SendToTwitter);
impl_direct_instruction_box!(crate::isi::social::CancelTwitterEscrow);
// Generic game session lifecycle is a public consensus-owned instruction surface.
impl_direct_instruction_box!(crate::isi::game::RegisterExecutionProofProfileV1);
impl_direct_instruction_box!(crate::isi::game::VerifyExecutionProofV1);
impl_direct_instruction_box!(crate::isi::game::SettleGameSessionV1);
impl_direct_instruction_box!(crate::isi::game::OpenGameSessionV1);
impl_direct_instruction_box!(crate::isi::game::JoinGameSessionV1);
impl_direct_instruction_box!(crate::isi::game::StartGameSessionV1);
impl_direct_instruction_box!(crate::isi::game::CommitGameCheckpointV1);
impl_direct_instruction_box!(crate::isi::game::ChallengeGameSessionV1);
impl_direct_instruction_box!(crate::isi::game::CommitGameInputsV1);
impl_direct_instruction_box!(crate::isi::game::RevealGameInputsV1);
impl_direct_instruction_box!(crate::isi::game::AdvanceGameDeadlineV1);
impl_direct_instruction_box!(crate::isi::game::ExpireGameSessionV1);
impl_direct_instruction_box!(crate::isi::game::ClaimGamePayoutV1);
impl_direct_instruction_box!(crate::isi::game::StakeGameItemV1);
// Native exact-price NFT offers.
impl_direct_instruction_box!(crate::isi::nft_market::OfferNftV1);
impl_direct_instruction_box!(crate::isi::nft_market::BuyNftV1);
impl_direct_instruction_box!(crate::isi::nft_market::CancelNftOfferV1);
// Allow direct boxing of native asset escrow instructions.
impl_direct_instruction_box!(crate::isi::escrow::OpenAssetEscrow);
impl_direct_instruction_box!(crate::isi::escrow::AcceptAssetEscrow);
impl_direct_instruction_box!(crate::isi::escrow::MarkEscrowPaymentSent);
impl_direct_instruction_box!(crate::isi::escrow::ReleaseAssetEscrow);
impl_direct_instruction_box!(crate::isi::escrow::CancelAssetEscrow);
impl_direct_instruction_box!(crate::isi::escrow::OpenEscrowDispute);
impl_direct_instruction_box!(crate::isi::escrow::ResolveEscrowDispute);
impl_direct_instruction_box!(crate::isi::escrow::OpenAssetLock);
impl_direct_instruction_box!(crate::isi::escrow::OpenConditionalEscrow);
impl_direct_instruction_box!(crate::isi::escrow::AttestEscrowCondition);
impl_direct_instruction_box!(crate::isi::escrow::ExpireConditionalEscrow);
impl_direct_instruction_box!(crate::isi::escrow::DrawdownAssetLock);
impl_direct_instruction_box!(crate::isi::escrow::CancelAssetLock);
impl_direct_instruction_box!(crate::isi::escrow::ExpireAssetLock);
// Allow direct boxing of SoraNet VPN lease escrow instructions.
impl_direct_instruction_box!(crate::isi::vpn::OpenVpnLeaseEscrow);
impl_direct_instruction_box!(crate::isi::vpn::SettleVpnLease);
impl_direct_instruction_box!(crate::isi::vpn::RefundExpiredVpnLease);
// Allow direct boxing of the SCCP v1 instructions (`specs/sccp.md` §4).
impl_direct_instruction_box!(
    crate::isi::sccp::InitializeSccpV1,
    crate::isi::sccp::SetSccpBridgeKeyV1,
    crate::isi::sccp::SubmitSccpAttestationsV1,
    crate::isi::sccp::SubmitSccpAttestationFaultV1,
    crate::isi::sccp::RecordSccpMessage,
    crate::isi::sccp::SubmitSccpInboundMessageV1,
    crate::isi::sccp::SettleSccpV1,
    crate::isi::sccp::SubmitSccpOutboundVoidV1,
    crate::isi::sccp::AdvanceSccpLightClientV1,
    crate::isi::sccp::ReportSccpLightClientEquivocationV1,
);
// Allow direct boxing of SoraFS capacity marketplace instructions.
impl_direct_instruction_box!(crate::isi::sorafs::RegisterCapacityDeclaration);
impl_direct_instruction_box!(crate::isi::sorafs::RecordCapacityTelemetry);
impl_direct_instruction_box!(crate::isi::sorafs::RegisterCapacityDispute);
impl_direct_instruction_box!(crate::isi::sorafs::ResolveSorafsCapacityDispute);
// Allow direct boxing of SoraFS pin registry instructions
impl_direct_instruction_box!(crate::isi::sorafs::RegisterPinManifest);
impl_direct_instruction_box!(crate::isi::sorafs::AssertSorafsPublicationV1);
impl_direct_instruction_box!(crate::isi::sorafs::InitializeSorafsProviderAdmissionV1);
impl_direct_instruction_box!(crate::isi::sorafs::ApprovePinManifest);
impl_direct_instruction_box!(crate::isi::sorafs::RetirePinManifest);
// Allow direct boxing of content lane instructions.
impl_direct_instruction_box!(crate::isi::content::PublishContentBundle);
impl_direct_instruction_box!(crate::isi::content::RetireContentBundle);
impl_direct_instruction_box!(crate::prelude::BindManifestAlias);
impl_direct_instruction_box!(crate::prelude::IssueReplicationOrder);
impl_direct_instruction_box!(crate::prelude::CompleteReplicationOrder);
impl_direct_instruction_box!(crate::prelude::ReviseReplicationOrderAssignments);
impl_direct_instruction_box!(crate::prelude::ExpireReplicationOrder);
impl_direct_instruction_box!(crate::prelude::SetProviderIngestCompletionAuthority);
impl_direct_instruction_box!(crate::prelude::RevokeProviderIngestCompletionAuthority);
impl_direct_instruction_box!(crate::prelude::SetPricingSchedule);
impl_direct_instruction_box!(crate::prelude::UpsertProviderCredit);
impl_direct_instruction_box!(crate::isi::sorafs::SetSorafsOrderbookPolicy);
impl_direct_instruction_box!(crate::isi::sorafs::SubmitSorafsOrderbookOrder);
impl_direct_instruction_box!(crate::isi::sorafs::CancelSorafsOrderbookOrder);
impl_direct_instruction_box!(crate::isi::sorafs::MutateSorafsStreamTokenCustody);
impl_direct_instruction_box!(crate::isi::sorafs::MutateSorafsStreamTokenAuthority);
impl_direct_instruction_box!(crate::isi::sorafs::MutateSorafsStreamTokenGateway);
impl_direct_instruction_box!(crate::isi::sorafs::MutateSorafsFinalPromotionAuthority);
impl_direct_instruction_box!(crate::isi::sorafs::MutateSorafsFinalPromotionAccountCustody);
impl_direct_instruction_box!(crate::isi::sorafs::MutateSorafsReleaseManifestAuthority);
impl_direct_instruction_box!(crate::isi::sorafs::MutateSorafsTopologyAuthority);
impl_direct_instruction_box!(crate::isi::sorafs::MatchSorafsOrderbook);
impl_direct_instruction_box!(crate::isi::sorafs::MaintainSorafsOrderbook);
impl_direct_instruction_box!(crate::isi::sorafs::RecordSorafsOrderbookSettlementReceipt);
impl_direct_instruction_box!(crate::isi::sorafs::SubmitSorafsRepairTask);
impl_direct_instruction_box!(crate::isi::sorafs::ApplySorafsRepairTaskAction);
impl_direct_instruction_box!(crate::isi::sorafs::SubmitSorafsRepairAppeal);
impl_direct_instruction_box!(crate::isi::sorafs::SetSorafsProofOutcomeSignerPolicy);
impl_direct_instruction_box!(crate::isi::sorafs::SubmitSorafsProofOutcome);
impl_direct_instruction_box!(crate::isi::sorafs::SetSorafsReputationJournalAuthorityPolicy);
impl_direct_instruction_box!(crate::isi::sorafs::AppendSorafsPorReputationJournalEntry);
impl_direct_instruction_box!(crate::isi::sorafs::AppendSorafsStreamTokenReputationJournalEntry);
macro_rules! impl_sorafs_reserve_instruction_box {
    ($($instruction:ty),+ $(,)?) => {
        $(
            impl From<$instruction> for InstructionBox {
                fn from(instruction: $instruction) -> Self {
                    InstructionBox(Box::new(instruction))
                }
            }
        )+
    };
}
impl_sorafs_reserve_instruction_box!(
    crate::isi::sorafs::SetSorafsReservePolicy,
    crate::isi::sorafs::RegisterSorafsReserveAccount,
    crate::isi::sorafs::RequestSorafsReserveMovement,
    crate::isi::sorafs::DecideSorafsReserveMovement,
    crate::isi::sorafs::ChargeSorafsReserveRent,
    crate::isi::sorafs::AdvanceSorafsReserveLifecycle,
    crate::isi::sorafs::DrawSorafsReserveCredit,
    crate::isi::sorafs::RepaySorafsReserveCredit,
    crate::isi::sorafs::SubmitSorafsReserveAppeal,
    crate::isi::sorafs::DecideSorafsReserveAppeal,
);
impl_direct_instruction_box!(crate::isi::sorafs::SetSorafsPopIssuerPolicy);
impl_direct_instruction_box!(crate::isi::sorafs::CommitSorafsPopCredentialBatch);
impl_direct_instruction_box!(crate::isi::sorafs::PublishSorafsPopRevocationList);
impl_direct_instruction_box!(crate::isi::sorafs::SetSorafsModerationPolicy);
impl_direct_instruction_box!(crate::isi::sorafs::SubmitSorafsModerationAppeal);
impl_direct_instruction_box!(crate::isi::sorafs::RegisterSorafsModerationJurorEligibility);
impl_direct_instruction_box!(crate::isi::sorafs::FinalizeSorafsModerationSortition);
impl_direct_instruction_box!(crate::isi::sorafs::AcceptSorafsModerationJurorAssignment);
impl_direct_instruction_box!(crate::isi::sorafs::ActivateSorafsModerationCase);
impl_direct_instruction_box!(crate::isi::sorafs::SubmitSorafsModerationCommit);
impl_direct_instruction_box!(crate::isi::sorafs::RaiseSorafsModerationChallenge);
impl_direct_instruction_box!(crate::isi::sorafs::ResolveSorafsModerationChallenge);
impl_direct_instruction_box!(crate::isi::sorafs::ExpireSorafsModerationChallenge);
impl_direct_instruction_box!(crate::isi::sorafs::SubmitSorafsModerationReveal);
impl_direct_instruction_box!(crate::isi::sorafs::FinalizeSorafsModerationCase);
impl_direct_instruction_box!(crate::isi::space_directory::PublishSpaceDirectoryManifest);
impl_direct_instruction_box!(crate::isi::space_directory::RevokeSpaceDirectoryManifest);
impl_direct_instruction_box!(crate::isi::space_directory::ExpireSpaceDirectoryManifest);
impl_direct_instruction_box!(crate::isi::alias_setup::EnsureAlias);
impl_direct_instruction_box!(crate::isi::alias_setup::RenewAliasLease);
impl_direct_instruction_box!(crate::isi::alias_setup::ConfigureAliasAutoRenew);
impl_direct_instruction_box!(crate::isi::alias_setup::RebindAccountAlias);
impl_direct_instruction_box!(crate::isi::alias_setup::CompareAndSetPrimaryAccountAlias);
impl_direct_instruction_box!(crate::isi::account_recovery::ReplaceAccountController);
impl_direct_instruction_box!(crate::isi::account_recovery::SetAccountRecoveryPolicy);
impl_direct_instruction_box!(crate::isi::account_recovery::ClearAccountRecoveryPolicy);
impl_direct_instruction_box!(crate::isi::account_recovery::ProposeAccountRecovery);
impl_direct_instruction_box!(crate::isi::account_recovery::ApproveAccountRecovery);
impl_direct_instruction_box!(crate::isi::account_recovery::CancelAccountRecovery);
impl_direct_instruction_box!(crate::isi::account_recovery::FinalizeAccountRecovery);
impl_direct_instruction_box!(crate::isi::contract_alias::SetContractAlias);
// Allow direct boxing of first-release Musubi registry instructions.
macro_rules! impl_musubi_instruction_box {
    ($($instruction:ident),+ $(,)?) => {
        $(
            impl From<crate::isi::musubi::$instruction> for InstructionBox {
                fn from(i: crate::isi::musubi::$instruction) -> Self {
                    InstructionBox(Box::new(i))
                }
            }
        )+
    };
}
impl_musubi_instruction_box!(
    RegisterMusubiNamespaceBindingV1,
    RegisterMusubiArchiveV1,
    AdvanceMusubiPinOutboxV1,
    CheckMusubiPinOutboxV1,
    RegisterMusubiProviderBundleAttestationV1,
    AddMusubiArchiveLocationV1,
    RetireMusubiArchiveLocationV1,
    PublishMusubiReleaseV1,
    SetMusubiReleaseYankV1,
    SetMusubiPackageMetadataV1,
    InviteMusubiPackageMaintainerV1,
    AcceptMusubiPackageMaintainerV1,
    RevokeMusubiPackageMaintainerInvitationV1,
    SetMusubiPackageMaintainerRoleV1,
    RemoveMusubiPackageMaintainerV1,
    RegisterMusubiAliasV1,
    RecoverMusubiPackageV1,
    RetargetMusubiAliasV1,
    SetMusubiArtifactTakedownV1,
    SetMusubiRegistryPolicyV1,
    AssertMusubiReleaseDigestV1,
);
impl_direct_instruction_box!(crate::isi::kagemusha_v1::TopUpKagemushaV1);
impl_direct_instruction_box!(crate::isi::kagemusha_v1::TopUpKagemushaOrdinaryV1);
impl_direct_instruction_box!(crate::isi::kagemusha_v1::RedeemKagemushaV1);
// Allow direct boxing of oracle feed instructions.
impl_direct_instruction_box!(crate::isi::oracle::RegisterOracleFeed);
impl_direct_instruction_box!(crate::isi::oracle::SubmitOracleObservation);
impl_direct_instruction_box!(crate::isi::oracle::AggregateOracleFeed);
impl_direct_instruction_box!(crate::isi::oracle::OpenOracleDispute);
impl_direct_instruction_box!(crate::isi::oracle::ResolveOracleDispute);
impl_direct_instruction_box!(crate::isi::oracle::ProposeOracleChange);
impl_direct_instruction_box!(crate::isi::oracle::VoteOracleChangeStage);
impl_direct_instruction_box!(crate::isi::oracle::RollbackOracleChange);
impl_direct_instruction_box!(crate::isi::oracle::SubmitDefiOracleAttestation);
impl_direct_instruction_box!(crate::isi::oracle::RecordTwitterBinding);
impl_direct_instruction_box!(crate::isi::oracle::RevokeTwitterBinding);
// Allow direct boxing of SoraDNS resolver-directory instructions.
impl_direct_instruction_box!(crate::isi::soradns::SubmitDirectoryDraft);
impl_direct_instruction_box!(crate::isi::soradns::PublishDirectory);
impl_direct_instruction_box!(crate::isi::soradns::RevokeResolver);
impl_direct_instruction_box!(crate::isi::soradns::UnrevokeResolver);
impl_direct_instruction_box!(crate::isi::soradns::AddReleaseSigner);
impl_direct_instruction_box!(crate::isi::soradns::RemoveReleaseSigner);
impl_direct_instruction_box!(crate::isi::soradns::SetDirectoryRotationPolicy);
// Allow direct boxing of public lane staking instructions.
impl_direct_instruction_box!(crate::isi::staking::RegisterPublicLaneCandidate);
impl_direct_instruction_box!(crate::isi::staking::RegisterPublicLaneValidator);
impl_direct_instruction_box!(crate::isi::staking::BondPublicLaneStake);
impl_direct_instruction_box!(crate::isi::staking::SchedulePublicLaneUnbond);
impl_direct_instruction_box!(crate::isi::staking::FinalizePublicLaneUnbond);
impl_direct_instruction_box!(crate::isi::staking::SlashPublicLaneValidator);
impl_direct_instruction_box!(crate::isi::staking::RecordPublicLaneRewards);
impl_direct_instruction_box!(crate::isi::staking::ClaimPublicLaneRewards);
// Allow direct boxing of confidential parameter registry instructions
impl_direct_instruction_box!(crate::isi::confidential::PublishPedersenParams);
impl_direct_instruction_box!(crate::isi::confidential::SetPedersenParamsLifecycle);
impl_direct_instruction_box!(crate::isi::confidential::PublishPoseidonParams);
impl_direct_instruction_box!(crate::isi::confidential::SetPoseidonParamsLifecycle);
// Allow direct boxing of governance instructions
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeDeployContract);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeContractLifecycleGovernance);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeContractEmergencyHold);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeGlobalDataTriggerPermissionGovernance);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeRuntimeUpgradeProposal);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeSccpRouteGovernance);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeSorafsProviderGovernance);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeValidationFeePolicy);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::ProposeValidationFeePayoutLifecycle);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::CreateParliamentGovernanceAttemptV1);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::SubmitParliamentLifecycleTransitionV1);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::CastZkBallot);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::CastPlainBallot);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::UpdatePlainConviction);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::SlashGovernanceLock);
#[cfg(feature = "governance")]
impl_direct_instruction_box!(crate::isi::governance::RestituteGovernanceLock);
// Allow direct boxing of asset metadata helpers
impl_direct_instruction_box!(crate::isi::transparent::SetAssetKeyValue);
impl_direct_instruction_box!(crate::isi::transparent::RemoveAssetKeyValue);
impl_direct_instruction_box!(crate::isi::transparent::AddSignatory);
impl_direct_instruction_box!(crate::isi::transparent::RemoveSignatory);
impl_direct_instruction_box!(crate::isi::transparent::SetAccountQuorum);
impl_direct_instruction_box!(crate::isi::ministry::SubmitAgendaProposal);
/// Object-safe cloning support for [`Instruction`] trait objects.
pub trait InstructionDynClone {
    /// Clone the underlying instruction into a boxed trait object.
    fn dyn_box_clone(&self) -> InstructionBox;
}
/// Marker trait designating instruction.
///
/// Instructions allow to change the state of `Iroha`.
///
/// If you need to use different instructions together,
/// consider wrapping them into [`crate::isi::InstructionBox`]es.
pub trait Instruction: InstructionDynClone + seal::Instruction + Send + Sync + 'static {
    /// Execute instruction
    fn dyn_execute(&self) {}
    /// Encode instruction into bytes
    fn dyn_encode(&self) -> Vec<u8>;
    /// Append encoded instruction bytes to `out`.
    fn dyn_encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.dyn_encode());
    }
    /// Return a best-effort capacity hint for [`Self::dyn_encode_into`].
    fn dyn_encode_capacity_hint(&self) -> Option<usize> {
        self.dyn_encoded_len()
    }
    /// Return the encoded instruction payload length without allocating when available.
    fn dyn_encoded_len(&self) -> Option<usize> {
        None
    }
    /// Write the exact canonical Norito frame without materializing an intermediate payload.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical frame encoding fails or the destination writer rejects the
    /// frame.
    fn dyn_write_frame(&self, writer: &mut dyn std::io::Write) -> Result<(), norito::core::Error>;
    /// Write the registry wire identifier and framed instruction as one canonical tuple.
    ///
    /// The concrete instruction owns frame measurement while retaining the encoder's
    /// destination, including length-only encoding passes.
    ///
    /// # Errors
    ///
    /// Returns tuple-prefix, frame-measurement, or checked-output errors.
    fn dyn_write_pair(
        &self,
        writer: &mut norito::core::Encoder<'_>,
        wire_id: &str,
    ) -> Result<(), norito::core::Error>;
    /// Return the exact canonical Norito frame length without allocating.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical frame length cannot be computed.
    fn dyn_frame_len(&self) -> Result<usize, norito::core::Error>;
    /// Downcast to concrete type
    fn as_any(&self) -> &dyn Any;
    /// Identifier of this instruction type.
    ///
    /// By default, it resolves to the name of the concrete type at compile time, providing a stable
    /// identifier without relying on runtime reflection.
    fn id(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
    /// Convert into [`crate::isi::InstructionBox`]
    fn into_instruction_box(self: Box<Self>) -> InstructionBox
    where
        Self: Sized,
    {
        // Coerce `Box<Self>` to `Box<dyn Instruction>` and wrap
        InstructionBox(self)
    }
}
/// Marker trait for built-in instructions.
pub trait BuiltInInstruction: Instruction {
    /// [`Encode`] [`Self`] as [`crate::isi::InstructionBox`].
    ///
    /// Used to avoid an unnecessary clone
    fn encode_as_instruction_box(&self) -> Vec<u8>;
}
impl<T> BuiltInInstruction for T
where
    T: Instruction + Encode,
{
    fn encode_as_instruction_box(&self) -> Vec<u8> {
        self.encode()
    }
}
impl<T> Instruction for T
where
    T: Clone
        + Debug
        + PartialEq
        + PartialOrd
        + norito::NoritoSerialize
        + seal::Instruction
        + Send
        + Sync
        + 'static,
{
    fn dyn_encode(&self) -> Vec<u8> {
        self.encode()
    }
    fn dyn_encode_into(&self, out: &mut Vec<u8>) {
        Encode::encode_to(self, out);
    }
    fn dyn_encode_capacity_hint(&self) -> Option<usize> {
        norito::SerializePayload::encoded_len_exact(self)
            .or_else(|| norito::SerializePayload::encoded_len_hint(self))
    }
    fn dyn_encoded_len(&self) -> Option<usize> {
        norito::SerializePayload::encoded_len_exact(self)
    }
    fn dyn_write_frame(&self, writer: &mut dyn std::io::Write) -> Result<(), norito::core::Error> {
        let mut writer = writer;
        norito::core::write_frame_to_writer(self, &mut writer)
    }
    fn dyn_write_pair(
        &self,
        writer: &mut norito::core::Encoder<'_>,
        wire_id: &str,
    ) -> Result<(), norito::core::Error> {
        norito::core::write_frame_with_prefix(self, writer, |writer, frame_len| {
            write_instruction_pair_prefix(writer, wire_id, frame_len)
        })
    }
    fn dyn_frame_len(&self) -> Result<usize, norito::core::Error> {
        norito::core::encoded_frame_len(self)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
// Provide an object-safe cloning path for any `T` that implements `Instruction` + `Clone`.
impl<T> InstructionDynClone for T
where
    T: Instruction + Clone,
{
    fn dyn_box_clone(&self) -> InstructionBox {
        InstructionBox(Box::new(self.clone()))
    }
}
fn instruction_tuple_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
fn write_instruction_pair_prefix<W: std::io::Write>(
    mut writer: W,
    name: &str,
    framed_payload_len: usize,
) -> Result<(), norito::core::Error> {
    let flags = instruction_tuple_flags();
    let name_len = norito::core::len_prefix_len_with_flags(name.len(), flags)
        .checked_add(name.len())
        .ok_or(norito::core::Error::LengthMismatch)?;
    norito::core::write_len_with_flags(
        &mut writer,
        u64::try_from(name_len).map_err(|_| norito::core::Error::LengthMismatch)?,
        flags,
    )?;
    norito::core::write_len_with_flags(
        &mut writer,
        u64::try_from(name.len()).map_err(|_| norito::core::Error::LengthMismatch)?,
        flags,
    )?;
    std::io::Write::write_all(&mut writer, name.as_bytes())?;
    let payload_len = core::mem::size_of::<u64>()
        .checked_add(framed_payload_len)
        .ok_or(norito::core::Error::LengthMismatch)?;
    norito::core::write_len_with_flags(
        &mut writer,
        u64::try_from(payload_len).map_err(|_| norito::core::Error::LengthMismatch)?,
        flags,
    )?;
    norito::core::write_seq_len(
        &mut writer,
        u64::try_from(framed_payload_len).map_err(|_| norito::core::Error::LengthMismatch)?,
    )?;
    Ok(())
}
struct ExactInstructionFrameWriter<'a, W: std::io::Write + ?Sized> {
    inner: &'a mut W,
    expected: usize,
    written: usize,
    rejected_write: bool,
}
impl<'a, W: std::io::Write + ?Sized> ExactInstructionFrameWriter<'a, W> {
    fn new(inner: &'a mut W, expected: usize) -> Self {
        Self {
            inner,
            expected,
            written: 0,
            rejected_write: false,
        }
    }
    fn is_complete(&self) -> bool {
        !self.rejected_write && self.written == self.expected
    }
    fn admit(&mut self, additional: usize) -> std::io::Result<()> {
        let Some(end) = self.written.checked_add(additional) else {
            self.rejected_write = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "instruction frame length overflow",
            ));
        };
        if end > self.expected {
            self.rejected_write = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "instruction frame exceeded its counted length",
            ));
        }
        Ok(())
    }
}
impl<W: std::io::Write + ?Sized> std::io::Write for ExactInstructionFrameWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.admit(bytes.len())?;
        let written = self.inner.write(bytes)?;
        self.written += written;
        Ok(written)
    }
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.admit(bytes.len())?;
        self.inner.write_all(bytes)?;
        self.written += bytes.len();
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
/// Return the stable registry wire identifier used to frame an instruction.
#[must_use]
pub fn instruction_wire_id(instr: &InstructionBox) -> Option<&'static str> {
    let inner = &**instr;
    let type_name = Instruction::id(inner);
    instruction_encoding_entry(type_name).map(|entry| entry.wire_id)
}
/// Encode one registered instruction into its stable wire id and exact Norito frame.
///
/// The returned payload is the same framed byte sequence embedded in an [`InstructionBox`] wire
/// tuple. It can be decoded with [`decode_instruction_from_pair`] and is suitable for planner
/// responses that clients must verify and submit without altering instruction bytes.
#[must_use]
pub fn framed_instruction_payload(instr: &InstructionBox) -> Option<(&'static str, Vec<u8>)> {
    let inner = &**instr;
    let type_name = Instruction::id(inner);
    let entry = {
        let registry = instruction_registry();
        registry.entry_for_type_name(type_name)
    }?;
    let framed_payload_len = inner.dyn_frame_len().ok()?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(framed_payload_len).ok()?;
    let (write_result, complete) = {
        let mut exact = ExactInstructionFrameWriter::new(&mut payload, framed_payload_len);
        let write_result = inner.dyn_write_frame(&mut exact);
        (write_result, exact.is_complete())
    };
    write_result.ok()?;
    complete.then_some((entry.wire_id, payload))
}
#[cfg(test)]
fn encoded_instruction_pair_payload(instr: &InstructionBox) -> Option<(&'static str, Vec<u8>)> {
    framed_instruction_payload(instr)
}
fn encoded_instruction_pair_len(instr: &InstructionBox) -> Option<usize> {
    let inner = &**instr;
    let type_name = Instruction::id(inner);
    let entry = instruction_encoding_entry(type_name)?;
    let framed_payload_len = inner.dyn_frame_len().ok()?;
    encoded_instruction_tuple_len(entry.wire_id, framed_payload_len)
}
fn encoded_instruction_pair_hint(instr: &InstructionBox) -> Option<usize> {
    let inner = &**instr;
    let type_name = Instruction::id(inner);
    let entry = instruction_encoding_entry(type_name)?;
    let payload_len = {
        let _guard = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        Instruction::dyn_encode_capacity_hint(inner)?
    };
    let framed_payload_len = (entry.frame_len)(payload_len)?;
    encoded_instruction_tuple_len(entry.wire_id, framed_payload_len)
}
fn encoded_instruction_tuple_len(name: &str, framed_payload_len: usize) -> Option<usize> {
    let flags = instruction_tuple_flags();
    let name_len =
        norito::core::len_prefix_len_with_flags(name.len(), flags).checked_add(name.len())?;
    let payload_vec_len = core::mem::size_of::<u64>().checked_add(framed_payload_len)?;
    tuple_field_len_with_flags(name_len, flags)?
        .checked_add(tuple_field_len_with_flags(payload_vec_len, flags)?)
}
fn tuple_field_len_with_flags(elem_len: usize, flags: u8) -> Option<usize> {
    let prefix_len = norito::core::len_prefix_len_with_flags(elem_len, flags);
    prefix_len.checked_add(elem_len)
}
fn framed_instruction_payload_len_for<T>(payload_len: usize) -> Option<usize> {
    let align = norito::core::archived_payload_align::<T>();
    let padding = if align <= 1 {
        0
    } else {
        let remainder = norito::core::Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    };
    norito::core::Header::SIZE
        .checked_add(padding)?
        .checked_add(payload_len)
}

impl norito::core::SerializePayload for InstructionBox {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let inner = &**self;
        let type_name = Instruction::id(inner);
        let entry =
            instruction_encoding_entry(type_name).ok_or(norito::core::Error::InvalidValue {
                context: "unregistered instruction",
            })?;
        inner.dyn_write_pair(writer, entry.wire_id)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        encoded_instruction_pair_len(self).or_else(|| encoded_instruction_pair_hint(self))
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        encoded_instruction_pair_len(self)
    }
}

impl<'a> norito::core::DeserializePayload<'a> for InstructionBox {
    fn deserialize(archived: &'a norito::core::Archived<InstructionBox>) -> Self {
        const MAX_MESSAGE_LEN: usize = 256;
        let truncate_message = |mut message: String| {
            // Keep the placeholder bounded; it may end up in logs/errors.
            if message.len() > MAX_MESSAGE_LEN {
                message.truncate(MAX_MESSAGE_LEN);
            }
            message
        };
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        if let Ok(bytes) = norito::core::payload_slice_from_ptr(ptr) {
            match decode_instruction_pair_fields_from_slice(bytes) {
                Ok((name, payload, used)) if used == bytes.len() => {
                    return match decode_instruction_from_pair(name, payload) {
                        Ok(inst) => inst,
                        Err(err) => {
                            let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
                            let message = truncate_message(err.to_string());
                            InstructionBox::from(crate::isi::transparent::InvalidInstruction::new(
                                name.to_owned(),
                                hash,
                                message,
                            ))
                        }
                    };
                }
                Ok((name, payload, _used)) => {
                    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
                    let message =
                        truncate_message(instruction_canonical_framing_error().to_string());
                    return InstructionBox::from(crate::isi::transparent::InvalidInstruction::new(
                        name.to_owned(),
                        hash,
                        message,
                    ));
                }
                Err(_) => {}
            }
        }
        let pair: Result<(String, Vec<u8>), norito::core::Error> =
            norito::core::DeserializePayload::try_deserialize(archived.cast());
        match pair {
            Ok((name, bytes)) => match decode_instruction_from_pair(&name, &bytes) {
                Ok(inst) => inst,
                Err(err) => {
                    // Avoid panics on malformed instruction payloads (DoS vector).
                    // Represent the decode error as a sentinel instruction that the executor rejects.
                    let hash: [u8; 32] = iroha_crypto::Hash::new(&bytes).into();
                    let message = truncate_message(err.to_string());
                    InstructionBox::from(crate::isi::transparent::InvalidInstruction::new(
                        name, hash, message,
                    ))
                }
            },
            Err(err) => {
                let message = truncate_message(err.to_string());
                InstructionBox::from(crate::isi::transparent::InvalidInstruction::new(
                    "<norito>", [0u8; 32], message,
                ))
            }
        }
    }
    fn try_deserialize(
        archived: &'a norito::core::Archived<InstructionBox>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        if let Ok(bytes) = norito::core::payload_slice_from_ptr(ptr) {
            match decode_instruction_from_borrowed_pair(bytes) {
                Ok((instruction, used)) if used == bytes.len() => return Ok(instruction),
                Ok((_instruction, _used)) => return Err(instruction_canonical_framing_error()),
                Err(_) => {}
            }
        }
        let (name, bytes): (String, Vec<u8>) =
            norito::core::DeserializePayload::try_deserialize(archived.cast())?;
        decode_instruction_from_pair(&name, &bytes)
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for InstructionBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (inst, used) =
            decode_instruction_from_borrowed_pair(bytes).map_err(|err| match err {
                norito::core::Error::Message(_) => err,
                _ => instruction_canonical_framing_error(),
            })?;
        if used != bytes.len() {
            return Err(instruction_canonical_framing_error());
        }
        norito::core::note_payload_access(bytes, used);
        Ok((inst, used))
    }
}
impl norito::json::FastJsonWrite for InstructionBox {
    fn write_json(&self, out: &mut String) {
        // JSON uses base64 of the canonical Norito-framed payload so clients can
        // round-trip without guessing decode flags.
        norito::json::write_canonical_base64_json(self, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_canonical_base64_json_to(self, out)
    }
}

fn instruction_box_from_base64_literal(
    encoded: &str,
) -> Result<InstructionBox, norito::json::Error> {
    let bytes = STANDARD
        .decode(encoded.as_bytes())
        .map_err(|err| norito::json::Error::Message(err.to_string()))?;
    norito::decode_canonical::<InstructionBox>(&bytes)
        .map_err(|err| norito::json::Error::Message(err.to_string()))
}

fn json_required_string(map: &norito::json::Map, key: &str) -> Result<String, norito::json::Error> {
    map.get(key)
        .and_then(norito::json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| norito::json::Error::Message(format!("instruction `{key}` is required")))
}

fn json_required_bool(map: &norito::json::Map, key: &str) -> Result<bool, norito::json::Error> {
    map.get(key)
        .and_then(norito::json::Value::as_bool)
        .ok_or_else(|| norito::json::Error::Message(format!("instruction `{key}` must be a bool")))
}

fn json_required_u64(map: &norito::json::Map, key: &str) -> Result<u64, norito::json::Error> {
    map.get(key)
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| {
            norito::json::Error::Message(format!("instruction `{key}` must be an unsigned integer"))
        })
}

fn json_required_asset_transfer_availability(
    map: &norito::json::Map,
    key: &str,
) -> Result<crate::asset::AssetTransferAvailability, norito::json::Error> {
    match map.get(key).and_then(norito::json::Value::as_str) {
        Some("Enabled") => Ok(crate::asset::AssetTransferAvailability::Enabled),
        Some("Disabled") => Ok(crate::asset::AssetTransferAvailability::Disabled),
        _ => Err(norito::json::Error::Message(format!(
            "instruction `{key}` must be exactly `Enabled` or `Disabled`"
        ))),
    }
}

fn json_optional_exact_nonblank_string(
    map: &norito::json::Map,
    key: &str,
) -> Result<Option<String>, norito::json::Error> {
    match map.get(key) {
        None | Some(norito::json::Value::Null) => Ok(None),
        Some(norito::json::Value::String(value))
            if !value.is_empty() && value.trim() == value.as_str() =>
        {
            Ok(Some(value.clone()))
        }
        _ => Err(norito::json::Error::Message(format!(
            "instruction `{key}` must be non-empty exact text or null"
        ))),
    }
}

fn json_quantity_opt(
    value: Option<&norito::json::Value>,
    field: &str,
) -> Result<Option<iroha_primitives::numeric::Quantity>, norito::json::Error> {
    use std::str::FromStr as _;
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    if let Some(value) = value.as_u64() {
        return Ok(Some(iroha_primitives::numeric::Quantity::from(value)));
    }
    if let Some(value) = value.as_i64() {
        if value < 0 {
            return Err(norito::json::Error::Message(format!(
                "asset transfer {field} must be non-negative"
            )));
        }
        return Ok(Some(iroha_primitives::numeric::Quantity::from(
            value.cast_unsigned(),
        )));
    }
    if let Some(value) = value.as_str() {
        let parsed = iroha_primitives::numeric::Quantity::from_str(value.trim())
            .map_err(|err| norito::json::Error::Message(err.to_string()))?;
        return Ok(Some(parsed));
    }
    Err(norito::json::Error::Message(format!(
        "asset transfer {field} must be a string, number, or null"
    )))
}

fn json_asset_transfer_target(
    params: &norito::json::Map,
) -> Result<(crate::account::AccountId, crate::asset::AssetDefinitionId), norito::json::Error> {
    use std::str::FromStr as _;
    let account_id = crate::account::AccountId::parse_encoded(
        json_required_string(params, "account_id")?.as_str(),
    )
    .map_err(|err| norito::json::Error::Message(err.to_string()))?;
    let asset_definition_id = crate::asset::AssetDefinitionId::from_str(
        json_required_string(params, "asset_definition_id")?.as_str(),
    )
    .map_err(|err| norito::json::Error::Message(err.to_string()))?;
    Ok((account_id, asset_definition_id))
}

fn instruction_box_from_object(
    map: &norito::json::Map,
) -> Result<InstructionBox, norito::json::Error> {
    use std::str::FromStr as _;
    let name = json_required_string(map, "name")?;
    let params = map
        .get("params")
        .and_then(norito::json::Value::as_object)
        .ok_or_else(|| {
            norito::json::Error::Message("instruction `params` must be an object".to_owned())
        })?;
    match name.as_str() {
        "SetAssetTransferAvailability" => {
            if let Some(unexpected) = params.keys().find(|key| {
                !matches!(
                    key.as_str(),
                    "account_id"
                        | "asset_definition_id"
                        | "expected_revision"
                        | "incoming"
                        | "outgoing"
                        | "reason"
                )
            }) {
                return Err(norito::json::Error::Message(format!(
                    "unsupported SetAssetTransferAvailability field `{unexpected}`"
                )));
            }
            let (account_id, asset_definition_id) = json_asset_transfer_target(params)?;
            Ok(
                crate::isi::asset_transfer_control::SetAssetTransferAvailability::new(
                    account_id,
                    asset_definition_id,
                    json_required_u64(params, "expected_revision")?,
                    json_required_asset_transfer_availability(params, "incoming")?,
                    json_required_asset_transfer_availability(params, "outgoing")?,
                    json_optional_exact_nonblank_string(params, "reason")?,
                )
                .into(),
            )
        }
        "SetAssetHoldingLimit" => {
            let (account_id, asset_definition_id) = json_asset_transfer_target(params)?;
            Ok(
                crate::isi::asset_transfer_control::SetAssetHoldingLimit::new(
                    account_id,
                    asset_definition_id,
                    json_quantity_opt(params.get("holding_limit"), "holding_limit")?,
                )
                .into(),
            )
        }
        "SetAssetTransferBlacklist" => {
            let (account_id, asset_definition_id) = json_asset_transfer_target(params)?;
            Ok(
                crate::isi::asset_transfer_control::SetAssetTransferBlacklist::new(
                    account_id,
                    asset_definition_id,
                    json_required_bool(params, "blacklisted")?,
                )
                .into(),
            )
        }
        "SetAssetTransferControl" => {
            let (account_id, asset_definition_id) = json_asset_transfer_target(params)?;
            let limits = params
                .get("limits")
                .and_then(norito::json::Value::as_array)
                .ok_or_else(|| {
                    norito::json::Error::Message("instruction `limits` must be an array".to_owned())
                })?
                .iter()
                .map(|entry| {
                    let entry = entry.as_object().ok_or_else(|| {
                        norito::json::Error::Message(
                            "each asset transfer limit must be an object".to_owned(),
                        )
                    })?;
                    let window = crate::asset::AssetTransferControlWindow::from_str(
                        json_required_string(entry, "window")?.as_str(),
                    )
                    .map_err(|err| norito::json::Error::Message(err.to_string()))?;
                    Ok(crate::asset::AssetTransferLimit {
                        window,
                        cap_amount: json_quantity_opt(entry.get("cap_amount"), "cap_amount")?,
                    })
                })
                .collect::<Result<Vec<_>, norito::json::Error>>()?;
            Ok(
                crate::isi::asset_transfer_control::SetAssetTransferControl::new(
                    account_id,
                    asset_definition_id,
                    limits,
                )
                .into(),
            )
        }
        other => Err(norito::json::Error::Message(format!(
            "unsupported structured instruction `{other}`"
        ))),
    }
}
impl norito::json::JsonDeserialize for InstructionBox {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        match norito::json::Value::json_deserialize(parser)? {
            norito::json::Value::String(encoded) => instruction_box_from_base64_literal(&encoded),
            norito::json::Value::Object(map) => instruction_box_from_object(&map),
            other => Err(norito::json::Error::Message(format!(
                "instruction JSON must be either a base64 string or an object, found {other:?}"
            ))),
        }
    }
}
impl iroha_schema::TypeId for InstructionBox {
    fn id() -> iroha_schema::Ident {
        std::any::type_name::<Self>().to_owned()
    }
}
/// Decode a wire-framed ISI payload into a typed [`InstructionBox`].
///
/// The `wire_id` must be the canonical stable identifier registered for the instruction. Concrete
/// Rust type names are encoding-side implementation details and are never accepted as decode
/// aliases. The `payload` must be framed with the Norito header as produced by
/// [`frame_instruction_payload`].
///
/// # Errors
/// Returns `norito::Error` if the wire identifier is not registered or payload decoding fails.
pub fn decode_instruction_from_pair(
    wire_id: &str,
    payload: &[u8],
) -> Result<InstructionBox, norito::Error> {
    let entry = {
        let registry = instruction_registry();
        registry.entry_for_wire_id(wire_id).copied()
    };
    if let Some(entry) = entry {
        let header_flags = framed_instruction_payload_header_flags(payload)?;
        return InstructionRegistry::decode_entry(&entry, header_flags, payload);
    }
    Err(norito::Error::Message(
        "unknown instruction wire identifier".to_owned(),
    ))
}
fn framed_instruction_payload_header_flags(payload: &[u8]) -> Result<u8, norito::Error> {
    let flags = *payload
        .get(norito::core::Header::SIZE - 1)
        .ok_or(norito::Error::LengthMismatch)?;
    norito::core::validate_header_flags(flags)?;
    Ok(flags)
}
fn instruction_canonical_framing_error() -> norito::Error {
    norito::Error::Message("instruction payload must use canonical Norito framing".to_owned())
}
fn decode_instruction_pair_fields_from_slice(
    bytes: &[u8],
) -> Result<(&str, &[u8], usize), norito::Error> {
    let flags =
        norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags);
    let (name_field_len, name_hdr) = norito::core::read_len_from_slice_with_flags(bytes, flags)?;
    let name_field_start = name_hdr;
    let name_field_end = name_field_start
        .checked_add(name_field_len)
        .ok_or(norito::Error::LengthMismatch)?;
    let name_field = bytes
        .get(name_field_start..name_field_end)
        .ok_or(norito::Error::LengthMismatch)?;
    let (name_len, inner_name_hdr) =
        norito::core::read_len_from_slice_with_flags(name_field, flags)?;
    let name_start = inner_name_hdr;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(norito::Error::LengthMismatch)?;
    if name_end != name_field.len() {
        return Err(norito::Error::LengthMismatch);
    }
    let name = core::str::from_utf8(
        name_field
            .get(name_start..name_end)
            .ok_or(norito::Error::LengthMismatch)?,
    )
    .map_err(|_| norito::Error::InvalidUtf8)?;
    let payload_field_prefix = bytes
        .get(name_field_end..)
        .ok_or(norito::Error::LengthMismatch)?;
    let (payload_field_len, payload_hdr) =
        norito::core::read_len_from_slice_with_flags(payload_field_prefix, flags)?;
    let payload_field_start = name_field_end
        .checked_add(payload_hdr)
        .ok_or(norito::Error::LengthMismatch)?;
    let payload_field_end = payload_field_start
        .checked_add(payload_field_len)
        .ok_or(norito::Error::LengthMismatch)?;
    let payload_field = bytes
        .get(payload_field_start..payload_field_end)
        .ok_or(norito::Error::LengthMismatch)?;
    let (payload_len, payload_inner_hdr) = norito::core::read_seq_len_slice(payload_field)?;
    let payload_start = payload_inner_hdr;
    let payload_end = payload_start
        .checked_add(payload_len)
        .ok_or(norito::Error::LengthMismatch)?;
    if payload_end != payload_field.len() {
        return Err(norito::Error::LengthMismatch);
    }
    let payload = payload_field
        .get(payload_start..payload_end)
        .ok_or(norito::Error::LengthMismatch)?;
    Ok((name, payload, payload_field_end))
}
fn decode_instruction_from_borrowed_pair(
    bytes: &[u8],
) -> Result<(InstructionBox, usize), norito::Error> {
    let (name, payload, used) = decode_instruction_pair_fields_from_slice(bytes)?;
    let instruction = decode_instruction_from_pair(name, payload)?;
    Ok((instruction, used))
}
/// Frame a bare instruction payload with its Norito header using its canonical wire identifier.
///
/// # Errors
/// Returns `norito::Error` if the wire identifier is not registered or framing fails for the
/// payload. Concrete Rust type names are not accepted as aliases.
pub fn frame_instruction_payload(wire_id: &str, payload: &[u8]) -> Result<Vec<u8>, norito::Error> {
    let entry = {
        let registry = instruction_registry();
        registry.entry_for_wire_id(wire_id).copied()
    };
    if let Some(entry) = entry {
        return (entry.frame)(payload, norito::core::default_encode_flags());
    }
    Err(norito::Error::Message(
        "unknown instruction wire identifier".to_owned(),
    ))
}
impl IntoSchema for InstructionBox {
    fn type_name() -> iroha_schema::Ident {
        "InstructionBox".to_owned()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        map.insert::<Self>(SchemaMetadata::Tuple(UnnamedFieldsMeta { types: vec![] }));
    }
}
/// Function signature used to construct an [`crate::isi::Instruction`] from header-framed bytes.
///
/// The `header_flags` argument carries the frame's declared v1 layout (0 or `COMPACT_LEN`) to the
/// constructor's decode guard.
pub type InstructionConstructor = fn(u8, &[u8]) -> Result<InstructionBox, norito::Error>;
/// Registry mapping concrete Rust type names for encoding and stable wire identifiers for decoding.
#[derive(Default, Clone)]
pub struct InstructionRegistry {
    /// Encoding-side lookup keyed only by the concrete Rust `type_name`.
    entries: HashMap<&'static str, RegistryEntry>,
    /// Decoding-side lookup keyed only by the canonical wire identifier.
    wire_entries: HashMap<&'static str, RegistryEntry>,
}
/// Borrowed wire identity and frame geometry; constructing this record owns no registry.
#[derive(Clone, Copy)]
struct InstructionEncodingEntry {
    wire_id: &'static str,
    frame_len: fn(usize) -> Option<usize>,
}
impl From<RegistryEntry> for InstructionEncodingEntry {
    fn from(entry: RegistryEntry) -> Self {
        Self {
            wire_id: entry.wire_id,
            frame_len: entry.frame_len,
        }
    }
}

#[derive(Clone, Copy)]
struct RegistryEntry {
    type_name: &'static str,
    ctor: InstructionConstructor,
    wire_id: &'static str,
    frame: fn(&[u8], u8) -> Result<Vec<u8>, norito::core::Error>,
    frame_len: fn(usize) -> Option<usize>,
}
impl InstructionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }
    /// Register an [`crate::isi::Instruction`] with an explicit, path-independent wire identifier.
    ///
    /// The concrete Rust [`std::any::type_name`] is retained only as the encoding-side key;
    /// decoders accept only `wire_id`.
    #[must_use]
    pub fn register_with_id<T>(mut self, wire_id: &'static str) -> Self
    where
        T: Instruction + Decode + 'static + norito::NoritoSerialize,
        for<'a> T: norito::NoritoDeserialize<'a>,
    {
        fn ctor<T>(header_flags: u8, input: &[u8]) -> Result<InstructionBox, norito::Error>
        where
            T: Instruction + Decode + 'static + norito::NoritoSerialize,
            for<'a> T: norito::NoritoDeserialize<'a>,
        {
            decode_instruction_payload::<T>(input, header_flags)
        }
        fn frame<T>(payload: &[u8], header_flags: u8) -> Result<Vec<u8>, norito::core::Error>
        where
            T: Instruction
                + Decode
                + 'static
                + norito::NoritoSerialize
                + for<'a> norito::NoritoDeserialize<'a>,
        {
            norito::core::frame_bare_with_header_flags::<T>(payload, header_flags)
        }
        fn frame_len<T>(payload_len: usize) -> Option<usize>
        where
            T: Instruction
                + Decode
                + 'static
                + norito::NoritoSerialize
                + for<'a> norito::NoritoDeserialize<'a>,
        {
            framed_instruction_payload_len_for::<T>(payload_len)
        }
        let name = std::any::type_name::<T>();
        let entry = RegistryEntry {
            type_name: name,
            ctor: ctor::<T>,
            wire_id,
            frame: frame::<T>,
            frame_len: frame_len::<T>,
        };
        self.insert_entry(entry);
        self
    }
    /// Register an [`crate::isi::Instruction`] with an explicit wire identifier
    /// and the direct slice decoder.
    ///
    /// This is intentionally opt-in because not every built-in instruction has a
    /// slice-safe decoder for all of its nested fields yet.
    #[must_use]
    pub(crate) fn register_with_id_slice<T>(mut self, wire_id: &'static str) -> Self
    where
        T: Instruction + Decode + 'static + norito::NoritoSerialize,
        for<'a> T: norito::NoritoDeserialize<'a> + norito::core::DecodeFromSlice<'a>,
    {
        fn ctor<T>(header_flags: u8, input: &[u8]) -> Result<InstructionBox, norito::Error>
        where
            T: Instruction + Decode + 'static + norito::NoritoSerialize,
            for<'a> T: norito::NoritoDeserialize<'a> + norito::core::DecodeFromSlice<'a>,
        {
            decode_instruction_payload_from_slice::<T>(input, header_flags)
        }
        fn frame<T>(payload: &[u8], header_flags: u8) -> Result<Vec<u8>, norito::core::Error>
        where
            T: Instruction
                + Decode
                + 'static
                + norito::NoritoSerialize
                + for<'a> norito::NoritoDeserialize<'a>,
        {
            norito::core::frame_bare_with_header_flags::<T>(payload, header_flags)
        }
        fn frame_len<T>(payload_len: usize) -> Option<usize>
        where
            T: Instruction
                + Decode
                + 'static
                + norito::NoritoSerialize
                + for<'a> norito::NoritoDeserialize<'a>,
        {
            framed_instruction_payload_len_for::<T>(payload_len)
        }
        let name = std::any::type_name::<T>();
        let entry = RegistryEntry {
            type_name: name,
            ctor: ctor::<T>,
            wire_id,
            frame: frame::<T>,
            frame_len: frame_len::<T>,
        };
        self.insert_entry(entry);
        self
    }
    /// Decode an [`crate::isi::Instruction`] using its canonical wire identifier.
    pub fn decode(
        &self,
        wire_id: &str,
        bytes: &[u8],
    ) -> Option<Result<InstructionBox, norito::Error>> {
        self.entry_for_wire_id(wire_id).map(|entry| {
            let header_flags = framed_instruction_payload_header_flags(bytes)?;
            Self::decode_entry(entry, header_flags, bytes)
        })
    }
    /// Decode an [`crate::isi::Instruction`] providing explicit Norito layout flags.
    ///
    /// The `header_flags` argument mirrors the values produced by
    /// [`norito::codec::encode_with_header_flags`] and selects the payload layout explicitly.
    pub fn decode_with_flags(
        &self,
        wire_id: &str,
        header_flags: u8,
        bytes: &[u8],
    ) -> Option<Result<InstructionBox, norito::Error>> {
        self.entry_for_wire_id(wire_id)
            .map(|entry| Self::decode_entry(entry, header_flags, bytes))
    }
    /// Number of registered instruction types.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether the registry holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Iterator over registered type names.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.entries.keys().copied()
    }
    /// Check whether the registry can decode the canonical wire identifier.
    pub fn contains(&self, wire_id: &str) -> bool {
        self.entry_for_wire_id(wire_id).is_some()
    }
    /// Return the stable wire identifier for the given type name, if registered.
    pub fn wire_id(&self, type_name: &str) -> Option<&'static str> {
        self.entries.get(type_name).map(|entry| entry.wire_id)
    }
    fn insert_entry(&mut self, entry: RegistryEntry) {
        let collision = entry.type_name == entry.wire_id
            || self.entries.contains_key(entry.type_name)
            || self.entries.contains_key(entry.wire_id)
            || self.wire_entries.contains_key(entry.type_name)
            || self.wire_entries.contains_key(entry.wire_id);
        assert!(
            !collision,
            "instruction registry key collision for type `{}` and wire identifier `{}`",
            entry.type_name, entry.wire_id
        );
        self.entries.insert(entry.type_name, entry);
        self.wire_entries.insert(entry.wire_id, entry);
    }
    fn entry_for_type_name(&self, type_name: &'static str) -> Option<RegistryEntry> {
        self.entries.get(type_name).copied()
    }
    fn entry_for_wire_id(&self, wire_id: &str) -> Option<&RegistryEntry> {
        self.wire_entries.get(wire_id)
    }
    fn decode_entry(
        entry: &RegistryEntry,
        header_flags: u8,
        bytes: &[u8],
    ) -> Result<InstructionBox, norito::Error> {
        (entry.ctor)(header_flags, bytes)
    }
}
fn decode_instruction_payload<T>(
    input: &[u8],
    header_flags: u8,
) -> Result<InstructionBox, norito::Error>
where
    T: Instruction + Decode + 'static + norito::NoritoSerialize,
    for<'a> T: norito::NoritoDeserialize<'a>,
{
    let _guard = norito::core::DecodeFlagsGuard::enter(header_flags);
    let instruction = norito::decode_from_bytes::<T>(input)?;
    Ok(InstructionBox(Box::new(instruction)))
}
fn decode_instruction_payload_from_slice<T>(
    input: &[u8],
    header_flags: u8,
) -> Result<InstructionBox, norito::Error>
where
    T: Instruction + Decode + 'static + norito::NoritoSerialize,
    for<'a> T: norito::NoritoDeserialize<'a> + norito::core::DecodeFromSlice<'a>,
{
    let _guard = norito::core::DecodeFlagsGuard::enter(header_flags);
    let instruction = norito::core::from_bytes_view(input)?.decode::<T>()?;
    Ok(InstructionBox(Box::new(instruction)))
}
pub(crate) fn read_aos_field<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    flags: u8,
) -> Result<&'a [u8], norito::core::Error> {
    let remaining = bytes
        .get(*offset..)
        .ok_or(norito::core::Error::LengthMismatch)?;
    let (field_len, hdr) = norito::core::read_len_from_slice_with_flags(remaining, flags)?;
    let field_start = (*offset)
        .checked_add(hdr)
        .ok_or(norito::core::Error::LengthMismatch)?;
    let field_end = field_start
        .checked_add(field_len)
        .ok_or(norito::core::Error::LengthMismatch)?;
    let field = bytes
        .get(field_start..field_end)
        .ok_or(norito::core::Error::LengthMismatch)?;
    *offset = field_end;
    Ok(field)
}
pub(crate) fn decode_aos_canonical_field<T>(
    field: &[u8],
    flags: u8,
) -> Result<T, norito::core::Error>
where
    T: for<'de> norito::core::DeserializePayload<'de> + norito::core::SerializePayload,
{
    let _guard = norito::core::DecodeFlagsGuard::enter(flags);
    let (value, used) = norito::core::decode_field_canonical::<T>(field)?;
    if used != field.len() {
        return Err(norito::core::Error::LengthMismatch);
    }
    Ok(value)
}
pub(crate) fn decode_aos_slice_field<T>(field: &[u8], flags: u8) -> Result<T, norito::core::Error>
where
    T: for<'de> norito::core::DeserializePayload<'de> + for<'de> norito::core::DecodeFromSlice<'de>,
{
    let _guard = norito::core::DecodeFlagsGuard::enter(flags);
    let (value, used) = norito::core::decode_field_canonical_from_slice::<T>(field)?;
    if used != field.len() {
        return Err(norito::core::Error::LengthMismatch);
    }
    Ok(value)
}
/// Build an [`InstructionRegistry`] registering each type with its annotated stable
/// wire identifier by reading its `WIRE_ID` associated constant.
#[macro_export]
macro_rules! instruction_registry_with_ids {
    ($($ty:ty),* $(,)?) => {{
        let mut registry = $crate::isi::InstructionRegistry::new();
        $(
            registry = registry.register_with_id::<$ty>(<$ty>::WIRE_ID);
        )*
        registry
    }};
}
static INSTRUCTION_REGISTRY: OnceLock<RwLock<Arc<InstructionRegistry>>> = OnceLock::new();
#[cfg(test)]
thread_local! {
    static INSTRUCTION_REGISTRY_OVERRIDE: RefCell<Option<Arc<InstructionRegistry>>> =
        const { RefCell::new(None) };
}
/// Set global [`InstructionRegistry`] used for deserializing [`crate::isi::InstructionBox`].
///
/// The supplied registry replaces an earlier registry even when decoder initialization races
/// with this call. Test builds retain their independent thread-local override.
pub fn set_instruction_registry(registry: InstructionRegistry) {
    let registry = Arc::new(registry);
    #[cfg(test)]
    {
        INSTRUCTION_REGISTRY_OVERRIDE.with(|cell| {
            *cell.borrow_mut() = Some(Arc::clone(&registry));
        });
    }
    #[cfg(not(test))]
    registry_install::install(&INSTRUCTION_REGISTRY, registry);
}
enum InstructionRegistryReadGuard {
    Global(std::sync::RwLockReadGuard<'static, Arc<InstructionRegistry>>),
    #[cfg(test)]
    Local(Arc<InstructionRegistry>),
}
impl std::ops::Deref for InstructionRegistryReadGuard {
    type Target = InstructionRegistry;
    fn deref(&self) -> &InstructionRegistry {
        match self {
            Self::Global(registry) => {
                let registry: &Arc<InstructionRegistry> = registry;
                registry.as_ref()
            }
            #[cfg(test)]
            Self::Local(registry) => registry.as_ref(),
        }
    }
}
// Installed registries are authoritative, including an intentionally missing entry.
// Only an uninstalled cold registry uses the sole static built-in inventory.
fn instruction_encoding_entry(type_name: &'static str) -> Option<InstructionEncodingEntry> {
    #[cfg(test)]
    if let Some(local) = INSTRUCTION_REGISTRY_OVERRIDE.with(|cell| {
        cell.borrow().as_ref().map(|registry| {
            registry
                .entry_for_type_name(type_name)
                .map(InstructionEncodingEntry::from)
        })
    }) {
        return local;
    }
    if let Some(lock) = INSTRUCTION_REGISTRY.get() {
        let registry = lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        return registry
            .entry_for_type_name(type_name)
            .map(InstructionEncodingEntry::from);
    }
    registry::default_encoding_entry(type_name)
}

fn instruction_registry() -> InstructionRegistryReadGuard {
    #[cfg(test)]
    if let Some(local) = INSTRUCTION_REGISTRY_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return InstructionRegistryReadGuard::Local(local);
    }
    // Lazily initialize with the built-in default registry if not explicitly set.
    // This makes binaries and tools robust even if they forgot to call an
    // explicit initializer before deserializing InstructionBox values (e.g., while reading genesis).
    let registry = INSTRUCTION_REGISTRY
        .get_or_init(|| RwLock::new(Arc::new(crate::instruction_registry::default())))
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    InstructionRegistryReadGuard::Global(registry)
}
macro_rules! isi {
    ($(#[$meta:meta])* pub struct $name:ident $($rest:tt)*) => {
        iroha_data_model_derive::model_single! {
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
            #[derive(getset::Getters)]
            #[derive(Decode, Encode, norito::NoritoSchema)]
            #[derive(iroha_schema::IntoSchema)]
            #[getset(get = "pub")]
            $(#[$meta])*
            pub struct $name $($rest)*
        }
    };
}
pub(crate) use isi;
macro_rules! impl_display {
    (
        $ty:ident $(< $($generic:tt),+ >)?
        $(where
            $( $lt:path $( : $clt:tt $(< $inner_generic:tt >)? $(+ $dlt:tt )* )? ),+ $(,)? )?
        => $fmt:literal, $($args:ident),* $(,)?
    ) => {
        impl $(< $($generic),+ >)? ::core::fmt::Display for $ty $(< $($generic),+ >)?
        $(where
            $( $lt $( : $clt $(< $inner_generic >)? $(+ $dlt )* )? ),+)? {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, $fmt, $(self.$args),*)
            }
        }
    }
}
macro_rules! impl_into_box {
    ( $($isi:ty)|* => $middle:ty ) => {
        impl From<$middle> for InstructionBox {
            fn from(instruction: $middle) -> Self {
                InstructionBox(Box::new(instruction))
            }
        }
        $(impl From<$isi> for InstructionBox {
            fn from(instruction: $isi) -> Self {
                InstructionBox::from(<$middle>::from(instruction))
            }
        })*
    };
}
macro_rules! isi_box {
    ($($meta:meta)* $item:item) => {
        #[derive(norito::NoritoSchema)]
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Display,
            Decode,
            Encode,
            iroha_schema::IntoSchema,
            derive_more::From,
        )]
        $($meta)*
        $item
    };
}
macro_rules! enum_type {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $( $(#[$variant_meta:meta])* $variant:ident ),+ $(,)? }) => {
        #[derive(norito::NoritoSchema)]
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
        )]
        $(#[$meta])*
        #[doc = concat!("Enum type `", stringify!($name), "` generated via `enum_type!`.")]
        #[repr(u8)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                #[doc = concat!("Variant `", stringify!($variant), "` of `", stringify!($name), "`.")]
                $variant
            ),+
        }
        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(match self {
                    $( Self::$variant => stringify!($variant), )+
                })
            }
        }
        impl ::core::convert::TryFrom<u8> for $name {
            type Error = ();
            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $( x if x == Self::$variant as u8 => Ok(Self::$variant), )+
                    _ => Err(()),
                }
            }
        }

        impl norito::json::FastJsonWrite for $name {
            fn write_json(&self, out: &mut String) {
                out.push('"');
                out.push_str(match self {
                    $( Self::$variant => stringify!($variant), )+
                });
                out.push('"');
            }
            fn write_json_to(
                &self,
                out: &mut dyn norito::json::JsonWriteSink,
            ) -> Result<(), norito::json::BoundedJsonError> {
                norito::json::write_json_string_to(match self {
                    $( Self::$variant => stringify!($variant), )+
                }, out)
            }
        }

        impl norito::json::JsonDeserialize for $name {
            fn json_deserialize(
                parser: &mut norito::json::Parser<'_>,
            ) -> Result<Self, norito::json::Error> {
                let value = parser.parse_string()?;
                match value.as_str() {
                    $( stringify!($variant) => Ok(Self::$variant), )+
                    other => Err(norito::json::Error::UnknownField {
                        field: other.to_owned(),
                    }),
                }
            }
        }
    };
}
/// Native account controller replacement and social recovery instructions.
pub mod account_recovery;
/// Declarative alias setup and explicit alias lifecycle instructions.
pub mod alias_setup;
/// Asset-definition alias binding instructions.
pub mod asset_alias;
/// Asset-scoped outbound transfer control instructions.
pub mod asset_transfer_control;
/// Confidential registry management instructions. Bridge proof ingestion instructions.
pub mod bridge;
/// Confidential registry management instructions.
pub mod confidential;
/// Content lane instructions.
pub mod content;
/// Contract alias binding instructions.
pub mod contract_alias;
/// DeFi-native instructions.
pub mod defi;
/// Ledger-managed asset escrow instructions.
pub mod escrow;
/// Hidden-function-backed identifier policy instructions.
pub mod identifier;
/// Clean-slate pooled-reserve KAGEMUSHA V1 instructions and operation records.
pub mod kagemusha_v1;
/// Kaigi collaboration instructions.
pub mod kaigi;
/// Mint and burn instruction variants and helpers.
pub mod mint_burn;
/// Musubi package registry instructions.
pub mod musubi;
/// Nexus lane governance instructions.
pub mod nexus;
/// Oracle feed registration and aggregation instructions.
pub mod oracle;
/// First-release privacy governance and proof-admission instructions.
pub mod privacy;
pub mod private_dataspace;
/// Atomic private cross-dataspace settlement carrier instructions.
pub mod private_settlement;
/// Generic RAM-LFE program-policy instructions.
pub mod ram_lfe;
/// Registration-related instructions (accounts, assets, domains, etc.).
pub mod register;
/// Instruction registries shared across instruction families.
pub mod registry;
mod registry_install;
/// Repo settlement instructions.
pub mod repo;
pub mod retail_daily_limit;
/// Runtime upgrade instructions and payloads.
pub mod runtime_upgrade;
/// Real-world asset lot instructions.
pub mod rwa;
/// SCCP v1 cross-chain instructions (`specs/sccp.md` §4).
pub mod sccp;
/// DvP/PvP settlement instructions.
pub mod settlement;
/// Smart contract code management instructions.
pub mod smart_contract_code;
/// Viral incentive and social reward instructions.
pub mod social;
/// Soracloud lifecycle and runtime-state instructions.
pub mod soracloud;
/// `SoraDNS` attestation and directory instructions.
pub mod soradns;
/// `SoraFS` pin registry instructions.
pub mod sorafs;
/// Space Directory manifest instructions.
pub mod space_directory;
/// Public lane staking instructions.
pub mod staking;
/// AMX two-phase-commit instructions of the global chain.
pub mod sumeragi_amx;
/// Asset, account, and value transfer instructions.
pub mod transfer;
mod transparent;
/// Verifying-key management instructions.
pub mod verifying_keys;
/// `SoraNet` VPN lease escrow instructions.
pub mod vpn;
/// Zero-knowledge instruction wrappers.
pub mod zk;
pub use account_recovery::*;
pub use asset_alias::*;
pub use asset_transfer_control::*;
pub use confidential::*;
pub use contract_alias::*;
pub use defi::*;
pub use identifier::*;
pub use kagemusha_v1::*;
pub use kaigi::*;
pub use ministry::*;
pub use mint_burn::*;
pub use nexus::*;
pub use oracle::*;
pub use privacy::*;
pub use ram_lfe::*;
pub use register::*;
pub use repo::*;
pub use settlement::*;
pub use soradns::*;
pub use sorafs::*;
pub use space_directory::*;
pub use staking::*;
pub use transfer::*;
pub use transparent::*;
pub use vpn::*;
/// Generic game session lifecycle instructions.
pub mod game;
/// Generic native NFT sales.
pub mod nft_market;
pub use game::*;
pub use zk::*;
isi_box! {
    /// Enum with all supported [`SetKeyValue`] instructions.
    ///
    /// Dev note: despite the "Box" suffix, this is an enum (tagged union),
    /// not a heap allocation. It groups related `SetKeyValue<T>` variants
    /// into a single visitable type that implements [`crate::isi::Instruction`].
    #[norito_schema(name = "iroha_data_model::isi::SetKeyValueBox")]
    pub enum SetKeyValueBox {
        /// Set key value for [`Domain`].
        Domain(SetKeyValue<Domain>),
        /// Set key value for [`Account`].
        Account(SetKeyValue<Account>),
        /// Set key value for [`AssetDefinition`].
        AssetDefinition(SetKeyValue<AssetDefinition>),
        /// Set key value for [`Nft`].
        Nft(SetKeyValue<Nft>),
        /// Set key value for [`Trigger`].
        Trigger(SetKeyValue<Trigger>),
    }
}
impl SetKeyValueBox {
    /// Norito wire identifier for `SetKeyValueBox` payload framing.
    pub const WIRE_ID: &'static str = "iroha.set_key_value";
}
enum_type! {
    /// Type discriminator for [`SetKeyValueBox`] variants.
    #[norito_schema(name = "iroha_data_model::isi::SetKeyValueType")]
    pub(crate) enum SetKeyValueType {
        Domain,
        Account,
        AssetDefinition,
        Nft,
        Trigger,
    }
}
isi_box! {
    /// Enum with all supported [`RemoveKeyValue`] instructions.
    ///
    /// Dev note: "Box" here means a boxed-up family of variants, not heap allocation.
    #[norito_schema(name = "iroha_data_model::isi::RemoveKeyValueBox")]
    pub enum RemoveKeyValueBox {
        /// Remove key value from [`Domain`].
        Domain(RemoveKeyValue<Domain>),
        /// Remove key value from [`Account`].
        Account(RemoveKeyValue<Account>),
        /// Remove key value from [`AssetDefinition`].
        AssetDefinition(RemoveKeyValue<AssetDefinition>),
        /// Remove key value from [`Nft`].
        Nft(RemoveKeyValue<Nft>),
        /// Remove key value for [`Trigger`].
        Trigger(RemoveKeyValue<Trigger>),
    }
}
impl RemoveKeyValueBox {
    /// Norito wire identifier for `RemoveKeyValueBox` payload framing.
    pub const WIRE_ID: &'static str = "iroha.remove_key_value";
}
enum_type! {
    /// Type discriminator for [`RemoveKeyValueBox`] variants.
    #[norito_schema(name = "iroha_data_model::isi::RemoveKeyValueType")]
    pub(crate) enum RemoveKeyValueType {
        Domain,
        Account,
        AssetDefinition,
        Nft,
        Trigger,
    }
}
isi_box! {
    /// Enum with all supported [`Grant`] instructions.
    ///
    /// Dev note: this enum aggregates concrete `Grant<_, _>` variants into
    /// one type for visiting and serialization; it is not a heap `Box`.
    #[norito_schema(name = "iroha_data_model::isi::GrantBox")]
    pub enum GrantBox {
        /// Grant [`Permission`] to [`Account`].
        Permission(Grant<Permission, Account>),
        /// Grant [`Role`] to [`Account`].
        Role(Grant<RoleId, Account>),
        /// Grant [`Permission`] to [`Role`].
        RolePermission(Grant<Permission, Role>),
    }
}
impl GrantBox {
    /// Norito wire identifier for `GrantBox` payload framing.
    pub const WIRE_ID: &'static str = "iroha.grant";
}
enum_type! {
    /// Type discriminator for [`GrantBox`] variants.
    #[norito_schema(name = "iroha_data_model::isi::GrantType")]
    pub(crate) enum GrantType {
        Permission,
        Role,
        RolePermission,
    }
}
isi_box! {
    /// Enum with all supported [`Revoke`] instructions.
    ///
    /// Dev note: this is a tagged union of concrete `Revoke<_, _>` variants,
    /// not a heap allocation.
    #[norito_schema(name = "iroha_data_model::isi::RevokeBox")]
    pub enum RevokeBox {
        /// Revoke [`Permission`] from [`Account`].
        Permission(Revoke<Permission, Account>),
        /// Revoke [`Role`] from [`Account`].
        Role(Revoke<RoleId, Account>),
        /// Revoke [`Permission`] from [`Role`].
        RolePermission(Revoke<Permission, Role>),
    }
}
impl RevokeBox {
    /// Norito wire identifier for `RevokeBox` payload framing.
    pub const WIRE_ID: &'static str = "iroha.revoke";
}
enum_type! {
    /// Type discriminator for [`RevokeBox`] variants.
    #[norito_schema(name = "iroha_data_model::isi::RevokeType")]
    pub(crate) enum RevokeType {
        /// Revoke [`Permission`] from an [`Account`].
        Permission,
        /// Revoke a [`Role`] from an [`Account`].
        Role,
        /// Revoke a [`Permission`] from a [`Role`].
        RolePermission,
    }
}
enum_type! {
    /// All built-in instruction kinds supported by the data model.
    #[norito_schema(name = "iroha_data_model::isi::InstructionType")]
    pub enum InstructionType {
        /// Modify a system parameter.
        SetParameter,
        /// Insert or update a key-value pair in metadata.
        SetKeyValue,
        /// Remove a metadata key-value pair.
        RemoveKeyValue,
        /// Add a new entity to the ledger.
        Register,
        /// Remove an entity from the ledger.
        Unregister,
        /// Increase a numeric asset quantity.
        Mint,
        /// Decrease a numeric asset quantity.
        Burn,
        /// Move value or ownership between accounts.
        Transfer,
        /// Grant a permission or role.
        Grant,
        /// Revoke a permission or role.
        Revoke,
        /// Activate a runtime upgrade proposal.
        Upgrade,
        /// Execute a registered trigger.
        ExecuteTrigger,
        /// Emit a log entry.
        Log,
        /// Execute a custom instruction.
        Custom,
    }
}
pub mod error {
    //! Module containing errors that can occur during instruction evaluation
    pub use self::model::*;
    use crate::{
        IdBox,
        isi::InstructionType,
        prelude::NumericSpec,
        query::error::{FindError, QueryExecutionFail},
    };
    use derive_more::Display;
    use iroha_data_model_derive::model;
    use iroha_schema::IntoSchema;
    use norito::codec::{Decode, Encode};
    use std::{boxed::Box, fmt::Debug, format, string::String, vec::Vec};
    #[model]
    mod model {
        use super::*;
        use getset::Getters;
        /// Instruction execution error type
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            derive_more::From,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub enum InstructionExecutionError {
            /// Instruction does not adhere to Iroha DSL specification
            Evaluate(#[source] InstructionEvaluationError),
            /// Query failed
            Query(#[source] QueryExecutionFail),
            /// Conversion Error: {0}
            Conversion(String),
            /// Entity missing
            Find(#[source] FindError),
            /// Repeated instruction
            Repetition(#[source] RepetitionError),
            /// Mintability assertion failed
            Mintability(#[source] MintabilityError),
            /// Illegal math operation
            Math(#[source] MathError),
            /// Invalid instruction parameter
            InvalidParameter(#[source] InvalidParameterError),
            /// Account admission rejected
            AccountAdmission(#[source] AccountAdmissionError),
            /// Asset transfer admission rejected
            AssetTransferAdmission(#[source] AssetTransferAdmissionError),
            /// Iroha invariant violation: {0}
            ///
            /// i.e. you can't burn last key
            InvariantViolation(Box<str>),
        }
        /// Typed asset-transfer policy failure.
        ///
        /// The variant is the stable machine classification. Human-readable detail is deliberately
        /// carried separately so receipt codes never depend on matching display text.
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[derive(thiserror::Error)]
        pub enum AssetTransferAdmissionError {
            /// `HoldingLimitExceeded`: {0}
            HoldingLimitExceeded(Box<str>),
            /// Incoming asset movement is disabled: {0}
            IncomingDisabled(Box<str>),
            /// Outgoing asset movement is disabled: {0}
            OutgoingDisabled(Box<str>),
            /// Availability revision did not match: {0}
            AvailabilityRevisionMismatch(Box<str>),
            /// Account is blacklisted for outbound transfer: {0}
            Blacklisted(Box<str>),
            /// Transfer policy rejected the operation: {0}
            PolicyRejected(Box<str>),
        }
        /// Quota scope used by [`AccountAdmissionError::QuotaExceeded`].
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[derive(thiserror::Error)]
        pub enum AccountAdmissionQuotaScope {
            /// Transaction-scoped quota.
            Transaction,
            /// Block-scoped quota.
            Block,
        }
        /// Errors raised while admitting implicit accounts under domain/chain policies.
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub enum AccountAdmissionError {
            /// Implicit account creation is disabled.
            ImplicitAccountCreationDisabled,
            /// Account admission policy is invalid: {0}.
            InvalidPolicy(AccountAdmissionInvalidPolicy),
            /// Failed to assign the configured default role: {0}.
            DefaultRoleError(AccountAdmissionDefaultRoleError),
            /// Implicit account creation quota exceeded: {0}.
            QuotaExceeded(AccountAdmissionQuotaExceeded),
            /// Signing algorithm {0} is not permitted for implicit account creation.
            AlgorithmNotAllowed(iroha_crypto::Algorithm),
            /// Implicit account creation in the genesis domain is not permitted.
            GenesisDomainForbidden,
            /// Fee required for implicit account creation could not be paid.
            FeeUnsatisfied(AccountAdmissionFeeUnsatisfied),
            /// Receipt amount is below the minimum required to create an account implicitly.
            MinInitialAmountUnsatisfied(AccountAdmissionMinInitialAmountUnsatisfied),
        }
        /// Account admission policy payload is invalid: {reason}.
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub struct AccountAdmissionInvalidPolicy {
            /// Human-readable reason describing the invalid payload.
            pub reason: String,
        }
        /// Default role assignment failed for `{role}`: {reason}.
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub struct AccountAdmissionDefaultRoleError {
            /// Role that could not be assigned.
            pub role: crate::role::RoleId,
            /// Reason for the failure.
            pub reason: String,
        }
        /// Implicit account creation quota exceeded for {scope} (created {created}, cap {cap}).
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub struct AccountAdmissionQuotaExceeded {
            /// Scope of the quota that was exceeded.
            pub scope: AccountAdmissionQuotaScope,
            /// Number of implicit accounts created so far within the scope.
            pub created: u32,
            /// Allowed cap for implicit accounts within the scope.
            pub cap: u32,
        }
        /// Implicit account creation fee could not be paid for `{asset_definition}` (required `{required}`, available `{available}`).
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub struct AccountAdmissionFeeUnsatisfied {
            /// Asset definition used to charge the fee.
            pub asset_definition: crate::asset::AssetDefinitionId,
            /// Fee required to create the account implicitly.
            pub required: iroha_primitives::numeric::Quantity,
            /// Amount available in the payer account.
            pub available: iroha_primitives::numeric::Quantity,
        }
        /// Minimum initial amount requirement is not satisfied for `{asset_definition}` (required {required}, provided {provided}).
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub struct AccountAdmissionMinInitialAmountUnsatisfied {
            /// Asset definition subject to the minimum requirement.
            pub asset_definition: crate::asset::AssetDefinitionId,
            /// Amount required by policy.
            pub required: iroha_primitives::numeric::Quantity,
            /// Amount supplied by the receipt operation.
            pub provided: iroha_primitives::numeric::Quantity,
        }
        /// Evaluation error. This error indicates instruction is not a valid Iroha DSL
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            derive_more::From,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[derive(thiserror::Error)]
        pub enum InstructionEvaluationError {
            /// Unsupported parameter type for instruction of type `{0}`
            Unsupported(InstructionType),
            /// Failed to find parameter in a permission: {0}
            PermissionParameter(String),
            /// Incorrect value type
            Type(#[source] TypeError),
        }
        /// Generic structure used to represent a mismatch
        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            thiserror::Error,
        )]
        #[display("Expected {expected:?}, actual {actual:?}")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_data_model::isi::error::model::Mismatch")]
        pub struct Mismatch<T>
        where
            T: Debug,
        {
            /// The value that is needed for normal execution
            pub expected: T,
            /// The value that caused the error
            pub actual: T,
        }

        impl<T> norito::json::JsonSerialize for Mismatch<T>
        where
            T: norito::json::JsonSerialize + Debug,
        {
            fn json_serialize(&self, out: &mut String) {
                out.push('{');
                norito::json::write_json_string("expected", out);
                out.push(':');
                self.expected.json_serialize(out);
                out.push(',');
                norito::json::write_json_string("actual", out);
                out.push(':');
                self.actual.json_serialize(out);
                out.push('}');
            }
            fn json_serialize_to(
                &self,
                out: &mut dyn norito::json::JsonWriteSink,
            ) -> Result<(), norito::json::BoundedJsonError> {
                out.begin_container()?;
                let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                    out.push_str("{\"expected\":")?;
                    self.expected.json_serialize_to(out)?;
                    out.push_str(",\"actual\":")?;
                    self.actual.json_serialize_to(out)?;
                    out.push('}')?;
                    Ok(())
                })();
                out.end_container();
                result?;
                Ok(())
            }
        }

        impl<T> norito::json::JsonDeserialize for Mismatch<T>
        where
            T: norito::json::JsonDeserialize + Debug,
        {
            fn json_deserialize(
                parser: &mut norito::json::Parser<'_>,
            ) -> Result<Self, norito::json::Error> {
                use norito::json::MapVisitor;
                let mut visitor = MapVisitor::new(parser)?;
                let mut expected: Option<T> = None;
                let mut actual: Option<T> = None;
                while let Some(key) = visitor.next_key()? {
                    match key.as_str() {
                        "expected" => {
                            if expected.is_some() {
                                return Err(norito::json::Error::duplicate_field("expected"));
                            }
                            expected = Some(visitor.parse_value::<T>()?);
                        }
                        "actual" => {
                            if actual.is_some() {
                                return Err(norito::json::Error::duplicate_field("actual"));
                            }
                            actual = Some(visitor.parse_value::<T>()?);
                        }
                        other => {
                            visitor.skip_value()?;
                            return Err(norito::json::Error::unknown_field(other));
                        }
                    }
                }
                visitor.finish()?;
                let expected =
                    expected.ok_or_else(|| norito::json::Error::missing_field("expected"))?;
                let actual = actual.ok_or_else(|| norito::json::Error::missing_field("actual"))?;
                Ok(Self { expected, actual })
            }
        }
        /// Type error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            derive_more::From,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[derive(thiserror::Error)]
        pub enum TypeError {
            /// Asset definition numeric spec mismatch (asset can't hold provided numeric value)
            AssetNumericSpec(#[source] Mismatch<NumericSpec>),
        }
        /// Math error, which occurs during instruction execution
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            derive_more::From,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        pub enum MathError {
            /// Overflow error occurred inside instruction
            Overflow,
            /// Not enough quantity to transfer/burn
            NotEnoughQuantity,
            /// Divide by zero
            DivideByZero,
            /// Negative value encountered
            NegativeValue,
            /// Domain violation
            DomainViolation,
            /// Unknown error
            ///
            /// No actual function should ever return this if possible
            Unknown,
            /// Conversion failed: {0}
            FixedPointConversion(String),
        }
        /// Mintability logic error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[derive(thiserror::Error)]
        #[repr(u8)]
        pub enum MintabilityError {
            /// This asset cannot be minted more than once and it was already minted
            MintUnmintable,
            /// This asset was set as infinitely mintable. You cannot forbid its minting
            ForbidMintOnMintable,
            /// Limited mintability token count `{0}` is invalid
            InvalidMintabilityTokens(u32),
        }
        /// Invalid instruction parameter error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "kind", content = "content")]
        #[ignore_extra_doc_attributes]
        #[derive(thiserror::Error)]
        #[repr(u8)]
        pub enum InvalidParameterError {
            /// Invalid smart contract: {0}
            SmartContract(String),
            /// Attempt to register a time-trigger with `start` point in the past
            TimeTriggerInThePast,
        }
        /// Repetition of `{instruction}` for id `{id}`
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Getters,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
            thiserror::Error,
        )]
        pub struct RepetitionError {
            /// Instruction type
            #[getset(get = "pub")]
            pub instruction: InstructionType,
            /// Id of the object being repeated
            pub id: IdBox,
        }
    }
    impl<T: Debug> Mismatch<T> {
        /// The value that is needed for normal execution
        pub fn expected(&self) -> &T {
            &self.expected
        }
    }
    impl<T: Debug> Mismatch<T> {
        /// The value that caused the error
        pub fn actual(&self) -> &T {
            &self.actual
        }
    }
    impl From<&str> for InstructionExecutionError {
        fn from(error: &str) -> Self {
            Self::Conversion(error.to_owned())
        }
    }
    impl From<TypeError> for InstructionExecutionError {
        fn from(err: TypeError) -> Self {
            Self::Evaluate(InstructionEvaluationError::Type(err))
        }
    }
}
/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    #[cfg(feature = "governance")]
    pub use super::governance::parliament::*;
    pub use super::{
        GrantBox, Instruction, InstructionBox, RemoveKeyValueBox, RevokeBox, SetKeyValueBox,
        account_recovery::{
            ApproveAccountRecovery, CancelAccountRecovery, ClearAccountRecoveryPolicy,
            FinalizeAccountRecovery, ProposeAccountRecovery, ReplaceAccountController,
            SetAccountRecoveryPolicy,
        },
        alias_setup::{
            CompareAndSetPrimaryAccountAlias, ConfigureAliasAutoRenew, EnsureAlias,
            RebindAccountAlias, RenewAliasLease,
        },
        asset_transfer_control::{
            SetAssetHoldingLimit, SetAssetTransferAvailability, SetAssetTransferBlacklist,
            SetAssetTransferControl,
        },
        bridge::{RecordBridgeReceipt, SubmitBridgeProof},
        confidential::{
            PublishPedersenParams, PublishPoseidonParams, SetPedersenParamsLifecycle,
            SetPoseidonParamsLifecycle,
        },
        consensus_keys::{
            ApplyThresholdKeyLifecycleCertificateV1, DisableConsensusKey, RegisterConsensusKey,
            RotateConsensusKey,
        },
        content::{PublishContentBundle, RetireContentBundle},
        contract_alias::SetContractAlias,
        endorsement::{
            RegisterDomainCommittee, SetDomainEndorsementPolicy, SubmitDomainEndorsement,
        },
        escrow::{
            AcceptAssetEscrow, AttestEscrowCondition, CancelAssetEscrow, CancelAssetLock,
            DrawdownAssetLock, ExpireAssetLock, ExpireConditionalEscrow, MarkEscrowPaymentSent,
            OpenAssetEscrow, OpenAssetLock, OpenConditionalEscrow, OpenEscrowDispute,
            ReleaseAssetEscrow, ResolveEscrowDispute,
        },
        identifier::{
            ActivateIdentifierPolicy, ClaimIdentifier, RegisterIdentifierPolicy, RevokeIdentifier,
        },
        ministry::SubmitAgendaProposal,
        mint_burn::{Burn, BurnBox, Mint, MintBox},
        oracle::{
            AggregateOracleFeed, OpenOracleDispute, ProposeOracleChange, RecordTwitterBinding,
            RegisterOracleFeed, ResolveOracleDispute, RevokeTwitterBinding, RollbackOracleChange,
            SubmitOracleObservation, VoteOracleChangeStage,
        },
        privacy::{
            BootstrapPrivacyOrchardPoolV1, BootstrapPrivacyPgcAccountsV1,
            BootstrapPrivacyProofManagedPoolV1, BootstrapPrivacyZkAmsRegistryV1,
            PublishPrivacyRootV1, RegisterPrivacyBootleLanternIssuerPolicyV1,
            RegisterPrivacyProtocolActivationV1, RegisterPrivacyZkAcePolicyV1,
            RegisterPrivacyZkX509CertificatePolicyV1, RegisterPrivacyZkX509CrlV1,
            RegisterPrivacyZkX509TrustAnchorV1, RevokePrivacyBootleLanternIssuerPolicyV1,
            RevokePrivacyZkAcePolicyV1, RevokePrivacyZkX509CertificatePolicyV1,
            RevokePrivacyZkX509CrlV1, RevokePrivacyZkX509TrustAnchorV1,
            RotatePrivacyBootleLanternIssuerPolicyV1, RotatePrivacyZkAcePolicyV1,
            RotatePrivacyZkX509CertificatePolicyV1, RotatePrivacyZkX509CrlV1,
            RotatePrivacyZkX509TrustAnchorV1, SchedulePrivacyConsensusPolicyTighteningV1,
            SchedulePrivacyProtocolLimitsTighteningV1, SubmitPrivacyProofV1,
            TransitionPrivacyProtocolLifecycleV1,
        },
        private_settlement::{
            AbortAtomicPrivateSettlementV1, ActivatePrivateSettlementPoolV1,
            FinalizeAtomicPrivateSettlementV1, PrivateSettlementPoolActivationValidationErrorV1,
            PrivateSettlementPoolRotationValidationErrorV1, RotatePrivateSettlementPoolPolicyV1,
        },
        ram_lfe::{
            ActivateRamLfeProgramPolicy, DeactivateRamLfeProgramPolicy, RegisterRamLfeProgramPolicy,
        },
        register::{Register, RegisterBox, Unregister, UnregisterBox},
        repo::{RepoInstructionBox, RepoIsi, ReverseRepoIsi},
        retail_daily_limit::{
            ActivateRetailDailyLimitV1, BindRetailIdentityV1, RetailMonetaryMovementV1,
        },
        rwa::{
            ForceTransferRwa, FreezeRwa, HoldRwa, MergeRwas, RedeemRwa, RegisterRwa, ReleaseRwa,
            RwaInstructionBox, SetRwaControls, TransferRwa, UnfreezeRwa,
        },
        settlement::{
            ATOMIC_SETTLEMENT_MAX_MOVEMENTS, ATOMIC_SETTLEMENT_MIN_MOVEMENTS,
            AtomicSettlementDetails, AtomicSettlementMovement, AtomicSettlementMovements, DvpIsi,
            DvpSettlementDetails, FundFxCorridorEscrow, FxCorridorId, FxCorridorOracleEvidence,
            FxCorridorPolicy, FxCorridorPolicyRegistry, FxCorridorPricingContext,
            FxCorridorSettlementDetails, FxCorridorUsage, PvpIsi, PvpSettlementDetails,
            RefundFxCorridorEscrow, ResolvedSettlementMovement, ResolvedSettlementMovements,
            SetFxCorridorPolicy, SettleAtomic, SettleFxCorridor, SettlementAtomicity,
            SettlementDetails, SettlementExecutionOrder, SettlementInstructionBox, SettlementLeg,
            SettlementPlan, SettlementReceipt,
        },
        social::{CancelTwitterEscrow, ClaimTwitterFollowReward, SendToTwitter},
        soracloud::{
            AdvanceSoracloudRollout, ApplySoracloudOrderedMailboxResult, DeploySoracloudService,
            MutateSoracloudState, RecordSoracloudAgentAutonomyExecution,
            RecordSoracloudDecryptionRequest, RecordSoracloudMailboxMessage,
            RecordSoracloudRuntimeReceipt, ReportSoracloudServiceLeaseUsage,
            RollbackSoracloudService, RunSoracloudFheJob, SetSoracloudRuntimeState,
            UpgradeSoracloudService,
        },
        soradns::{
            AddReleaseSigner, PublishDirectory, RemoveReleaseSigner, RevokeResolver,
            SetDirectoryRotationPolicy, SubmitDirectoryDraft, UnrevokeResolver,
        },
        sorafs::{
            AcceptSorafsModerationJurorAssignment, ActivateSorafsModerationCase,
            AdvanceSorafsReserveLifecycle, AppendSorafsPorReputationJournalEntry,
            AppendSorafsStreamTokenReputationJournalEntry, ApprovePinManifest,
            AssertSorafsPublicationV1, BindManifestAlias, CancelSorafsOrderbookOrder,
            ChargeSorafsReserveRent, CommitSorafsPopCredentialBatch, CompleteReplicationOrder,
            DecideSorafsReserveAppeal, DecideSorafsReserveMovement, DrawSorafsReserveCredit,
            ExpireReplicationOrder, ExpireSorafsModerationChallenge, FinalizeSorafsModerationCase,
            FinalizeSorafsModerationSortition, InitializeSorafsProviderAdmissionV1,
            IssueReplicationOrder, MaintainSorafsOrderbook, MatchSorafsOrderbook,
            MutateSorafsFinalPromotionAccountCustody, MutateSorafsFinalPromotionAuthority,
            MutateSorafsReleaseManifestAuthority, MutateSorafsStreamTokenAuthority,
            MutateSorafsStreamTokenCustody, MutateSorafsStreamTokenGateway,
            MutateSorafsTopologyAuthority, PublishSorafsPopRevocationList,
            RaiseSorafsModerationChallenge, RecordCapacityTelemetry,
            RecordSorafsOrderbookSettlementReceipt, RegisterCapacityDeclaration,
            RegisterCapacityDispute, RegisterPinManifest, RegisterSorafsModerationJurorEligibility,
            RegisterSorafsReserveAccount, RepaySorafsReserveCredit, RequestSorafsReserveMovement,
            ResolveSorafsCapacityDispute, ResolveSorafsModerationChallenge, RetirePinManifest,
            ReviseReplicationOrderAssignments, RevokeProviderIngestCompletionAuthority,
            SetPricingSchedule, SetProviderIngestCompletionAuthority, SetSorafsModerationPolicy,
            SetSorafsOrderbookPolicy, SetSorafsPopIssuerPolicy,
            SetSorafsReputationJournalAuthorityPolicy, SetSorafsReservePolicy,
            SubmitSorafsModerationAppeal, SubmitSorafsModerationCommit,
            SubmitSorafsModerationReveal, SubmitSorafsOrderbookOrder, SubmitSorafsReserveAppeal,
            UpsertProviderCredit,
        },
        space_directory::{
            ExpireSpaceDirectoryManifest, PublishSpaceDirectoryManifest,
            RevokeSpaceDirectoryManifest,
        },
        staking::{
            ActivatePublicLaneValidator, BondPublicLaneStake, ClaimPublicLaneRewards,
            ExitPublicLaneValidator, FinalizePublicLaneUnbond, RebindPublicLaneValidatorPeer,
            RecordPublicLaneRewards, RegisterPublicLaneCandidate, RegisterPublicLaneValidator,
            SchedulePublicLaneUnbond, SlashPublicLaneValidator,
        },
        transfer::{Transfer, TransferAssetBatch, TransferAssetBatchEntry, TransferBox},
        transparent::{
            CustomInstruction, ExecuteTrigger, Grant, Log, RemoveKeyValue, Revoke, SetKeyValue,
            SetParameter, Upgrade,
        },
        vpn::{OpenVpnLeaseEscrow, RefundExpiredVpnLease, SettleVpnLease},
    };
}
#[cfg(test)]
#[path = "shared_test_helpers.rs"]
mod test_support;
#[cfg(test)]
#[path = "instruction_enum_tests.rs"]
mod tests;

#[cfg(test)]
mod framing_tests;

#[cfg(test)]
mod generated_argument_identity_tests;

#[cfg(test)]
mod generated_enum_identity_tests;

#[cfg(test)]
mod generated_box_identity_tests;

#[cfg(test)]
pub(crate) mod generated_record_identity_tests;

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use crate::checked_container_refusal_controls::audit;

    #[test]
    fn original_mismatch_checked_container_retains_bytes_errors_and_depth() {
        audit(&crate::isi::error::Mismatch {
            expected: 7_u64,
            actual: 9_u64,
        });
    }
}
