//! This module contains enumeration of all possible Iroha Special Instructions, generic instruction
//! types and related implementations.
pub mod account;
mod account_admission;
pub mod asset;
pub mod block;
/// Content lane instruction handlers.
pub mod content;
/// DeFi-native instruction handlers.
pub mod defi;
pub mod domain;
/// Native asset escrow instruction handlers.
pub mod escrow;
/// Generic game custody and proof settlement transitions.
pub mod game;
/// Authorization, signature and error-mapping helpers shared by ISI modules.
pub(crate) mod helpers;
pub mod identifier;
pub mod kaigi;
/// Ministry agenda submission handlers.
pub mod ministry;
pub mod multisig;
/// Musubi package registry instruction handlers.
pub mod musubi;
pub mod nft;
/// Shared protected NFT reservation and exact-price sale support.
pub mod nft_custody;
/// Generic native exact-price NFT marketplace.
pub mod nft_market;
/// Oracle feed admission and aggregation instruction handlers.
pub mod oracle;
/// Canonical first-release privacy governance and proof admission.
pub mod privacy;
/// Atomic private cross-dataspace settlement carrier execution.
pub mod private_settlement;
pub mod query;
pub mod ram_lfe;
pub mod repo;
pub mod retail_daily_limit;
pub mod rwa;
/// SCCP v1 cross-chain core: state access, hooks, admission and instructions.
pub mod sccp;
pub mod settlement;
/// SNS-backed ownership query handlers.
pub mod sns;
/// Viral social incentive instruction handlers.
pub mod social;
/// Soracloud lifecycle and runtime-state instruction handlers.
pub mod soracloud;
pub mod soradns;
/// `SoraFS` pin registry instruction handlers.
pub mod sorafs;
pub mod sorafs_final_promotion_account_custody;
/// Governed deployment custody and durable final-promotion signer-operation authority.
pub mod sorafs_final_promotion_authority;
/// Authoritative `SoraFS` moderation commit/reveal ledger handlers.
pub mod sorafs_moderation;
/// Authoritative `SoraFS` orderbook instruction handlers.
pub mod sorafs_orderbook;
/// Authoritative `SoraFS` proof-of-personhood issuer and registry handlers.
pub mod sorafs_pop_registry;
/// Finalized chain-authoritative `SoraFS` PDP and PoTR outcome handlers.
pub mod sorafs_proof_outcome;
/// Certified Parliament provider-admission effects.
pub mod sorafs_provider_admission;
/// Closed role-13 release-manifest instruction and distinct deployment permissions.
pub mod sorafs_release_manifest_authority;
/// Authoritative native `SoraFS` reputation recorder policy and source journal.
pub mod sorafs_reputation;
/// Authoritative `SoraFS` reserve/rent instruction handlers.
pub mod sorafs_reserve;
/// Provider-scoped stream-token operation journal; challenged Check remains closed.
pub mod sorafs_stream_token_authority;
/// Native stream-token custody policy and hardware enrollment transitions.
pub mod sorafs_stream_token_custody;
/// Governed native gateway quotas, leases and ordered callback history.
pub(crate) mod sorafs_stream_token_gateway;
/// Closed role-16 topology authority instruction; no native mutation or signer capability yet.
pub mod sorafs_topology_authority;
pub mod space_directory;
/// Public lane staking instruction handlers.
pub mod staking;
pub mod triggers;
pub mod tx;
/// Native SoraNet VPN lease escrow instruction handlers.
pub mod vpn;
pub mod world;
use super::Execute;
use crate::{
    smartcontracts::triggers::set::SetReadOnly,
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
};
use eyre::Result;
pub use iroha_data_model::Registrable;
use iroha_data_model::{
    isi::{error::InstructionExecutionError as Error, *},
    prelude::*,
};
use iroha_logger::prelude::*;
use mv::storage::StorageReadOnly;
type InstructionHandler =
    fn(&InstructionBox, &AccountId, &mut StateTransaction<'_, '_>) -> Option<Result<(), Error>>;
fn dispatch_instruction<T: Execute + Clone + 'static>(
    instruction: &InstructionBox,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Option<Result<(), Error>> {
    instruction
        .as_any()
        .downcast_ref::<T>()
        .map(|isi| isi.clone().execute(authority, state_transaction))
}
/// Fixed rejection for explicitly unavailable native operations, including at genesis.
pub(crate) const INITIAL_NATIVE_INSTRUCTION_CLOSED_REASON: &str =
    "native instruction is explicitly closed; Core execution is unavailable";
/// Explicit Initial-executor disposition reviewed alongside a native handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitialNativeInstructionAdmission {
    /// The native handler enforces the instruction's exact authority and state constraints.
    CoreAuthorized,
    /// The operation is registered for decoding but is not available for execution.
    Closed,
}
/// Test-owned static numeric-asset audit, independent of execution authority.
///
/// Actual user payments retain the common numeric mutation and signed assessment checks.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeInstructionAssetEffect {
    /// The handler changes no numeric asset balance or supply.
    NoNumericAssetEffect,
    /// The handler can cause numeric asset effects not exposed as signed transfer coordinates.
    MayAffectNumericAssets,
}
macro_rules! define_instruction_handlers {
    ($($handler:ident::<$instruction:ty $(,)?> $(=> $admission:ident)? $([asset_effect = $asset_effect:ident])?),* $(,)?) => {
        const INSTRUCTION_HANDLERS: &[InstructionHandler] = &[
            $($handler::<$instruction>),*
        ];
        #[cfg(test)]
        trait NativeInstructionRegistered {}
        $(
            #[cfg(test)]
            impl NativeInstructionRegistered for $instruction {}
        )*
        #[cfg(test)]
        fn registered_native_instruction_type_names() -> Vec<&'static str> {
            vec![$(core::any::type_name::<$instruction>()),*]
        }
        #[cfg(test)]
        fn registered_native_instruction_asset_effects()
            -> Vec<(&'static str, NativeInstructionAssetEffect)>
        {
            vec![$($( (
                core::any::type_name::<$instruction>(),
                NativeInstructionAssetEffect::$asset_effect,
            ), )?)*]
        }
        /// Match only concrete instruction types whose Initial disposition was reviewed here.
        ///
        /// Unannotated handlers do not acquire admission by being registered. They remain subject
        /// to the Initial executor's other explicit native parity gates.
        pub(crate) fn registered_native_instruction_initial_admission(
            instruction: &InstructionBox,
        ) -> Option<InitialNativeInstructionAdmission> {
            $(
                $(
                    if instruction.as_any().downcast_ref::<$instruction>().is_some() {
                        return Some(InitialNativeInstructionAdmission::$admission);
                    }
                )?
            )*
            None
        }
        #[cfg(test)]
        fn registered_native_instruction_initial_dispositions()
            -> Vec<(&'static str, InitialNativeInstructionAdmission)>
        {
            vec![$($( (
                core::any::type_name::<$instruction>(),
                InitialNativeInstructionAdmission::$admission,
            ), )?)*]
        }
    };
}
define_instruction_handlers! {
    dispatch_instruction::<iroha_data_model::isi::nft_market::OfferNftV1>,
    dispatch_instruction::<iroha_data_model::isi::nft_market::BuyNftV1>,
    dispatch_instruction::<iroha_data_model::isi::nft_market::CancelNftOfferV1>,
    dispatch_instruction::<iroha_data_model::isi::game::RegisterExecutionProofProfileV1>,
    dispatch_instruction::<iroha_data_model::isi::game::VerifyExecutionProofV1>,
    dispatch_instruction::<iroha_data_model::isi::game::SettleGameSessionV1>,
    dispatch_instruction::<iroha_data_model::isi::game::OpenGameSessionV1>,
    dispatch_instruction::<iroha_data_model::isi::game::JoinGameSessionV1>,
    dispatch_instruction::<iroha_data_model::isi::game::StartGameSessionV1>,
    dispatch_instruction::<iroha_data_model::isi::game::CommitGameCheckpointV1>,
    dispatch_instruction::<iroha_data_model::isi::game::ChallengeGameSessionV1>,
    dispatch_instruction::<iroha_data_model::isi::game::CommitGameInputsV1>,
    dispatch_instruction::<iroha_data_model::isi::game::RevealGameInputsV1>,
    dispatch_instruction::<iroha_data_model::isi::game::AdvanceGameDeadlineV1>,
    dispatch_instruction::<iroha_data_model::isi::game::ExpireGameSessionV1>,
    dispatch_instruction::<iroha_data_model::isi::game::ClaimGamePayoutV1>,
    dispatch_instruction::<iroha_data_model::isi::game::StakeGameItemV1>,

    dispatch_instruction::<iroha_data_model::isi::register::RegisterCommitteePeerWithPop>,
    dispatch_instruction::<RegisterPeerWithPop>,
    dispatch_instruction::<RegisterBox>,
    dispatch_instruction::<UnregisterBox>,
    dispatch_instruction::<MintBox>,
    dispatch_instruction::<BurnBox>,
    dispatch_instruction::<TransferBox>,
    dispatch_instruction::<SetKeyValueBox>,
    dispatch_instruction::<RemoveKeyValueBox>,
    dispatch_instruction::<SetAssetKeyValue>,
    dispatch_instruction::<RemoveAssetKeyValue>,
    dispatch_instruction::<AddSignatory>,
    dispatch_instruction::<RemoveSignatory>,
    dispatch_instruction::<SetAccountQuorum>,
    dispatch_instruction::<GrantBox>,
    dispatch_instruction::<RevokeBox>,
    dispatch_instruction::<ExecuteTrigger>,
    dispatch_instruction::<SetParameter>,
    dispatch_instruction::<Upgrade>,
    dispatch_instruction::<Log>,
    dispatch_instruction::<iroha_data_model::isi::alias_setup::EnsureAlias>,
    dispatch_instruction::<iroha_data_model::isi::alias_setup::RenewAliasLease>,
    dispatch_instruction::<iroha_data_model::isi::alias_setup::ConfigureAliasAutoRenew>,
    dispatch_instruction::<iroha_data_model::isi::alias_setup::RebindAccountAlias>,
    dispatch_instruction::<iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias>,
    dispatch_instruction::<iroha_data_model::isi::InvalidInstruction>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::CreateKaigi>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::JoinKaigi>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::LeaveKaigi>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::EndKaigi>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::RecordKaigiUsage>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::SetKaigiRelayManifest>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::RegisterKaigiRelay>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::UnregisterKaigiRelay>,
    dispatch_instruction::<iroha_data_model::isi::kaigi::ReportKaigiRelayHealth>,
    dispatch_instruction::<runtime_upgrade::ProposeRuntimeUpgrade>,
    dispatch_instruction::<runtime_upgrade::ActivateRuntimeUpgrade>,
    dispatch_instruction::<runtime_upgrade::CancelRuntimeUpgrade>,
    dispatch_instruction::<Mint<Quantity, Asset>>,
    dispatch_instruction::<Burn<Quantity, Asset>>,
    dispatch_instruction::<Transfer<Asset, Quantity, Account>>,
    dispatch_instruction::<TransferAssetBatch>,
    dispatch_instruction::<iroha_data_model::isi::SetAssetTransferAvailability>,
    dispatch_instruction::<iroha_data_model::isi::SetAssetTransferBlacklist>,
    dispatch_instruction::<iroha_data_model::isi::SetAssetTransferControl>,
    dispatch_instruction::<iroha_data_model::isi::SetAssetHoldingLimit>,
    dispatch_instruction::<iroha_data_model::isi::retail_daily_limit::ActivateRetailDailyLimitV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::retail_daily_limit::BindRetailIdentityV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::retail_daily_limit::RetailMonetaryMovementV1> => CoreAuthorized [asset_effect = MayAffectNumericAssets],
    // Native AMX two-phase commit retains exact signed-root transitions and monetary custody.
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::RegisterAmxDataspaceV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::private_dataspace::RegisterPrivateDataspace> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::private_dataspace::AnchorPrivateDataspace> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::BeginAmxV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::RelayAmxPreparedV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::RelayAmxHandoffV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::RegisterAmxParticipantV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::PrepareAmxV1> => CoreAuthorized [asset_effect = MayAffectNumericAssets],
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::SettleAmxV1> => CoreAuthorized [asset_effect = MayAffectNumericAssets],
    dispatch_instruction::<iroha_data_model::isi::sumeragi_amx::RelayGlobalAmxHandoffV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::repo::RepoInstructionBox>,
    dispatch_instruction::<iroha_data_model::isi::repo::RepoIsi>,
    dispatch_instruction::<iroha_data_model::isi::repo::ReverseRepoIsi>,
    dispatch_instruction::<iroha_data_model::isi::repo::RepoMarginCallIsi>,
    dispatch_instruction::<iroha_data_model::isi::rwa::RwaInstructionBox>,
    dispatch_instruction::<iroha_data_model::isi::rwa::RegisterRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::TransferRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::MergeRwas>,
    dispatch_instruction::<iroha_data_model::isi::rwa::RedeemRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::FreezeRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::UnfreezeRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::HoldRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::ReleaseRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::ForceTransferRwa>,
    dispatch_instruction::<iroha_data_model::isi::rwa::SetRwaControls>,
    dispatch_instruction::<iroha_data_model::isi::defi::DeFiInstructionBox>,
    dispatch_instruction::<iroha_data_model::isi::defi::SubmitDefiIntent>,
    dispatch_instruction::<iroha_data_model::isi::defi::SettleDefiIntent>,
    dispatch_instruction::<iroha_data_model::isi::defi::RegisterDefiVault>,
    dispatch_instruction::<iroha_data_model::isi::defi::RecordDefiVaultRequest>,
    dispatch_instruction::<iroha_data_model::isi::defi::RegisterDefiOperator>,
    dispatch_instruction::<iroha_data_model::isi::defi::RecordDefiOperatorHeartbeat>,
    dispatch_instruction::<iroha_data_model::isi::defi::ConfigureDefiAmmHook>,
    dispatch_instruction::<iroha_data_model::isi::defi::RecordDefiHookExecution>,
    dispatch_instruction::<iroha_data_model::isi::defi::RegisterDefiMarginMarket>,
    dispatch_instruction::<iroha_data_model::isi::defi::UpdateDefiMarginAccount>,
    dispatch_instruction::<iroha_data_model::isi::defi::RegisterDefiRwaMarket>,
    dispatch_instruction::<iroha_data_model::isi::defi::ReportDefiRwaNav>,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RegisterPinManifest> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::AssertSorafsPublicationV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::InitializeSorafsProviderAdmissionV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ApprovePinManifest> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RetirePinManifest> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::BindManifestAlias> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RegisterProviderOwner> => Closed,
    dispatch_instruction::<iroha_data_model::isi::sorafs::UnregisterProviderOwner> => Closed,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RegisterCapacityDeclaration> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RecordCapacityTelemetry> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RegisterCapacityDispute> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ResolveSorafsCapacityDispute> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::IssueReplicationOrder> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::CompleteReplicationOrder> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ReviseReplicationOrderAssignments> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ExpireReplicationOrder> => CoreAuthorized,
    dispatch_instruction::<
        iroha_data_model::isi::sorafs::SetProviderIngestCompletionAuthority,
    > => CoreAuthorized,
    dispatch_instruction::<
        iroha_data_model::isi::sorafs::RevokeProviderIngestCompletionAuthority,
    > => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SetPricingSchedule> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::UpsertProviderCredit> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SetSorafsOrderbookPolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsOrderbookOrder> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::CancelSorafsOrderbookOrder> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MutateSorafsStreamTokenCustody> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MutateSorafsStreamTokenGateway> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAuthority> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAccountCustody> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MutateSorafsReleaseManifestAuthority> => Closed,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MutateSorafsTopologyAuthority> => Closed,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MatchSorafsOrderbook> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::MaintainSorafsOrderbook> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RecordSorafsOrderbookSettlementReceipt> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SetSorafsReservePolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RegisterSorafsReserveAccount> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RequestSorafsReserveMovement> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::DecideSorafsReserveMovement> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ChargeSorafsReserveRent> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::AdvanceSorafsReserveLifecycle> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::DrawSorafsReserveCredit> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RepaySorafsReserveCredit> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsReserveAppeal> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::DecideSorafsReserveAppeal> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsRepairTask> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ApplySorafsRepairTaskAction> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsRepairAppeal> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SetSorafsProofOutcomeSignerPolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsProofOutcome> => CoreAuthorized,
    dispatch_instruction::<
        iroha_data_model::isi::sorafs::SetSorafsReputationJournalAuthorityPolicy
    > => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::AppendSorafsPorReputationJournalEntry> => CoreAuthorized,
    dispatch_instruction::<
        iroha_data_model::isi::sorafs::AppendSorafsStreamTokenReputationJournalEntry
    > => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SetSorafsPopIssuerPolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::CommitSorafsPopCredentialBatch> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::PublishSorafsPopRevocationList> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SetSorafsModerationPolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsModerationAppeal> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RegisterSorafsModerationJurorEligibility> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::FinalizeSorafsModerationSortition> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::AcceptSorafsModerationJurorAssignment> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ActivateSorafsModerationCase> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsModerationCommit> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::RaiseSorafsModerationChallenge> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ResolveSorafsModerationChallenge> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::ExpireSorafsModerationChallenge> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::SubmitSorafsModerationReveal> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sorafs::FinalizeSorafsModerationCase> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::content::PublishContentBundle>,
    dispatch_instruction::<iroha_data_model::isi::content::RetireContentBundle>,
    dispatch_instruction::<iroha_data_model::isi::soradns::SubmitDirectoryDraft>,
    dispatch_instruction::<iroha_data_model::isi::soradns::PublishDirectory>,
    dispatch_instruction::<iroha_data_model::isi::soradns::RevokeResolver>,
    dispatch_instruction::<iroha_data_model::isi::soradns::UnrevokeResolver>,
    dispatch_instruction::<iroha_data_model::isi::soradns::AddReleaseSigner>,
    dispatch_instruction::<iroha_data_model::isi::soradns::RemoveReleaseSigner>,
    dispatch_instruction::<iroha_data_model::isi::soradns::SetDirectoryRotationPolicy>,
    dispatch_instruction::<iroha_data_model::isi::space_directory::PublishSpaceDirectoryManifest>,
    dispatch_instruction::<iroha_data_model::isi::space_directory::RevokeSpaceDirectoryManifest>,
    dispatch_instruction::<iroha_data_model::isi::space_directory::ExpireSpaceDirectoryManifest>,
    dispatch_instruction::<iroha_data_model::isi::account_recovery::ReplaceAccountController>,
    dispatch_instruction::<iroha_data_model::isi::account_recovery::SetAccountRecoveryPolicy>,
    dispatch_instruction::<iroha_data_model::isi::account_recovery::ClearAccountRecoveryPolicy>,
    dispatch_instruction::<iroha_data_model::isi::account_recovery::ProposeAccountRecovery>,
    dispatch_instruction::<iroha_data_model::isi::account_recovery::ApproveAccountRecovery>,
    dispatch_instruction::<iroha_data_model::isi::account_recovery::CancelAccountRecovery>,
    dispatch_instruction::<iroha_data_model::isi::account_recovery::FinalizeAccountRecovery>,
    dispatch_instruction::<iroha_data_model::isi::contract_alias::SetContractAlias>,
    // The native namespace owner/generation and exact static/SNS dataspace mapping authorize
    // registration and current-owner replay; no executor-level blanket grant is introduced.
    dispatch_instruction::<iroha_data_model::isi::musubi::RegisterMusubiNamespaceBindingV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::musubi::RegisterMusubiArchiveV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::AdvanceMusubiPinOutboxV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::CheckMusubiPinOutboxV1>,
    // The native archive manager, original completed provider evidence and current revision
    // checks own these publication operations; Initial only routes to those exact owners.
    dispatch_instruction::<
        iroha_data_model::isi::musubi::RegisterMusubiProviderBundleAttestationV1,
    > => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::musubi::AddMusubiArchiveLocationV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::musubi::RetireMusubiArchiveLocationV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::PublishMusubiReleaseV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::musubi::SetMusubiReleaseYankV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::SetMusubiPackageMetadataV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::InviteMusubiPackageMaintainerV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::AcceptMusubiPackageMaintainerV1>,
    dispatch_instruction::<
        iroha_data_model::isi::musubi::RevokeMusubiPackageMaintainerInvitationV1,
    >,
    dispatch_instruction::<iroha_data_model::isi::musubi::SetMusubiPackageMaintainerRoleV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::RemoveMusubiPackageMaintainerV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::RegisterMusubiAliasV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::RecoverMusubiPackageV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::RetargetMusubiAliasV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::SetMusubiArtifactTakedownV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::SetMusubiRegistryPolicyV1>,
    dispatch_instruction::<iroha_data_model::isi::musubi::AssertMusubiReleaseDigestV1>,
    dispatch_instruction::<iroha_data_model::isi::identifier::RegisterIdentifierPolicy>,
    dispatch_instruction::<iroha_data_model::isi::identifier::ActivateIdentifierPolicy>,
    dispatch_instruction::<iroha_data_model::isi::identifier::ClaimIdentifier>,
    dispatch_instruction::<iroha_data_model::isi::identifier::RevokeIdentifier>,
    dispatch_instruction::<iroha_data_model::isi::ram_lfe::RegisterRamLfeProgramPolicy>,
    dispatch_instruction::<iroha_data_model::isi::ram_lfe::ActivateRamLfeProgramPolicy>,
    dispatch_instruction::<iroha_data_model::isi::ram_lfe::DeactivateRamLfeProgramPolicy>,
    dispatch_instruction::<iroha_data_model::isi::SetAssetDefinitionAlias>,
    dispatch_instruction::<iroha_data_model::isi::social::ClaimTwitterFollowReward>,
    dispatch_instruction::<iroha_data_model::isi::social::SendToTwitter>,
    dispatch_instruction::<iroha_data_model::isi::social::CancelTwitterEscrow>,
    dispatch_instruction::<iroha_data_model::isi::escrow::OpenAssetEscrow>,
    dispatch_instruction::<iroha_data_model::isi::escrow::AcceptAssetEscrow>,
    dispatch_instruction::<iroha_data_model::isi::escrow::MarkEscrowPaymentSent>,
    dispatch_instruction::<iroha_data_model::isi::escrow::ReleaseAssetEscrow>,
    dispatch_instruction::<iroha_data_model::isi::escrow::CancelAssetEscrow>,
    dispatch_instruction::<iroha_data_model::isi::escrow::OpenEscrowDispute>,
    dispatch_instruction::<iroha_data_model::isi::escrow::ResolveEscrowDispute>,
    dispatch_instruction::<iroha_data_model::isi::escrow::OpenAssetLock>,
    dispatch_instruction::<iroha_data_model::isi::escrow::OpenConditionalEscrow>,
    dispatch_instruction::<iroha_data_model::isi::escrow::AttestEscrowCondition>,
    dispatch_instruction::<iroha_data_model::isi::escrow::ExpireConditionalEscrow>,
    dispatch_instruction::<iroha_data_model::isi::escrow::DrawdownAssetLock>,
    dispatch_instruction::<iroha_data_model::isi::escrow::CancelAssetLock>,
    dispatch_instruction::<iroha_data_model::isi::escrow::ExpireAssetLock>,
    dispatch_instruction::<iroha_data_model::isi::vpn::OpenVpnLeaseEscrow>,
    dispatch_instruction::<iroha_data_model::isi::vpn::SettleVpnLease>,
    dispatch_instruction::<iroha_data_model::isi::vpn::RefundExpiredVpnLease>,
    dispatch_instruction::<iroha_data_model::isi::soracloud::DeploySoracloudService> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::UpgradeSoracloudService> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::DeploySoracloudAppInfra> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::UpgradeSoracloudAppInfra> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RollbackSoracloudService> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::SetSoracloudServiceConfig> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::DeleteSoracloudServiceConfig> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::SetSoracloudServiceSecret> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::DeleteSoracloudServiceSecret> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::MutateSoracloudState> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RegisterSoracloudFhePolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RotateSoracloudFhePolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RevokeSoracloudFhePolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RunSoracloudFheJob> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RecordSoracloudDecryptionRequest> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::JoinSoracloudHfSharedLease> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::LeaveSoracloudHfSharedLease> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RenewSoracloudHfSharedLease> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::AdvertiseSoracloudInrouHost> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::WithdrawSoracloudInrouHost> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::ReconcileSoracloudInrouPlacements> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::DeploySoracloudAgentApartment> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RenewSoracloudAgentLease> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RestartSoracloudAgentApartment> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RevokeSoracloudAgentPolicy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RequestSoracloudAgentWalletSpend> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::ApproveSoracloudAgentWalletSpend> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::EnqueueSoracloudAgentMessage> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::AcknowledgeSoracloudAgentMessage> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::AllowSoracloudAgentAutonomyArtifact> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RunSoracloudAgentAutonomy> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RecordSoracloudAgentAutonomyExecution> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::StartSoracloudTrainingJob> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::CheckpointSoracloudTrainingJob> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RetrySoracloudTrainingJob> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RegisterSoracloudModelArtifact> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RegisterSoracloudModelWeight> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::PromoteSoracloudModelWeight> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RollbackSoracloudModelWeight> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RegisterSoracloudUploadedModelBundle> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::FinalizeSoracloudUploadedModelBundle> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::AdvanceSoracloudRollout> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::SetSoracloudRuntimeState> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::SetSoracloudInrouReplicaRuntimeState> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::ClearSoracloudInrouReplicaRuntimeState> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::ReportSoracloudServiceLeaseUsage> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RecordSoracloudMailboxMessage> => Closed,
    dispatch_instruction::<iroha_data_model::isi::soracloud::RecordSoracloudRuntimeReceipt> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::soracloud::ApplySoracloudOrderedMailboxResult> => Closed,
    dispatch_instruction::<iroha_data_model::isi::oracle::RegisterOracleFeed>,
    dispatch_instruction::<iroha_data_model::isi::oracle::SubmitOracleObservation>,
    dispatch_instruction::<iroha_data_model::isi::oracle::AggregateOracleFeed>,
    dispatch_instruction::<iroha_data_model::isi::oracle::OpenOracleDispute>,
    dispatch_instruction::<iroha_data_model::isi::oracle::ResolveOracleDispute>,
    dispatch_instruction::<iroha_data_model::isi::oracle::ProposeOracleChange>,
    dispatch_instruction::<iroha_data_model::isi::oracle::VoteOracleChangeStage>,
    dispatch_instruction::<iroha_data_model::isi::oracle::RollbackOracleChange>,
    dispatch_instruction::<iroha_data_model::isi::oracle::SubmitDefiOracleAttestation>,
    dispatch_instruction::<iroha_data_model::isi::oracle::RecordTwitterBinding>,
    dispatch_instruction::<iroha_data_model::isi::oracle::RevokeTwitterBinding>,
    dispatch_instruction::<iroha_data_model::isi::staking::RebindPublicLaneValidatorPeer>,
    dispatch_instruction::<iroha_data_model::isi::staking::ActivatePublicLaneValidator>,
    dispatch_instruction::<iroha_data_model::isi::staking::ExitPublicLaneValidator>,
    dispatch_instruction::<
        iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation
    >,
    dispatch_instruction::<iroha_data_model::isi::nexus::CreateFeeSponsorProgram>,
    dispatch_instruction::<iroha_data_model::isi::nexus::StageFeeSponsorProgramRevision>,
    dispatch_instruction::<iroha_data_model::isi::nexus::ActivateFeeSponsorProgramRevision>,
    dispatch_instruction::<iroha_data_model::isi::nexus::PauseFeeSponsorProgram>,
    dispatch_instruction::<iroha_data_model::isi::nexus::BeginCloseFeeSponsorProgram>,
    dispatch_instruction::<iroha_data_model::isi::nexus::CloseFeeSponsorProgram>,
    dispatch_instruction::<iroha_data_model::isi::nexus::EnrollFeeSponsorBeneficiary>,
    dispatch_instruction::<iroha_data_model::isi::nexus::UnenrollFeeSponsorBeneficiary>,
    dispatch_instruction::<iroha_data_model::isi::nexus::FundFeeSponsorProgram>,
    dispatch_instruction::<iroha_data_model::isi::nexus::WithdrawFeeSponsorProgram>,
    dispatch_instruction::<iroha_data_model::isi::staking::RegisterPublicLaneCandidate>,
    dispatch_instruction::<iroha_data_model::isi::staking::RegisterPublicLaneValidator>,
    dispatch_instruction::<iroha_data_model::isi::staking::BondPublicLaneStake>,
    dispatch_instruction::<iroha_data_model::isi::staking::SchedulePublicLaneUnbond>,
    dispatch_instruction::<iroha_data_model::isi::staking::FinalizePublicLaneUnbond>,
    dispatch_instruction::<iroha_data_model::isi::staking::SlashPublicLaneValidator>,
    dispatch_instruction::<iroha_data_model::isi::staking::RecordPublicLaneRewards>,
    dispatch_instruction::<iroha_data_model::isi::staking::ClaimPublicLaneRewards>,
    dispatch_instruction::<iroha_data_model::isi::settlement::SettlementInstructionBox>,
    dispatch_instruction::<iroha_data_model::isi::settlement::DvpIsi>,
    dispatch_instruction::<iroha_data_model::isi::settlement::SettleAtomic> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::settlement::PvpIsi>,
    dispatch_instruction::<SetKeyValue<Trigger>>,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode>,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes>,
    dispatch_instruction::<
        iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk
    >,
    dispatch_instruction::<
        iroha_data_model::isi::smart_contract_code::FinalizeSmartContractCodeUpload
    >,
    dispatch_instruction::<
        iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload
    >,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::ActivateContractInstance>,
    dispatch_instruction::<
        iroha_data_model::isi::smart_contract_code::SetContractParliamentDelegation
    >,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::OfferContractOwnership>,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::AcceptContractOwnership>,
    dispatch_instruction::<
        iroha_data_model::isi::smart_contract_code::CancelContractOwnershipOffer
    >,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::CommitContractDeployment>,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::DeactivateContractInstance>,
    dispatch_instruction::<iroha_data_model::isi::smart_contract_code::RemoveSmartContractBytes>,
    dispatch_instruction::<verifying_keys::RegisterVerifyingKey>,
    dispatch_instruction::<verifying_keys::UpdateVerifyingKey>,
    dispatch_instruction::<zk::RegisterZkAsset>,
    dispatch_instruction::<zk::ScheduleConfidentialPolicyTransition>,
    dispatch_instruction::<zk::CancelConfidentialPolicyTransition>,
    dispatch_instruction::<zk::CreateElection>,
    dispatch_instruction::<zk::SubmitBallot>,
    dispatch_instruction::<zk::FinalizeElection>,
    // Generic verification records a bounded cryptographic result using an active registered
    // key. Core checks the exact backend, envelope, limits and duplicate identity; this does
    // not authorize spending, key administration or stronger execution-proof semantics.
    dispatch_instruction::<zk::VerifyProof> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<zk::PruneProofs>,
    dispatch_instruction::<iroha_data_model::isi::bridge::SubmitBridgeProof>,
    dispatch_instruction::<iroha_data_model::isi::bridge::RecordBridgeReceipt>,
    dispatch_instruction::<confidential::PublishPedersenParams>,
    dispatch_instruction::<confidential::SetPedersenParamsLifecycle>,
    dispatch_instruction::<confidential::PublishPoseidonParams>,
    dispatch_instruction::<confidential::SetPoseidonParamsLifecycle>,
    dispatch_instruction::<iroha_data_model::isi::consensus_keys::RegisterConsensusKey>,
    dispatch_instruction::<iroha_data_model::isi::consensus_keys::RotateConsensusKey>,
    dispatch_instruction::<iroha_data_model::isi::consensus_keys::DisableConsensusKey>,
    dispatch_instruction::<
        iroha_data_model::isi::consensus_keys::ApplyThresholdKeyLifecycleCertificateV1
    >,
    dispatch_instruction::<iroha_data_model::isi::endorsement::RegisterDomainCommittee>,
    dispatch_instruction::<iroha_data_model::isi::endorsement::SetDomainEndorsementPolicy>,
    dispatch_instruction::<iroha_data_model::isi::endorsement::SubmitDomainEndorsement>,
    dispatch_instruction::<iroha_data_model::isi::ministry::SubmitAgendaProposal>,
    dispatch_instruction::<iroha_data_model::isi::governance::ProposeDeployContract>,
    dispatch_instruction::<
        iroha_data_model::isi::governance::ProposeContractLifecycleGovernance
    >,
    dispatch_instruction::<iroha_data_model::isi::governance::ProposeContractEmergencyHold>,
    dispatch_instruction::<
        iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance
    >,
    dispatch_instruction::<iroha_data_model::isi::governance::ProposeRuntimeUpgradeProposal>,
    dispatch_instruction::<iroha_data_model::isi::governance::ProposeSccpRouteGovernance>,
    dispatch_instruction::<iroha_data_model::isi::governance::ProposeSorafsProviderGovernance>,
    dispatch_instruction::<iroha_data_model::isi::governance::ProposeValidationFeePolicy>,
    dispatch_instruction::<
        iroha_data_model::isi::governance::ProposeValidationFeePayoutLifecycle
    >,
    dispatch_instruction::<iroha_data_model::isi::governance::CastZkBallot>,
    dispatch_instruction::<iroha_data_model::isi::governance::CastPlainBallot>,
    dispatch_instruction::<iroha_data_model::isi::governance::UpdatePlainConviction>,
    dispatch_instruction::<
        iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1
    >,
    dispatch_instruction::<
        iroha_data_model::isi::governance::SubmitParliamentLifecycleTransitionV1
    >,
    dispatch_instruction::<iroha_data_model::isi::governance::RegisterCitizen>,
    dispatch_instruction::<iroha_data_model::isi::governance::UnregisterCitizen>,
    dispatch_instruction::<iroha_data_model::isi::governance::SlashGovernanceLock>,
    dispatch_instruction::<iroha_data_model::isi::governance::RestituteGovernanceLock>,
    // Privacy governance checks exact native permissions and lifecycle state. Proof
    // submissions and settlement carriers enforce their signed transaction bindings
    // and exhaustive verification in Core before committing persistent effects.
    // Asset-effect metadata is an independent audit: governance, roots, bootstraps and APS
    // carriers update typed privacy state, opaque commitments and rollback-safe budgets.
    // Their ordinary signed network fees remain payable. SubmitPrivacyProof can authorize
    // transparent transfers, whose user payment legs retain the common signed assessment checks.
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RegisterPrivacyProtocolActivationV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RegisterPrivacyExact12QualificationV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::SchedulePrivacyConsensusPolicyTighteningV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::SchedulePrivacyProtocolLimitsTighteningV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::TransitionPrivacyProtocolLifecycleV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::PublishPrivacyRootV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::BootstrapPrivacyOrchardPoolV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::BootstrapPrivacyProofManagedPoolV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::BootstrapPrivacyPgcAccountsV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::BootstrapPrivacyZkAmsRegistryV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RegisterPrivacyZkAcePolicyV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RotatePrivacyZkAcePolicyV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RevokePrivacyZkAcePolicyV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RegisterPrivacyBootleLanternIssuerPolicyV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RotatePrivacyBootleLanternIssuerPolicyV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RevokePrivacyBootleLanternIssuerPolicyV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RegisterPrivacyVegaIssuerV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RotatePrivacyVegaIssuerV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RevokePrivacyVegaIssuerV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RegisterPrivacyZkX509TrustAnchorV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RotatePrivacyZkX509TrustAnchorV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RevokePrivacyZkX509TrustAnchorV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RegisterPrivacyZkX509CertificatePolicyV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RotatePrivacyZkX509CertificatePolicyV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::privacy::RevokePrivacyZkX509CertificatePolicyV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RegisterPrivacyZkX509CrlV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RotatePrivacyZkX509CrlV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::RevokePrivacyZkX509CrlV1> => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<iroha_data_model::isi::privacy::SubmitPrivacyProofV1> => CoreAuthorized [asset_effect = MayAffectNumericAssets],
    dispatch_instruction::<
        iroha_data_model::isi::private_settlement::ActivatePrivateSettlementPoolV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::private_settlement::RotatePrivateSettlementPoolPolicyV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::private_settlement::RegisterAtomicPrivateSettlementPrepareV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::private_settlement::AbortAtomicPrivateSettlementV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    dispatch_instruction::<
        iroha_data_model::isi::private_settlement::FinalizeAtomicPrivateSettlementV1
    > => CoreAuthorized [asset_effect = NoNumericAssetEffect],
    // Core enforces every SCCP v1 rule (`specs/sccp.md` §4.19); exact user payments and
    // protected custody retain the common numeric mutation and fee checks.
    dispatch_instruction::<iroha_data_model::isi::sccp::InitializeSccpV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::SetSccpBridgeKeyV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::SubmitSccpAttestationsV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::SubmitSccpAttestationFaultV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::RecordSccpMessage> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::SubmitSccpInboundMessageV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::SettleSccpV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::SubmitSccpOutboundVoidV1> => CoreAuthorized,
    dispatch_instruction::<iroha_data_model::isi::sccp::AdvanceSccpLightClientV1> => CoreAuthorized,
    dispatch_instruction::<
        iroha_data_model::isi::sccp::ReportSccpLightClientEquivocationV1
    > => CoreAuthorized,
}
pub(crate) fn execute_borrowed_instruction(
    instruction: &InstructionBox,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    crate::executor::root_scope::ensure_instruction_scope(instruction, state_transaction)
        .map_err(|error| Error::from(error.to_string()))?;
    iroha_logger::debug!(isi=%instruction, "Executing");
    if let Some(result) = INSTRUCTION_HANDLERS
        .iter()
        .find_map(|handler| handler(instruction, authority, state_transaction))
    {
        return result;
    }
    // Custom instructions are expected to be handled by a custom executor
    if instruction
        .as_any()
        .downcast_ref::<CustomInstruction>()
        .is_some()
    {
        return Err(Error::from(
            "Custom instructions require an executor upgrade",
        ));
    }
    // If we reach here, the instruction type is unknown or unregistered
    Err(Error::from("Unknown instruction type"))
}
#[cfg(test)]
mod registry_dispatch_tests {
    use super::*;
    use std::collections::BTreeSet;
    fn has_dispatch_handler(type_name: &str) -> bool {
        registered_native_instruction_type_names().contains(&type_name)
    }
    fn assert_native_registration<T: NativeInstructionRegistered>() {}
    fn assert_reviewed_initial_family(family: &str, expected_closed: BTreeSet<&str>) {
        let wire_types: BTreeSet<_> = iroha_data_model::isi::registry::default()
            .names()
            .filter(|name| name.starts_with(family))
            .collect();
        let dispatch_types: BTreeSet<_> = registered_native_instruction_type_names()
            .into_iter()
            .filter(|name| name.starts_with(family))
            .collect();
        let dispositions: Vec<_> = registered_native_instruction_initial_dispositions()
            .into_iter()
            .filter(|(name, _)| name.starts_with(family))
            .collect();
        let reviewed_types: BTreeSet<_> = dispositions.iter().map(|(name, _)| *name).collect();
        assert!(
            !wire_types.is_empty(),
            "the canonical reviewed family must be found"
        );
        assert_eq!(
            wire_types, dispatch_types,
            "every wire type needs a native handler"
        );
        assert_eq!(
            dispatch_types, reviewed_types,
            "every reviewed-family handler needs an explicit reviewed Initial disposition"
        );
        assert_eq!(
            dispositions.len(),
            reviewed_types.len(),
            "duplicate disposition"
        );
        let closed_types: BTreeSet<_> = dispositions
            .into_iter()
            .filter_map(|(name, admission)| {
                (admission == InitialNativeInstructionAdmission::Closed).then_some(name)
            })
            .collect();
        assert_eq!(
            closed_types, expected_closed,
            "closed native operations must not acquire admission"
        );
    }
    fn assert_reviewed_asset_effect_family(
        family: &str,
        expected_count: usize,
        expected_ds_capable: BTreeSet<&str>,
    ) {
        let wire_types: BTreeSet<_> = iroha_data_model::isi::registry::default()
            .names()
            .filter(|name| name.starts_with(family))
            .collect();
        let effects: Vec<_> = registered_native_instruction_asset_effects()
            .into_iter()
            .filter(|(name, _)| name.starts_with(family))
            .collect();
        let reviewed_types: BTreeSet<_> = effects.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            wire_types.len(),
            expected_count,
            "review the complete family on change"
        );
        assert_eq!(
            wire_types, reviewed_types,
            "every wire type needs an explicit asset-effect audit"
        );
        assert_eq!(
            effects.len(),
            reviewed_types.len(),
            "duplicate asset-effect audit"
        );
        let ds_capable: BTreeSet<_> = effects
            .into_iter()
            .filter_map(|(name, effect)| match effect {
                NativeInstructionAssetEffect::NoNumericAssetEffect => None,
                NativeInstructionAssetEffect::MayAffectNumericAssets => Some(name),
            })
            .collect();
        assert_eq!(
            ds_capable, expected_ds_capable,
            "authority does not imply balance neutrality"
        );
    }
    #[test]
    fn every_soracloud_wire_instruction_has_a_reviewed_initial_disposition() {
        assert_reviewed_initial_family(
            "iroha_data_model::isi::soracloud::",
            BTreeSet::from([
                core::any::type_name::<
                    iroha_data_model::isi::soracloud::RecordSoracloudMailboxMessage,
                >(),
                core::any::type_name::<
                    iroha_data_model::isi::soracloud::ApplySoracloudOrderedMailboxResult,
                >(),
            ]),
        );
    }
    #[test]
    fn every_sccp_wire_instruction_has_a_reviewed_initial_disposition() {
        assert_reviewed_initial_family("iroha_data_model::isi::sccp::", BTreeSet::new());
        for instruction in crate::smartcontracts::isi::sccp::test_support::SampleInstructions::all()
        {
            assert_eq!(
                registered_native_instruction_initial_admission(&instruction),
                Some(InitialNativeInstructionAdmission::CoreAuthorized),
                "{instruction:?}"
            );
        }
    }
    #[test]
    fn every_sorafs_wire_instruction_has_a_reviewed_initial_disposition() {
        assert_reviewed_initial_family(
            "iroha_data_model::isi::sorafs::",
            BTreeSet::from([
                core::any::type_name::<iroha_data_model::isi::sorafs::RegisterProviderOwner>(),
                core::any::type_name::<iroha_data_model::isi::sorafs::UnregisterProviderOwner>(),
                core::any::type_name::<
                    iroha_data_model::isi::sorafs::MutateSorafsReleaseManifestAuthority,
                >(),
                core::any::type_name::<iroha_data_model::isi::sorafs::MutateSorafsTopologyAuthority>(
                ),
            ]),
        );
    }
    #[test]
    fn game_and_committee_peer_instructions_have_native_handlers() {
        use iroha_data_model::isi::{game, register::RegisterCommitteePeerWithPop};

        assert_native_registration::<game::RegisterExecutionProofProfileV1>();
        assert_native_registration::<game::VerifyExecutionProofV1>();
        assert_native_registration::<game::SettleGameSessionV1>();
        assert_native_registration::<game::OpenGameSessionV1>();
        assert_native_registration::<game::JoinGameSessionV1>();
        assert_native_registration::<game::StartGameSessionV1>();
        assert_native_registration::<game::CommitGameCheckpointV1>();
        assert_native_registration::<game::ChallengeGameSessionV1>();
        assert_native_registration::<game::CommitGameInputsV1>();
        assert_native_registration::<game::RevealGameInputsV1>();
        assert_native_registration::<game::AdvanceGameDeadlineV1>();
        assert_native_registration::<game::ExpireGameSessionV1>();
        assert_native_registration::<game::ClaimGamePayoutV1>();
        assert_native_registration::<game::StakeGameItemV1>();
        assert_native_registration::<RegisterCommitteePeerWithPop>();
    }
    #[test]
    fn parliament_lifecycle_and_standalone_ballots_have_native_handlers() {
        use iroha_data_model::isi::governance;

        assert_native_registration::<governance::CreateParliamentGovernanceAttemptV1>();
        assert_native_registration::<governance::SubmitParliamentLifecycleTransitionV1>();
        assert_native_registration::<governance::CastZkBallot>();
        assert_native_registration::<governance::CastPlainBallot>();
        assert_native_registration::<governance::UpdatePlainConviction>();
    }
    #[test]
    fn every_canonical_privacy_instruction_has_a_native_dispatch_impl() {
        use iroha_data_model::isi::privacy;
        assert_native_registration::<privacy::RegisterPrivacyProtocolActivationV1>();
        assert_native_registration::<privacy::RegisterPrivacyExact12QualificationV1>();
        assert_native_registration::<privacy::SchedulePrivacyConsensusPolicyTighteningV1>();
        assert_native_registration::<privacy::SchedulePrivacyProtocolLimitsTighteningV1>();
        assert_native_registration::<privacy::TransitionPrivacyProtocolLifecycleV1>();
        assert_native_registration::<privacy::PublishPrivacyRootV1>();
        assert_native_registration::<privacy::BootstrapPrivacyOrchardPoolV1>();
        assert_native_registration::<privacy::BootstrapPrivacyProofManagedPoolV1>();
        assert_native_registration::<privacy::BootstrapPrivacyPgcAccountsV1>();
        assert_native_registration::<privacy::BootstrapPrivacyZkAmsRegistryV1>();
        assert_native_registration::<privacy::RegisterPrivacyZkAcePolicyV1>();
        assert_native_registration::<privacy::RotatePrivacyZkAcePolicyV1>();
        assert_native_registration::<privacy::RevokePrivacyZkAcePolicyV1>();
        assert_native_registration::<privacy::RegisterPrivacyBootleLanternIssuerPolicyV1>();
        assert_native_registration::<privacy::RotatePrivacyBootleLanternIssuerPolicyV1>();
        assert_native_registration::<privacy::RevokePrivacyBootleLanternIssuerPolicyV1>();
        assert_native_registration::<privacy::RegisterPrivacyVegaIssuerV1>();
        assert_native_registration::<privacy::RotatePrivacyVegaIssuerV1>();
        assert_native_registration::<privacy::RevokePrivacyVegaIssuerV1>();
        assert_native_registration::<privacy::RegisterPrivacyZkX509TrustAnchorV1>();
        assert_native_registration::<privacy::RotatePrivacyZkX509TrustAnchorV1>();
        assert_native_registration::<privacy::RevokePrivacyZkX509TrustAnchorV1>();
        assert_native_registration::<privacy::RegisterPrivacyZkX509CertificatePolicyV1>();
        assert_native_registration::<privacy::RotatePrivacyZkX509CertificatePolicyV1>();
        assert_native_registration::<privacy::RevokePrivacyZkX509CertificatePolicyV1>();
        assert_native_registration::<privacy::RegisterPrivacyZkX509CrlV1>();
        assert_native_registration::<privacy::RotatePrivacyZkX509CrlV1>();
        assert_native_registration::<privacy::RevokePrivacyZkX509CrlV1>();
        assert_native_registration::<privacy::SubmitPrivacyProofV1>();
        assert_reviewed_initial_family("iroha_data_model::isi::privacy::", BTreeSet::new());
        assert_reviewed_asset_effect_family(
            "iroha_data_model::isi::privacy::",
            29,
            BTreeSet::from([core::any::type_name::<privacy::SubmitPrivacyProofV1>()]),
        );
        assert_reviewed_asset_effect_family(
            "iroha_data_model::isi::private_settlement::",
            5,
            BTreeSet::new(),
        );
        assert_reviewed_initial_family(
            "iroha_data_model::isi::private_settlement::",
            BTreeSet::new(),
        );
    }
    #[test]
    fn default_instruction_registry_entries_have_core_dispatch_handlers() {
        let registry = iroha_data_model::isi::registry::default();
        let custom_instruction = std::any::type_name::<CustomInstruction>();
        let missing = registry
            .names()
            .filter(|name| *name != custom_instruction)
            .filter(|name| !has_dispatch_handler(name))
            .collect::<BTreeSet<_>>();
        assert!(
            missing.is_empty(),
            "default registry entries missing core dispatch handlers: {missing:?}"
        );
    }
    #[test]
    fn custom_instruction_is_only_default_registry_entry_without_core_dispatch_handler() {
        let registry = iroha_data_model::isi::registry::default();
        let missing = registry
            .names()
            .filter(|name| !has_dispatch_handler(name))
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([std::any::type_name::<CustomInstruction>()]);
        assert_eq!(
            missing, expected,
            "only CustomInstruction should require a custom executor"
        );
    }
    #[test]
    fn custom_instruction_stays_custom_executor_only() {
        let registry = iroha_data_model::isi::registry::default();
        let custom_instruction = std::any::type_name::<CustomInstruction>();
        assert!(
            registry.contains(
                registry
                    .wire_id(custom_instruction)
                    .expect("canonical CustomInstruction wire id")
            ),
            "custom instructions must remain decodable for custom executors"
        );
        assert!(
            !has_dispatch_handler(custom_instruction),
            "custom instructions must not be executable by the default core dispatcher"
        );
    }
    #[test]
    fn direct_grouped_variants_stay_out_of_default_registry_even_with_handlers() {
        let registry = iroha_data_model::isi::registry::default();
        let direct_variants = [
            std::any::type_name::<iroha_data_model::isi::register::RegisterPeerWithPop>(),
            std::any::type_name::<Mint<Quantity, Asset>>(),
            std::any::type_name::<Burn<Quantity, Asset>>(),
            std::any::type_name::<Transfer<Asset, Quantity, Account>>(),
            std::any::type_name::<SetKeyValue<Trigger>>(),
            std::any::type_name::<iroha_data_model::isi::repo::RepoIsi>(),
            std::any::type_name::<iroha_data_model::isi::repo::ReverseRepoIsi>(),
            std::any::type_name::<iroha_data_model::isi::repo::RepoMarginCallIsi>(),
            std::any::type_name::<iroha_data_model::isi::rwa::RegisterRwa>(),
            std::any::type_name::<iroha_data_model::isi::rwa::TransferRwa>(),
            std::any::type_name::<iroha_data_model::isi::rwa::MergeRwas>(),
            std::any::type_name::<iroha_data_model::isi::rwa::RedeemRwa>(),
            std::any::type_name::<iroha_data_model::isi::rwa::FreezeRwa>(),
            std::any::type_name::<iroha_data_model::isi::rwa::UnfreezeRwa>(),
            std::any::type_name::<iroha_data_model::isi::rwa::HoldRwa>(),
            std::any::type_name::<iroha_data_model::isi::settlement::DvpIsi>(),
            std::any::type_name::<iroha_data_model::isi::settlement::SettleAtomic>(),
            std::any::type_name::<iroha_data_model::isi::settlement::PvpIsi>(),
        ];
        for name in direct_variants {
            assert!(
                has_dispatch_handler(name),
                "{name} should remain an internal delegation target"
            );
            assert!(
                !registry.contains(name),
                "{name} is an internal handler target, not a public wire form"
            );
        }
    }
    #[test]
    fn removed_direct_stable_wire_ids_do_not_alias_boxed_dispatch_entries() {
        let registry = iroha_data_model::isi::registry::default();
        let removed_wire_ids = [
            iroha_data_model::isi::repo::RepoIsi::WIRE_ID,
            iroha_data_model::isi::repo::ReverseRepoIsi::WIRE_ID,
            iroha_data_model::isi::repo::RepoMarginCallIsi::WIRE_ID,
            iroha_data_model::isi::settlement::DvpIsi::WIRE_ID,
            iroha_data_model::isi::settlement::SettleAtomic::WIRE_ID,
            iroha_data_model::isi::settlement::PvpIsi::WIRE_ID,
        ];
        for wire_id in removed_wire_ids {
            assert!(
                !registry.contains(wire_id),
                "{wire_id} must not alias any default dispatcher entry"
            );
        }
    }
    #[test]
    fn retired_sns_mutations_have_no_native_dispatch_handler() {
        let registry = iroha_data_model::isi::registry::default();
        let removed_type_names = [
            "iroha_data_model::isi::sns::RegisterSnsName",
            "iroha_data_model::isi::sns::RenewSnsName",
            "iroha_data_model::isi::sns::TransferSnsName",
            "iroha_data_model::isi::sns::UpdateSnsNameControllers",
            "iroha_data_model::isi::sns::FreezeSnsName",
            "iroha_data_model::isi::sns::UnfreezeSnsName",
        ];
        let removed_wire_ids = [
            "iroha.sns.name.register",
            "iroha.sns.name.renew",
            "iroha.sns.name.transfer",
            "iroha.sns.name.controllers.update",
            "iroha.sns.name.freeze",
            "iroha.sns.name.unfreeze",
        ];
        for type_name in removed_type_names {
            assert!(!has_dispatch_handler(type_name));
            assert!(!registry.contains(type_name));
        }
        for wire_id in removed_wire_ids {
            assert!(!registry.contains(wire_id));
        }
    }
}
impl Execute for InstructionBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_borrowed_instruction(&self, authority, state_transaction)
    }
}
impl Execute for iroha_data_model::isi::InvalidInstruction {
    fn execute(
        self,
        _authority: &AccountId,
        _state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        Err(Error::from(format!(
            "invalid instruction payload: wire_id={} payload_hash={} message={}",
            self.wire_id,
            hex::encode(self.payload_hash),
            self.message
        )))
    }
}
impl Execute for RegisterBox {
    #[iroha_logger::log(name = "register", skip_all, fields(id))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Peer(isi) => isi.execute(authority, state_transaction),
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Nft(isi) => isi.execute(authority, state_transaction),
            Self::Role(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for UnregisterBox {
    #[iroha_logger::log(name = "unregister", skip_all, fields(id))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Peer(isi) => isi.execute(authority, state_transaction),
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Nft(isi) => isi.execute(authority, state_transaction),
            Self::Role(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for MintBox {
    #[iroha_logger::log(name = "Mint", skip_all, fields(destination))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Asset(isi) => isi.execute(authority, state_transaction),
            Self::TriggerRepetitions(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for BurnBox {
    #[iroha_logger::log(name = "burn", skip_all, fields(destination))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Asset(isi) => isi.execute(authority, state_transaction),
            Self::TriggerRepetitions(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for TransferBox {
    #[iroha_logger::log(name = "transfer", skip_all, fields(from, to))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Asset(isi) => isi.execute(authority, state_transaction),
            Self::Nft(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for SetKeyValueBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Nft(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for RemoveKeyValueBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Nft(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for iroha_data_model::isi::rwa::RwaInstructionBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Register(isi) => isi.execute(authority, state_transaction),
            Self::Transfer(isi) => isi.execute(authority, state_transaction),
            Self::Merge(isi) => isi.execute(authority, state_transaction),
            Self::Redeem(isi) => isi.execute(authority, state_transaction),
            Self::Freeze(isi) => isi.execute(authority, state_transaction),
            Self::Unfreeze(isi) => isi.execute(authority, state_transaction),
            Self::Hold(isi) => isi.execute(authority, state_transaction),
            Self::Release(isi) => isi.execute(authority, state_transaction),
            Self::ForceTransfer(isi) => isi.execute(authority, state_transaction),
            Self::SetControls(isi) => isi.execute(authority, state_transaction),
            Self::SetKeyValue(isi) => isi.execute(authority, state_transaction),
            Self::RemoveKeyValue(isi) => isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for GrantBox {
    #[iroha_logger::log(name = "grant", skip_all, fields(object))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Permission(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::Role(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::RolePermission(sub_isi) => sub_isi.execute(authority, state_transaction),
        }
    }
}
impl Execute for RevokeBox {
    #[iroha_logger::log(name = "revoke", skip_all, fields(object))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Permission(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::Role(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::RolePermission(sub_isi) => sub_isi.execute(authority, state_transaction),
        }
    }
}
pub mod prelude {
    //! Re-export important traits and types for glob import `(::*)`
    pub use super::*;
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::ValidBlock,
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
        tx::AcceptedTransaction,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        events::execute_trigger::ExecuteTriggerEventFilter,
        isi::error::{InstructionExecutionError, InvalidParameterError},
        permission,
    };
    use iroha_executor_data_model::permission::trigger::CanRegisterTrigger;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;

    use iroha_test_samples::{
        ALICE_ID, ALICE_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
        gen_account_in,
    };
    use std::sync::Arc;
    use tokio::test;
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("ISI module fixture key generation should succeed")
    }
    #[test]
    async fn checked_keypair_helper_preserves_default_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    }
    fn minimal_contract_artifact() -> (
        Vec<u8>,
        iroha_data_model::smart_contract::manifest::ContractManifest,
    ) {
        let meta = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 4,
            abi_version: 1,
        };
        let interface = ivm::EmbeddedContractInterfaceV1 {
            callables: vec![ivm::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm::call::CallSchemaV1::empty(),
                results: ivm::call::CallSchemaV1::unit(),
            }],
            seiyaku_name: "TestContract".to_owned(),
            compiler_fingerprint: "isi-mod-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: "main".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                permission: None,
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: None,
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let mut code = Vec::new();
        for instruction in [
            ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
            ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
        ] {
            code.extend_from_slice(&instruction.to_le_bytes());
        }
        let mut artifact = meta.encode();
        artifact.extend_from_slice(&interface.encode_section());
        artifact.extend_from_slice(&code);
        let verified = ivm::verify_contract_artifact(&artifact).expect("valid test contract");
        (artifact, verified.manifest)
    }
    fn state_with_test_domains(kura: &Arc<Kura>) -> Result<State> {
        let world = World::with([], [], []);
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura.clone(), query_handle);
        let asset_definition_id =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "rose".parse()?,
            );
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let wonderland: DomainId = DomainId::try_new("wonderland", "universal")?;
        Register::domain(Domain::new(wonderland.clone()))
            .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
        let trigger_perm: permission::Permission = CanRegisterTrigger {
            authority: ALICE_ID.clone(),
        }
        .into();
        Grant::account_permission(trigger_perm, ALICE_ID.clone())
            .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
        Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        Ok(state)
    }
    fn authenticated_instruction_state(genesis_instructions: Vec<InstructionBox>) -> State {
        use crate::sumeragi::{
            startup,
            test_chain::{CertifiedTestChain, TestChainConfig},
        };

        let mut config = TestChainConfig::new(World::default(), 0);
        config.genesis_key = SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone();
        config.genesis_instructions = genesis_instructions;
        let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
        let consensus_mode = config.consensus_mode;
        let prepared = CertifiedTestChain::prepare(config).expect("prepare signed ISI genesis");
        // Before spawning a worker, consume the original unique State and apply
        // its independently validated genesis. Root authority is never copied.
        let state = Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished ISI State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &genesis_account,
            consensus_mode.into(),
            None,
        )
        .expect("apply signed ISI genesis");
        state
    }
    fn authenticated_state_with_test_domains() -> Result<State> {
        let wonderland = DomainId::try_new("wonderland", "universal")?;
        let asset_definition_id =
            AssetDefinitionId::derive_from_components(wonderland.clone(), "rose".parse()?);
        let trigger_permission: permission::Permission = CanRegisterTrigger {
            authority: ALICE_ID.clone(),
        }
        .into();
        // These are the same original registrations and grant as the direct
        // component helper, now authored in the canonical signed genesis source.
        Ok(authenticated_instruction_state(vec![
            Register::domain(Domain::new(wonderland)).into(),
            Register::account(Account::new(ALICE_ID.clone())).into(),
            Grant::account_permission(trigger_permission, ALICE_ID.clone()).into(),
            Register::asset_definition(AssetDefinition::numeric(
                asset_definition_id,
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))
            .into(),
        ]))
    }
    fn ordinary_instruction_header(state: &State) -> BlockHeader {
        BlockHeader::new(
            std::num::NonZeroU64::new(
                u64::try_from(state.committed_height()).expect("ISI fixture height") + 1,
            )
            .expect("ordinary ISI successor"),
            state.view().latest_block_hash(),
            None,
            1_000,
            0,
        )
    }
    #[test]
    async fn authenticated_instruction_fixture_retains_original_registrations_and_root()
    -> Result<()> {
        let state = authenticated_state_with_test_domains()?;
        assert_eq!(state.committed_height(), 1);
        assert_eq!(state.kura().blocks_count(), 1);
        let genesis = state
            .kura()
            .get_block(
                std::num::NonZeroUsize::new(1).unwrap(),
                &state.ivm_execution_budget(),
            )
            .expect("completed original State read")
            .unwrap();
        assert_eq!(
            state.network_id_ref(),
            &NetworkId::from_genesis_hash(genesis.hash())
        );
        let signed =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&genesis)
                .expect("original signed ISI root metadata");
        let view = state.view();
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(view.world()),
            Some(signed.sumeragi_context.root_scope)
        );
        assert_eq!(ordinary_instruction_header(&state).height().get(), 2);
        assert_eq!(
            ordinary_instruction_header(&state).prev_block_hash(),
            Some(genesis.hash())
        );
        let wonderland = DomainId::try_new("wonderland", "universal")?;
        assert_eq!(
            view.world.domain(&wonderland)?.owned_by(),
            &*SAMPLE_GENESIS_ACCOUNT_ID
        );
        assert!(view.world.account(&ALICE_ID).is_ok());
        let rose = AssetDefinitionId::derive_from_components(wonderland, "rose".parse()?);
        assert_eq!(
            view.world.asset_definition(&rose)?.owned_by(),
            &*SAMPLE_GENESIS_ACCOUNT_ID
        );
        let trigger_permission: permission::Permission = CanRegisterTrigger {
            authority: ALICE_ID.clone(),
        }
        .into();
        assert!(
            view.world
                .account_permissions
                .get(&ALICE_ID)
                .unwrap()
                .contains(&trigger_permission)
        );
        Ok(())
    }
    #[test]
    async fn default_executor_rejects_invalid_instruction_placeholders() -> Result<()> {
        let state = authenticated_instruction_state(Vec::new());
        let mut state_block = state.block(ordinary_instruction_header(&state));
        let mut state_transaction = state_block.transaction();
        let instruction = InstructionBox::from(iroha_data_model::isi::InvalidInstruction::new(
            "iroha.register",
            [0xAB; 32],
            "malformed boxed payload",
        ));
        let err = execute_borrowed_instruction(&instruction, &ALICE_ID, &mut state_transaction)
            .expect_err("invalid instruction placeholders must fail execution");
        assert!(matches!(
            err,
            InstructionExecutionError::Conversion(message)
                if message.contains("invalid instruction payload")
                    && message.contains("wire_id=iroha.register")
                    && message.contains("malformed boxed payload")
        ));
        Ok(())
    }
    #[test]
    async fn default_executor_rejects_custom_instruction_without_custom_executor() -> Result<()> {
        let state = authenticated_instruction_state(Vec::new());
        let mut state_block = state.block(ordinary_instruction_header(&state));
        let mut state_transaction = state_block.transaction();
        let instruction = InstructionBox::from(CustomInstruction::new("requires custom executor"));
        let err = execute_borrowed_instruction(&instruction, &ALICE_ID, &mut state_transaction)
            .expect_err("custom instructions must not execute through the default dispatcher");
        assert!(matches!(
            err,
            InstructionExecutionError::Conversion(message)
                if message.contains("Custom instructions require an executor upgrade")
        ));
        Ok(())
    }
    #[test]
    async fn nft() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let nft_id: NftId = "rose$wonderland.universal".parse()?;
        let key = "Bytes".parse::<Name>()?;
        Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
            .execute(&account_id, &mut state_transaction)?;
        SetKeyValue::nft(nft_id.clone(), key.clone(), vec![1_u32, 2_u32, 3_u32])
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let state_view = state.view();
        let nft = state_view.world.nft(&nft_id)?;
        let value = nft.content.get(&key).cloned();
        assert_eq!(value, Some(vec![1_u32, 2_u32, 3_u32,].into()));
        Ok(())
    }
    #[test]
    async fn account_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let key = "Bytes".parse::<Name>()?;
        SetKeyValue::account(account_id.clone(), key.clone(), vec![1_u32, 2_u32, 3_u32])
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let bytes = state.view().world.map_account(&account_id, |account| {
            account.value().metadata().get(&key).cloned()
        })?;
        assert_eq!(bytes, Some(vec![1_u32, 2_u32, 3_u32,].into()));
        Ok(())
    }
    #[test]
    async fn account_metadata_limit() -> Result<()> {
        use iroha_data_model::{
            parameter::{CustomParameter, CustomParameterId},
            prelude::Parameter,
        };
        use iroha_primitives::json::Json;
        use std::str::FromStr as _;
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        // Set a very small metadata size limit via custom parameter
        let param_id = CustomParameterId::from_str("max_metadata_value_bytes")?;
        let small_limit = 16_u64;
        let set_param = SetParameter::new(Parameter::Custom(CustomParameter::new(
            param_id,
            Json::new(small_limit),
        )));
        set_param.execute(&account_id, &mut state_transaction)?;
        // Attempt to set a metadata value exceeding the limit
        let key = "TooBig".parse::<Name>()?;
        let big = Json::new("X".repeat(32)); // 32 > 16
        let res = SetKeyValue::account(account_id.clone(), key.clone(), big)
            .execute(&account_id, &mut state_transaction);
        assert!(matches!(res, Err(Error::InvalidParameter(_))));
        // Now lower the value and ensure it succeeds
        let ok = Json::new("Y".repeat(8));
        SetKeyValue::account(account_id.clone(), key.clone(), ok)
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        Ok(())
    }
    #[test]
    async fn registration_metadata_values_share_the_set_key_value_limit() -> Result<()> {
        use iroha_data_model::{
            asset::{AssetBalancePolicy, AssetDefinitionId},
            isi::rwa::RegisterRwa,
            parameter::{CustomParameter, CustomParameterId},
            prelude::Parameter,
            rwa::{NewRwa, RwaControlPolicy},
        };
        use iroha_primitives::json::Json;
        use iroha_primitives::numeric::{NumericSpec, Quantity};
        use std::str::FromStr as _;

        fn metadata_with_encoded_size(size: usize) -> Metadata {
            let value = Json::new("X".repeat(size.saturating_sub(2)));
            assert_eq!(
                value.get().len(),
                size,
                "fixture must hit the wire-size boundary"
            );
            let mut metadata = Metadata::default();
            metadata.insert("bounded".parse().expect("metadata key"), value);
            metadata
        }

        fn assert_metadata_limit(error: Error, entity: &str) {
            assert!(
                matches!(error, Error::InvalidParameter(_)),
                "oversized {entity} registration returned {error:?}"
            );
        }

        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let limit_id = CustomParameterId::from_str("max_metadata_value_bytes")?;
        SetParameter::new(Parameter::Custom(CustomParameter::new(
            limit_id,
            Json::new(16_u64),
        )))
        .execute(&ALICE_ID, &mut state_transaction)?;

        let exact = metadata_with_encoded_size(16);
        let oversized = metadata_with_encoded_size(17);

        let exact_account = AccountId::new(checked_keypair().public_key().clone());
        Register::account(Account::new(exact_account.clone()).with_metadata(exact.clone()))
            .execute(&ALICE_ID, &mut state_transaction)?;
        let oversized_account = AccountId::new(checked_keypair().public_key().clone());
        assert_metadata_limit(
            Register::account(
                Account::new(oversized_account.clone()).with_metadata(oversized.clone()),
            )
            .execute(&ALICE_ID, &mut state_transaction)
            .expect_err("oversized account metadata must fail"),
            "account",
        );
        assert!(state_transaction.world.account(&oversized_account).is_err());

        let exact_domain = DomainId::try_new("metadata-exact", "universal")?;
        Register::domain(Domain::new(exact_domain).with_metadata(exact.clone()))
            .execute(&ALICE_ID, &mut state_transaction)?;
        let oversized_domain = DomainId::try_new("metadata-oversized", "universal")?;
        assert_metadata_limit(
            Register::domain(
                Domain::new(oversized_domain.clone()).with_metadata(oversized.clone()),
            )
            .execute(&ALICE_ID, &mut state_transaction)
            .expect_err("oversized domain metadata must fail"),
            "domain",
        );
        assert!(state_transaction.world.domain(&oversized_domain).is_err());

        let wonderland = DomainId::try_new("wonderland", "universal")?;
        let exact_definition = AssetDefinitionId::derive_from_components(
            wonderland.clone(),
            "metadata_exact".parse()?,
        );
        Register::asset_definition(
            AssetDefinition::numeric(
                exact_definition,
                "metadata exact",
                AssetBalancePolicy::Global,
                None,
            )
            .with_metadata(exact.clone()),
        )
        .execute(&ALICE_ID, &mut state_transaction)?;
        let oversized_definition = AssetDefinitionId::derive_from_components(
            wonderland.clone(),
            "metadata_oversized".parse()?,
        );
        assert_metadata_limit(
            Register::asset_definition(
                AssetDefinition::numeric(
                    oversized_definition.clone(),
                    "metadata oversized",
                    AssetBalancePolicy::Global,
                    None,
                )
                .with_metadata(oversized.clone()),
            )
            .execute(&ALICE_ID, &mut state_transaction)
            .expect_err("oversized asset-definition metadata must fail"),
            "asset definition",
        );
        assert!(
            state_transaction
                .world
                .asset_definition(&oversized_definition)
                .is_err()
        );

        let exact_nft: NftId = "metadata_exact$wonderland.universal".parse()?;
        Register::nft(Nft::new(exact_nft, exact.clone()))
            .execute(&ALICE_ID, &mut state_transaction)?;
        let oversized_nft: NftId = "metadata_oversized$wonderland.universal".parse()?;
        assert_metadata_limit(
            Register::nft(Nft::new(oversized_nft.clone(), oversized.clone()))
                .execute(&ALICE_ID, &mut state_transaction)
                .expect_err("oversized NFT metadata must fail"),
            "NFT",
        );
        assert!(state_transaction.world.nft(&oversized_nft).is_err());

        state_transaction.tx_call_hash = Some(iroha_crypto::Hash::new(b"metadata-limit-rwa"));
        RegisterRwa {
            rwa: NewRwa::new(
                wonderland.clone(),
                "1".parse::<Quantity>()?,
                NumericSpec::integer(),
                "metadata-exact".to_owned(),
                None,
                exact,
                Vec::new(),
                RwaControlPolicy::default(),
            ),
        }
        .execute(&ALICE_ID, &mut state_transaction)?;
        let rwa_count = state_transaction.world.rwas.len();
        assert_metadata_limit(
            RegisterRwa {
                rwa: NewRwa::new(
                    wonderland,
                    "1".parse::<Quantity>()?,
                    NumericSpec::integer(),
                    "metadata-oversized".to_owned(),
                    None,
                    oversized,
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&ALICE_ID, &mut state_transaction)
            .expect_err("oversized RWA metadata must fail"),
            "RWA",
        );
        assert_eq!(state_transaction.world.rwas.len(), rwa_count);
        Ok(())
    }
    #[test]
    async fn register_contract_manifest_is_queryable_with_runtime_authority() -> Result<()> {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::{
            isi::smart_contract_code, permission, prelude as dm, query::smart_contract::prelude,
        };
        let state = authenticated_state_with_test_domains()?;
        let mut state_block = state.block(ordinary_instruction_header(&state));
        let mut stx = state_block.transaction();
        let alice = ALICE_ID.clone();
        let token =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
        let permission: permission::Permission = token.into();
        dm::Grant::account_permission(permission, alice.clone()).execute(&alice, &mut stx)?;
        let (code, manifest) = minimal_contract_artifact();
        let h = manifest.code_hash.expect("manifest code hash");
        smart_contract_code::RegisterSmartContractBytes {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                h,
            ),
            code,
        }
        .execute(&alice, &mut stx)?;
        let manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &ALICE_KEYPAIR,
            )
            .expect("sign bounded fixture manifest");
        {
            let scoped_manifest = manifest.clone();
            smart_contract_code::RegisterSmartContractCode {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    scoped_manifest
                        .code_hash
                        .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
                ),
                manifest: scoped_manifest,
            }
        }
        .execute(&alice, &mut stx)?;
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        // Verify it is stored
        let got = state
            .view()
            .world()
            .contract_manifests()
            .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                h,
            ))
            .cloned();
        assert_eq!(got, Some(manifest.clone()));
        // Verify query returns it
        let q = prelude::FindContractManifestByArtifactId {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                h,
            ),
        };
        let out = <_ as crate::smartcontracts::ValidSingularQuery<_>>::execute(&q, &state.view())?;
        assert_eq!(out, manifest);
        Ok(())
    }
    #[test]
    async fn register_contract_manifest_requires_provenance() -> Result<()> {
        use iroha_crypto::Hash;
        use iroha_data_model::{isi::smart_contract_code, permission, prelude as dm};
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut stx = state_block.transaction();
        let alice = ALICE_ID.clone();
        let h = Hash::new(b"dummy_code");
        let (_, mut manifest) = minimal_contract_artifact();
        manifest.code_hash = Some(h);
        manifest.provenance = None;
        let token =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
        let perm: permission::Permission = token.into();
        dm::Grant::account_permission(perm, alice.clone()).execute(&alice, &mut stx)?;
        let err = {
            let scoped_manifest = manifest;
            smart_contract_code::RegisterSmartContractCode {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    scoped_manifest
                        .code_hash
                        .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
                ),
                manifest: scoped_manifest,
            }
        }
        .execute(&alice, &mut stx)
        .expect_err("missing provenance must fail");
        match err {
            Error::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
                assert!(msg.contains("provenance"), "unexpected msg: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        Ok(())
    }
    #[test]
    async fn register_contract_manifest_rejects_wrong_signer() -> Result<()> {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_crypto::Hash;
        use iroha_data_model::{isi::smart_contract_code, permission, prelude as dm};
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut stx = state_block.transaction();
        let alice = ALICE_ID.clone();
        let h = Hash::new(b"dummy_code");
        let (_, mut manifest) = minimal_contract_artifact();
        manifest.code_hash = Some(h);
        let manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &checked_keypair(),
            )
            .expect("sign bounded fixture manifest");
        let token =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
        let perm: permission::Permission = token.into();
        dm::Grant::account_permission(perm, alice.clone()).execute(&alice, &mut stx)?;
        let err = {
            let scoped_manifest = manifest;
            smart_contract_code::RegisterSmartContractCode {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    scoped_manifest
                        .code_hash
                        .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
                ),
                manifest: scoped_manifest,
            }
        }
        .execute(&alice, &mut stx)
        .expect_err("wrong signer must fail");
        match err {
            Error::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
                assert!(
                    msg.contains("not authorised"),
                    "unexpected msg for wrong signer: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        Ok(())
    }
    #[test]
    async fn burning_trigger_to_zero_removes_it() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let trigger_id = "will_be_removed".parse::<TriggerId>()?;
        // Register the trigger with Exactly(1) repeats
        let register_trigger = Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(account_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        register_trigger.execute(&account_id, &mut state_transaction)?;
        // Burn 1 repeat to reach zero; the trigger should be removed immediately
        Burn::trigger_repetitions(1, trigger_id.clone())
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        // Verify trigger is no longer active
        let active = state
            .view()
            .world
            .triggers()
            .inspect_by_id(&trigger_id, |_| ())
            .is_some();
        assert!(!active, "trigger should be removed at zero repeats");
        Ok(())
    }
    #[test]
    async fn registering_zero_repeat_trigger_is_rejected() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let trigger_id = "no_effect".parse::<TriggerId>()?;
        // Attempt to register a trigger with Exactly(0) repeats
        let register_trigger = Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(0),
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(account_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        let error = register_trigger
            .execute(&account_id, &mut state_transaction)
            .expect_err("a depleted trigger must not be accepted for registration");
        assert!(matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message == "trigger repeat count must be greater than zero"
        ));
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        // Rejection must leave trigger state unchanged.
        let active = state
            .view()
            .world
            .triggers()
            .inspect_by_id(&trigger_id, |_| ())
            .is_some();
        assert!(!active, "a rejected zero-repeat trigger must not be stored");
        Ok(())
    }
    #[test]
    async fn register_box_trigger_executes() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let trigger_id = "boxed_trigger".parse::<TriggerId>()?;
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(ALICE_ID.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        RegisterBox::Trigger(Register::trigger(trigger))
            .execute(&ALICE_ID, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let registered = state
            .view()
            .world
            .triggers()
            .inspect_by_id(&trigger_id, |_| ())
            .is_some();
        assert!(registered, "trigger should be registered via RegisterBox");
        Ok(())
    }
    #[test]
    async fn asset_definition_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let account_id = ALICE_ID.clone();
        let key = "Bytes".parse::<Name>()?;
        SetKeyValue::asset_definition(
            definition_id.clone(),
            key.clone(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let value = state
            .view()
            .world
            .asset_definition(&definition_id)?
            .metadata()
            .get(&key)
            .cloned();
        assert_eq!(value, Some(vec![1_u32, 2_u32, 3_u32,].into()));
        Ok(())
    }
    #[test]
    async fn instruction_box_handles_asset_metadata() -> Result<()> {
        let state = authenticated_state_with_test_domains()?;
        let mut state_block = state.block(ordinary_instruction_header(&state));
        let mut state_transaction = state_block.transaction_for_fastpq_testing(
            iroha_crypto::Hash::new(b"instruction_box_handles_asset_metadata"),
        );
        let account_id = ALICE_ID.clone();
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        Mint::asset_quantity(1_u32, asset_id.clone())
            .execute(&account_id, &mut state_transaction)?;
        let key = "note".parse::<Name>()?;
        let value = Json::from(norito::json!("demo"));
        InstructionBox::from(SetAssetKeyValue::new(asset_id.clone(), key.clone(), value))
            .execute(&account_id, &mut state_transaction)?;
        InstructionBox::from(RemoveAssetKeyValue::new(asset_id.clone(), key))
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        let metadata = view.world.asset_metadata().get(&asset_id);
        assert!(metadata.is_none(), "asset metadata should be cleared");
        Ok(())
    }
    #[test]
    async fn domain_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let domain_id = DomainId::try_new("wonderland", "universal")?;
        let account_id = ALICE_ID.clone();
        let key = "Bytes".parse::<Name>()?;
        SetKeyValue::domain(domain_id.clone(), key.clone(), vec![1_u32, 2_u32, 3_u32])
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let bytes = state
            .view()
            .world
            .domain(&domain_id)?
            .metadata()
            .get(&key)
            .cloned();
        assert_eq!(bytes, Some(vec![1_u32, 2_u32, 3_u32,].into()));
        Ok(())
    }
    #[test]
    async fn executing_unregistered_trigger_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let trigger_id = "test_trigger_id".parse()?;
        assert!(matches!(
            ExecuteTrigger::new(trigger_id)
                .execute(&account_id, &mut state_transaction)
                .expect_err("Error expected"),
            Error::Find(_)
        ));
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        Ok(())
    }
    #[test]
    async fn unauthorized_trigger_execution_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction_for_callback_testing();
        let account_id = ALICE_ID.clone();
        let (fake_account_id, _fake_account_keypair) = gen_account_in("wonderland");
        let trigger_id = "test_trigger_id".parse::<TriggerId>()?;
        // register fake account
        let register_account = Register::account(Account::new(fake_account_id.clone()));
        register_account.execute(&account_id, &mut state_transaction)?;
        // register the trigger
        let register_trigger = Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(account_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        register_trigger.execute(&account_id, &mut state_transaction)?;
        // execute with the valid account
        ExecuteTrigger::new(trigger_id.clone()).execute(&account_id, &mut state_transaction)?;
        // execute with the fake account
        assert!(matches!(
            ExecuteTrigger::new(trigger_id)
                .execute(&fake_account_id, &mut state_transaction)
                .expect_err("Error expected"),
            Error::InvalidParameter(InvalidParameterError::SmartContract(message))
                if message.contains("trigger cannot be executed manually")
        ));
        state_transaction
            .apply_callback_for_testing()
            .expect("capture successful component callbacks");
        state_block.commit_world_overlay_for_testing().unwrap();
        Ok(())
    }
    #[test]
    async fn time_trigger_with_single_execution_is_not_mintable() -> Result<()> {
        use iroha_data_model::events::time::{ExecutionTime, Schedule, TimeEventFilter};
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let trigger_id = "single_time".parse::<TriggerId>()?;
        // Schedule with no period (single execution) is not mintable; repeats must be Exactly(1)
        let filter = TimeEventFilter::new(ExecutionTime::Schedule(Schedule {
            start_ms: 0,
            period_ms: None,
        }));
        let bad = Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(2), // invalid for non-mintable filter
                account_id.clone(),
                filter,
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        assert!(matches!(
            bad.execute(&account_id, &mut state_transaction)
                .expect_err("expected error"),
            Error::Math(_)
        ));
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        Ok(())
    }
    #[test]
    async fn not_allowed_to_register_genesis_domain_but_genesis_account_can_be_linked() -> Result<()>
    {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(checked_keypair().private_key())
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        assert!(matches!(
            Register::domain(Domain::new(DomainId::try_new("genesis", "universal")?))
                .execute(&account_id, &mut state_transaction)
                .expect_err("Error expected"),
            Error::InvariantViolation(_)
        ));
        Register::account(Account::new(SAMPLE_GENESIS_ACCOUNT_ID.clone()))
            .execute(&account_id, &mut state_transaction)?;
        let genesis_account = state_transaction
            .world
            .account(&SAMPLE_GENESIS_ACCOUNT_ID)?;
        assert!(
            genesis_account.id() == &*SAMPLE_GENESIS_ACCOUNT_ID,
            "genesis account should remain canonical after registration"
        );
        state_transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        Ok(())
    }
    #[test]
    async fn transaction_signed_by_genesis_account_is_statelessly_accepted() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction())
        };
        let tx = TransactionBuilder::new(
            state.network_id,
            SAMPLE_GENESIS_ACCOUNT_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "genesis stateless admission".to_owned(),
        )])
        .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
        let crypto_cfg = state.crypto();
        let (_clock, time_source) =
            iroha_primitives::time::TimeSource::new_mock(tx.creation_time());
        assert!(
            AcceptedTransaction::accept_with_time_source(
                tx,
                &state.network_id,
                max_clock_drift,
                tx_limits,
                crypto_cfg.as_ref(),
                &time_source,
            )
            .is_ok(),
            "stateless admission should not special-case genesis authority"
        );
        Ok(())
    }
}
