// Detached executor note: Keep this handler minimal and side-effect free; record only deltas.
// Perform complex checks during `StateBlock::merge_into`; extend cautiously for new ISIs.
//! Structures and impls related to processing Iroha Virtual Machine (IVM) runtime executors.
#[cfg(feature = "zk-preverify")]
use crate::zk::PreverifyResult;
use crate::{
    gas as isi_gas,
    smartcontracts::{
        Execute as _, code,
        ivm::cache::{ExecutableProgramSummary, IvmCache, ProgramSummary},
    },
    state::{
        StateReadOnly, StateTransaction, WorldReadOnly, fee_sponsor_revision_safe_activation_height,
    },
    status::{self, NexusFeeEvent, NexusFeePayer},
};
use base64::Engine as _;
use core::{
    convert::TryFrom,
    ops::{Deref, DerefMut},
    str::FromStr,
};
use derive_more::Debug;
use iroha_config::parameters::actual::{GasLiquidity, GasVolatility, NexusFees, Pipeline};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_data_model::nexus::{
    VERIFIED_FEE_SPONSOR_VAULT_ALLOCATION_STATE_KEY_PREFIX, VerifiedFeeSponsorVaultAllocation,
};
#[cfg(test)]
use iroha_data_model::prelude::Domain;
use iroha_data_model::smart_contract::manifest::{
    ContractPermissionScopeV1, EntrypointAuthorizationV1,
};
use iroha_data_model::{
    Identifiable as _, ValidationFail,
    account::AccountId,
    asset::{
        AssetBalancePolicy, AssetDefinition, ResolvedAssetDefinitionAliasV1,
        id::{AssetBalanceScope, AssetDefinitionId, AssetId},
        value::Asset,
    },
    block::BlockHeader,
    executor::{self as data_model_executor, ExecutorDataModel},
    isi::{
        CustomInstruction, Grant, GrantBox, InstructionBox, InstructionBox as DMInstructionBox,
        RemoveKeyValueBox, Revoke, RevokeBox, SetKeyValueBox, TransferBox, UnregisterBox,
        error::InstructionExecutionError, mint_burn::MintBox, register::RegisterBox,
    },
    nexus::{
        FeeDebitSource, FeeRejectionCode, FeeSponsorBeneficiaryEpochBudgetWindow,
        FeeSponsorBlockBudgetWindow, FeeSponsorBudgetCounter, FeeSponsorBudgetCounterKey,
        FeeSponsorBudgetWindow, FeeSponsorEligibility, FeeSponsorEnrollmentKey,
        FeeSponsorMultisigOperation, FeeSponsorProgramEpochBudgetWindow, FeeSponsorProgramId,
        FeeSponsorProgramLifecycle, FeeSponsorProgramRevision, FeeSponsorProgramRevisionKey,
        FeeSponsorRuleEffect, FeeSponsorRuleSelector, FeeSponsorVaultKey,
    },
    parameter::CustomParameterId,
    permission::Permission,
    prelude::{Account, Burn, Mint, Register, Transfer, Trigger, Unregister},
    query::{
        self as data_model_query, AnyQueryBox, QueryItemKind, QueryRequest, QueryWithParams,
        SingularQueryBox,
    },
    role::{Role, RoleId},
    smart_contract::payloads::{ExecutorContext, Validate as ValidatePayload},
    transaction::{
        Executable, ExecutableBatchItem, FeeChargeKind, FeeChargeLimit, FeePaymentIntent,
        SignedTransaction, executable::ContractInvocation, signed::TransactionPayload,
    },
    trigger::TriggerId,
};
use iroha_executor_data_model::{
    isi::multisig::MultisigInstructionBox, permission as executor_permission,
};
use iroha_logger::{debug, trace, warn};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::state_path::StatePath;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{
    json::Json,
    numeric::{Numeric, Quantity},
};
use ivm::runtime::IvmConfig;
use ivm::{IVM, Memory, RuntimeTemplate, VMError};
use mv::storage::StorageReadOnly;
use norito::{
    codec::{Decode, Encode},
    json::{self, JsonDeserialize as JsonDeserializeTrait, JsonSerialize as JsonSerializeTrait},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};
#[path = "executor_execution_fee.rs"]
mod execution_fee;
mod fee_sponsor_multisig;
pub(crate) mod private_fees;
/// Authenticated root scope for native and contract-generated instruction effects.
pub(crate) mod root_scope;
pub(crate) use execution_fee::{
    ExecutionFeeExemption, ExecutionFeeMeter, ExecutionFeeSettlementError,
};
#[path = "executor_execution_effects.rs"]
mod execution_effects;
pub(crate) use execution_effects::ExecutionEffects;
#[path = "executor_fastpq_rejection_tail.rs"]
mod fastpq_rejection_tail;
/// Signature-bound inputs already captured before executable dispatch.
struct RawIvmTransactionInputs {
    metadata: Metadata,
    gas_limit_md: Option<u64>,
    gas_asset_opt: Option<String>,
    fee_sponsor: Option<FeeSponsorProgramId>,
    skip_nexus_fee: bool,
    tx_bytes_len: usize,
}

/// One-shot proof that the executor debited one exact sponsored fee charge.
pub(crate) struct VerifiedFeeSponsorCharge {
    submitting_authority: AccountId,
    program_id: FeeSponsorProgramId,
    kind: FeeChargeKind,
    source_id: AssetId,
    destination: Option<AccountId>,
    amount: Quantity,
    // Retained only from the original executor invocation after its signed fee
    // limit and sponsor debit checks. Test-only capability fixtures leave this
    // absent and cannot establish quantity-source ownership.
    quantity_source: Option<(Hash, Hash, u64)>,
}
impl VerifiedFeeSponsorCharge {
    fn transfer(
        submitting_authority: AccountId,
        program_id: FeeSponsorProgramId,
        kind: FeeChargeKind,
        source_id: AssetId,
        destination: AccountId,
        amount: Quantity,
        quantity_source: Option<(Hash, Hash, u64)>,
    ) -> Self {
        Self {
            submitting_authority,
            program_id,
            kind,
            source_id,
            destination: Some(destination),
            amount,
            quantity_source,
        }
    }
    fn burn(
        submitting_authority: AccountId,
        program_id: FeeSponsorProgramId,
        kind: FeeChargeKind,
        source_id: AssetId,
        amount: Quantity,
        quantity_source: Option<(Hash, Hash, u64)>,
    ) -> Self {
        Self {
            submitting_authority,
            program_id,
            kind,
            source_id,
            destination: None,
            amount,
            quantity_source,
        }
    }
    #[cfg(test)]
    pub(crate) fn transfer_for_test(
        submitting_authority: AccountId,
        program_id: FeeSponsorProgramId,
        source_id: AssetId,
        destination: AccountId,
        amount: Quantity,
    ) -> Self {
        Self::transfer(
            submitting_authority,
            program_id,
            FeeChargeKind::PipelineGas,
            source_id,
            destination,
            amount,
            None,
        )
    }
    #[cfg(test)]
    pub(crate) fn burn_for_test(
        submitting_authority: AccountId,
        program_id: FeeSponsorProgramId,
        source_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self::burn(
            submitting_authority,
            program_id,
            FeeChargeKind::Nexus,
            source_id,
            amount,
            None,
        )
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        AccountId,
        FeeSponsorProgramId,
        FeeChargeKind,
        AssetId,
        Option<AccountId>,
        Quantity,
        Option<(Hash, Hash, u64)>,
    ) {
        (
            self.submitting_authority,
            self.program_id,
            self.kind,
            self.source_id,
            self.destination,
            self.amount,
            self.quantity_source,
        )
    }
}
// NoritoDecode alias is unused; keep Decode via norito::codec where needed inline
const EXECUTOR_LENGTH_PREFIX_BYTES: usize = 8;
const EXECUTOR_LENGTH_PREFIX_BYTES_U64: u64 = 8;
/// Maximum accepted size of one framed executor result, including its prefix.
///
/// Executor results conventionally share the VM's one-MiB heap window with their input. Keeping the
/// host-side limit at that deterministic region size prevents a guest-controlled length prefix from
/// requesting an unbounded host allocation, while retaining the entire addressable result envelope.
const MAX_EXECUTOR_OUTPUT_BYTES: u64 = Memory::HEAP_MAX_SIZE;
#[derive(Debug, Clone, PartialEq, Eq)]
enum NativeQueryAccess {
    /// Control-plane or public-definition data available to any registered account.
    Registered,
    /// Private data for one exact account.
    Account(AccountId),
    /// Exact account identity or direct permissions eligible for scoped DPN enrollment checks.
    EnrollmentAccount(AccountId),
    /// Ledger-wide state requiring the genesis-issued read root.
    AllLedger,
}
fn decode_native_iterable_payload_exact<Q>(payload: &[u8]) -> Option<Q>
where
    Q: Decode + Encode,
{
    let mut input = payload;
    let query = Q::decode(&mut input).ok()?;
    (query.encode() == payload).then_some(query)
}
#[allow(clippy::too_many_lines)]
fn native_singular_query_access(query: &SingularQueryBox) -> NativeQueryAccess {
    match query {
        SingularQueryBox::FindAccountById(query) => {
            NativeQueryAccess::EnrollmentAccount(query.account_id().clone())
        }
        SingularQueryBox::FindAliasesByAccountId(query) => {
            NativeQueryAccess::Account(query.account_id().clone())
        }
        SingularQueryBox::FindAssetById(query) => {
            NativeQueryAccess::Account(query.asset_id().account().clone())
        }
        SingularQueryBox::FindFeeSponsorProgramById(query) => {
            NativeQueryAccess::Account(query.id().sponsor.clone())
        }
        // Runtime/control-plane definitions and explicitly routed subsystem state do not expose
        // the general account roster, balances, or transaction history. Alias reads still pass
        // through their separate exact-scope gate below, and protected SoraFS records pass
        // through the subsystem-specific gates.
        SingularQueryBox::FindExecutorDataModel(_)
        | SingularQueryBox::FindGameSessionById(_)
        | SingularQueryBox::FindExecutionProofVerificationById(_)
        | SingularQueryBox::FindParameters(_)
        | SingularQueryBox::FindAccountRecoveryPolicyByAlias(_)
        | SingularQueryBox::FindAccountRecoveryRequestByAlias(_)
        | SingularQueryBox::FindContractManifestByArtifactId(_)
        | SingularQueryBox::FindAbiVersion(_)
        | SingularQueryBox::FindAssetDefinitionById(_)
        | SingularQueryBox::FindAssetDefinitionDirectHome(_)
        | SingularQueryBox::FindOracleFeedById(_)
        | SingularQueryBox::FindDomainEndorsementPolicy(_)
        | SingularQueryBox::FindDomainCommittee(_)
        | SingularQueryBox::FindSorafsProviderOwner(_)
        | SingularQueryBox::FindSorafsPinManifest(_)
        | SingularQueryBox::FindSorafsPinManifests(_)
        | SingularQueryBox::FindSorafsOrderbookPolicy(_)
        | SingularQueryBox::FindSorafsOrderbookOrderById(_)
        | SingularQueryBox::FindSorafsOrderbookCancellationByOrderId(_)
        | SingularQueryBox::FindSorafsOrderbookReceiptById(_)
        | SingularQueryBox::FindSorafsOrderbookTradeById(_)
        | SingularQueryBox::FindSorafsOrderbookChannelById(_)
        | SingularQueryBox::FindSorafsOrderbookStatus(_)
        | SingularQueryBox::FindSorafsOrderbookOrders(_)
        | SingularQueryBox::FindSorafsOrderbookReceipts(_)
        | SingularQueryBox::FindSorafsOrderbookTrades(_)
        | SingularQueryBox::FindSorafsOrderbookChannels(_)
        | SingularQueryBox::FindSorafsOrderbookEvents(_)
        | SingularQueryBox::FindSorafsReservePolicy(_)
        | SingularQueryBox::FindSorafsReserveProviderById(_)
        | SingularQueryBox::FindSorafsReserveMovementById(_)
        | SingularQueryBox::FindSorafsReserveAppealById(_)
        | SingularQueryBox::FindSorafsReserveProviders(_)
        | SingularQueryBox::FindSorafsReserveMovements(_)
        | SingularQueryBox::FindSorafsReserveAppeals(_)
        | SingularQueryBox::FindSorafsReserveEvents(_)
        | SingularQueryBox::FindSorafsPopIssuerPolicy(_)
        | SingularQueryBox::FindSorafsPopCredentialCommitmentByDigest(_)
        | SingularQueryBox::FindSorafsPopCommitmentRootByVersion(_)
        | SingularQueryBox::FindSorafsPopRevocationPublicationByVersion(_)
        | SingularQueryBox::FindSorafsPopRevocationByNonceCommitment(_)
        | SingularQueryBox::FindSorafsPopAuditDigestBySequence(_)
        | SingularQueryBox::FindSorafsPopRegistryStatus(_)
        | SingularQueryBox::FindSorafsRepairTask(_)
        | SingularQueryBox::FindSorafsRepairTasks(_)
        | SingularQueryBox::FindSorafsRepairStatus(_)
        | SingularQueryBox::FindSorafsRepairEvents(_)
        | SingularQueryBox::FindSorafsProofOutcome(_)
        | SingularQueryBox::FindSorafsProofOutcomeEvents(_)
        | SingularQueryBox::FindSorafsReputationJournalAuthorityPolicy(_)
        | SingularQueryBox::FindSorafsReputationJournalEventBySourceId(_)
        | SingularQueryBox::FindSorafsReputationJournalEvents(_)
        | SingularQueryBox::FindSorafsModerationPolicy(_)
        | SingularQueryBox::FindSorafsModerationAppeal(_)
        | SingularQueryBox::FindSorafsModerationJurorEligibility(_)
        | SingularQueryBox::FindSorafsModerationCase(_)
        | SingularQueryBox::FindSorafsModerationCommit(_)
        | SingularQueryBox::FindSorafsModerationReveal(_)
        | SingularQueryBox::FindSorafsModerationChallenge(_)
        | SingularQueryBox::FindSorafsModerationOutcome(_)
        | SingularQueryBox::FindSorafsModerationNoShow(_)
        | SingularQueryBox::FindSorafsModerationStatus(_)
        | SingularQueryBox::FindSorafsModerationSnapshot(_)
        | SingularQueryBox::FindSorafsModerationEvents(_)
        | SingularQueryBox::FindDataspaceNameOwnerById(_)
        | SingularQueryBox::FindMusubiExactPackageV1(_)
        | SingularQueryBox::FindMusubiExactReleaseV1(_)
        | SingularQueryBox::FindMusubiProviderBundleAttestationV1(_)
        | SingularQueryBox::FindMusubiResolverIndexV1(_)
        | SingularQueryBox::FindMusubiVersionsV1(_)
        | SingularQueryBox::FindMusubiMaintainersV1(_)
        | SingularQueryBox::FindMusubiArchiveLocationsV1(_)
        | SingularQueryBox::FindMusubiArchiveRetentionV1(_)
        | SingularQueryBox::FindMusubiAliasV1(_)
        | SingularQueryBox::FindMusubiAliasHistoryV1(_)
        | SingularQueryBox::FindMusubiOrderedPrefixV1(_)
        | SingularQueryBox::FindAccountByAlias(_)
        | SingularQueryBox::FindDomainById(_) => NativeQueryAccess::Registered,
        SingularQueryBox::FindProofRecordById(_)
        | SingularQueryBox::FindAssetEscrowById(_)
        | SingularQueryBox::FindTriggerById(_)
        | SingularQueryBox::FindTwitterBindingByHash(_)
        | SingularQueryBox::FindOracleDisputeById(_)
        | SingularQueryBox::FindOracleChangeById(_)
        | SingularQueryBox::FindOracleProviderStatsByKey(_)
        | SingularQueryBox::FindLatestDefiOracleAttestation(_)
        | SingularQueryBox::FindDomainEndorsements(_)
        | SingularQueryBox::FindDaPinIntentByTicket(_)
        | SingularQueryBox::FindDaPinIntentByManifest(_)
        | SingularQueryBox::FindDaPinIntentByAlias(_)
        | SingularQueryBox::FindDaPinIntentByLaneEpochSequence(_)
        | SingularQueryBox::FindFxCorridorPolicyRegistry(_)
        | SingularQueryBox::FindFxCorridorPolicyById(_)
        | SingularQueryBox::FindSettlementReceiptById(_)
        | SingularQueryBox::FindSorafsCitizenBondBySerialCommitment(_)
        | SingularQueryBox::FindSorafsCitizenBondSnapshot(_)
        | SingularQueryBox::FindNftById(_)
        | SingularQueryBox::FindNftSaleOfferById(_) => NativeQueryAccess::AllLedger,
    }
}
#[allow(clippy::too_many_lines)]
fn native_iterable_query_access(
    query: &QueryWithParams,
) -> Result<NativeQueryAccess, ValidationFail> {
    macro_rules! payload_for {
        ($item:ty, $kind:ident) => {{ (query.item == QueryItemKind::$kind).then_some(query.query_payload.as_slice()) }};
    }
    macro_rules! any_exact {
        ($payload:expr; $($query_ty:path),+ $(,)?) => {
            false $(|| decode_native_iterable_payload_exact::<$query_ty>($payload).is_some())+
        };
    }
    if let Some(payload) = payload_for!(iroha_data_model::role::Role, Role) {
        if any_exact!(payload; data_model_query::role::prelude::FindRoles) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(RoleId, RoleId) {
        if any_exact!(payload; data_model_query::role::prelude::FindRoleIds) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::role::prelude::FindRolesByAccountId,
        >(payload)
        {
            return Ok(NativeQueryAccess::Account(query.account_id().clone()));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(Permission, Permission) {
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::permission::prelude::FindPermissionsByAccountId,
        >(payload)
        {
            return Ok(NativeQueryAccess::EnrollmentAccount(
                query.account_id().clone(),
            ));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(Account, Account) {
        if any_exact!(
            payload;
            data_model_query::account::prelude::FindAccounts,
            data_model_query::account::prelude::FindAccountsWithAsset,
        ) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(AccountId, AccountId) {
        if any_exact!(payload; data_model_query::account::prelude::FindAccountIds) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::asset::value::Asset, Asset) {
        if any_exact!(payload; data_model_query::asset::prelude::FindAssets) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::asset::prelude::FindAssetsByAccountId,
        >(payload)
        {
            return Ok(NativeQueryAccess::Account(query.account_id().clone()));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::asset::definition::AssetDefinition,
        AssetDefinition
    ) {
        if any_exact!(payload; data_model_query::asset::prelude::FindAssetDefinitions) {
            // Listing every definition would disclose privately homed definitions.
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::repo::RepoAgreement, RepoAgreement) {
        if any_exact!(payload; data_model_query::repo::FindRepoAgreements) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::nft::Nft, Nft) {
        if any_exact!(payload; data_model_query::nft::prelude::FindNfts) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::nft::prelude::FindNftsByAccountId,
        >(payload)
        {
            return Ok(NativeQueryAccess::Account(query.account_id().clone()));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::rwa::Rwa, Rwa) {
        if any_exact!(payload; data_model_query::rwa::prelude::FindRwas) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::domain::Domain, Domain) {
        if any_exact!(payload; data_model_query::domain::prelude::FindDomains) {
            return Ok(NativeQueryAccess::Registered);
        }
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::domain::prelude::FindDomainsByAccountId,
        >(payload)
        {
            return Ok(NativeQueryAccess::Account(query.account_id().clone()));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_model_base::peer::PeerId, PeerId) {
        if any_exact!(payload; data_model_query::peer::prelude::FindPeers) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(TriggerId, TriggerId) {
        if any_exact!(payload; data_model_query::trigger::prelude::FindActiveTriggerIds) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(Trigger, Trigger) {
        if any_exact!(payload; data_model_query::trigger::prelude::FindTriggers) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) =
        payload_for!(data_model_query::CommittedTransaction, CommittedTransaction)
    {
        if any_exact!(
            payload;
            data_model_query::transaction::prelude::FindTransactions
        ) {
            if let Ok(Some(authority)) = query.exact_transaction_read_authority_with_limits(
                norito::canonical_decode_limits(query.predicate_bytes.len()),
            ) {
                return Ok(NativeQueryAccess::Account(authority));
            }
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::block::SignedBlock, SignedBlock) {
        if any_exact!(payload; data_model_query::block::prelude::FindBlocks) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(BlockHeader, BlockHeader) {
        if any_exact!(payload; data_model_query::block::prelude::FindBlockHeaders) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::proof::ProofRecord, ProofRecord) {
        if any_exact!(
            payload;
            data_model_query::proof::prelude::FindProofRecords,
            data_model_query::proof::prelude::FindProofRecordsByBackend,
            data_model_query::proof::prelude::FindProofRecordsByStatus,
        ) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::nexus::FeeSponsorProgram,
        FeeSponsorProgram
    ) {
        if any_exact!(payload; data_model_query::nexus::prelude::FindFeeSponsorPrograms) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::nexus::prelude::FindFeeSponsorProgramsBySponsor,
        >(payload)
        {
            return Ok(NativeQueryAccess::Account(query.sponsor().clone()));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::nexus::FeeSponsorProgramId,
        FeeSponsorProgramId
    ) {
        if any_exact!(payload; data_model_query::nexus::prelude::FindFeeSponsorProgramIds) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::oracle::FeedConfig, OracleFeedConfig) {
        if any_exact!(payload; data_model_query::oracle::prelude::FindOracleFeeds) {
            return Ok(NativeQueryAccess::Registered);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::events::data::oracle::FeedEventRecord,
        OracleFeedEventRecord
    ) {
        if any_exact!(payload; data_model_query::oracle::prelude::FindOracleHistoryByFeedId) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::oracle::OracleProviderStatsRecord,
        OracleProviderStatsRecord
    ) {
        if any_exact!(payload; data_model_query::oracle::prelude::FindOracleProviderStatsByFeedId) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(iroha_data_model::oracle::OracleDispute, OracleDispute) {
        if any_exact!(
            payload;
            data_model_query::oracle::prelude::FindOracleDisputes,
            data_model_query::oracle::prelude::FindOracleDisputesByFeedId,
        ) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::oracle::OracleChangeProposal,
        OracleChangeProposal
    ) {
        if any_exact!(payload; data_model_query::oracle::prelude::FindOracleChanges) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::oracle::TwitterBindingRecord,
        TwitterBindingRecord
    ) {
        if any_exact!(payload; data_model_query::oracle::prelude::FindTwitterBindingsByUaid) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::oracle::DefiOracleAttestation,
        DefiOracleAttestation
    ) {
        if any_exact!(payload; data_model_query::oracle::prelude::FindDefiOracleAttestationsByKey) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::escrow::AssetEscrowRecord,
        AssetEscrowRecord
    ) {
        if any_exact!(payload; data_model_query::escrow::prelude::FindAssetEscrows) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::escrow::AssetEscrowRecord,
        AssetEscrowsBySeller
    ) {
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::escrow::prelude::FindAssetEscrowsBySeller,
        >(payload)
        {
            return Ok(NativeQueryAccess::Account(query.seller.clone()));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::escrow::AssetEscrowRecord,
        AssetEscrowsByBuyer
    ) {
        if let Some(query) = decode_native_iterable_payload_exact::<
            data_model_query::escrow::prelude::FindAssetEscrowsByBuyer,
        >(payload)
        {
            return Ok(NativeQueryAccess::Account(query.buyer.clone()));
        }
        return Err(invalid_native_iterable_query());
    }
    if let Some(payload) = payload_for!(
        iroha_data_model::escrow::AssetEscrowRecord,
        AssetEscrowsByStatus
    ) {
        if any_exact!(payload; data_model_query::escrow::prelude::FindAssetEscrowsByStatus) {
            return Ok(NativeQueryAccess::AllLedger);
        }
        return Err(invalid_native_iterable_query());
    }
    Err(invalid_native_iterable_query())
}
fn invalid_native_iterable_query() -> ValidationFail {
    ValidationFail::NotPermitted(
        "iterable query is malformed or is not part of the native authorization matrix".to_owned(),
    )
}
/// Return whether one of the two exact native enrollment observations is permitted by a direct
/// domain-scoped DPN capability and the target's current UAID/SNS binding.
///
/// This narrow predicate is also used by Torii route admission. It never authorizes balances,
/// roster queries, alias lists, roles, or arbitrary reads from the same restricted dataspace.
///
/// # Errors
/// Returns native state or permission decoding errors without treating malformed state as absent.
pub fn can_observe_dpn_enrollment_query(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    query: &QueryRequest,
    now_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let access = match query {
        QueryRequest::Singular(query) => native_singular_query_access(query),
        QueryRequest::Start(query) => native_iterable_query_access(query)?,
        QueryRequest::Continue(_) => return Ok(false),
    };
    match access {
        NativeQueryAccess::EnrollmentAccount(account) => {
            authority_can_enroll_dpn_account(world, authority, &account, now_ms)
        }
        _ => Ok(false),
    }
}
fn validate_builtin_native_query_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    query: &QueryRequest,
    now_ms: u64,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    world.account(authority).map_err(|_| {
        ValidationFail::NotPermitted(format!(
            "query authority `{authority}` is not a registered account"
        ))
    })?;
    let access = match query {
        QueryRequest::Singular(query) => native_singular_query_access(query),
        QueryRequest::Start(query) => native_iterable_query_access(query)?,
        // The store-aware continuation corridor revalidates the archived Start request before
        // validating and advancing this cursor. Raw public validation cannot construct Continue.
        QueryRequest::Continue(_) => return Ok(()),
    };
    let has_global = || authority_has_native_global_read_permission(world, authority);
    let enrollment_query = matches!(&access, NativeQueryAccess::EnrollmentAccount(_));
    match access {
        NativeQueryAccess::Registered => Ok(()),
        NativeQueryAccess::AllLedger => has_global()?
            .then_some(())
            .ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "CanReadAllLedgerData permission is required for this query".to_owned(),
                )
            })
            .map_err(Into::into),
        NativeQueryAccess::Account(account) | NativeQueryAccess::EnrollmentAccount(account) => {
            if account == *authority || has_global()? {
                return Ok(());
            }
            if enrollment_query
                && authority_can_enroll_dpn_account(world, authority, &account, now_ms)?
            {
                return Ok(());
            }
            authority_has_native_account_read_permission(world, authority, &account)?
                .then_some(())
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "exact CanReadAccountData permission is required to read account `{account}`"
                    ))
                }).map_err(Into::into)
        }
    }
}
/// Borrow the exact parameterless grant without allocating a JSON token under a read budget.
fn authority_has_native_global_read_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
) -> Result<bool, ValidationFail> {
    let exact = |permission: &Permission| {
        permission.name() == "CanReadAllLedgerData" && permission.payload().get().as_str() == "null"
    };
    let permissions = world.account_permissions_iter(authority).map_err(|error| {
        ValidationFail::InstructionFailed(InstructionExecutionError::Find(error))
    })?;
    Ok(permissions.into_iter().any(exact)
        || world.account_roles_iter(authority).any(|role_id| {
            world
                .roles()
                .get(role_id)
                .is_some_and(|role| role.permissions().any(exact))
        }))
}

/// Read the existing exact grant. `Json` has canonical lexical form; the strict
/// one-field adapter and AccountId's canonical-I105 decoder preserve exact token semantics.
/// Unlike constructing a fresh token, inherited decoder refusal remains fallible here.
fn authority_has_native_account_read_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    target: &AccountId,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    #[derive(crate::json_macros::JsonDeserialize)]
    #[norito(deny_unknown_fields)]
    struct AccountReadGrant {
        account: AccountId,
    }
    authority_has_borrowed_permission(world, authority, "CanReadAccountData", |permission| {
        read_permission_payload::<AccountReadGrant>(permission)
            .map(|grant| grant.is_some_and(|grant| grant.account == *target))
    })
}

/// Decode only an existing exact-name grant; incomplete local inspection is not a denial.
fn read_permission_payload<T: norito::json::JsonDeserialize>(
    permission: &Permission,
) -> Result<Option<T>, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    match norito::json::from_str(permission.payload().get()) {
        Ok(grant) => Ok(Some(grant)),
        Err(
            norito::json::Error::DecodeResourceLimit
            | norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::ArchiveLengthExceeded { .. }
                | norito::core::DecodeResourceError::SequenceLengthExceeded { .. }
                | norito::core::DecodeResourceError::FieldLengthExceeded { .. }
                | norito::core::DecodeResourceError::TotalElementsExceeded { .. }
                | norito::core::DecodeResourceError::TotalAllocationExceeded { .. },
            ),
        ) if !cfg!(all(test, sumeragi_core_mutation = "HC30")) => {
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into(),
            ))
        }
        Err(
            norito::json::Error::AllocationFailed
            | norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::AllocationFailed { .. },
            ),
        ) if !cfg!(all(test, sumeragi_core_mutation = "HC30")) => {
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            ))
        }
        Err(_) => Ok(None),
    }
}

/// Preserve account existence, direct grants and assigned-role authority while inspecting
/// canonical stored payloads without constructing a second permission token.
fn authority_has_borrowed_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    name: &str,
    inspect: impl Fn(
        &Permission,
    )
        -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>>,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let permissions = world.account_permissions_iter(authority).map_err(|error| {
        ValidationFail::InstructionFailed(InstructionExecutionError::Find(error))
    })?;
    for permission in permissions {
        if permission.name() == name && inspect(permission)? {
            return Ok(true);
        }
    }
    for role_id in world.account_roles_iter(authority) {
        if let Some(role) = world.roles().get(role_id) {
            for permission in role.permissions() {
                if permission.name() == name && inspect(permission)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn validate_builtin_account_alias_query_permission(
    world: &impl WorldReadOnly,
    latest_block: Option<&BlockHeader>,
    authority: &AccountId,
    query: &QueryRequest,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let deny = || {
        ValidationFail::NotPermitted(
            "exact CanResolveAccountAlias permission is required for this alias query".to_owned(),
        )
    };
    let require_alias = |alias: &iroha_data_model::account::rekey::AccountAlias| -> Result<
        (),
        crate::execution_attempt::ExecutionAttemptError<ValidationFail>,
    > {
        crate::alias::authority_can_resolve_account_alias(world, authority, alias)
            .map_err(|error| {
                error.into_attempt_error(|error| ValidationFail::InternalError(error.to_string()))
            })?
            .then_some(())
            .ok_or_else(|| deny().into())
    };
    let QueryRequest::Singular(query) = query else {
        return Ok(());
    };
    match query {
        SingularQueryBox::FindAccountByAlias(query) => {
            require_alias(query.alias()).map_err(Into::into)
        }
        SingularQueryBox::FindAccountRecoveryPolicyByAlias(query) => {
            require_alias(query.alias()).map_err(Into::into)
        }
        SingularQueryBox::FindAccountRecoveryRequestByAlias(query) => {
            require_alias(query.alias()).map_err(Into::into)
        }
        SingularQueryBox::FindAliasesByAccountId(query) => {
            let catalog = world.dataspace_catalog();
            let dataspace_filter = query
                .dataspace()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|dataspace| {
                    catalog
                        .by_alias(dataspace)
                        .map(|entry| entry.id)
                        .ok_or_else(|| deny())
                })
                .transpose()?;
            let domain_filter = query
                .domain()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|domain| {
                    domain
                        .parse::<iroha_data_model::account::rekey::AccountAliasDomain>()
                        .map_err(|_| deny())
                })
                .transpose()?;
            if domain_filter.is_some() && dataspace_filter.is_none() {
                return Err(deny().into());
            }
            if let Some(dataspace) = dataspace_filter {
                let probe = iroha_data_model::account::rekey::AccountAlias::new(
                    "lookup".parse().expect("static alias label"),
                    domain_filter.clone(),
                    dataspace,
                );
                require_alias(&probe)?;
            }
            let now_ms = latest_block.map_or(0, |header| {
                u64::try_from(header.creation_time().as_millis()).unwrap_or(u64::MAX)
            });
            let labels = world
                .account_aliases_by_account()
                .get(query.account_id())
                .cloned()
                .unwrap_or_default();
            for alias in labels {
                let resolved =
                    crate::sns::resolve_active_account_alias(world, catalog, &alias, now_ms)
                        .map_err(|error| {
                            error.into_attempt_error(|error| {
                                ValidationFail::InternalError(error.to_string())
                            })
                        })?;
                if dataspace_filter.is_some_and(|dataspace| alias.dataspace != dataspace)
                    || domain_filter
                        .as_ref()
                        .is_some_and(|domain| alias.domain.as_ref() != Some(domain))
                    || resolved.as_ref() != Some(query.account_id())
                {
                    continue;
                }
                require_alias(&alias)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
fn validate_builtin_subsystem_query_permission(
    world: &impl WorldReadOnly,
    latest_block: Option<&BlockHeader>,
    authority: &AccountId,
    query: &QueryRequest,
) -> Result<(), ValidationFail> {
    // Preserve the stricter SoraFS confidentiality gates independently of the
    // mandatory native account/global read policy and the pluggable executor.
    if latest_block.is_none_or(BlockHeader::is_genesis) {
        return Ok(());
    }
    let QueryRequest::Singular(query) = query else {
        return Ok(());
    };
    match query {
        SingularQueryBox::FindSorafsOrderbookPolicy(_)
        | SingularQueryBox::FindSorafsOrderbookOrderById(_)
        | SingularQueryBox::FindSorafsOrderbookCancellationByOrderId(_)
        | SingularQueryBox::FindSorafsOrderbookReceiptById(_)
        | SingularQueryBox::FindSorafsOrderbookTradeById(_)
        | SingularQueryBox::FindSorafsOrderbookChannelById(_)
        | SingularQueryBox::FindSorafsOrderbookStatus(_)
        | SingularQueryBox::FindSorafsOrderbookOrders(_)
        | SingularQueryBox::FindSorafsOrderbookReceipts(_)
        | SingularQueryBox::FindSorafsOrderbookTrades(_)
        | SingularQueryBox::FindSorafsOrderbookChannels(_)
        | SingularQueryBox::FindSorafsOrderbookEvents(_) => {
            let can_set_pricing: Permission =
                executor_permission::sorafs::CanSetSorafsPricing.into();
            // Provider-scoped completion authority grants no global orderbook inventory.
            if authority_has_permission(world, authority, &can_set_pricing)? {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted(
                    "Can't read authoritative SoraFS orderbook state".to_owned(),
                ))
            }
        }
        SingularQueryBox::FindSorafsReservePolicy(_)
        | SingularQueryBox::FindSorafsReserveProviderById(_)
        | SingularQueryBox::FindSorafsReserveMovementById(_)
        | SingularQueryBox::FindSorafsReserveAppealById(_)
        | SingularQueryBox::FindSorafsReserveProviders(_)
        | SingularQueryBox::FindSorafsReserveMovements(_)
        | SingularQueryBox::FindSorafsReserveAppeals(_)
        | SingularQueryBox::FindSorafsReserveEvents(_) => {
            let can_set_reserve_policy: Permission =
                executor_permission::sorafs::CanSetSorafsReservePolicy.into();
            if authority_has_permission(world, authority, &can_set_reserve_policy)? {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted(
                    "Can't read authoritative SoraFS reserve state".to_owned(),
                ))
            }
        }
        SingularQueryBox::FindSorafsReputationJournalAuthorityPolicy(_) => {
            let can_manage_reputation_policy: Permission =
                executor_permission::sorafs::CanManageSorafsReputationJournalPolicy.into();
            let can_record_reputation: Permission =
                executor_permission::sorafs::CanRecordSorafsReputationJournal.into();
            let can_resolve_dispute: Permission =
                executor_permission::sorafs::CanResolveSorafsCapacityDispute.into();
            if authority_has_permission(world, authority, &can_manage_reputation_policy)?
                || authority_has_permission(world, authority, &can_record_reputation)?
                || authority_has_permission(world, authority, &can_resolve_dispute)?
            {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted(
                    "Can't read the active authoritative SoraFS reputation-journal authority policy"
                        .to_owned(),
                ))
            }
        }
        SingularQueryBox::FindSorafsModerationJurorEligibility(query) => {
            let can_manage_moderation: Permission =
                executor_permission::sorafs::CanManageSorafsModeration.into();
            if authority == &query.juror
                || authority_has_permission(world, authority, &can_manage_moderation)?
            {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted(
                    "Can't read another juror's moderation PoP eligibility record".to_owned(),
                ))
            }
        }
        SingularQueryBox::FindSorafsModerationSnapshot(_) => {
            let can_manage_moderation: Permission =
                executor_permission::sorafs::CanManageSorafsModeration.into();
            if authority_has_permission(world, authority, &can_manage_moderation)? {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted(
                    "Can't read the complete authoritative SoraFS moderation snapshot".to_owned(),
                ))
            }
        }
        _ => Ok(()),
    }
}
fn encode_executor_input<T: Encode>(payload: &T) -> Result<Vec<u8>, ValidationFail> {
    let payload_bytes = payload.encode();
    let total_len = EXECUTOR_LENGTH_PREFIX_BYTES
        .checked_add(payload_bytes.len())
        .and_then(|len| u64::try_from(len).ok())
        .ok_or_else(|| {
            ValidationFail::InternalError(
                "executor input length exceeds the fixed u64 framing domain".to_owned(),
            )
        })?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(total_len).expect("executor input length originated as usize"),
    );
    bytes.extend_from_slice(&total_len.to_le_bytes());
    bytes.extend_from_slice(&payload_bytes);
    Ok(bytes)
}
fn executor_output_payload<'ivm>(
    ivm: &'ivm IVM,
    ret_ptr: u64,
    output_kind: &str,
) -> Result<&'ivm [u8], crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let returned_len = ivm.memory.load_u64(ret_ptr).map_err(|error| {
        crate::execution_attempt::vm_attempt_error(error, |error| {
            ValidationFail::InternalError(format!(
                "executor {output_kind} length prefix is not readable: {error}"
            ))
        })
    })?;
    if returned_len < EXECUTOR_LENGTH_PREFIX_BYTES_U64 {
        return Err(ValidationFail::InternalError(format!(
            "executor {output_kind} is shorter than its fixed u64 length prefix"
        ))
        .into());
    }
    if returned_len > MAX_EXECUTOR_OUTPUT_BYTES {
        return Err(ValidationFail::InternalError(format!(
            "executor {output_kind} length exceeds the {MAX_EXECUTOR_OUTPUT_BYTES}-byte limit"
        ))
        .into());
    }
    let framed = ivm
        .memory
        .load_region(ret_ptr, returned_len)
        .map_err(|error| {
            crate::execution_attempt::vm_attempt_error(error, |error| {
                ValidationFail::InternalError(format!(
                    "executor {output_kind} is not fully readable: {error}"
                ))
            })
        })?;
    Ok(&framed[EXECUTOR_LENGTH_PREFIX_BYTES..])
}

#[cfg(test)]
pub(crate) fn build_program_from_encoded_result(result_bytes: &[u8]) -> Vec<u8> {
    ivm::prebuilt_fixtures::build_encoded_result_program(result_bytes)
}
#[cfg(test)]
mod encoded_result_program_tests {
    use super::*;
    #[test]
    fn encoded_result_program_is_admitted_and_copies_exact_bytes() {
        let result = [0xde, 0xad, 0xbe, 0xef, 0x42];
        let program = build_program_from_encoded_result(&result);
        let parsed = ivm::ProgramMetadata::parse(&program).expect("program metadata parses");
        assert!(
            parsed
                .literal_section
                .is_some_and(|literals| literals.count > 0),
            "encoded bytes must live in authenticated typed literals"
        );
        let mut vm = ivm::IVM::new(1_000_000);
        vm.load_program(&program)
            .expect("encoded-result program passes strict admission");
        vm.set_register(10, ivm::Memory::OUTPUT_START);
        vm.run().expect("encoded-result program runs");
        let output = vm.read_output_used();
        assert_eq!(
            u64::from_le_bytes(output[..8].try_into().expect("fixed u64 prefix")),
            8 + u64::try_from(result.len()).expect("bounded result length")
        );
        assert_eq!(&output[8..8 + result.len()], result);
    }
    #[test]
    fn executor_input_framing_uses_a_fixed_u64_prefix() {
        let payload = 42_u64;
        let payload_bytes = payload.encode();
        let framed = encode_executor_input(&payload).expect("frame executor input");
        assert_eq!(EXECUTOR_LENGTH_PREFIX_BYTES, 8);
        assert_eq!(
            u64::from_le_bytes(framed[..8].try_into().expect("fixed u64 prefix")),
            u64::try_from(8 + payload_bytes.len()).expect("bounded framed length")
        );
        assert_eq!(&framed[8..], payload_bytes);
    }
}
#[cfg(test)]
fn generate_verdict_program(verdict: &Result<(), ValidationFail>) -> Vec<u8> {
    let verdict_bytes = verdict.encode();
    build_program_from_encoded_result(&verdict_bytes)
}
/// Build a user executor that rejects every validation request with a stable message.
#[cfg(test)]
pub(crate) fn denying_executor_for_testing(message: &str) -> Executor {
    let verdict = Err(ValidationFail::NotPermitted(message.to_owned()));
    let bytecode = generate_verdict_program(&verdict);
    let raw = data_model_executor::Executor::new(
        iroha_data_model::transaction::executable::IvmBytecode::from_compiled(bytecode),
    );
    Executor::UserProvided(LoadedExecutor::load(raw).expect("load deny-all test executor"))
}
const SORA_V2_CLAIM_TX_HASH_METADATA_KEY: &str = "sora_v2_claim_tx_hash";
const SORA_NEXUS_CLAIM_RECIPIENT_METADATA_KEY: &str = "sora_nexus_claim_recipient";
#[cfg(test)]
/// Execute a single instruction in a detached overlay for delta regression tests.
///
/// This regression-test helper pre-applies side-effect-free instructions without
/// borrowing a live `StateBlock`. Unsupported instructions return `ValidationFail::InternalError`
/// to preserve the reference fallback boundary exercised by the tests.
#[allow(clippy::too_many_lines)]
pub(crate) fn execute_instruction_detached(
    authority: &AccountId,
    instruction: &iroha_data_model::isi::InstructionBox,
    delta: &mut crate::state::DetachedStateTransactionDelta,
) -> Result<(), ValidationFail> {
    use iroha_data_model::isi::{
        BurnBox, GrantBox, MintBox, RegisterBox, RemoveKeyValueBox, RevokeBox, SetKeyValueBox,
        TransferBox, UnregisterBox,
    };
    if mutates_contract_deployment_permission(instruction) {
        return Err(ValidationFail::InternalError(
            "detached: CanManageSmartContractCode permission mutation requires the sequential consensus gate"
                .to_owned(),
        ));
    }
    let any = instruction.as_any();
    // These mutations all depend on live ownership, permission, reserved-key, or
    // trigger state. A detached delta has no authoritative world view, so recording
    // them here would bypass the Initial executor's consensus authorization. Force
    // the caller onto the sequential path instead.
    if any.downcast_ref::<SetKeyValueBox>().is_some()
        || any.downcast_ref::<RemoveKeyValueBox>().is_some()
        || any.downcast_ref::<MintBox>().is_some()
        || any.downcast_ref::<BurnBox>().is_some()
        || any
            .downcast_ref::<iroha_data_model::isi::SetParameter>()
            .is_some()
        || any
            .downcast_ref::<iroha_data_model::isi::ExecuteTrigger>()
            .is_some()
    {
        return Err(ValidationFail::InternalError(
            "detached: live authorization requires sequential execution".to_owned(),
        ));
    }
    // Transfers
    if let Some(tb) = any.downcast_ref::<TransferBox>() {
        match tb {
            TransferBox::Asset(t) => {
                if t.source.account() != authority {
                    return Err(ValidationFail::InternalError(
                        "detached: delegated asset transfer requires sequential authorization"
                            .to_owned(),
                    ));
                }
                let src = t.source.clone();
                let qty = t.object.clone();
                delta.transfer_asset(src, t.destination.clone(), qty);
            }
            TransferBox::Domain(_) | TransferBox::AssetDefinition(_) | TransferBox::Nft(_) => {
                return Err(ValidationFail::InternalError(
                    "detached: ownership transfer requires sequential authorization".to_owned(),
                ));
            }
        }
        return Ok(());
    }
    // Registration and removal depend on live ownership and permission state.
    if any
        .downcast_ref::<iroha_data_model::isi::register::RegisterCommitteePeerWithPop>()
        .is_some()
    {
        return Err(ValidationFail::InternalError(
            "detached: registration requires sequential authorization".to_owned(),
        ));
    }
    if let Some(rb) = any.downcast_ref::<RegisterBox>() {
        match rb {
            RegisterBox::Peer(_) => {}
            RegisterBox::Domain(_)
            | RegisterBox::Account(_)
            | RegisterBox::AssetDefinition(_)
            | RegisterBox::Nft(_)
            | RegisterBox::Role(_)
            | RegisterBox::Trigger(_) => {}
        }
        return Err(ValidationFail::InternalError(
            "detached: registration requires sequential authorization".to_owned(),
        ));
    }
    if let Some(ub) = any.downcast_ref::<UnregisterBox>() {
        match ub {
            UnregisterBox::Peer(_) => {}
            UnregisterBox::Domain(_)
            | UnregisterBox::Account(_)
            | UnregisterBox::AssetDefinition(_)
            | UnregisterBox::Nft(_)
            | UnregisterBox::Role(_)
            | UnregisterBox::Trigger(_) => {}
        }
        return Err(ValidationFail::InternalError(
            "detached: removal requires sequential authorization".to_owned(),
        ));
    }
    // Permission and role mutation depends on live authority, ownership, and role state.
    // Never pre-apply it to a detached delta: force the sequential executor path so the
    // same consensus authorization is evaluated for every scheduling profile.
    if any.downcast_ref::<GrantBox>().is_some() || any.downcast_ref::<RevokeBox>().is_some() {
        return Err(ValidationFail::InternalError(
            "detached: permission and role mutation requires sequential authorization".to_owned(),
        ));
    }
    // Unknown instruction kind – signal fallback
    Err(ValidationFail::InternalError(
        "detached: unsupported instruction".to_owned(),
    ))
}
/// Executor that verifies that operation is valid and executes it.
///
/// Executing is done in order to verify dependent instructions in transaction.
/// Can be upgraded with [`Upgrade`](iroha_data_model::isi::Upgrade) instruction.
#[derive(Debug, Default, Clone)]
pub enum Executor {
    /// Initial executor with minimal built-in permission checks for critical instructions.
    #[default]
    Initial,
    /// User-provided executor with arbitrary logic.
    UserProvided(LoadedExecutor),
}
/// Execution profile applied when running native ISIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InstructionExecutionProfile {
    /// Full runtime behaviour (logging, telemetry, and policy hooks).
    #[default]
    Runtime,
    /// Lightweight execution for benchmarks/tests lacking a global logger.
    Bench,
}
impl JsonSerializeTrait for Executor {
    fn json_serialize(&self, out: &mut String) {
        let bytes =
            executor_norito::to_bytes(self).unwrap_or_else(|e| panic!("norito encode failed: {e}"));
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        out.push('{');
        json::write_json_string("norito", out);
        out.push(':');
        json::write_json_string(&encoded, out);
        out.push('}');
    }
}
impl JsonDeserializeTrait for Executor {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        parse_executor_value(value)
    }
}
fn parse_executor_value(value: json::Value) -> Result<Executor, json::Error> {
    match value {
        json::Value::Object(mut map) => {
            if let Some(inner) = map.remove("norito").or_else(|| map.remove("bytes")) {
                let bytes = decode_executor_bytes(inner, "norito")?;
                return executor_norito::from_bytes(&bytes).map_err(json::Error::Message);
            }
            if !map.is_empty() {
                for key in map.keys() {
                    trace!(target: "executor::deserialize", field = %key, "ignoring unknown executor field");
                }
            }
            Err(json::Error::Message(
                "invalid executor object: expected {\"norito\": ...}".into(),
            ))
        }
        json::Value::String(s) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| json::Error::Message(e.to_string()))?;
            executor_norito::from_bytes(&bytes).map_err(json::Error::Message)
        }
        other => Err(json::Error::Message(format!(
            "invalid executor JSON: expected object or string, got {other:?}"
        ))),
    }
}
fn decode_executor_bytes(value: json::Value, context: &str) -> Result<Vec<u8>, json::Error> {
    match value {
        json::Value::String(s) => {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| json::Error::InvalidField {
                    field: context.into(),
                    message: e.to_string(),
                })
        }
        json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                let byte = v
                    .as_u64()
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or_else(|| json::Error::InvalidField {
                        field: context.into(),
                        message: "expected byte in range 0..=255".into(),
                    })?;
                out.push(byte);
            }
            Ok(out)
        }
        other => Err(json::Error::InvalidField {
            field: context.into(),
            message: format!("expected base64 string or byte array, got {other:?}"),
        }),
    }
}
fn execute_system_fee_instruction(
    instr: DMInstructionBox,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), InstructionExecutionError> {
    let previous_tx_dataspace_id = state_transaction.current_dataspace_id;
    let previous_world_dataspace_id = state_transaction.world.current_dataspace_id;
    state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let result = instr.execute(authority, state_transaction);
    state_transaction.current_dataspace_id = previous_tx_dataspace_id;
    state_transaction.world.current_dataspace_id = previous_world_dataspace_id;
    result
}
fn execute_gas_fee_transfer_instruction(
    definition: &AssetDefinition,
    instr: DMInstructionBox,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), InstructionExecutionError> {
    if definition.balance_scope_policy() == AssetBalancePolicy::Global {
        execute_system_fee_instruction(instr, authority, state_transaction)
    } else {
        instr.execute(authority, state_transaction)
    }
}
fn metadata_string(
    metadata: &Metadata,
    key: &str,
) -> Result<Option<String>, crate::execution_attempt::ExecutionDeferred> {
    let Some(raw) = metadata.get(key) else {
        return Ok(None);
    };
    let mut value = match norito::json::from_str::<String>(raw.get()) {
        Ok(value) => value,
        Err(error) => match crate::execution_attempt::json_decode_attempt_error(error, |_| ()) {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                return Err(reason);
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(()) => return Ok(None),
        },
    };
    // Trim in the original decoded String; no second unreserved metadata allocation.
    let start = value.len() - value.trim_start().len();
    let end = start + value.trim().len();
    value.truncate(end);
    value.drain(..start);
    Ok((!value.is_empty()).then_some(value))
}
fn should_charge_pipeline_gas_asset(
    skip_nexus_fee: bool,
    nexus_fees: &NexusFees,
    gas_asset_opt: &Option<String>,
) -> bool {
    !skip_nexus_fee && gas_asset_opt.is_some() && nexus_fees.per_gas_unit_fee.is_zero()
}
fn is_sora_v2_tx_hash_literal(value: &str) -> bool {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn successful_claim_fee_authority_allowed(
    nexus: &iroha_config::parameters::actual::Nexus,
    authority: &AccountId,
) -> bool {
    nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .contains(authority)
}
fn successful_claim_fee_exempt_instructions(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    authority: &AccountId,
    metadata: &Metadata,
    instructions: &[InstructionBox],
    observation_time_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionDeferred> {
    if !successful_claim_fee_authority_allowed(nexus, authority) {
        return Ok(false);
    }
    let Some(claim_tx_hash) = metadata_string(metadata, SORA_V2_CLAIM_TX_HASH_METADATA_KEY)? else {
        return Ok(false);
    };
    if !is_sora_v2_tx_hash_literal(&claim_tx_hash) {
        return Ok(false);
    }
    let Some(recipient_literal) =
        metadata_string(metadata, SORA_NEXUS_CLAIM_RECIPIENT_METADATA_KEY)?
    else {
        return Ok(false);
    };
    let recipient = match parse_account_id_literal(
        world,
        world.dataspace_catalog(),
        &recipient_literal,
        observation_time_ms,
    ) {
        Ok(Some(recipient)) => recipient,
        Err(crate::sns::SnsError::Deferred(reason)) => return Err(reason),
        Ok(None) | Err(_) => return Ok(false),
    };
    let Some(asset_def) = crate::block::resolve_network_xor_asset_definition(
        world,
        &nexus.fees.fee_asset_id,
        observation_time_ms,
    )?
    else {
        return Ok(false);
    };
    let [instruction] = instructions else {
        return Ok(false);
    };
    let Some(mint) = instruction.as_any().downcast_ref::<MintBox>() else {
        return Ok(false);
    };
    Ok(match mint {
        MintBox::Asset(mint) => {
            mint.destination.account() == &recipient
                && mint.destination.definition() == &asset_def
                && !mint.object.is_zero()
        }
        MintBox::TriggerRepetitions(_) => false,
    })
}
fn successful_claim_fee_exempt_transaction(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    transaction: &SignedTransaction,
    observation_time_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionDeferred> {
    successful_claim_fee_exempt_payload(world, nexus, transaction.payload(), observation_time_ms)
}
fn successful_claim_fee_exempt_payload(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    payload: &TransactionPayload,
    observation_time_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionDeferred> {
    let Executable::Instructions(instructions) = &payload.instructions else {
        return Ok(false);
    };
    let result = successful_claim_fee_exempt_instructions(
        world,
        nexus,
        &payload.authority,
        &payload.metadata,
        instructions.as_ref(),
        observation_time_ms,
    );
    if cfg!(all(test, sumeragi_core_mutation = "HC36")) && result.is_err() {
        return Ok(false);
    }
    result
}
fn nexus_protocol_fee_exempt_instruction(instruction: &InstructionBox) -> bool {
    let any = instruction.as_any();
    any.downcast_ref::<iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation>()
        .is_some()
}
fn nexus_fee_exempt_instruction(instruction: &InstructionBox) -> bool {
    nexus_protocol_fee_exempt_instruction(instruction)
}
fn nexus_fee_exempt_instructions(instructions: &[InstructionBox]) -> bool {
    !instructions.is_empty() && instructions.iter().all(nexus_fee_exempt_instruction)
}
fn nexus_fee_exempt_transaction(transaction: &SignedTransaction) -> bool {
    nexus_fee_exempt_payload(transaction.payload())
}
fn nexus_fee_exempt_payload(payload: &TransactionPayload) -> bool {
    let Executable::Instructions(instructions) = &payload.instructions else {
        return false;
    };
    nexus_fee_exempt_instructions(instructions.as_ref())
}
fn fee_exempt_payload(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    payload: &TransactionPayload,
    observation_time_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionDeferred> {
    Ok(private_fees::permits_public_exemption(world)?
        && (nexus_fee_exempt_payload(payload)
            || successful_claim_fee_exempt_payload(world, nexus, payload, observation_time_ms)?
            || crate::smartcontracts::isi::sccp::fees::exempt_on_success(world, payload)))
}
/// Return whether `transaction` skips the Nexus fee when it succeeds, judged against the
/// committed `world` the next block executes on (queue admission). Execution uses
/// [`transaction_fee_exemption`], which also says whether a failure is charged.
fn fee_exempt_transaction(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    transaction: &SignedTransaction,
    observation_time_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionDeferred> {
    // `world` is the committed parent World, the one SCCP eligibility is judged against.
    Ok(private_fees::permits_public_exemption(world)?
        && (nexus_fee_exempt_transaction(transaction)
            || successful_claim_fee_exempt_transaction(
                world,
                nexus,
                transaction,
                observation_time_ms,
            )?
            || crate::smartcontracts::isi::sccp::fees::exempt_on_success(
                world,
                transaction.payload(),
            )))
}
/// Return how the Nexus fee applies to `transaction` executing in `state_transaction`, with
/// its SCCP exempt class when it has one.
///
/// Protocol and successful-claim exemptions are judged against the executing World and hold
/// whatever the outcome. SCCP exemptions are judged against the committed parent World of the
/// executing block, exactly like queue admission, fee quoting and the per-block exempt cap,
/// and hold on success only: a failure is charged the ordinary fee (`specs/sccp.md` §4.19).
fn transaction_fee_exemption(
    state_transaction: &StateTransaction<'_, '_>,
    transaction: &SignedTransaction,
) -> Result<
    (
        ExecutionFeeExemption,
        Option<crate::smartcontracts::isi::sccp::admission::SccpExemptClassV1>,
    ),
    crate::execution_attempt::ExecutionDeferred,
> {
    let world = &state_transaction.world;
    if !private_fees::permits_public_exemption(world)? {
        return Ok((ExecutionFeeExemption::Charged, None));
    }
    if nexus_fee_exempt_transaction(transaction)
        || successful_claim_fee_exempt_transaction(
            world,
            &state_transaction.nexus,
            transaction,
            state_transaction.block_unix_timestamp_ms(),
        )?
    {
        return Ok((ExecutionFeeExemption::Exempt, None));
    }
    Ok(
        match crate::smartcontracts::isi::sccp::fees::exempt_class_in_block(
            state_transaction,
            transaction.payload(),
        ) {
            Some(class) => (ExecutionFeeExemption::ExemptOnSuccess, Some(class)),
            None => (ExecutionFeeExemption::Charged, None),
        },
    )
}
#[derive(Clone, Copy)]
enum PermissionOrRoleMutation<'a> {
    AccountPermission {
        permission: &'a Permission,
        destination: &'a AccountId,
        is_revoke: bool,
    },
    AccountRole {
        role: &'a RoleId,
        is_revoke: bool,
    },
    RolePermission {
        permission: &'a Permission,
        role: &'a RoleId,
        is_revoke: bool,
    },
}
fn extract_permission_or_role_mutation(
    instruction: &InstructionBox,
) -> Option<PermissionOrRoleMutation<'_>> {
    fn from_grant(grant: &GrantBox) -> PermissionOrRoleMutation<'_> {
        match grant {
            GrantBox::Permission(grant) => PermissionOrRoleMutation::AccountPermission {
                permission: grant.object(),
                destination: grant.destination(),
                is_revoke: false,
            },
            GrantBox::Role(grant) => PermissionOrRoleMutation::AccountRole {
                role: grant.object(),
                is_revoke: false,
            },
            GrantBox::RolePermission(grant) => PermissionOrRoleMutation::RolePermission {
                permission: grant.object(),
                role: grant.destination(),
                is_revoke: false,
            },
        }
    }
    fn from_revoke(revoke: &RevokeBox) -> PermissionOrRoleMutation<'_> {
        match revoke {
            RevokeBox::Permission(revoke) => PermissionOrRoleMutation::AccountPermission {
                permission: revoke.object(),
                destination: revoke.destination(),
                is_revoke: true,
            },
            RevokeBox::Role(revoke) => PermissionOrRoleMutation::AccountRole {
                role: revoke.object(),
                is_revoke: true,
            },
            RevokeBox::RolePermission(revoke) => PermissionOrRoleMutation::RolePermission {
                permission: revoke.object(),
                role: revoke.destination(),
                is_revoke: true,
            },
        }
    }
    let any = instruction.as_any();
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return Some(from_grant(grant));
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return Some(from_revoke(revoke));
    }
    if let Some(grant) = any.downcast_ref::<Grant<Permission, Account>>() {
        return Some(PermissionOrRoleMutation::AccountPermission {
            permission: grant.object(),
            destination: grant.destination(),
            is_revoke: false,
        });
    }
    if let Some(revoke) = any.downcast_ref::<Revoke<Permission, Account>>() {
        return Some(PermissionOrRoleMutation::AccountPermission {
            permission: revoke.object(),
            destination: revoke.destination(),
            is_revoke: true,
        });
    }
    if let Some(grant) = any.downcast_ref::<Grant<RoleId, Account>>() {
        return Some(PermissionOrRoleMutation::AccountRole {
            role: grant.object(),
            is_revoke: false,
        });
    }
    if let Some(revoke) = any.downcast_ref::<Revoke<RoleId, Account>>() {
        return Some(PermissionOrRoleMutation::AccountRole {
            role: revoke.object(),
            is_revoke: true,
        });
    }
    if let Some(grant) = any.downcast_ref::<Grant<Permission, Role>>() {
        return Some(PermissionOrRoleMutation::RolePermission {
            permission: grant.object(),
            role: grant.destination(),
            is_revoke: false,
        });
    }
    any.downcast_ref::<Revoke<Permission, Role>>()
        .map(|revoke| PermissionOrRoleMutation::RolePermission {
            permission: revoke.object(),
            role: revoke.destination(),
            is_revoke: true,
        })
}
#[cfg(test)]
fn mutates_contract_deployment_permission(instruction: &InstructionBox) -> bool {
    matches!(
        extract_permission_or_role_mutation(instruction),
        Some(
            PermissionOrRoleMutation::AccountPermission { permission, .. }
                | PermissionOrRoleMutation::RolePermission { permission, .. }
        ) if matches!(permission.name().as_ref(), "CanManageSmartContractCode" | "CanGrantSmartContractCodeManagement")
    )
}
fn ensure_contract_code_management_permission_lifecycle(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &Permission,
) -> Result<(), ValidationFail> {
    let is_genesis = is_initial_genesis_context(state_transaction);
    match permission.name().as_ref() {
        "CanGrantSmartContractCodeManagement" => {
            executor_permission::smart_contract::CanGrantSmartContractCodeManagement::try_from(
                permission,
            )
            .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if is_genesis {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted(
                    "CanGrantSmartContractCodeManagement is only granted or revoked in genesis"
                        .to_owned(),
                ))
            }
        }
        "CanManageSmartContractCode" => {
            executor_permission::smart_contract::CanManageSmartContractCode::try_from(permission)
                .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            let manager: Permission =
                executor_permission::smart_contract::CanGrantSmartContractCodeManagement.into();
            if is_genesis
                || authority_has_permission(&state_transaction.world, authority, &manager)?
            {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted(
                    "granting or revoking CanManageSmartContractCode requires CanGrantSmartContractCodeManagement".to_owned(),
                ))
            }
        }
        _ => Ok(()),
    }
}
fn ensure_contract_deployment_permission_mutation_allowed(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &InstructionBox,
) -> Result<(), ValidationFail> {
    let validate = |permission: &Permission| {
        ensure_contract_code_management_permission_lifecycle(
            state_transaction,
            authority,
            permission,
        )
    };
    if let Some(register) = extract_register_role(instruction) {
        for permission in register.object().inner().permissions() {
            validate(permission)?;
        }
    }
    let role_id = match extract_permission_or_role_mutation(instruction) {
        Some(
            PermissionOrRoleMutation::AccountPermission { permission, .. }
            | PermissionOrRoleMutation::RolePermission { permission, .. },
        ) => {
            return validate(permission);
        }
        Some(PermissionOrRoleMutation::AccountRole { role, .. }) => Some(role.clone()),
        None => extract_unregister_role(instruction).map(|unregister| unregister.object().clone()),
    };
    if let Some(role_id) = role_id
        && let Some(role) = state_transaction.world.roles().get(&role_id)
    {
        for permission in role.permissions() {
            validate(permission)?;
        }
    }
    Ok(())
}
/// Enforce exact entrypoint delegation before any executor can approve a mutation.
/// This boundary also receives instructions emitted by IVM hosts and triggers.
fn ensure_contract_entrypoint_authorization_mutation_allowed(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &InstructionBox,
) -> Result<(), ValidationFail> {
    let validate = |permission: &Permission| {
        if permission.name() == "CanUseContractPermission" {
            return if contract_permission_delegation_allowed(
                state_transaction,
                authority,
                permission,
            )? {
                Ok(())
            } else {
                Err(ValidationFail::NotPermitted("only an exact holder or the current account lifecycle owner may grant or revoke a declared instance permission".to_owned()))
            };
        }
        if permission.name() != "CanInvokeContractEntrypoint" {
            return Ok(());
        }
        if contract_entrypoint_authorization_delegation_allowed(
            state_transaction,
            authority,
            permission,
        )? {
            return Ok(());
        }
        Err(ValidationFail::NotPermitted(
            "only genesis, an exact holder, a smart-contract code manager, or the current account lifecycle owner may grant or revoke an exact contract entrypoint permission".to_owned(),
        ))
    };
    if let Some(register) = extract_register_role(instruction) {
        for permission in register.object().inner().permissions() {
            validate(permission)?;
        }
    }
    let role_id = match extract_permission_or_role_mutation(instruction) {
        Some(
            PermissionOrRoleMutation::AccountPermission { permission, .. }
            | PermissionOrRoleMutation::RolePermission { permission, .. },
        ) => return validate(permission),
        Some(PermissionOrRoleMutation::AccountRole { role, .. }) => Some(role.clone()),
        None => extract_unregister_role(instruction).map(|unregister| unregister.object().clone()),
    };
    if let Some(role_id) = role_id
        && let Some(role) = state_transaction.world.roles().get(&role_id)
    {
        for permission in role.permissions() {
            validate(permission)?;
        }
    }
    Ok(())
}
fn ensure_contract_runtime_permission_mutation_allowed(
    authority: &AccountId,
    instruction: &InstructionBox,
    contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
) -> Result<(), ValidationFail> {
    let Some(context) = contract_runtime_context else {
        return Ok(());
    };
    let mutation = extract_permission_or_role_mutation(instruction);
    let mutates_role = extract_register_role(instruction).is_some()
        || extract_unregister_role(instruction).is_some()
        || matches!(
            mutation,
            Some(
                PermissionOrRoleMutation::AccountRole { .. }
                    | PermissionOrRoleMutation::RolePermission { .. }
            )
        );
    if mutates_role {
        return Err(ValidationFail::NotPermitted(
            "deployed contracts may not register, unregister, or mutate role membership or role permissions"
                .to_owned(),
        ));
    }
    let Some(PermissionOrRoleMutation::AccountPermission { permission, .. }) = mutation else {
        return Ok(());
    };
    let scoped =
        executor_permission::smart_contract::CanUseContractPermission::try_from(permission)
            .map_err(|_| {
                ValidationFail::NotPermitted(
            "deployed contracts may grant or revoke only exact CanUseContractPermission tokens"
                .to_owned(),
        )
            })?;
    if authority != &context.contract_subject
        || scoped.contract != context.contract_address
        || scoped.contract.subject_id() != *authority
        || context.contract_address.subject_id() != context.contract_subject
    {
        return Err(ValidationFail::NotPermitted(
            "deployed contract permission mutation must be bound to its immutable subject, address, and a declared instance permission"
                .to_owned(),
        ));
    }
    Ok(())
}
fn parse_account_id_literal(
    world: &impl WorldReadOnly,
    dataspace_catalog: &iroha_data_model::nexus::DataSpaceCatalog,
    literal: &str,
    now_ms: u64,
) -> Result<Option<AccountId>, crate::sns::SnsError> {
    crate::block::parse_account_literal_with_world(world, dataspace_catalog, literal, now_ms)
}
/// Deterministic reason a Nexus fee quote or admission check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NexusFeeAdmissionError {
    /// The selected fee payer cannot satisfy deterministic admission.
    Rejected {
        /// Stable machine-readable rejection code.
        code: FeeRejectionCode,
        /// Human-readable diagnostic detail.
        reason: String,
    },
    /// Node or persisted fee configuration is invalid.
    ConfigInvalid(String),
}
impl core::fmt::Display for NexusFeeAdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.reason())
    }
}
impl std::error::Error for NexusFeeAdmissionError {}
impl NexusFeeAdmissionError {
    fn rejected(code: FeeRejectionCode, reason: impl Into<String>) -> Self {
        Self::Rejected {
            code,
            reason: reason.into(),
        }
    }
    fn sponsor(code: FeeRejectionCode, reason: impl Into<String>) -> Self {
        Self::rejected(code, reason)
    }
    /// Stable fee-admission denial code.
    pub const fn code(&self) -> FeeRejectionCode {
        match self {
            Self::Rejected { code, .. } => *code,
            Self::ConfigInvalid(_) => FeeRejectionCode::InvalidProgramConfiguration,
        }
    }
    /// Human-readable detail suitable for authorized diagnostics.
    pub fn reason(&self) -> &str {
        match self {
            Self::Rejected { reason, .. } | Self::ConfigInvalid(reason) => reason,
        }
    }
}
#[cfg(test)]
fn smart_contract_state_name(
    raw: String,
    context: &'static str,
) -> Result<StatePath, NexusFeeAdmissionError> {
    StatePath::from_str(&raw).map_err(|_| {
        NexusFeeAdmissionError::ConfigInvalid(format!(
            "invalid smart-contract state key: {context}"
        ))
    })
}
#[cfg(test)]
fn decode_verified_fee_sponsor_vault_allocation_state(
    payload: &[u8],
) -> Result<VerifiedFeeSponsorVaultAllocation, NexusFeeAdmissionError> {
    let json: Json = norito::decode_from_bytes(payload).map_err(|err| {
        NexusFeeAdmissionError::ConfigInvalid(format!(
            "verified fee sponsor vault allocation state decode failed: {err}"
        ))
    })?;
    norito::json::from_slice(json.get().as_bytes()).map_err(|err| {
        NexusFeeAdmissionError::ConfigInvalid(format!(
            "verified fee sponsor vault allocation JSON decode failed: {err}"
        ))
    })
}
#[cfg(test)]
fn fee_sponsor_vault_allocation_usage_state_key(
    lease_id: &iroha_crypto::Hash,
) -> Result<StatePath, NexusFeeAdmissionError> {
    smart_contract_state_name(
        VerifiedFeeSponsorVaultAllocation::usage_state_key_for(lease_id),
        "verified fee sponsor vault allocation usage",
    )
}
#[cfg(test)]
fn fee_sponsor_vault_allocation_settled_usage_state_key(
    lease_id: &iroha_crypto::Hash,
) -> Result<StatePath, NexusFeeAdmissionError> {
    smart_contract_state_name(
        VerifiedFeeSponsorVaultAllocation::settled_usage_state_key_for(lease_id),
        "settled verified fee sponsor vault allocation usage",
    )
}
#[cfg(test)]
fn fee_sponsor_vault_allocation_quantity_at(
    world: &impl WorldReadOnly,
    key: &StatePath,
) -> Result<Quantity, NexusFeeAdmissionError> {
    world.smart_contract_state().get(key).map_or_else(
        || Ok(Quantity::zero()),
        |payload| {
            norito::decode_from_bytes(payload).map_err(|err| {
                NexusFeeAdmissionError::ConfigInvalid(format!(
                    "verified fee sponsor vault allocation usage decode failed: {err}"
                ))
            })
        },
    )
}
#[cfg(test)]
fn fee_sponsor_vault_allocation_spent(
    world: &impl WorldReadOnly,
    lease_id: &iroha_crypto::Hash,
) -> Result<Quantity, NexusFeeAdmissionError> {
    let executed_key = fee_sponsor_vault_allocation_usage_state_key(lease_id)?;
    let settled_key = fee_sponsor_vault_allocation_settled_usage_state_key(lease_id)?;
    let executed = fee_sponsor_vault_allocation_quantity_at(world, &executed_key)?;
    let settled = fee_sponsor_vault_allocation_quantity_at(world, &settled_key)?;
    Ok(core::cmp::max(executed, settled))
}
#[cfg(test)]
fn select_fee_sponsor_relay_lease(
    world: &impl WorldReadOnly,
    program_id: &FeeSponsorProgramId,
    program_revision: u64,
    asset_definition_id: &AssetDefinitionId,
    route_dataspace_id: Option<DataSpaceId>,
    admission_height: u64,
    required: &Quantity,
) -> Result<(VerifiedFeeSponsorVaultAllocation, Quantity), NexusFeeAdmissionError> {
    let source_dataspace_id = route_dataspace_id.unwrap_or(DataSpaceId::UNIVERSAL);
    let mut candidates = Vec::new();
    for (key, payload) in world.smart_contract_state().iter() {
        if !key
            .to_string()
            .starts_with(VERIFIED_FEE_SPONSOR_VAULT_ALLOCATION_STATE_KEY_PREFIX)
        {
            continue;
        }
        let record = decode_verified_fee_sponsor_vault_allocation_state(payload)?;
        let canonical_key = VerifiedFeeSponsorVaultAllocation::state_key_for(
            &record.program_id,
            &record.asset_definition_id,
            &record.lease_id,
        );
        if key.to_string() != canonical_key {
            return Err(NexusFeeAdmissionError::ConfigInvalid(format!(
                "verified fee sponsor vault allocation `{}` is stored under a non-canonical key",
                record.lease_id
            )));
        }
        if &record.program_id != program_id
            || record.program_revision != program_revision
            || &record.asset_definition_id != asset_definition_id
            || record.source_dataspace_id != source_dataspace_id
            || record.source_height > admission_height
            || record.verified_at_height > admission_height
            || record.expires_at_height < admission_height
        {
            continue;
        }
        let spent = fee_sponsor_vault_allocation_spent(world, &record.lease_id)?;
        let remaining = record
            .verified_allocation
            .checked_sub(&spent)
            .map_err(|_| {
                NexusFeeAdmissionError::ConfigInvalid(format!(
                    "verified fee sponsor vault allocation `{}` is overspent",
                    record.lease_id
                ))
            })?;
        if remaining >= *required {
            candidates.push((record, remaining));
        }
    }
    candidates.sort_by(|(left, _), (right, _)| left.lease_id.as_ref().cmp(right.lease_id.as_ref()));
    candidates.into_iter().next().ok_or_else(|| {
        NexusFeeAdmissionError::sponsor(
            FeeRejectionCode::RelayCapacityUnavailable,
            format!(
                "no unexpired verified spend lease covers sponsor program `{program_id}` revision {program_revision}, route dataspace {}, asset `{asset_definition_id}`, and charge {required}",
                source_dataspace_id.as_u64(),
            ),
        )
    })
}
#[cfg(test)]
fn select_fee_sponsor_relay_leases(
    world: &impl WorldReadOnly,
    program_id: &FeeSponsorProgramId,
    program_revision: u64,
    route_dataspace_id: Option<DataSpaceId>,
    admission_height: u64,
    charges: &[FeeChargeBound],
) -> Result<BTreeMap<AssetDefinitionId, FeeSponsorRelayLeaseCapacity>, NexusFeeAdmissionError> {
    let mut required_by_asset = BTreeMap::<AssetDefinitionId, Quantity>::new();
    for charge in charges {
        let current = required_by_asset
            .get(&charge.asset_definition_id)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        required_by_asset.insert(
            charge.asset_definition_id.clone(),
            checked_quantity_add(&current, &charge.max_bound, "relay spend-lease charge")?,
        );
    }
    let mut selections = BTreeMap::new();
    for (asset_definition_id, required) in required_by_asset {
        let (record, remaining) = select_fee_sponsor_relay_lease(
            world,
            program_id,
            program_revision,
            &asset_definition_id,
            route_dataspace_id,
            admission_height,
            &required,
        )?;
        selections.insert(
            asset_definition_id,
            FeeSponsorRelayLeaseCapacity {
                lease_id: record.lease_id,
                remaining,
            },
        );
    }
    Ok(selections)
}
fn validation_fail_to_nexus_fee_admission_error(err: ValidationFail) -> NexusFeeAdmissionError {
    match err {
        ValidationFail::InternalError(reason) => NexusFeeAdmissionError::ConfigInvalid(reason),
        other => {
            NexusFeeAdmissionError::rejected(FeeRejectionCode::InvalidFeeIntent, other.to_string())
        }
    }
}
fn nexus_fee_admission_error_to_validation_fail(err: NexusFeeAdmissionError) -> ValidationFail {
    match err {
        NexusFeeAdmissionError::Rejected { reason, .. } => ValidationFail::NotPermitted(reason),
        NexusFeeAdmissionError::ConfigInvalid(reason) => ValidationFail::InternalError(reason),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum FeeSponsorOperation {
    NativeInstruction {
        wire_id: String,
        asset_definition_id: Option<AssetDefinitionId>,
    },
    Multisig {
        operation: FeeSponsorMultisigOperation,
        account_id: AccountId,
    },
    ContractCall {
        contract_address: iroha_data_model::smart_contract::ContractAddress,
        code_hash: iroha_crypto::Hash,
        entrypoint: String,
    },
    Ivm {
        code_hash: iroha_crypto::Hash,
        proved: bool,
    },
}
/// One deterministic fee component quoted by Core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeChargeBound {
    /// Fee component represented by this bound.
    pub kind: FeeChargeKind,
    /// Canonical asset in which the component is charged.
    pub asset_definition_id: AssetDefinitionId,
    /// Deterministic maximum charge for the supplied payload and state.
    pub max_bound: Quantity,
}
/// Remaining capacity for one program asset at the observed state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSponsorCapacity {
    /// Current isolated program-vault balance.
    pub vault_balance: Quantity,
    /// Balance that must remain after the charge.
    pub reserve_floor: Quantity,
    /// Capacity remaining in the observed block window before this quote.
    pub block_remaining: Quantity,
    /// Capacity remaining in the observed program epoch before this quote.
    pub program_epoch_remaining: Quantity,
    /// Capacity remaining for this beneficiary epoch before this quote.
    pub beneficiary_epoch_remaining: Quantity,
}
/// Exact proof-bound spend lease selected for one sponsored fee asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSponsorRelayLeaseCapacity {
    /// Canonical lease selected for the program revision, asset, and route.
    pub lease_id: iroha_crypto::Hash,
    /// Remaining verified allocation on the lease before this quote.
    pub remaining: Quantity,
}
/// Read-only deterministic fee quote shared by queue admission and Torii.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeAdmissionQuote {
    /// Deterministic charge bounds, canonically ordered by component.
    pub charges: Vec<FeeChargeBound>,
    /// Exact account or isolated program vault selected by the payload.
    pub debit_source: FeeDebitSource,
    /// Active immutable sponsor revision, when sponsored.
    pub program_revision: Option<u64>,
    /// Canonically selected proof-bound spend lease for each sponsored fee asset.
    ///
    /// This map is populated only for receipt-lane settlement. All charge components using the same
    /// asset share one selection and consume its aggregate maximum.
    pub relay_leases: BTreeMap<AssetDefinitionId, FeeSponsorRelayLeaseCapacity>,
    /// Per-asset sponsor capacity snapshot, empty for authority payment.
    pub capacities: BTreeMap<AssetDefinitionId, FeeSponsorCapacity>,
    /// Exact authority balance buckets observed for account-paid charges.
    ///
    /// Keys include global versus dataspace-restricted scope so queue
    /// reservations cannot overbook two components against the same bucket.
    pub authority_balances: BTreeMap<AssetId, Quantity>,
    /// Exact authority balance bucket selected for each charge component.
    pub authority_charge_assets: BTreeMap<FeeChargeKind, AssetId>,
}
/// Unsigned quote result with the exact fee intent that should be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeAdmissionDraftQuote {
    /// Admission result for the returned signature-bound intent.
    pub quote: FeeAdmissionQuote,
    /// Exact payer selection, revision, gas limit, assets, and charge maxima to sign.
    pub recommended_intent: FeePaymentIntent,
}
#[derive(Clone, Debug)]
struct ResolvedSponsorProgram {
    id: FeeSponsorProgramId,
    revision: FeeSponsorProgramRevision,
}
fn fee_sponsor_asset_transfer_definition_id(
    instruction: &InstructionBox,
) -> Option<AssetDefinitionId> {
    let any = instruction.as_any();
    if let Some(transfer) = any.downcast_ref::<TransferBox>() {
        return match transfer {
            TransferBox::Asset(transfer) => Some(transfer.source.definition().clone()),
            TransferBox::Domain(_) | TransferBox::AssetDefinition(_) | TransferBox::Nft(_) => None,
        };
    }
    any.downcast_ref::<Transfer<Asset, Quantity, Account>>()
        .map(|transfer| transfer.source.definition().clone())
}
fn fee_sponsor_instruction_operation(
    instruction: &InstructionBox,
) -> Result<
    FeeSponsorOperation,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    use crate::execution_attempt::ExecutionAttemptError;
    let multisig = match MultisigInstructionBox::try_from(instruction) {
        Ok(value) => Some(value),
        Err(error) => {
            match crate::smartcontracts::isi::multisig::multisig_instruction_decode_attempt(
                error,
                |_| (),
            ) {
                ExecutionAttemptError::Deferred(reason) => {
                    return Err(ExecutionAttemptError::Deferred(reason));
                }
                ExecutionAttemptError::Rejected(()) => None,
            }
        }
    };
    if let Some(multisig) = multisig {
        let (operation, account_id) = match multisig {
            MultisigInstructionBox::Propose(propose) => {
                (FeeSponsorMultisigOperation::Propose, propose.account)
            }
            MultisigInstructionBox::Approve(approve) => {
                (FeeSponsorMultisigOperation::Approve, approve.account)
            }
            MultisigInstructionBox::Cancel(cancel) => {
                (FeeSponsorMultisigOperation::Cancel, cancel.account)
            }
            MultisigInstructionBox::InvalidateOutstanding(invalidate) => {
                (FeeSponsorMultisigOperation::Cancel, invalidate.account)
            }
            MultisigInstructionBox::Register(register) => {
                (FeeSponsorMultisigOperation::Register, register.account)
            }
        };
        return Ok(FeeSponsorOperation::Multisig {
            operation,
            account_id,
        });
    }
    let wire_id = iroha_data_model::isi::instruction_wire_id(instruction)
        .ok_or_else(|| {
            NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::InvalidProgramConfiguration,
                "fee sponsor program could not resolve native instruction wire id",
            )
        })?
        .to_owned();
    Ok(FeeSponsorOperation::NativeInstruction {
        wire_id,
        asset_definition_id: fee_sponsor_asset_transfer_definition_id(instruction),
    })
}
fn fee_sponsor_operations(
    executable: &Executable,
) -> Result<
    Vec<FeeSponsorOperation>,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    match executable {
        Executable::Instructions(instructions) => instructions
            .iter()
            .map(fee_sponsor_instruction_operation)
            .collect(),
        Executable::ContractCall(invocation) => Ok(vec![FeeSponsorOperation::ContractCall {
            contract_address: invocation.contract_address.clone(),
            code_hash: invocation.expected_code_hash,
            entrypoint: invocation.entrypoint.clone(),
        }]),
        Executable::Batch(items) => items
            .iter()
            .map(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => {
                    fee_sponsor_instruction_operation(instruction)
                }
                ExecutableBatchItem::ContractCall(invocation) => {
                    Ok(FeeSponsorOperation::ContractCall {
                        contract_address: invocation.contract_address.clone(),
                        code_hash: invocation.expected_code_hash,
                        entrypoint: invocation.entrypoint.clone(),
                    })
                }
            })
            .collect(),
        Executable::Ivm(bytecode) => Ok(vec![FeeSponsorOperation::Ivm {
            code_hash: iroha_crypto::Hash::new(bytecode.as_ref()),
            proved: false,
        }]),
        Executable::IvmProved(proved) => Ok(vec![FeeSponsorOperation::Ivm {
            code_hash: iroha_crypto::Hash::new(proved.bytecode.as_ref()),
            proved: true,
        }]),
    }
}
fn fee_sponsor_selector_matches_operation(
    selector: &FeeSponsorRuleSelector,
    operation: &FeeSponsorOperation,
) -> bool {
    match (selector, operation) {
        (
            FeeSponsorRuleSelector::NativeInstruction(selector),
            FeeSponsorOperation::NativeInstruction {
                wire_id,
                asset_definition_id,
            },
        ) => {
            selector.wire_id == *wire_id
                && selector
                    .asset_definition_id
                    .as_ref()
                    .is_none_or(|selected| asset_definition_id.as_ref() == Some(selected))
        }
        (
            FeeSponsorRuleSelector::Multisig(selector),
            FeeSponsorOperation::Multisig {
                operation,
                account_id,
            },
        ) => {
            selector.operations.binary_search(operation).is_ok()
                && selector.account_ids.binary_search(account_id).is_ok()
        }
        (
            FeeSponsorRuleSelector::ContractCall(selector),
            FeeSponsorOperation::ContractCall {
                contract_address,
                code_hash,
                entrypoint,
            },
        ) => {
            selector.contract_address == *contract_address
                && selector.code_hash == *code_hash
                && (selector.entrypoints.is_empty() || selector.entrypoints.contains(entrypoint))
        }
        (
            FeeSponsorRuleSelector::Ivm(selector),
            FeeSponsorOperation::Ivm {
                code_hash,
                proved: false,
            },
        )
        | (
            FeeSponsorRuleSelector::IvmProved(selector),
            FeeSponsorOperation::Ivm {
                code_hash,
                proved: true,
            },
        ) => selector.code_hash == *code_hash,
        _ => false,
    }
}
fn validate_fee_sponsor_rules(
    world: &impl WorldReadOnly,
    revision: &FeeSponsorProgramRevision,
    beneficiary: &AccountId,
    payload: &TransactionPayload,
    context: fee_sponsor_multisig::RuleContext,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>> {
    let operations = fee_sponsor_operations(&payload.instructions)?;
    if operations.is_empty() {
        return Err(NexusFeeAdmissionError::sponsor(
            FeeRejectionCode::OperationNotAllowed,
            "fee sponsor program cannot authorize an empty executable",
        )
        .into());
    }
    for (index, operation) in operations.iter().enumerate() {
        let mut allowed = false;
        // Evaluate every matching deny before accepting an allow. Typed resource
        // deferral must never become a non-match that silently skips a deny.
        for effect in [FeeSponsorRuleEffect::Deny, FeeSponsorRuleEffect::Allow] {
            for rule in revision.rules.iter().filter(|rule| rule.effect == effect) {
                for selector in &rule.selectors {
                    let matches = match selector {
                        FeeSponsorRuleSelector::EnrolledMultisigContractCall(selector) => {
                            fee_sponsor_multisig::selector_matches(
                                world,
                                &revision.program_id,
                                beneficiary,
                                selector,
                                payload,
                                index,
                                context,
                            )?
                        }
                        _ => fee_sponsor_selector_matches_operation(selector, operation),
                    };
                    if matches {
                        if effect == FeeSponsorRuleEffect::Deny {
                            return Err(NexusFeeAdmissionError::sponsor(
                                FeeRejectionCode::OperationDenied,
                                "signed operation matches an explicit fee sponsor deny rule",
                            )
                            .into());
                        }
                        allowed = true;
                    }
                }
            }
        }
        if !allowed {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::OperationNotAllowed,
                "signed operation is not covered by a fee sponsor allow rule",
            )
            .into());
        }
    }
    Ok(())
}
fn resolve_fee_sponsor_program(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    program_id: &FeeSponsorProgramId,
    signed_revision: u64,
    beneficiary: &AccountId,
    payload: &TransactionPayload,
    route_dataspace_id: Option<DataSpaceId>,
    block_height: u64,
    context: fee_sponsor_multisig::RuleContext,
) -> Result<
    ResolvedSponsorProgram,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    let program = world
        .fee_sponsor_programs()
        .get(program_id)
        .ok_or_else(|| {
            NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::ProgramNotFound,
                format!("fee sponsor program `{program_id}` does not exist"),
            )
        })?;
    let due_revision = program
        .scheduled_activation
        .filter(|activation| activation.activate_at_height <= block_height)
        .map(|activation| {
            fee_sponsor_revision_safe_activation_height(
                world,
                program_id,
                activation.revision,
                block_height,
                block_height,
            )
            .map(|safe_height| (safe_height == block_height).then_some(activation.revision))
            .map_err(NexusFeeAdmissionError::ConfigInvalid)
        })
        .transpose()?
        .flatten();
    let effective_revision = due_revision.or(program.active_revision);
    let lifecycle_accepts = program.lifecycle == FeeSponsorProgramLifecycle::Active
        || (due_revision.is_some()
            && !matches!(
                program.lifecycle,
                FeeSponsorProgramLifecycle::Closing | FeeSponsorProgramLifecycle::Closed
            ));
    if !lifecycle_accepts {
        return Err(NexusFeeAdmissionError::sponsor(
            FeeRejectionCode::ProgramNotActive,
            format!(
                "fee sponsor program `{program_id}` is {:?}",
                program.lifecycle
            ),
        )
        .into());
    }
    if effective_revision != Some(signed_revision) {
        return Err(NexusFeeAdmissionError::sponsor(
            FeeRejectionCode::RevisionNotActive,
            format!(
                "fee sponsor program `{program_id}` active revision is {:?}; transaction selected {signed_revision}",
                effective_revision
            ),
        ).into());
    }
    let revision = world
        .fee_sponsor_program_revisions()
        .get(&FeeSponsorProgramRevisionKey::new(
            program_id.clone(),
            signed_revision,
        ))
        .cloned()
        .ok_or_else(|| {
            NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::RevisionNotFound,
                format!("fee sponsor program `{program_id}` revision {signed_revision} is missing"),
            )
        })?;
    if revision.program_id != *program_id {
        return Err(NexusFeeAdmissionError::sponsor(
            FeeRejectionCode::InvalidProgramConfiguration,
            "fee sponsor revision key does not match its embedded program id",
        )
        .into());
    }
    let enrollment_key = FeeSponsorEnrollmentKey {
        program_id: program_id.clone(),
        beneficiary: beneficiary.clone(),
    };
    let enrolled = world
        .fee_sponsor_enrollments()
        .get(&enrollment_key)
        .is_some();
    let exact_route_default = route_dataspace_id.is_some_and(|dataspace| {
        nexus.dataspace_fee_sponsor_program_ids.get(&dataspace) == Some(program_id)
    });
    let eligible = enrolled
        || (revision.eligibility == FeeSponsorEligibility::EnrolledOrRouteDefault
            && exact_route_default);
    if !eligible {
        return Err(NexusFeeAdmissionError::sponsor(
            FeeRejectionCode::BeneficiaryNotEligible,
            format!(
                "beneficiary `{beneficiary}` is not enrolled and `{program_id}` is not the eligible exact route default"
            ),
        ).into());
    }
    validate_fee_sponsor_rules(world, &revision, beneficiary, payload, context)?;
    Ok(ResolvedSponsorProgram {
        id: program_id.clone(),
        revision,
    })
}
fn checked_quantity_add(
    lhs: &Quantity,
    rhs: &Quantity,
    context: &'static str,
) -> Result<Quantity, NexusFeeAdmissionError> {
    lhs.checked_add(rhs).map_err(|_| {
        NexusFeeAdmissionError::sponsor(
            FeeRejectionCode::InvalidProgramConfiguration,
            format!("fee sponsor {context} arithmetic overflow"),
        )
    })
}
fn counter_spent(world: &impl WorldReadOnly, key: &FeeSponsorBudgetCounterKey) -> Quantity {
    world
        .fee_sponsor_budget_counters()
        .get(key)
        .map_or_else(Quantity::zero, |counter| counter.spent.clone())
}
fn remaining_capacity(limit: &Quantity, spent: &Quantity) -> Quantity {
    limit
        .checked_sub(spent)
        .unwrap_or_else(|_| Quantity::zero())
}
fn evaluate_fee_sponsor_capacity(
    world: &impl WorldReadOnly,
    resolved: &ResolvedSponsorProgram,
    beneficiary: &AccountId,
    block_height: u64,
    charges: &[FeeChargeBound],
) -> Result<BTreeMap<AssetDefinitionId, FeeSponsorCapacity>, NexusFeeAdmissionError> {
    let mut totals = BTreeMap::<AssetDefinitionId, Quantity>::new();
    for charge in charges {
        let total = totals
            .get(&charge.asset_definition_id)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        totals.insert(
            charge.asset_definition_id.clone(),
            checked_quantity_add(&total, &charge.max_bound, "per-transaction charge")?,
        );
    }
    let mut capacities = BTreeMap::new();
    for (asset_definition_id, amount) in totals {
        let definition = world.asset_definition(&asset_definition_id).map_err(|_| {
            NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::InvalidProgramConfiguration,
                format!("fee sponsor asset `{asset_definition_id}` is not registered"),
            )
        })?;
        if definition.balance_scope_policy() != AssetBalancePolicy::Global {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::InvalidProgramConfiguration,
                format!("fee sponsor asset `{asset_definition_id}` must use Global balance scope"),
            ));
        }
        let budget = resolved
            .revision
            .asset_budgets
            .iter()
            .find(|budget| budget.asset_definition_id == asset_definition_id)
            .ok_or_else(|| {
                NexusFeeAdmissionError::sponsor(
                    FeeRejectionCode::FeeAssetNotCovered,
                    format!(
                        "fee sponsor revision {} does not cover asset `{asset_definition_id}`",
                        resolved.revision.revision
                    ),
                )
            })?;
        if amount > budget.per_transaction {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::ProgramTransactionLimitExceeded,
                format!(
                    "fee sponsor per-transaction budget for `{asset_definition_id}` is {}; requires {amount}",
                    budget.per_transaction
                ),
            ));
        }
        let epoch = block_height.saturating_sub(1) / budget.epoch_length_blocks.get();
        let block_key = FeeSponsorBudgetCounterKey {
            program_id: resolved.id.clone(),
            asset_definition_id: asset_definition_id.clone(),
            window: FeeSponsorBudgetWindow::Block(FeeSponsorBlockBudgetWindow {
                height: block_height,
            }),
        };
        let program_epoch_key = FeeSponsorBudgetCounterKey {
            program_id: resolved.id.clone(),
            asset_definition_id: asset_definition_id.clone(),
            window: FeeSponsorBudgetWindow::ProgramEpoch(FeeSponsorProgramEpochBudgetWindow {
                epoch,
            }),
        };
        let beneficiary_epoch_key = FeeSponsorBudgetCounterKey {
            program_id: resolved.id.clone(),
            asset_definition_id: asset_definition_id.clone(),
            window: FeeSponsorBudgetWindow::BeneficiaryEpoch(
                FeeSponsorBeneficiaryEpochBudgetWindow {
                    epoch,
                    beneficiary: beneficiary.clone(),
                },
            ),
        };
        let block_spent = counter_spent(world, &block_key);
        let program_spent = counter_spent(world, &program_epoch_key);
        let beneficiary_spent = counter_spent(world, &beneficiary_epoch_key);
        let block_after = checked_quantity_add(&block_spent, &amount, "block budget")?;
        if block_after > budget.per_block {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::ProgramBlockBudgetExhausted,
                format!("fee sponsor block budget for `{asset_definition_id}` is exhausted"),
            ));
        }
        let program_after = checked_quantity_add(&program_spent, &amount, "program epoch budget")?;
        if program_after > budget.per_program_epoch {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::ProgramEpochBudgetExhausted,
                format!(
                    "fee sponsor program epoch budget for `{asset_definition_id}` is exhausted"
                ),
            ));
        }
        let beneficiary_after =
            checked_quantity_add(&beneficiary_spent, &amount, "beneficiary epoch budget")?;
        if beneficiary_after > budget.per_beneficiary_epoch {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::BeneficiaryEpochBudgetExhausted,
                format!(
                    "fee sponsor beneficiary epoch budget for `{asset_definition_id}` is exhausted"
                ),
            ));
        }
        let vault_key = FeeSponsorVaultKey {
            program_id: resolved.id.clone(),
            asset_definition_id: asset_definition_id.clone(),
        };
        let vault_balance = world
            .fee_sponsor_vaults()
            .get(&vault_key)
            .map_or_else(Quantity::zero, |vault| vault.balance.clone());
        let required = checked_quantity_add(&amount, &budget.reserve_floor, "vault reserve")?;
        if vault_balance < required {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::VaultInsufficient,
                format!(
                    "fee sponsor vault for `{asset_definition_id}` requires {required}; available {vault_balance}"
                ),
            ));
        }
        capacities.insert(
            asset_definition_id,
            FeeSponsorCapacity {
                vault_balance,
                reserve_floor: budget.reserve_floor.clone(),
                block_remaining: remaining_capacity(&budget.per_block, &block_spent),
                program_epoch_remaining: remaining_capacity(
                    &budget.per_program_epoch,
                    &program_spent,
                ),
                beneficiary_epoch_remaining: remaining_capacity(
                    &budget.per_beneficiary_epoch,
                    &beneficiary_spent,
                ),
            },
        );
    }
    Ok(capacities)
}
fn validate_signed_charge_limits(
    intent: &FeePaymentIntent,
    charges: &[FeeChargeBound],
) -> Result<(), NexusFeeAdmissionError> {
    for charge in charges {
        let limit = intent
            .charge_limits()
            .iter()
            .find(|limit| limit.kind == charge.kind)
            .ok_or_else(|| {
                NexusFeeAdmissionError::sponsor(
                    FeeRejectionCode::InvalidFeeIntent,
                    format!(
                        "signed fee intent is missing {:?} charge limit",
                        charge.kind
                    ),
                )
            })?;
        if limit.asset_definition_id != charge.asset_definition_id {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::FeeAssetNotCovered,
                format!(
                    "signed {:?} fee asset `{}` does not match required `{}`",
                    charge.kind, limit.asset_definition_id, charge.asset_definition_id
                ),
            ));
        }
        if limit.max_amount < charge.max_bound {
            return Err(NexusFeeAdmissionError::sponsor(
                FeeRejectionCode::SignedLimitExceeded,
                format!(
                    "computed {:?} fee {} exceeds signed maximum {}",
                    charge.kind, charge.max_bound, limit.max_amount
                ),
            ));
        }
    }
    Ok(())
}
/// Return the explicit signature-bound executable gas limit.
pub(crate) fn transaction_gas_limit(transaction: &SignedTransaction) -> Option<u64> {
    transaction
        .fee_payment_intent()
        .gas_limit()
        .map(core::num::NonZeroU64::get)
}
fn overlay_build_error_to_attempt_validation_fail(
    state: &mut StateTransaction<'_, '_>,
    error: crate::pipeline::overlay::OverlayBuildError,
) -> ValidationFail {
    match error.execution_deferral() {
        Some(reason) => state.defer_execution(reason),
        None => overlay_build_error_to_validation_fail(error),
    }
}
fn overlay_build_error_to_validation_fail(
    error: crate::pipeline::overlay::OverlayBuildError,
) -> ValidationFail {
    match error {
        crate::pipeline::overlay::OverlayBuildError::ExecutionOwner(message) => {
            ValidationFail::InternalError(message)
        }
        crate::pipeline::overlay::OverlayBuildError::HeaderPolicy(error) => {
            ValidationFail::IvmAdmission(error)
        }
        crate::pipeline::overlay::OverlayBuildError::AxtReject(context) => {
            ValidationFail::AxtReject(context)
        }
        crate::pipeline::overlay::OverlayBuildError::InvalidAxtPolicySnapshot(error) => {
            ValidationFail::InternalError(format!("invalid AXT policy snapshot: {error}"))
        }
        other => ValidationFail::NotPermitted(other.to_string()),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedIvmZkAvailability {
    RequireLocalBackend,
    GovernedProof,
}
fn validate_prepared_ivm_execution_policy_with_availability<R: StateReadOnly>(
    state: &R,
    metadata: &ivm::ProgramMetadata,
    zk_availability: PreparedIvmZkAvailability,
) -> Result<std::num::NonZeroU64, ValidationFail> {
    crate::pipeline::overlay::validate_header_policy(metadata)
        .map_err(ValidationFail::IvmAdmission)?;
    if zk_availability == PreparedIvmZkAvailability::RequireLocalBackend
        && metadata.mode & ivm::ivm_mode::ZK != 0
        && !(state.zk().pipa_r.enabled || state.zk().stark.enabled)
    {
        return Err(ValidationFail::IvmAdmission(
            iroha_data_model::executor::IvmAdmissionError::UnsupportedFeatureBits(
                ivm::ivm_mode::ZK,
            ),
        ));
    }
    let effective_cycles = crate::smartcontracts::ivm::validate_cycle_limits(
        metadata,
        state.pipeline().ivm_max_cycles_upper_bound,
        state.world().parameters().smart_contract().fuel(),
    )
    .map_err(ValidationFail::IvmAdmission)?;
    crate::pipeline::overlay::enforce_pre_execution_policy(
        state.pipeline().ivm_max_cycles_upper_bound,
        metadata,
    )
    .map_err(overlay_build_error_to_validation_fail)?;
    Ok(effective_cycles)
}
/// Apply the canonical first-release IVM admission policy to an already prepared program.
///
/// Preparation authenticates and predecodes the image, while this check binds local execution to
/// the node/governance limits and requires a locally enabled backend for ZK-mode execution. The
/// metadata-only interface prevents warm dispatch from rewalking authenticated opcode bytes.
pub(crate) fn validate_prepared_ivm_execution_policy<R: StateReadOnly>(
    state: &R,
    metadata: &ivm::ProgramMetadata,
) -> Result<std::num::NonZeroU64, ValidationFail> {
    validate_prepared_ivm_execution_policy_with_availability(
        state,
        metadata,
        PreparedIvmZkAvailability::RequireLocalBackend,
    )
}
// Proof-carrying execution uses the same deterministic header/resource limits, while native
// verification is selected by the governed on-chain verifier record rather than local proving
// availability toggles. `verify_ivm_proved_execution` performs that governed verification.
fn validate_governed_ivm_proved_execution_policy<R: StateReadOnly>(
    state: &R,
    metadata: &ivm::ProgramMetadata,
) -> Result<std::num::NonZeroU64, ValidationFail> {
    validate_prepared_ivm_execution_policy_with_availability(
        state,
        metadata,
        PreparedIvmZkAvailability::GovernedProof,
    )
}
#[derive(Clone, Debug)]
pub(crate) struct ContractRuntimeExecutionContext {
    pub(crate) contract_address: iroha_data_model::smart_contract::ContractAddress,
    pub(crate) contract_subject: AccountId,
    // Retained as canonical provenance for queued/nested calls. Authorization must never branch
    // on this value; caller metadata is canonicalized against WSV before this context is built.
    pub(crate) contract_alias: Option<iroha_data_model::smart_contract::ContractAlias>,
    pub(crate) entrypoint: String,
}
/// Immutable authorization selected before a contract invocation is decoded or executed.
///
/// This snapshot deliberately carries the permission name chosen from the validated artifact.
/// Apply paths must validate this exact value and must not derive a replacement from mutable
/// world state after the VM has queued effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContractEntrypointAuthorizationSnapshot {
    pub(crate) lifecycle_revision: u64,
    pub(crate) authority: AccountId,
    pub(crate) entrypoint: String,
    pub(crate) authorization: EntrypointAuthorizationV1,
    pub(crate) contract_address: iroha_data_model::smart_contract::ContractAddress,
    pub(crate) contract_alias: Option<iroha_data_model::smart_contract::ContractAlias>,
    pub(crate) contract_alias_binding: Option<crate::state::ContractAliasBindingRecord>,
    pub(crate) code_hash: iroha_crypto::Hash,
    parent: Option<Box<ContractEntrypointAuthorizationSnapshot>>,
}
impl ContractEntrypointAuthorizationSnapshot {
    /// Capture the exact live identity and selected artifact permission at dispatch time.
    pub(crate) fn new(
        authority: AccountId,
        entrypoint: String,
        authorization: EntrypointAuthorizationV1,
        identity: &code::BoundContractIdentity,
    ) -> Self {
        Self {
            lifecycle_revision: identity.lifecycle_revision,
            authority,
            entrypoint,
            authorization,
            contract_address: identity.contract_address.clone(),
            contract_alias: identity.contract_alias.clone(),
            contract_alias_binding: identity.contract_alias_binding.clone(),
            code_hash: identity.code_hash,
            parent: None,
        }
    }
    /// Attach the complete caller authorization chain for a nested invocation.
    #[must_use]
    pub(crate) fn with_parent(
        mut self,
        parent: Option<ContractEntrypointAuthorizationSnapshot>,
    ) -> Self {
        self.parent = parent.map(Box::new);
        self
    }
    /// Return whether this snapshot is the root or retains it in its caller chain.
    pub(crate) fn descends_from(&self, root: &Self) -> bool {
        self == root
            || self
                .parent
                .as_deref()
                .is_some_and(|parent| parent.descends_from(root))
    }
    /// Return whether this snapshot represents a top-level invocation.
    pub(crate) fn is_root(&self) -> bool {
        self.parent.is_none()
    }
    /// Return whether `path` is owned by the exact contract instance captured by this snapshot.
    ///
    /// Durable contract state is namespaced by the immutable contract address rather than by a
    /// movable alias. Lifecycle markers use the same address digest in their reserved namespace.
    /// Keeping this check on the snapshot prevents a valid permission for one contract from being
    /// attached to a durable write targeting another contract's namespace.
    pub(crate) fn owns_durable_state_path(&self, path: &StatePath) -> bool {
        let address = self.contract_address.to_string();
        let digest = hex::encode(iroha_crypto::Hash::new(address.as_bytes()).as_ref());
        let path: &str = path.as_ref();
        path.strip_prefix("sc/")
            .and_then(|suffix| suffix.strip_prefix(&digest))
            .is_some_and(|suffix| suffix.starts_with('/'))
            || path == code::contract_lifecycle_state_key(&self.contract_address).as_ref()
    }
    /// Validate the immutable caller relationship between every adjacent invocation.
    ///
    /// A nested contract executes as the subject account derived from its immediate caller's
    /// address. Merely retaining an arbitrary ancestor is insufficient: without this adjacency
    /// check a forged leaf could borrow an unrelated caller's permission while still embedding a
    /// valid root snapshot somewhere in its chain.
    pub(crate) fn validate_chain_structure(
        &self,
        world: &impl WorldReadOnly,
    ) -> Result<(), ValidationFail> {
        let Some(parent) = self.parent.as_deref() else {
            return Ok(());
        };
        parent.validate_chain_structure(world)?;
        let parent_subject = world
            .contract_subject_bindings()
            .get(&parent.contract_address)
            .ok_or_else(|| {
                ValidationFail::NotPermitted(format!(
                    "parent contract instance `{}` has no subject binding",
                    parent.contract_address
                ))
            })?;
        parent_subject
            .validate_for(&parent.contract_address)
            .map_err(ValidationFail::NotPermitted)?;
        if self.authority != parent_subject.subject {
            return Err(ValidationFail::NotPermitted(
                "nested contract authorization caller does not match its immediate parent contract"
                    .to_owned(),
            ));
        }
        Ok(())
    }
    /// Revalidate the captured caller permission and the exact forward/reverse live binding.
    pub(crate) fn validate(
        &self,
        world: &impl WorldReadOnly,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        self.validate_chain_structure(world)?;
        self.validate_live(world)
    }
    /// Revalidate the snapshot and require every captured invocation to be executable now.
    pub(crate) fn validate_at_height(
        &self,
        world: &impl WorldReadOnly,
        execution_height: u64,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        self.validate(world)?;
        self.validate_execution_allowed(world, execution_height)
            .map_err(Into::into)
    }
    fn validate_execution_allowed(
        &self,
        world: &impl WorldReadOnly,
        execution_height: u64,
    ) -> Result<(), ValidationFail> {
        if let Some(parent) = self.parent.as_deref() {
            parent.validate_execution_allowed(world, execution_height)?;
        }
        code::ensure_contract_execution_allowed(world, &self.contract_address, execution_height)
            .map_err(ValidationFail::NotPermitted)
    }
    fn validate_live(
        &self,
        world: &impl WorldReadOnly,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        root_scope::ensure_committed_contract_scope(world, &self.contract_address)?;
        if let Some(parent) = self.parent.as_deref() {
            parent.validate_live(world)?;
        }
        let live_code_hash = world
            .contract_instances()
            .get(&self.contract_address)
            .copied()
            .ok_or_else(|| {
                ValidationFail::NotPermitted(format!(
                    "contract instance `{}` is no longer active",
                    self.contract_address
                ))
            })?;
        if live_code_hash != self.code_hash {
            return Err(ValidationFail::NotPermitted(format!(
                "contract instance `{}` changed code binding while its call was prepared: captured `{}`, live `{}`",
                self.contract_address, self.code_hash, live_code_hash
            )).into());
        }
        let binding = world
            .contract_subject_bindings()
            .get(&self.contract_address)
            .ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "contract lifecycle binding disappeared during execution".to_owned(),
                )
            })?;
        binding
            .validate_for(&self.contract_address)
            .map_err(ValidationFail::NotPermitted)?;
        if binding.lifecycle.revision != self.lifecycle_revision {
            return Err(ValidationFail::NotPermitted(format!(
                "contract instance `{}` changed lifecycle revision while its call was prepared",
                self.contract_address
            ))
            .into());
        }
        let live_alias_binding = world
            .contract_alias_bindings()
            .get(&self.contract_address)
            .cloned();
        if live_alias_binding != self.contract_alias_binding {
            return Err(ValidationFail::NotPermitted(format!(
                "contract instance `{}` changed alias binding while its call was prepared",
                self.contract_address
            ))
            .into());
        }
        let reverse_alias = live_alias_binding
            .as_ref()
            .map(|binding| binding.alias.clone());
        if reverse_alias != self.contract_alias {
            return Err(ValidationFail::NotPermitted(format!(
                "contract instance `{}` has inconsistent captured alias binding metadata",
                self.contract_address
            ))
            .into());
        }
        if let Some(alias) = self.contract_alias.as_ref()
            && world.contract_aliases().get(alias) != Some(&self.contract_address)
        {
            return Err(ValidationFail::NotPermitted(format!(
                "contract instance `{}` has an inconsistent live alias binding",
                self.contract_address
            ))
            .into());
        }
        if world.contract_aliases().iter().any(|(alias, address)| {
            address == &self.contract_address && Some(alias) != self.contract_alias.as_ref()
        }) {
            return Err(ValidationFail::NotPermitted(format!(
                "contract instance `{}` has a non-canonical forward alias binding",
                self.contract_address
            ))
            .into());
        }
        enforce_named_contract_entrypoint_authorization(
            world,
            &self.authority,
            &self.contract_address,
            &self.entrypoint,
            &self.authorization,
        )
        .map_err(Into::into)
    }
    /// Validate the snapshot and require the apply-time caller to be the captured caller.
    pub(crate) fn validate_for_authority(
        &self,
        world: &impl WorldReadOnly,
        authority: &AccountId,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        if authority != &self.authority {
            return Err(ValidationFail::NotPermitted(
                "prepared contract authorization caller changed before apply".to_owned(),
            )
            .into());
        }
        self.validate(world)
    }
    /// Validate the apply-time caller and require the captured invocation chain to be executable.
    pub(crate) fn validate_for_authority_at_height(
        &self,
        world: &impl WorldReadOnly,
        authority: &AccountId,
        execution_height: u64,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        if authority != &self.authority {
            return Err(ValidationFail::NotPermitted(
                "prepared contract authorization caller changed before apply".to_owned(),
            )
            .into());
        }
        self.validate_at_height(world, execution_height)
    }
}
/// Reject binding mutations emitted from a lifecycle hook before executor dispatch.
///
/// This guard runs ahead of both initial and user-provided executors and is shared by owned and
/// borrowed overlay paths. Without it, a hook could deactivate/reactivate its address and let the
/// completion tombstone erase the newly staged lifecycle record.
pub(crate) fn ensure_lifecycle_hook_cannot_mutate_contract_binding(
    context: Option<&ContractRuntimeExecutionContext>,
    instruction: &InstructionBox,
) -> Result<(), ValidationFail> {
    let Some(context) = context else {
        return Ok(());
    };
    if !matches!(
        context.entrypoint.as_str(),
        "hajimari" | "始まり" | "kaizen" | "改善"
    ) {
        return Ok(());
    }
    let instruction = instruction.as_any();
    if instruction
        .downcast_ref::<iroha_data_model::isi::smart_contract_code::ActivateContractInstance>()
        .is_none()
        && instruction
            .downcast_ref::<iroha_data_model::isi::smart_contract_code::CommitContractDeployment>()
            .is_none()
        && instruction
            .downcast_ref::<iroha_data_model::isi::smart_contract_code::DeactivateContractInstance>(
            )
            .is_none()
    {
        return Ok(());
    }
    Err(ValidationFail::NotPermitted(format!(
        "lifecycle entrypoint `{}` cannot activate or deactivate contract bindings",
        context.entrypoint
    )))
}
#[derive(Clone, Debug)]
/// Parsed contract dispatch metadata used to configure IVM execution.
pub struct ContractCallExecutionContext {
    pub(crate) contract_address: Option<iroha_data_model::smart_contract::ContractAddress>,
    pub(crate) contract_subject: Option<AccountId>,
    pub(crate) contract_alias: Option<iroha_data_model::smart_contract::ContractAlias>,
    pub(crate) entrypoint: Option<String>,
    pub(crate) entrypoint_pc: Option<u64>,
    pub(crate) entrypoint_authorization: EntrypointAuthorizationV1,
    pub(crate) args: Json,
    pub(crate) argument_record: Option<ivm::PreparedArgumentRecord>,
}
/// Cache-independent inputs resolved for one deployed-contract invocation.
///
/// Keeping the prepared summary owned lets trigger execution release the outer IVM cache mutex
/// before guest-emitted instructions are applied and potentially invoke another VM-backed trigger.
#[derive(Debug)]
pub(crate) struct ResolvedContractInvocation {
    identity: code::BoundContractIdentity,
    contract_subject: AccountId,
    summary: ProgramSummary,
}
/// Effects and metering information returned by one deployed-contract invocation.
#[derive(Debug)]
pub(crate) struct ContractInvocationOutcome {
    /// Gas consumed by the VM, including execution that ended in a later artifact error.
    pub(crate) gas_used: u64,
    /// Guest-emitted instructions that were successfully applied.
    pub(crate) executed_instructions: Vec<InstructionBox>,
    /// Trigger-local NFT sequence after successful guest execution.
    pub(crate) next_nft_sequence: Option<u64>,
}
impl ContractCallExecutionContext {
    pub(crate) fn runtime_context(&self) -> Option<ContractRuntimeExecutionContext> {
        let contract_address = self.contract_address.clone()?;
        let contract_subject = self.contract_subject.clone()?;
        Some(ContractRuntimeExecutionContext {
            contract_subject,
            contract_address,
            contract_alias: self.contract_alias.clone(),
            entrypoint: self.entrypoint.clone()?,
        })
    }
    pub(crate) fn bind_runtime_identity(
        &mut self,
        identity: code::BoundContractIdentity,
        contract_subject: AccountId,
    ) {
        self.contract_address = Some(identity.contract_address);
        self.contract_subject = Some(contract_subject);
        self.contract_alias = identity.contract_alias;
    }
    pub(crate) fn entrypoint_pc(&self) -> Option<u64> {
        self.entrypoint_pc
    }
    pub(crate) fn entrypoint_authorization(&self) -> &EntrypointAuthorizationV1 {
        &self.entrypoint_authorization
    }
    pub(crate) fn args(&self) -> &Json {
        &self.args
    }
    #[cfg(test)]
    pub(crate) fn argument_record(&self) -> Option<&[u8]> {
        self.argument_record
            .as_ref()
            .map(ivm::PreparedArgumentRecord::canonical_bytes)
    }
    pub(crate) fn prepared_argument_record(&self) -> Option<&ivm::PreparedArgumentRecord> {
        self.argument_record.as_ref()
    }
}
pub(crate) fn encode_contract_argument_record(
    schema: Option<&ivm::EntrypointArgumentSchemaV1>,
    payload: Option<&Json>,
) -> Result<Option<Vec<u8>>, ValidationFail> {
    match (schema, payload) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(ValidationFail::NotPermitted(
            "zero-parameter entrypoint must not receive a payload".to_owned(),
        )),
        (Some(_), None) => Err(ValidationFail::NotPermitted(
            "parameterized entrypoint requires a payload".to_owned(),
        )),
        (Some(schema), Some(payload)) => {
            ivm_abi::arguments::encode_argument_record_from_json(schema, payload)
                .map(Some)
                .map_err(|error| {
                    ValidationFail::NotPermitted(format!(
                        "contract payload does not match the entrypoint argument schema: {error}"
                    ))
                })
        }
    }
}
fn prepare_contract_argument_record_from_json(
    schema: Option<&ivm::EntrypointArgumentSchemaV1>,
    payload: Option<&Json>,
    gas_limit: u64,
) -> Result<Option<ivm::PreparedArgumentRecord>, ValidationFail> {
    let canonical = encode_contract_argument_record(schema, payload)?;
    match (schema, canonical) {
        (None, None) => Ok(None),
        (Some(schema), Some(canonical)) => {
            ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), gas_limit)
                .map(Some)
                .map_err(|error| {
                    ValidationFail::NotPermitted(format!(
                        "failed to prepare canonical contract arguments: {error}"
                    ))
                })
        }
        _ => Err(ValidationFail::InternalError(
            "contract argument schema and canonical record diverged".to_owned(),
        )),
    }
}
fn prepare_validated_contract_argument_record(
    schema: Option<&ivm::EntrypointArgumentSchemaV1>,
    arguments: Option<&[u8]>,
    gas_limit: u64,
) -> Result<Option<ivm::PreparedArgumentRecord>, ValidationFail> {
    match (schema, arguments) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(ValidationFail::NotPermitted(
            "zero-parameter entrypoint must not carry an argument record".to_owned(),
        )),
        (Some(_), None) => Err(ValidationFail::NotPermitted(
            "parameterized entrypoint requires an argument record".to_owned(),
        )),
        (Some(schema), Some(arguments)) => ivm::prepare_argument_record_with_gas_limit(
            schema,
            Arc::<[u8]>::from(arguments),
            gas_limit,
        )
        .map(Some)
        .map_err(|error| {
            ValidationFail::NotPermitted(format!("invalid contract argument record: {error}"))
        }),
    }
}
type ResolvedContractEntrypoint = (
    u64,
    EntrypointAuthorizationV1,
    Option<ivm::EntrypointArgumentSchemaV1>,
);
#[cfg(test)]
fn resolve_callable_contract_entrypoint(
    bytecode: &[u8],
    selector: &str,
    interface_required_message: &'static str,
) -> Result<ResolvedContractEntrypoint, ValidationFail> {
    let parsed = ivm::ProgramMetadata::parse(bytecode).map_err(|err| {
        ValidationFail::NotPermitted(format!(
            "invalid contract artifact for contract call dispatch: {err}"
        ))
    })?;
    let prefix_len = parsed.prefix_len() as u64;
    let contract_interface = parsed
        .contract_interface
        .as_ref()
        .ok_or_else(|| ValidationFail::NotPermitted(interface_required_message.to_owned()))?;
    let descriptor = contract_interface
        .entrypoints
        .iter()
        .find(|candidate| candidate.name == selector)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!("unknown contract entrypoint `{selector}`"))
        })?;
    let permission = callable_contract_entrypoint_authorization(descriptor, selector)?;
    Ok((
        prefix_len + descriptor.entry_pc,
        permission,
        descriptor.argument_schema.clone(),
    ))
}
fn resolve_raw_contract_entrypoint(
    bytecode: &[u8],
    selector: &str,
    interface_required_message: &'static str,
) -> Result<ResolvedContractEntrypoint, ValidationFail> {
    let parsed = ivm::ProgramMetadata::parse(bytecode).map_err(|err| {
        ValidationFail::NotPermitted(format!(
            "invalid contract artifact for contract call dispatch: {err}"
        ))
    })?;
    let prefix_len = parsed.prefix_len() as u64;
    let contract_interface = parsed
        .contract_interface
        .as_ref()
        .ok_or_else(|| ValidationFail::NotPermitted(interface_required_message.to_owned()))?;
    let descriptor = contract_interface
        .entrypoints
        .iter()
        .find(|candidate| candidate.name == selector)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!("unknown contract entrypoint `{selector}`"))
        })?;
    let permission = raw_contract_entrypoint_authorization(descriptor, selector)?;
    Ok((
        prefix_len + descriptor.entry_pc,
        permission,
        descriptor.argument_schema.clone(),
    ))
}
fn resolve_prepared_contract_entrypoint(
    contract: &ivm::PreparedContract,
    selector: &str,
) -> Result<ResolvedContractEntrypoint, ValidationFail> {
    let descriptor = contract.entrypoint_descriptor(selector).ok_or_else(|| {
        ValidationFail::NotPermitted(format!("unknown contract entrypoint `{selector}`"))
    })?;
    let entrypoint_pc = contract.entrypoint_pc(selector).ok_or_else(|| {
        ValidationFail::NotPermitted(format!(
            "contract entrypoint `{selector}` has no validated program counter"
        ))
    })?;
    reject_unavailable_private_input_entrypoint(contract, selector)?;
    let permission = callable_contract_entrypoint_authorization(descriptor, selector)?;
    Ok((
        entrypoint_pc,
        permission,
        descriptor.argument_schema.clone(),
    ))
}
fn resolve_prepared_contract_view_entrypoint(
    contract: &ivm::PreparedContract,
    selector: &str,
) -> Result<ResolvedContractEntrypoint, ValidationFail> {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    let descriptor = contract.entrypoint_descriptor(selector).ok_or_else(|| {
        ValidationFail::NotPermitted(format!("unknown contract entrypoint `{selector}`"))
    })?;
    if descriptor.kind != EntryPointKind::View {
        return Err(ValidationFail::NotPermitted(format!(
            "contract entrypoint `{selector}` is not a read-only view"
        )));
    }
    let entrypoint_pc = contract.entrypoint_pc(selector).ok_or_else(|| {
        ValidationFail::NotPermitted(format!(
            "contract entrypoint `{selector}` has no validated program counter"
        ))
    })?;
    reject_unavailable_private_input_entrypoint(contract, selector)?;
    Ok((
        entrypoint_pc,
        descriptor.authorization.clone(),
        descriptor.argument_schema.clone(),
    ))
}
fn resolve_prepared_raw_contract_entrypoint(
    contract: &ivm::PreparedContract,
    selector: &str,
) -> Result<ResolvedContractEntrypoint, ValidationFail> {
    let descriptor = contract.entrypoint_descriptor(selector).ok_or_else(|| {
        ValidationFail::NotPermitted(format!("unknown contract entrypoint `{selector}`"))
    })?;
    let entrypoint_pc = contract.entrypoint_pc(selector).ok_or_else(|| {
        ValidationFail::NotPermitted(format!(
            "contract entrypoint `{selector}` has no validated program counter"
        ))
    })?;
    reject_unavailable_private_input_entrypoint(contract, selector)?;
    let permission = raw_contract_entrypoint_authorization(descriptor, selector)?;
    Ok((
        entrypoint_pc,
        permission,
        descriptor.argument_schema.clone(),
    ))
}
fn reject_unavailable_private_input_entrypoint(
    contract: &ivm::PreparedContract,
    selector: &str,
) -> Result<(), ValidationFail> {
    // ABI V1 deliberately has no consensus transport for private witnesses.
    // Any future proof-carrying invocation ABI must bind the seiyaku address
    // and code hash, selector, public arguments, authority and chain, state
    // root and exact read/write sets, outputs and events, gas schedule and
    // ceiling, and circuit and verifier-key versions. Raw private witnesses
    // must never enter signed transport or deterministic validator replay.
    match contract.entrypoint_requires_private_inputs(selector) {
        Some(false) => Ok(()),
        Some(true) => Err(ValidationFail::NotPermitted(format!(
            "seiyaku declaration `{selector}` reads Secret<T> private witnesses; ABI V1 consensus execution rejects raw witness transport until a complete proof-carrying invocation statement replaces deterministic replay"
        ))),
        None => Err(ValidationFail::InternalError(format!(
            "validated seiyaku selector `{selector}` is missing its bytecode-derived private-input policy"
        ))),
    }
}
/// Resolve authorization for a top-level deployed-contract transaction entrypoint.
pub(crate) fn callable_contract_entrypoint_authorization(
    descriptor: &ivm::EmbeddedEntrypointDescriptor,
    selector: &str,
) -> Result<EntrypointAuthorizationV1, ValidationFail> {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    match descriptor.kind {
        EntryPointKind::Kotoage => Ok(descriptor.authorization.clone()),
        EntryPointKind::View => Err(ValidationFail::NotPermitted(format!(
            "contract entrypoint `{selector}` is read-only and cannot be invoked as a transaction"
        ))),
        EntryPointKind::Hajimari | EntryPointKind::Kaizen => {
            Ok(EntrypointAuthorizationV1::RuntimeLifecycle)
        }
    }
}
/// Resolve authorization for raw-IVM source dispatch.
///
/// Lifecycle hooks require a consensus-bound deployed-instance transition and therefore can only
/// be selected through `Executable::ContractCall`.
pub(crate) fn raw_contract_entrypoint_authorization(
    descriptor: &ivm::EmbeddedEntrypointDescriptor,
    selector: &str,
) -> Result<EntrypointAuthorizationV1, ValidationFail> {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    match descriptor.kind {
        EntryPointKind::Kotoage => Ok(descriptor.authorization.clone()),
        EntryPointKind::View => Err(ValidationFail::NotPermitted(format!(
            "contract entrypoint `{selector}` is read-only and cannot be invoked as a transaction"
        ))),
        EntryPointKind::Hajimari | EntryPointKind::Kaizen => {
            Err(ValidationFail::NotPermitted(format!(
                "`{selector}` is a hajimari/始まり or kaizen/改善 entrypoint and requires a top-level deployed ContractCall"
            )))
        }
    }
}
/// Resolve authorization for an ordinary nested contract call.
///
/// Nested calls may invoke `kotoage`/`言挙げ` and `view` entrypoints, but lifecycle
/// hooks remain reserved for the deployment and `kaizen`/`改善` state machine.
pub(crate) fn nested_contract_entrypoint_authorization(
    descriptor: &ivm::EmbeddedEntrypointDescriptor,
    selector: &str,
) -> Result<EntrypointAuthorizationV1, ValidationFail> {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    match descriptor.kind {
        EntryPointKind::Kotoage | EntryPointKind::View => Ok(descriptor.authorization.clone()),
        EntryPointKind::Hajimari | EntryPointKind::Kaizen => {
            Err(ValidationFail::NotPermitted(format!(
                "`{selector}` is a hajimari/始まり or kaizen/改善 entrypoint and cannot be invoked by a nested call"
            )))
        }
    }
}
fn is_self_describing_contract(bytecode: &[u8]) -> bool {
    ivm::ProgramMetadata::parse(bytecode)
        .ok()
        .and_then(|parsed| parsed.contract_interface)
        .is_some()
}
enum ContractDispatchSource<'a> {
    Bytecode(&'a [u8]),
    Prepared(&'a ivm::PreparedContract),
}
impl ContractDispatchSource<'_> {
    fn resolve(
        &self,
        selector: &str,
        interface_required_message: &'static str,
    ) -> Result<ResolvedContractEntrypoint, ValidationFail> {
        match self {
            Self::Bytecode(bytecode) => {
                resolve_raw_contract_entrypoint(bytecode, selector, interface_required_message)
            }
            Self::Prepared(contract) => {
                resolve_prepared_raw_contract_entrypoint(contract, selector)
            }
        }
    }
    fn is_self_describing(&self) -> bool {
        match self {
            Self::Bytecode(bytecode) => is_self_describing_contract(bytecode),
            Self::Prepared(_) => true,
        }
    }
}
#[cfg(test)]
pub(crate) fn parse_contract_call_execution_context(
    metadata: &Metadata,
    bytecode: &[u8],
) -> Result<Option<ContractCallExecutionContext>, ValidationFail> {
    parse_contract_call_execution_context_from_source(
        metadata,
        ContractDispatchSource::Bytecode(bytecode),
        ContractArgumentSource::Metadata,
        u64::MAX,
    )
}
pub(crate) fn parse_prepared_contract_call_execution_context(
    metadata: &Metadata,
    contract: &ivm::PreparedContract,
    gas_limit: u64,
) -> Result<Option<ContractCallExecutionContext>, ValidationFail> {
    parse_contract_call_execution_context_from_source(
        metadata,
        ContractDispatchSource::Prepared(contract),
        ContractArgumentSource::Metadata,
        gas_limit,
    )
}
/// Read and normalize the explicitly selected contract entrypoint.
///
/// Callers use this cheap metadata-only step to authorize a selector before
/// argument records are decoded or materialized.
pub(crate) fn requested_contract_entrypoint(
    metadata: &Metadata,
) -> Result<Option<String>, ValidationFail> {
    let entrypoint = metadata
        .get("contract_entrypoint")
        .map(|raw| {
            raw.try_into_any_norito::<String>().map_err(|err| {
                ValidationFail::NotPermitted(format!("invalid contract_entrypoint metadata: {err}"))
            })
        })
        .transpose()?
        .map(|value| value.trim().to_owned());
    if entrypoint.as_deref().is_some_and(str::is_empty) {
        return Err(ValidationFail::NotPermitted(
            "contract_entrypoint must not be empty".to_owned(),
        ));
    }
    Ok(entrypoint)
}
/// Require a by-reference invocation to match the exact live code binding authorized by its signer.
pub(crate) fn ensure_contract_invocation_code_hash(
    invocation: &ContractInvocation,
    actual_code_hash: iroha_crypto::Hash,
) -> Result<(), ValidationFail> {
    if invocation.expected_code_hash != actual_code_hash {
        return Err(ValidationFail::NotPermitted(format!(
            "contract instance `{}` is bound to code `{actual_code_hash}`, not signed expected code `{}`",
            invocation.contract_address, invocation.expected_code_hash
        )));
    }
    Ok(())
}
/// Bind a top-level by-reference contract invocation to the exact human-reviewable
/// transaction metadata carried by the same signed payload.
///
/// Wallets can validate canonical JSON metadata without embedding a Kotodama ABI
/// encoder. Consensus therefore reconstructs the schema-bound argument record
/// from that metadata and refuses any executable whose opaque argument bytes
/// encode a different payload. A `contract_alias` entry must name the address's
/// `live_alias`, so indexers can attribute the call to that alias.
///
/// Metadata that carries any of these keys must carry the full identity binding
/// (address, code hash, entrypoint). Other keys, such as `contract_module` or
/// `contract_event_*`, are never checked and must not be trusted by readers.
fn ensure_contract_invocation_metadata_binding(
    invocation: &ContractInvocation,
    metadata: &Metadata,
    contract: &ivm::PreparedContract,
    live_alias: Option<&iroha_data_model::smart_contract::ContractAlias>,
) -> Result<(), ValidationFail> {
    let carries_reviewable_binding = [
        "contract_address",
        "contract_alias",
        "contract_code_hash",
        "contract_entrypoint",
        "contract_payload",
    ]
    .iter()
    .any(|key| metadata.get(*key).is_some());
    if !carries_reviewable_binding {
        return Ok(());
    }
    let metadata_address = requested_contract_address(metadata)?.ok_or_else(|| {
        ValidationFail::NotPermitted(
            "top-level ContractCall requires contract_address metadata".to_owned(),
        )
    })?;
    if metadata_address != invocation.contract_address {
        return Err(ValidationFail::NotPermitted(
            "top-level ContractCall address differs from contract_address metadata".to_owned(),
        ));
    }
    if let Some(metadata_alias) = requested_contract_alias(metadata)?
        && live_alias != Some(&metadata_alias)
    {
        return Err(ValidationFail::NotPermitted(format!(
            "contract_alias metadata `{metadata_alias}` is not the live alias of `{}`",
            invocation.contract_address
        )));
    }
    let code_hash_literal = metadata
        .get("contract_code_hash")
        .ok_or_else(|| {
            ValidationFail::NotPermitted(
                "top-level ContractCall requires contract_code_hash metadata".to_owned(),
            )
        })?
        .try_into_any_norito::<String>()
        .map_err(|error| {
            ValidationFail::NotPermitted(format!("invalid contract_code_hash metadata: {error}"))
        })?;
    if code_hash_literal.trim() != code_hash_literal {
        return Err(ValidationFail::NotPermitted(
            "contract_code_hash metadata must use canonical spelling".to_owned(),
        ));
    }
    let metadata_code_hash = code_hash_literal
        .parse::<iroha_crypto::Hash>()
        .map_err(|error| {
            ValidationFail::NotPermitted(format!(
                "invalid contract_code_hash metadata literal `{code_hash_literal}`: {error}"
            ))
        })?;
    if metadata_code_hash != invocation.expected_code_hash {
        return Err(ValidationFail::NotPermitted(
            "top-level ContractCall code hash differs from contract_code_hash metadata".to_owned(),
        ));
    }
    let metadata_entrypoint = requested_contract_entrypoint(metadata)?.ok_or_else(|| {
        ValidationFail::NotPermitted(
            "top-level ContractCall requires contract_entrypoint metadata".to_owned(),
        )
    })?;
    if metadata_entrypoint != invocation.entrypoint {
        return Err(ValidationFail::NotPermitted(
            "top-level ContractCall entrypoint differs from contract_entrypoint metadata"
                .to_owned(),
        ));
    }
    let descriptor = contract
        .entrypoint_descriptor(&metadata_entrypoint)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "unknown contract entrypoint `{metadata_entrypoint}`"
            ))
        })?;
    let payload = metadata.get("contract_payload");
    let canonical_arguments =
        encode_contract_argument_record(descriptor.argument_schema.as_ref(), payload)?;
    if canonical_arguments.as_deref() != invocation.arguments.as_deref() {
        return Err(ValidationFail::NotPermitted(
            "top-level ContractCall arguments differ from the canonical contract_payload metadata"
                .to_owned(),
        ));
    }
    Ok(())
}
pub(crate) fn requested_contract_address(
    metadata: &Metadata,
) -> Result<Option<iroha_data_model::smart_contract::ContractAddress>, ValidationFail> {
    metadata
        .get("contract_address")
        .map(|raw| {
            raw.try_into_any_norito::<String>().map_err(|err| {
                ValidationFail::NotPermitted(format!("invalid contract_address metadata: {err}"))
            })
        })
        .transpose()?
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ValidationFail::NotPermitted(
                    "contract_address must not be empty".to_owned(),
                ));
            }
            trimmed.parse().map_err(|err| {
                ValidationFail::NotPermitted(format!(
                    "invalid contract_address metadata literal `{trimmed}`: {err}"
                ))
            })
        })
        .transpose()
}
fn requested_contract_alias(
    metadata: &Metadata,
) -> Result<Option<iroha_data_model::smart_contract::ContractAlias>, ValidationFail> {
    metadata
        .get("contract_alias")
        .map(|raw| {
            raw.try_into_any_norito::<String>().map_err(|err| {
                ValidationFail::NotPermitted(format!("invalid contract_alias metadata: {err}"))
            })
        })
        .transpose()?
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ValidationFail::NotPermitted(
                    "contract_alias must not be empty".to_owned(),
                ));
            }
            trimmed.parse().map_err(|err| {
                ValidationFail::NotPermitted(format!(
                    "invalid contract_alias metadata literal `{trimmed}`: {err}"
                ))
            })
        })
        .transpose()
}
/// Resolve raw-IVM identity metadata exclusively through live world-state bindings.
///
/// User metadata selects an identity; it never supplies the trusted alias or
/// contract subject used by runtime authorization exceptions and state scope.
pub(crate) fn resolve_raw_contract_runtime_identity(
    world: &impl WorldReadOnly,
    code_hash: iroha_crypto::Hash,
    metadata: &Metadata,
) -> Result<Option<code::BoundContractIdentity>, ValidationFail> {
    let requested_address = requested_contract_address(metadata)?;
    let requested_alias = requested_contract_alias(metadata)?;
    let alias_address = requested_alias
        .as_ref()
        .map(|alias| {
            world.contract_aliases().get(alias).cloned().ok_or_else(|| {
                ValidationFail::NotPermitted(format!(
                    "contract alias `{alias}` is not bound in live state"
                ))
            })
        })
        .transpose()?;
    if let (Some(requested), Some(resolved)) = (&requested_address, &alias_address)
        && requested != resolved
    {
        return Err(ValidationFail::NotPermitted(format!(
            "contract alias metadata resolves to `{resolved}`, not requested address `{requested}`"
        )));
    }
    let Some(contract_address) = requested_address.or(alias_address) else {
        return Ok(None);
    };
    let bound_code_hash = world
        .contract_instances()
        .get(&contract_address)
        .copied()
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "contract instance `{contract_address}` not found in live state"
            ))
        })?;
    if bound_code_hash != code_hash {
        return Err(ValidationFail::NotPermitted(format!(
            "contract instance `{contract_address}` is bound to code `{bound_code_hash}`, not executing code `{code_hash}`"
        )));
    }
    let live_alias_binding = world
        .contract_alias_bindings()
        .get(&contract_address)
        .cloned();
    let live_alias = live_alias_binding
        .as_ref()
        .map(|binding| binding.alias.clone());
    if let Some(alias) = live_alias.as_ref()
        && world.contract_aliases().get(alias) != Some(&contract_address)
    {
        return Err(ValidationFail::NotPermitted(format!(
            "contract instance `{contract_address}` has an inconsistent live alias binding"
        )));
    }
    if requested_alias.as_ref().is_some_and(|requested| {
        live_alias.as_ref() != Some(requested)
            || world.contract_aliases().get(requested) != Some(&contract_address)
    }) {
        return Err(ValidationFail::NotPermitted(format!(
            "contract alias metadata does not match the live alias for `{contract_address}`"
        )));
    }
    Ok(Some(code::BoundContractIdentity {
        lifecycle_revision: world
            .contract_subject_bindings()
            .get(&contract_address)
            .ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "contract instance has no lifecycle binding".to_owned(),
                )
            })?
            .lifecycle
            .revision,
        contract_address,
        contract_alias: live_alias,
        contract_alias_binding: live_alias_binding,
        code_hash,
    }))
}
/// Resolve the mandatory live identity for a selected raw-IVM contract entrypoint.
///
/// A selected entrypoint is contract dispatch, even when its descriptor has no named
/// permission. It therefore cannot execute with an anonymous/state-free runtime identity.
pub(crate) fn require_raw_contract_runtime_identity(
    world: &impl WorldReadOnly,
    code_hash: iroha_crypto::Hash,
    metadata: &Metadata,
) -> Result<code::BoundContractIdentity, ValidationFail> {
    resolve_raw_contract_runtime_identity(world, code_hash, metadata)?.ok_or_else(|| {
        ValidationFail::NotPermitted(
            "raw-IVM contract entrypoint dispatch requires a live contract_address or contract_alias binding"
                .to_owned(),
        )
    })
}
#[derive(Clone, Copy)]
enum ContractArgumentSource<'a> {
    Metadata,
    TriggerEvent(&'a Json),
    SchemaOnly,
}
/// Resolve a self-describing IVM trigger callback and bind the current event
/// arguments to its compiler-emitted schema.
///
/// Trigger actions select the callback with `contract_entrypoint` metadata, but their payload is
/// supplied by the event that fired the trigger. The payload is converted here, once, into the same
/// schema-bound canonical Norito record used by ordinary contract calls. A fixed `contract_payload`
/// in trigger metadata is rejected so it cannot shadow the signed event arguments.
pub(crate) fn parse_prepared_trigger_call_execution_context(
    metadata: &Metadata,
    contract: &ivm::PreparedContract,
    event_args: &Json,
    gas_limit: u64,
) -> Result<ContractCallExecutionContext, ValidationFail> {
    parse_contract_call_execution_context_from_source(
        metadata,
        ContractDispatchSource::Prepared(contract),
        ContractArgumentSource::TriggerEvent(event_args),
        gas_limit,
    )?
    .ok_or_else(|| {
        ValidationFail::NotPermitted(
            "self-describing IVM trigger action did not resolve a callback".to_owned(),
        )
    })
}
/// Bind a deployed trigger callback to its firing event using the signed schema.
///
/// A registered callback cannot shadow event arguments with a fixed call record.
/// Zero-argument callbacks still receive the event through `context::trigger_event`.
pub(crate) fn parse_prepared_trigger_invocation_execution_context(
    invocation: &ContractInvocation,
    contract: &ivm::PreparedContract,
    contract_alias: Option<iroha_data_model::smart_contract::ContractAlias>,
    contract_subject: AccountId,
    event_args: &Json,
    gas_limit: u64,
) -> Result<ContractCallExecutionContext, ValidationFail> {
    if invocation.arguments.is_some() {
        return Err(ValidationFail::NotPermitted(
            "trigger callbacks must take arguments from the firing event, not a fixed call record"
                .to_owned(),
        ));
    }
    let selector = invocation.entrypoint.as_str();
    let (entrypoint_pc, entrypoint_authorization, argument_schema) =
        resolve_prepared_raw_contract_entrypoint(contract, selector)?;
    let argument_record = prepare_contract_argument_record_from_json(
        argument_schema.as_ref(),
        argument_schema.as_ref().map(|_| event_args),
        gas_limit,
    )?;
    Ok(ContractCallExecutionContext {
        contract_address: Some(invocation.contract_address.clone()),
        contract_subject: Some(contract_subject),
        contract_alias,
        entrypoint: Some(selector.to_owned()),
        entrypoint_pc: Some(entrypoint_pc),
        entrypoint_authorization,
        args: event_args.clone(),
        argument_record,
    })
}
/// Validate trigger callback selection at registration without fabricating an
/// event payload for a parameterized callback.
pub(crate) fn validate_trigger_call_execution_context(
    metadata: &Metadata,
    bytecode: &[u8],
) -> Result<(), ValidationFail> {
    parse_contract_call_execution_context_from_source(
        metadata,
        ContractDispatchSource::Bytecode(bytecode),
        ContractArgumentSource::SchemaOnly,
        u64::MAX,
    )?
    .ok_or_else(|| {
        ValidationFail::NotPermitted(
            "self-describing IVM trigger action did not resolve a callback".to_owned(),
        )
    })?;
    Ok(())
}
fn parse_contract_call_execution_context_from_source(
    metadata: &Metadata,
    source: ContractDispatchSource<'_>,
    argument_source: ContractArgumentSource<'_>,
    gas_limit: u64,
) -> Result<Option<ContractCallExecutionContext>, ValidationFail> {
    let contract_address = requested_contract_address(metadata)?;
    let contract_alias = requested_contract_alias(metadata)?;
    let entrypoint = requested_contract_entrypoint(metadata)?;
    let metadata_payload = metadata.get("contract_payload").cloned();
    if !matches!(argument_source, ContractArgumentSource::Metadata) && metadata_payload.is_some() {
        return Err(ValidationFail::NotPermitted(
            "IVM trigger actions must take arguments from the triggering event, not contract_payload metadata"
                .to_owned(),
        ));
    }
    let (entrypoint, entrypoint_pc, entrypoint_authorization, argument_schema) =
        if let Some(selector) = entrypoint.as_deref() {
            let (entrypoint_pc, entrypoint_authorization, argument_schema) = source.resolve(
                selector,
                "contract call entrypoint metadata requires a self-describing contract artifact",
            )?;
            (
                Some(selector.to_owned()),
                Some(entrypoint_pc),
                entrypoint_authorization,
                argument_schema,
            )
        } else if source.is_self_describing() {
            return Err(ValidationFail::NotPermitted(
                "self-describing contract calls require explicit contract_entrypoint metadata"
                    .to_owned(),
            ));
        } else if metadata_payload.is_none() {
            return Ok(None);
        } else {
            (None, None, EntrypointAuthorizationV1::Anyone, None)
        };
    let payload = match argument_source {
        ContractArgumentSource::Metadata => metadata_payload,
        ContractArgumentSource::TriggerEvent(event_args) => {
            argument_schema.as_ref().map(|_| event_args.clone())
        }
        ContractArgumentSource::SchemaOnly => None,
    };
    let argument_record = if matches!(argument_source, ContractArgumentSource::SchemaOnly) {
        None
    } else {
        prepare_contract_argument_record_from_json(
            argument_schema.as_ref(),
            payload.as_ref(),
            gas_limit,
        )?
    };
    let args = match argument_source {
        ContractArgumentSource::TriggerEvent(event_args) => event_args.clone(),
        ContractArgumentSource::Metadata | ContractArgumentSource::SchemaOnly => {
            payload.unwrap_or_default()
        }
    };
    Ok(Some(ContractCallExecutionContext {
        contract_address,
        contract_subject: None,
        contract_alias,
        entrypoint,
        entrypoint_pc,
        entrypoint_authorization,
        args,
        argument_record,
    }))
}
#[cfg(test)]
pub(crate) fn parse_contract_invocation_execution_context(
    invocation: &ContractInvocation,
    bytecode: &[u8],
    contract_alias: Option<iroha_data_model::smart_contract::ContractAlias>,
    contract_subject: AccountId,
) -> Result<ContractCallExecutionContext, ValidationFail> {
    let selector = invocation.entrypoint.trim();
    if selector.is_empty() {
        return Err(ValidationFail::NotPermitted(
            "contract entrypoint must not be empty".to_owned(),
        ));
    }
    let (entrypoint_pc, entrypoint_authorization, argument_schema) =
        resolve_callable_contract_entrypoint(
            bytecode,
            selector,
            "contract call requires a self-describing contract artifact",
        )?;
    let args = Json::default();
    let argument_record = prepare_validated_contract_argument_record(
        argument_schema.as_ref(),
        invocation.arguments.as_deref(),
        u64::MAX,
    )?;
    Ok(ContractCallExecutionContext {
        contract_address: Some(invocation.contract_address.clone()),
        contract_subject: Some(contract_subject),
        contract_alias,
        entrypoint: Some(selector.to_owned()),
        entrypoint_pc: Some(entrypoint_pc),
        entrypoint_authorization,
        args,
        argument_record,
    })
}
pub(crate) fn parse_prepared_contract_invocation_execution_context(
    invocation: &ContractInvocation,
    contract: &ivm::PreparedContract,
    contract_alias: Option<iroha_data_model::smart_contract::ContractAlias>,
    contract_subject: AccountId,
    gas_limit: u64,
) -> Result<ContractCallExecutionContext, ValidationFail> {
    let selector = invocation.entrypoint.trim();
    if selector.is_empty() {
        return Err(ValidationFail::NotPermitted(
            "contract entrypoint must not be empty".to_owned(),
        ));
    }
    let (entrypoint_pc, entrypoint_authorization, argument_schema) =
        resolve_prepared_contract_entrypoint(contract, selector)?;
    let args = Json::default();
    let argument_record = prepare_validated_contract_argument_record(
        argument_schema.as_ref(),
        invocation.arguments.as_deref(),
        gas_limit,
    )?;
    Ok(ContractCallExecutionContext {
        contract_address: Some(invocation.contract_address.clone()),
        contract_subject: Some(contract_subject),
        contract_alias,
        entrypoint: Some(selector.to_owned()),
        entrypoint_pc: Some(entrypoint_pc),
        entrypoint_authorization,
        args,
        argument_record,
    })
}
/// Validate a top-level deployed entrypoint against the instance lifecycle state.
pub(crate) fn validate_prepared_contract_lifecycle_call(
    world: &impl WorldReadOnly,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    code_hash: iroha_crypto::Hash,
    contract: &ivm::PreparedContract,
    selector: &str,
) -> Result<Option<code::PendingContractLifecycle>, ValidationFail> {
    let descriptor = contract.entrypoint_descriptor(selector).ok_or_else(|| {
        ValidationFail::NotPermitted(format!("unknown contract entrypoint `{selector}`"))
    })?;
    code::validate_contract_lifecycle_call(world, contract_address, code_hash, descriptor.kind)
}
pub(crate) fn compute_nexus_fee_amount(
    cfg: &iroha_config::parameters::actual::NexusFees,
    tx_bytes_len: usize,
    instruction_count: usize,
    gas_used: u64,
) -> Result<Quantity, ValidationFail> {
    let tx_bytes_u64 = u64::try_from(tx_bytes_len).map_err(|_| {
        ValidationFail::InternalError("transaction too large for fee accounting".to_owned())
    })?;
    let instr_u64 = u64::try_from(instruction_count).map_err(|_| {
        ValidationFail::InternalError("instruction count too large for fee accounting".to_owned())
    })?;
    let mut fee = cfg.base_fee.clone();
    for (unit, count) in [
        (&cfg.per_byte_fee, tx_bytes_u64),
        (&cfg.per_instruction_fee, instr_u64),
        (&cfg.per_gas_unit_fee, gas_used),
    ] {
        let delta = unit.try_mul_decimal(&Numeric::from(count)).map_err(|_| {
            ValidationFail::NotPermitted("fee amount exceeds supported numeric bounds".to_owned())
        })?;
        fee = fee.checked_add(&delta).map_err(|_| {
            ValidationFail::NotPermitted("fee amount exceeds supported numeric bounds".to_owned())
        })?;
    }
    Ok(fee)
}
fn fee_bound_for_admission_payload(
    payload: &TransactionPayload,
) -> Result<(usize, usize, u64), NexusFeeAdmissionError> {
    let tx_bytes_len = norito::canonical_frame_len(payload).map_err(|err| {
        NexusFeeAdmissionError::ConfigInvalid(format!(
            "failed to encode transaction for fee metering: {err}"
        ))
    })?;
    let (instruction_count, gas_used) = match &payload.instructions {
        Executable::Instructions(instructions) => (
            instructions.len(),
            isi_gas::meter_instructions(instructions.as_ref()),
        ),
        Executable::ContractCall(_) | Executable::Ivm(_) => {
            let gas_limit = payload
                .fee_payment
                .gas_limit()
                .map(core::num::NonZeroU64::get)
                .ok_or_else(|| {
                    NexusFeeAdmissionError::rejected(
                        FeeRejectionCode::InvalidGasLimit,
                        "missing gas limit in fee payment intent",
                    )
                })?;
            (0, gas_limit)
        }
        Executable::IvmProved(proved) => {
            let gas_limit = payload
                .fee_payment
                .gas_limit()
                .map(core::num::NonZeroU64::get)
                .ok_or_else(|| {
                    NexusFeeAdmissionError::rejected(
                        FeeRejectionCode::InvalidGasLimit,
                        "missing gas limit in fee payment intent",
                    )
                })?;
            (proved.overlay.len(), gas_limit)
        }
        Executable::Batch(items) => {
            let instructions: Vec<_> = items
                .iter()
                .filter_map(|item| match item {
                    ExecutableBatchItem::Instruction(instruction) => Some(instruction.clone()),
                    ExecutableBatchItem::ContractCall(_) => None,
                })
                .collect();
            let contains_contract_call = items
                .iter()
                .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)));
            let gas_used = if contains_contract_call {
                payload
                    .fee_payment
                    .gas_limit()
                    .map(core::num::NonZeroU64::get)
                    .ok_or_else(|| {
                        NexusFeeAdmissionError::rejected(
                            FeeRejectionCode::InvalidGasLimit,
                            "missing gas limit in fee payment intent",
                        )
                    })?
            } else {
                isi_gas::meter_instructions(&instructions)
            };
            (instructions.len(), gas_used)
        }
    };
    Ok((tx_bytes_len, instruction_count, gas_used))
}
fn fee_bound_for_admission(
    transaction: &SignedTransaction,
) -> Result<(usize, usize, u64), NexusFeeAdmissionError> {
    fee_bound_for_admission_payload(transaction.payload())
}
fn pipeline_gas_component_enabled(
    nexus: &iroha_config::parameters::actual::Nexus,
    pipeline: &Pipeline,
) -> bool {
    !pipeline.gas.accepted_assets.is_empty() && nexus.fees.per_gas_unit_fee.is_zero()
}
fn resolve_pipeline_gas_quote_asset(
    world: &impl WorldReadOnly,
    pipeline: &Pipeline,
    payload: &TransactionPayload,
    validate_charge_limits: bool,
) -> Result<(AssetDefinitionId, AssetDefinition, u64), NexusFeeAdmissionError> {
    let requested = payload
        .fee_payment
        .charge_limits()
        .iter()
        .find(|limit| limit.kind == FeeChargeKind::PipelineGas)
        .map(|limit| limit.asset_definition_id.canonical_address());
    let requested_is_accepted = requested.as_ref().is_some_and(|requested| {
        pipeline
            .gas
            .accepted_assets
            .iter()
            .any(|accepted| accepted == requested)
    });
    let sponsor_revision =
        payload
            .fee_payment
            .sponsor_program()
            .and_then(|(program_id, revision)| {
                world
                    .fee_sponsor_program_revisions()
                    .get(&FeeSponsorProgramRevisionKey::new(
                        program_id.clone(),
                        revision,
                    ))
            });
    let sponsor_covers = |asset: &str| {
        sponsor_revision.is_none_or(|revision| {
            revision
                .asset_budgets
                .iter()
                .any(|budget| budget.asset_definition_id.canonical_address() == asset)
        })
    };
    let selected = if validate_charge_limits {
        let requested = requested.ok_or_else(|| {
            NexusFeeAdmissionError::rejected(
                FeeRejectionCode::InvalidFeeIntent,
                "signed fee intent is missing PipelineGas charge limit",
            )
        })?;
        if !requested_is_accepted {
            return Err(NexusFeeAdmissionError::rejected(
                FeeRejectionCode::FeeAssetNotCovered,
                format!("pipeline gas asset `{requested}` is not accepted by node policy"),
            ));
        }
        requested
    } else if requested_is_accepted
        && requested
            .as_deref()
            .is_some_and(|asset| sponsor_covers(asset))
    {
        requested.expect("accepted requested pipeline gas asset exists")
    } else {
        pipeline
            .gas
            .accepted_assets
            .iter()
            .find(|asset| sponsor_covers(asset))
            .cloned()
            .ok_or_else(|| {
                NexusFeeAdmissionError::ConfigInvalid(
                    "pipeline gas is enabled without an accepted asset".to_owned(),
                )
            })?
    };
    let rate = pipeline
        .gas
        .units_per_gas
        .iter()
        .find(|rate| rate.asset == selected)
        .ok_or_else(|| {
            NexusFeeAdmissionError::ConfigInvalid(format!(
                "missing pipeline gas units_per_gas mapping for `{selected}`"
            ))
        })?;
    if rate.units_per_gas == 0 {
        return Err(NexusFeeAdmissionError::ConfigInvalid(format!(
            "pipeline gas units_per_gas mapping for `{selected}` must be positive"
        )));
    }
    let parsed = AssetDefinitionId::parse_address_literal(&selected).map_err(|_| {
        NexusFeeAdmissionError::ConfigInvalid(format!(
            "invalid pipeline gas asset `{selected}`; expected a canonical asset definition address"
        ))
    })?;
    let (asset_definition_id, definition) = if let Ok(definition) = world.asset_definition(&parsed)
    {
        (definition.id().clone(), definition)
    } else {
        world
            .asset_definitions()
            .iter()
            .find(|(id, _)| id.canonical_address() == selected)
            .map(|(id, definition)| (id.clone(), definition.clone()))
            .ok_or_else(|| {
                NexusFeeAdmissionError::ConfigInvalid(format!(
                    "pipeline gas asset `{selected}` is not registered"
                ))
            })?
    };
    Ok((asset_definition_id, definition, rate.units_per_gas))
}
fn authority_fee_asset_id(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    route_dataspace_id: Option<DataSpaceId>,
    charge: &FeeChargeBound,
) -> Result<AssetId, crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>> {
    if charge.kind == FeeChargeKind::Nexus {
        let scope = private_fees::private_scope(world, route_dataspace_id)?
            .map_or(AssetBalanceScope::Global, AssetBalanceScope::Dataspace);
        return Ok(AssetId::with_scope(
            charge.asset_definition_id.clone(),
            authority.clone(),
            scope,
        ));
    }
    let definition = world
        .asset_definition(&charge.asset_definition_id)
        .map_err(|_| {
            NexusFeeAdmissionError::ConfigInvalid(format!(
                "quoted fee asset `{}` disappeared before authority balance evaluation",
                charge.asset_definition_id
            ))
        })?;
    let scope = match definition.balance_scope_policy() {
        AssetBalancePolicy::Global => AssetBalanceScope::Global,
        AssetBalancePolicy::DataspaceRestricted => {
            AssetBalanceScope::Dataspace(route_dataspace_id.unwrap_or(DataSpaceId::UNIVERSAL))
        }
    };
    Ok(AssetId::with_scope(
        charge.asset_definition_id.clone(),
        authority.clone(),
        scope,
    ))
}
/// Refuse the retired receipt settlement mode before any monetary effect or plan.
fn require_direct_fee_settlement(
    nexus: &iroha_config::parameters::actual::Nexus,
) -> Result<(), NexusFeeAdmissionError> {
    if nexus.fees.settlement_mode
        != iroha_config::parameters::actual::NexusFeeSettlementMode::Direct
    {
        return Err(NexusFeeAdmissionError::ConfigInvalid(
            "retired lane-relay-burn fee settlement is not admitted by native execution".to_owned(),
        ));
    }
    Ok(())
}
fn evaluate_nexus_fee_admission_payload(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    pipeline: &Pipeline,
    payload: &TransactionPayload,
    observation_time_ms: u64,
    next_block_height: u64,
    route_dataspace_id: Option<DataSpaceId>,
    validate_charge_limits: bool,
) -> Result<
    FeeAdmissionQuote,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    require_direct_fee_settlement(nexus)?;
    let fees = private_fees::effective(world, &nexus.fees)?;
    // TODO: Private sponsorship needs vaults with exact dataspace custody. Public
    // sponsor-program identifiers alone cannot authorize a private monetary debit.
    if private_fees::private_scope(world, route_dataspace_id)?.is_some()
        && payload.fee_payment.sponsor_program().is_some()
    {
        return Err(NexusFeeAdmissionError::ConfigInvalid(
            "private-root fee sponsors require a scoped vault owner".into(),
        )
        .into());
    }
    let (tx_bytes_len, instruction_count, gas_used) = fee_bound_for_admission_payload(payload)?;
    let mut charges = Vec::with_capacity(2);
    let fee = compute_nexus_fee_amount(&fees, tx_bytes_len, instruction_count, gas_used)
        .map_err(validation_fail_to_nexus_fee_admission_error)?;
    let asset_definition_id = private_fees::currency(world, &fees, observation_time_ms)?;
    if !fee.is_zero() {
        charges.push(FeeChargeBound {
            kind: FeeChargeKind::Nexus,
            asset_definition_id,
            max_bound: fee,
        });
    }
    if !pipeline.gas.accepted_assets.is_empty() && fees.per_gas_unit_fee.is_zero() && gas_used > 0 {
        let (asset_definition_id, _definition, units_per_gas) =
            resolve_pipeline_gas_quote_asset(world, pipeline, payload, validate_charge_limits)?;
        let max_bound = Quantity::from(u128::from(gas_used) * u128::from(units_per_gas));
        if !max_bound.is_zero() {
            charges.push(FeeChargeBound {
                kind: FeeChargeKind::PipelineGas,
                asset_definition_id,
                max_bound,
            });
        }
    }
    charges.sort_by_key(|charge| charge.kind);
    let intent = &payload.fee_payment;
    if validate_charge_limits {
        validate_signed_charge_limits(intent, &charges)?;
    }
    match intent.sponsor_program() {
        None => {
            let mut required_by_asset = BTreeMap::<AssetId, Quantity>::new();
            let mut authority_charge_assets = BTreeMap::new();
            for charge in &charges {
                let payer_asset =
                    authority_fee_asset_id(world, &payload.authority, route_dataspace_id, charge)?;
                authority_charge_assets.insert(charge.kind, payer_asset.clone());
                let current = required_by_asset
                    .get(&payer_asset)
                    .cloned()
                    .unwrap_or_else(Quantity::zero);
                required_by_asset.insert(
                    payer_asset,
                    checked_quantity_add(&current, &charge.max_bound, "authority charge")?,
                );
            }
            let mut authority_balances = BTreeMap::new();
            for (payer_asset, required) in required_by_asset {
                let available = world
                    .assets()
                    .get(&payer_asset)
                    .map_or_else(Quantity::zero, |balance| balance.as_ref().clone());
                if available < required {
                    return Err(NexusFeeAdmissionError::rejected(
                        FeeRejectionCode::AuthorityPayerInsufficient,
                        format!(
                            "fee balance `{payer_asset}` for authority `{}` is insufficient: requires {required}, available {available}",
                            payload.authority
                        ),
                    ).into());
                }
                authority_balances.insert(payer_asset, available);
            }
            Ok(FeeAdmissionQuote {
                charges,
                debit_source: FeeDebitSource::Account(payload.authority.clone()),
                program_revision: None,
                relay_leases: BTreeMap::new(),
                capacities: BTreeMap::new(),
                authority_balances,
                authority_charge_assets,
            })
        }
        Some((program_id, program_revision)) => {
            let resolved = resolve_fee_sponsor_program(
                world,
                nexus,
                program_id,
                program_revision,
                &payload.authority,
                payload,
                route_dataspace_id,
                next_block_height,
                fee_sponsor_multisig::RuleContext::admission(observation_time_ms),
            )?;
            let capacities = evaluate_fee_sponsor_capacity(
                world,
                &resolved,
                &payload.authority,
                next_block_height,
                &charges,
            )?;
            Ok(FeeAdmissionQuote {
                charges,
                debit_source: FeeDebitSource::SponsorProgram(program_id.clone()),
                program_revision: Some(program_revision),
                relay_leases: BTreeMap::new(),
                capacities,
                authority_balances: BTreeMap::new(),
                authority_charge_assets: BTreeMap::new(),
            })
        }
    }
}
/// Quote and validate the exact fee funding source for a canonical unsigned draft.
///
/// The fee byte component is measured over the canonical [`TransactionPayload`] encoding, so this
/// result remains identical after the payload is signed. The supplied intent must already contain
/// adequate signature-bound charge limits. Protocol and successful-claim exemptions return an
/// accepted zero-component quote because execution skips the same exact signed payloads.
pub fn quote_nexus_fee_admission_payload(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    pipeline: &Pipeline,
    payload: &TransactionPayload,
    observation_time_ms: u64,
    next_block_height: u64,
    route_dataspace_id: Option<DataSpaceId>,
) -> Result<
    FeeAdmissionQuote,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    require_direct_fee_settlement(nexus)?;
    if fee_exempt_payload(world, nexus, payload, observation_time_ms)
        .map_err(crate::execution_attempt::ExecutionAttemptError::Deferred)?
    {
        return Ok(fee_exempt_admission_quote(payload));
    }
    evaluate_nexus_fee_admission_payload(
        world,
        nexus,
        pipeline,
        payload,
        observation_time_ms,
        next_block_height,
        route_dataspace_id,
        true,
    )
}
fn fee_intent_with_exact_bounds(
    template: &FeePaymentIntent,
    charges: &[FeeChargeBound],
) -> FeePaymentIntent {
    let limits = charges
        .iter()
        .map(|charge| {
            FeeChargeLimit::new(
                charge.kind,
                charge.asset_definition_id.clone(),
                charge.max_bound.clone(),
            )
        })
        .collect();
    match template {
        FeePaymentIntent::Authority(payment) => {
            FeePaymentIntent::authority(limits, payment.gas_limit)
        }
        FeePaymentIntent::Sponsor(payment) => FeePaymentIntent::sponsor(
            payment.program_id.clone(),
            payment.program_revision,
            limits,
            payment.gas_limit,
        ),
    }
}
fn fee_exempt_admission_quote(payload: &TransactionPayload) -> FeeAdmissionQuote {
    let (debit_source, program_revision) = payload.fee_payment.sponsor_program().map_or_else(
        || (FeeDebitSource::Account(payload.authority.clone()), None),
        |(program_id, revision)| {
            (
                FeeDebitSource::SponsorProgram(program_id.clone()),
                Some(revision),
            )
        },
    );
    FeeAdmissionQuote {
        charges: Vec::new(),
        debit_source,
        program_revision,
        relay_leases: BTreeMap::new(),
        capacities: BTreeMap::new(),
        authority_balances: BTreeMap::new(),
        authority_charge_assets: BTreeMap::new(),
    }
}
/// Discover the exact charge limits for an unsigned transaction draft.
///
/// Callers may supply empty or stale limits. Core deterministically reaches a fixed point because
/// the limits themselves contribute to the canonical byte fee, then returns the exact
/// [`FeePaymentIntent`] to place in the payload before signing. Exempt payloads canonicalize
/// directly to empty charge limits. Queue admission intentionally uses the strict quote API.
pub fn quote_nexus_fee_admission_draft(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    pipeline: &Pipeline,
    payload: &TransactionPayload,
    observation_time_ms: u64,
    next_block_height: u64,
    route_dataspace_id: Option<DataSpaceId>,
) -> Result<
    FeeAdmissionDraftQuote,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    require_direct_fee_settlement(nexus)?;
    if fee_exempt_payload(world, nexus, payload, observation_time_ms)
        .map_err(crate::execution_attempt::ExecutionAttemptError::Deferred)?
    {
        // TODO(ws31): an SCCP payload is exempt on success only, and a failure is charged
        // only within its signed limits (`specs/sccp.md` §4.19). Recommend the ordinary
        // limits for such payloads (without requiring the payer to hold the fee asset now),
        // so a funded signer of an eligible SCCP transaction makes its failure chargeable.
        return Ok(FeeAdmissionDraftQuote {
            quote: fee_exempt_admission_quote(payload),
            recommended_intent: fee_intent_with_exact_bounds(&payload.fee_payment, &[]),
        });
    }
    let mut candidate = payload.clone();
    // Canonical numeric and sequence encodings settle after only a few boundary
    // crossings. Keep a hard deterministic guard against malformed schedules.
    for _ in 0..32 {
        let quote = evaluate_nexus_fee_admission_payload(
            world,
            nexus,
            pipeline,
            &candidate,
            observation_time_ms,
            next_block_height,
            route_dataspace_id,
            false,
        )?;
        let recommended_intent =
            fee_intent_with_exact_bounds(&candidate.fee_payment, &quote.charges);
        if candidate.fee_payment == recommended_intent {
            let quote = evaluate_nexus_fee_admission_payload(
                world,
                nexus,
                pipeline,
                &candidate,
                observation_time_ms,
                next_block_height,
                route_dataspace_id,
                true,
            )?;
            return Ok(FeeAdmissionDraftQuote {
                quote,
                recommended_intent,
            });
        }
        candidate.fee_payment = recommended_intent;
    }
    Err(NexusFeeAdmissionError::ConfigInvalid(
        "fee quote did not converge to a canonical charge-limit fixed point".to_owned(),
    )
    .into())
}
/// Quote and validate the fee funding source selected by a signed transaction.
///
/// This is the queue/admission wrapper around
/// [`quote_nexus_fee_admission_payload`]; signatures do not affect fee bytes.
pub fn quote_nexus_fee_admission(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    pipeline: &Pipeline,
    transaction: &SignedTransaction,
    observation_time_ms: u64,
    next_block_height: u64,
    route_dataspace_id: Option<DataSpaceId>,
) -> Result<
    FeeAdmissionQuote,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    quote_nexus_fee_admission_payload(
        world,
        nexus,
        pipeline,
        transaction.payload(),
        observation_time_ms,
        next_block_height,
        route_dataspace_id,
    )
}
#[cfg(test)]
pub(crate) mod sorafs_admission_hash_probe {
    //! Per-thread observation of the actual initializer helper's outer hash call.
    use std::cell::Cell;

    thread_local! {
        static HASHES: Cell<Option<usize>> = const { Cell::new(None) };
    }

    /// Observe the next original outer hash only while this thread has an active probe.
    pub(crate) fn note_outer_hash() {
        HASHES.with(|hashes| {
            if let Some(count) = hashes.get() {
                hashes.set(Some(count + 1));
            }
        });
    }

    /// Count actual helper hashes in one lexical call, restoring prior state even on unwind.
    pub(crate) fn count<R>(body: impl FnOnce() -> R) -> (R, usize) {
        struct Restore(Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                HASHES.with(|hashes| hashes.set(self.0));
            }
        }
        let restore = Restore(HASHES.with(|hashes| hashes.replace(Some(0))));
        let result = body();
        let count = HASHES.with(|hashes| hashes.get().expect("active hash observation"));
        drop(restore);
        (result, count)
    }
}

/// Return whether execution is running inside the chain's initial genesis block.
///
/// The empty committed-block history keeps a genesis-shaped header replayed against live state
/// outside every bootstrap-only permission and fee exception.
pub(crate) fn is_initial_genesis_context(state_transaction: &StateTransaction<'_, '_>) -> bool {
    state_transaction._curr_block.is_genesis() && state_transaction.block_hashes.is_empty()
}
pub(crate) fn quote_external_nexus_fee_admission(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    pipeline: &Pipeline,
    transaction: &SignedTransaction,
    observation_time_ms: u64,
    next_block_height: u64,
    route_dataspace_id: Option<DataSpaceId>,
) -> Result<
    Option<FeeAdmissionQuote>,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    if fee_exempt_transaction(world, nexus, transaction, observation_time_ms)
        .map_err(crate::execution_attempt::ExecutionAttemptError::Deferred)?
    {
        return Ok(None);
    }
    quote_nexus_fee_admission(
        world,
        nexus,
        pipeline,
        transaction,
        observation_time_ms,
        next_block_height,
        route_dataspace_id,
    )
    .map(|quote| (!quote.charges.is_empty()).then_some(quote))
}
/// Revalidate the exact signed fee intent against the state used for block execution.
///
/// Queue reservations are an availability optimization, not consensus authority. Except for the
/// authentic initial genesis bootstrap, every execution path, including overlay application, must
/// run this check before applying business effects so a block producer cannot bypass signed maxima,
/// sponsor rules, budgets, or payer balance checks.
pub(crate) fn validate_transaction_fee_admission(
    state_transaction: &mut StateTransaction<'_, '_>,
    transaction: &SignedTransaction,
) -> Result<(), ValidationFail> {
    if is_initial_genesis_context(state_transaction)
        || transaction_fee_exemption(state_transaction, transaction)
            .map_err(|reason| state_transaction.defer_execution(reason))?
            .0
            .skips_fee_on_success()
    {
        return Ok(());
    }
    Executor::refresh_gas_from_parameters(state_transaction)?;
    quote_nexus_fee_admission(
        &state_transaction.world,
        &state_transaction.nexus,
        &state_transaction.pipeline,
        transaction,
        state_transaction.block_unix_timestamp_ms(),
        state_transaction.block_height(),
        state_transaction.current_dataspace_id,
    )
    .map_err(|error| {
        state_transaction.attempt_error_to_validation_fail(
            error.map_rejection(nexus_fee_admission_error_to_validation_fail),
        )
    })?;
    Ok(())
}
#[cfg(test)]
fn applied_overlay_base_gas(
    transaction: &SignedTransaction,
    overlay: &crate::pipeline::overlay::TxOverlay,
) -> Result<(u64, usize), ValidationFail> {
    let gas_limit = transaction_gas_limit(transaction);
    let (gas_used, instruction_count, require_gas_limit) = match transaction.instructions() {
        Executable::ContractCall(_) | Executable::Ivm(_) => (
            overlay.ivm_gas_used().ok_or_else(|| {
                ValidationFail::InternalError(
                    "missing IVM gas usage metadata for overlay-applied transaction".to_owned(),
                )
            })?,
            0,
            true,
        ),
        Executable::Instructions(_) => (
            overlay.instructions().fold(0_u64, |gas, instruction| {
                gas.saturating_add(isi_gas::meter_instruction(instruction))
            }),
            overlay.instruction_count(),
            false,
        ),
        Executable::IvmProved(_) => (
            overlay.ivm_gas_used().ok_or_else(|| {
                ValidationFail::InternalError(
                    "missing replayed IVM gas usage metadata for proved overlay transaction"
                        .to_owned(),
                )
            })?,
            overlay.instruction_count(),
            true,
        ),
        Executable::Batch(_) => {
            return Err(ValidationFail::InternalError(
                "mixed batch reached overlay fee settlement".to_owned(),
            ));
        }
    };
    if require_gas_limit && gas_limit.is_none() {
        return Err(ValidationFail::NotPermitted(
            "missing gas limit in fee payment intent".to_owned(),
        ));
    }
    if let Some(limit) = gas_limit
        && gas_used > limit
    {
        return Err(ValidationFail::NotPermitted(format!(
            "out of gas: used {gas_used} > limit {limit}"
        )));
    }
    Ok((gas_used, instruction_count))
}

#[cfg(test)]
/// Reference gas and SORA Nexus fee settlement for overlay regression tests.
///
/// The caller snapshots metering before consuming the overlay, then settles against
/// the pre-effect fee policy after applying its owned effects.
fn charge_fees_for_applied_overlay(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    transaction: &SignedTransaction,
    gas_used: u64,
    instruction_count: usize,
) -> Result<(), ValidationFail> {
    // Genesis transactions are bootstrap operations and must remain fee-free.
    if is_initial_genesis_context(state_transaction) {
        return Ok(());
    }
    let tx_bytes_len = norito::canonical_frame_len(transaction.payload()).map_err(|err| {
        ValidationFail::InternalError(format!(
            "failed to encode transaction payload for fee metering: {err}"
        ))
    })?;
    let fee_sponsor = transaction
        .fee_payment_intent()
        .sponsor_program()
        .map(|(program_id, _)| program_id.clone());
    let skip_nexus_fee = transaction_fee_exemption(state_transaction, transaction)
        .map_err(|reason| state_transaction.defer_execution(reason))?
        .0
        .skips_fee_on_success();
    // Admission captured the governed gas policy before business effects were applied.
    // Keep that immutable snapshot for settlement so this transaction cannot alter its
    // own fee asset, rate, or destination account through the overlay.
    let gas_asset_opt = transaction
        .fee_payment_intent()
        .charge_limits()
        .iter()
        .find(|limit| limit.kind == FeeChargeKind::PipelineGas)
        .map(|limit| limit.asset_definition_id.canonical_address());
    let pipeline_gas = &state_transaction.pipeline.gas;
    let pipeline_gas_bound = fee_bound_for_admission(transaction)
        .map_err(nexus_fee_admission_error_to_validation_fail)?
        .2;
    if !skip_nexus_fee
        && pipeline_gas_component_enabled(&state_transaction.nexus, &state_transaction.pipeline)
        && pipeline_gas_bound > 0
    {
        let Some(ref gas_asset_id_str) = gas_asset_opt else {
            return Err(ValidationFail::NotPermitted(
                "missing pipeline gas charge limit in fee payment intent".to_owned(),
            ));
        };
        if !pipeline_gas
            .accepted_assets
            .iter()
            .any(|a| a == gas_asset_id_str)
        {
            return Err(ValidationFail::NotPermitted(format!(
                "gas asset `{gas_asset_id_str}` is not accepted by node policy"
            )));
        }
    }
    state_transaction.last_tx_gas_used =
        state_transaction.last_tx_gas_used.saturating_add(gas_used);
    Executor::enforce_transaction_gas_fits_block(
        state_transaction,
        state_transaction.last_tx_gas_used,
    )?;
    if should_charge_pipeline_gas_asset(
        skip_nexus_fee,
        &state_transaction.nexus.fees,
        &gas_asset_opt,
    ) && let Some(gas_asset_id_str) = gas_asset_opt
    {
        Executor::charge_pipeline_gas_asset_fee(
            state_transaction,
            authority,
            transaction,
            &gas_asset_id_str,
            gas_used,
            fee_sponsor.as_ref(),
        )?;
    }
    if !skip_nexus_fee {
        Executor::charge_nexus_fees(
            state_transaction,
            authority,
            transaction,
            fee_sponsor,
            tx_bytes_len,
            instruction_count,
            gas_used,
        )?;
    }
    Ok(())
}
#[cfg(test)]
fn live_batch_overlay_byte_size(instructions: &[InstructionBox]) -> u64 {
    instructions.iter().fold(0_u64, |total, instruction| {
        total.saturating_add(u64::try_from(instruction.encode().len()).unwrap_or(u64::MAX))
    })
}
fn live_batch_contract_execution_limit(
    signed_gas_limit: Option<u64>,
    direct_gas_used: u64,
    block_remaining_at_start: u64,
    accountable_gas_used: u64,
) -> u64 {
    signed_gas_limit
        .unwrap_or(u64::MAX)
        .saturating_sub(direct_gas_used)
        .min(block_remaining_at_start.saturating_sub(accountable_gas_used))
}
fn is_reserved_multisig_role_id(role_id: &RoleId) -> bool {
    const MULTISIG_SIGNATORY_NAMESPACE: &str = "MULTISIG_SIGNATORY";
    let name = role_id.name().as_ref();
    name == MULTISIG_SIGNATORY_NAMESPACE
        || name
            .strip_prefix(MULTISIG_SIGNATORY_NAMESPACE)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
impl Executor {
    fn resolve_pipeline_gas_asset_definition(
        state_transaction: &StateTransaction<'_, '_>,
        gas_asset_id_str: &str,
    ) -> Result<(AssetDefinitionId, AssetDefinition), ValidationFail> {
        let parsed = AssetDefinitionId::parse_address_literal(gas_asset_id_str).map_err(|_| {
            ValidationFail::NotPermitted(
                "invalid gas_asset_id; expected an unprefixed Base58 asset definition id"
                    .to_owned(),
            )
        })?;
        if let Ok(definition) = state_transaction.world.asset_definition(&parsed) {
            return Ok((definition.id().clone(), definition));
        }
        state_transaction
            .world
            .asset_definitions()
            .iter()
            .find(|(id, _)| id.canonical_address() == gas_asset_id_str)
            .map(|(id, definition)| (id.clone(), definition.clone()))
            .ok_or_else(|| {
                ValidationFail::NotPermitted(format!(
                    "gas asset `{gas_asset_id_str}` is not registered"
                ))
            })
    }
    fn enforce_transaction_gas_fits_block(
        state_transaction: &StateTransaction<'_, '_>,
        gas_used: u64,
    ) -> Result<(), ValidationFail> {
        let limit = state_transaction.gas_limit_per_block;
        let used_in_block = state_transaction.gas_used_in_block_so_far;
        if !crate::gas::gas_components_fit_block_limit(limit, [used_in_block, gas_used]) {
            let total = u128::from(used_in_block) + u128::from(gas_used);
            return Err(ValidationFail::NotPermitted(format!(
                "block gas limit exceeded: {total} > {limit}"
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    fn consume_fee_sponsor_relay_lease(
        state_transaction: &mut StateTransaction<'_, '_>,
        program_id: &FeeSponsorProgramId,
        program_revision: u64,
        asset_definition_id: &AssetDefinitionId,
        amount: &Quantity,
        directly_settled: bool,
    ) -> Result<iroha_crypto::Hash, ValidationFail> {
        let (record, _) = select_fee_sponsor_relay_lease(
            &state_transaction.world,
            program_id,
            program_revision,
            asset_definition_id,
            state_transaction.current_dataspace_id,
            state_transaction.block_height(),
            amount,
        )
        .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let executed_key = fee_sponsor_vault_allocation_usage_state_key(&record.lease_id)
            .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let settled_key = fee_sponsor_vault_allocation_settled_usage_state_key(&record.lease_id)
            .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let executed =
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let settled =
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let spent = core::cmp::max(executed, settled.clone());
        let updated_executed = spent.checked_add(amount).map_err(|_| {
            ValidationFail::InternalError(
                "verified fee sponsor vault allocation usage overflow".to_owned(),
            )
        })?;
        if updated_executed > record.verified_allocation {
            return Err(ValidationFail::NotPermitted(format!(
                "verified fee sponsor spend lease `{}` is insufficient",
                record.lease_id
            )));
        }
        let encoded = norito::to_bytes(&updated_executed).map_err(|err| {
            ValidationFail::InternalError(format!(
                "failed to encode verified fee sponsor vault allocation usage: {err}"
            ))
        })?;
        state_transaction
            .world
            .smart_contract_state
            .insert(executed_key, encoded);
        if directly_settled {
            let updated_settled = settled.checked_add(amount).map_err(|_| {
                ValidationFail::InternalError(
                    "settled verified fee sponsor vault allocation usage overflow".to_owned(),
                )
            })?;
            let settled_encoded = norito::to_bytes(&updated_settled).map_err(|err| {
                ValidationFail::InternalError(format!(
                    "failed to encode settled verified fee sponsor vault allocation usage: {err}"
                ))
            })?;
            state_transaction
                .world
                .smart_contract_state
                .insert(settled_key, settled_encoded);
        }
        Ok(record.lease_id)
    }
    fn increment_fee_sponsor_counter(
        state_transaction: &mut StateTransaction<'_, '_>,
        key: FeeSponsorBudgetCounterKey,
        amount: &Quantity,
    ) -> Result<(), ValidationFail> {
        let spent = state_transaction
            .world
            .fee_sponsor_budget_counters
            .get(&key)
            .map_or_else(Quantity::zero, |counter| counter.spent.clone())
            .checked_add(amount)
            .map_err(|_| {
                ValidationFail::InternalError(
                    "fee sponsor budget counter arithmetic overflow".to_owned(),
                )
            })?;
        state_transaction
            .world
            .fee_sponsor_budget_counters
            .insert(key.clone(), FeeSponsorBudgetCounter { key, spent });
        Ok(())
    }
    fn debit_fee_sponsor_program(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction: &SignedTransaction,
        program_id: &FeeSponsorProgramId,
        kind: FeeChargeKind,
        asset_definition_id: &AssetDefinitionId,
        amount: &Quantity,
    ) -> Result<(), ValidationFail> {
        let Some((selected_program, program_revision)) =
            transaction.fee_payment_intent().sponsor_program()
        else {
            return Err(ValidationFail::InternalError(
                "sponsor-program debit requested for an authority-paid transaction".to_owned(),
            ));
        };
        if selected_program != program_id {
            return Err(ValidationFail::InternalError(
                "sponsor-program debit does not match the signed fee intent".to_owned(),
            ));
        }
        let entrypoint_hash = transaction.try_hash_as_entrypoint().map_err(|error| {
            state_transaction.attempt_error_to_validation_fail(
                crate::smartcontracts::isi::multisig::multisig_instruction_decode_attempt(
                    error,
                    |error| {
                        ValidationFail::InternalError(format!("fee settlement entrypoint: {error}"))
                    },
                ),
            )
        })?;
        let authenticated_entrypoint = (state_transaction.tx_call_hash
            == Some(Hash::from(entrypoint_hash)))
        .then_some(*entrypoint_hash.as_ref());
        let observation_time_ms = state_transaction
            ._curr_block
            .creation_time()
            .as_millis()
            .try_into()
            .map_err(|_| {
                ValidationFail::InternalError(
                    "fee settlement block timestamp exceeds u64".to_owned(),
                )
            })?;
        let resolved = resolve_fee_sponsor_program(
            &state_transaction.world,
            &state_transaction.nexus,
            program_id,
            program_revision,
            authority,
            transaction.payload(),
            state_transaction.current_dataspace_id,
            state_transaction.block_height(),
            fee_sponsor_multisig::RuleContext::settlement(
                observation_time_ms,
                authenticated_entrypoint,
                state_transaction.block_height(),
            ),
        )
        .map_err(|error| {
            state_transaction.attempt_error_to_validation_fail(
                error.map_rejection(nexus_fee_admission_error_to_validation_fail),
            )
        })?;
        let charge = FeeChargeBound {
            kind,
            asset_definition_id: asset_definition_id.clone(),
            max_bound: amount.clone(),
        };
        validate_signed_charge_limits(
            transaction.fee_payment_intent(),
            core::slice::from_ref(&charge),
        )
        .map_err(nexus_fee_admission_error_to_validation_fail)?;
        evaluate_fee_sponsor_capacity(
            &state_transaction.world,
            &resolved,
            authority,
            state_transaction.block_height(),
            core::slice::from_ref(&charge),
        )
        .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let budget = resolved
            .revision
            .asset_budgets
            .iter()
            .find(|budget| &budget.asset_definition_id == asset_definition_id)
            .ok_or_else(|| {
                ValidationFail::InternalError(
                    "validated fee sponsor budget disappeared before debit".to_owned(),
                )
            })?;
        let vault_key = FeeSponsorVaultKey {
            program_id: program_id.clone(),
            asset_definition_id: asset_definition_id.clone(),
        };
        let mut vault = state_transaction
            .world
            .fee_sponsor_vaults
            .get(&vault_key)
            .cloned()
            .ok_or_else(|| {
                ValidationFail::InternalError(
                    "validated fee sponsor vault disappeared before debit".to_owned(),
                )
            })?;
        vault.balance = vault.balance.checked_sub(amount).map_err(|_| {
            ValidationFail::InternalError(
                "validated fee sponsor vault became insufficient before debit".to_owned(),
            )
        })?;
        state_transaction
            .world
            .fee_sponsor_vaults
            .insert(vault_key, vault);
        let epoch =
            state_transaction.block_height().saturating_sub(1) / budget.epoch_length_blocks.get();
        for window in [
            FeeSponsorBudgetWindow::Block(FeeSponsorBlockBudgetWindow {
                height: state_transaction.block_height(),
            }),
            FeeSponsorBudgetWindow::ProgramEpoch(FeeSponsorProgramEpochBudgetWindow { epoch }),
            FeeSponsorBudgetWindow::BeneficiaryEpoch(FeeSponsorBeneficiaryEpochBudgetWindow {
                epoch,
                beneficiary: authority.clone(),
            }),
        ] {
            Self::increment_fee_sponsor_counter(
                state_transaction,
                FeeSponsorBudgetCounterKey {
                    program_id: program_id.clone(),
                    asset_definition_id: asset_definition_id.clone(),
                    window,
                },
                amount,
            )?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn charge_pipeline_gas_asset_fee(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction: &SignedTransaction,
        gas_asset_id_str: &str,
        gas_used: u64,
        fee_sponsor: Option<&FeeSponsorProgramId>,
    ) -> Result<(), ValidationFail> {
        require_direct_fee_settlement(&state_transaction.nexus)
            .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let gas_rate = state_transaction
            .pipeline
            .gas
            .units_per_gas
            .iter()
            .find(|rate| rate.asset == gas_asset_id_str)
            .ok_or_else(|| {
                ValidationFail::NotPermitted(format!(
                    "missing units_per_gas mapping for `{gas_asset_id_str}`"
                ))
            })?;
        let units_per_gas = gas_rate.units_per_gas;
        if gas_used == 0 || units_per_gas == 0 {
            return Ok(());
        }
        let tech_account: AccountId = parse_account_id_literal(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            &state_transaction.pipeline.gas.tech_account_id,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| {
            let error = error.into_attempt_error(|error| ValidationFail::InternalError(error.to_string()));
            state_transaction.attempt_error_to_validation_fail(error)
        })?
        .ok_or_else(|| {
            ValidationFail::InternalError(
                "invalid pipeline.gas.tech_account_id; expected canonical I105 account id or on-chain alias"
                    .to_owned(),
            )
        })?;
        let (asset_definition_id, definition) =
            Self::resolve_pipeline_gas_asset_definition(state_transaction, gas_asset_id_str)?;
        // The product of two `u64` values is always exactly representable in
        // `u128`; keep fee consensus arithmetic exact instead of silently
        // selecting a saturation policy that can never be reached here.
        let fee_u128 = u128::from(gas_used) * u128::from(units_per_gas);
        if fee_u128 == 0 {
            return Ok(());
        }
        let qty = Quantity::from(fee_u128);
        let actual_charge = FeeChargeBound {
            kind: FeeChargeKind::PipelineGas,
            asset_definition_id: asset_definition_id.clone(),
            max_bound: qty.clone(),
        };
        validate_signed_charge_limits(
            transaction.fee_payment_intent(),
            core::slice::from_ref(&actual_charge),
        )
        .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let payer = if let Some(program_id) = fee_sponsor {
            Self::debit_fee_sponsor_program(
                state_transaction,
                authority,
                transaction,
                program_id,
                FeeChargeKind::PipelineGas,
                &asset_definition_id,
                &qty,
            )?;
            state_transaction
                .nexus
                .fees
                .sponsor_vault_custody_account_id
                .clone()
        } else {
            authority.clone()
        };
        let payer_scope = match definition.balance_scope_policy() {
            AssetBalancePolicy::Global => AssetBalanceScope::Global,
            AssetBalancePolicy::DataspaceRestricted => AssetBalanceScope::Dataspace(
                state_transaction
                    .current_dataspace_id
                    .unwrap_or(DataSpaceId::UNIVERSAL),
            ),
        };
        let payer_asset = AssetId::with_scope(asset_definition_id.clone(), payer, payer_scope);
        let transfer_result = if let Some(program_id) = fee_sponsor {
            let charge = VerifiedFeeSponsorCharge::transfer(
                authority.clone(),
                program_id.clone(),
                FeeChargeKind::PipelineGas,
                payer_asset,
                tech_account,
                qty.clone(),
                state_transaction.tx_call_hash.and_then(|entry| {
                    transaction
                        .fee_payment_intent()
                        .sponsor_program()
                        .map(|(_, revision)| (entry, Hash::from(transaction.hash()), revision))
                }),
            );
            crate::smartcontracts::isi::asset::isi::execute_verified_fee_sponsor_charge(
                state_transaction,
                charge,
            )
        } else {
            let transfer = iroha_data_model::isi::Transfer::<
                Asset,
                Quantity,
                iroha_data_model::account::Account,
            >::asset_quantity(payer_asset, qty.clone(), tech_account);
            let instr: DMInstructionBox = transfer.into();
            execute_gas_fee_transfer_instruction(&definition, instr, authority, state_transaction)
        };
        transfer_result.map_err(|err| {
            iroha_logger::debug!(
                ?err,
                authority = %authority,
                "gas fee transfer failed to apply"
            );
            ValidationFail::from(err)
        })?;
        #[cfg(feature = "telemetry")]
        {
            let delta = u64::try_from(fee_u128.min(u128::from(u64::MAX))).unwrap_or(u64::MAX);
            state_transaction.stage_block_fee_amount(Quantity::from(delta));
        }
        // This actual scoped transfer is the fee settlement. No synthetic XOR
        // conversion quote or lane-relay receipt can stand in for a balance effect.
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    fn charge_nexus_fees(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction: &SignedTransaction,
        sponsor: Option<FeeSponsorProgramId>,
        tx_bytes_len: usize,
        instruction_count: usize,
        gas_used: u64,
    ) -> Result<(), ValidationFail> {
        require_direct_fee_settlement(&state_transaction.nexus)
            .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let cfg = private_fees::effective(&state_transaction.world, &state_transaction.nexus.fees)
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    state_transaction.defer_execution(reason)
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                    nexus_fee_admission_error_to_validation_fail(error)
                }
            })?;
        let private_scope = private_fees::private_scope(
            &state_transaction.world,
            state_transaction.current_dataspace_id,
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                state_transaction.defer_execution(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                nexus_fee_admission_error_to_validation_fail(error)
            }
        })?;
        if private_scope.is_some() && sponsor.is_some() {
            return Err(ValidationFail::NotPermitted(
                "private-root fee sponsors require a scoped vault owner".into(),
            ));
        }
        let fee = compute_nexus_fee_amount(&cfg, tx_bytes_len, instruction_count, gas_used)?;
        if fee.is_zero() {
            return Ok(());
        }
        let payer_kind = if sponsor.is_some() {
            NexusFeePayer::Sponsor
        } else {
            NexusFeePayer::Payer
        };
        let asset_def = private_fees::currency(
            &state_transaction.world,
            &cfg,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                state_transaction.defer_execution(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                nexus_fee_admission_error_to_validation_fail(error)
            }
        })?;
        let actual_charge = FeeChargeBound {
            kind: FeeChargeKind::Nexus,
            asset_definition_id: asset_def.clone(),
            max_bound: fee.clone(),
        };
        validate_signed_charge_limits(
            transaction.fee_payment_intent(),
            core::slice::from_ref(&actual_charge),
        )
        .map_err(nexus_fee_admission_error_to_validation_fail)?;
        let receipt = state_transaction.prepare_actual_nexus_fee_receipt(
            authority,
            transaction,
            sponsor.as_ref(),
            &asset_def,
            &fee,
            &cfg,
            tx_bytes_len,
            instruction_count,
            gas_used,
        )?;
        let (payer, payer_id, program_revision) = if let Some(program_id) = sponsor.as_ref() {
            let program_revision = transaction
                .fee_payment_intent()
                .sponsor_program()
                .map(|(_, revision)| revision)
                .ok_or_else(|| {
                    ValidationFail::InternalError(
                        "sponsored Nexus fee is missing its signed program revision".to_owned(),
                    )
                })?;
            Self::debit_fee_sponsor_program(
                state_transaction,
                authority,
                transaction,
                program_id,
                FeeChargeKind::Nexus,
                &asset_def,
                &fee,
            )?;
            (
                state_transaction
                    .nexus
                    .fees
                    .sponsor_vault_custody_account_id
                    .clone(),
                program_id.to_string(),
                Some(program_revision),
            )
        } else {
            (authority.clone(), authority.to_string(), None)
        };
        let payer_kind_label = match payer_kind {
            NexusFeePayer::Payer => "payer",
            NexusFeePayer::Sponsor => "sponsor",
        };
        let payer_asset = AssetId::with_scope(
            asset_def,
            payer.clone(),
            private_scope.map_or(AssetBalanceScope::Global, AssetBalanceScope::Dataspace),
        );
        let asset_label = payer_asset.definition().to_string();
        let previous_tx_dataspace_id = state_transaction.current_dataspace_id;
        let previous_world_dataspace_id = state_transaction.world.current_dataspace_id;
        state_transaction.current_dataspace_id =
            Some(private_scope.unwrap_or(DataSpaceId::UNIVERSAL));
        state_transaction.world.current_dataspace_id =
            Some(private_scope.unwrap_or(DataSpaceId::UNIVERSAL));
        let fee_burn_result = if matches!(payer_kind, NexusFeePayer::Sponsor) {
            let program_id = sponsor.clone().ok_or_else(|| {
                ValidationFail::InternalError(
                    "sponsored Nexus burn lost its verified program id".to_owned(),
                )
            })?;
            let charge = VerifiedFeeSponsorCharge::burn(
                authority.clone(),
                program_id,
                FeeChargeKind::Nexus,
                payer_asset,
                fee.clone(),
                state_transaction.tx_call_hash.and_then(|entry| {
                    program_revision
                        .map(|revision| (entry, Hash::from(transaction.hash()), revision))
                }),
            );
            crate::smartcontracts::isi::asset::isi::execute_verified_fee_sponsor_charge(
                state_transaction,
                charge,
            )
        } else {
            let burn = Burn::asset_quantity(fee.clone(), payer_asset);
            let instr: DMInstructionBox = burn.into();
            instr.execute(authority, state_transaction)
        };
        state_transaction.current_dataspace_id = previous_tx_dataspace_id;
        state_transaction.world.current_dataspace_id = previous_world_dataspace_id;
        fee_burn_result.map_err(|err| {
            let reason = format!("nexus fee burn failed to apply: {err}");
            status::record_nexus_fee_event(NexusFeeEvent::TransferFailed {
                payer_kind,
                payer_id: payer_id.clone(),
                amount: fee.clone(),
                asset_id: asset_label.clone(),
                reason: reason.clone(),
            });
            warn!(
                target: "economics",
                ?err,
                payer = %payer_id,
                payer_kind = payer_kind_label,
                fee_amount = %fee,
                asset = %asset_label,
                "nexus fee burn failed"
            );
            ValidationFail::from(err)
        })?;
        state_transaction.pending_nexus_fee_receipt = Some(receipt);
        // Stage the charged event so rejected transactions don't report successful debits.
        state_transaction.stage_nexus_fee_event(NexusFeeEvent::Charged {
            payer_kind,
            payer_id,
            amount: fee,
            asset_id: asset_label,
        });
        Ok(())
    }
    /// Refresh pipeline.gas snapshot from on-chain custom parameters (genesis/governance updatable).
    fn refresh_gas_from_parameters(
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), ValidationFail> {
        #[derive(crate::json_macros::JsonDeserialize)]
        struct GasRateSerde {
            asset: String,
            units_per_gas: u64,
            twap_local_per_xor: Option<String>,
            liquidity_profile: Option<String>,
            volatility_class: Option<String>,
        }
        let params = state_transaction.world.parameters.get();
        // Decode the complete governed snapshot before replacing any live value. A malformed
        // parameter must fail closed without leaving a partially refreshed fee policy behind.
        let mut tech_account_id = state_transaction.pipeline.gas.tech_account_id.clone();
        if let Ok(name) = core::str::FromStr::from_str("ivm_gas_tech_account_id")
            && let Some(custom) = params.custom().get(&CustomParameterId(name))
        {
            tech_account_id =
                custom
                    .payload()
                    .try_into_any_norito::<String>()
                    .map_err(|error| {
                        ValidationFail::InternalError(format!(
                            "invalid governed ivm_gas_tech_account_id payload: {error}"
                        ))
                    })?;
        }
        let mut accepted_assets = state_transaction.pipeline.gas.accepted_assets.clone();
        if let Ok(name) = core::str::FromStr::from_str("ivm_gas_accepted_assets")
            && let Some(custom) = params.custom().get(&CustomParameterId(name))
        {
            accepted_assets = custom
                .payload()
                .try_into_any_norito::<Vec<String>>()
                .map_err(|error| {
                    ValidationFail::InternalError(format!(
                        "invalid governed ivm_gas_accepted_assets payload: {error}"
                    ))
                })?;
        }
        let mut units_per_gas = state_transaction.pipeline.gas.units_per_gas.clone();
        if let Ok(name) = core::str::FromStr::from_str("ivm_gas_units_per_gas")
            && let Some(custom) = params.custom().get(&CustomParameterId(name))
        {
            let governed_rates = custom
                .payload()
                .try_into_any_norito::<Vec<GasRateSerde>>()
                .map_err(|error| {
                    ValidationFail::InternalError(format!(
                        "invalid governed ivm_gas_units_per_gas payload: {error}"
                    ))
                })?;
            units_per_gas = governed_rates
                .into_iter()
                .map(|r| -> Result<iroha_config::parameters::actual::GasRate, ValidationFail> {
                    let asset = r.asset;
                    let twap = match r.twap_local_per_xor.as_deref() {
                        Some(value) => {
                            let parsed = Numeric::from_str(value).map_err(|error| {
                                ValidationFail::InternalError(format!(
                                    "invalid governed ivm_gas_units_per_gas twap `{value}` for asset `{asset}`: {error}"
                                ))
                            })?;
                            if parsed <= Numeric::zero() {
                                return Err(ValidationFail::InternalError(format!(
                                    "invalid governed ivm_gas_units_per_gas twap `{value}` for asset `{asset}`: value must be positive"
                                )));
                            }
                            parsed
                        }
                        None => Numeric::one(),
                    };
                    let liquidity = match r.liquidity_profile.as_deref() {
                        Some(value) => GasLiquidity::from_str(value).map_err(|()| {
                            ValidationFail::InternalError(format!(
                                "invalid governed ivm_gas_units_per_gas liquidity `{value}` for asset `{asset}`"
                            ))
                        })?,
                        None => GasLiquidity::default(),
                    };
                    let volatility = match r.volatility_class.as_deref() {
                        Some(value) => GasVolatility::from_str(value).map_err(|()| {
                            ValidationFail::InternalError(format!(
                                "invalid governed ivm_gas_units_per_gas volatility `{value}` for asset `{asset}`"
                            ))
                        })?,
                        None => GasVolatility::default(),
                    };
                    Ok(iroha_config::parameters::actual::GasRate {
                        asset,
                        units_per_gas: r.units_per_gas,
                        twap_local_per_xor: twap,
                        liquidity,
                        volatility,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        if !is_initial_genesis_context(state_transaction) {
            state_transaction.nexus.fees =
                private_fees::effective(&state_transaction.world, &state_transaction.nexus.fees)
                    .map_err(|error| match error {
                        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                            state_transaction.defer_execution(reason)
                        }
                        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                            nexus_fee_admission_error_to_validation_fail(error)
                        }
                    })?;
        }
        state_transaction.pipeline.gas.tech_account_id = tech_account_id;
        state_transaction.pipeline.gas.accepted_assets = accepted_assets;
        state_transaction.pipeline.gas.units_per_gas = units_per_gas;
        Ok(())
    }
    /// Identify a role-11 instruction in the exact outer signed Network entry.
    ///
    /// Sealed reveals use an inner execution call hash, while their output proof names the
    /// distinct outer entry. Contract-emitted instructions have no direct signed ordinal.
    pub(crate) fn direct_stream_token_instruction_index(
        state_transaction: &StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
        instruction: &InstructionBox,
        index: usize,
        direct_body: bool,
    ) -> Result<Option<u32>, ValidationFail> {
        use iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority;
        if !direct_body {
            return Ok(None);
        }
        let submitted = match transaction.instructions() {
            Executable::Instructions(instructions) => instructions.get(index),
            Executable::Batch(items) => items.get(index).and_then(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => Some(instruction),
                ExecutableBatchItem::ContractCall(_) => None,
            }),
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => None,
        };
        let expected = submitted.and_then(|item| {
            item.as_any()
                .downcast_ref::<MutateSorafsStreamTokenAuthority>()
        });
        let actual = instruction
            .as_any()
            .downcast_ref::<MutateSorafsStreamTokenAuthority>();
        if expected.is_none() || expected != actual {
            return Ok(None);
        }
        let signed_entry_hash = transaction.hash_as_entrypoint();
        if state_transaction.current_network_entrypoint_hash != Some(signed_entry_hash)
            || state_transaction.tx_call_hash != Some(iroha_crypto::Hash::from(signed_entry_hash))
            || state_transaction.current_tx_hash != Some(transaction.hash())
            || state_transaction
                .current_entrypoint_index
                .and_then(|value| u32::try_from(value).ok())
                .is_none()
        {
            return Ok(None);
        }
        u32::try_from(index).map(Some).map_err(|_| {
            ValidationFail::NotPermitted("signed stream-token instruction index exceeds u32".into())
        })
    }
    /// Identify a gateway instruction in the exact outer signed Network entry.
    ///
    /// Sealed reveals use an inner execution call hash, while their output proof names the
    /// distinct outer entry. Contract-emitted instructions have no direct signed ordinal.
    pub(crate) fn direct_stream_token_gateway_instruction_index(
        state_transaction: &StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
        instruction: &InstructionBox,
        index: usize,
        direct_body: bool,
    ) -> Result<Option<u32>, ValidationFail> {
        use iroha_data_model::isi::sorafs::MutateSorafsStreamTokenGateway;
        if !direct_body || transaction.network_id() != Some(state_transaction.network_id()) {
            return Ok(None);
        }
        let submitted = match transaction.instructions() {
            Executable::Instructions(instructions) => instructions.get(index),
            Executable::Batch(items) => items.get(index).and_then(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => Some(instruction),
                ExecutableBatchItem::ContractCall(_) => None,
            }),
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => None,
        };
        let expected = submitted.and_then(|item| {
            item.as_any()
                .downcast_ref::<MutateSorafsStreamTokenGateway>()
        });
        let actual = instruction
            .as_any()
            .downcast_ref::<MutateSorafsStreamTokenGateway>();
        if expected.is_none() || expected != actual {
            return Ok(None);
        }
        // Governance cancellation is one complete signed operation; it cannot borrow a
        // manager's authority from an enclosing batch or accompanying instruction.
        if actual.is_some_and(|instruction| matches!(instruction.request.action,
            iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayActionV1::CancelReputationDelivery { .. }))
            && !matches!(transaction.instructions(), Executable::Instructions(items)
                if items.len() == 1 && index == 0)
        {
            return Ok(None);
        }
        let signed_entry_hash = transaction.hash_as_entrypoint();
        if state_transaction.current_network_entrypoint_hash != Some(signed_entry_hash)
            || state_transaction.tx_call_hash != Some(iroha_crypto::Hash::from(signed_entry_hash))
            || state_transaction.current_tx_hash != Some(transaction.hash())
            || state_transaction
                .current_entrypoint_index
                .and_then(|value| u32::try_from(value).ok())
                .is_none()
        {
            return Ok(None);
        }
        u32::try_from(index).map(Some).map_err(|_| {
            ValidationFail::NotPermitted(
                "signed stream-token gateway instruction index exceeds u32".into(),
            )
        })
    }
    /// Capture the exact original signed SetPolicy; genesis requires its opaque source owner.
    pub(crate) fn direct_reputation_policy_origin(
        state: &StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
        instruction: &InstructionBox,
        index: usize,
        direct_body: bool,
    ) -> Option<iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1> {
        use iroha_data_model::{
            isi::sorafs::SetSorafsReputationJournalAuthorityPolicy,
            sorafs::{
                reputation::ReputationJournalPolicyOriginV1 as Origin,
                stream_token_gateway::native::StreamTokenGatewayExecutionV1 as Execution,
            },
        };
        if !direct_body
            || !instruction
                .as_any()
                .is::<SetSorafsReputationJournalAuthorityPolicy>()
        {
            return None;
        }
        let Executable::Instructions(items) = transaction.instructions() else {
            return None;
        };
        if items.get(index) != Some(instruction)
            || state.current_network_entrypoint_hash != Some(transaction.hash_as_entrypoint())
            || state.tx_call_hash
                != Some(iroha_crypto::Hash::from(transaction.hash_as_entrypoint()))
            || state.current_tx_hash != Some(transaction.hash())
        {
            return None;
        }
        let execution = Execution {
            height: state._curr_block.height().get(),
            transaction_hash: *transaction.hash_as_entrypoint().as_ref(),
            entry_index: u32::try_from(state.current_entrypoint_index?).ok()?,
            instruction_index: u32::try_from(index).ok()?,
            recorded_at_unix_ms: state.block_unix_timestamp_ms(),
            authority: transaction.authority().clone(),
        };
        let origin = if is_initial_genesis_context(state)
            && transaction.network_id().is_none()
            && state
                .genesis_execution_scope
                .as_ref()
                .and_then(|scope| scope.for_transaction(state))
                .is_some()
        {
            Origin::Genesis(execution)
        } else if !is_initial_genesis_context(state)
            && transaction.network_id() == Some(state.network_id())
            && items.len() == 1
            && index == 0
        {
            Origin::Network(execution)
        } else {
            return None;
        };
        origin.validate().ok()?;
        Some(origin)
    }
    /// Bind only the sole exact external stream-token reputation append, including all signed fields.
    pub(crate) fn direct_stream_token_reputation_payload(
        state_transaction: &StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
        instruction: &InstructionBox,
        direct_body: bool,
    ) -> Option<iroha_data_model::transaction::TransactionPayload> {
        use iroha_data_model::isi::sorafs::AppendSorafsStreamTokenReputationJournalEntry;
        let Executable::Instructions(items) = transaction.instructions() else {
            return None;
        };
        if !direct_body
            || items.len() != 1
            || items.first() != Some(instruction)
            || !instruction
                .as_any()
                .is::<AppendSorafsStreamTokenReputationJournalEntry>()
            || transaction.network_id() != Some(state_transaction.network_id())
            || transaction.multisig_signatures().is_some()
            || transaction
                .authority()
                .try_signatory()
                .is_none_or(|key| key.algorithm() != iroha_crypto::Algorithm::Ed25519)
            || state_transaction.current_network_entrypoint_hash
                != Some(transaction.hash_as_entrypoint())
            || state_transaction.tx_call_hash
                != Some(iroha_crypto::Hash::from(transaction.hash_as_entrypoint()))
            || state_transaction.current_tx_hash != Some(transaction.hash())
            || state_transaction.current_entrypoint_index.is_none()
        {
            return None;
        }
        Some(transaction.payload().clone())
    }
    /// Recognize only the exact direct instruction in the original signed genesis transaction.
    pub(crate) fn direct_sorafs_admission_initialization(
        state_transaction: &StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
        instruction: &InstructionBox,
        index: usize,
        direct_body: bool,
    ) -> bool {
        use iroha_data_model::isi::sorafs::InitializeSorafsProviderAdmissionV1;
        if !direct_body
            || !is_initial_genesis_context(state_transaction)
            || !instruction
                .as_any()
                .is::<InitializeSorafsProviderAdmissionV1>()
        {
            return false;
        }
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return false;
        };
        if instructions.get(index) != Some(instruction) {
            return false;
        }
        // Authenticate the complete signed intent only for its exact initializer. This helper
        // is called for every genesis instruction, including unrelated instructions.
        #[cfg(test)]
        sorafs_admission_hash_probe::note_outer_hash();
        let outer = transaction.hash_as_entrypoint();
        state_transaction.current_network_entrypoint_hash == Some(outer)
            && state_transaction.tx_call_hash == Some(iroha_crypto::Hash::from(outer))
            && state_transaction.current_tx_hash == Some(transaction.hash())
            && state_transaction.current_entrypoint_index.is_some()
            && transaction.network_id().is_none()
    }
    /// Bind one role-15 operation to its sole direct signed External Network entry.
    ///
    /// Contract, IVM, sealed-reveal and mixed-batch effects cannot acquire this token.
    /// Local allocation refusals retain their first nonwire retry owner and cannot become a
    /// completed source rejection, fee, or output.
    pub(crate) fn direct_final_promotion_operation_origin(
        state_transaction: &mut StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
        instruction: &InstructionBox,
        direct_body: bool,
    ) -> Result<
        Option<
            iroha_data_model::sorafs::final_promotion_authority::FinalPromotionOperationOriginV1,
        >,
        ValidationFail,
    > {
        use crate::execution_attempt::{ExecutionAttemptError, norito_decode_attempt_error};
        use iroha_data_model::{
            isi::sorafs::MutateSorafsFinalPromotionAuthority,
            sorafs::final_promotion_authority::{
                FinalPromotionAuthorityActionV1, FinalPromotionOperationOriginV1,
            },
        };
        state_transaction.current_direct_final_promotion_operation_origin = None;
        if !direct_body {
            return Ok(None);
        }
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Ok(None);
        };
        if instructions.len() != 1 || instructions.first() != Some(instruction) {
            return Ok(None);
        }
        let Some(native) = instruction
            .as_any()
            .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
        else {
            return Ok(None);
        };
        if !matches!(
            &native.action,
            FinalPromotionAuthorityActionV1::Reserve(_)
                | FinalPromotionAuthorityActionV1::Complete(_)
        ) {
            return Ok(None);
        }
        let outer = transaction.try_hash_as_entrypoint().map_err(|error| {
            state_transaction.attempt_error_to_validation_fail(norito_decode_attempt_error(
                error,
                |_| {
                    ValidationFail::NotPermitted("invalid final-promotion original encoding".into())
                },
            ))
        })?;
        let signed_hash =
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::from(outer));
        if state_transaction.current_network_entrypoint_hash != Some(outer)
            || state_transaction.tx_call_hash != Some(iroha_crypto::Hash::from(outer))
            || state_transaction.current_tx_hash != Some(signed_hash)
            || transaction.network_id() != Some(&state_transaction.network_id)
        {
            return Ok(None);
        }
        match crate::query::signer_check::native_signed_transaction_frame_attempt_v1(transaction) {
            Ok(_) => {}
            Err(ExecutionAttemptError::Rejected(_)) => return Ok(None),
            Err(ExecutionAttemptError::Deferred(reason)) => {
                return Err(state_transaction.defer_execution(reason));
            }
        }
        let Some(entry_index) = state_transaction
            .current_entrypoint_index
            .and_then(|index| u32::try_from(index).ok())
        else {
            return Ok(None);
        };
        Ok(Some(FinalPromotionOperationOriginV1 {
            entry_hash: *outer.as_ref(),
            entry_index,
        }))
    }
    #[allow(clippy::too_many_lines)]
    fn execute_metered_instructions(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction: &SignedTransaction,
        instructions: Vec<InstructionBox>,
        ivm_proved_replay: Option<crate::pipeline::overlay::IvmProvedReplay>,
        contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
        entrypoint_authorization: Option<&ContractEntrypointAuthorizationSnapshot>,
        tx_bytes_len: usize,
        gas_limit_md: Option<u64>,
        require_gas_limit: bool,
        gas_asset_opt: Option<String>,
        fee_sponsor: Option<FeeSponsorProgramId>,
        skip_nexus_fee: bool,
    ) -> Result<(), ValidationFail> {
        state_transaction.current_direct_kagemusha_load_instruction_index = None;
        state_transaction.current_direct_amx_instruction_index = None;
        if require_gas_limit && gas_limit_md.is_none() {
            return Err(ValidationFail::NotPermitted(
                "missing gas limit in fee payment intent".to_owned(),
            ));
        }
        if let Some(replay) = ivm_proved_replay.as_ref() {
            if state_transaction.last_tx_gas_used != replay.gas_used {
                return Err(ValidationFail::InternalError(
                    "proved replay lost its retained execution work".into(),
                ));
            }
            crate::validation_fee::enforce_ivm_proved_completed_axt_admission(
                replay.completed_axt.len(),
                state_transaction,
            )?;
        }
        // 1) Deterministically meter the instruction batch. Proved IVM transactions retain the
        // verified replay gas because the plain overlay does not account for VM execution cost.
        let used = ivm_proved_replay.as_ref().map_or_else(
            || isi_gas::meter_instructions(&instructions),
            |replay| replay.gas_used,
        );
        // 2) Enforce optional payer-provided gas limit (caps fee exposure).
        if let Some(limit) = gas_limit_md
            && used > limit
        {
            return Err(ValidationFail::NotPermitted(format!(
                "out of gas: used {used} > limit {limit}"
            )));
        }
        Self::enforce_transaction_gas_fits_block(state_transaction, used)?;
        // Preserve deterministic work accounting even if an instruction later
        // rejects. The block corridor decides whether the rejected live
        // transaction is fee-eligible and carries these counters forward.
        if ivm_proved_replay.is_some() {
            // The verifier's actual run already transferred its work, before
            // any AXT, gas or effect admission below could reject the replay.
            state_transaction.admit_replayed_execution_effects(instructions.iter())?;
        } else {
            // A refused authored set never starts, so it creates no work/fee basis.
            state_transaction.admit_authored_execution_effects(&instructions)?;
            state_transaction.last_tx_gas_used = used;
            state_transaction.record_execution_fee_instructions(instructions.len(), used)?;
        }
        if let Some(replay) = ivm_proved_replay.as_ref() {
            if entrypoint_authorization.is_none()
                && replay.queued.iter().any(|effect| {
                    effect.contract_runtime_context.is_some()
                        || effect.entrypoint_authorization.is_some()
                })
            {
                return Err(ValidationFail::NotPermitted(
                    "proved contract effects are missing their root authorization snapshot".into(),
                ));
            }
            crate::deferred_authority::reject_opaque_instruction_authority(
                replay
                    .queued
                    .iter()
                    .filter_map(|queued| queued.instruction()),
                state_transaction,
            )
            .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        }
        let confidential_delta = crate::gas::sum_confidential_gas_costs(instructions.iter());
        if confidential_delta > 0 {
            state_transaction.record_confidential_gas_delta(confidential_delta);
        }
        match (contract_runtime_context, entrypoint_authorization) {
            (Some(context), Some(authorization)) => {
                if !authorization.is_root() {
                    return Err(ValidationFail::NotPermitted(
                        "proved overlay root authorization contains a parent invocation".to_owned(),
                    ));
                }
                let live_subject = code::fetch_bound_contract_subject(
                    state_transaction,
                    &context.contract_address,
                )
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "contract instance `{}` has no valid subject binding",
                        context.contract_address
                    ))
                })?;
                if context.contract_subject != live_subject
                    || context.contract_address != authorization.contract_address
                    || context.contract_alias != authorization.contract_alias
                    || context.entrypoint != authorization.entrypoint
                {
                    return Err(ValidationFail::NotPermitted(
                        "proved overlay runtime context does not match its immutable authorization snapshot"
                            .to_owned(),
                    ));
                }
                authorization
                    .validate_for_authority(&state_transaction.world, authority)
                    .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
            }
            (Some(_), None) => {
                return Err(ValidationFail::NotPermitted(
                    "proved contract overlay is missing its immutable authorization snapshot"
                        .to_owned(),
                ));
            }
            (None, Some(_)) => {
                return Err(ValidationFail::InternalError(
                    "proved entrypoint authorization has no contract runtime context".to_owned(),
                ));
            }
            (None, None) => {}
        }
        if let Some(replay) = ivm_proved_replay.as_ref()
            && !replay.durable_state_overlay.is_empty()
        {
            let root = entrypoint_authorization.ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "proved durable-state replay is missing its root authorization snapshot"
                        .to_owned(),
                )
            })?;
            crate::pipeline::overlay::validate_ivm_proved_durable_authorizations(
                &state_transaction.world,
                &replay.durable_state_overlay,
                &replay.durable_state_authorizations,
                root,
            )
            .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        }
        let instruction_count = instructions.len();
        // 3) Execute ISIs in order.
        let execution_result = (|| -> Result<(), ValidationFail> {
            if let Some(replay) = ivm_proved_replay {
                for queued in replay.queued {
                    match (
                        queued.contract_runtime_context.as_ref(),
                        queued.entrypoint_authorization.as_ref(),
                    ) {
                        (Some(context), Some(authorization)) => {
                            if let Some(root) = entrypoint_authorization
                                && !authorization.descends_from(root)
                            {
                                return Err(ValidationFail::NotPermitted(
                                    "proved overlay effect authorization does not descend from its root invocation"
                                        .to_owned(),
                                ));
                            }
                            let live_subject = code::fetch_bound_contract_subject(
                                state_transaction,
                                &context.contract_address,
                            )
                            .ok_or_else(|| {
                                ValidationFail::NotPermitted(format!(
                                    "contract instance `{}` has no valid subject binding",
                                    context.contract_address
                                ))
                            })?;
                            if context.contract_subject != live_subject
                                || context.contract_address != authorization.contract_address
                                || context.contract_alias != authorization.contract_alias
                                || context.entrypoint != authorization.entrypoint
                                || queued.authority != context.contract_subject
                            {
                                return Err(ValidationFail::NotPermitted(
                                    "proved overlay effect runtime context does not match its immutable authorization snapshot"
                                        .to_owned(),
                                ));
                            }
                            authorization
                                .validate(&state_transaction.world)
                                .map_err(|error| {
                                    state_transaction.attempt_error_to_validation_fail(error)
                                })?;
                        }
                        (Some(_), None) => {
                            return Err(ValidationFail::NotPermitted(
                                "proved contract effect is missing its immutable authorization snapshot"
                                    .to_owned(),
                            ));
                        }
                        (None, Some(_)) => {
                            return Err(ValidationFail::InternalError(
                                "proved effect authorization has no contract runtime context"
                                    .to_owned(),
                            ));
                        }
                        (None, None) => {}
                    }
                    match queued.payload {
                        crate::smartcontracts::ivm::host::QueuedEffectPayload::Instruction(
                            instruction,
                        ) => {
                            self.execute_instruction_with_contract_runtime_context(
                                state_transaction,
                                &queued.authority,
                                instruction,
                                queued.contract_runtime_context.as_ref(),
                            )?;
                        }
                        crate::smartcontracts::ivm::host::QueuedEffectPayload::Emission(
                            emission,
                        ) => {
                            crate::smartcontracts::ivm::host::HostExecutionArtifacts::validate_emission_provenance(
                                &state_transaction.world, &emission.value, queued.contract_runtime_context.as_ref(), queued.entrypoint_authorization.as_ref(),
                            )?;
                            state_transaction.record_contract_emission(emission)?;
                        }
                    }
                    if let Some(root) = entrypoint_authorization {
                        root.validate_for_authority(&state_transaction.world, authority)
                            .map_err(|error| {
                                state_transaction.attempt_error_to_validation_fail(error)
                            })?;
                    }
                    if let Some(authorization) = queued.entrypoint_authorization.as_ref() {
                        authorization
                            .validate(&state_transaction.world)
                            .map_err(|error| {
                                state_transaction.attempt_error_to_validation_fail(error)
                            })?;
                    }
                }
                if !replay.durable_state_overlay.is_empty() {
                    let root = entrypoint_authorization.ok_or_else(|| {
                        ValidationFail::NotPermitted(
                            "proved durable-state replay is missing its root authorization snapshot"
                                .to_owned(),
                        )
                    })?;
                    root.validate_for_authority(&state_transaction.world, authority)
                        .map_err(|error| {
                            state_transaction.attempt_error_to_validation_fail(error)
                        })?;
                    // A queued instruction can revoke the selected permission or replace a live
                    // contract binding. Validate the complete set before recording any replay
                    // artifact or writing the first durable key, so rejection remains atomic.
                    crate::pipeline::overlay::validate_ivm_proved_durable_authorizations(
                        &state_transaction.world,
                        &replay.durable_state_overlay,
                        &replay.durable_state_authorizations,
                        root,
                    )
                    .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
                }
                crate::smartcontracts::ivm::host::HostExecutionArtifacts::record_completed_axt_states(
                    state_transaction,
                    replay.completed_axt,
                )?;
                for (path, value) in replay.durable_state_overlay {
                    let authorization = replay
                        .durable_state_authorizations
                        .get(&path)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| {
                            ValidationFail::InternalError(format!(
                                "proved durable state path `{path}` lost its authorization snapshot before apply"
                            ))
                        })?;
                    authorization
                        .validate(&state_transaction.world)
                        .map_err(|error| {
                            state_transaction.attempt_error_to_validation_fail(error)
                        })?;
                    if !authorization.owns_durable_state_path(&path) {
                        return Err(ValidationFail::NotPermitted(format!(
                            "proved durable state path `{path}` does not belong to its contract authorization snapshot"
                        )));
                    }
                    if let Some(stored) = value {
                        state_transaction
                            .world
                            .smart_contract_state
                            .insert(path, stored);
                    } else {
                        state_transaction.world.smart_contract_state.remove(path);
                    }
                }
            } else {
                for (index, isi) in instructions.into_iter().enumerate() {
                    if let Some(authorization) = entrypoint_authorization {
                        authorization
                            .validate_for_authority(&state_transaction.world, authority)
                            .map_err(|error| {
                                state_transaction.attempt_error_to_validation_fail(error)
                            })?;
                    }
                    let direct_index = Self::direct_stream_token_instruction_index(
                        state_transaction,
                        transaction,
                        &isi,
                        index,
                        contract_runtime_context.is_none() && entrypoint_authorization.is_none(),
                    )?;
                    state_transaction.current_direct_stream_token_instruction_index = direct_index;
                    state_transaction.current_direct_reputation_policy_origin =
                        Self::direct_reputation_policy_origin(
                            state_transaction,
                            transaction,
                            &isi,
                            index,
                            contract_runtime_context.is_none()
                                && entrypoint_authorization.is_none(),
                        );
                    state_transaction.current_direct_stream_token_reputation_payload =
                        Self::direct_stream_token_reputation_payload(
                            state_transaction,
                            transaction,
                            &isi,
                            contract_runtime_context.is_none()
                                && entrypoint_authorization.is_none(),
                        );
                    state_transaction.current_direct_stream_token_gateway_instruction_index =
                        Self::direct_stream_token_gateway_instruction_index(
                            state_transaction,
                            transaction,
                            &isi,
                            index,
                            contract_runtime_context.is_none()
                                && entrypoint_authorization.is_none(),
                        )?;
                    state_transaction.current_direct_sorafs_admission_initialization =
                        Self::direct_sorafs_admission_initialization(
                            state_transaction,
                            transaction,
                            &isi,
                            index,
                            contract_runtime_context.is_none()
                                && entrypoint_authorization.is_none(),
                        );
                    state_transaction.current_direct_final_promotion_operation_origin =
                        Self::direct_final_promotion_operation_origin(
                            state_transaction,
                            transaction,
                            &isi,
                            contract_runtime_context.is_none()
                                && entrypoint_authorization.is_none(),
                        )?;
                    state_transaction.current_direct_musubi_pin_outbox_origin =
                        crate::smartcontracts::isi::musubi::capture_pin_outbox_operation_origin(
                            state_transaction,
                            transaction,
                            &isi,
                            contract_runtime_context.is_none()
                                && entrypoint_authorization.is_none(),
                        )?;
                    state_transaction.current_direct_kagemusha_load_instruction_index =
                        (contract_runtime_context.is_none() && entrypoint_authorization.is_none())
                            .then_some(index);
                    state_transaction.current_direct_amx_instruction_index =
                        (contract_runtime_context.is_none()
                            && entrypoint_authorization.is_none()
                            && isi
                                .as_any()
                                .downcast_ref::<iroha_data_model::isi::sumeragi_amx::PrepareAmxV1>()
                                .is_some())
                        .then_some(index);
                    let result = self.execute_instruction_with_contract_runtime_context(
                        state_transaction,
                        authority,
                        isi,
                        contract_runtime_context,
                    );
                    state_transaction.current_direct_kagemusha_load_instruction_index = None;
                    state_transaction.current_direct_amx_instruction_index = None;
                    state_transaction.current_direct_stream_token_instruction_index = None;
                    state_transaction.current_direct_stream_token_gateway_instruction_index = None;
                    state_transaction.current_direct_stream_token_reputation_payload = None;
                    state_transaction.current_direct_reputation_policy_origin = None;
                    state_transaction.current_direct_sorafs_admission_initialization = false;
                    state_transaction.current_direct_final_promotion_operation_origin = None;
                    state_transaction.current_direct_musubi_pin_outbox_origin = None;
                    result?;
                    if let Some(authorization) = entrypoint_authorization {
                        authorization
                            .validate_for_authority(&state_transaction.world, authority)
                            .map_err(|error| {
                                state_transaction.attempt_error_to_validation_fail(error)
                            })?;
                    }
                }
            }
            if let Some(authorization) = entrypoint_authorization {
                authorization
                    .validate_for_authority(&state_transaction.world, authority)
                    .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
            }
            Ok(())
        })();
        execution_result?;
        // 4) Charge gas fees when configured and the transaction specified a gas asset.
        if should_charge_pipeline_gas_asset(
            skip_nexus_fee,
            &state_transaction.nexus.fees,
            &gas_asset_opt,
        ) && let Some(gas_asset_id_str) = gas_asset_opt
        {
            Self::charge_pipeline_gas_asset_fee(
                state_transaction,
                authority,
                transaction,
                &gas_asset_id_str,
                used,
                fee_sponsor.as_ref(),
            )?;
        }
        if !skip_nexus_fee {
            Self::charge_nexus_fees(
                state_transaction,
                authority,
                &transaction,
                fee_sponsor,
                tx_bytes_len,
                instruction_count,
                used,
            )?;
        }
        Ok(())
    }
    /// Resolve the cache-bound inputs for one deployed-contract invocation.
    ///
    /// The returned value owns its prepared-program handle and can therefore be executed after
    /// the caller releases any mutex guard used to access `ivm_cache`.
    pub(crate) fn resolve_contract_invocation(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        call: &ContractInvocation,
        ivm_cache: &mut IvmCache,
    ) -> Result<ResolvedContractInvocation, ValidationFail> {
        root_scope::ensure_contract_scope(state_transaction, &call.contract_address)?;
        code::ensure_contract_execution_allowed(
            &state_transaction.world,
            &call.contract_address,
            state_transaction.block_height(),
        )
        .map_err(ValidationFail::NotPermitted)?;
        let identity =
            code::fetch_bound_contract_identity(state_transaction, &call.contract_address)
                .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "contract instance `{}` not found in WSV",
                        call.contract_address
                    ))
                })?;
        ensure_contract_invocation_code_hash(call, identity.code_hash)?;
        let contract_subject =
            code::fetch_bound_contract_subject(state_transaction, &identity.contract_address)
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "contract instance `{}` has no valid subject binding",
                        identity.contract_address
                    ))
                })?;
        let code_bytes = state_transaction
            .world
            .contract_code()
            .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                identity.contract_address.dataspace_id().map_err(|_| {
                    ValidationFail::NotPermitted("invalid contract dataspace".into())
                })?,
                identity.code_hash,
            ))
            .ok_or_else(|| {
                ValidationFail::NotPermitted(format!(
                    "contract bytecode `{}` not found in WSV",
                    identity.code_hash
                ))
            })?;
        let summary = if let Some(summary) = ivm_cache
            .cached_program_summary(identity.code_hash)
            .map_err(|error| ValidationFail::InternalError(error.to_string()))?
        {
            summary
        } else {
            ivm_cache
                .summarize_program_with_hash(identity.code_hash, code_bytes.as_ref())
                .map_err(|error| ValidationFail::InternalError(error.to_string()))?
        };
        if summary.prepared_contract().artifact() != code_bytes.as_slice() {
            return Err(ValidationFail::NotPermitted(format!(
                "cached contract bytecode `{}` does not match live WSV",
                identity.code_hash
            )));
        }
        Ok(ResolvedContractInvocation {
            identity,
            contract_subject,
            summary,
        })
    }
    /// Execute one deployed-contract invocation against the current transaction view.
    ///
    /// Fee settlement and block-gas accounting deliberately remain with the enclosing
    /// executable. This lets a mixed batch invoke this helper multiple times while sharing one
    /// signed gas limit and settling exactly once.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_contract_invocation(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        call: &ContractInvocation,
        ivm_cache: &mut IvmCache,
        effective_limit: u64,
        logical_time_ms: u64,
        trigger_context: Option<(&TriggerId, u64)>,
    ) -> Result<ContractInvocationOutcome, ValidationFail> {
        // A contract frame cannot inherit a native instruction's signed ordinal.
        state_transaction.current_direct_kagemusha_load_instruction_index = None;
        state_transaction.current_direct_amx_instruction_index = None;
        state_transaction.current_direct_stream_token_gateway_instruction_index = None;
        state_transaction.current_direct_stream_token_reputation_payload = None;
        state_transaction.current_direct_reputation_policy_origin = None;
        state_transaction.current_direct_musubi_pin_outbox_origin = None;
        let resolved = self.resolve_contract_invocation(state_transaction, call, ivm_cache)?;
        self.execute_resolved_contract_invocation(
            state_transaction,
            authority,
            call,
            resolved,
            effective_limit,
            logical_time_ms,
            trigger_context,
        )
    }
    /// Execute a previously resolved deployed-contract invocation without accessing `IvmCache`.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_resolved_contract_invocation(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        call: &ContractInvocation,
        resolved: ResolvedContractInvocation,
        effective_limit: u64,
        logical_time_ms: u64,
        trigger_context: Option<(&TriggerId, u64)>,
    ) -> Result<ContractInvocationOutcome, ValidationFail> {
        // A contract frame cannot inherit a native instruction's signed ordinal.
        state_transaction.current_direct_kagemusha_load_instruction_index = None;
        state_transaction.current_direct_amx_instruction_index = None;
        state_transaction.current_direct_stream_token_gateway_instruction_index = None;
        state_transaction.current_direct_stream_token_reputation_payload = None;
        state_transaction.current_direct_reputation_policy_origin = None;
        state_transaction.current_direct_musubi_pin_outbox_origin = None;
        root_scope::ensure_contract_scope(state_transaction, &call.contract_address)?;
        use crate::smartcontracts::ivm::host::CoreHostImpl as CoreCoreHost;
        let ResolvedContractInvocation {
            identity,
            contract_subject,
            summary,
        } = resolved;
        let effective_cycles =
            validate_prepared_ivm_execution_policy(state_transaction, &summary.metadata)?;
        let effective_limit = effective_limit.min(
            crate::smartcontracts::ivm::gas_limit_for_cycles(effective_cycles),
        );
        let manifest = state_transaction
            .world
            .contract_manifests()
            .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                identity.contract_address.dataspace_id().map_err(|_| {
                    ValidationFail::NotPermitted("invalid contract dataspace".into())
                })?,
                identity.code_hash,
            ))
            .ok_or_else(|| {
                ValidationFail::NotPermitted(format!(
                    "contract instance `{}` has no manifest",
                    identity.contract_address
                ))
            })?;
        crate::smartcontracts::ivm::validate_manifest_hashes(
            manifest,
            summary.code_hash,
            summary.abi_hash,
        )
        .map_err(ValidationFail::IvmAdmission)?;
        let lifecycle_transition = validate_prepared_contract_lifecycle_call(
            &state_transaction.world,
            &call.contract_address,
            identity.code_hash,
            summary.prepared_contract(),
            &call.entrypoint,
        )?;
        let entrypoint_authorization = authorize_prepared_contract_selector(
            &state_transaction.world,
            authority,
            summary.prepared_contract(),
            &call.entrypoint,
            &identity,
        )
        .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        let contract_call_context = parse_prepared_contract_invocation_execution_context(
            call,
            summary.prepared_contract(),
            identity.contract_alias.clone(),
            contract_subject,
            effective_limit,
        )?;
        let heap_limit = state_transaction
            .world
            .parameters
            .get()
            .smart_contract()
            .memory()
            .get();
        let mut runtime = summary
            .checkout_runtime(effective_limit, heap_limit)
            .map_err(|error| {
                state_transaction.vm_error_to_validation_fail(error, |error| {
                    ValidationFail::InternalError(error.to_string())
                })
            })?;
        runtime.set_max_cycles(effective_cycles.get());
        runtime.set_gas_limit(effective_limit);
        if let Some(entrypoint_pc) = contract_call_context.entrypoint_pc {
            let code_len = runtime.memory.code_len();
            runtime.set_register(1, code_len);
            runtime.set_program_counter(entrypoint_pc).map_err(|err| {
                let selector = contract_call_context
                    .entrypoint
                    .as_deref()
                    .unwrap_or("main");
                ValidationFail::NotPermitted(format!(
                    "contract entrypoint `{selector}` resolved to invalid pc: {err}"
                ))
            })?;
        }
        let precharge_result = contract_call_context
            .argument_record
            .as_ref()
            .map_or(Ok(()), |record| record.precharge_vm(&mut runtime));
        if let Err(error) = &precharge_result {
            runtime.record_boundary_fault(
                error,
                iroha_data_model::executor::fault::IvmFaultPositionV1::Initialization,
            );
        }
        let contract_runtime_context = contract_call_context.runtime_context();
        let accounts = state_transaction.accounts_snapshot();
        let mut host = CoreCoreHost::with_accounts_and_argument_record(
            authority.clone(),
            Arc::clone(&accounts),
            contract_call_context.argument_record,
        );
        host.set_output_limits_from_parameters(
            state_transaction.world.parameters.get().smart_contract(),
        );
        host.set_prepared_contract_cache(summary.prepared_contract_cache());
        host.hydrate_axt_state(state_transaction).map_err(|error| {
            ValidationFail::InternalError(format!("invalid AXT policy snapshot: {error}"))
        })?;
        // User contract calls execute before the enclosing block has a finalized creation
        // timestamp, so their caller supplies the deterministic logical time. Trigger callers
        // additionally bind the trigger id and deterministic NFT sequence base.
        host.set_block_time_ms(logical_time_ms);
        if let Some((trigger_id, nft_seq_base)) = trigger_context {
            host.set_trigger_id(trigger_id.clone());
            host.set_nft_seq_base(nft_seq_base);
        }
        host.set_crypto_config(Arc::clone(&state_transaction.crypto));
        host.set_zk_config(&state_transaction.zk);
        host.set_public_inputs_from_parameters(state_transaction.world.parameters.get());
        host.set_vrf_epoch_seeds_from_state(state_transaction)
            .map_err(|error| {
                state_transaction.attempt_error_to_validation_fail(
                    error.map_rejection(ValidationFail::InternalError),
                )
            })?;
        host.set_query_state(state_transaction);
        host.set_contract_runtime_context(contract_runtime_context.clone());
        host.set_contract_entrypoint_authorization(Some(entrypoint_authorization));
        if let Some(pending) = lifecycle_transition {
            host.set_contract_lifecycle_transition(&call.contract_address, pending);
        }
        host.set_chain_id(&state_transaction.chain_id);
        #[cfg(feature = "telemetry")]
        host.set_telemetry(state_transaction.telemetry.clone());
        host.set_zk_snapshots_from_world(&state_transaction.world, &state_transaction.zk)
            .map_err(|err| {
                ValidationFail::InternalError(format!("invalid ZK snapshot state: {err}"))
            })?;
        let cycle_budget = state_transaction.execution_cycle_budget()?;
        let run_result = precharge_result
            .and_then(|()| match cycle_budget {
                Some(budget) => runtime.run_with_host_and_cycle_budget(&mut host, budget),
                None => runtime.run_with_host(&mut host),
            })
            .and_then(|()| host.finish_contract_result(&runtime));
        let gas_used = effective_limit.saturating_sub(runtime.remaining_gas());
        if let Err(err) = run_result {
            let attempt =
                crate::smartcontracts::ivm::map_vm_error_with_context_to_validation(&runtime, err);
            drop(host);
            let error = match attempt {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    return Err(state_transaction.defer_execution(reason));
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
            };
            // Retain attempted VM work even when the guest traps. Live-batch rejection discards
            // business state but uses this counter for block budgeting and rejected fees.
            state_transaction.last_tx_gas_used =
                state_transaction.last_tx_gas_used.saturating_add(gas_used);
            if trigger_context.is_none() {
                state_transaction.record_execution_fee_vm_work(gas_used)?;
            }
            return Err(error);
        }
        let returned_error = matches!(run_result, Ok(true));
        let lifecycle_transition = lifecycle_transition.filter(|_| !returned_error);
        let next_nft_sequence = trigger_context.map(|(_, initial_sequence)| {
            if returned_error {
                initial_sequence
            } else {
                host.next_nft_sequence()
            }
        });
        let runtime_origin = contract_runtime_context.as_ref().map(|context| {
            crate::validation_fee::OpaqueDeferredRuntimeOrigin::new(
                context,
                summary.prepared_contract().artifact(),
            )
        });
        let artifacts = host.into_execution_artifacts(contract_runtime_context.clone());
        // Retain completed VM work even when artifact validation or application later fails.
        state_transaction.last_tx_gas_used =
            state_transaction.last_tx_gas_used.saturating_add(gas_used);
        if trigger_context.is_none() {
            state_transaction.record_execution_fee_vm_work(gas_used)?;
        }
        let artifacts = artifacts?;
        let validation_outcome = crate::validation_fee::enforce_opaque_deferred_instruction_groups(
            &artifacts.queued_instructions_by_authority(),
            &artifacts.queued_instructions_with_authority(),
            state_transaction,
            runtime_origin,
        )
        .map_err(|rejection| match rejection {
            crate::tx::TransactionRejectionReason::Validation(fail) => fail,
            other => ValidationFail::NotPermitted(format!(
                "validation-fee policy resolution failed during deployed contract execution: {other:?}"
            )),
        })?;
        if validation_outcome == crate::validation_fee::OpaqueDeferredValidationOutcome::NoOp {
            return Ok(ContractInvocationOutcome {
                gas_used,
                executed_instructions: Vec::new(),
                next_nft_sequence,
            });
        }
        if let Some(pending) = lifecycle_transition {
            code::validate_contract_lifecycle_completion(
                &state_transaction.world,
                &call.contract_address,
                pending,
            )?;
        }
        let executed = artifacts.apply_to_transaction_with_lifecycle(
            state_transaction,
            authority,
            lifecycle_transition.map(|pending| (&call.contract_address, pending)),
        )?;
        Ok(ContractInvocationOutcome {
            gas_used,
            executed_instructions: executed,
            next_nft_sequence,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn settle_live_transaction_fees(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction: &SignedTransaction,
        direct_gas_used: u64,
        instruction_count: usize,
        tx_bytes_len: usize,
        gas_asset_opt: Option<String>,
        fee_sponsor: Option<FeeSponsorProgramId>,
        skip_nexus_fee: bool,
    ) -> Result<(), ValidationFail> {
        if state_transaction.last_tx_gas_used < direct_gas_used {
            return Err(ValidationFail::InternalError(
                "live fee settlement lost staged direct gas".to_owned(),
            ));
        }
        let accountable_gas_used = state_transaction.last_tx_gas_used;
        Self::enforce_transaction_gas_fits_block(state_transaction, accountable_gas_used)?;
        if should_charge_pipeline_gas_asset(
            skip_nexus_fee,
            &state_transaction.nexus.fees,
            &gas_asset_opt,
        ) && let Some(gas_asset_id_str) = gas_asset_opt
        {
            Self::charge_pipeline_gas_asset_fee(
                state_transaction,
                authority,
                transaction,
                &gas_asset_id_str,
                direct_gas_used,
                fee_sponsor.as_ref(),
            )?;
        }
        if !skip_nexus_fee {
            Self::charge_nexus_fees(
                state_transaction,
                authority,
                transaction,
                fee_sponsor,
                tx_bytes_len,
                instruction_count,
                direct_gas_used,
            )?;
        }
        Ok(())
    }
    /// Check bounded proof attachments against native registry metadata and block dedup state.
    ///
    /// This performs the same preliminary check used by transaction execution. It neither
    /// verifies a complete operation relation nor grants execution or publication authority.
    ///
    /// # Errors
    /// Returns the original structural, registry, activity, namespace, budget or duplicate error.
    #[cfg(feature = "zk-preverify")]
    pub fn preverify_attachments(
        state_transaction: &mut StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
    ) -> Result<(), ValidationFail> {
        let md = transaction.metadata();
        use iroha_data_model::proof::ProofAttachment;
        let namespace_hint = md
            .get("contract_alias")
            .and_then(|value| value.try_into_any_norito::<String>().ok())
            .and_then(|raw| {
                raw.trim()
                    .parse::<iroha_data_model::smart_contract::ContractAlias>()
                    .ok()
            })
            .map(|alias| alias.dataspace_segment().to_owned())
            .or_else(|| {
                md.get("contract_address")
                    .and_then(|value| value.try_into_any_norito::<String>().ok())
                    .and_then(|raw| {
                        raw.trim()
                            .parse::<iroha_data_model::smart_contract::ContractAddress>()
                            .ok()
                    })
                    .and_then(|contract_address| contract_address.dataspace_id().ok())
                    .and_then(|dataspace_id| {
                        state_transaction
                            .nexus
                            .dataspace_catalog
                            .by_id(dataspace_id)
                            .map(|entry| entry.alias.clone())
                    })
            });
        // Process the signed transaction's bounded ZK attachments.
        if let Some(attachments) = transaction.attachments() {
            // Canonicalize verification order for determinism
            let mut list_sorted = attachments.as_slice().to_vec();
            list_sorted.sort_by(|a, b| {
                let ah = crate::zk::hash_proof(&a.proof);
                let bh = crate::zk::hash_proof(&b.proof);
                (a.backend.as_str(), ah).cmp(&(b.backend.as_str(), bh))
            });
            for attachment in list_sorted.into_iter() {
                if let Some((field, message)) = attachment.structural_error() {
                    return Err(ValidationFail::NotPermitted(format!(
                        "malformed proof attachment: {field} {message}"
                    )));
                }
                let ProofAttachment {
                    backend,
                    proof,
                    vk_ref,
                    vk_commitment,
                    ..
                } = attachment;
                // Sanity: proof.backend should match attachment backend
                if proof.backend != backend {
                    return Err(ValidationFail::NotPermitted(
                        "proof backend mismatch".to_owned(),
                    ));
                }
                if vk_ref.backend != backend {
                    return Err(ValidationFail::NotPermitted(
                        "verifying key backend mismatch".to_owned(),
                    ));
                }
                if crate::zk::is_production_claim_backend_label(backend.as_str()) {
                    return Err(ValidationFail::NotPermitted(
                        "readiness-claim proof backends are not supported".to_owned(),
                    ));
                }
                if crate::zk::is_trusted_setup_backend_label(backend.as_str()) {
                    return Err(ValidationFail::NotPermitted(
                        "trusted-setup proof backends are not supported".to_owned(),
                    ));
                }
                if crate::zk::is_developer_only_backend_label(backend.as_str()) {
                    return Err(ValidationFail::NotPermitted(
                        "developer-only proof backends are not supported".to_owned(),
                    ));
                }
                if !crate::zk::is_verifier_backend_registry_label_v1(backend.as_str()) {
                    return Err(ValidationFail::NotPermitted(
                        "unsupported proof backends are not supported".to_owned(),
                    ));
                }
                // If a VK reference is provided without a commitment, check existence in
                // WSV. If a commitment is provided, skip the lookup to keep pre-verify
                // stateless and cheap.
                if vk_commitment.is_none()
                    && state_transaction
                        .world
                        .verifying_keys
                        .get(&vk_ref)
                        .is_none()
                {
                    return Err(ValidationFail::NotPermitted(format!(
                        "referenced verifying key missing: {}::{}",
                        vk_ref.backend, vk_ref.name
                    )));
                }
                // Perform lightweight pre-verify (dedup + tag sanity).
                let block_height = state_transaction.block_height();
                let (expected_commitment, vk_active) =
                    if let Some(rec) = state_transaction.world.verifying_keys.get(&vk_ref) {
                        if let Some(ns_hint) = namespace_hint.as_deref() {
                            if !rec.namespace.is_empty() && rec.namespace != ns_hint {
                                return Err(ValidationFail::NotPermitted(
                                    "verifying key namespace/manifest mismatch".to_owned(),
                                ));
                            }
                        }
                        (Some(rec.commitment), rec.is_active_at(block_height))
                    } else {
                        (vk_commitment, false)
                    };
                let res = state_transaction.preverify_proof(
                    &proof,
                    None,
                    state_transaction.zk.preverify_budget_bytes,
                    vk_commitment,
                    expected_commitment,
                    vk_active,
                );
                match res {
                    PreverifyResult::Accepted => {}
                    PreverifyResult::Duplicate => {
                        return Err(ValidationFail::NotPermitted(
                            "duplicate proof in block".to_owned(),
                        ));
                    }
                    PreverifyResult::UnsupportedBackend => {
                        return Err(ValidationFail::NotPermitted(
                            "unsupported proof backend".to_owned(),
                        ));
                    }
                    PreverifyResult::ProofTooBig => {
                        return Err(ValidationFail::NotPermitted("proof too big".to_owned()));
                    }
                    PreverifyResult::MalformedProof => {
                        return Err(ValidationFail::NotPermitted("malformed proof".to_owned()));
                    }
                    PreverifyResult::PreverifyBudgetExceeded => {
                        return Err(ValidationFail::NotPermitted(
                            "pre-verify budget exceeded".to_owned(),
                        ));
                    }
                    PreverifyResult::VerifyingKeyMissing => {
                        return Err(ValidationFail::NotPermitted(
                            "verifying key missing".to_owned(),
                        ));
                    }
                    PreverifyResult::VerifyingKeyMismatch => {
                        return Err(ValidationFail::NotPermitted(
                            "verifying key mismatch".to_owned(),
                        ));
                    }
                    PreverifyResult::NamespaceMismatch => {
                        return Err(ValidationFail::NotPermitted(
                            "verifying key namespace/manifest mismatch".to_owned(),
                        ));
                    }
                    PreverifyResult::VerifyingKeyInactive => {
                        return Err(ValidationFail::NotPermitted(
                            "verifying key inactive".to_owned(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute [`SignedTransaction`].
    /// # Errors
    /// Returns an error when IVM preparation or execution fails, or the executor denies the operation.
    pub fn execute_transaction(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction: SignedTransaction,
        ivm_cache: &mut IvmCache,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        state_transaction.bind_kagemusha_load_entrypoint_v1(None);
        if let Some(reason) = state_transaction.execution_deferral() {
            return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                reason,
            ));
        }
        let result =
            self.execute_transaction_body(state_transaction, authority, transaction, ivm_cache);
        // The self-claim marker belongs to the signed body only, never to later callbacks.
        state_transaction.sccp_exempt_self_claim = None;
        state_transaction.bind_kagemusha_load_entrypoint_v1(None);
        // A local refusal has no completed execution, fee, gas, or effect result.
        // The transaction overlay remains poisoned until its owner drops it.
        if let Some(reason) = state_transaction.execution_deferral() {
            return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                reason,
            ));
        }
        let effects = state_transaction.finish_execution_effect_budget();
        state_transaction.close_execution_fee_meter();
        effects?;
        result.map_err(Into::into)
    }

    /// Run one admitted signed body under its actual root effect and fee owners.
    #[allow(clippy::too_many_lines)]
    fn execute_transaction_body(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction: SignedTransaction,
        ivm_cache: &mut IvmCache,
    ) -> Result<(), ValidationFail> {
        root_scope::ensure_executable_scope(state_transaction, transaction.instructions())?;
        state_transaction.bind_privacy_transaction_intent_v1(None);
        state_transaction.bind_private_settlement_carrier_v1(None);
        state_transaction.bind_governance_ballot_entrypoint_v1(None);
        if transaction.authority() != authority {
            return Err(ValidationFail::InternalError(
                "signed authority mismatch".into(),
            ));
        }
        trace!("Running transaction execution");
        let privacy_intent_binding =
            crate::privacy::signed_privacy_transaction_intent_binding_v1(&transaction)?;
        state_transaction.bind_privacy_transaction_intent_v1(privacy_intent_binding);
        let private_settlement_carrier_binding =
            crate::private_settlement::carrier::signed_private_settlement_carrier_binding_v1(
                &transaction,
            )?;
        state_transaction.bind_private_settlement_carrier_v1(private_settlement_carrier_binding);
        let governance_ballot_binding =
            crate::state::standalone_governance_ballot_instruction_v1(transaction.instructions())
                .map_err(|message| ValidationFail::NotPermitted(message.to_owned()))?;
        let call_hash = transaction.hash_as_entrypoint();
        state_transaction.tx_call_hash = Some(iroha_crypto::Hash::from(call_hash));
        let tx_hash = transaction.hash();
        state_transaction.current_tx_hash = Some(tx_hash.clone());
        let tx_bytes_len = norito::canonical_frame_len(transaction.payload()).map_err(|err| {
            ValidationFail::InternalError(format!(
                "failed to encode transaction for fee metering: {err}"
            ))
        })?;
        let fee_sponsor = transaction
            .fee_payment_intent()
            .sponsor_program()
            .map(|(program_id, _)| program_id.clone());
        let (fee_exemption, sccp_class) = if is_initial_genesis_context(state_transaction) {
            (ExecutionFeeExemption::Exempt, None)
        } else {
            transaction_fee_exemption(state_transaction, &transaction)
                .map_err(|reason| state_transaction.defer_execution(reason))?
        };
        let skip_nexus_fee = fee_exemption.skips_fee_on_success();
        // Only an exempt self-claim makes the self-claim fee due at release (§4.12.4).
        state_transaction.sccp_exempt_self_claim = (sccp_class
            == Some(crate::smartcontracts::isi::sccp::admission::SccpExemptClassV1::SelfClaim))
        .then(|| authority.clone());
        // Quote against the exact governed gas snapshot execution will charge.
        Self::refresh_gas_from_parameters(state_transaction)?;
        let fee_quote = if !skip_nexus_fee {
            Some(
                quote_nexus_fee_admission(
                    &state_transaction.world,
                    &state_transaction.nexus,
                    &state_transaction.pipeline,
                    &transaction,
                    state_transaction.block_unix_timestamp_ms(),
                    state_transaction.block_height(),
                    state_transaction.current_dataspace_id,
                )
                .map_err(|error| {
                    state_transaction.attempt_error_to_validation_fail(
                        error.map_rejection(nexus_fee_admission_error_to_validation_fail),
                    )
                })?,
            )
        } else {
            None
        };
        fastpq_rejection_tail::preflight(
            state_transaction,
            authority,
            &transaction,
            fee_quote.as_ref(),
            governance_ballot_binding.as_ref(),
        )?;
        state_transaction.bind_governance_ballot_entrypoint_v1(governance_ballot_binding);
        state_transaction.bind_kagemusha_load_entrypoint_v1(Some(&transaction));
        state_transaction.begin_execution_fee_meter(&transaction, tx_bytes_len, fee_exemption)?;
        state_transaction.begin_execution_effect_budget(&transaction)?;
        // Disallow direct signing with multisig accounts; only explicit multisig
        // proposal/approval envelopes with bundled multisig signatures are allowed.
        {
            if let Ok(account) = state_transaction.world.account(authority) {
                if account.id().controller().multisig_policy().is_some() {
                    let only_custom_instruction_envelopes = matches!(
                        transaction.instructions(),
                        Executable::Instructions(items)
                            if !items.is_empty()
                                && items.iter().all(|instruction| {
                                    instruction
                                        .as_any()
                                        .downcast_ref::<CustomInstruction>()
                                        .is_some()
                                })
                    );
                    if only_custom_instruction_envelopes {
                        // Allowed: custom instruction envelopes are validated by their respective
                        // runtime handlers (including multisig propose/approve/register paths).
                    } else {
                        #[cfg(feature = "telemetry")]
                        crate::telemetry::record_social_rejection(
                            state_transaction.telemetry,
                            "multisig_direct_sign",
                        );
                        return Err(ValidationFail::NotPermitted(
                            "direct signing with multisig accounts is forbidden; use multisig propose/approve"
                                .to_owned(),
                        ));
                    }
                }
            }
        }
        // Gas asset and limit are explicit signature-bound fee intent fields.
        let md = transaction.metadata().clone();
        let gas_asset_opt = transaction
            .fee_payment_intent()
            .charge_limits()
            .iter()
            .find(|limit| limit.kind == FeeChargeKind::PipelineGas)
            .map(|limit| limit.asset_definition_id.canonical_address());
        let gas_limit_md = transaction_gas_limit(&transaction);
        let pipeline_gas = &state_transaction.pipeline.gas;
        let pipeline_gas_bound = fee_bound_for_admission(&transaction)
            .map_err(nexus_fee_admission_error_to_validation_fail)?
            .2;
        if !skip_nexus_fee
            && pipeline_gas_component_enabled(&state_transaction.nexus, &state_transaction.pipeline)
            && pipeline_gas_bound > 0
        {
            let Some(ref gas_asset_id_str) = gas_asset_opt else {
                return Err(ValidationFail::NotPermitted(
                    "missing pipeline gas charge limit in fee payment intent".to_owned(),
                ));
            };
            if !pipeline_gas
                .accepted_assets
                .iter()
                .any(|a| a == gas_asset_id_str)
            {
                return Err(ValidationFail::NotPermitted(format!(
                    "gas asset `{gas_asset_id_str}` is not accepted by node policy"
                )));
            }
        }
        let execution_dataspace = root_scope::captured_dataspace(state_transaction)?;
        enforce_transaction_contract_permission_before_proof_verification(
            state_transaction,
            authority,
            &transaction,
            ivm_cache,
            state_transaction.block_height(),
            execution_dataspace,
        )
        .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        #[cfg(feature = "zk-preverify")]
        Self::preverify_attachments(state_transaction, &transaction)?;
        let mut proved_contract_runtime_context = None;
        let mut proved_entrypoint_authorization = None;
        // Full verification for proof-carrying IVM executables must run before we move the
        // transaction payload out of `SignedTransaction`.
        let ivm_proved_replay = if let Executable::IvmProved(proved) = transaction.instructions() {
            if gas_limit_md.is_none() {
                return Err(ValidationFail::NotPermitted(
                    "missing gas limit in fee payment intent".to_owned(),
                ));
            }
            let summary = ivm_cache
                .summarize_program(proved.bytecode.as_ref())
                .map_err(|e| ValidationFail::InternalError(e.to_string()))?;
            let meta = summary.metadata.clone();
            validate_governed_ivm_proved_execution_policy(state_transaction, &meta)?;
            crate::pipeline::overlay::validate_contract_binding(
                state_transaction,
                transaction.payload(),
                &summary,
            )
            .map_err(|error| {
                overlay_build_error_to_attempt_validation_fail(state_transaction, error)
            })?;
            let selector = requested_contract_entrypoint(transaction.metadata())?.ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "self-describing proved raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                        .to_owned(),
                )
            })?;
            let identity = require_raw_contract_runtime_identity(
                &state_transaction.world,
                summary.code_hash,
                transaction.metadata(),
            )?;
            let authorization = authorize_prepared_raw_contract_selector(
                &state_transaction.world,
                authority,
                summary.prepared_contract(),
                &selector,
                &identity,
            )
            .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
            let contract_subject =
                code::fetch_bound_contract_subject(state_transaction, &identity.contract_address)
                    .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "contract instance `{}` has no valid subject binding",
                        identity.contract_address
                    ))
                })?;
            proved_contract_runtime_context = Some(ContractRuntimeExecutionContext {
                contract_subject,
                contract_address: identity.contract_address,
                contract_alias: identity.contract_alias,
                entrypoint: selector,
            });
            proved_entrypoint_authorization = Some(authorization);
            crate::pipeline::overlay::enforce_manifest_is_pre_registered(
                state_transaction,
                transaction.payload(),
                summary.code_hash,
            )
            .map_err(|error| {
                overlay_build_error_to_attempt_validation_fail(state_transaction, error)
            })?;
            let mut replay_work = crate::pipeline::overlay::IvmProvedReplayWork::default();
            let replay_result = crate::pipeline::overlay::verify_ivm_proved_execution(
                state_transaction,
                &transaction,
                proved,
                &summary,
                state_transaction.execution_cycle_budget()?,
                &mut replay_work,
            );
            let observed_gas = replay_work
                .gas_used()
                .map_err(|message| ValidationFail::InternalError(message.into()))?;
            if let Some(gas) = observed_gas {
                // Transfer actual work before any fallible binding or replay
                // admission. Even an otherwise valid replay can exceed AXT or
                // remaining block capacity; its completed VM work still exists.
                state_transaction.last_tx_gas_used =
                    state_transaction.last_tx_gas_used.saturating_add(gas);
                match &replay_result {
                    Ok(replay) => state_transaction.record_execution_fee_instructions(
                        replay
                            .queued
                            .iter()
                            .filter(|effect| effect.instruction().is_some())
                            .count(),
                        gas,
                    )?,
                    Err(_) => state_transaction.record_execution_fee_vm_work(gas)?,
                }
            }
            let replay = replay_result.map_err(|error| {
                overlay_build_error_to_attempt_validation_fail(state_transaction, error)
            })?;
            if observed_gas != Some(replay.gas_used) {
                return Err(ValidationFail::InternalError(
                    "verified replay lost its actual gas owner".into(),
                ));
            }
            crate::pipeline::overlay::require_ivm_proved_gas_within_limit(
                &transaction,
                replay.gas_used,
            )
            .map_err(overlay_build_error_to_validation_fail)?;
            Some(replay)
        } else {
            None
        };
        let tx_creation_time_ms =
            u64::try_from(transaction.creation_time().as_millis()).unwrap_or(u64::MAX);
        let transaction_for_fee = transaction.clone();
        let (tx_authority, executable) = transaction.into();
        debug_assert_eq!(&tx_authority, authority, "authority mismatch");
        match (self, executable) {
            (Self::Initial | Self::UserProvided(_), Executable::Instructions(instructions)) => self
                .execute_metered_instructions(
                    state_transaction,
                    authority,
                    &transaction_for_fee,
                    instructions.into_vec(),
                    None,
                    None,
                    None,
                    tx_bytes_len,
                    gas_limit_md,
                    false,
                    gas_asset_opt,
                    fee_sponsor,
                    skip_nexus_fee,
                ),
            (Self::Initial | Self::UserProvided(_), Executable::IvmProved(_)) => {
                let replay = ivm_proved_replay
                    .expect("proved execution must retain the deterministic replay verified above");
                let instructions = replay
                    .queued
                    .iter()
                    .filter_map(|queued| queued.instruction().cloned())
                    .collect();
                self.execute_metered_instructions(
                    state_transaction,
                    authority,
                    &transaction_for_fee,
                    instructions,
                    Some(replay),
                    proved_contract_runtime_context.as_ref(),
                    proved_entrypoint_authorization.as_ref(),
                    tx_bytes_len,
                    gas_limit_md,
                    true,
                    gas_asset_opt,
                    fee_sponsor,
                    false,
                )
            }
            (Self::Initial | Self::UserProvided(_), Executable::ContractCall(call)) => {
                let gas_limit = gas_limit_md.ok_or_else(|| {
                    ValidationFail::NotPermitted(
                        "missing gas limit in fee payment intent".to_owned(),
                    )
                })?;
                let block_remaining = if state_transaction.gas_limit_per_block == 0 {
                    u64::MAX
                } else {
                    state_transaction
                        .gas_limit_per_block
                        .saturating_sub(state_transaction.gas_used_in_block_so_far)
                };
                let effective_limit = gas_limit.min(block_remaining);
                let outcome = self.execute_contract_invocation(
                    state_transaction,
                    authority,
                    &call,
                    ivm_cache,
                    effective_limit,
                    tx_creation_time_ms,
                    None,
                )?;
                Self::settle_live_transaction_fees(
                    state_transaction,
                    authority,
                    &transaction_for_fee,
                    outcome.gas_used,
                    0,
                    tx_bytes_len,
                    gas_asset_opt,
                    fee_sponsor,
                    skip_nexus_fee,
                )
            }
            (Self::Initial | Self::UserProvided(_), Executable::Batch(items)) => {
                if items.is_empty() {
                    return Err(ValidationFail::NotPermitted(
                        "executable batch must not be empty".to_owned(),
                    ));
                }
                let items = items.into_vec();
                let contains_contract_call = items
                    .iter()
                    .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)));
                let gas_limit = if contains_contract_call {
                    Some(gas_limit_md.ok_or_else(|| {
                        ValidationFail::NotPermitted(
                            "missing gas limit in fee payment intent".to_owned(),
                        )
                    })?)
                } else {
                    gas_limit_md
                };
                let explicit_instructions: Vec<_> = items
                    .iter()
                    .filter_map(|item| match item {
                        ExecutableBatchItem::Instruction(instruction) => Some(instruction.clone()),
                        ExecutableBatchItem::ContractCall(_) => None,
                    })
                    .collect();
                let explicit_gas = isi_gas::meter_instructions(&explicit_instructions);
                if let Some(limit) = gas_limit
                    && explicit_gas > limit
                {
                    return Err(ValidationFail::NotPermitted(format!(
                        "out of gas: used {explicit_gas} > limit {limit}"
                    )));
                }
                let block_remaining = if state_transaction.gas_limit_per_block == 0 {
                    u64::MAX
                } else {
                    state_transaction
                        .gas_limit_per_block
                        .saturating_sub(state_transaction.gas_used_in_block_so_far)
                };
                if explicit_gas > block_remaining {
                    return Err(ValidationFail::NotPermitted(format!(
                        "block gas limit exceeded: {} > {}",
                        state_transaction
                            .gas_used_in_block_so_far
                            .saturating_add(explicit_gas),
                        state_transaction.gas_limit_per_block
                    )));
                }
                let mut gas_used = explicit_gas;
                state_transaction.admit_authored_execution_effects(&explicit_instructions)?;
                // Native ISIs are metered as one authored set, matching the existing
                // `Executable::Instructions` rejected-business fee behavior.
                state_transaction.last_tx_gas_used = explicit_gas;
                state_transaction
                    .record_execution_fee_instructions(explicit_instructions.len(), explicit_gas)?;
                let confidential_delta =
                    crate::gas::sum_confidential_gas_costs(explicit_instructions.iter());
                if confidential_delta > 0 {
                    state_transaction.record_confidential_gas_delta(confidential_delta);
                }
                for (index, item) in items.into_iter().enumerate() {
                    match item {
                        ExecutableBatchItem::Instruction(instruction) => {
                            // Mixed batches intentionally do not inherit the pure-ISI
                            // deployment self-bootstrap exception.
                            let direct_index = Self::direct_stream_token_instruction_index(
                                state_transaction,
                                &transaction_for_fee,
                                &instruction,
                                index,
                                true,
                            )?;
                            state_transaction.current_direct_stream_token_instruction_index =
                                direct_index;
                            state_transaction.current_direct_stream_token_reputation_payload = None;
                            state_transaction.current_direct_reputation_policy_origin = None;
                            state_transaction
                                .current_direct_stream_token_gateway_instruction_index =
                                Self::direct_stream_token_gateway_instruction_index(
                                    state_transaction,
                                    &transaction_for_fee,
                                    &instruction,
                                    index,
                                    true,
                                )?;
                            state_transaction.current_direct_final_promotion_operation_origin =
                                None;
                            state_transaction.current_direct_musubi_pin_outbox_origin = None;
                            let result =
                                self.execute_instruction(state_transaction, authority, instruction);
                            state_transaction.current_direct_kagemusha_load_instruction_index =
                                None;
                            state_transaction.current_direct_stream_token_instruction_index = None;
                            state_transaction.current_direct_stream_token_reputation_payload = None;
                            state_transaction.current_direct_reputation_policy_origin = None;
                            state_transaction
                                .current_direct_stream_token_gateway_instruction_index = None;
                            state_transaction.current_direct_final_promotion_operation_origin =
                                None;
                            state_transaction.current_direct_musubi_pin_outbox_origin = None;
                            result?;
                        }
                        ExecutableBatchItem::ContractCall(call) => {
                            state_transaction.current_direct_kagemusha_load_instruction_index =
                                None;
                            state_transaction.current_direct_stream_token_instruction_index = None;
                            state_transaction.current_direct_stream_token_reputation_payload = None;
                            state_transaction.current_direct_reputation_policy_origin = None;
                            state_transaction
                                .current_direct_stream_token_gateway_instruction_index = None;
                            state_transaction.current_direct_final_promotion_operation_origin =
                                None;
                            state_transaction.current_direct_musubi_pin_outbox_origin = None;
                            let remaining = live_batch_contract_execution_limit(
                                gas_limit,
                                gas_used,
                                block_remaining,
                                state_transaction.last_tx_gas_used,
                            );
                            let outcome = self.execute_contract_invocation(
                                state_transaction,
                                authority,
                                &call,
                                ivm_cache,
                                remaining,
                                tx_creation_time_ms,
                                None,
                            )?;
                            gas_used = gas_used.saturating_add(outcome.gas_used);
                        }
                    }
                }
                Self::settle_live_transaction_fees(
                    state_transaction,
                    authority,
                    &transaction_for_fee,
                    gas_used,
                    explicit_instructions.len(),
                    tx_bytes_len,
                    gas_asset_opt,
                    fee_sponsor,
                    skip_nexus_fee,
                )
            }
            (Self::Initial | Self::UserProvided(_), Executable::Ivm(bytes)) => self
                .execute_raw_ivm_transaction(
                    state_transaction,
                    authority,
                    &transaction_for_fee,
                    ivm_cache,
                    bytes,
                    RawIvmTransactionInputs {
                        metadata: md,
                        gas_limit_md,
                        gas_asset_opt,
                        fee_sponsor,
                        skip_nexus_fee,
                        tx_bytes_len,
                    },
                ),
        }
    }
    /// Run only the selected raw-IVM branch, retaining its original fee and effect order.
    /// Native instructions do not reserve the runtime and host locals from this stage.
    #[allow(clippy::too_many_lines)]
    fn execute_raw_ivm_transaction(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        transaction_for_fee: &SignedTransaction,
        ivm_cache: &mut IvmCache,
        bytes: iroha_data_model::transaction::executable::IvmBytecode,
        inputs: RawIvmTransactionInputs,
    ) -> Result<(), ValidationFail> {
        let RawIvmTransactionInputs {
            metadata: md,
            gas_limit_md,
            gas_asset_opt,
            fee_sponsor,
            skip_nexus_fee,
            tx_bytes_len,
        } = inputs;
        // IVM path: run the bytecode through the VM with CoreHost, enqueueing ISIs,
        // then apply them via the standard executor logic.
        use crate::smartcontracts::ivm::host::CoreHostImpl as CoreCoreHost;
        // Set gas limit per transaction (payer-provided), clamped to remaining block budget.
        // Read the signature-bound payer cap captured before moving the transaction.
        let gas_limit_md = gas_limit_md.ok_or_else(|| {
            ValidationFail::NotPermitted("missing gas limit in fee payment intent".to_owned())
        })?;
        let block_remaining = if state_transaction.gas_limit_per_block == 0 {
            u64::MAX
        } else {
            state_transaction
                .gas_limit_per_block
                .saturating_sub(state_transaction.gas_used_in_block_so_far)
        };
        let effective_limit = gas_limit_md.min(block_remaining);
        let admitted = ivm_cache
            .summarize_executable(bytes.as_ref())
            .map_err(|error| {
                state_transaction.vm_error_to_validation_fail(
                    error,
                    crate::smartcontracts::ivm::program_admission_error,
                )
            })?;
        let summary = match admitted {
            ExecutableProgramSummary::Contract(summary) => summary,
            ExecutableProgramSummary::Generic(summary) => {
                let artifact =
                    root_scope::captured_artifact_id(state_transaction, summary.code_hash)?;
                crate::smartcontracts::ivm::validate_generic_execution_context(
                    &state_transaction.world,
                    &md,
                    artifact,
                )?;
                let effective_cycles =
                    validate_prepared_ivm_execution_policy(state_transaction, &summary.metadata)?;
                let prepared_contract_cache = ivm_cache.prepared_contract_cache();
                let amx_analysis =
                    ivm_cache
                        .analyze_generic_program(&summary)
                        .map_err(|error| {
                            state_transaction
                                .program_analysis_error_to_validation_fail(error, "generic-program")
                        })?;
                let streaming_metadata = crate::pipeline::overlay::resolve_streaming_metadata(
                    state_transaction,
                    authority,
                );
                let bound_contract_records = code::snapshot_bound_contract_records_by_subject(
                    state_transaction,
                )
                .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
                let heap_limit = state_transaction
                    .world
                    .parameters
                    .get()
                    .smart_contract()
                    .memory()
                    .get();
                let mut runtime = ivm_cache
                    .checkout_generic_runtime(&summary, effective_limit, heap_limit)
                    .map_err(|error| {
                        state_transaction.vm_error_to_validation_fail(error, |error| {
                            ValidationFail::InternalError(error.to_string())
                        })
                    })?;
                runtime.set_max_cycles(effective_cycles.get());
                runtime.set_gas_limit(effective_limit);
                let accounts = state_transaction.accounts_snapshot();
                let mut host =
                    CoreCoreHost::with_accounts(authority.clone(), Arc::clone(&accounts));
                host.set_output_limits_from_parameters(
                    state_transaction.world.parameters.get().smart_contract(),
                );
                host.set_generic_execution();
                host.set_prepared_contract_cache(prepared_contract_cache);
                host.set_amx_analysis(amx_analysis);
                host.set_amx_limits(
                    crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(
                        state_transaction.pipeline(),
                    ),
                );
                host.hydrate_axt_state(state_transaction).map_err(|error| {
                    ValidationFail::InternalError(format!("invalid AXT policy snapshot: {error}"))
                })?;
                host.set_crypto_config(Arc::clone(&state_transaction.crypto));
                host.set_zk_config(&state_transaction.zk);
                host.set_public_inputs_from_parameters(state_transaction.world.parameters.get());
                host.set_vrf_epoch_seeds_from_state(state_transaction)
                    .map_err(|error| {
                        state_transaction.attempt_error_to_validation_fail(
                            error.map_rejection(ValidationFail::InternalError),
                        )
                    })?;
                host.set_query_state(state_transaction);
                host.set_bound_contract_records_by_subject_snapshot(bound_contract_records);
                crate::pipeline::overlay::apply_streaming_metadata(&mut host, streaming_metadata);
                host.set_chain_id(&state_transaction.chain_id);
                #[cfg(feature = "telemetry")]
                host.set_telemetry(state_transaction.telemetry.clone());
                host.set_zk_snapshots_from_world(&state_transaction.world, &state_transaction.zk)
                    .map_err(|err| {
                        ValidationFail::InternalError(format!("invalid ZK snapshot state: {err}"))
                    })?;
                let run_result = match state_transaction.execution_cycle_budget()? {
                    Some(budget) => runtime.run_with_host_and_cycle_budget(&mut host, budget),
                    None => runtime.run_with_host(&mut host),
                }
                .and_then(|()| host.finish_contract_result(&runtime).map(|_| ()));
                let gas_used = effective_limit.saturating_sub(runtime.remaining_gas());
                if let Err(err) = run_result {
                    let attempt =
                        crate::smartcontracts::ivm::map_vm_error_with_context_to_validation(
                            &runtime, err,
                        );
                    drop(host);
                    let error = match attempt {
                        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                            return Err(state_transaction.defer_execution(reason));
                        }
                        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                    };
                    // The actual VM consumed this work even though business effects
                    // will roll back. Retain it before returning the original failure.
                    state_transaction.last_tx_gas_used = gas_used;
                    state_transaction.record_execution_fee_vm_work(gas_used)?;
                    return Err(error);
                }
                let artifacts = host.into_execution_artifacts(None);
                // Consume the host borrow, then retain root work before artifact
                // validation/application can reject. Later nested work must not be
                // overwritten by a post-application root-gas assignment.
                state_transaction.last_tx_gas_used = gas_used;
                state_transaction.record_execution_fee_vm_work(gas_used)?;
                let artifacts = artifacts?;
                let _executed = artifacts.apply_to_transaction(state_transaction, authority)?;
                Self::enforce_transaction_gas_fits_block(state_transaction, gas_used)?;
                if should_charge_pipeline_gas_asset(
                    skip_nexus_fee,
                    &state_transaction.nexus.fees,
                    &gas_asset_opt,
                ) && let Some(gas_asset_id_str) = gas_asset_opt
                {
                    Self::charge_pipeline_gas_asset_fee(
                        state_transaction,
                        authority,
                        transaction_for_fee,
                        &gas_asset_id_str,
                        gas_used,
                        fee_sponsor.as_ref(),
                    )?;
                }
                if !skip_nexus_fee {
                    Self::charge_nexus_fees(
                        state_transaction,
                        authority,
                        transaction_for_fee,
                        fee_sponsor,
                        tx_bytes_len,
                        0,
                        gas_used,
                    )?;
                }
                return Ok(());
            }
        };
        let effective_cycles =
            validate_prepared_ivm_execution_policy(state_transaction, &summary.metadata)?;
        crate::pipeline::overlay::validate_contract_binding(
            state_transaction,
            transaction_for_fee.payload(),
            &summary,
        )
        .map_err(|error| {
            overlay_build_error_to_attempt_validation_fail(state_transaction, error)
        })?;
        let selector = requested_contract_entrypoint(&md)?.ok_or_else(|| {
            ValidationFail::NotPermitted(
                "self-describing raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                    .to_owned(),
            )
        })?;
        let runtime_identity = require_raw_contract_runtime_identity(
            &state_transaction.world,
            summary.code_hash,
            &md,
        )?;
        code::ensure_contract_execution_allowed(
            &state_transaction.world,
            &runtime_identity.contract_address,
            state_transaction.block_height(),
        )
        .map_err(ValidationFail::NotPermitted)?;
        let entrypoint_authorization = authorize_prepared_raw_contract_selector(
            &state_transaction.world,
            authority,
            summary.prepared_contract(),
            &selector,
            &runtime_identity,
        )
        .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        let contract_subject = code::fetch_bound_contract_subject(
            state_transaction,
            &runtime_identity.contract_address,
        )
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "contract instance `{}` has no valid subject binding",
                runtime_identity.contract_address
            ))
        })?;
        let transition = validate_prepared_contract_lifecycle_call(
            &state_transaction.world,
            &runtime_identity.contract_address,
            runtime_identity.code_hash,
            summary.prepared_contract(),
            &selector,
        )?;
        debug_assert!(
            transition.is_none(),
            "raw lifecycle selectors are rejected before state validation"
        );
        let mut contract_call_context = parse_prepared_contract_call_execution_context(
            &md,
            summary.prepared_contract(),
            effective_limit,
        )?;
        if let Some(context) = contract_call_context.as_mut() {
            context.bind_runtime_identity(runtime_identity, contract_subject);
        }
        if let Some(context) = contract_call_context.as_ref() {
            enforce_contract_entrypoint_authorization(&state_transaction.world, authority, context)
                .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        }
        let heap_limit = state_transaction
            .world
            .parameters
            .get()
            .smart_contract()
            .memory()
            .get();
        let mut runtime = summary
            .checkout_runtime(effective_limit, heap_limit)
            .map_err(|error| {
                state_transaction.vm_error_to_validation_fail(error, |error| {
                    ValidationFail::InternalError(error.to_string())
                })
            })?;
        runtime.set_max_cycles(effective_cycles.get());
        runtime.set_gas_limit(effective_limit);
        if let Some(context) = contract_call_context.as_ref() {
            if let Some(entrypoint_pc) = context.entrypoint_pc {
                let code_len = runtime.memory.code_len();
                runtime.set_register(1, code_len);
                runtime.set_program_counter(entrypoint_pc).map_err(|err| {
                    let selector = context.entrypoint.as_deref().unwrap_or("main");
                    ValidationFail::NotPermitted(format!(
                        "contract entrypoint `{selector}` resolved to invalid pc: {err}"
                    ))
                })?;
            }
        }
        let precharge_result = contract_call_context
            .as_ref()
            .and_then(ContractCallExecutionContext::prepared_argument_record)
            .map_or(Ok(()), |record| record.precharge_vm(&mut runtime));
        if let Err(error) = &precharge_result {
            runtime.record_boundary_fault(
                error,
                iroha_data_model::executor::fault::IvmFaultPositionV1::Initialization,
            );
        }
        let contract_runtime_context = contract_call_context
            .as_ref()
            .and_then(ContractCallExecutionContext::runtime_context);
        // Attach host with a snapshot of known accounts for vendor helpers when present.
        let accounts = state_transaction.accounts_snapshot();
        let mut host = if let Some(context) = contract_call_context {
            CoreCoreHost::with_accounts_and_argument_record(
                authority.clone(),
                Arc::clone(&accounts),
                context.argument_record,
            )
        } else {
            CoreCoreHost::with_accounts(authority.clone(), Arc::clone(&accounts))
        };
        host.set_output_limits_from_parameters(
            state_transaction.world.parameters.get().smart_contract(),
        );
        host.set_prepared_contract_cache(summary.prepared_contract_cache());
        host.hydrate_axt_state(state_transaction).map_err(|error| {
            ValidationFail::InternalError(format!("invalid AXT policy snapshot: {error}"))
        })?;
        host.set_crypto_config(Arc::clone(&state_transaction.crypto));
        host.set_zk_config(&state_transaction.zk);
        host.set_public_inputs_from_parameters(state_transaction.world.parameters.get());
        host.set_vrf_epoch_seeds_from_state(state_transaction)
            .map_err(|error| {
                state_transaction.attempt_error_to_validation_fail(
                    error.map_rejection(ValidationFail::InternalError),
                )
            })?;
        host.set_query_state(state_transaction);
        host.set_contract_runtime_context(contract_runtime_context.clone());
        host.set_contract_entrypoint_authorization(Some(entrypoint_authorization));
        // Keep the human-readable label available through SYSVAR_CHAIN_ID; AXT
        // hydration above installs the exact NetworkId used by VRF verification.
        host.set_chain_id(&state_transaction.chain_id);
        #[cfg(feature = "telemetry")]
        host.set_telemetry(state_transaction.telemetry.clone());
        // Thread ZK snapshots (roots, elections, verifying keys) for read/verify syscalls.
        host.set_zk_snapshots_from_world(&state_transaction.world, &state_transaction.zk)
            .map_err(|err| {
                ValidationFail::InternalError(format!("invalid ZK snapshot state: {err}"))
            })?;
        let cycle_budget = state_transaction.execution_cycle_budget()?;
        let run_result = precharge_result
            .and_then(|()| match cycle_budget {
                Some(budget) => runtime.run_with_host_and_cycle_budget(&mut host, budget),
                None => runtime.run_with_host(&mut host),
            })
            .and_then(|()| host.finish_contract_result(&runtime).map(|_| ()));
        let gas_used = effective_limit.saturating_sub(runtime.remaining_gas());
        if let Err(err) = run_result {
            let attempt =
                crate::smartcontracts::ivm::map_vm_error_with_context_to_validation(&runtime, err);
            drop(host);
            let error = match attempt {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    return Err(state_transaction.defer_execution(reason));
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
            };
            state_transaction.last_tx_gas_used = gas_used;
            state_transaction.record_execution_fee_vm_work(gas_used)?;
            return Err(error);
        }
        // Retain completed root work before artifact validation/application;
        // a rejected artifact must not make an executed raw contract free.
        let artifacts = host.into_execution_artifacts(contract_runtime_context);
        state_transaction.last_tx_gas_used = gas_used;
        state_transaction.record_execution_fee_vm_work(gas_used)?;
        let artifacts = artifacts?;
        let _executed = artifacts.apply_to_transaction(state_transaction, authority)?;
        Self::enforce_transaction_gas_fits_block(state_transaction, gas_used)?;
        // Charge gas fees: if a gas asset was provided and accepted by policy.
        if should_charge_pipeline_gas_asset(
            skip_nexus_fee,
            &state_transaction.nexus.fees,
            &gas_asset_opt,
        ) && let Some(gas_asset_id_str) = gas_asset_opt
        {
            Self::charge_pipeline_gas_asset_fee(
                state_transaction,
                authority,
                transaction_for_fee,
                &gas_asset_id_str,
                gas_used,
                fee_sponsor.as_ref(),
            )?;
        }
        if !skip_nexus_fee {
            Self::charge_nexus_fees(
                state_transaction,
                authority,
                transaction_for_fee,
                fee_sponsor,
                tx_bytes_len,
                0,
                gas_used,
            )?;
        }
        Ok(())
    }
    /// Execute [`InstructionBox`].
    ///
    /// # Errors
    ///
    /// - Failed to prepare the IVM runtime;
    /// - Failed to execute the entrypoint of the IVM bytecode;
    /// - Executor denied the operation.
    pub fn execute_instruction(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: InstructionBox,
    ) -> Result<(), ValidationFail> {
        self.execute_instruction_with_profile_and_contract_runtime_context(
            state_transaction,
            authority,
            instruction,
            InstructionExecutionProfile::Runtime,
            None,
        )
    }
    /// Execute [`InstructionBox`] using the runtime profile and an optional
    /// contract execution context for nested contract-originated instructions.
    pub(crate) fn execute_instruction_with_contract_runtime_context(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: InstructionBox,
        contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
    ) -> Result<(), ValidationFail> {
        self.execute_instruction_with_profile_and_contract_runtime_context(
            state_transaction,
            authority,
            instruction,
            InstructionExecutionProfile::Runtime,
            contract_runtime_context,
        )
    }
    /// Execute a borrowed overlay instruction using the runtime profile.
    ///
    /// The public executor API remains owned-instruction based. Overlay apply
    /// calls this crate-private adapter so built-in executor borrowing can be
    /// extended without changing custom executor or wire/API behaviour.
    pub(crate) fn execute_borrowed_overlay_instruction(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: &InstructionBox,
        contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
    ) -> Result<(), ValidationFail> {
        match self {
            Self::Initial => self
                .execute_borrowed_instruction_with_profile_and_contract_runtime_context(
                    state_transaction,
                    authority,
                    instruction,
                    InstructionExecutionProfile::Runtime,
                    contract_runtime_context,
                ),
            Self::UserProvided(_) => {
                iroha_logger::trace!(
                    instr = %instruction.id(),
                    "using owned overlay instruction fallback for user-provided executor"
                );
                self.execute_instruction_with_profile_and_contract_runtime_context(
                    state_transaction,
                    authority,
                    instruction.clone(),
                    InstructionExecutionProfile::Runtime,
                    contract_runtime_context,
                )
            }
        }
    }
    /// Execute [`InstructionBox`] using a specific execution profile.
    ///
    /// `InstructionExecutionProfile::Runtime` mirrors production behaviour.
    /// `InstructionExecutionProfile::Bench` disables logging so benchmarks/tests
    /// can run without installing the global logger while still enforcing policy checks.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationFail`] when the delegated executor rejects the instruction,
    /// or if preparing or running the IVM bytecode fails.
    pub fn execute_instruction_with_profile(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: InstructionBox,
        profile: InstructionExecutionProfile,
    ) -> Result<(), ValidationFail> {
        self.execute_instruction_with_profile_and_contract_runtime_context(
            state_transaction,
            authority,
            instruction,
            profile,
            None,
        )
    }
    fn execute_instruction_with_profile_and_contract_runtime_context(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: InstructionBox,
        profile: InstructionExecutionProfile,
        contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
    ) -> Result<(), ValidationFail> {
        root_scope::ensure_instruction_scope(&instruction, state_transaction)?;
        ensure_contract_deployment_permission_mutation_allowed(
            state_transaction,
            authority,
            &instruction,
        )?;
        ensure_contract_entrypoint_authorization_mutation_allowed(
            state_transaction,
            authority,
            &instruction,
        )?;
        ensure_lifecycle_hook_cannot_mutate_contract_binding(
            contract_runtime_context,
            &instruction,
        )?;
        ensure_contract_runtime_permission_mutation_allowed(
            authority,
            &instruction,
            contract_runtime_context,
        )?;
        trace!("Running instruction execution");
        let instr_id = instruction.id();
        let result = match self {
            Self::Initial => Self::execute_initial_instruction(
                state_transaction,
                authority,
                &instruction,
                profile,
                contract_runtime_context,
            ),
            Self::UserProvided(loaded_executor) => dispatch_instruction_with_ivm(
                loaded_executor,
                state_transaction,
                authority,
                instruction,
            ),
        };
        if let Err(err) = &result {
            iroha_logger::error!(
                ?profile,
                instr = %instr_id,
                ?err,
                "instruction execution failed"
            );
        }
        result
    }
    fn execute_borrowed_instruction_with_profile_and_contract_runtime_context(
        &self,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: &InstructionBox,
        profile: InstructionExecutionProfile,
        contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
    ) -> Result<(), ValidationFail> {
        root_scope::ensure_instruction_scope(instruction, state_transaction)?;
        ensure_contract_deployment_permission_mutation_allowed(
            state_transaction,
            authority,
            instruction,
        )?;
        ensure_contract_entrypoint_authorization_mutation_allowed(
            state_transaction,
            authority,
            instruction,
        )?;
        ensure_lifecycle_hook_cannot_mutate_contract_binding(
            contract_runtime_context,
            instruction,
        )?;
        ensure_contract_runtime_permission_mutation_allowed(
            authority,
            instruction,
            contract_runtime_context,
        )?;
        trace!("Running borrowed instruction execution");
        let instr_id = instruction.id();
        let result = match self {
            Self::Initial => Self::execute_initial_instruction(
                state_transaction,
                authority,
                instruction,
                profile,
                contract_runtime_context,
            ),
            Self::UserProvided(_) => self
                .execute_instruction_with_profile_and_contract_runtime_context(
                    state_transaction,
                    authority,
                    instruction.clone(),
                    profile,
                    contract_runtime_context,
                ),
        };
        if let Err(err) = &result {
            iroha_logger::error!(
                ?profile,
                instr = %instr_id,
                ?err,
                "borrowed instruction execution failed"
            );
        }
        result
    }
    #[allow(clippy::too_many_lines, clippy::items_after_statements)]
    fn execute_initial_instruction(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        instruction: &InstructionBox,
        profile: InstructionExecutionProfile,
        contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
    ) -> Result<(), ValidationFail> {
        if matches!(profile, InstructionExecutionProfile::Runtime) {
            iroha_logger::trace!(
                instr = %instruction.id(),
                "executing instruction (Initial executor)"
            );
        }
        match MultisigInstructionBox::try_from(instruction) {
            Ok(multisig) => {
                return crate::smartcontracts::isi::multisig::execute_multisig_instruction(
                    state_transaction,
                    authority,
                    multisig,
                );
            }
            Err(err) => {
                let err =
                    match crate::smartcontracts::isi::multisig::multisig_instruction_decode_attempt(
                        err,
                        std::convert::identity,
                    ) {
                        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                            return Err(state_transaction.defer_execution(reason));
                        }
                        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                    };
                if let Some(custom) = instruction.as_any().downcast_ref::<CustomInstruction>() {
                    iroha_logger::error!(
                        ?err,
                        instr = %instruction.id(),
                        payload = %custom.payload(),
                        "failed to decode multisig custom instruction"
                    );
                }
            }
        }
        if instruction
            .as_any()
            .downcast_ref::<CustomInstruction>()
            .is_some()
        {
            return Err(ValidationFail::NotPermitted(
                "custom instructions require an executor upgrade".to_owned(),
            ));
        }
        let is_genesis = is_initial_genesis_context(state_transaction);
        validate_initial_permission_or_role_mutation(
            state_transaction,
            authority,
            instruction,
            is_genesis,
        )
        .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        validate_initial_native_instruction_authority(
            state_transaction,
            authority,
            instruction,
            is_genesis,
        )
        .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
        if instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::TransferAssetBatch>()
            .is_some()
            && !valid_contract_runtime_subject(
                &state_transaction.world,
                authority,
                contract_runtime_context,
            )
        {
            return Err(ValidationFail::NotPermitted(
                "Can't transfer asset batch from an inactive or inconsistent contract subject"
                    .to_owned(),
            ));
        }
        if let Some(register_role) = extract_register_role(instruction) {
            if is_reserved_multisig_role_id(register_role.object().id()) {
                return Err(ValidationFail::NotPermitted(
                    "reserved multisig role names may not be registered".to_owned(),
                ));
            }
            let role = register_role.object();
            let mut normalized_role = Role::new(role.id().clone(), role.grant_to().clone());
            for permission in role.inner().permissions() {
                let normalized =
                    normalize_role_permission_for_initial_executor(state_transaction, permission)?;
                if !is_genesis
                    && !initial_permission_delegation_allowed(
                        state_transaction,
                        authority,
                        &normalized,
                    )
                    .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?
                {
                    return Err(ValidationFail::NotPermitted(format!(
                        "Can't seed role with permission `{}`",
                        normalized.name()
                    )));
                }
                normalized_role = normalized_role.add_permission(normalized);
            }
            if !is_genesis {
                let can_manage_roles: Permission = executor_permission::role::CanManageRoles.into();
                let has_manage_roles = authority_has_permission(
                    &state_transaction.world,
                    authority,
                    &can_manage_roles,
                )?;
                if !has_manage_roles {
                    return Err(ValidationFail::NotPermitted(
                        "Can't register role".to_owned(),
                    ));
                }
            }
            Register::role(normalized_role)
                .execute(authority, state_transaction)
                .map_err(ValidationFail::from)?;
            return Ok(());
        }
        if extract_unregister_role(instruction).is_some() && !is_genesis {
            let can_manage_roles: Permission = executor_permission::role::CanManageRoles.into();
            if !authority_has_permission(&state_transaction.world, authority, &can_manage_roles)? {
                return Err(ValidationFail::NotPermitted(
                    "Can't unregister role".to_owned(),
                ));
            }
        }
        // Native fail-safe authorization remains active until an on-chain executor is
        // installed. Keep the specialized validation below for registration invariants
        // and CBDC-specific authority relationships that go beyond the generic gates.
        // Only attempt to decode as Register<Trigger> when the dynamic type matches.
        // Guard against panics in Norito deserialization for mismatched schemas.
        let is_reg_trigger = instruction
            .id()
            .starts_with(core::any::type_name::<Register<Trigger>>());
        let reg_trg = if is_reg_trigger {
            iroha_panic_hook::catch_unwind_suppressed(|| {
                Register::<Trigger>::decode(&mut &instruction.dyn_encode()[..])
            })
            .ok()
            .and_then(Result::ok)
        } else {
            None
        };
        if let Some(reg_trg) = reg_trg {
            // Allow in genesis, for the exact trigger owner, or if tx authority has
            // explicit CanRegisterTrigger { authority: <owner> }. Alias-domain
            // ownership does not authorize the canonical, domainless account.
            let trg_owner = reg_trg.object().action().authority().clone();
            let is_owner = authority == &trg_owner;
            // Prefer cached permission check; parse once per tx/account.
            let has_permission =
                (!is_genesis) && state_transaction.can_register_trigger_for(authority, &trg_owner);
            if !(is_genesis || is_owner || has_permission) {
                return Err(ValidationFail::NotPermitted(
                    "Can't register trigger owned by another account".to_owned(),
                ));
            }
        }
        if let Some(reg) = extract_register_dataspace_asset_definition(instruction) {
            crate::smartcontracts::isi::domain::isi::ensure_dataspace_asset_definition_registration_allowed(
                state_transaction, authority, &reg,
            ).map_err(ValidationFail::InstructionFailed)?;
        }
        if let Some(reg_asset_definition) = extract_register_asset_definition(instruction) {
            ensure_asset_definition_registration_allowed(
                state_transaction,
                authority,
                &reg_asset_definition,
            )?;
        }
        if !is_genesis
            && let Some(mint) = extract_mint_asset(instruction)
            && !can_mint_asset(&state_transaction.world, authority, mint.destination())?
        {
            return Err(ValidationFail::NotPermitted(
                "Can't mint an asset without owning its definition or an exact mint permission"
                    .to_owned(),
            ));
        }
        if !is_genesis
            && let Some(asset_definition_id) = extract_asset_definition_metadata_target(instruction)
            && !can_modify_asset_definition_metadata(
                &state_transaction.world,
                authority,
                &asset_definition_id,
            )?
        {
            return Err(ValidationFail::NotPermitted(
                "Can't modify asset-definition metadata without ownership or an exact permission"
                    .to_owned(),
            ));
        }
        if let Some(account_id) = extract_account_metadata_target(instruction) {
            if !is_genesis
                && !can_modify_account_metadata(&state_transaction.world, authority, &account_id)?
            {
                return Err(ValidationFail::NotPermitted(
                    "Can't set value to the metadata of another account".to_owned(),
                ));
            }
        }
        fn has_modify_nft_metadata_permission(
            state_transaction: &mut StateTransaction<'_, '_>,
            authority: &AccountId,
            nft_id: &iroha_data_model::nft::NftId,
        ) -> Result<bool, ValidationFail> {
            let is_target_permission = |permission: &Permission| -> bool {
                permission
                    .payload()
                    .try_into_any_norito::<executor_permission::nft::CanModifyNftMetadata>()
                    .is_ok_and(|token| token.nft == *nft_id)
            };
            {
                let permissions = state_transaction
                    .world
                    .account_permissions_iter(authority)
                    .map_err(|err| {
                        ValidationFail::InstructionFailed(InstructionExecutionError::Find(err))
                    })?;
                if permissions.into_iter().any(is_target_permission) {
                    return Ok(true);
                }
            }
            for role_id in state_transaction.world.account_roles_iter(authority) {
                if let Some(role) = state_transaction.world.roles.get(role_id) {
                    if role.permissions.iter().any(is_target_permission) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        if let Some(nft_id) = instruction
            .as_any()
            .downcast_ref::<SetKeyValueBox>()
            .and_then(|kv| match kv {
                SetKeyValueBox::Nft(set) => Some(set.object.clone()),
                _ => None,
            })
            .or_else(|| {
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::SetKeyValue<iroha_data_model::nft::Nft>>()
                    .map(|set| set.object.clone())
            })
            .or_else(|| {
                instruction
                    .as_any()
                    .downcast_ref::<RemoveKeyValueBox>()
                    .and_then(|rm| match rm {
                        RemoveKeyValueBox::Nft(rm) => Some(rm.object.clone()),
                        _ => None,
                    })
            })
            .or_else(|| {
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::RemoveKeyValue<iroha_data_model::nft::Nft>>()
                    .map(|rm| rm.object.clone())
            })
        {
            if !is_initial_genesis_context(state_transaction) {
                let domain_owner = state_transaction
                    .world
                    .domain(nft_id.domain())
                    .map(|domain| domain.owned_by().clone())
                    .map_err(|err| {
                        ValidationFail::InstructionFailed(InstructionExecutionError::Find(err))
                    })?;
                if &domain_owner != authority
                    && !has_modify_nft_metadata_permission(state_transaction, authority, &nft_id)?
                {
                    return Err(ValidationFail::NotPermitted(
                        "Can't modify NFT from domain owned by another account".to_owned(),
                    ));
                }
            }
        }
        if let Some(transfer_domain) = extract_transfer_domain(instruction)
            && !can_transfer_domain(
                &state_transaction.world,
                authority,
                &transfer_domain,
                state_transaction.block_unix_timestamp_ms(),
            )
            .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?
        {
            return Err(ValidationFail::NotPermitted(
                "Can't transfer domain of another account".to_owned(),
            ));
        }
        if let Some(transfer_asset_definition) = extract_transfer_asset_definition(instruction)
            && !can_transfer_asset_definition(
                &state_transaction.world,
                authority,
                &transfer_asset_definition,
            )?
        {
            return Err(ValidationFail::NotPermitted(
                "Can't transfer asset definition of another account".to_owned(),
            ));
        }
        if let Some(transfer_nft) = extract_transfer_nft(instruction)
            && !can_transfer_nft(&state_transaction.world, authority, &transfer_nft)?
        {
            return Err(ValidationFail::NotPermitted(
                "Can't transfer NFT of another account".to_owned(),
            ));
        }
        if !is_genesis
            && let Some(transfer_asset) = extract_transfer_asset(instruction)
            && !can_transfer_asset(
                &state_transaction.world,
                authority,
                contract_runtime_context,
                &transfer_asset,
            )?
        {
            return Err(ValidationFail::NotPermitted(
                "Can't transfer asset: source asset owner must sign the transaction".to_owned(),
            ));
        }
        let instruction_id = instruction.id();
        crate::smartcontracts::isi::execute_borrowed_instruction(
            instruction,
            authority,
            state_transaction,
        )
        .map_err(|err| {
            if matches!(profile, InstructionExecutionProfile::Runtime) {
                iroha_logger::debug!(
                    ?err,
                    %instruction_id,
                    authority = %authority,
                    "initial executor rejected instruction during application"
                );
            }
            ValidationFail::from(err)
        })
    }
    /// Validate [`QueryRequest`].
    ///
    /// # Errors
    ///
    /// - Failed to prepare the IVM runtime;
    /// - Failed to execute the entrypoint of the IVM bytecode;
    /// - Executor denied the operation.
    pub(crate) fn validate_query<S: StateReadOnly>(
        &self,
        state_ro: &S,
        authority: &AccountId,
        query: &QueryRequest,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        let latest_block = state_ro
            .latest_block()
            .map_err(|error| {
                error.map_rejection(|error| {
                    ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::CanonicalHistory(error),
                    )
                })
            })?
            .map(|block| block.header());
        self.validate_query_with_world_parts(
            state_ro.world(),
            latest_block,
            authority,
            query,
            &state_ro.execution_budget(),
        )
    }
    /// Validate [`QueryRequest`] using world-state and latest committed block header.
    ///
    /// This variant avoids requiring a full [`StateReadOnly`] snapshot in callers that
    /// already have a world view and can cheaply resolve the latest block header.
    ///
    /// # Errors
    ///
    /// - Failed to prepare the IVM runtime;
    /// - Failed to execute the entrypoint of the IVM bytecode;
    /// - Executor denied the operation.
    pub(crate) fn validate_query_with_world_parts(
        &self,
        world_ro: &impl WorldReadOnly,
        latest_block: Option<BlockHeader>,
        authority: &AccountId,
        query: &QueryRequest,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        trace!("Running query validation");
        // This native boundary is mandatory for Initial and user-provided executors alike.
        // A custom executor may further restrict a query, but can never widen these grants.
        validate_builtin_native_query_permission(
            world_ro,
            authority,
            query,
            latest_block.as_ref().map_or(0, |header| {
                u64::try_from(header.creation_time().as_millis()).unwrap_or(u64::MAX)
            }),
        )?;
        let query_box = match query {
            QueryRequest::Singular(singular) => AnyQueryBox::Singular(singular.clone()),
            QueryRequest::Start(iterable) => AnyQueryBox::Iterable(iterable.clone()),
            QueryRequest::Continue(_) => {
                // The iterable query was validated when it started. Execution still
                // binds the cursor to this request's authority in LiveQueryStore
                // before advancing any stored state.
                return Ok(());
            }
        };
        // Alias reads carry privacy and routing authority independent of the pluggable executor.
        // Enforce the exact built-in dataspace/domain grants first so neither the permissive
        // initial executor nor an incomplete user executor visitor can bypass them.
        validate_builtin_account_alias_query_permission(
            world_ro,
            latest_block.as_ref(),
            authority,
            query,
        )?;
        validate_builtin_subsystem_query_permission(
            world_ro,
            latest_block.as_ref(),
            authority,
            query,
        )?;
        match self {
            Self::Initial => Ok(()),
            Self::UserProvided(loaded_executor) => {
                let curr_block = latest_block.map_or_else(
                    || BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0),
                    core::convert::identity,
                );
                let context = ExecutorContext {
                    authority: authority.clone(),
                    curr_block,
                };
                let payload = ValidatePayload {
                    context,
                    target: query_box,
                };
                let query_label = match query {
                    QueryRequest::Singular(_) => "query::singular",
                    QueryRequest::Start(_) => "query::start",
                    QueryRequest::Continue(_) => unreachable!("continue queries return early"),
                };
                let executor_parameters = world_ro.parameters().executor();
                let gas_limit = executor_parameters.fuel().get();
                let heap_limit = executor_parameters.memory().get();
                let report = run_executor_validation(
                    loaded_executor,
                    &payload,
                    query_label,
                    gas_limit,
                    heap_limit,
                    budget,
                )?;
                match report.verdict {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        iroha_logger::debug!(
                            ?err,
                            authority = %authority,
                            query = %query_label,
                            "executor validation rejected query"
                        );
                        Err(err.into())
                    }
                }
            }
        }
    }
    /// Migrate executor to a new user-provided one.
    ///
    /// Execute `migrate()` entrypoint of the `raw_executor` and set `self` to
    /// [`UserProvided`](Executor::UserProvided) with `raw_executor`.
    ///
    /// # Errors
    ///
    /// - The caller is outside initial genesis and does not hold `CanUpgradeExecutor`;
    /// - Failed to load `raw_executor`;
    /// - Failed to prepare the IVM runtime;
    /// - Failed to execute the entrypoint of the IVM bytecode.
    pub fn migrate(
        &mut self,
        raw_executor: data_model_executor::Executor,
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
    ) -> Result<(), VMError> {
        trace!("Running executor migration");
        let can_upgrade: Permission = executor_permission::executor::CanUpgradeExecutor.into();
        if !is_initial_genesis_context(state_transaction)
            && !authority_has_permission(&state_transaction.world, authority, &can_upgrade)
                .map_err(|_| VMError::PermissionDenied)?
        {
            return Err(VMError::PermissionDenied);
        }
        // Load new executor bytecode
        let loaded_executor = LoadedExecutor::load(raw_executor).map_err(|error| {
            if let Some(reason) = crate::execution_attempt::ExecutionDeferred::from_vm_error(&error)
            {
                state_transaction.defer_execution(reason);
            }
            error
        })?;
        let curr_block = state_transaction._curr_block;
        let context = ExecutorContext {
            authority: authority.clone(),
            curr_block,
        };
        let executor_parameters = state_transaction.world.parameters.get().executor();
        let gas_limit = executor_parameters.fuel().get();
        let heap_limit = executor_parameters.memory().get();
        let maybe_data_model = run_executor_migration(
            &loaded_executor,
            &context,
            gas_limit,
            heap_limit,
            &state_transaction.execution_budget(),
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                map_migration_fail_to_vm_error(error)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                state_transaction.defer_execution(reason.clone());
                reason.into_vm_error()
            }
        })?;
        if let Some(data_model) = maybe_data_model {
            debug!("executor migrate entrypoint supplied a new data model");
            state_transaction
                .world
                .apply_executor_data_model(data_model);
        }
        *self = Self::UserProvided(loaded_executor);
        Ok(())
    }
}
struct ExecutorValidationReport {
    verdict: Result<(), ValidationFail>,
    gas_used: u64,
}
fn initial_executor_permission_names() -> BTreeSet<String> {
    INITIAL_EXECUTOR_PERMISSION_NAMES
        .iter()
        .map(|permission| (*permission).to_owned())
        .collect()
}
pub(crate) fn initial_executor_data_model_fallback() -> ExecutorDataModel {
    ExecutorDataModel::new(
        BTreeMap::new(),
        BTreeSet::new(),
        initial_executor_permission_names(),
        Json::new(()),
    )
}
fn run_executor_validation<T>(
    executor: &LoadedExecutor,
    payload: &ValidatePayload<T>,
    verdict_context: &str,
    gas_limit: u64,
    heap_limit: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<ExecutorValidationReport, crate::execution_attempt::ExecutionAttemptError<ValidationFail>>
where
    ValidatePayload<T>: Encode,
{
    let mut ivm = executor
        .checkout_runtime_for_gas_limit(gas_limit, heap_limit, budget)
        .map_err(|error| {
            crate::execution_attempt::vm_attempt_error(error, |error| {
                ValidationFail::InternalError(error.to_string())
            })
        })?;
    ivm.set_host(ivm::host::DefaultHost::default());
    let bytes = encode_executor_input(payload)?;
    let ptr = Memory::HEAP_START;
    ivm.store_bytes(ptr, &bytes).map_err(|error| {
        crate::execution_attempt::vm_attempt_error(error, |error| {
            ValidationFail::InternalError(error.to_string())
        })
    })?;
    ivm.set_register(10, ptr);
    ivm.set_gas_limit(gas_limit);
    let run_result = ivm.run();
    let gas_used = gas_limit.saturating_sub(ivm.remaining_gas());
    if let Err(err) = run_result {
        if matches!(err, VMError::ExceededMaxCycles | VMError::OutOfGas) {
            return Ok(ExecutorValidationReport {
                verdict: Err(ValidationFail::TooComplex),
                gas_used,
            });
        }
        return Err(crate::execution_attempt::vm_attempt_error(err, |error| {
            ValidationFail::InternalError(error.to_string())
        }));
    }
    let ret_ptr = ivm.register(10);
    let mut slice = executor_output_payload(&ivm, ret_ptr, "validation verdict")?;
    let verdict: Result<(), ValidationFail> = Decode::decode(&mut slice).map_err(|err| {
        ValidationFail::InternalError(format!(
            "executor returned undecodable verdict: {verdict_context}: {err}"
        ))
    })?;
    if !slice.is_empty() {
        return Err(ValidationFail::InternalError(format!(
            "executor returned a verdict with trailing bytes: {verdict_context}"
        ))
        .into());
    }
    Ok(ExecutorValidationReport {
        verdict: verdict.map_err(validate_executor_rejection_origin),
        gas_used,
    })
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::executor::MigrationResultPayload")]
#[derive(Debug, Decode, Encode)]
enum MigrationResultPayload {
    Ok(ExecutorDataModel),
    Err(ValidationFail),
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::executor::MigrationUnitPayload")]
#[derive(Debug, Decode, Encode)]
enum MigrationUnitPayload {
    Ok(()),
    Err(ValidationFail),
}
fn run_executor_migration(
    executor: &LoadedExecutor,
    context: &ExecutorContext,
    gas_limit: u64,
    heap_limit: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<
    Option<ExecutorDataModel>,
    crate::execution_attempt::ExecutionAttemptError<ValidationFail>,
> {
    let mut ivm = executor
        .checkout_runtime_for_gas_limit(gas_limit, heap_limit, budget)
        .map_err(|error| {
            crate::execution_attempt::vm_attempt_error(error, |error| {
                ValidationFail::InternalError(error.to_string())
            })
        })?;
    ivm.set_host(ivm::host::DefaultHost::default());
    let bytes = encode_executor_input(context)?;
    let ptr = Memory::HEAP_START;
    ivm.store_bytes(ptr, &bytes).map_err(|error| {
        crate::execution_attempt::vm_attempt_error(error, |error| {
            ValidationFail::InternalError(error.to_string())
        })
    })?;
    ivm.set_register(10, ptr);
    ivm.set_gas_limit(gas_limit);
    ivm.run().map_err(|error| {
        crate::execution_attempt::vm_attempt_error(error, |error| {
            ValidationFail::InternalError(error.to_string())
        })
    })?;
    let ret_ptr = ivm.register(10);
    let payload = executor_output_payload(&ivm, ret_ptr, "migration result")?;
    let mut slice = payload;
    if let Ok(verdict) = MigrationResultPayload::decode(&mut slice)
        && slice.is_empty()
    {
        return match verdict {
            MigrationResultPayload::Ok(model) => Ok(Some(model)),
            MigrationResultPayload::Err(fail) => {
                Err(validate_executor_rejection_origin(fail).into())
            }
        };
    }
    let mut slice_unit = payload;
    if let Ok(verdict) = MigrationUnitPayload::decode(&mut slice_unit)
        && slice_unit.is_empty()
    {
        return match verdict {
            MigrationUnitPayload::Ok(()) => Ok(None),
            MigrationUnitPayload::Err(fail) => Err(validate_executor_rejection_origin(fail).into()),
        };
    }
    Err(ValidationFail::InternalError(
        "executor migrate entrypoint returned an undecodable or non-canonical result".to_owned(),
    )
    .into())
}
/// Only the native execution boundary may certify a runtime fault origin.
fn validate_executor_rejection_origin(fail: ValidationFail) -> ValidationFail {
    if matches!(fail, ValidationFail::IvmFault(_)) {
        ValidationFail::InternalError(
            "executor verdict cannot supply a runtime fault origin".to_owned(),
        )
    } else {
        fail
    }
}
fn map_migration_fail_to_vm_error(fail: ValidationFail) -> VMError {
    match fail {
        ValidationFail::NotPermitted(reason) => {
            debug!(
                reason = %reason,
                "executor migrate entrypoint rejected migration"
            );
            VMError::PermissionDenied
        }
        ValidationFail::TooComplex => VMError::ExceededMaxCycles,
        ValidationFail::IvmAdmission(info) => {
            debug!(
                info = ?info,
                "executor migrate entrypoint failed admission checks"
            );
            VMError::DecodeError
        }
        ValidationFail::InstructionFailed(err) => {
            debug!(
                err = ?err,
                "executor migrate entrypoint instruction failure"
            );
            VMError::DecodeError
        }
        ValidationFail::IvmFault(_) => VMError::DecodeError,
        ValidationFail::ContractRejected(rejection) => {
            debug!(
                ?rejection,
                "executor migrate entrypoint returned a declared contract rejection"
            );
            VMError::PermissionDenied
        }
        ValidationFail::QueryFailed(err) => {
            debug!(
                err = ?err,
                "executor migrate entrypoint query failure"
            );
            VMError::DecodeError
        }
        ValidationFail::InternalError(message) => {
            debug!(
                message = %message,
                "executor migrate entrypoint reported internal error"
            );
            VMError::DecodeError
        }
        ValidationFail::AxtReject(ctx) => {
            debug!(?ctx, "executor migrate entrypoint rejected AXT payload");
            VMError::PermissionDenied
        }
    }
}
fn dispatch_instruction_with_ivm(
    executor: &LoadedExecutor,
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: InstructionBox,
) -> Result<(), ValidationFail> {
    let latest_block = state_transaction
        .latest_block()
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                state_transaction.defer_execution(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::CanonicalHistory(error),
                )
            }
        })?;
    let curr_block = latest_block.map_or_else(
        || BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0),
        |b| b.header(),
    );
    let context = ExecutorContext {
        authority: authority.clone(),
        curr_block,
    };
    let payload = ValidatePayload {
        context,
        target: instruction.clone(),
    };
    let instruction_id = instruction.id();
    let gas_limit = state_transaction.executor_fuel_remaining;
    let heap_limit = state_transaction
        .world
        .parameters
        .get()
        .executor()
        .memory()
        .get();
    let report = run_executor_validation(
        executor,
        &payload,
        instruction_id,
        gas_limit,
        heap_limit,
        &state_transaction.execution_budget(),
    )
    .map_err(|error| state_transaction.attempt_error_to_validation_fail(error))?;
    state_transaction.executor_fuel_remaining = state_transaction
        .executor_fuel_remaining
        .saturating_sub(report.gas_used);
    match report.verdict {
        Ok(()) => {
            if execute_multisig_custom_instruction_if_present(
                state_transaction,
                authority,
                &instruction,
            )? {
                return Ok(());
            }
            instruction
                .execute(authority, state_transaction)
                .map_err(|err| {
                    iroha_logger::debug!(
                        ?err,
                        %instruction_id,
                        authority = %authority,
                        "state application of executor-approved instruction failed"
                    );
                    ValidationFail::from(err)
                })
        }
        Err(e) => {
            iroha_logger::debug!(
                ?e,
                %instruction_id,
                authority = %authority,
                "executor validation rejected instruction"
            );
            Err(e)
        }
    }
}
fn execute_multisig_custom_instruction_if_present(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &InstructionBox,
) -> Result<bool, ValidationFail> {
    if instruction
        .as_any()
        .downcast_ref::<CustomInstruction>()
        .is_none()
    {
        return Ok(false);
    }
    let Ok(multisig) = MultisigInstructionBox::try_from(instruction) else {
        return Ok(false);
    };
    crate::smartcontracts::isi::multisig::execute_multisig_instruction(
        state_transaction,
        authority,
        multisig,
    )?;
    Ok(true)
}
fn extract_register_role(instruction: &InstructionBox) -> Option<Register<Role>> {
    let instr_any = instruction.as_any();
    if let Some(reg) = instr_any.downcast_ref::<Register<Role>>() {
        return Some(reg.clone());
    }
    if let Some(reg_box) = instr_any.downcast_ref::<RegisterBox>() {
        return match reg_box {
            RegisterBox::Role(reg) => Some(reg.clone()),
            _ => None,
        };
    }
    None
}
fn extract_unregister_role(instruction: &InstructionBox) -> Option<Unregister<Role>> {
    let instr_any = instruction.as_any();
    if let Some(unregister) = instr_any.downcast_ref::<Unregister<Role>>() {
        return Some(unregister.clone());
    }
    if let Some(unregister_box) = instr_any.downcast_ref::<UnregisterBox>() {
        return match unregister_box {
            UnregisterBox::Role(unregister) => Some(unregister.clone()),
            _ => None,
        };
    }
    None
}
fn extract_account_metadata_target(instruction: &InstructionBox) -> Option<AccountId> {
    instruction
        .as_any()
        .downcast_ref::<SetKeyValueBox>()
        .and_then(|set| match set {
            SetKeyValueBox::Account(set) => Some(set.object.clone()),
            _ => None,
        })
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::SetKeyValue<iroha_data_model::account::Account>>()
                .map(|set| set.object.clone())
        })
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<RemoveKeyValueBox>()
                .and_then(|rm| match rm {
                    RemoveKeyValueBox::Account(rm) => Some(rm.object.clone()),
                    _ => None,
                })
        })
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::RemoveKeyValue<iroha_data_model::account::Account>>()
                .map(|rm| rm.object.clone())
        })
}
fn extract_asset_definition_metadata_target(
    instruction: &InstructionBox,
) -> Option<AssetDefinitionId> {
    instruction
        .as_any()
        .downcast_ref::<SetKeyValueBox>()
        .and_then(|set| match set {
            SetKeyValueBox::AssetDefinition(set) => Some(set.object.clone()),
            _ => None,
        })
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<
                    iroha_data_model::isi::SetKeyValue<
                        iroha_data_model::asset::AssetDefinition,
                    >,
                >()
                .map(|set| set.object.clone())
        })
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<RemoveKeyValueBox>()
                .and_then(|remove| match remove {
                    RemoveKeyValueBox::AssetDefinition(remove) => Some(remove.object.clone()),
                    _ => None,
                })
        })
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<
                    iroha_data_model::isi::RemoveKeyValue<
                        iroha_data_model::asset::AssetDefinition,
                    >,
                >()
                .map(|remove| remove.object.clone())
        })
}
fn extract_mint_asset(instruction: &InstructionBox) -> Option<Mint<Quantity, Asset>> {
    let any = instruction.as_any();
    if let Some(mint) = any.downcast_ref::<Mint<Quantity, Asset>>() {
        return Some(mint.clone());
    }
    if let Some(mint) = any.downcast_ref::<MintBox>() {
        return match mint {
            MintBox::Asset(mint) => Some(mint.clone()),
            MintBox::TriggerRepetitions(_) => None,
        };
    }
    if !instruction_has_concrete_type::<Mint<Quantity, Asset>>(instruction) {
        return None;
    }
    let bytes = instruction.dyn_encode();
    iroha_panic_hook::catch_unwind_suppressed(|| {
        Mint::<Quantity, Asset>::decode(&mut bytes.as_slice()).ok()
    })
    .ok()
    .flatten()
}
fn extract_transfer_asset(
    instruction: &InstructionBox,
) -> Option<Transfer<Asset, Quantity, Account>> {
    let instr_any = instruction.as_any();
    if let Some(transfer) = instr_any.downcast_ref::<Transfer<Asset, Quantity, Account>>() {
        return Some(transfer.clone());
    }
    if let Some(transfer_box) = instr_any.downcast_ref::<TransferBox>() {
        return match transfer_box {
            TransferBox::Asset(transfer) => Some(transfer.clone()),
            _ => None,
        };
    }
    if !instruction_has_concrete_type::<Transfer<Asset, Quantity, Account>>(instruction) {
        return None;
    }
    let bytes = instruction.dyn_encode();
    iroha_panic_hook::catch_unwind_suppressed(|| {
        let mut slice = &bytes[..];
        Transfer::<Asset, Quantity, Account>::decode(&mut slice).ok()
    })
    .ok()
    .flatten()
}
fn extract_transfer_domain(
    instruction: &InstructionBox,
) -> Option<Transfer<Account, DomainId, Account>> {
    let instr_any = instruction.as_any();
    if let Some(transfer) = instr_any.downcast_ref::<Transfer<Account, DomainId, Account>>() {
        return Some(transfer.clone());
    }
    if let Some(transfer_box) = instr_any.downcast_ref::<TransferBox>() {
        return match transfer_box {
            TransferBox::Domain(transfer) => Some(transfer.clone()),
            _ => None,
        };
    }
    if !instruction_has_concrete_type::<Transfer<Account, DomainId, Account>>(instruction) {
        return None;
    }
    let bytes = instruction.dyn_encode();
    iroha_panic_hook::catch_unwind_suppressed(|| {
        let mut slice = &bytes[..];
        Transfer::<Account, DomainId, Account>::decode(&mut slice).ok()
    })
    .ok()
    .flatten()
}
fn extract_transfer_asset_definition(
    instruction: &InstructionBox,
) -> Option<Transfer<Account, AssetDefinitionId, Account>> {
    let instr_any = instruction.as_any();
    if let Some(transfer) =
        instr_any.downcast_ref::<Transfer<Account, AssetDefinitionId, Account>>()
    {
        return Some(transfer.clone());
    }
    if let Some(transfer_box) = instr_any.downcast_ref::<TransferBox>() {
        return match transfer_box {
            TransferBox::AssetDefinition(transfer) => Some(transfer.clone()),
            _ => None,
        };
    }
    if !instruction_has_concrete_type::<Transfer<Account, AssetDefinitionId, Account>>(instruction)
    {
        return None;
    }
    let bytes = instruction.dyn_encode();
    iroha_panic_hook::catch_unwind_suppressed(|| {
        let mut slice = &bytes[..];
        Transfer::<Account, AssetDefinitionId, Account>::decode(&mut slice).ok()
    })
    .ok()
    .flatten()
}
fn extract_transfer_nft(
    instruction: &InstructionBox,
) -> Option<Transfer<Account, iroha_data_model::NftId, Account>> {
    let instr_any = instruction.as_any();
    if let Some(transfer) =
        instr_any.downcast_ref::<Transfer<Account, iroha_data_model::NftId, Account>>()
    {
        return Some(transfer.clone());
    }
    if let Some(transfer_box) = instr_any.downcast_ref::<TransferBox>() {
        return match transfer_box {
            TransferBox::Nft(transfer) => Some(transfer.clone()),
            _ => None,
        };
    }
    if !instruction_has_concrete_type::<Transfer<Account, iroha_data_model::NftId, Account>>(
        instruction,
    ) {
        return None;
    }
    let bytes = instruction.dyn_encode();
    iroha_panic_hook::catch_unwind_suppressed(|| {
        let mut slice = &bytes[..];
        Transfer::<Account, iroha_data_model::NftId, Account>::decode(&mut slice).ok()
    })
    .ok()
    .flatten()
}
fn authority_has_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    target: &Permission,
) -> Result<bool, ValidationFail> {
    let permissions = world
        .account_permissions_iter(authority)
        .map_err(|err| ValidationFail::InstructionFailed(InstructionExecutionError::Find(err)))?;
    if permissions
        .into_iter()
        .any(|permission| permission == target)
    {
        return Ok(true);
    }
    for role_id in world.account_roles_iter(authority) {
        if let Some(role) = world.roles().get(role_id)
            && role.permissions.contains(target)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn authority_has_direct_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    target: &Permission,
) -> Result<bool, ValidationFail> {
    world
        .account_permissions_iter(authority)
        .map_err(|err| ValidationFail::InstructionFailed(InstructionExecutionError::Find(err)))
        .map(|permissions| {
            permissions
                .into_iter()
                .any(|permission| permission == target)
        })
}
fn authority_has_role(world: &impl WorldReadOnly, authority: &AccountId, role_id: &RoleId) -> bool {
    world
        .account_roles_iter(authority)
        .any(|assigned| assigned == role_id)
}
const INITIAL_GENESIS_ONLY_PERMISSION_NAMES: &[&str] = &[
    "CanManagePeers",
    "CanRegisterDomain",
    "CanManageRoles",
    "CanUpgradeExecutor",
    "CanGrantSmartContractCodeManagement",
    "CanReadAllLedgerData",
    "CanReadRestrictedDataspace",
    "CanManageFxCorridors",
    "CanProposeSccpRouteGovernance",
];
include!("executor_initial_permission_authority.rs");
fn is_builtin_initial_permission_name(permission_name: &str) -> bool {
    INITIAL_EXECUTOR_PERMISSION_NAMES.contains(&permission_name)
}
/// Return the `Register<AssetDefinition>` carried by `instruction`, whether it is typed,
/// wrapped in a [`RegisterBox`], or an encoded instruction of that concrete type.
pub(crate) fn extract_register_asset_definition(
    instruction: &InstructionBox,
) -> Option<Register<AssetDefinition>> {
    let instr_any = instruction.as_any();
    if let Some(reg) = instr_any.downcast_ref::<Register<AssetDefinition>>() {
        return Some(reg.clone());
    }
    if let Some(reg_box) = instr_any.downcast_ref::<RegisterBox>() {
        return match reg_box {
            RegisterBox::AssetDefinition(reg) => Some(reg.clone()),
            _ => None,
        };
    }
    if !instruction_has_concrete_type::<Register<AssetDefinition>>(instruction) {
        return None;
    }
    let bytes = instruction.dyn_encode();
    iroha_panic_hook::catch_unwind_suppressed(|| {
        let mut slice = &bytes[..];
        Register::<AssetDefinition>::decode(&mut slice).ok()
    })
    .ok()
    .flatten()
}
/// Extract only the distinct direct-dataspace registration wire instruction.
pub(crate) fn extract_register_dataspace_asset_definition(
    instruction: &InstructionBox,
) -> Option<iroha_data_model::isi::RegisterDataspaceAssetDefinition> {
    use iroha_data_model::isi::RegisterDataspaceAssetDefinition;
    if let Some(reg) = instruction
        .as_any()
        .downcast_ref::<RegisterDataspaceAssetDefinition>()
    {
        return Some(reg.clone());
    }
    if !instruction_has_concrete_type::<RegisterDataspaceAssetDefinition>(instruction) {
        return None;
    }
    let bytes = instruction.dyn_encode();
    iroha_panic_hook::catch_unwind_suppressed(|| {
        RegisterDataspaceAssetDefinition::decode(&mut &bytes[..]).ok()
    })
    .ok()
    .flatten()
}
/// Authorize registration against the signed owning domain and its current owner.
/// Domainless definitions are restricted to the authenticated genesis context;
/// optional aliases never supply registration authority.
pub(crate) fn ensure_asset_definition_registration_allowed(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    reg_asset_definition: &Register<AssetDefinition>,
) -> Result<(), ValidationFail> {
    let is_genesis_context = is_initial_genesis_context(state_transaction)
        && state_transaction
            .world
            .domain(&iroha_genesis::GENESIS_DOMAIN_ID)
            .is_ok();
    if is_genesis_context {
        return Ok(());
    }
    // Ownership is an explicit signed field. Optional display aliases cannot grant
    // registration authority or replace the canonical owning-domain binding.
    let Some(domain_id) = reg_asset_definition.object().owning_domain.as_ref() else {
        return Err(ValidationFail::NotPermitted(
            "domainless asset definitions may only be registered in genesis".to_owned(),
        ));
    };
    let domain_owner = state_transaction
        .world
        .domain(domain_id)
        .map(|domain| domain.owned_by().clone())
        .map_err(|err| ValidationFail::InstructionFailed(InstructionExecutionError::Find(err)))?;
    if &domain_owner == authority {
        return Ok(());
    }
    Err(ValidationFail::NotPermitted(
        "Can't register asset definition".to_owned(),
    ))
}
#[cfg(test)]
#[path = "executor_runtime_memory_tests.rs"]
mod runtime_memory_tests;

#[cfg(test)]
#[path = "executor_public_pin_admission_tests.rs"]
mod public_pin_admission_tests;

#[cfg(test)]
#[path = "executor_opaque_monetary_tests.rs"]
mod opaque_monetary_tests;

#[cfg(test)]
#[path = "executor_opaque_sccp_record_tests.rs"]
mod opaque_sccp_record_tests;

#[cfg(test)]
fn executor_test_budget() -> iroha_allocation::AllocationBudget {
    thread_local! {
        static BUDGET: iroha_allocation::AllocationBudget =
            iroha_allocation::AllocationBudget::new(512 * 1024 * 1024);
    }
    BUDGET.with(Clone::clone)
}

/// [`Executor`] with cached [`IVM`] for execution.
#[derive(Debug, Clone)]
#[debug("LoadedExecutor {{ runtime: <IVM> }}")]
pub struct LoadedExecutor {
    runtime_pool: Arc<Mutex<ExecutorRuntimePool>>,
    _pool_memory: Arc<ivm::cache_memory::MemoryReservation>,
    _eviction: ivm::cache_memory::CacheEvictionRegistration,
    /// Sharing immutable bytecode makes executor clones cheap.
    /// See [`crate::tx::TransactionExecutor::validate_with_runtime_executor`].
    raw_executor: ivm::cache_memory::SharedValue<data_model_executor::Executor>,
}
// Stack sizing and the governed heap ceiling define distinct VM memory
// authorities. Keep a small bounded LRU so adversarial governance/gas
// variation cannot retain an unbounded number of complete memory images and
// Merkle baselines.
const EXECUTOR_RUNTIME_VARIANT_CAPACITY: usize = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ExecutorRuntimeKey {
    stack_limit: u64,
    heap_limit: u64,
}
impl ExecutorRuntimeKey {
    fn for_limits(gas_limit: u64, heap_limit: u64) -> Self {
        // The exact gas limit is replenished on every checkout. Keying by it
        // would create distinct variants with identical memory layouts.
        Self {
            stack_limit: stack_limit_for_gas(gas_limit),
            heap_limit,
        }
    }
}
struct ExecutorRuntimeVariant {
    identity: ivm::cache_memory::SharedValue<()>,
    available: Option<(RuntimeTemplate, IVM)>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ExecutorRuntimePoolStats {
    hits: u64,
    misses: u64,
    program_loads: u64,
    template_builds: u64,
    dirty_resets: u64,
    evictions: u64,
}
#[derive(Clone, Copy)]
enum ExecutorRuntimePoolEvent {
    Hit,
    Miss,
    ProgramLoad,
    TemplateBuild,
    DirtyReset,
    Eviction,
}
struct ExecutorRuntimePool {
    // Bound once to the first State owner. Foreign State clones execute uncached.
    execution_budget: Option<iroha_allocation::AllocationBudget>,
    variants: BTreeMap<ExecutorRuntimeKey, ExecutorRuntimeVariant>,
    order: VecDeque<ExecutorRuntimeKey>,
    capacity: usize,
    #[cfg(test)]
    stats: ExecutorRuntimePoolStats,
    // Release aggregate charges after every owned allocation above is destroyed.
    index_memory: ivm::cache_memory::MemoryReservation,
}
impl ExecutorRuntimePool {
    fn new(capacity: usize) -> Self {
        Self {
            execution_budget: None,
            index_memory: ivm::cache_memory::MemoryReservation::active(0),
            variants: BTreeMap::new(),
            order: VecDeque::new(),
            capacity,
            #[cfg(test)]
            stats: ExecutorRuntimePoolStats::default(),
        }
    }
    fn clear_storage(&mut self) {
        #[cfg(test)]
        {
            self.stats.evictions = self
                .stats
                .evictions
                .saturating_add(self.variants.len() as u64);
        }
        self.variants = BTreeMap::new();
        self.order = VecDeque::new();
        self.index_memory.set_known_bytes(0);
    }
    fn retain_index_or_clear(&mut self) {
        let bytes = norito::core::owned_btree_allocation_bytes::<
            ExecutorRuntimeKey,
            ExecutorRuntimeVariant,
        >(self.variants.len())
        .ok()
        .and_then(|bytes| {
            bytes.checked_add(
                self.order
                    .capacity()
                    .checked_mul(core::mem::size_of::<ExecutorRuntimeKey>())?,
            )
        });
        let Some(bytes) = bytes else {
            self.clear_storage();
            return;
        };
        // BTree removal may retain spare nodes. Preserve the high-water charge
        // until clear_storage drops the original container allocation.
        self.index_memory
            .set_known_bytes(bytes.max(self.index_memory.bytes()));
        if !self.index_memory.try_retain() {
            self.clear_storage();
        }
    }
    fn record(&mut self, event: ExecutorRuntimePoolEvent) {
        #[cfg(test)]
        match event {
            ExecutorRuntimePoolEvent::Hit => {
                self.stats.hits = self.stats.hits.saturating_add(1);
            }
            ExecutorRuntimePoolEvent::Miss => {
                self.stats.misses = self.stats.misses.saturating_add(1);
            }
            ExecutorRuntimePoolEvent::ProgramLoad => {
                self.stats.program_loads = self.stats.program_loads.saturating_add(1);
            }
            ExecutorRuntimePoolEvent::TemplateBuild => {
                self.stats.template_builds = self.stats.template_builds.saturating_add(1);
            }
            ExecutorRuntimePoolEvent::DirtyReset => {
                self.stats.dirty_resets = self.stats.dirty_resets.saturating_add(1);
            }
            ExecutorRuntimePoolEvent::Eviction => {
                self.stats.evictions = self.stats.evictions.saturating_add(1);
            }
        }
        #[cfg(not(test))]
        let _ = event;
    }
    // Move at most one original idle owner out for destruction after unlocking. Keep
    // its bounded key/identity row: active borrowers and the index high-water charge
    // are independent owners and are never reclaimed by this retention retry.
    fn take_idle_runtime_for_retention(
        &mut self,
        returning_key: ExecutorRuntimeKey,
        returning_identity: &ivm::cache_memory::SharedValue<()>,
    ) -> Option<(RuntimeTemplate, IVM)> {
        let returning = self.variants.get(&returning_key)?;
        if !ivm::cache_memory::SharedValue::ptr_eq(&returning.identity, returning_identity)
            || returning.available.is_some()
        {
            return None;
        }
        let idle_key = self.order.iter().copied().find(|key| {
            *key != returning_key
                && self
                    .variants
                    .get(key)
                    .is_some_and(|variant| variant.available.is_some())
        })?;
        let idle = self.variants.get_mut(&idle_key)?.available.take()?;
        self.record(ExecutorRuntimePoolEvent::Eviction);
        Some(idle)
    }
    fn touch(&mut self, key: ExecutorRuntimeKey) {
        if let Some(position) = self.order.iter().position(|candidate| *candidate == key) {
            self.order.remove(position);
        }
        self.order.push_back(key);
    }
    fn insert_variant(&mut self, key: ExecutorRuntimeKey) -> ivm::cache_memory::SharedValue<()> {
        while self.variants.len() >= self.capacity {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            if self.variants.remove(&evicted).is_some() {
                self.record(ExecutorRuntimePoolEvent::Eviction);
            }
        }
        let identity = ivm::cache_memory::SharedValue::new((), Some(0));
        if self.capacity == 0 || !identity.try_retain() {
            return identity;
        }
        self.variants.insert(
            key,
            ExecutorRuntimeVariant {
                identity: identity.clone(),
                available: None,
            },
        );
        self.touch(key);
        self.retain_index_or_clear();
        identity
    }
}
/// The actual pool guard determines refund custody; equal limits are not pool identity.
/// Every guard drops inside its original scope, including on unwind. State writers
/// retain the enclosing same-pool notifications through their existing refund owner.
fn with_executor_runtime_pool<R>(
    pool: &Mutex<ExecutorRuntimePool>,
    operation: impl FnOnce(&mut ExecutorRuntimePool) -> R,
) -> R {
    let mut guard = pool.lock().unwrap_or_else(|error| error.into_inner());
    let budget = guard.execution_budget.clone();
    let run = move || operation(&mut guard);
    match budget {
        Some(budget) => budget.with_deferred_refund_notifications(move |_| run()),
        None => run(),
    }
}

struct ExecutorRuntimeLease {
    pool: Arc<Mutex<ExecutorRuntimePool>>,
    _pool_memory: Arc<ivm::cache_memory::MemoryReservation>,
    key: ExecutorRuntimeKey,
    variant_identity: Option<ivm::cache_memory::SharedValue<()>>,
    execution_budget: iroha_allocation::AllocationBudget,
    baseline: RuntimeTemplate,
    vm: Option<IVM>,
}
impl Deref for ExecutorRuntimeLease {
    type Target = IVM;
    fn deref(&self) -> &Self::Target {
        self.vm
            .as_ref()
            .expect("executor runtime lease always owns a VM")
    }
}
impl DerefMut for ExecutorRuntimeLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.vm
            .as_mut()
            .expect("executor runtime lease always owns a VM")
    }
}
impl Drop for ExecutorRuntimeLease {
    fn drop(&mut self) {
        let Some(vm) = self.vm.take() else {
            return;
        };
        // The VM moves into the scope before any path can destroy it. The baseline
        // field's later final release also occurs outside every physical pool guard.
        let budget = self.execution_budget.clone();
        budget.with_deferred_refund_notifications(move |_| self.return_runtime(vm));
    }
}
impl ExecutorRuntimeLease {
    fn return_runtime(&self, mut vm: IVM) {
        let Some(identity) = self.variant_identity.as_ref() else {
            return;
        };
        let (can_return, mut idle_reclaims_left) = with_executor_runtime_pool(&self.pool, |pool| {
            (
                pool.variants.get(&self.key).is_some_and(|variant| {
                    ivm::cache_memory::SharedValue::ptr_eq(&variant.identity, identity)
                        && variant.available.is_none()
                }),
                pool.capacity,
            )
        });
        if !can_return || vm.reset_from_runtime_template(&self.baseline).is_err() {
            return;
        }
        while !self.baseline.try_retain_cache_allocations() || !vm.try_retain_cache_allocations() {
            if idle_reclaims_left == 0 {
                return;
            }
            idle_reclaims_left -= 1;
            let idle = with_executor_runtime_pool(&self.pool, |pool| {
                pool.take_idle_runtime_for_retention(self.key, identity)
            });
            let Some(idle) = idle else {
                return;
            };
            drop(idle);
        }
        with_executor_runtime_pool(&self.pool, move |pool| {
            let stored = pool.variants.get_mut(&self.key).is_some_and(|variant| {
                if !ivm::cache_memory::SharedValue::ptr_eq(&variant.identity, identity)
                    || variant.available.is_some()
                {
                    return false;
                }
                variant.available = Some((self.baseline.clone(), vm));
                true
            });
            if stored {
                pool.record(ExecutorRuntimePoolEvent::DirtyReset);
                pool.touch(self.key);
                pool.retain_index_or_clear();
            }
        });
    }
}
fn stack_limit_for_gas(gas_limit: u64) -> u64 {
    IvmConfig::new(gas_limit).stack_limit_for_gas()
}
impl LoadedExecutor {
    pub(crate) fn load(raw_executor: data_model_executor::Executor) -> Result<Self, VMError> {
        // Restore validates the same static image as load_program, but has no State
        // resource owner yet. Mutable runtimes are funded only at live checkout.
        IVM::validate_program(raw_executor.bytecode().as_ref())?;
        // Normalize caller spare Vec capacity, then charge the actual owned Vec.
        let bytecode = raw_executor.bytecode().as_ref().to_vec();
        let bytecode_capacity = bytecode.capacity();
        let raw_executor = ivm::cache_memory::SharedValue::new(
            data_model_executor::Executor::new(
                iroha_data_model::transaction::IvmBytecode::from_compiled(bytecode),
            ),
            Some(bytecode_capacity),
        );
        let runtime_pool = Arc::new(Mutex::new(ExecutorRuntimePool::new(
            EXECUTOR_RUNTIME_VARIANT_CAPACITY,
        )));
        let pool_memory = Arc::new(ivm::cache_memory::MemoryReservation::active(
            norito::core::owned_arc_allocation_bytes::<Mutex<ExecutorRuntimePool>>()
                .expect("executor pool fits")
                + norito::core::owned_arc_allocation_bytes::<ivm::cache_memory::MemoryReservation>(
                )
                .expect("pool accounting fits"),
        ));
        struct PoolControl {
            weak: std::sync::Weak<Mutex<ExecutorRuntimePool>>,
            _memory: Arc<ivm::cache_memory::MemoryReservation>,
        }
        impl PoolControl {
            fn clear(&self) {
                if let Some(pool) = self.weak.upgrade() {
                    with_executor_runtime_pool(&pool, ExecutorRuntimePool::clear_storage);
                }
            }
        }
        let control = PoolControl {
            weak: Arc::downgrade(&runtime_pool),
            _memory: Arc::clone(&pool_memory),
        };
        let eviction = ivm::cache_memory::register_cache_evictor(move || control.clear());
        Ok(Self {
            runtime_pool,
            _pool_memory: pool_memory,
            _eviction: eviction,
            raw_executor,
        })
    }
    fn load_runtime(
        raw_executor: &data_model_executor::Executor,
        gas_limit: u64,
        heap_limit: u64,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<IVM, VMError> {
        let mut vm = IVM::try_new_with_memory_budget(gas_limit, budget)?;
        vm.memory.set_heap_max_limit(heap_limit)?;
        vm.load_program(raw_executor.bytecode().as_ref())?;
        vm.set_gas_limit(gas_limit);
        Ok(vm)
    }
    fn checkout_runtime_for_gas_limit(
        &self,
        gas_limit: u64,
        heap_limit: u64,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<ExecutorRuntimeLease, VMError> {
        let key = ExecutorRuntimeKey::for_limits(gas_limit, heap_limit);
        let (variant_identity, runtime) = with_executor_runtime_pool(&self.runtime_pool, |pool| {
            let original = pool.execution_budget.get_or_insert_with(|| budget.clone());
            if !original.same_pool(budget) {
                // Cloned Worlds can belong to different States. Do not transfer a
                // retained image's original credit, or evict it beneath foreign writers.
                return (None, None);
            }
            if let Some(variant) = pool.variants.get_mut(&key) {
                let identity = variant.identity.clone();
                let runtime = variant.available.take();
                pool.record(if runtime.is_some() {
                    ExecutorRuntimePoolEvent::Hit
                } else {
                    ExecutorRuntimePoolEvent::Miss
                });
                pool.touch(key);
                (Some(identity), runtime)
            } else {
                pool.record(ExecutorRuntimePoolEvent::Miss);
                (Some(pool.insert_variant(key)), None)
            }
        });
        // Admission never waits or holds a pool lock. Each new baseline reserves
        // its complete clone demand from this same VM budget before allocation.
        let (baseline, mut vm) = if let Some(runtime) = runtime {
            runtime
        } else {
            let mut vm = Self::load_runtime(&self.raw_executor, gas_limit, heap_limit, budget)?;
            let baseline = vm.try_runtime_template()?;
            if variant_identity.is_some() {
                with_executor_runtime_pool(&self.runtime_pool, |pool| {
                    pool.record(ExecutorRuntimePoolEvent::ProgramLoad);
                    pool.record(ExecutorRuntimePoolEvent::TemplateBuild);
                });
            }
            (baseline, vm)
        };
        vm.activate_cached_runtime();
        vm.set_gas_limit(gas_limit);
        Ok(ExecutorRuntimeLease {
            pool: Arc::clone(&self.runtime_pool),
            _pool_memory: Arc::clone(&self._pool_memory),
            key,
            variant_identity,
            execution_budget: budget.clone(),
            baseline,
            vm: Some(vm),
        })
    }
    #[cfg(test)]
    fn runtime_pool_snapshot(&self) -> (ExecutorRuntimePoolStats, usize) {
        let pool = self
            .runtime_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        (pool.stats, pool.variants.len())
    }
    #[cfg(test)]
    fn runtime_variant_capacity(&self) -> usize {
        self.runtime_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .capacity
    }
}
/// Norito encode/decode helpers for the runtime `Executor`.
///
/// These helpers serialize the core `Executor` enum into a compact Norito payload using a local DTO
/// and provide a materialization path that loads a `LoadedExecutor` when required.
pub mod executor_norito {
    use super::*;
    /// Local DTO used for Norito encoding of `Executor`.
    #[derive(Encode, Decode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_core::executor::executor_norito::ExecutorDto")]
    enum ExecutorDto {
        Initial,
        UserProvided(iroha_data_model::executor::Executor),
    }
    /// Serialize the given `Executor` to Norito bytes.
    /// Serialize an [`Executor`] into Norito-encoded bytes.
    ///
    /// # Errors
    /// Returns an error if Norito encoding fails for the provided executor variant.
    pub fn to_bytes(executor: &Executor) -> Result<Vec<u8>, norito::core::Error> {
        let dto = match executor {
            Executor::Initial => ExecutorDto::Initial,
            Executor::UserProvided(le) => {
                // Serialize the raw executor (data_model)
                ExecutorDto::UserProvided((*le.raw_executor).clone())
            }
        };
        norito::to_bytes(&dto)
    }
    /// Hash the executor's borrowed semantic payload for the private World delta.
    /// Loaded VM variants, caches and pool history are not State values.
    pub(crate) fn net_state_hash(executor: &Executor) -> Result<iroha_crypto::Hash, String> {
        const DOMAIN: &[u8] = b"iroha:world-net-delta:executor:v1\0";
        match executor {
            Executor::Initial => Ok(iroha_crypto::Hash::new_from_chunks(&[DOMAIN, &[0]])),
            Executor::UserProvided(loaded) => {
                let raw = crate::state::world_projection::hash_value(&*loaded.raw_executor)?;
                Ok(iroha_crypto::Hash::new_from_chunks(&[
                    DOMAIN,
                    &[1],
                    raw.as_ref(),
                ]))
            }
        }
    }

    /// Deserialize Norito bytes into a materialized `Executor`.
    ///
    /// For `UserProvided` DTO, loads the IVM program to construct a `LoadedExecutor`.
    /// Deserialize an [`Executor`] from Norito-encoded bytes.
    ///
    /// # Errors
    /// Returns an error if the byte slice does not represent a valid executor value.
    pub fn from_bytes(bytes: &[u8]) -> Result<Executor, String> {
        let decoded =
            iroha_panic_hook::catch_unwind_suppressed(|| norito::decode_from_bytes(bytes))
                .map_err(|_| "executor decode failed: panic during Norito decode".to_owned())?;
        let dto: ExecutorDto = decoded.map_err(|e| format!("executor decode failed: {e}"))?;
        match dto {
            ExecutorDto::Initial => Ok(Executor::Initial),
            ExecutorDto::UserProvided(raw) => LoadedExecutor::load(raw)
                .map(Executor::UserProvided)
                .map_err(|e| format!("executor load failed: {e}")),
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn initial_roundtrip() {
            let exec = Executor::Initial;
            let bytes = to_bytes(&exec).expect("encode");
            assert_eq!(
                <ExecutorDto as norito::NoritoSchema>::nominal_name(),
                "iroha_core::executor::executor_norito::ExecutorDto"
            );
            assert_eq!(
                bytes[6..22],
                norito::schema::identity::frame_hash::<ExecutorDto>()
            );
            assert!(matches!(
                norito::decode_canonical::<ExecutorDto>(&bytes).expect("DTO frame"),
                ExecutorDto::Initial
            ));
            let mut substituted = bytes.clone();
            substituted[6] ^= 1;
            assert!(matches!(
                norito::decode_canonical::<ExecutorDto>(&substituted),
                Err(norito::Error::SchemaMismatch)
            ));
            assert!(from_bytes(&substituted).is_err());
            assert!(from_bytes(&bytes[..bytes.len() - 1]).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(from_bytes(&trailing).is_err());
            let dec = from_bytes(&bytes).expect("decode");
            assert_eq!(
                to_bytes(&dec).expect("materialized executor re-encodes"),
                bytes
            );
            match dec {
                Executor::Initial => {}
                _ => panic!("expected Initial variant"),
            }
        }
        #[test]
        fn net_state_hash_binds_raw_executor_and_ignores_loaded_runtime_cache() {
            let first = denying_executor_for_testing("projection one");
            let same = denying_executor_for_testing("projection one");
            let other = denying_executor_for_testing("projection two");
            let expected = net_state_hash(&first).unwrap();
            assert_eq!(expected, net_state_hash(&same).unwrap());
            assert_ne!(expected, net_state_hash(&other).unwrap());
            assert_ne!(expected, net_state_hash(&Executor::Initial).unwrap());
            let Executor::UserProvided(loaded) = &first else {
                panic!("fixture must load its actual executor");
            };
            let parameters = iroha_data_model::parameter::SmartContractParameters::default();
            let before = loaded.runtime_pool_snapshot();
            {
                let _lease = loaded
                    .checkout_runtime_for_gas_limit(
                        parameters.fuel().get(),
                        parameters.memory().get(),
                        &executor_test_budget(),
                    )
                    .unwrap();
                assert_eq!(expected, net_state_hash(&first).unwrap());
            }
            assert_ne!(
                before,
                loaded.runtime_pool_snapshot(),
                "actual runtime pool changed"
            );
            assert_eq!(expected, net_state_hash(&first).unwrap());
        }

        #[test]
        fn userprovided_encodes_but_load_may_fail() {
            // Construct a dummy data-model executor with some bytecode; loading may fail,
            // but encoding itself should succeed.
            let raw = iroha_data_model::executor::Executor::new(
                iroha_data_model::transaction::IvmBytecode::from_compiled(vec![0x00, 0x01, 0x02]),
            );
            let bytes = norito::to_bytes(&ExecutorDto::UserProvided(raw)).expect("encode dto");
            // Decoding to materialized `Executor` may fail due to invalid bytecode; assert the error is surfaced.
            let res = from_bytes(&bytes);
            assert!(res.is_err());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query,
        state::{State, World},
    };
    #[cfg(feature = "telemetry")]
    use iroha_config::parameters::actual::{GasLiquidity, GasVolatility};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_data_model::{
        asset::{
            ASSET_TRANSFER_CONTROL_METADATA_KEY, AssetTransferAvailability,
            AssetTransferControlRecord, AssetTransferControlStoreV1, AssetTransferControlWindow,
        },
        events::data::prelude::{AssetBatchTransferLegStatus, AssetBatchTransferRejectionCode},
        executor::{self as data_model_executor, ExecutorDataModel},
        isi::{
            Grant, SetAssetTransferAvailability, SetAssetTransferControl,
            transfer::{TransferAssetBatch, TransferAssetBatchEntry},
        },
        parameter::{CustomParameter, CustomParameterId},
        prelude::*,
        query::{QueryRequest, SingularQueryBox, prelude::FindParameters},
        smart_contract::{ContractAddress, ContractEmergencyHoldV1},
        transaction::executable::IvmBytecode,
    };
    use iroha_executor_data_model::isi::multisig::{
        MultisigApprove, MultisigCancel, MultisigPropose, MultisigRegister, MultisigSpec,
    };
    use iroha_model_base::name::Name;
    use iroha_model_base::{chain::ChainId, peer::PeerId};
    use iroha_primitives::json::Json;
    use iroha_test_samples::{
        ALICE_ID, ALICE_KEYPAIR, BOB_ID, SAMPLE_GENESIS_ACCOUNT_ID, gen_account_in,
    };
    use mv::storage::StorageReadOnly;
    use nonzero_ext::nonzero;
    #[test]
    fn multisig_role_namespace_reservation_is_process_independent() {
        for name in [
            "MULTISIG_SIGNATORY",
            "MULTISIG_SIGNATORY/domain/address",
            "MULTISIG_SIGNATORY//opaque",
        ] {
            let role_id: RoleId = name.parse().expect("valid reserved role id");
            assert!(
                is_reserved_multisig_role_id(&role_id),
                "must reserve {name}"
            );
        }
        for name in [
            "MULTISIG_SIGNATORY_ADJACENT",
            "MULTISIG_SIGNATORY2/domain/address",
            "ordinary-role",
        ] {
            let role_id: RoleId = name.parse().expect("valid ordinary role id");
            assert!(
                !is_reserved_multisig_role_id(&role_id),
                "must not reserve {name}"
            );
        }
    }
    #[test]
    fn executor_byte_array_accepts_maximum_byte() {
        let value = json::Value::Array(vec![json::Value::from(u64::from(u8::MAX))]);
        let decoded = decode_executor_bytes(value, "norito").expect("decode byte array");
        assert_eq!(decoded, vec![u8::MAX]);
    }
    #[test]
    fn executor_byte_array_rejects_byte_overflow() {
        let value = json::Value::Array(vec![json::Value::from(u64::from(u8::MAX) + 1)]);
        let error = decode_executor_bytes(value, "norito").expect_err("reject byte overflow");
        match error {
            json::Error::InvalidField { field, message } => {
                assert_eq!(field, "norito");
                assert_eq!(message, "expected byte in range 0..=255");
            }
            other => panic!("unexpected error: {other}"),
        }
    }
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("executor fixture key generation should succeed")
    }
    fn executor_test_network_id(seed: &[u8]) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            seed,
        )))
    }
    fn state_for_testing(world: World) -> State {
        // These component fixtures execute on an explicitly committed global root.
        let mut parameters = world.parameters.block();
        parameters.set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ));
        parameters.commit();
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            query::store::LiveQueryStore::start_test(),
        )
    }
    /// Structural post-genesis fixture with an explicit committed Global root.
    /// This metadata grants no authenticated genesis or block-publication capability.
    fn component_world_for_testing(world: World) -> World {
        let mut parameters = world.parameters.block();
        assert!(
            !parameters.custom().contains_key(
                &iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id()
            ),
            "component root must be selected before State construction"
        );
        parameters.set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ));
        parameters.commit();
        world
    }
    fn component_state_for_testing(world: World) -> State {
        state_for_testing(component_world_for_testing(world))
    }
    /// Seed canonical contract storage for an ordinary component fixture after real genesis.
    /// This changes only its fixture World; it does not grant root scope or publication authority.
    fn bind_executor_test_contract_after_genesis(
        state: &State,
        address: &ContractAddress,
        owner: &AccountId,
        code_hash: Hash,
    ) {
        let mut world = state.world.block();
        world.accounts.insert(
            address.subject_id(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        world.contract_instances.insert(address.clone(), code_hash);
        world
            .contract_subject_addresses
            .insert(address.subject_id(), address.clone());
        world.contract_subject_bindings.insert(
            address.clone(),
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(address, owner.clone())
                .with_active_code_hash(code_hash),
        );
        world.commit();
    }

    #[test]
    fn ordinary_contract_fixture_retains_authenticated_genesis_identity() {
        let owner = ALICE_ID.clone();
        let state = state_after_genesis(World::with(
            [],
            [Account::new(owner.clone()).build(&owner)],
            [],
        ));
        let parent = state.view().latest_block_hash().unwrap();
        let root =
            crate::sumeragi::lanes::routing::committed_root_scope(state.view().world()).unwrap();
        let address =
            ContractAddress::derive(&state.network_id, &owner, 501, DataSpaceId::UNIVERSAL)
                .unwrap();
        let code_hash = Hash::new(b"ordinary-contract-fixture-identity");
        bind_executor_test_contract_after_genesis(&state, &address, &owner, code_hash);
        let view = state.view();
        assert_eq!(state.committed_height(), 1);
        assert_eq!(view.latest_block_hash(), Some(parent));
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(view.world()),
            Some(root)
        );
        assert_eq!(
            view.world().contract_instances.get(&address),
            Some(&code_hash)
        );
        assert_eq!(
            view.world()
                .contract_subject_addresses
                .get(&address.subject_id()),
            Some(&address)
        );
        assert!(view.world().account(&address.subject_id()).is_ok());
    }

    fn state_after_genesis(world: World) -> State {
        state_after_genesis_with_instructions(world, |_| Vec::new())
    }

    fn state_after_genesis_with_instructions(
        world: World,
        instructions: impl FnOnce(&AccountId) -> Vec<InstructionBox>,
    ) -> State {
        use crate::sumeragi::{
            startup,
            test_chain::{CertifiedTestChain, TestChainConfig},
        };

        let mut config = TestChainConfig::new(world, 0);
        let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
        config.genesis_instructions = instructions(&genesis_account);
        let consensus_mode = config.consensus_mode;
        let prepared =
            CertifiedTestChain::prepare(config).expect("prepare signed executor genesis");
        // Preparation has not spawned a StateExecutor. Consume the original unique
        // State, then apply its actual signed genesis without copying root metadata.
        let state = Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished executor State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &genesis_account,
            consensus_mode.into(),
            None,
        )
        .expect("apply signed executor genesis");
        state
    }

    #[test]
    fn post_genesis_fixture_retains_original_world_and_authenticated_root() {
        let marker: Name = "executor_fixture_original".parse().unwrap();
        let mut metadata = Metadata::default();
        metadata.insert(marker.clone(), Json::new(true));
        let world = World::with(
            [],
            [Account::new(ALICE_ID.clone())
                .with_metadata(metadata)
                .build(&ALICE_ID)],
            [],
        );
        let state = state_after_genesis(world);
        assert_eq!(state.committed_height(), 1);
        assert_eq!(state.kura().blocks_count(), 1);
        let genesis = state
            .kura()
            .get_block(nonzero!(1_usize), &state.ivm_execution_budget())
            .expect("completed original State read")
            .unwrap();
        assert_eq!(
            state.network_id_ref(),
            &NetworkId::from_genesis_hash(genesis.hash())
        );
        let signed =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&genesis)
                .unwrap();
        let view = state.view();
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(view.world()),
            Some(signed.sumeragi_context.root_scope)
        );
        assert_eq!(
            view.world()
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&marker),
            Some(&Json::new(true))
        );

        // Refusal fixtures remain genuinely pre-genesis, with no routing authority.
        let pristine = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            query::store::LiveQueryStore::start_test(),
        );
        assert_eq!(pristine.committed_height(), 0);
        assert_eq!(pristine.kura().blocks_count(), 0);
        assert!(
            crate::sumeragi::lanes::routing::committed_root_scope(pristine.view().world())
                .is_none()
        );
    }
    #[test]
    fn rejected_standalone_ballot_records_equal_gas_for_instruction_and_batch_carriers() {
        let ballot = InstructionBox::from(iroha_data_model::isi::governance::CastZkBallot {
            election_id: "gas.parity.v1".to_owned(),
            proof_b64: "AA==".to_owned(),
            public_inputs_json: "{}".to_owned(),
        });
        let expected_gas = isi_gas::meter_instructions(core::slice::from_ref(&ballot));
        assert!(expected_gas > 0);
        let execute_rejected = |executable: Executable| {
            let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
            let state = state_after_genesis(World::with([], [account], []));
            let signed = TransactionBuilder::new(
                *state.network_id_ref(),
                ALICE_ID.clone(),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_executable(executable)
            .sign(ALICE_KEYPAIR.private_key());
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                Some(
                    state
                        .view()
                        .latest_block_hash()
                        .expect("genuine genesis parent"),
                ),
                None,
                0,
                0,
            ));
            let mut transaction =
                block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
            transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let mut cache = IvmCache::new();
            crate::executor::Executor::Initial
                .execute_transaction(&mut transaction, &ALICE_ID, signed, &mut cache)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("an unpermitted ballot must reject");
            transaction.last_tx_gas_used
        };
        let instructions_gas =
            execute_rejected(Executable::Instructions(vec![ballot.clone()].into()));
        let batch_gas = execute_rejected(Executable::Batch(
            vec![ExecutableBatchItem::Instruction(ballot)].into(),
        ));
        assert_eq!(instructions_gas, expected_gas);
        assert_eq!(batch_gas, expected_gas);
    }
    #[test]
    fn successful_live_batch_settlement_retains_nested_execute_trigger_ivm_gas() {
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let state = state_after_genesis(World::with([], [account], []));
        let trigger_id: TriggerId = "live_batch_ivm_gas".parse().expect("trigger id");
        let mut program = ivm::ProgramMetadata {
            max_cycles: 100,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        program.extend_from_slice(
            &ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 1, 0, 1)
                .to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::Ivm(IvmBytecode::from_compiled(program)),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(ALICE_ID.clone()),
            )
            .expect("valid generic IVM trigger action"),
        );
        let mut setup_block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        {
            let mut setup_tx = setup_block.transaction_for_callback_testing();
            Register::trigger(trigger)
                .execute(&ALICE_ID, &mut setup_tx)
                .expect("register generic IVM trigger");
            setup_tx
                .apply_callback_for_testing()
                .expect("capture successful component callbacks");
        }
        setup_block
            .commit_world_overlay_for_testing()
            .expect("commit trigger fixture");

        let mut block = state.block(BlockHeader::new(
            nonzero!(3_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let nested_ivm_gas = {
            let mut baseline_tx = block.transaction_for_callback_testing();
            baseline_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            baseline_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            baseline_tx
                .execute_called_trigger(
                    &trigger_id,
                    &ExecuteTriggerEvent {
                        trigger_id: trigger_id.clone(),
                        authority: ALICE_ID.clone(),
                        args: Json::default(),
                    },
                )
                .expect("baseline generic IVM trigger execution");
            baseline_tx.last_tx_gas_used
        };
        assert!(nested_ivm_gas > 0, "generic IVM trigger must consume gas");
        let execute_trigger = InstructionBox::from(ExecuteTrigger::new(trigger_id.clone()));
        let direct_gas = isi_gas::meter_instructions(core::slice::from_ref(&execute_trigger));
        let transaction = TransactionBuilder::new(
            *state.network_id_ref(),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Batch(
            vec![ExecutableBatchItem::Instruction(execute_trigger)].into(),
        ))
        .sign(ALICE_KEYPAIR.private_key());
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        super::Executor::Initial
            .execute_transaction(&mut state_tx, &ALICE_ID, transaction, &mut IvmCache::new())
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect("live batch executes its generic IVM trigger");
        assert_eq!(
            state_tx.last_tx_gas_used,
            direct_gas.saturating_add(nested_ivm_gas),
            "fee settlement must retain nested trigger VM gas"
        );
    }
    #[test]
    fn rejected_live_batch_retains_nested_execute_trigger_gas() {
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let state = state_after_genesis(World::with([], [account], []));
        let trigger_id: TriggerId = "rejected_live_batch_gas".parse().expect("trigger id");
        let trigger_body = vec![
            InstructionBox::from(Log::new(Level::INFO, "meter rejected trigger".to_owned())),
            InstructionBox::from(Unregister::domain(
                DomainId::try_new("missing", "universal").expect("missing domain id"),
            )),
        ];
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                trigger_body.clone(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(ALICE_ID.clone()),
            )
            .expect("valid failing trigger action"),
        );
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let execute_trigger = InstructionBox::from(ExecuteTrigger::new(trigger_id));
        let direct_gas = isi_gas::meter_instructions(core::slice::from_ref(&execute_trigger));
        let nested_gas = isi_gas::meter_instructions(&trigger_body);
        let transaction = TransactionBuilder::new(
            *state.network_id_ref(),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Batch(
            vec![ExecutableBatchItem::Instruction(execute_trigger)].into(),
        ))
        .sign(ALICE_KEYPAIR.private_key());
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut state_tx)
            .expect("register failing trigger");
        super::Executor::Initial
            .execute_transaction(&mut state_tx, &ALICE_ID, transaction, &mut IvmCache::new())
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("failing trigger rejects its enclosing live batch");
        assert_eq!(
            state_tx.last_tx_gas_used,
            direct_gas.saturating_add(nested_gas),
            "rejected live execution must retain authored and nested trigger gas"
        );
    }
    fn seed_test_asset_supply(world: &mut World, asset_definition_id: &AssetDefinitionId) {
        let total = world
            .assets
            .view()
            .iter()
            .filter(|(asset_id, _)| asset_id.definition() == asset_definition_id)
            .try_fold(Quantity::zero(), |total, (_, value)| {
                total.checked_add(value.as_ref())
            })
            .expect("fixture asset supply must add exactly");
        let mut definition = world
            .asset_definitions
            .view()
            .get(asset_definition_id)
            .cloned()
            .expect("fixture asset definition exists");
        definition.total_quantity = total;
        world
            .asset_definitions
            .insert(asset_definition_id.clone(), definition);
    }
    struct InitialBatchFixture {
        world: World,
        source: AccountId,
        foreign_source: AccountId,
        delegate: AccountId,
        first_destination: AccountId,
        second_destination: AccountId,
        asset_definition: AssetDefinitionId,
        source_asset: AssetId,
        foreign_source_asset: AssetId,
    }
    fn initial_batch_fixture() -> InitialBatchFixture {
        let source = checked_account_id();
        let foreign_source = checked_account_id();
        let delegate = checked_account_id();
        let first_destination = checked_account_id();
        let second_destination = checked_account_id();
        let domain_id = DomainId::try_new("batch_assets", "universal").expect("domain id");
        let asset_definition = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "coin".parse().expect("asset name"),
        );
        let source_asset = AssetId::new(asset_definition.clone(), source.clone());
        let foreign_source_asset = AssetId::new(asset_definition.clone(), foreign_source.clone());
        let mut world = World::with_assets(
            [Domain::new(domain_id).build(&source)],
            [
                Account::new(source.clone()).build(&source),
                Account::new(foreign_source.clone()).build(&foreign_source),
                Account::new(delegate.clone()).build(&delegate),
                Account::new(first_destination.clone()).build(&first_destination),
                Account::new(second_destination.clone()).build(&second_destination),
            ],
            [AssetDefinition::numeric(
                asset_definition.clone(),
                "batch coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&source)],
            [
                Asset::new(source_asset.clone(), Quantity::from(20_u32)),
                Asset::new(foreign_source_asset.clone(), Quantity::from(20_u32)),
            ],
            [],
        );
        seed_test_asset_supply(&mut world, &asset_definition);
        InitialBatchFixture {
            world,
            source,
            foreign_source,
            delegate,
            first_destination,
            second_destination,
            asset_definition,
            source_asset,
            foreign_source_asset,
        }
    }
    fn initial_batch_balance(world: &impl WorldReadOnly, asset_id: &AssetId) -> Quantity {
        world
            .asset(asset_id)
            .map(|asset| asset.value().clone().into_inner())
            .unwrap_or_else(|_| Quantity::zero())
    }
    fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("executor algorithm-specific fixture key generation should succeed")
    }
    fn checked_account_id() -> AccountId {
        AccountId::new(checked_keypair().public_key().clone())
    }
    #[test]
    fn native_settlement_receipt_query_requires_all_ledger_access() {
        let query = SingularQueryBox::from(
            iroha_data_model::query::settlement::FindSettlementReceiptById::new(
                "business_receipt".parse().expect("settlement id"),
            ),
        );
        assert_eq!(
            native_singular_query_access(&query),
            NativeQueryAccess::AllLedger
        );
        let fixture = initial_batch_fixture();
        let authority = fixture.source.clone();
        let state = state_for_testing(fixture.world);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let mut tx = block.transaction();
        let request = QueryRequest::Singular(query);
        assert!(
            validate_builtin_native_query_permission(tx.world(), &authority, &request, 0).is_err()
        );
        tx.world.account_permissions.insert(
            authority.clone(),
            BTreeSet::from([executor_permission::query::CanReadAccountData {
                account: authority.clone(),
            }
            .into()]),
        );
        assert!(
            validate_builtin_native_query_permission(tx.world(), &authority, &request, 0).is_err()
        );
        tx.world.account_permissions.insert(
            authority.clone(),
            BTreeSet::from([executor_permission::query::CanReadAllLedgerData.into()]),
        );
        validate_builtin_native_query_permission(tx.world(), &authority, &request, 0)
            .expect("ledger-wide receipt reader");
        tx.world.account_permissions.remove(authority.clone());
        assert!(
            validate_builtin_native_query_permission(tx.world(), &authority, &request, 0).is_err()
        );
    }
    #[test]
    fn native_sorafs_citizen_bond_queries_require_all_ledger_access() {
        use iroha_data_model::query::sorafs::prelude::{
            FindSorafsCitizenBondBySerialCommitment, FindSorafsCitizenBondSnapshot,
        };

        let queries: [SingularQueryBox; 2] = [
            FindSorafsCitizenBondBySerialCommitment::new([0x11; 32]).into(),
            FindSorafsCitizenBondSnapshot.into(),
        ];
        for query in &queries {
            assert_eq!(
                native_singular_query_access(query),
                NativeQueryAccess::AllLedger
            );
        }
    }
    #[test]
    fn asset_definition_listing_requires_all_ledger_access() {
        use iroha_data_model::query::{
            asset::prelude::{
                FindAssetDefinitionById, FindAssetDefinitionDirectHome, FindAssetDefinitions,
            },
            parameters::QueryParams,
        };
        let envelope = QueryWithParams {
            query: (),
            query_payload: FindAssetDefinitions.encode(),
            item: QueryItemKind::AssetDefinition,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        };
        assert_eq!(
            native_iterable_query_access(&envelope).expect("authorize definition listing"),
            NativeQueryAccess::AllLedger
        );
        let id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("homes", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
        for query in [
            SingularQueryBox::from(FindAssetDefinitionById::new(id.clone())),
            SingularQueryBox::from(FindAssetDefinitionDirectHome::new(id)),
        ] {
            assert_eq!(
                native_singular_query_access(&query),
                NativeQueryAccess::Registered
            );
        }
    }
    #[test]
    fn native_escrow_query_authorization_uses_query_specific_tags() {
        use iroha_data_model::{
            escrow::AssetEscrowStatus,
            query::{
                escrow::prelude::{
                    FindAssetEscrowsByBuyer, FindAssetEscrowsBySeller, FindAssetEscrowsByStatus,
                },
                parameters::QueryParams,
            },
        };
        let seller = checked_account_id();
        let buyer = checked_account_id();
        let seller_query = FindAssetEscrowsBySeller {
            seller: seller.clone(),
        };
        let buyer_query = FindAssetEscrowsByBuyer {
            buyer: buyer.clone(),
        };
        let status_query = FindAssetEscrowsByStatus {
            status: AssetEscrowStatus::Accepted,
        };
        let seller_envelope = QueryWithParams {
            query: (),
            query_payload: seller_query.encode(),
            item: QueryItemKind::AssetEscrowsBySeller,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        };
        assert_eq!(
            native_iterable_query_access(&seller_envelope).expect("authorize seller query"),
            NativeQueryAccess::Account(seller)
        );
        let buyer_envelope = QueryWithParams {
            query: (),
            query_payload: buyer_query.encode(),
            item: QueryItemKind::AssetEscrowsByBuyer,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        };
        assert_eq!(
            native_iterable_query_access(&buyer_envelope).expect("authorize buyer query"),
            NativeQueryAccess::Account(buyer)
        );
        let status_envelope = QueryWithParams {
            query: (),
            query_payload: status_query.encode(),
            item: QueryItemKind::AssetEscrowsByStatus,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        };
        assert_eq!(
            native_iterable_query_access(&status_envelope).expect("authorize status query"),
            NativeQueryAccess::AllLedger
        );
    }
    #[test]
    fn native_escrow_query_authorization_rejects_wrong_or_malformed_tags() {
        use iroha_data_model::query::{
            escrow::prelude::FindAssetEscrowsBySeller, parameters::QueryParams,
        };
        let seller_query = FindAssetEscrowsBySeller {
            seller: checked_account_id(),
        };
        let legacy_item_tag = QueryWithParams {
            query: (),
            query_payload: seller_query.encode(),
            item: QueryItemKind::AssetEscrowRecord,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        };
        assert!(native_iterable_query_access(&legacy_item_tag).is_err());
        let status_tag_with_account_payload = QueryWithParams {
            query: (),
            query_payload: seller_query.encode(),
            item: QueryItemKind::AssetEscrowsByStatus,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        };
        assert!(native_iterable_query_access(&status_tag_with_account_payload).is_err());
        let malformed_seller = QueryWithParams {
            query: (),
            query_payload: vec![0xff],
            item: QueryItemKind::AssetEscrowsBySeller,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        };
        assert!(native_iterable_query_access(&malformed_seller).is_err());
    }
    #[test]
    fn fee_sponsor_operations_preserve_every_mixed_batch_item() {
        let authority = checked_account_id();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            31,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let expected_code_hash = Hash::new(b"sponsored-mixed-batch");
        let executable = Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(InstructionBox::from(Log::new(
                    Level::INFO,
                    "sponsored instruction".to_owned(),
                ))),
                ExecutableBatchItem::ContractCall(ContractInvocation {
                    contract_address: contract_address.clone(),
                    expected_code_hash,
                    entrypoint: "main".to_owned(),
                    arguments: None,
                }),
            ]
            .into(),
        );
        let operations = fee_sponsor_operations(&executable).expect("resolve sponsor operations");
        assert_eq!(operations.len(), 2);
        assert!(matches!(
            &operations[0],
            FeeSponsorOperation::NativeInstruction { .. }
        ));
        assert!(matches!(
            &operations[1],
            FeeSponsorOperation::ContractCall {
                contract_address: seen_address,
                code_hash: seen_hash,
                entrypoint,
            } if seen_address == &contract_address
                && seen_hash == &expected_code_hash
                && entrypoint == "main"
        ));
    }
    #[test]
    fn fee_sponsor_multisig_operations_decode_variant_and_exact_target_account() {
        let target = checked_account_id();
        let signatory = checked_account_id();
        let proposed_instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "multisig proposal".to_owned(),
        ))];
        let instructions_hash = HashOf::new(&proposed_instructions);
        let spec = MultisigSpec::new(
            BTreeMap::from([(signatory, 1)]),
            nonzero!(1_u16),
            nonzero!(60_000_u64),
        );
        let instructions = [
            InstructionBox::from(MultisigPropose::new(
                target.clone(),
                proposed_instructions,
                None,
            )),
            InstructionBox::from(MultisigApprove::new(
                target.clone(),
                instructions_hash.clone(),
            )),
            InstructionBox::from(MultisigCancel::new(target.clone(), instructions_hash)),
            InstructionBox::from(MultisigRegister::new(target.clone(), None, spec)),
        ];
        let expected = [
            FeeSponsorMultisigOperation::Propose,
            FeeSponsorMultisigOperation::Approve,
            FeeSponsorMultisigOperation::Cancel,
            FeeSponsorMultisigOperation::Register,
        ];
        for (instruction, expected_operation) in instructions.iter().zip(expected) {
            assert_eq!(
                fee_sponsor_instruction_operation(instruction)
                    .expect("decode exact multisig sponsor operation"),
                FeeSponsorOperation::Multisig {
                    operation: expected_operation,
                    account_id: target.clone(),
                }
            );
        }
    }
    #[test]
    fn fee_sponsor_multisig_selector_is_exact_and_register_is_opt_in() {
        let target = checked_account_id();
        let other_target = checked_account_id();
        let propose_instruction =
            InstructionBox::from(MultisigPropose::new(target.clone(), Vec::new(), None));
        assert_eq!(
            iroha_data_model::isi::instruction_wire_id(&propose_instruction),
            Some("iroha.custom"),
            "regression fixture must exercise a custom multisig instruction"
        );
        let propose = fee_sponsor_instruction_operation(&propose_instruction)
            .expect("decode propose sponsor operation");
        let approve = FeeSponsorOperation::Multisig {
            operation: FeeSponsorMultisigOperation::Approve,
            account_id: target.clone(),
        };
        let cancel = FeeSponsorOperation::Multisig {
            operation: FeeSponsorMultisigOperation::Cancel,
            account_id: target.clone(),
        };
        let register = FeeSponsorOperation::Multisig {
            operation: FeeSponsorMultisigOperation::Register,
            account_id: target.clone(),
        };
        let other_account = FeeSponsorOperation::Multisig {
            operation: FeeSponsorMultisigOperation::Propose,
            account_id: other_target,
        };
        let mut selector = iroha_data_model::nexus::FeeSponsorMultisigSelector {
            operations: vec![
                FeeSponsorMultisigOperation::Propose,
                FeeSponsorMultisigOperation::Approve,
                FeeSponsorMultisigOperation::Cancel,
            ],
            account_ids: vec![target],
        };
        let selector_box = FeeSponsorRuleSelector::Multisig(selector.clone());
        assert!(fee_sponsor_selector_matches_operation(
            &selector_box,
            &propose
        ));
        assert!(fee_sponsor_selector_matches_operation(
            &selector_box,
            &approve
        ));
        assert!(fee_sponsor_selector_matches_operation(
            &selector_box,
            &cancel
        ));
        assert!(!fee_sponsor_selector_matches_operation(
            &selector_box,
            &register
        ));
        assert!(!fee_sponsor_selector_matches_operation(
            &selector_box,
            &other_account
        ));
        let broad_custom = FeeSponsorRuleSelector::NativeInstruction(
            iroha_data_model::nexus::FeeSponsorNativeInstructionSelector {
                wire_id: "iroha.custom".to_owned(),
                asset_definition_id: None,
            },
        );
        assert!(
            !fee_sponsor_selector_matches_operation(&broad_custom, &propose),
            "decoded multisig payloads must not fall back to broad iroha.custom sponsorship"
        );
        selector
            .operations
            .push(FeeSponsorMultisigOperation::Register);
        assert!(fee_sponsor_selector_matches_operation(
            &FeeSponsorRuleSelector::Multisig(selector),
            &register
        ));
    }
    include!("executor_dpn_domain_enrollment_tests.rs");
    include!("executor_account_lineage_tests.rs");
    include!("executor_sns_attempt_tests.rs");
    include!("executor_raw_ivm_work_tests.rs");
    include!("executor_effect_budget_tests.rs");
    include!("executor_sorafs_repair_tests.rs");
    include!("executor_stream_token_custody_permission_tests.rs");
    include!("executor_cross_scope_permission_tests.rs");
    include!("executor_stream_token_direct_source_tests.rs");
    include!("executor_stream_token_gateway_direct_source_tests.rs");
    include!("executor_stream_token_gateway_permission_tests.rs");
    include!("executor_sorafs_market_tests.rs");
    include!("executor_sorafs_provider_governance_tests.rs");
    include!("executor_sorafs_pop_registry_tests.rs");
    include!("executor_asset_lock_admission_tests.rs");
    macro_rules! concrete_instruction_box {
        ($instruction_ty:ty, $instruction:expr) => {{
            const TEST_WIRE_ID: &str = "iroha.test.concrete_instruction.v1";
            let instruction: $instruction_ty = $instruction;
            let registry = iroha_data_model::isi::InstructionRegistry::new()
                .register_with_id::<$instruction_ty>(TEST_WIRE_ID);
            let (payload, flags) = norito::codec::encode_with_header_flags(&instruction);
            let framed =
                norito::core::frame_bare_with_header_flags::<$instruction_ty>(&payload, flags)
                    .expect("frame concrete instruction");
            let decoded = registry
                .decode(TEST_WIRE_ID, &framed)
                .expect("concrete instruction type is registered")
                .expect("decode concrete instruction");
            assert!(
                decoded.as_any().is::<$instruction_ty>(),
                "test fixture must preserve the concrete instruction dynamic shape",
            );
            decoded
        }};
    }
    include!("executor_contract_deployment_tests.rs");
    include!("executor_contract_owner_permission_tests.rs");
    #[test]
    fn initial_executor_genesis_rejects_unclassified_oracle_instruction() {
        let keypair = checked_keypair();
        let authority = AccountId::new(keypair.public_key().clone());
        let account = Account::new(authority.clone()).build(&authority);
        let instruction: InstructionBox = iroha_data_model::isi::oracle::AggregateOracleFeed {
            feed_id: "genesis_oracle".parse().expect("feed id"),
            slot: 0,
            request_hash: Hash::new(b"genesis oracle request"),
            evidence_hashes: Vec::new(),
        }
        .into();
        // This negative source is signed by the maintained builder; its actual Oracle
        // input must be refused by Initial before this candidate could publish genesis.
        let chain_id = ChainId::from("genesis-oracle-native-refusal");
        let source = crate::sumeragi::test_chain::signed_genesis_fixture(
            &chain_id,
            &keypair,
            &crate::sumeragi::test_chain::fixture_validators(),
            vec![instruction.clone()],
            0,
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            None,
        )
        .expect("build actual signed Oracle negative input");
        let state = State::new_with_chain_and_network_id_for_testing(
            World::with(
                [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&authority)],
                [account],
                [],
            ),
            Kura::blank_kura_for_testing(),
            query::store::LiveQueryStore::start_test(),
            chain_id,
            NetworkId::from_genesis_hash(source.hash()),
        );
        let index = source.external_transactions().position(|signed| matches!(signed.instructions(),
            Executable::Instructions(instructions) if instructions.iter().eq(core::iter::once(&instruction))
        )).expect("source contains exactly the tested Oracle instruction");
        let mut block = state
            .block_with_pristine_carrier_stage(&source, |_| Ok::<_, String>(()))
            .expect("capture original Oracle carrier before effects");
        let mut state_transaction = block
            .transaction_for_original_genesis_testing(&source, index, &authority, &instruction)
            .expect("authenticate the exact original Oracle bootstrap input");
        assert!(
            state_transaction._curr_block.is_genesis() && state_transaction.block_hashes.is_empty(),
            "the regression must exercise the authenticated genesis context"
        );
        let error = super::Executor::Initial
            .execute_instruction(&mut state_transaction, &authority, instruction)
            .expect_err("genesis must not bypass the native instruction allowlist");
        assert!(
            matches!(&error, ValidationFail::NotPermitted(reason)
            if reason.contains("does not admit unclassified native instruction")),
            "{error:?}"
        );
        drop(state_transaction);
        assert_eq!(block.committed_fragment_count(), 0);
        assert_eq!(state.committed_height(), 0);
    }
    #[test]
    fn initial_executor_admits_the_complete_kaigi_surface() {
        use iroha_data_model::{
            isi::kaigi::{
                CreateKaigi, EndKaigi, JoinKaigi, LeaveKaigi, RecordKaigiUsage, RegisterKaigiRelay,
                ReportKaigiRelayHealth, SetKaigiRelayManifest, UnregisterKaigiRelay,
            },
            kaigi::{KaigiId, KaigiRelayHealthStatus, KaigiRelayRegistration, NewKaigi},
        };

        let host = checked_account_id();
        let participant = checked_account_id();
        let relay = checked_account_id();
        let domain_id = DomainId::try_new("kaigi", "universal").expect("domain id");
        let call_id = KaigiId::new(
            domain_id.clone(),
            Name::from_str("initial-admission").expect("call name"),
        );
        let instructions: Vec<InstructionBox> = vec![
            CreateKaigi {
                call: NewKaigi::with_defaults(call_id.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .into(),
            JoinKaigi {
                call_id: call_id.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .into(),
            LeaveKaigi {
                call_id: call_id.clone(),
                participant,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .into(),
            EndKaigi {
                call_id: call_id.clone(),
                ended_at_ms: None,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .into(),
            RecordKaigiUsage {
                call_id: call_id.clone(),
                duration_ms: 1,
                billed_gas: 0,
                usage_commitment: None,
                proof: None,
            }
            .into(),
            SetKaigiRelayManifest {
                call_id: call_id.clone(),
                relay_manifest: None,
            }
            .into(),
            RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: relay.clone(),
                    hpke_public_key: vec![1],
                    bandwidth_class: 1,
                },
            }
            .into(),
            UnregisterKaigiRelay {
                relay_id: relay.clone(),
            }
            .into(),
            ReportKaigiRelayHealth {
                call_id,
                relay_id: relay,
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 0,
                notes: None,
            }
            .into(),
        ];

        for instruction in instructions {
            assert!(
                initial_native_instruction_is_explicitly_admitted(&instruction),
                "{} must reach its native Core authorization checks",
                instruction.id()
            );
        }
    }
    #[test]
    fn initial_executor_executes_kaigi_create_through_core() {
        use iroha_data_model::{
            isi::kaigi::CreateKaigi,
            kaigi::{KaigiId, NewKaigi, kaigi_metadata_key},
        };

        let host = checked_account_id();
        let domain_id = DomainId::try_new("kaigi", "universal").expect("domain id");
        let call_name = Name::from_str("initial-create").expect("call name");
        let call_id = KaigiId::new(domain_id.clone(), call_name.clone());
        let world = World::with(
            [Domain::new(domain_id.clone()).build(&host)],
            [Account::new(host.clone()).build(&host)],
            [],
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            1,
            0,
        ));
        let mut state_transaction = block.transaction();
        let instruction: InstructionBox = CreateKaigi {
            call: NewKaigi::with_defaults(call_id, host.clone()),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();

        super::Executor::Initial
            .execute_instruction(&mut state_transaction, &host, instruction)
            .expect("Initial executor must dispatch Kaigi create to Core");
        let key = kaigi_metadata_key(&call_name).expect("Kaigi metadata key");
        assert!(
            state_transaction
                .world
                .domain(&domain_id)
                .expect("domain")
                .metadata()
                .contains(&key),
            "Core Kaigi execution must persist the call record"
        );
    }
    #[test]
    fn initial_executor_rejects_kaigi_create_in_foreign_domain() {
        use iroha_data_model::{
            isi::kaigi::CreateKaigi,
            kaigi::{KaigiId, NewKaigi, kaigi_metadata_key},
        };

        let owner = checked_account_id();
        let intruder = checked_account_id();
        let domain_id = DomainId::try_new("kaigi", "universal").expect("domain id");
        let call_name = Name::from_str("squatted-call").expect("call name");
        let call_id = KaigiId::new(domain_id.clone(), call_name.clone());
        let world = World::with(
            [Domain::new(domain_id.clone()).build(&owner)],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(intruder.clone()).build(&owner),
            ],
            [],
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            1,
            0,
        ));
        let mut state_transaction = block.transaction();
        let instruction: InstructionBox = CreateKaigi {
            call: NewKaigi::with_defaults(call_id, intruder.clone()),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();

        let error = super::Executor::Initial
            .execute_instruction(&mut state_transaction, &intruder, instruction)
            .expect_err("a non-owner must not squat another domain's Kaigi namespace");
        assert!(
            matches!(
                error,
                ValidationFail::NotPermitted(ref message)
                    if message == "authority cannot create a Kaigi in this domain"
            ),
            "unexpected foreign-domain Kaigi rejection: {error:?}",
        );
        let key = kaigi_metadata_key(&call_name).expect("Kaigi metadata key");
        assert!(
            !state_transaction
                .world
                .domain(&domain_id)
                .expect("domain")
                .metadata()
                .contains(&key),
            "denied Kaigi creation must not reserve the foreign call name",
        );
    }
    #[test]
    fn initial_executor_rejects_direct_native_kaigi_metadata_writes() {
        use iroha_data_model::kaigi::kaigi_metadata_key;

        let authority = checked_account_id();
        let domain_id = DomainId::try_new("kaigi", "universal").expect("domain id");
        let key = kaigi_metadata_key(&Name::from_str("forged").expect("call name"))
            .expect("Kaigi metadata key");
        let world = World::with(
            [Domain::new(domain_id.clone()).build(&authority)],
            [Account::new(authority.clone()).build(&authority)],
            [],
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            1,
            0,
        ));
        let mut state_transaction = block.transaction();
        let instruction = SetKeyValue::domain(domain_id, key, Json::new("forged record")).into();

        let error = super::Executor::Initial
            .execute_instruction(&mut state_transaction, &authority, instruction)
            .expect_err("ordinary domain metadata must not overwrite native Kaigi state");
        assert!(
            matches!(
                error,
                ValidationFail::NotPermitted(ref message)
                    if message == "native Kaigi metadata keys cannot be changed directly"
            ),
            "unexpected reserved Kaigi metadata rejection: {error:?}"
        );
    }
    #[test]
    fn initial_executor_committee_publication_preserves_owner_proofs_and_parameter_authority() {
        use crate::{
            beacon::{
                InMemoryGlobalThresholdBeaconPartialSignerV1,
                ValidatedGlobalThresholdBeaconSessionV1,
                prepared_session_and_signers_fixture_for_keys_v1,
                prove_global_threshold_beacon_seat_readiness_v1,
                seat_readiness::verify_global_threshold_beacon_seat_readiness_v1,
            },
            sumeragi::test_chain::CertifiedTestChain,
        };
        use iroha_crypto::SignatureOf;
        use iroha_data_model::{
            consensus::GlobalThresholdBeaconDkgSessionV1,
            isi::{
                PublicLaneCandidateAuthorization, RegisterPublicLaneCandidate,
                RegisterPublicLaneValidator, SetParameter,
            },
            nexus::{
                AdmitValidatorCommitteeSeatV1, PrepareValidatorCommitteeCredentialsV1,
                PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1,
                PublicLaneMonetaryRegistrationV1, PublicLaneMonetaryScopeV1,
                ValidatorCommitteeCredentialsV1, ValidatorCommitteeOperationV1,
                ValidatorCommitteeSeatReadinessV1,
            },
            parameter::{Parameter, custom::CustomParameter, system::SumeragiNposParameters},
            sumeragi::epoch::InstalledBeaconEpochBindingV1,
        };
        use iroha_model_base::topology::LaneId;
        struct Beacon {
            session: ValidatedGlobalThresholdBeaconSessionV1,
            signers: Vec<InMemoryGlobalThresholdBeaconPartialSignerV1>,
        }
        #[inline(never)]
        fn prepared_chain() -> (
            CertifiedTestChain,
            Vec<KeyPair>,
            Vec<KeyPair>,
            Beacon,
            PrepareValidatorCommitteeCredentialsV1,
        ) {
            use crate::beacon::{
                FinalizedGlobalThresholdBeaconKeySessionRecordV1,
                GlobalThresholdBeaconPartialSignerV1, GlobalThresholdBeaconPulseAggregatorV1,
            };
            use crate::sumeragi::test_chain::{Signers, TestChainConfig};
            use iroha_data_model::{
                consensus::{
                    GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconPulseContextV1,
                },
                isi::{
                    RegisterPublicLaneValidator,
                    consensus_keys::{
                        ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
                        ThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleSignatureV1,
                    },
                },
                nexus::{PrepareValidatorCommitteeCredentialsV1, PublicLaneMonetaryPlanV1},
                parameter::system::SumeragiParameter,
            };
            use std::num::NonZeroU64;

            const EPOCH: u64 = 16;
            let mut keys = (0x51..=0x54)
                .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
                .collect::<Vec<_>>();
            keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
            let owners = (0xD1..=0xD4)
                .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519))
                .chain(
                    [0xE1, 0xE2]
                        .into_iter()
                        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)),
                )
                .collect::<Vec<_>>();
            let accounts = owners
                .iter()
                .map(|key| AccountId::new(key.public_key().clone()))
                .collect::<Vec<_>>();
            let staking = iroha_config::parameters::actual::NexusStaking::default();
            let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
            let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
            let world = World::with_assets(
                [
                    Domain::new(DomainId::try_new("nexus", "universal").unwrap())
                        .build(&accounts[0]),
                ],
                accounts
                    .iter()
                    .map(|account| Account::new(account.clone()).build(account))
                    .chain([Account::new(escrow.clone()).build(&escrow)]),
                [AssetDefinition::new(
                    definition.clone(),
                    "Staked XOR",
                    iroha_primitives::numeric::NumericSpec::fractional(9),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
                .build(&accounts[0])],
                accounts.iter().map(|account| {
                    Asset::new(
                        AssetId::new(definition.clone(), account.clone()),
                        Quantity::from(1_000u64),
                    )
                }),
                [],
            );
            let mut config = TestChainConfig::new(world, 1_000);
            config.validator_keys = Some(keys.clone());
            config.consensus_mode =
                iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
            config.genesis_parameters.extend([
                Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                    NonZeroU64::new(EPOCH).unwrap(),
                )),
                Parameter::Custom(
                    SumeragiNposParameters {
                        epoch_length_blocks: NonZeroU64::new(EPOCH).unwrap(),
                        max_validators: 4,
                        evidence_horizon_blocks: EPOCH,
                        slashing_delay_blocks: 2,
                        ..SumeragiNposParameters::default()
                    }
                    .into_custom_parameter(),
                ),
            ]);
            for (account, key) in accounts.iter().zip(&keys) {
                let source = AssetId::new(definition.clone(), account.clone());
                let destination = AssetId::new(definition.clone(), escrow.clone());
                config.genesis_instructions.push(
                    RegisterPublicLaneValidator::new(
                        LaneId::SINGLE,
                        account.clone(),
                        PeerId::new(key.public_key().clone()),
                        account.clone(),
                        Quantity::from(1_000u64),
                        Metadata::default(),
                        PublicLaneMonetaryPlanV1::genesis_registration(
                            source,
                            destination,
                            Quantity::from(1_000u64),
                        ),
                    )
                    .into(),
                );
            }
            let mut chain = CertifiedTestChain::start(config).unwrap();

            fn ceremony(
                chain: &CertifiedTestChain,
                keys: &[KeyPair],
                generation: u64,
                session_id: [u8; 32],
                attempt_id: [u8; 32],
                start: u64,
            ) -> Beacon {
                let roster = keys
                    .iter()
                    .map(|key| PeerId::new(key.public_key().clone()))
                    .collect::<Vec<_>>();
                let (session, signers) = prepared_session_and_signers_fixture_for_keys_v1(
                    GlobalThresholdBeaconDkgSessionV1 {
                        version: 1,
                        network_id: chain.network_id(),
                        session_id,
                        attempt_id,
                        authority_generation: generation,
                        roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
                        committee_size: 4,
                        threshold: 2,
                        start_height: start,
                        commitments_end_height: start + 1,
                        deliveries_end_height: start + 2,
                        acceptances_end_height: start + 3,
                    },
                    keys,
                    &chain.state().ivm_execution_budget(),
                );
                assert!(session.belongs_to(&chain.state().ivm_execution_budget()));
                Beacon { session, signers }
            }
            fn install(
                chain: &mut CertifiedTestChain,
                beacon: &Beacon,
                keys: &[KeyPair],
                owner: &KeyPair,
            ) {
                let height = chain.height() + 1;
                let roster = keys
                    .iter()
                    .map(|key| PeerId::new(key.public_key().clone()))
                    .collect::<Vec<_>>();
                let record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
                    beacon.session.record().clone(),
                    &chain.state().ivm_execution_budget(),
                )
                .unwrap();
                let mut certificate = ThresholdKeyLifecycleCertificateV1 {
                    version: crate::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
                    action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
                    expected_active_session_id: chain
                        .state()
                        .view()
                        .world()
                        .active_global_beacon_key_session(),
                    effective_height: height,
                    network_id: chain.network_id(),
                    roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
                    committee_size: 4,
                    quorum: 3,
                    session_id: record.session.session_id,
                    transcript_hash: record.session.transcript_hash,
                    public_state: norito::encode_canonical(&record).unwrap(),
                    signatures: Vec::new(),
                };
                let preimage =
                    crate::state::threshold_key_lifecycle_certificate_preimage_v1(&certificate)
                        .unwrap();
                certificate.signatures = keys
                    .iter()
                    .take(3)
                    .enumerate()
                    .map(|(index, key)| ThresholdKeyLifecycleSignatureV1 {
                        signer_index: index as u16,
                        signature: iroha_crypto::Signature::try_new(key.private_key(), &preimage)
                            .unwrap(),
                    })
                    .collect();
                crate::state::verify_threshold_key_lifecycle_certificate_v1(
                    &certificate,
                    &chain.network_id(),
                    height,
                    &roster,
                )
                .unwrap();
                let signed = chain.sign(
                    owner,
                    [ApplyThresholdKeyLifecycleCertificateV1 { certificate }.into()],
                    height * 1_000,
                );
                assert_eq!(chain.commit_at(height * 1_000, vec![signed]), [true]);
            }
            fn advance(chain: &mut CertifiedTestChain, target: u64, beacon: &Beacon) {
                while chain.height() < target {
                    let height = chain.height() + 1;
                    let current = chain
                        .state()
                        .view()
                        .world()
                        .consensus_schedule()
                        .ready(height)
                        .unwrap()
                        .epoch
                        .clone();
                    let control = if height + 1 == current.authorization.last_height {
                        let parent = chain.committed(chain.height());
                        let epoch = crate::sumeragi::schedule::core_epoch(&current).unwrap().id;
                        let mut pulse = GlobalThresholdBeaconPulseAggregatorV1::new(
                            beacon.session.clone(),
                            height,
                            GlobalThresholdBeaconChainAnchorV1 {
                                height: chain.height(),
                                block_hash: parent.block_hash(),
                            },
                            GlobalThresholdBeaconPulseContextV1 {
                                instance: chain.instance().0,
                                epoch: epoch.epoch,
                                epoch_context_id: epoch.context.0,
                                parent_consensus_hash: parent.core_hash().0,
                                parent_result: parent.result().0,
                            },
                        )
                        .unwrap();
                        for signer in beacon.signers.iter().take(2) {
                            pulse
                                .accept_partial(
                                    signer
                                        .sign_partial(pulse.session(), pulse.payload())
                                        .unwrap(),
                                )
                                .unwrap();
                        }
                        crate::sumeragi::epoch_beacon::control::encode(Some(
                            pulse.finalize().unwrap(),
                        ))
                        .unwrap()
                    } else {
                        iroha_sumeragi::types::ControlWitness::empty()
                    };
                    chain.commit_with_control(
                        Some(height * 1_000),
                        Vec::new(),
                        Signers::Quorum,
                        control,
                    );
                    assert_eq!(chain.height(), height);
                }
            }
            let bootstrap = ceremony(&chain, &keys, 0, [0x71; 32], [0x71; 32], 1);
            advance(&mut chain, 3, &bootstrap);
            install(&mut chain, &bootstrap, &keys, &owners[0]);
            advance(&mut chain, EPOCH, &bootstrap);
            let preparation = chain
                .state()
                .view()
                .world()
                .validator_committee_transitions()
                .get(&2)
                .unwrap()
                .preparation
                .clone();
            assert_eq!(preparation.selection_height, EPOCH);
            assert_eq!(
                preparation.selection_anchor,
                chain.committed(EPOCH - 1).block_hash()
            );
            assert_eq!(
                preparation.generation().validators,
                keys.iter()
                    .map(|key| PeerId::new(key.public_key().clone()))
                    .collect::<Vec<_>>()
            );
            let target = ceremony(
                &chain,
                &keys,
                1,
                preparation.beacon_session_id().unwrap(),
                preparation.transition_id().unwrap(),
                EPOCH + 1,
            );
            advance(&mut chain, EPOCH + 4, &bootstrap);
            install(&mut chain, &target, &keys, &owners[0]);
            let command = PrepareValidatorCommitteeCredentialsV1 {
                transition_id: preparation.transition_id().unwrap(),
                target_epoch: 2,
                credentials: ValidatorCommitteeCredentialsV1 {
                    beacon: InstalledBeaconEpochBindingV1 {
                        session_id: target.session.record().session_id,
                        transcript_hash: target.session.record().transcript_hash,
                    },
                },
            };
            assert!(
                chain
                    .state()
                    .view()
                    .world()
                    .validator_committee_transitions()
                    .get(&2)
                    .unwrap()
                    .credentials
                    .is_none()
            );
            (chain, owners, keys, target, command)
        }

        fn operation(command: ValidatorCommitteeOperationV1) -> InstructionBox {
            SetParameter::new(Parameter::Custom(command.into_custom_parameter())).into()
        }
        fn submit(
            chain: &mut CertifiedTestChain,
            inputs: Vec<(&KeyPair, InstructionBox, Option<&str>)>,
        ) {
            let height = chain.height() + 1;
            let time = height * 1_000;
            let transactions = inputs
                .iter()
                .map(|(key, instruction, _)| chain.sign(key, [instruction.clone()], time))
                .collect();
            let outcomes = chain.commit_at(time, transactions);
            assert_eq!(chain.height(), height);
            let committed = chain.committed(height);
            for (index, (_, _, expected)) in inputs.iter().enumerate() {
                let error = committed.block().output_error(index);
                assert_eq!(
                    outcomes[index],
                    expected.is_none(),
                    "input {index}: {error:?}"
                );
                if let Some(expected) = expected {
                    assert!(
                        format!("{error:?}").contains(expected),
                        "input {index}: {error:?}"
                    );
                } else {
                    assert!(error.is_none(), "input {index}: {error:?}");
                }
            }
        }

        // This fixture executes the original genesis, H16 selection, and both actual DKG installs.
        // Commands below are signed account work through Initial; no World preparation is injected.
        let (mut chain, owners, original_keys, target, credentials) = prepared_chain();
        assert_eq!(chain.height(), 21);
        let before = chain
            .state()
            .view()
            .world()
            .validator_committee_transitions()
            .get(&2)
            .unwrap()
            .clone();
        let authority_before =
            crate::state::validator_committee::current_authority(&chain.state().view()).unwrap();
        let candidate_owner = AccountId::new(owners[4].public_key().clone());
        let intruder = &owners[5];
        let candidate_key = KeyPair::from_seed(vec![0x61; 32], Algorithm::BlsNormal);
        let peer = PeerId::new(candidate_key.public_key().clone());
        let staking = iroha_config::parameters::actual::NexusStaking::default();
        let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
        let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
        let source = AssetId::new(definition.clone(), candidate_owner.clone());
        let destination = AssetId::new(definition, escrow);
        // The H16 boundary already froze epoch 2; this new peer may target only epoch 3.
        let activation_height = before.preparation.last_height.checked_add(1).unwrap();
        let registration = RegisterPublicLaneValidator::new(
            LaneId::SINGLE,
            candidate_owner.clone(),
            peer.clone(),
            candidate_owner.clone(),
            Quantity::from(1_000u64),
            Metadata::default(),
            PublicLaneMonetaryPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Network(chain.network_id()),
                valid_until_height: 28,
                source_asset: source.clone(),
                destination_asset: destination,
                amount: Quantity::from(1_000u64),
                precondition: PublicLaneMonetaryPreconditionV1::Registration(
                    PublicLaneMonetaryRegistrationV1 { activation_height },
                ),
            },
        );
        let consent = PublicLaneCandidateAuthorization::new(
            chain.network_id(),
            registration.clone(),
            activation_height,
        );
        let candidate = RegisterPublicLaneCandidate {
            registration,
            activation_height,
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(candidate_key.private_key())
                .unwrap(),
            peer_signature: SignatureOf::new(candidate_key.private_key(), &consent),
        };
        candidate
            .peer_signature
            .verify(candidate_key.public_key(), &consent)
            .unwrap();
        let mut foreign_consent = consent.clone();
        foreign_consent.network_id =
            executor_test_network_id(b"foreign candidate committee publication");
        let mut foreign = candidate.clone();
        foreign.peer_signature = SignatureOf::new(candidate_key.private_key(), &foreign_consent);
        foreign
            .peer_signature
            .verify(candidate_key.public_key(), &foreign_consent)
            .unwrap();
        let mut later = candidate.clone();
        later.activation_height = activation_height + 16;
        let mut bad_pop = candidate.clone();
        bad_pop.proof_of_possession[0] ^= 1;
        submit(
            &mut chain,
            vec![
                (
                    intruder,
                    candidate.clone().into(),
                    Some("public validator lifecycle requires the validator account authority"),
                ),
                (
                    &owners[4],
                    later.into(),
                    Some("consent targets activation height"),
                ),
                (
                    &owners[4],
                    foreign.into(),
                    Some("does not authorize this network and registration"),
                ),
                (
                    &owners[4],
                    bad_pop.into(),
                    Some("invalid BLS-normal proof of possession"),
                ),
            ],
        );
        {
            let view = chain.state().view();
            assert!(
                view.world()
                    .public_lane_validators()
                    .get(&(LaneId::SINGLE, candidate_owner.clone()))
                    .is_none()
            );
            assert!(!view.world().peers().iter().any(|value| value == &peer));
            assert!(
                view.world()
                    .consensus_keys_by_pk()
                    .get(&peer.public_key().to_string())
                    .is_none()
            );
            assert!(
                view.world()
                    .public_lane_stake_custody()
                    .get(&(LaneId::SINGLE, candidate_owner.clone()))
                    .is_none()
            );
            assert_eq!(
                initial_batch_balance(view.world(), &source),
                Quantity::from(1_000u64)
            );
            assert_eq!(
                view.world().validator_committee_transitions().get(&2),
                Some(&before)
            );
        }
        submit(
            &mut chain,
            vec![(&owners[4], candidate.clone().into(), None)],
        );
        {
            let view = chain.state().view();
            let registered = view
                .world()
                .public_lane_validators()
                .get(&(LaneId::SINGLE, candidate_owner.clone()))
                .unwrap();
            assert_eq!(registered.peer_id, peer);
            assert_eq!(registered.activation_height, activation_height);
            assert_eq!(registered.total_stake, Quantity::from(1_000u64));
            assert_eq!(
                initial_batch_balance(view.world(), &source),
                Quantity::zero()
            );
            assert_eq!(
                view.world().validator_committee_transitions().get(&2),
                Some(&before)
            );
        }
        let mut absent = credentials;
        absent.target_epoch = 1;
        let mut wrong_attempt = credentials;
        wrong_attempt.transition_id[0] ^= 1;
        let mut forged_transcript = credentials;
        forged_transcript.credentials.beacon.transcript_hash[0] ^= 1;
        submit(
            &mut chain,
            vec![
                (
                    intruder,
                    operation(ValidatorCommitteeOperationV1::PrepareCredentials(
                        credentials,
                    )),
                    Some("exact target validator owner"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::PrepareCredentials(absent)),
                    Some("attempt has not been frozen"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::PrepareCredentials(
                        wrong_attempt,
                    )),
                    Some("terminal, replayed or outside its preparation cutoff"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::PrepareCredentials(
                        forged_transcript,
                    )),
                    Some("outside its exact preparation attempt or cutoff"),
                ),
            ],
        );
        assert_eq!(
            chain
                .state()
                .view()
                .world()
                .validator_committee_transitions()
                .get(&2),
            Some(&before)
        );
        submit(
            &mut chain,
            vec![(
                &owners[0],
                operation(ValidatorCommitteeOperationV1::PrepareCredentials(
                    credentials,
                )),
                None,
            )],
        );
        let mut expected = before;
        expected.credentials = Some(credentials.credentials);
        assert_eq!(
            chain
                .state()
                .view()
                .world()
                .validator_committee_transitions()
                .get(&2),
            Some(&expected)
        );
        let generation = expected.preparation.generation();
        let context = expected.readiness_context(0).unwrap();
        let proof = prove_global_threshold_beacon_seat_readiness_v1(
            &target.signers[0],
            &target.session,
            &generation,
            &context,
        )
        .unwrap();
        verify_global_threshold_beacon_seat_readiness_v1(
            &target.session,
            &generation,
            &context,
            &proof,
        )
        .unwrap();
        let ready = AdmitValidatorCommitteeSeatV1 {
            transition_id: credentials.transition_id,
            target_epoch: credentials.target_epoch,
            readiness: ValidatorCommitteeSeatReadinessV1 {
                validator_index: 0,
                beacon: proof,
            },
        };
        let proof_for_generation = |number| {
            let mut foreign_generation = generation.clone();
            foreign_generation.generation = number;
            let mut foreign_context = context;
            foreign_context.authority_generation = number;
            foreign_context.authority_id = foreign_generation.generation_id().unwrap();
            // This is a genuine adaptive share proof for a different complete challenge.
            // It is not authority for the immutable generation selected on this chain.
            let foreign_proof = prove_global_threshold_beacon_seat_readiness_v1(
                &target.signers[0],
                &target.session,
                &foreign_generation,
                &foreign_context,
            )
            .unwrap();
            verify_global_threshold_beacon_seat_readiness_v1(
                &target.session,
                &foreign_generation,
                &foreign_context,
                &foreign_proof,
            )
            .unwrap();
            assert!(
                verify_global_threshold_beacon_seat_readiness_v1(
                    &target.session,
                    &generation,
                    &context,
                    &foreign_proof,
                )
                .is_err()
            );
            let mut command = ready.clone();
            command.readiness.beacon = foreign_proof;
            command
        };
        let previous_generation = proof_for_generation(0);
        let next_generation = proof_for_generation(2);
        let mut corrupted = ready.clone();
        corrupted.readiness.beacon.proof.z_s[0] ^= 1;
        submit(
            &mut chain,
            vec![
                (
                    intruder,
                    operation(ValidatorCommitteeOperationV1::AdmitSeat(ready.clone())),
                    Some("exact target validator owner"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::AdmitSeat(
                        previous_generation,
                    )),
                    Some("custody proof is invalid"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::AdmitSeat(next_generation)),
                    Some("custody proof is invalid"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::AdmitSeat(corrupted)),
                    Some("custody proof is invalid"),
                ),
            ],
        );
        assert_eq!(
            chain
                .state()
                .view()
                .world()
                .validator_committee_transitions()
                .get(&2),
            Some(&expected)
        );
        submit(
            &mut chain,
            vec![(
                &owners[0],
                operation(ValidatorCommitteeOperationV1::AdmitSeat(ready.clone())),
                None,
            )],
        );
        expected.readiness.push(ready.readiness.clone());
        assert_eq!(
            chain
                .state()
                .view()
                .world()
                .validator_committee_transitions()
                .get(&2),
            Some(&expected)
        );
        // A peer admitted for a future election is not in the incumbent commit topology.
        // Its replay reaches that live-key gate before the validator-row duplicate guard.
        let fresh_peer_refusal = "global validator peer must be present in the commit topology; a prepared epoch key transition is required for a fresh peer";
        let incumbent_owner = AccountId::new(owners[0].public_key().clone());
        let incumbent_peer = PeerId::new(original_keys[0].public_key().clone());
        let incumbent_source = AssetId::new(source.definition().clone(), incumbent_owner.clone());
        let mut incumbent_registration = candidate.registration.clone();
        incumbent_registration.validator = incumbent_owner.clone();
        incumbent_registration.stake_account = incumbent_owner.clone();
        incumbent_registration.peer_id = incumbent_peer.clone();
        incumbent_registration.monetary_plan.source_asset = incumbent_source.clone();
        let incumbent_consent = PublicLaneCandidateAuthorization::new(
            chain.network_id(),
            incumbent_registration.clone(),
            activation_height,
        );
        let incumbent_duplicate = RegisterPublicLaneCandidate {
            registration: incumbent_registration,
            activation_height,
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(original_keys[0].private_key())
                .unwrap(),
            peer_signature: SignatureOf::new(original_keys[0].private_key(), &incumbent_consent),
        };
        iroha_crypto::bls_normal_pop_verify(
            incumbent_peer.public_key(),
            &incumbent_duplicate.proof_of_possession,
        )
        .unwrap();
        incumbent_duplicate
            .peer_signature
            .verify(incumbent_peer.public_key(), &incumbent_consent)
            .unwrap();
        let replay_accounts = [
            (&candidate_owner, &source),
            (&incumbent_owner, &incumbent_source),
        ];
        let replay_before = {
            let view = chain.state().view();
            replay_accounts.map(|(owner, source)| {
                (
                    view.world()
                        .public_lane_validators()
                        .get(&(LaneId::SINGLE, owner.clone()))
                        .unwrap()
                        .clone(),
                    view.world()
                        .public_lane_stake_shares()
                        .get(&(LaneId::SINGLE, owner.clone(), owner.clone()))
                        .unwrap()
                        .clone(),
                    initial_batch_balance(view.world(), source),
                )
            })
        };
        assert_eq!(replay_before[1].0.peer_id, incumbent_peer);
        let ordinary = SetParameter::new(Parameter::Custom(CustomParameter::new(
            "ordinary_setting".parse().unwrap(),
            Json::new(1_u64),
        )));
        submit(
            &mut chain,
            vec![
                (&owners[4], candidate.into(), Some(fresh_peer_refusal)),
                (
                    &owners[0],
                    incumbent_duplicate.into(),
                    Some("validator already registered for lane"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::PrepareCredentials(
                        credentials,
                    )),
                    Some("prepared credentials cannot be replaced"),
                ),
                (
                    &owners[0],
                    operation(ValidatorCommitteeOperationV1::AdmitSeat(ready)),
                    Some("target seat readiness is already recorded"),
                ),
                (&owners[0], ordinary.into(), Some("CanSetParameters")),
            ],
        );
        let committed = chain.committed(28);
        for (index, refusal) in [fresh_peer_refusal, "validator already registered for lane"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                committed.block().output_error(index),
                Some(&crate::tx::TransactionRejectionReason::Validation(
                    ValidationFail::InstructionFailed(
                        InstructionExecutionError::InvariantViolation(refusal.into())
                    )
                )),
                "each replay must reach its exact native registration guard"
            );
        }
        let view = chain.state().view();
        assert_eq!(chain.height(), 28);
        for ((owner, source), (record, share, balance)) in
            replay_accounts.into_iter().zip(replay_before)
        {
            assert_eq!(
                view.world()
                    .public_lane_validators()
                    .get(&(LaneId::SINGLE, owner.clone())),
                Some(&record),
                "rejected replay must preserve the complete original validator record"
            );
            assert_eq!(
                view.world().public_lane_stake_shares().get(&(
                    LaneId::SINGLE,
                    owner.clone(),
                    owner.clone()
                )),
                Some(&share),
                "rejected replay must preserve the original bonded share"
            );
            assert_eq!(
                initial_batch_balance(view.world(), source),
                balance,
                "rejected replay must not transfer a second original stake"
            );
        }
        assert_eq!(
            view.world().validator_committee_transitions().get(&2),
            Some(&expected)
        );
        assert_eq!(
            crate::state::validator_committee::current_authority(&view).unwrap(),
            authority_before
        );
        assert_eq!(
            authority_before.0.validators,
            original_keys
                .iter()
                .map(|key| PeerId::new(key.public_key().clone()))
                .collect::<Vec<_>>()
        );
        assert!(expected.outcome.is_none());
        assert!(
            !view
                .world()
                .parameters()
                .custom()
                .contains_key(&ValidatorCommitteeOperationV1::parameter_id())
        );
        assert!(
            !view
                .world()
                .parameters()
                .custom()
                .contains_key(&"ordinary_setting".parse().unwrap())
        );
    }
    #[test]
    fn initial_executor_citizenship_preserves_owner_bond_and_release_checks() {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_data_model::isi::governance::{RegisterCitizen, UnregisterCitizen};
        let owner_key = checked_keypair();
        let escrow_key = checked_keypair();
        let owner = AccountId::new(owner_key.public_key().clone());
        let escrow = AccountId::new(escrow_key.public_key().clone());
        let domain = DomainId::try_new("citizens", "universal").unwrap();
        let definition =
            AssetDefinitionId::derive_from_components(domain.clone(), "bond".parse().unwrap());
        let owner_asset = AssetId::new(definition.clone(), owner.clone());
        let escrow_asset = AssetId::new(definition.clone(), escrow.clone());
        let world = World::with_assets(
            [Domain::new(domain).build(&owner)],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(escrow.clone()).build(&escrow),
            ],
            [AssetDefinition::numeric(
                definition.clone(),
                "bond",
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&owner)],
            [
                Asset::new(owner_asset.clone(), Quantity::from(100_u32)),
                Asset::new(escrow_asset.clone(), Quantity::zero()),
            ],
            [],
        );
        let mut governance = state_after_genesis(World::new()).gov.clone();
        governance.citizenship_asset_id = definition;
        governance.citizenship_bond_amount = Quantity::from(50_u32);
        governance.citizenship_escrow_account = escrow.clone();
        let mut config = TestChainConfig::new(world, 1_000);
        config.governance = Some(governance);
        let mut chain = CertifiedTestChain::start(config).expect("signed governance policy");
        let submit =
            |chain: &mut CertifiedTestChain, key: &KeyPair, instruction, expected: Option<&str>| {
                let time = (chain.height() + 1) * 1_000;
                let transaction = chain.sign(key, [instruction], time);
                let outcome = chain.commit_at(time, vec![transaction]);
                let committed = chain.committed(chain.height());
                let error = committed.block().output_error(0);
                if let Some(expected) = expected {
                    assert_eq!(outcome, [false]);
                    assert!(format!("{error:?}").contains(expected), "{error:?}");
                } else {
                    assert_eq!(outcome, [true], "{error:?}");
                    assert!(error.is_none());
                }
            };
        let register = |amount| {
            InstructionBox::from(RegisterCitizen {
                owner: owner.clone(),
                amount: Quantity::from(amount),
            })
        };
        for (key, amount, expected) in [
            (&escrow_key, 50_u32, "owner must equal authority"),
            (&owner_key, 49, "citizenship bond below minimum"),
        ] {
            submit(&mut chain, key, register(amount), Some(expected));
            let view = chain.state().view();
            assert!(view.world().citizens().get(&owner).is_none());
            assert_eq!(
                initial_batch_balance(view.world(), &owner_asset),
                Quantity::from(100_u32)
            );
        }
        submit(&mut chain, &owner_key, register(50_u32), None);
        let bonded_height = chain.height();
        {
            let view = chain.state().view();
            assert_eq!(
                view.world().citizens().get(&owner).unwrap().bonded_height,
                bonded_height
            );
            assert_eq!(
                initial_batch_balance(view.world(), &owner_asset),
                Quantity::from(50_u32)
            );
            assert_eq!(
                initial_batch_balance(view.world(), &escrow_asset),
                Quantity::from(50_u32)
            );
        }
        submit(&mut chain, &owner_key, register(60_u32), None);
        submit(
            &mut chain,
            &owner_key,
            register(50_u32),
            Some("citizenship bond cannot decrease"),
        );
        let unregister = || {
            InstructionBox::from(UnregisterCitizen {
                owner: owner.clone(),
            })
        };
        submit(
            &mut chain,
            &escrow_key,
            unregister(),
            Some("owner must equal authority"),
        );
        {
            let view = chain.state().view();
            let citizen = view.world().citizens().get(&owner).unwrap();
            assert_eq!(citizen.bonded_height, bonded_height);
            assert_eq!(citizen.amount, Quantity::from(60_u32));
            assert_eq!(
                initial_batch_balance(view.world(), &owner_asset),
                Quantity::from(40_u32)
            );
            assert_eq!(
                initial_batch_balance(view.world(), &escrow_asset),
                Quantity::from(60_u32)
            );
        }
        submit(&mut chain, &owner_key, unregister(), None);
        let view = chain.state().view();
        assert!(view.world().citizens().get(&owner).is_none());
        assert_eq!(
            initial_batch_balance(view.world(), &owner_asset),
            Quantity::from(100_u32)
        );
        assert!(view.world().assets().get(&escrow_asset).is_none());
    }
    #[test]
    fn initial_executor_classifies_verifying_key_bootstrap_as_genesis_only() {
        use iroha_data_model::{
            isi::verifying_keys::{RegisterVerifyingKey, UpdateVerifyingKey},
            proof::{VerifyingKeyId, VerifyingKeyRecord},
            zk::BackendTag,
        };
        let id = VerifyingKeyId::new("halo2/ipa", "genesis_vk");
        let record = VerifyingKeyRecord::new(
            1,
            "genesis-vk-circuit",
            BackendTag::NativePipaRPasta,
            "pallas",
            [0x11; 32],
            [0x22; 32],
        );
        let instructions: [InstructionBox; 2] = [
            RegisterVerifyingKey {
                id: id.clone(),
                record: record.clone(),
            }
            .into(),
            UpdateVerifyingKey { id, record }.into(),
        ];
        for instruction in &instructions {
            assert!(
                initial_genesis_instruction_is_explicitly_admitted(instruction),
                "{} must be admitted during authenticated genesis",
                instruction.id()
            );
            assert!(
                !initial_native_instruction_is_explicitly_admitted(instruction),
                "{} must remain unavailable through the post-genesis Initial executor",
                instruction.id()
            );
        }
    }
    #[test]
    fn initial_executor_routes_native_privacy_corridor_to_core() {
        use crate::privacy_profiles::compiled_privacy_profile_v1;
        use iroha_data_model::{
            isi::privacy::{
                RegisterPrivacyProtocolActivationV1, SubmitPrivacyProofV1,
                TransitionPrivacyProtocolLifecycleV1,
            },
            privacy::{
                IrohaJindoPolynomialCommitmentStatementV1, PrivacyActiveLifecycleV1,
                PrivacyJindoFieldElementV1, PrivacyJindoLatticeCommitmentV1, PrivacyProofBytesV1,
                PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProposedLifecycleV1,
                PrivacyProtocolIdV1, PrivacyProtocolLifecycleV1, PrivacyStatementContextV1,
                PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
            },
        };

        let profile =
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
                .expect("load compiled Jindo profile");
        let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Proposed(
            PrivacyProposedLifecycleV1 {
                proposed_at_height: 2,
            },
        ));
        let statement = PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(
            IrohaJindoPolynomialCommitmentStatementV1 {
                context: PrivacyStatementContextV1 {
                    network_id: executor_test_network_id(b"initial-privacy-corridor"),
                    action_index: 0,
                    transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0x11; 32]),
                    parameter_id: profile.parameter_id,
                    parameter_digest: profile.parameter_digest,
                    verifier_digest: profile.verifier_digest,
                    statement_schema_digest: profile.statement_schema_digest,
                    engine_manifest_digest: profile.engine_manifest_digest,
                },
                polynomial_commitments: vec![PrivacyJindoLatticeCommitmentV1::new(vec![0x22])],
                evaluation_point: PrivacyJindoFieldElementV1::new([0x33; 32]),
                claimed_evaluations: vec![PrivacyJindoFieldElementV1::new([0x44; 32])],
            },
        );
        let statement_digest = statement.digest().expect("hash Jindo statement fixture");
        let envelope = PrivacyProofEnvelopeV1 {
            wire_magic: Default::default(),
            catalog_commitment: Default::default(),
            protocol_id: profile.protocol_id,
            proof_system_id: profile.proof_system_id,
            engine_id: profile.engine_id,
            parameter_id: profile.parameter_id,
            parameter_digest: profile.parameter_digest,
            verifier_digest: profile.verifier_digest,
            statement_schema_digest: profile.statement_schema_digest,
            engine_manifest_digest: profile.engine_manifest_digest,
            statement_digest,
            statement,
            proof: PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1::new(
                vec![0x55],
            )),
        };
        let instructions: [InstructionBox; 3] = [
            RegisterPrivacyProtocolActivationV1::new(activation).into(),
            TransitionPrivacyProtocolLifecycleV1::new(
                profile.protocol_id,
                PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                    proposed_at_height: 2,
                    activated_at_height: 2,
                    state_since_height: 2,
                }),
            )
            .into(),
            SubmitPrivacyProofV1::new(envelope).into(),
        ];
        for instruction in &instructions {
            assert!(
                initial_native_instruction_is_explicitly_admitted(instruction),
                "{} must reach its exact native Core authorization and verification gates",
                instruction.id(),
            );
        }
    }
    #[test]
    fn initial_executor_routes_threshold_key_lifecycle_to_core_qc_authentication() {
        use iroha_data_model::isi::consensus_keys::{
            ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
            ThresholdKeyLifecycleCertificateV1,
        };

        let authority = checked_account_id();
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            1,
            0,
        ));
        let mut state_transaction = block.transaction();
        let instruction: InstructionBox = ApplyThresholdKeyLifecycleCertificateV1 {
            certificate: ThresholdKeyLifecycleCertificateV1 {
                version: crate::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
                action: ThresholdKeyLifecycleActionV1::RetireParliamentTleKey,
                expected_active_session_id: Some([0x31; 32]),
                effective_height: 2,
                network_id: executor_test_network_id(b"initial threshold lifecycle admission"),
                roster_hash: [0x32; 32],
                committee_size: 4,
                quorum: 3,
                session_id: [0x31; 32],
                transcript_hash: [0x33; 32],
                public_state: Vec::new(),
                signatures: Vec::new(),
            },
        }
        .into();
        assert!(
            initial_native_instruction_is_explicitly_admitted(&instruction),
            "the proof-carrying lifecycle instruction must reach Core"
        );

        let error = super::Executor::Initial
            .execute_instruction(&mut state_transaction, &authority, instruction)
            .expect_err("an empty validator QC must fail in Core");
        assert!(
            format!("{error:?}")
                .contains("threshold-key lifecycle certificate authentication failed"),
            "the Initial executor must route the instruction to exact Core QC verification: {error:?}"
        );
    }
    #[test]
    fn initial_executor_cannot_bypass_native_asset_transfer_control_metadata() {
        let authority = checked_account_id();
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            1,
            0,
        ));
        let mut state_transaction = block.transaction();
        let key: Name = iroha_data_model::asset::ASSET_TRANSFER_CONTROL_METADATA_KEY
            .parse()
            .expect("asset transfer control metadata key");
        let instructions: [InstructionBox; 2] = [
            SetKeyValue::account(
                authority.clone(),
                key.clone(),
                Json::new("generic replacement"),
            )
            .into(),
            RemoveKeyValue::account(authority.clone(), key).into(),
        ];

        for instruction in instructions {
            let error = super::Executor::Initial
                .execute_instruction(&mut state_transaction, &authority, instruction)
                .expect_err("Initial executor must preserve Core's reserved metadata guard");
            assert!(
                format!("{error:?}").contains("reserved for native asset transfer controls"),
                "unexpected Initial-executor rejection: {error:?}"
            );
        }
    }
    #[test]
    fn initial_executor_rejects_reserved_native_metadata_during_account_registration() {
        let authority = checked_account_id();
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            1,
            0,
        ));
        let mut state_transaction = block.transaction();
        for key in [
            ASSET_TRANSFER_CONTROL_METADATA_KEY,
            iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY,
        ] {
            let target = checked_account_id();
            let mut metadata = Metadata::default();
            metadata.insert(
                key.parse().expect("reserved metadata key"),
                Json::new(7_u64),
            );
            let instruction: InstructionBox =
                Register::account(NewAccount::new(target.clone()).with_metadata(metadata)).into();
            let error = super::Executor::Initial
                .execute_instruction(&mut state_transaction, &authority, instruction)
                .expect_err("Initial executor must reject native metadata seeding");
            assert!(
                error.to_string().contains("reserved native metadata"),
                "unexpected Initial-executor rejection: {error}"
            );
            assert!(state_transaction.world.account(&target).is_err());
        }
    }
    #[test]
    fn initial_executor_rejects_account_removal_with_transfer_control_state() {
        let target = checked_account_id();
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("transfer", "controls").expect("domain id"),
            "rose".parse().expect("asset name"),
        );
        let mut record = AssetTransferControlRecord::new(asset_definition);
        record.blacklisted = true;
        let mut metadata = Metadata::default();
        metadata.insert(
            ASSET_TRANSFER_CONTROL_METADATA_KEY
                .parse()
                .expect("transfer-control metadata key"),
            Json::new(AssetTransferControlStoreV1 {
                controls: vec![record],
            }),
        );
        let world = World::with(
            [],
            [Account::new(target.clone())
                .with_metadata(metadata)
                .build(&target)],
            [],
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            1,
            0,
        ));
        let mut state_transaction = block.transaction();
        let error = super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &target,
                Unregister::account(target.clone()).into(),
            )
            .expect_err("Initial executor must preserve native transfer-control history");
        assert!(
            error.to_string().contains("dedicated instructions"),
            "unexpected Initial-executor rejection: {error}"
        );
        assert!(state_transaction.world.account(&target).is_ok());
    }
    #[test]
    fn initial_executor_keeps_the_complete_vpn_lifecycle_allowlisted() {
        let source = include_str!("executor_initial_permission_authority.rs");
        let allowlist = source
            .split_once("fn initial_native_instruction_is_explicitly_admitted(")
            .expect("native Initial-executor classifier")
            .1
            .split_once("fn initial_genesis_instruction_is_explicitly_admitted(")
            .expect("end of native Initial-executor classifier")
            .0;
        for instruction in [
            "OpenVpnLeaseEscrow",
            "SettleVpnLease",
            "RefundExpiredVpnLease",
        ] {
            assert!(
                allowlist.contains(&format!("iroha_data_model::isi::vpn::{instruction},")),
                "Initial executor VPN lifecycle allowlist omitted {instruction}"
            );
        }
    }
    #[test]
    fn initial_executor_validator_lifecycle_requires_owner_without_peer_management() {
        use iroha_data_model::isi::staking::{
            ActivatePublicLaneValidator, ExitPublicLaneValidator, RegisterPublicLaneValidator,
        };
        let authority = checked_account_id();
        let intruder = checked_account_id();
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 1, 0));
        let stx = block.transaction();
        let lane = iroha_model_base::topology::LaneId::SINGLE;
        let peer = iroha_model_base::peer::PeerId::new(authority.expect_single_signatory().clone());
        let stake_asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("staking", "universal").unwrap(),
            "stake".parse().unwrap(),
        );
        let escrow = checked_account_id();
        let instructions: [InstructionBox; 3] = [
            RegisterPublicLaneValidator::new(
                lane,
                authority.clone(),
                peer,
                authority.clone(),
                Quantity::from(1_u64),
                Metadata::default(),
                iroha_data_model::nexus::PublicLaneMonetaryPlanV1 {
                    network_scope: iroha_data_model::nexus::PublicLaneMonetaryScopeV1::Network(
                        *state.network_id_ref(),
                    ),
                    valid_until_height: 2,
                    source_asset: AssetId::of(stake_asset.clone(), authority.clone()),
                    destination_asset: AssetId::of(stake_asset, escrow),
                    amount: Quantity::one(),
                    precondition:
                        iroha_data_model::nexus::PublicLaneMonetaryPreconditionV1::Registration(
                            iroha_data_model::nexus::PublicLaneMonetaryRegistrationV1 {
                                activation_height: 2,
                            },
                        ),
                },
            )
            .into(),
            ActivatePublicLaneValidator::new(lane, authority.clone()).into(),
            ExitPublicLaneValidator {
                lane_id: lane,
                validator: authority.clone(),
                release_at_ms: 10,
            }
            .into(),
        ];
        for instruction in instructions {
            validate_initial_native_instruction_authority(&stx, &authority, &instruction, false)
                .expect("self-owned lifecycle reaches Core");
            assert!(matches!(
                validate_initial_native_instruction_authority(&stx, &intruder, &instruction, false)
                    .map_err(crate::execution_attempt::expect_completed_rejection),
                Err(ValidationFail::NotPermitted(_))
            ));
        }
    }
    #[test]
    fn initial_executor_routes_self_authorized_public_lane_user_actions_to_core() {
        use iroha_data_model::isi::staking::{
            BondPublicLaneStake, ClaimPublicLaneRewards, FinalizePublicLaneUnbond,
            RebindPublicLaneValidatorPeer, SchedulePublicLaneUnbond,
        };

        let validator = checked_account_id();
        let staker = checked_account_id();
        let rebind_key = checked_keypair();
        let peer = iroha_model_base::peer::PeerId::new(rebind_key.public_key().clone());
        let rebind_consent =
            iroha_data_model::isi::staking::PublicLanePeerBindingAuthorization::new(
                executor_test_network_id(b"staking-classification-rebind"),
                iroha_model_base::topology::LaneId::SINGLE,
                validator.clone(),
                peer.clone(),
                1,
                iroha_model_base::peer::PeerId::new(validator.expect_single_signatory().clone()),
            );
        let request_id = Hash::prehashed([0xA5; Hash::LENGTH]);
        use iroha_data_model::nexus::{
            PublicLaneMonetaryBondV1, PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1,
            PublicLaneMonetaryScopeV1, PublicLaneMonetaryUnbondV1, PublicLaneRewardClaimPlanV1,
            PublicLaneUnbonding, public_lane_unbonding_commitment,
        };
        // This test checks dispatch and self-authority, while Core separately
        // authenticates these exact tenure, custody and withdrawal bindings.
        let stake_asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("staking", "universal").unwrap(),
            "stake".parse().unwrap(),
        );
        let escrow = checked_account_id();
        let staker_asset = AssetId::of(stake_asset.clone(), staker.clone());
        let escrow_asset = AssetId::of(stake_asset, escrow);
        let network_scope = PublicLaneMonetaryScopeV1::Network(executor_test_network_id(
            b"public lane user dispatch",
        ));
        let request = PublicLaneUnbonding {
            request_id,
            amount: Quantity::one(),
            release_at_ms: 1,
            slashable_through_height: 1,
            liability_release_height: 2,
        };
        let bond_plan = PublicLaneMonetaryPlanV1 {
            network_scope,
            valid_until_height: 2,
            source_asset: staker_asset.clone(),
            destination_asset: escrow_asset.clone(),
            amount: Quantity::one(),
            precondition: PublicLaneMonetaryPreconditionV1::Bond(PublicLaneMonetaryBondV1 {
                activation_height: 1,
                peer_id: peer.clone(),
            }),
        };
        let unbond_plan = PublicLaneMonetaryPlanV1 {
            network_scope,
            valid_until_height: 2,
            source_asset: escrow_asset,
            destination_asset: staker_asset,
            amount: request.amount.clone(),
            precondition: PublicLaneMonetaryPreconditionV1::Unbond(PublicLaneMonetaryUnbondV1 {
                activation_height: 1,
                request_hash: public_lane_unbonding_commitment(&request).unwrap(),
            }),
        };
        let instructions: [InstructionBox; 5] = [
            RebindPublicLaneValidatorPeer::new(
                iroha_model_base::topology::LaneId::SINGLE,
                validator.clone(),
                peer,
                iroha_crypto::SignatureOf::try_new(rebind_key.private_key(), &rebind_consent)
                    .expect("staking classification peer consent"),
            )
            .into(),
            BondPublicLaneStake {
                lane_id: iroha_model_base::topology::LaneId::SINGLE,
                validator: validator.clone(),
                staker: staker.clone(),
                amount: Quantity::from(1_u32),
                metadata: Metadata::default(),
                monetary_plan: bond_plan,
            }
            .into(),
            SchedulePublicLaneUnbond {
                lane_id: iroha_model_base::topology::LaneId::SINGLE,
                validator: validator.clone(),
                staker: staker.clone(),
                request_id,
                amount: Quantity::from(1_u32),
                release_at_ms: 1,
            }
            .into(),
            FinalizePublicLaneUnbond {
                lane_id: iroha_model_base::topology::LaneId::SINGLE,
                validator,
                staker: staker.clone(),
                request_id,
                monetary_plan: unbond_plan.clone(),
            }
            .into(),
            ClaimPublicLaneRewards {
                lane_id: iroha_model_base::topology::LaneId::SINGLE,
                account: staker.clone(),
                claim_plan: PublicLaneRewardClaimPlanV1 {
                    fee_claim: iroha_data_model::nexus::PublicLaneFeeRewardClaimV1 {
                        lifecycle_seal: [1; 32],
                        beneficiary_id: staker.clone(),
                        beneficiary_revision: 0,
                        source_asset: unbond_plan.source_asset.clone(),
                        destination_asset: unbond_plan.destination_asset.clone(),
                        amount: Quantity::one(),
                        expected_claim_sequence: 0,
                    },
                    network_scope,
                    valid_until_height: 2,
                },
            }
            .into(),
        ];
        for instruction in &instructions {
            assert!(
                initial_native_instruction_is_explicitly_admitted(instruction),
                "{} must reach its exact self-authority and state checks in Core",
                instruction.id()
            );
            assert!(
                !initial_genesis_instruction_is_explicitly_admitted(instruction),
                "{} is an ordinary signed user action, not a genesis-only administrative path",
                instruction.id()
            );
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn initial_executor_routes_exact_scoped_governance_isis_through_core_authorization() {
        use iroha_data_model::governance::types::{AbiVersion, ContractAbiHash, ContractCodeHash};
        use iroha_data_model::isi::governance as gov;
        use iroha_executor_data_model::permission::governance::{
            CanProposeContractDeployment, CanProposeRuntimeUpgrade, CanRestituteGovernanceLock,
            CanSlashGovernanceLock, CanSubmitGovernanceBallot,
        };
        let authority = checked_account_id();
        let citizen_target = checked_account_id();
        let account = Account::new(authority.clone()).build(&authority);
        let state = state_after_genesis(World::with([], [account], []));
        let network_id = state.network_id;
        let contract_address =
            ContractAddress::derive(&network_id, &authority, 1, DataSpaceId::UNIVERSAL)
                .expect("canonical contract address");
        let other_contract_address =
            ContractAddress::derive(&network_id, &authority, 2, DataSpaceId::UNIVERSAL)
                .expect("second canonical contract address");
        let abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
            name: "initial-executor-exact-scope".to_owned(),
            description: "governance admission regression".to_owned(),
            abi_version: 1,
            abi_hash,
            added_syscalls: Vec::new(),
            added_pointer_types: Vec::new(),
            start_height: 10,
            end_height: 10,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        };
        let referendum_id = "exact-governance-scope".to_owned();
        let probes: Vec<(InstructionBox, &str, &str)> = vec![
            (
                gov::ProposeDeployContract {
                    contract_address: contract_address.clone(),
                    code_hash: ContractCodeHash::new([0x11; 32]),
                    abi_hash: ContractAbiHash::new(abi_hash),
                    abi_version: AbiVersion::new(2),
                    manifest_provenance: None,
                }
                .into(),
                "CanProposeContractDeployment",
                "abi_version must be exactly 1",
            ),
            (
                gov::ProposeRuntimeUpgradeProposal { manifest }.into(),
                "CanProposeRuntimeUpgrade",
                "runtime upgrade window",
            ),
            (
                gov::CastZkBallot {
                    election_id: referendum_id.clone(),
                    proof_b64: "AA==".to_owned(),
                    public_inputs_json: r#"{"unknown":"field"}"#.to_owned(),
                }
                .into(),
                "CanSubmitGovernanceBallot",
                "unknown field",
            ),
            (
                gov::SlashGovernanceLock {
                    referendum_id: referendum_id.clone(),
                    owner: citizen_target.clone(),
                    amount: Quantity::zero(),
                    reason: "scope regression".to_owned(),
                }
                .into(),
                "CanSlashGovernanceLock",
                "slash amount must be > 0",
            ),
            (
                gov::RestituteGovernanceLock {
                    referendum_id: referendum_id.clone(),
                    owner: citizen_target.clone(),
                    amount: Quantity::zero(),
                    reason: "scope regression".to_owned(),
                }
                .into(),
                "CanRestituteGovernanceLock",
                "restitution amount must be > 0",
            ),
        ];
        for (instruction, _, _) in &probes {
            assert!(
                initial_native_instruction_is_explicitly_admitted(instruction),
                "{} must be admitted to its Core authorization gate",
                instruction.id()
            );
        }
        let mut world = state.world.block();
        world.account_permissions.insert(
            authority.clone(),
            BTreeSet::from([
                Permission::from(CanProposeContractDeployment {
                    contract_address: other_contract_address,
                }),
                Permission::from(CanProposeRuntimeUpgrade {
                    abi_version: 1,
                    abi_hash: [0xFF; 32],
                }),
                Permission::from(CanSubmitGovernanceBallot {
                    referendum_id: "other-governance-scope".to_owned(),
                }),
                Permission::from(CanSlashGovernanceLock {
                    referendum_id: "other-governance-scope".to_owned(),
                }),
                Permission::from(CanRestituteGovernanceLock {
                    referendum_id: "other-governance-scope".to_owned(),
                }),
            ]),
        );
        world.commit();
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        state_transaction.gov.citizenship_bond_amount = Quantity::zero();
        for (instruction, permission_name, _) in &probes {
            let error = super::Executor::Initial
                .execute_instruction(&mut state_transaction, &authority, instruction.clone())
                .expect_err("an adjacent governance scope must fail closed");
            assert!(
                format!("{error:?}").contains(&format!("exact {permission_name} target"))
                    || (*permission_name == "CanProposeRuntimeUpgrade"
                        && format!("{error:?}")
                            .contains("exact CanProposeRuntimeUpgrade ABI target")),
                "unexpected wrong-scope {permission_name} rejection: {error:?}"
            );
        }
        assert!(
            state_transaction
                .world
                .governance_proposals
                .iter()
                .next()
                .is_none()
        );
        assert!(
            state_transaction
                .world
                .governance_referenda
                .iter()
                .next()
                .is_none()
        );
        assert!(state_transaction.world.elections.iter().next().is_none());
        assert!(
            state_transaction
                .world
                .governance_locks
                .iter()
                .next()
                .is_none()
        );
        assert!(
            state_transaction
                .world
                .governance_slashes
                .iter()
                .next()
                .is_none()
        );
        assert!(state_transaction.world.citizens.iter().next().is_none());
        state_transaction.world.account_permissions.insert(
            authority.clone(),
            BTreeSet::from([
                Permission::from(CanProposeContractDeployment { contract_address }),
                Permission::from(CanProposeRuntimeUpgrade {
                    abi_version: 1,
                    abi_hash,
                }),
                Permission::from(CanSubmitGovernanceBallot {
                    referendum_id: referendum_id.clone(),
                }),
                Permission::from(CanSlashGovernanceLock {
                    referendum_id: referendum_id.clone(),
                }),
                Permission::from(CanRestituteGovernanceLock { referendum_id }),
            ]),
        );
        for (instruction, permission_name, downstream_error) in probes {
            let error = super::Executor::Initial
                .execute_instruction(&mut state_transaction, &authority, instruction)
                .expect_err("the exact scope must reach the deliberately invalid Core probe");
            assert!(
                format!("{error:?}").contains(downstream_error),
                "exact {permission_name} scope did not reach Core validation: {error:?}"
            );
        }
    }
    #[test]
    fn initial_executor_keeps_low_level_submit_ballot_behind_the_ivm_latch() {
        let backend = "halo2/ipa";
        let proof = iroha_data_model::proof::ProofAttachment::new_ref(
            backend.into(),
            iroha_data_model::proof::ProofBox::new(backend.into(), vec![0x01]),
            iroha_data_model::proof::VerifyingKeyId::new(backend, "ballot-v1"),
        );
        let instruction: InstructionBox = iroha_data_model::isi::zk::SubmitBallot {
            election_id: "latched-election".to_owned(),
            ciphertext: vec![0x02],
            ballot_proof: proof,
            nullifier: [0x03; 32],
        }
        .into();
        assert!(
            !initial_native_instruction_is_explicitly_admitted(&instruction),
            "direct signed SubmitBallot would bypass the IVM host's one-shot verification latch"
        );
    }
    #[test]
    fn initial_executor_keeps_explicitly_standalone_referendum_ballots() {
        use iroha_data_model::isi::governance::{
            CastPlainBallot, CastZkBallot, UpdatePlainConviction,
        };

        let ballots = [
            InstructionBox::from(CastPlainBallot {
                referendum_id: "standalone-plain".to_owned(),
                owner: checked_account_id(),
                amount: 1_u64.into(),
                duration_blocks: 1,
                direction: 0,
            }),
            InstructionBox::from(UpdatePlainConviction {
                referendum_id: "standalone-plain".to_owned(),
                owner: checked_account_id(),
                amount: 2_u64.into(),
                duration_blocks: 2,
            }),
            InstructionBox::from(CastZkBallot {
                election_id: "standalone-zk".to_owned(),
                proof_b64: "AA==".to_owned(),
                public_inputs_json: "{}".to_owned(),
            }),
        ];
        for ballot in &ballots {
            assert!(
                initial_native_instruction_is_explicitly_admitted(ballot),
                "standalone referendum ballot must remain reachable after Parliament cutover"
            );
        }
    }
    #[test]
    fn initial_executor_admits_public_ministry_agenda_submissions() {
        use iroha_data_model::{
            isi::ministry::SubmitAgendaProposal,
            ministry::{
                AGENDA_PROPOSAL_VERSION_V1, AgendaProposalAction, AgendaProposalSubmitter,
                AgendaProposalSummary, AgendaProposalV1,
            },
        };
        let instruction: InstructionBox = SubmitAgendaProposal {
            proposal: AgendaProposalV1 {
                version: AGENDA_PROPOSAL_VERSION_V1,
                proposal_id: "AC-2026-001".to_owned(),
                submitted_at_unix_ms: 1,
                language: "en".to_owned(),
                action: AgendaProposalAction::AmendPolicy,
                summary: AgendaProposalSummary {
                    title: "Public agenda proposal".to_owned(),
                    motivation: "Exercise the signed public submission surface.".to_owned(),
                    expected_impact: "The initial executor reaches exact Core validation."
                        .to_owned(),
                },
                tags: Vec::new(),
                targets: Vec::new(),
                evidence: Vec::new(),
                submitter: AgendaProposalSubmitter {
                    name: "Citizen".to_owned(),
                    contact: "citizen@example.org".to_owned(),
                    organization: None,
                    pgp_fingerprint: None,
                },
                duplicates: Vec::new(),
            },
        }
        .into();
        assert!(
            initial_native_instruction_is_explicitly_admitted(&instruction),
            "signed public Ministry proposals must reach exact Core validation"
        );
    }
    #[test]
    fn initial_executor_denies_chain_and_foreign_controller_takeover_paths() {
        let attacker = checked_account_id();
        let victim = checked_account_id();
        let world = World::with(
            [],
            [
                Account::new(attacker.clone()).build(&attacker),
                Account::new(victim.clone()).build(&victim),
            ],
            [],
        );
        let state = state_for_testing(world);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let mut state_transaction = block.transaction();
        let custom_id: CustomParameterId = "attacker_parameter".parse().expect("parameter id");
        let set_parameter = iroha_data_model::isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Custom(CustomParameter::new(
                custom_id,
                Json::new(1_u32),
            )),
        );
        let upgrade = iroha_data_model::isi::Upgrade::new(data_model_executor::Executor::new(
            IvmBytecode::from_compiled(generate_denied_program("attacker executor")),
        ));
        let foreign_signatory = checked_keypair().public_key().clone();
        let instructions: Vec<InstructionBox> = vec![
            set_parameter.into(),
            upgrade.into(),
            iroha_data_model::isi::AddSignatory::new(victim.clone(), foreign_signatory.clone())
                .into(),
            iroha_data_model::isi::RemoveSignatory::new(victim.clone(), foreign_signatory).into(),
            iroha_data_model::isi::SetAccountQuorum::new(
                victim.clone(),
                std::num::NonZeroU16::new(1).expect("quorum"),
            )
            .into(),
        ];
        for instruction in instructions {
            let error = super::Executor::Initial
                .execute_instruction(&mut state_transaction, &attacker, instruction)
                .expect_err(
                    "an ordinary account must not mutate chain policy or a foreign controller",
                );
            assert!(
                matches!(error, ValidationFail::NotPermitted(_)),
                "{error:?}"
            );
        }
        assert!(matches!(
            &*state_transaction.world.executor,
            super::Executor::Initial
        ));
        assert!(state_transaction.world.account(&victim).is_ok());
    }
    #[test]
    fn initial_executor_reserves_hijiri_parameters_for_dedicated_permission() {
        use iroha_data_model::hijiri::{
            FeeMultiplierBand, HijiriFeePolicy, HijiriParametersV1, Q16,
        };
        let generic_parameter_admin = checked_account_id();
        let hijiri_admin = checked_account_id();
        let mut world = World::with(
            [],
            [
                Account::new(generic_parameter_admin.clone()).build(&generic_parameter_admin),
                Account::new(hijiri_admin.clone()).build(&hijiri_admin),
            ],
            [],
        );
        world.account_permissions.insert(
            generic_parameter_admin.clone(),
            BTreeSet::from([executor_permission::parameter::CanSetParameters.into()]),
        );
        world.account_permissions.insert(
            hijiri_admin.clone(),
            BTreeSet::from([executor_permission::parameter::CanSetHijiriParameters.into()]),
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        let parameters = HijiriParametersV1::try_new(
            1,
            None,
            HijiriFeePolicy::new(
                vec![FeeMultiplierBand::new(Q16::ONE, Q16::ONE).unwrap()],
                Q16::ONE,
            )
            .unwrap(),
            Q16::ONE,
        )
        .unwrap();
        let instruction = || {
            InstructionBox::from(iroha_data_model::isi::SetParameter::new(
                iroha_data_model::parameter::Parameter::Custom(
                    parameters.clone().into_custom_parameter(),
                ),
            ))
        };
        let error = super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &generic_parameter_admin,
                instruction(),
            )
            .expect_err("generic parameter permission must not control Hijiri fees");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message)
                if message.contains("CanSetHijiriParameters")),
            "unexpected generic-admin rejection: {error:?}"
        );
        super::Executor::Initial
            .execute_instruction(&mut state_transaction, &hijiri_admin, instruction())
            .expect("dedicated Hijiri permission must install the initial parameter");
        assert!(
            state_transaction
                .world
                .parameters()
                .custom()
                .contains_key(&HijiriParametersV1::parameter_id())
        );
    }
    #[test]
    fn initial_executor_treats_sccp_proposer_permission_as_genesis_only() {
        let permission: Permission =
            executor_permission::sccp::CanProposeSccpRouteGovernance.into();
        assert!(is_builtin_initial_permission_name(
            permission.name().as_ref()
        ));
        assert!(
            initial_permission_is_genesis_only(&permission),
            "SCCP route governance proposers are granted and revoked only in genesis"
        );
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn initial_executor_enforces_capability_roots_for_every_scoped_permission() {
        use iroha_data_model::{
            account::rekey::AccountAliasDomain,
            events::execute_trigger::ExecuteTriggerEventFilter,
            nexus::UniversalAccountId,
            trigger::action::{Action, Repeats},
        };
        use iroha_executor_data_model::permission::account::AccountAliasPermissionScope;
        let legitimate_root = checked_account_id();
        let adjacent_owner = checked_account_id();
        let delegation_sink = checked_account_id();
        let governed_domain =
            DomainId::try_new("grant_policy", "universal").expect("governed domain");
        let adjacent_domain =
            DomainId::try_new("adjacent_owner", "universal").expect("adjacent domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            governed_domain.clone(),
            "root_asset".parse().expect("asset name"),
        );
        let root_asset = AssetId::new(asset_definition.clone(), legitimate_root.clone());
        // The exact mint permission deliberately names the attacker as destination. Mint
        // authority belongs to the definition owner, never to the destination account.
        let nft_id = NftId::new(
            governed_domain.clone(),
            "root_nft".parse().expect("NFT name"),
        );
        let trigger_id: TriggerId = "grant_policy_trigger".parse().expect("trigger id");
        let world = World::with_assets(
            [
                Domain::new(governed_domain.clone()).build(&legitimate_root),
                Domain::new(adjacent_domain.clone()).build(&adjacent_owner),
            ],
            [
                Account::new(legitimate_root.clone()).build(&legitimate_root),
                Account::new(adjacent_owner.clone()).build(&adjacent_owner),
                Account::new(delegation_sink.clone()).build(&delegation_sink),
            ],
            [AssetDefinition::numeric(
                asset_definition.clone(),
                "root asset".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&legitimate_root)],
            [],
            [Nft::new(nft_id.clone(), Metadata::default()).build(&legitimate_root)],
        );
        let state = state_after_genesis(world);
        // The address deliberately embeds the attacker as its subject. Contract subjects are
        // not code-management authorities and therefore cannot mint invocation permissions.
        let contract = ContractAddress::derive(
            &state.network_id,
            &adjacent_owner,
            77,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let dataspace = DataSpaceId::new(7);
        let manifest_root: Permission =
            executor_permission::nexus::CanPublishSpaceDirectoryManifest { dataspace }.into();
        let contract_proposal_permission: Permission =
            executor_permission::governance::CanProposeContractDeployment {
                contract_address: contract.clone(),
            }
            .into();
        let runtime_proposal_permission: Permission =
            executor_permission::governance::CanProposeRuntimeUpgrade {
                abi_version: 1,
                abi_hash: [0xA5; 32],
            }
            .into();
        let ballot_permission: Permission =
            executor_permission::governance::CanSubmitGovernanceBallot {
                referendum_id: "grant-policy-referendum".to_owned(),
            }
            .into();
        let slash_permission: Permission =
            executor_permission::governance::CanSlashGovernanceLock {
                referendum_id: "grant-policy-referendum".to_owned(),
            }
            .into();
        let restitute_permission: Permission =
            executor_permission::governance::CanRestituteGovernanceLock {
                referendum_id: "grant-policy-referendum".to_owned(),
            }
            .into();
        let mut world = state.world.block();
        world.account_permissions.insert(
            legitimate_root.clone(),
            BTreeSet::from([
                executor_permission::smart_contract::CanManageSmartContractCode.into(),
                executor_permission::settlement::CanManageFxCorridors.into(),
                manifest_root,
                contract_proposal_permission.clone(),
                runtime_proposal_permission.clone(),
                ballot_permission.clone(),
                slash_permission.clone(),
                restitute_permission.clone(),
            ]),
        );
        world.commit();
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        seed_owner_permission_contract(
            &mut state_transaction,
            &contract,
            &legitimate_root,
            Hash::new(b"scoped contract capability fixture"),
        );
        Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                legitimate_root.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(legitimate_root.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ))
        .execute(&legitimate_root, &mut state_transaction)
        .expect("seed trigger authority");
        let alias_scope = AccountAliasPermissionScope::Domain(governed_domain.clone());
        let asset_alias_scope =
            executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Domain(
                governed_domain.clone(),
            );
        let program_id = FeeSponsorProgramId::new(
            legitimate_root.clone(),
            "root_program".parse().expect("program name"),
        );
        let policy_id: Name = "root_policy".parse().expect("policy name");
        // `false` means that the permission intentionally has no ownership-derived root and must
        // be bootstrapped once, after which only exact holders may propagate it.
        let cases: Vec<(&str, Permission, bool)> = vec![
            (
                "CanUnregisterDomain",
                executor_permission::domain::CanUnregisterDomain {
                    domain: governed_domain.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyDomainMetadata",
                executor_permission::domain::CanModifyDomainMetadata {
                    domain: governed_domain.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanRegisterAccount",
                executor_permission::account::CanRegisterAccount {
                    domain: governed_domain.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanUnregisterAccount",
                executor_permission::account::CanUnregisterAccount {
                    account: legitimate_root.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyAccountMetadata",
                executor_permission::account::CanModifyAccountMetadata {
                    account: legitimate_root.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanReplaceAccountController",
                executor_permission::account::CanReplaceAccountController {
                    account: legitimate_root.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanResolveAccountAlias",
                executor_permission::account::CanResolveAccountAlias {
                    scope: alias_scope.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanDelegateAccountAliasResolution",
                executor_permission::account::CanDelegateAccountAliasResolution {
                    scope: alias_scope.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanManageAccountAlias",
                executor_permission::account::CanManageAccountAlias { scope: alias_scope }.into(),
                true,
            ),
            (
                "CanManageAssetDefinitionAlias",
                executor_permission::asset_definition::CanManageAssetDefinitionAlias {
                    scope: asset_alias_scope,
                }
                .into(),
                true,
            ),
            (
                "CanUnregisterAssetDefinition",
                executor_permission::asset_definition::CanUnregisterAssetDefinition {
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyAssetDefinitionMetadata",
                executor_permission::asset_definition::CanModifyAssetDefinitionMetadata {
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanManageAssetDefinitionConfidentialPolicy",
                executor_permission::asset_definition::CanManageAssetDefinitionConfidentialPolicy {
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanMintAssetWithDefinition",
                executor_permission::asset::CanMintAssetWithDefinition {
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanBurnAssetWithDefinition",
                executor_permission::asset::CanBurnAssetWithDefinition {
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanTransferAssetWithDefinition",
                executor_permission::asset::CanTransferAssetWithDefinition {
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyAssetMetadataWithDefinition",
                executor_permission::asset::CanModifyAssetMetadataWithDefinition {
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanSetAssetTransferAvailability",
                executor_permission::asset::CanSetAssetTransferAvailability {
                    account: adjacent_owner.clone(),
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanSetAssetTransferDailyLimit",
                executor_permission::asset::CanSetAssetTransferDailyLimit {
                    asset_definition: asset_definition.clone(),
                    account_domain: AccountAliasDomain::new(
                        "retail".parse().expect("account alias domain"),
                    ),
                    account_dataspace: dataspace,
                }
                .into(),
                true,
            ),
            (
                "CanSetAssetHoldingLimit",
                executor_permission::asset::CanSetAssetHoldingLimit {
                    account: adjacent_owner.clone(),
                    asset_definition: asset_definition.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanMintAssetToAccount",
                executor_permission::asset::CanMintAssetToAccount {
                    asset_definition: asset_definition.clone(),
                    account: adjacent_owner.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanBurnAsset",
                executor_permission::asset::CanBurnAsset {
                    asset: root_asset.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanTransferAsset",
                executor_permission::asset::CanTransferAsset {
                    asset: root_asset.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyAssetMetadata",
                executor_permission::asset::CanModifyAssetMetadata {
                    asset: root_asset.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanRegisterNft",
                executor_permission::nft::CanRegisterNft {
                    domain: governed_domain.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanUnregisterNft",
                executor_permission::nft::CanUnregisterNft {
                    nft: nft_id.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanTransferNft",
                executor_permission::nft::CanTransferNft {
                    nft: nft_id.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyNftMetadata",
                executor_permission::nft::CanModifyNftMetadata {
                    nft: nft_id.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanRegisterTrigger",
                executor_permission::trigger::CanRegisterTrigger {
                    authority: legitimate_root.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanUnregisterTrigger",
                executor_permission::trigger::CanUnregisterTrigger {
                    trigger: trigger_id.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyTrigger",
                executor_permission::trigger::CanModifyTrigger {
                    trigger: trigger_id.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanExecuteTrigger",
                executor_permission::trigger::CanExecuteTrigger {
                    trigger: trigger_id.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanModifyTriggerMetadata",
                executor_permission::trigger::CanModifyTriggerMetadata {
                    trigger: trigger_id,
                }
                .into(),
                true,
            ),
            (
                "CanInvokeContractEntrypoint",
                executor_permission::smart_contract::CanInvokeContractEntrypoint {
                    contract: contract.clone(),
                    entrypoint: "hajimari".to_owned(),
                }
                .into(),
                true,
            ),
            (
                "CanUseContractPermission",
                executor_permission::smart_contract::CanUseContractPermission {
                    contract,
                    permission: "write".parse().unwrap(),
                }
                .into(),
                true,
            ),
            (
                "CanExecuteSettlement",
                executor_permission::settlement::CanExecuteSettlement {
                    debited_asset: root_asset,
                    settlement_id: "grant_policy_settlement".parse().expect("settlement id"),
                    intent_hash: Hash::new(b"grant-policy-settlement"),
                }
                .into(),
                true,
            ),
            (
                "CanSetFxCorridorPolicy",
                executor_permission::settlement::CanSetFxCorridorPolicy {
                    policy_id: policy_id.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanPublishSpaceDirectoryManifest",
                executor_permission::nexus::CanPublishSpaceDirectoryManifest { dataspace }.into(),
                false,
            ),
            (
                "CanPublishSpaceDirectoryManifestForUaid",
                executor_permission::nexus::CanPublishSpaceDirectoryManifestForUaid {
                    dataspace,
                    uaid: UniversalAccountId::from_hash(Hash::new(b"grant-policy-uaid")),
                }
                .into(),
                true,
            ),
            (
                "CanPublishSpaceDirectoryManifestForAccountDomain",
                executor_permission::nexus::CanPublishSpaceDirectoryManifestForAccountDomain {
                    dataspace,
                    // The attacker owns this domain, but only the explicit dataspace-wide parent
                    // is a delegation root for this permission.
                    domain: adjacent_domain,
                }
                .into(),
                true,
            ),
            (
                "CanManageFeeSponsorProgram",
                executor_permission::nexus::CanManageFeeSponsorProgram {
                    sponsor: legitimate_root.clone(),
                }
                .into(),
                true,
            ),
            (
                "CanEnrollFeeSponsorProgram",
                executor_permission::nexus::CanEnrollFeeSponsorProgram { program_id }.into(),
                true,
            ),
            (
                "CanProposeContractDeployment",
                contract_proposal_permission,
                false,
            ),
            (
                "CanProposeRuntimeUpgrade",
                runtime_proposal_permission,
                false,
            ),
            ("CanSubmitGovernanceBallot", ballot_permission, false),
            ("CanSlashGovernanceLock", slash_permission, false),
            ("CanRestituteGovernanceLock", restitute_permission, false),
        ];
        assert_eq!(cases.len(), 47, "update this table for every scoped arm");
        assert_eq!(
            cases
                .iter()
                .map(|(name, _, _)| *name)
                .collect::<BTreeSet<_>>()
                .len(),
            cases.len(),
            "permission cases must be unique",
        );
        for name in [
            "CanProposeContractDeployment",
            "CanProposeRuntimeUpgrade",
            "CanSubmitGovernanceBallot",
            "CanSlashGovernanceLock",
            "CanRestituteGovernanceLock",
        ] {
            let malformed = Permission::new(name.to_owned(), Json::new(()));
            let error = initial_permission_capability_root_authority(
                &state_transaction,
                &legitimate_root,
                &malformed,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("malformed scoped governance payload must fail closed");
            assert!(
                matches!(&error, ValidationFail::NotPermitted(message)
                    if message.contains(name) && message.contains("Invalid permission payload")),
                "unexpected malformed {name} rejection: {error:?}"
            );
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    &legitimate_root,
                    Grant::account_permission(malformed, adjacent_owner.clone()).into(),
                )
                .expect_err("malformed scoped governance grant must fail before storage");
            assert!(
                !state_transaction
                    .world
                    .account_permissions_iter(&adjacent_owner)
                    .expect("adjacent account permissions")
                    .any(|permission| permission.name() == name),
                "malformed {name} permission reached account storage"
            );
        }
        for (name, permission, expected_root) in &cases {
            assert_eq!(permission.name(), *name);
            assert_eq!(
                initial_permission_capability_root_authority(
                    &state_transaction,
                    &legitimate_root,
                    permission,
                )
                .expect("legitimate root lookup"),
                Some(*expected_root),
                "wrong capability root decision for {name}",
            );
            assert!(
                initial_permission_delegation_allowed(
                    &state_transaction,
                    &legitimate_root,
                    permission
                )
                .expect("legitimate delegation lookup"),
                "legitimate authority must be able to grant {name}",
            );
            assert_eq!(
                initial_permission_capability_root_authority(
                    &state_transaction,
                    &adjacent_owner,
                    permission,
                )
                .expect("adjacent-owner root lookup"),
                Some(false),
                "adjacent ownership must not root {name}",
            );
            assert!(
                !initial_permission_delegation_allowed(
                    &state_transaction,
                    &adjacent_owner,
                    permission
                )
                .expect("adjacent-owner delegation lookup"),
                "unprivileged authority must not self-grant {name}",
            );
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    &adjacent_owner,
                    Grant::account_permission(permission.clone(), adjacent_owner.clone()).into(),
                )
                .expect_err("adjacent owner must not self-grant a scoped permission");
        }
        for (name, permission, _) in &cases {
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    &legitimate_root,
                    Grant::account_permission(permission.clone(), adjacent_owner.clone()).into(),
                )
                .unwrap_or_else(|error| panic!("legitimate root could not grant {name}: {error}"));
            let holder_delegable = !matches!(
                *name,
                "CanResolveAccountAlias"
                    | "CanExecuteSettlement"
                    | "CanSetFxCorridorPolicy"
                    | "CanManageFeeSponsorProgram"
            );
            assert_eq!(
                initial_permission_delegation_allowed(
                    &state_transaction,
                    &adjacent_owner,
                    permission
                )
                .expect("exact-holder delegation lookup"),
                holder_delegable,
                "wrong exact-holder delegation decision for {name}",
            );
            if !holder_delegable {
                let error = super::Executor::Initial
                    .execute_instruction(
                        &mut state_transaction,
                        &adjacent_owner,
                        Grant::account_permission(permission.clone(), delegation_sink.clone())
                            .into(),
                    )
                    .expect_err("a leaf holder must not bypass its dedicated delegation root");
                assert!(
                    matches!(error, ValidationFail::NotPermitted(_)),
                    "{error:?}"
                );
                assert!(
                    !state_transaction
                        .world
                        .account_permissions_iter(&delegation_sink)
                        .expect("delegation sink permissions")
                        .any(|candidate| candidate == permission),
                    "unauthorized {name} grant reached storage",
                );
            }
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    &legitimate_root,
                    Revoke::account_permission(permission.clone(), adjacent_owner.clone()).into(),
                )
                .unwrap_or_else(|error| panic!("legitimate root could not revoke {name}: {error}"));
        }
    }
    #[test]
    fn initial_executor_rejects_noncanonical_governance_permission_selectors_before_storage() {
        use iroha_executor_data_model::permission::governance::{
            CanRestituteGovernanceLock, CanSlashGovernanceLock, CanSubmitGovernanceBallot,
        };
        let authority = checked_account_id();
        let destination = checked_account_id();
        let invalid_permissions = vec![
            Permission::from(CanSubmitGovernanceBallot {
                referendum_id: ".hidden-ballot".to_owned(),
            }),
            Permission::from(CanSlashGovernanceLock {
                referendum_id: "slash/alias".to_owned(),
            }),
            Permission::from(CanRestituteGovernanceLock {
                referendum_id: "restitution\nalias".to_owned(),
            }),
        ];
        let mut world = World::with(
            [],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(destination.clone()).build(&destination),
            ],
            [],
        );
        // Seed the malformed tokens as exact holdings so this regression proves that canonical
        // payload validation happens before the ordinary exact-holder delegation rule.
        world.account_permissions.insert(
            authority.clone(),
            invalid_permissions.iter().cloned().collect(),
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        let role_id: RoleId = "governance_selector_sink".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), authority.clone()))
            .execute(&authority, &mut state_transaction)
            .expect("seed empty role fixture");
        for permission in invalid_permissions {
            let permission_name: &str = permission.name().as_ref();
            for (path, instruction) in [
                (
                    "account",
                    Grant::account_permission(permission.clone(), destination.clone()).into(),
                ),
                (
                    "role",
                    Grant::role_permission(permission.clone(), role_id.clone()).into(),
                ),
            ] {
                let error = super::Executor::Initial
                    .execute_instruction(&mut state_transaction, &authority, instruction)
                    .unwrap_err();
                assert!(
                    matches!(&error, ValidationFail::NotPermitted(message)
                        if message.contains(permission_name)
                            && message.contains("canonical governance selector V1")),
                    "unexpected {path} grant rejection: {error:?}"
                );
            }
            assert!(
                !state_transaction
                    .world
                    .account_permissions_iter(&destination)
                    .expect("destination permissions")
                    .any(|stored| stored == &permission),
                "noncanonical permission reached account storage"
            );
            assert!(
                !state_transaction
                    .world
                    .roles()
                    .get(&role_id)
                    .expect("role fixture")
                    .permissions()
                    .any(|stored| stored == &permission),
                "noncanonical permission reached role storage"
            );
        }
    }
    #[test]
    fn initial_executor_requires_canonical_operational_governance_unit_permissions() {
        use iroha_executor_data_model::permission::governance::{
            CanManageConfidentialParams, CanManageConsensusKeys, CanManageRuntimeUpgrades,
        };

        let authority = checked_account_id();
        let destination = checked_account_id();
        let canonical_permissions = vec![
            Permission::from(CanManageRuntimeUpgrades),
            Permission::from(CanManageConsensusKeys),
            Permission::from(CanManageConfidentialParams),
        ];
        let mut world = World::with(
            [],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(destination.clone()).build(&destination),
            ],
            [],
        );
        world.account_permissions.insert(
            authority.clone(),
            canonical_permissions.iter().cloned().collect(),
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        let role_id: RoleId = "operational_governance_sink".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), authority.clone()))
            .execute(&authority, &mut state_transaction)
            .expect("seed empty role fixture");

        for canonical in canonical_permissions {
            let name = canonical.name().to_string();
            assert!(INITIAL_EXECUTOR_PERMISSION_NAMES.contains(&name.as_str()));
            validate_initial_permission_payload_constraints(&canonical)
                .unwrap_or_else(|error| panic!("canonical {name} token rejected: {error:?}"));
            for instruction in [
                Grant::account_permission(canonical.clone(), destination.clone()).into(),
                Grant::role_permission(canonical.clone(), role_id.clone()).into(),
            ] {
                super::Executor::Initial
                    .execute_instruction(&mut state_transaction, &authority, instruction)
                    .unwrap_or_else(|error| {
                        panic!("exact holder could not delegate {name}: {error}")
                    });
            }

            let malformed =
                Permission::new(name.clone(), Json::new("invented-scope-must-not-authorize"));
            for (path, instruction) in [
                (
                    "account",
                    Grant::account_permission(malformed.clone(), destination.clone()).into(),
                ),
                (
                    "role",
                    Grant::role_permission(malformed.clone(), role_id.clone()).into(),
                ),
            ] {
                let error = super::Executor::Initial
                    .execute_instruction(&mut state_transaction, &authority, instruction)
                    .expect_err("same-name non-unit payload must fail before storage");
                assert!(
                    matches!(&error, ValidationFail::NotPermitted(message)
                        if message.contains(&name) && message.contains("Invalid permission payload")),
                    "unexpected {path} {name} rejection: {error:?}",
                );
            }
            assert!(
                !state_transaction
                    .world
                    .account_permissions_iter(&destination)
                    .expect("destination permissions")
                    .any(|stored| stored == &malformed),
                "malformed {name} permission reached account storage",
            );
            assert!(
                !state_transaction
                    .world
                    .roles()
                    .get(&role_id)
                    .expect("role fixture")
                    .permissions()
                    .any(|stored| stored == &malformed),
                "malformed {name} permission reached role storage",
            );
        }
    }
    #[test]
    fn initial_executor_keeps_vpn_quote_issuer_leaf_manager_controlled() {
        let manager = checked_account_id();
        let issuer = checked_account_id();
        let destination = checked_account_id();
        let domain = DomainId::try_new("vpn_issuer_policy", "universal").expect("domain id");
        let manager_permission: Permission =
            executor_permission::soranet::CanManageSoranetVpnQuoteIssuers.into();
        let issuer_permission: Permission =
            executor_permission::soranet::CanIssueSoranetVpnQuote.into();
        let mut world = World::with(
            [Domain::new(domain).build(&manager)],
            [
                Account::new(manager.clone()).build(&manager),
                Account::new(issuer.clone()).build(&issuer),
                Account::new(destination.clone()).build(&destination),
            ],
            [],
        );
        world
            .account_permissions
            .insert(manager.clone(), BTreeSet::from([manager_permission]));
        world
            .account_permissions
            .insert(issuer.clone(), BTreeSet::from([issuer_permission.clone()]));
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        assert!(
            !initial_permission_delegation_allowed(&state_transaction, &issuer, &issuer_permission)
                .expect("issuer-leaf delegation decision")
        );
        assert!(
            initial_permission_delegation_allowed(&state_transaction, &manager, &issuer_permission)
                .expect("issuer-manager delegation decision")
        );
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &issuer,
                Grant::account_permission(issuer_permission.clone(), destination.clone()).into(),
            )
            .expect_err("an issuer leaf must not appoint another issuer");
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &manager,
                Grant::account_permission(issuer_permission.clone(), destination.clone()).into(),
            )
            .expect("the issuer manager may appoint an issuer");
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &manager,
                Revoke::account_permission(issuer_permission, destination).into(),
            )
            .expect("the issuer manager may revoke an issuer");
    }
    #[test]
    fn initial_executor_requires_direct_dpn_admin_for_dpn_permission_lifecycle() {
        use iroha_executor_data_model::permission::dpn::{
            DpnAdmin, DpnEprGuard, DpnInori, DpnSettlement, DpnUser,
        };

        let admin = checked_account_id();
        let leaf_holder = checked_account_id();
        let role_admin = checked_account_id();
        let destination = checked_account_id();
        let admin_permission: Permission = DpnAdmin.into();
        let leaf_permissions: Vec<Permission> = vec![
            DpnUser.into(),
            DpnInori.into(),
            DpnSettlement.into(),
            DpnEprGuard.into(),
        ];
        let mut world = World::with(
            [],
            [
                Account::new(admin.clone()).build(&admin),
                Account::new(leaf_holder.clone()).build(&leaf_holder),
                Account::new(role_admin.clone()).build(&role_admin),
                Account::new(destination.clone()).build(&destination),
            ],
            [],
        );
        world
            .account_permissions
            .insert(admin.clone(), BTreeSet::from([admin_permission.clone()]));
        world.account_permissions.insert(
            leaf_holder.clone(),
            leaf_permissions.iter().cloned().collect(),
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        let admin_role: RoleId = "initial_dpn_role_admin".parse().expect("role id");
        Register::role(
            Role::new(admin_role.clone(), admin.clone()).add_permission(admin_permission.clone()),
        )
        .execute(&admin, &mut state_transaction)
        .expect("seed DPN admin role");
        Grant::account_role(admin_role, role_admin.clone())
            .execute(&admin, &mut state_transaction)
            .expect("seed role-derived DPN admin");

        for permission in &leaf_permissions {
            for unauthorized in [&leaf_holder, &role_admin] {
                assert!(
                    !initial_permission_delegation_allowed(
                        &state_transaction,
                        unauthorized,
                        permission
                    )
                    .expect("DPN delegation decision"),
                    "only a direct DpnAdmin may manage {}",
                    permission.name(),
                );
                super::Executor::Initial
                    .execute_instruction(
                        &mut state_transaction,
                        unauthorized,
                        Grant::account_permission(permission.clone(), destination.clone()).into(),
                    )
                    .expect_err("a DPN leaf or role-derived admin must not delegate DPN markers");
            }
        }

        for permission in std::iter::once(&admin_permission).chain(&leaf_permissions) {
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    &admin,
                    Grant::account_permission(permission.clone(), destination.clone()).into(),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "direct DpnAdmin could not grant {}: {error}",
                        permission.name()
                    )
                });
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    &admin,
                    Revoke::account_permission(permission.clone(), destination.clone()).into(),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "direct DpnAdmin could not revoke {}: {error}",
                        permission.name()
                    )
                });
        }
    }
    #[test]
    fn initial_executor_exact_asset_alias_lifecycle_survives_clear_without_issuer_guessing() {
        use iroha_data_model::asset::AssetDefinitionAlias;
        use iroha_executor_data_model::permission::{
            account::{AccountAliasPermissionScope, CanManageAccountAlias},
            asset_definition::{
                AssetDefinitionAliasPermissionScope, CanManageAssetDefinitionAlias,
            },
        };
        let namespace_root = checked_account_id();
        let asset_owner = checked_account_id();
        let holder = checked_account_id();
        let unrelated = checked_account_id();
        let domain = DomainId::try_new("banka", "universal").expect("alias domain");
        let alias: AssetDefinitionAlias = "usd#banka.universal".parse().expect("asset alias");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain.clone(),
            "usd".parse().expect("asset definition name"),
        );
        let account_alias_permission: Permission = CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(domain.clone()),
        }
        .into();
        let namespace_permission: Permission = CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Domain(domain.clone()),
        }
        .into();
        let exact_permission: Permission = CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Alias(ResolvedAssetDefinitionAliasV1::new(
                alias.clone(),
                DataSpaceId::UNIVERSAL,
                definition_id.clone(),
            )),
        }
        .into();
        let mut world = World::with_assets(
            [Domain::new(domain).build(&namespace_root)],
            [
                Account::new(namespace_root.clone()).build(&namespace_root),
                Account::new(asset_owner.clone()).build(&asset_owner),
                Account::new(holder.clone()).build(&holder),
                Account::new(unrelated.clone()).build(&unrelated),
            ],
            [AssetDefinition::numeric(
                definition_id.clone(),
                "usd".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .with_alias(Some(alias.clone()))
            .build(&asset_owner)],
            [],
            [],
        );
        world.account_permissions.insert(
            asset_owner.clone(),
            BTreeSet::from([account_alias_permission]),
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            10_000,
            0,
        ));
        let mut state_transaction = block.transaction();
        let malformed_permission =
            Permission::new("CanManageAssetDefinitionAlias".to_owned(), Json::new(()));
        let malformed = Grant::account_permission(malformed_permission, holder.clone())
            .execute(&asset_owner, &mut state_transaction)
            .expect_err("Core must reject malformed built-in asset-alias permission payloads");
        assert!(malformed.to_string().contains("current live binding"));
        let mismatched_permission: Permission = CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Alias(ResolvedAssetDefinitionAliasV1::new(
                alias.clone(),
                DataSpaceId::new(7),
                definition_id.clone(),
            )),
        }
        .into();
        let mismatch = Grant::account_permission(mismatched_permission, holder.clone())
            .execute(&asset_owner, &mut state_transaction)
            .expect_err("Core must reject a text/ID pair that does not match the live catalog");
        assert!(mismatch.to_string().contains("current live binding"));
        let live_binding = state_transaction
            .world
            .asset_definition_alias_bindings
            .get(&definition_id)
            .cloned()
            .expect("fixture alias binding");
        {
            let binding = state_transaction
                .world
                .asset_definition_alias_bindings
                .get_mut(&definition_id)
                .expect("fixture alias binding");
            binding.lease_expiry_ms = Some(1);
            binding.grace_until_ms = None;
        }
        Grant::account_permission(exact_permission.clone(), holder.clone())
            .execute(&asset_owner, &mut state_transaction)
            .expect_err("Core must reject a grace-expired binding pending cleanup");
        state_transaction
            .world
            .asset_definition_alias_bindings
            .insert(definition_id.clone(), live_binding);
        let other_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("banka", "universal").expect("alias domain"),
            "eur".parse().expect("asset definition name"),
        );
        let rebound_target: Permission = CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Alias(ResolvedAssetDefinitionAliasV1::new(
                alias.clone(),
                DataSpaceId::UNIVERSAL,
                other_definition_id,
            )),
        }
        .into();
        Grant::account_permission(rebound_target, holder.clone())
            .execute(&asset_owner, &mut state_transaction)
            .expect_err("Core must reject an exact label capability for a different definition");
        for authority in [&namespace_root, &asset_owner] {
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    authority,
                    Grant::account_permission(exact_permission.clone(), holder.clone()).into(),
                )
                .expect_err(
                    "neither namespace ownership alone nor account-alias permission may grant an exact asset alias",
                );
        }
        state_transaction
            .world
            .add_account_permission(&asset_owner, namespace_permission);
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &asset_owner,
                Grant::account_permission(exact_permission.clone(), holder.clone()).into(),
            )
            .expect(
                "active asset owner with asset-alias namespace authority may grant exact scope",
            );
        let permission_role: RoleId = "asset_alias_permission_lifecycle".parse().expect("role id");
        Register::role(
            Role::new(permission_role.clone(), namespace_root.clone())
                .add_permission(exact_permission.clone()),
        )
        .execute(&namespace_root, &mut state_transaction)
        .expect("seed exact role permission while the matching binding is live");
        let membership_role: RoleId = "asset_alias_membership_lifecycle".parse().expect("role id");
        Register::role(
            Role::new(membership_role.clone(), namespace_root.clone())
                .add_permission(exact_permission.clone()),
        )
        .execute(&namespace_root, &mut state_transaction)
        .expect("seed exact role membership while the matching binding is live");
        Grant::account_role(membership_role.clone(), holder.clone())
            .execute(&namespace_root, &mut state_transaction)
            .expect("seed exact role membership revocation fixture");
        state_transaction
            .world
            .clear_asset_definition_alias(&definition_id);
        assert!(
            state_transaction
                .world
                .asset_definition_aliases()
                .get(&alias)
                .is_none(),
            "test must exercise revocation after the binding is cleared",
        );
        Grant::account_permission(exact_permission.clone(), unrelated.clone())
            .execute(&namespace_root, &mut state_transaction)
            .expect_err("Core must reject a new exact grant after the binding is cleared");
        for authority in [&unrelated, &holder, &asset_owner] {
            super::Executor::Initial
                .execute_instruction(
                    &mut state_transaction,
                    authority,
                    Revoke::account_permission(exact_permission.clone(), holder.clone()).into(),
                )
                .expect_err(
                    "unrelated, exact-holder, and former grant-issuer identities are not namespace roots",
                );
        }
        assert!(
            state_transaction
                .world
                .account_permissions_iter(&holder)
                .expect("holder permissions")
                .any(|permission| permission == &exact_permission),
            "failed revocations must preserve the exact capability",
        );
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &namespace_root,
                Revoke::account_permission(exact_permission.clone(), holder.clone()).into(),
            )
            .expect("native namespace root may revoke exact scope after clear");
        assert!(
            !state_transaction
                .world
                .account_permissions_iter(&holder)
                .expect("holder permissions")
                .any(|permission| permission == &exact_permission),
        );
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &namespace_root,
                Revoke::role_permission(exact_permission.clone(), permission_role.clone()).into(),
            )
            .expect("native namespace root may revoke exact role permission after clear");
        assert!(
            !state_transaction
                .world
                .roles()
                .get(&permission_role)
                .expect("permission role")
                .permissions()
                .any(|permission| permission == &exact_permission),
        );
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &namespace_root,
                Revoke::account_role(membership_role.clone(), holder.clone()).into(),
            )
            .expect("native namespace root may revoke exact role membership after clear");
        assert!(!authority_has_role(
            &state_transaction.world,
            &holder,
            &membership_role,
        ));
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn initial_executor_authorizes_every_permission_and_role_mutation_path() {
        let attacker = checked_account_id();
        let administrator = checked_account_id();
        let attacker_account = Account::new(attacker.clone()).build(&attacker);
        let administrator_account = Account::new(administrator.clone()).build(&administrator);
        let ordinary_permission: Permission =
            executor_permission::parameter::CanSetParameters.into();
        let genesis_only_permission: Permission =
            executor_permission::sccp::CanProposeSccpRouteGovernance.into();
        let mut world = World::with([], [attacker_account, administrator_account], []);
        world.account_permissions.insert(
            administrator.clone(),
            BTreeSet::from([ordinary_permission.clone(), genesis_only_permission.clone()]),
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        let ordinary_role: RoleId = "initial_executor_ordinary_role".parse().expect("role id");
        Register::role(
            Role::new(ordinary_role.clone(), administrator.clone())
                .add_permission(ordinary_permission.clone()),
        )
        .execute(&administrator, &mut state_transaction)
        .expect("seed ordinary role fixture");
        let genesis_only_role: RoleId = "initial_executor_genesis_only_role"
            .parse()
            .expect("role id");
        Register::role(
            Role::new(genesis_only_role.clone(), administrator.clone())
                .add_permission(genesis_only_permission.clone()),
        )
        .execute(&administrator, &mut state_transaction)
        .expect("seed governed role fixture");
        let denied = [
            Grant::account_permission(ordinary_permission.clone(), attacker.clone()).into(),
            Revoke::account_permission(ordinary_permission.clone(), administrator.clone()).into(),
            Grant::role_permission(ordinary_permission.clone(), ordinary_role.clone()).into(),
            Revoke::role_permission(ordinary_permission.clone(), ordinary_role.clone()).into(),
            Grant::account_role(ordinary_role.clone(), attacker.clone()).into(),
            Revoke::account_role(ordinary_role.clone(), administrator.clone()).into(),
            Unregister::role(ordinary_role.clone()).into(),
        ];
        for instruction in denied {
            super::Executor::Initial
                .execute_instruction(&mut state_transaction, &attacker, instruction)
                .expect_err("an unprivileged authority must not mutate permissions or roles");
        }
        assert!(
            !state_transaction
                .world
                .account_permissions_iter(&attacker)
                .expect("attacker permissions")
                .any(|permission| permission == &ordinary_permission)
        );
        assert!(!authority_has_role(
            &state_transaction.world,
            &attacker,
            &ordinary_role
        ));
        super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &administrator,
                Grant::account_permission(ordinary_permission.clone(), attacker.clone()).into(),
            )
            .expect("an exact holder may delegate an ordinary exact permission");
        assert!(
            state_transaction
                .world
                .account_permissions_iter(&attacker)
                .expect("attacker permissions")
                .any(|permission| permission == &ordinary_permission)
        );
        for instruction in [
            Grant::account_permission(genesis_only_permission.clone(), attacker.clone()).into(),
            Grant::account_role(genesis_only_role.clone(), attacker.clone()).into(),
        ] {
            super::Executor::Initial
                .execute_instruction(&mut state_transaction, &administrator, instruction)
                .expect_err(
                    "genesis-only authority must not be delegated directly or through a role",
                );
        }
        assert!(
            !state_transaction
                .world
                .account_permissions_iter(&attacker)
                .expect("attacker permissions")
                .any(|permission| permission == &genesis_only_permission)
        );
        assert!(!authority_has_role(
            &state_transaction.world,
            &attacker,
            &genesis_only_role
        ));
    }
    #[test]
    fn initial_executor_restricted_reader_cannot_mutate_direct_or_role_grants() {
        let holder = checked_account_id();
        let grant_destination = checked_account_id();
        let revoke_destination = checked_account_id();
        let exact: Permission = executor_permission::query::CanReadRestrictedDataspace {
            dataspace: DataSpaceId::new(10),
        }
        .into();
        let can_manage_roles: Permission = executor_permission::role::CanManageRoles.into();
        let mut world = World::with(
            [],
            [
                Account::new(holder.clone()).build(&holder),
                Account::new(grant_destination.clone()).build(&grant_destination),
                Account::new(revoke_destination.clone()).build(&revoke_destination),
            ],
            [],
        );
        world.account_permissions.insert(
            holder.clone(),
            BTreeSet::from([exact.clone(), can_manage_roles]),
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        let reader_role: RoleId = "restricted_reader_role".parse().expect("role id");
        Register::role(
            Role::new(reader_role.clone(), holder.clone()).add_permission(exact.clone()),
        )
        .execute(&holder, &mut state_transaction)
        .expect("seed restricted-reader role fixture");
        Grant::account_role(reader_role.clone(), revoke_destination.clone())
            .execute(&holder, &mut state_transaction)
            .expect("seed revocation membership fixture");
        let empty_role: RoleId = "empty_reader_role".parse().expect("role id");
        Register::role(Role::new(empty_role.clone(), holder.clone()))
            .execute(&holder, &mut state_transaction)
            .expect("seed empty role fixture");
        let attempted_registration: RoleId =
            "attempted_restricted_reader_role".parse().expect("role id");
        let denied = [
            (
                "direct grant",
                Grant::account_permission(exact.clone(), grant_destination.clone()).into(),
            ),
            (
                "direct revoke",
                Revoke::account_permission(exact.clone(), holder.clone()).into(),
            ),
            (
                "role membership grant",
                Grant::account_role(reader_role.clone(), grant_destination.clone()).into(),
            ),
            (
                "role membership revoke",
                Revoke::account_role(reader_role.clone(), revoke_destination.clone()).into(),
            ),
            (
                "role permission grant",
                Grant::role_permission(exact.clone(), empty_role.clone()).into(),
            ),
            (
                "role permission revoke",
                Revoke::role_permission(exact.clone(), reader_role.clone()).into(),
            ),
            (
                "role registration",
                InstructionBox::from(RegisterBox::Role(Register::role(
                    Role::new(attempted_registration.clone(), holder.clone())
                        .add_permission(exact.clone()),
                ))),
            ),
        ];
        for (path, instruction) in denied {
            let error = super::Executor::Initial
                .execute_instruction(&mut state_transaction, &holder, instruction)
                .expect_err("restricted-read permission mutations must be genesis-only");
            assert!(matches!(error, ValidationFail::NotPermitted(_)));
            assert!(
                error.to_string().contains("CanReadRestrictedDataspace"),
                "unexpected rejection for {path}: {error}",
            );
        }
        let grant_destination_permissions = state_transaction
            .world
            .account_permissions_iter(&grant_destination)
            .expect("grant destination permissions")
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(!grant_destination_permissions.contains(&exact));
        assert!(
            state_transaction
                .world
                .account_permissions_iter(&holder)
                .expect("holder permissions")
                .any(|permission| permission == &exact),
            "rejected direct revoke must leave the exact permission in place",
        );
        assert!(!authority_has_role(
            &state_transaction.world,
            &grant_destination,
            &reader_role,
        ));
        assert!(
            authority_has_role(&state_transaction.world, &revoke_destination, &reader_role,),
            "rejected role revoke must leave membership in place",
        );
        assert!(
            !state_transaction
                .world
                .roles()
                .get(&empty_role)
                .expect("empty role")
                .permissions()
                .any(|permission| permission == &exact),
            "rejected role-permission grant must not mutate the role",
        );
        assert!(
            state_transaction
                .world
                .roles()
                .get(&reader_role)
                .expect("reader role")
                .permissions()
                .any(|permission| permission == &exact),
            "rejected role-permission revoke must leave the token in place",
        );
        assert!(
            state_transaction
                .world
                .roles()
                .get(&attempted_registration)
                .is_none(),
            "rejected role registration must not create the role",
        );
    }
    #[test]
    fn lifecycle_runtime_context_rejects_binding_mutations_for_every_executor_path() {
        let subject = checked_account_id();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &subject,
            404,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let instructions = [
            InstructionBox::from(
                iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
                    contract_address: contract_address.clone(),
                    expected_revision: 1,
                    code_hash: Hash::new(b"executor-lifecycle-activation"),
                },
            ),
            InstructionBox::from(
                iroha_data_model::isi::smart_contract_code::DeactivateContractInstance {
                    contract_address: contract_address.clone(),
                    expected_revision: 1,
                    reason: Some("executor lifecycle guard".to_owned()),
                },
            ),
            InstructionBox::from(
                iroha_data_model::isi::smart_contract_code::CommitContractDeployment {
                    expected_deploy_nonce: 404,
                    contract_address: contract_address.clone(),
                    code_hash: Hash::new(b"executor-lifecycle-atomic-deployment"),
                    contract_alias: "payments::universal".parse().expect("contract alias"),
                    lease_expiry_ms: None,
                    expected_previous_contract_address: None,
                },
            ),
        ];
        for entrypoint in ["hajimari", "始まり", "kaizen", "改善"] {
            let context = ContractRuntimeExecutionContext {
                contract_address: contract_address.clone(),
                contract_subject: contract_address.subject_id(),
                contract_alias: None,
                entrypoint: entrypoint.to_owned(),
            };
            for instruction in &instructions {
                assert!(matches!(
                    ensure_lifecycle_hook_cannot_mutate_contract_binding(
                        Some(&context),
                        instruction,
                    ),
                    Err(ValidationFail::NotPermitted(_))
                ));
            }
        }
        let ordinary_context = ContractRuntimeExecutionContext {
            contract_address,
            contract_subject: subject,
            contract_alias: None,
            entrypoint: "kotoage".to_owned(),
        };
        for instruction in &instructions {
            ensure_lifecycle_hook_cannot_mutate_contract_binding(
                Some(&ordinary_context),
                instruction,
            )
            .expect("ordinary kotoage dispatch is governed by the instruction permission layer");
        }
    }
    #[test]
    fn contract_runtime_permission_boundary_precedes_user_executor_dispatch() {
        let deployer = checked_account_id();
        let destination = checked_account_id();
        let state = state_after_genesis(World::with(
            [],
            [
                Account::new(deployer.clone()).build(&deployer),
                Account::new(destination.clone()).build(&destination),
            ],
            [],
        ));
        let contract_address =
            ContractAddress::derive(&state.network_id, &deployer, 505, DataSpaceId::UNIVERSAL)
                .expect("contract address");
        let contract_subject = contract_address.subject_id();
        let context = ContractRuntimeExecutionContext {
            contract_subject: contract_subject.clone(),
            contract_address: contract_address.clone(),
            contract_alias: None,
            entrypoint: "main".to_owned(),
        };
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        state_transaction.world.accounts.insert(
            contract_subject.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        state_transaction.tx_call_hash = Some(Hash::prehashed([0xD8; Hash::LENGTH]));
        let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(
            generate_denied_program("user executor reached"),
        ));
        let executor = super::Executor::UserProvided(
            super::LoadedExecutor::load(raw).expect("load denying executor"),
        );
        let role_id: RoleId = "contract_forbidden_role".parse().expect("role id");
        let role = Role::new(role_id.clone(), destination.clone())
            .add_permission(executor_permission::parameter::CanSetParameters);
        let register_role = Register::role(role);
        let unregister_role = Unregister::role(role_id.clone());
        let ordinary_permission: Permission =
            executor_permission::parameter::CanSetParameters.into();
        let boxed_forbidden = vec![
            InstructionBox::from(RegisterBox::Role(register_role.clone())),
            InstructionBox::from(UnregisterBox::Role(unregister_role.clone())),
            Grant::account_role(role_id.clone(), destination.clone()).into(),
            Revoke::account_role(role_id.clone(), destination.clone()).into(),
            Grant::role_permission(ordinary_permission.clone(), role_id.clone()).into(),
            Revoke::role_permission(ordinary_permission.clone(), role_id.clone()).into(),
            Grant::account_permission(ordinary_permission.clone(), destination.clone()).into(),
            Revoke::account_permission(ordinary_permission.clone(), destination.clone()).into(),
        ];
        let concrete_forbidden = vec![
            concrete_instruction_box!(Register<Role>, register_role),
            concrete_instruction_box!(Unregister<Role>, unregister_role),
            concrete_instruction_box!(
                Grant<RoleId, Account>,
                Grant::account_role(role_id.clone(), destination.clone())
            ),
            concrete_instruction_box!(
                Revoke<RoleId, Account>,
                Revoke::account_role(role_id.clone(), destination.clone())
            ),
            concrete_instruction_box!(
                Grant<Permission, Role>,
                Grant::role_permission(ordinary_permission.clone(), role_id.clone())
            ),
            concrete_instruction_box!(
                Revoke<Permission, Role>,
                Revoke::role_permission(ordinary_permission.clone(), role_id.clone())
            ),
            concrete_instruction_box!(
                Grant<Permission, Account>,
                Grant::account_permission(ordinary_permission.clone(), destination.clone())
            ),
            concrete_instruction_box!(
                Revoke<Permission, Account>,
                Revoke::account_permission(ordinary_permission, destination.clone())
            ),
        ];
        for instruction in boxed_forbidden.into_iter().chain(concrete_forbidden) {
            let error = executor
                .execute_instruction_with_contract_runtime_context(
                    &mut state_transaction,
                    &contract_subject,
                    instruction,
                    Some(&context),
                )
                .expect_err("the common contract boundary must reject before user executor IVM");
            assert!(
                !error.to_string().contains("user executor reached"),
                "forbidden mutation reached the user executor: {error}",
            );
            assert!(matches!(error, ValidationFail::NotPermitted(_)));
        }
        let borrowed_role_grant: InstructionBox =
            Grant::account_role(role_id, destination.clone()).into();
        let error = executor
            .execute_borrowed_overlay_instruction(
                &mut state_transaction,
                &contract_subject,
                &borrowed_role_grant,
                Some(&context),
            )
            .expect_err("the borrowed path must apply the same common contract boundary");
        assert!(
            !error.to_string().contains("user executor reached"),
            "borrowed role mutation reached the user executor: {error}",
        );
        seed_owner_permission_contract(
            &mut state_transaction,
            &contract_address,
            &deployer,
            Hash::new(b"contract permission boundary"),
        );
        let exact: Permission = executor_permission::smart_contract::CanUseContractPermission {
            contract: contract_address.clone(),
            permission: "write".parse().unwrap(),
        }
        .into();
        state_transaction
            .world
            .add_account_permission(&contract_subject, exact.clone());
        let error = executor
            .execute_instruction_with_contract_runtime_context(
                &mut state_transaction,
                &contract_subject,
                Grant::account_permission(exact, destination.clone()).into(),
                Some(&context),
            )
            .expect_err("the denying user executor must receive an exact bound token");
        assert!(
            error.to_string().contains("user executor reached"),
            "an exact bound token should pass the common boundary: {error}",
        );
        let inconsistent_context = ContractRuntimeExecutionContext {
            contract_subject: destination.clone(),
            contract_address: contract_address.clone(),
            contract_alias: None,
            entrypoint: "main".to_owned(),
        };
        let inconsistent_exact: Permission =
            executor_permission::smart_contract::CanUseContractPermission {
                contract: contract_address.clone(),
                permission: "write".parse().unwrap(),
            }
            .into();
        let error = executor
            .execute_instruction_with_contract_runtime_context(
                &mut state_transaction,
                &destination,
                Grant::account_permission(inconsistent_exact, destination.clone()).into(),
                Some(&inconsistent_context),
            )
            .expect_err("an inconsistent contract subject/address context must fail closed");
        assert!(
            !error.to_string().contains("user executor reached"),
            "inconsistent contract context reached the user executor: {error}",
        );
        let sibling_address =
            ContractAddress::derive(&state.network_id, &deployer, 506, DataSpaceId::UNIVERSAL)
                .expect("sibling contract address");
        let sibling: Permission = executor_permission::smart_contract::CanUseContractPermission {
            contract: sibling_address,
            permission: "write".parse().unwrap(),
        }
        .into();
        let error = executor
            .execute_instruction_with_contract_runtime_context(
                &mut state_transaction,
                &contract_subject,
                Grant::account_permission(sibling, destination).into(),
                Some(&context),
            )
            .expect_err("a contract may not delegate a sibling contract token");
        assert!(
            !error.to_string().contains("user executor reached"),
            "sibling token reached the user executor: {error}",
        );
    }
    // These private-call fixtures supply post-verification replay metadata.
    // Their real signatures select the IvmProved root kind, but neither the Halt
    // envelope nor the supplied commitments claim cryptographic replay verification.
    fn supplied_replay_fixture_source(
        state: &State,
        authority: &AccountId,
        keypair: &KeyPair,
        overlay: Vec<InstructionBox>,
    ) -> SignedTransaction {
        let mut bytecode = ivm::ProgramMetadata::default().encode();
        bytecode.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000)),
        )
        .with_executable(Executable::IvmProved(
            iroha_data_model::transaction::IvmProved {
                bytecode: IvmBytecode::from_compiled(bytecode),
                overlay: overlay.into(),
                events_commitment: Hash::new(b"events"),
                gas_policy_commitment: Hash::new(b"supplied replay gas-policy fixture"),
            },
        ))
        .sign(keypair.private_key())
    }

    fn bind_supplied_replay_fixture_root(
        transaction: &mut StateTransaction<'_, '_>,
        signed: &SignedTransaction,
        replay: &crate::pipeline::overlay::IvmProvedReplay,
    ) {
        assert!(matches!(signed.instructions(), Executable::IvmProved(_)));
        assert_eq!(
            transaction.current_dataspace_id,
            transaction.world.current_dataspace_id
        );
        transaction.current_tx_hash = Some(signed.hash());
        transaction.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
        transaction
            .begin_execution_effect_budget(signed)
            .expect("bind exact supplied-replay root");
        // Explicit supplied post-verification handoff, not measured VM work.
        transaction.last_tx_gas_used = replay.gas_used;
        transaction
            .record_execution_fee_instructions(
                replay
                    .queued
                    .iter()
                    .filter(|effect| effect.instruction().is_some())
                    .count(),
                replay.gas_used,
            )
            .expect("bind supplied replay fee work");
    }

    #[test]
    fn proved_empty_overlay_accounts_verified_replay_gas() {
        let keypair = checked_keypair();
        let authority = AccountId::new(keypair.public_key().clone());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = query::store::LiveQueryStore::start_test();
        let state = State::new_for_testing(World::default(), kura, query_handle);
        let tx = supplied_replay_fixture_source(&state, &authority, &keypair, Vec::new());
        let replay_gas = 40_000;
        let (axt_descriptor, axt_binding) = ivm::axt::AxtDescriptor::builder()
            .dataspace(DataSpaceId::UNIVERSAL)
            .build_with_binding()
            .expect("AXT descriptor");
        let mut completed_axt = ivm::axt::HostAxtState::new(axt_descriptor, axt_binding);
        completed_axt
            .record_proof(
                DataSpaceId::UNIVERSAL,
                Some(ivm::axt::ProofBlob {
                    payload: vec![1],
                    expiry_slot: None,
                }),
                None,
            )
            .expect("record AXT proof");
        completed_axt
            .validate_commit()
            .expect("completed AXT fixture");
        let replay = crate::pipeline::overlay::IvmProvedReplay {
            queued: Vec::new(),
            completed_axt: vec![completed_axt],
            durable_state_overlay: BTreeMap::new(),
            durable_state_authorizations: BTreeMap::new(),
            access_log: None,
            gas_used: replay_gas,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut state_tx = block.transaction();
        bind_supplied_replay_fixture_root(&mut state_tx, &tx, &replay);
        super::Executor::Initial
            .execute_metered_instructions(
                &mut state_tx,
                &authority,
                &tx,
                Vec::new(),
                Some(replay),
                None,
                None,
                0,
                Some(50_000),
                true,
                None,
                None,
                true,
            )
            .expect("empty proved overlay should retain replay gas");
        state_tx
            .finish_execution_effect_budget()
            .expect("close supplied-replay root");
        assert_eq!(state_tx.last_tx_gas_used, replay_gas);
        state_tx.apply();
        assert_eq!(
            block.axt_envelopes().len(),
            1,
            "direct proved replay must persist completed AXT envelopes"
        );
        assert_eq!(block.axt_envelopes()[0].binding.as_bytes(), &axt_binding);
    }
    #[test]
    fn proved_replay_applies_durable_state_with_exact_per_path_authorization() {
        let keypair = checked_keypair();
        let authority = AccountId::new(keypair.public_key().clone());
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").expect("valid test domain"))
                .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let state = state_after_genesis(World::with([domain], [account], []));
        let contract_address =
            ContractAddress::derive(&state.network_id, &authority, 405, DataSpaceId::UNIVERSAL)
                .expect("contract address");
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                "seiyaku ProvedDurable { kotoage fn write() authorize(anyone) {} }",
            )
            .expect("compile exact replay authorization");
        let code_hash = ivm::contract_code_hash(&program);
        bind_executor_test_contract_after_genesis(&state, &contract_address, &authority, code_hash);
        {
            let mut world = state.world.block();
            world.contract_manifests.insert(
                iroha_data_model::smart_contract::ContractArtifactId::for_address(
                    &contract_address,
                    code_hash,
                )
                .unwrap(),
                manifest
                    .try_signed(
                        manifest_signing.context(),
                        manifest_signing.max_frame_bytes(),
                        &keypair,
                    )
                    .expect("sign replay authorization manifest"),
            );
            world.commit();
        }
        let tx = supplied_replay_fixture_source(&state, &authority, &keypair, Vec::new());
        let authorization = ContractEntrypointAuthorizationSnapshot::new(
            authority.clone(),
            "write".to_owned(),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            &code::BoundContractIdentity {
                lifecycle_revision: 1,
                contract_address: contract_address.clone(),
                contract_alias: None,
                contract_alias_binding: None,
                code_hash,
            },
        );
        let runtime_context = ContractRuntimeExecutionContext {
            contract_subject: contract_address.subject_id(),
            contract_address: contract_address.clone(),
            contract_alias: None,
            entrypoint: "write".to_owned(),
        };
        let digest = hex::encode(Hash::new(contract_address.to_string().as_bytes()).as_ref());
        let marker: StatePath = format!("sc/{digest}/Values/fixture")
            .parse()
            .expect("scoped durable state marker");
        let stored = vec![0xA5];
        let replay = crate::pipeline::overlay::IvmProvedReplay {
            queued: Vec::new(),
            completed_axt: Vec::new(),
            durable_state_overlay: BTreeMap::from([(marker.clone(), Some(stored.clone()))]),
            durable_state_authorizations: BTreeMap::from([(
                marker.clone(),
                Some(authorization.clone()),
            )]),
            access_log: None,
            gas_used: 0,
        };
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut state_tx = block.transaction();
        bind_supplied_replay_fixture_root(&mut state_tx, &tx, &replay);
        super::Executor::Initial
            .execute_metered_instructions(
                &mut state_tx,
                &authority,
                &tx,
                Vec::new(),
                Some(replay),
                Some(&runtime_context),
                Some(&authorization),
                0,
                Some(50_000),
                true,
                None,
                None,
                true,
            )
            .expect("proved replay applies its authorized durable write");
        state_tx
            .finish_execution_effect_budget()
            .expect("close supplied-replay root");
        assert_eq!(
            state_tx.world.smart_contract_state.get(&marker),
            Some(&stored)
        );
        drop(state_tx);
        drop(block);
        let malformed_replay = crate::pipeline::overlay::IvmProvedReplay {
            queued: Vec::new(),
            completed_axt: Vec::new(),
            durable_state_overlay: BTreeMap::from([(marker.clone(), Some(stored))]),
            durable_state_authorizations: BTreeMap::new(),
            access_log: None,
            gas_used: 0,
        };
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut malformed_block = state.block(header);
        let mut malformed_tx = malformed_block.transaction();
        bind_supplied_replay_fixture_root(&mut malformed_tx, &tx, &malformed_replay);
        let error = super::Executor::Initial
            .execute_metered_instructions(
                &mut malformed_tx,
                &authority,
                &tx,
                Vec::new(),
                Some(malformed_replay),
                Some(&runtime_context),
                Some(&authorization),
                0,
                Some(50_000),
                true,
                None,
                None,
                true,
            )
            .expect_err("post-verification replay metadata must retain an exact authorization map");
        malformed_tx
            .finish_execution_effect_budget()
            .expect("close supplied-replay root");
        assert!(matches!(
            error,
            ValidationFail::InternalError(message)
                if message.contains("structurally inconsistent")
        ));
        assert!(
            malformed_tx
                .world
                .smart_contract_state
                .get(&marker)
                .is_none(),
            "malformed replay authorization metadata must apply zero durable writes"
        );
        drop(malformed_tx);
        drop(malformed_block);
        let foreign_digest = hex::encode(Hash::new(b"foreign contract namespace").as_ref());
        let foreign_path: StatePath = format!("sc/{foreign_digest}/Values/fixture")
            .parse()
            .expect("foreign scoped durable state marker");
        let foreign_replay = crate::pipeline::overlay::IvmProvedReplay {
            queued: Vec::new(),
            completed_axt: Vec::new(),
            durable_state_overlay: BTreeMap::from([(foreign_path.clone(), Some(vec![0x5A]))]),
            durable_state_authorizations: BTreeMap::from([(
                foreign_path.clone(),
                Some(authorization.clone()),
            )]),
            access_log: None,
            gas_used: 0,
        };
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut foreign_block = state.block(header);
        let mut foreign_tx = foreign_block.transaction();
        bind_supplied_replay_fixture_root(&mut foreign_tx, &tx, &foreign_replay);
        let error = super::Executor::Initial
            .execute_metered_instructions(
                &mut foreign_tx,
                &authority,
                &tx,
                Vec::new(),
                Some(foreign_replay),
                Some(&runtime_context),
                Some(&authorization),
                0,
                Some(50_000),
                true,
                None,
                None,
                true,
            )
            .expect_err("one contract's snapshot must not authorize another state namespace");
        foreign_tx
            .finish_execution_effect_budget()
            .expect("close supplied-replay root");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message)
                if message.contains("does not belong to its contract authorization snapshot")
        ));
        assert!(
            foreign_tx
                .world
                .smart_contract_state
                .get(&foreign_path)
                .is_none(),
            "a foreign per-path snapshot must apply zero durable writes"
        );
    }
    #[test]
    fn proved_replay_rejects_durable_state_without_root_authorization_before_effects() {
        let keypair = checked_keypair();
        let authority = AccountId::new(keypair.public_key().clone());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = query::store::LiveQueryStore::start_test();
        let state = State::new_for_testing(World::default(), kura, query_handle);
        let tx = supplied_replay_fixture_source(&state, &authority, &keypair, Vec::new());
        let marker: StatePath = "proved_replay_forbidden_marker"
            .parse()
            .expect("durable state marker");
        let replay = crate::pipeline::overlay::IvmProvedReplay {
            queued: Vec::new(),
            completed_axt: Vec::new(),
            durable_state_overlay: BTreeMap::from([(marker.clone(), Some(vec![0xA5]))]),
            durable_state_authorizations: BTreeMap::from([(marker.clone(), None)]),
            access_log: None,
            gas_used: 0,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut state_tx = block.transaction();
        bind_supplied_replay_fixture_root(&mut state_tx, &tx, &replay);
        let error = super::Executor::Initial
            .execute_metered_instructions(
                &mut state_tx,
                &authority,
                &tx,
                Vec::new(),
                Some(replay),
                None,
                None,
                0,
                Some(50_000),
                true,
                None,
                None,
                true,
            )
            .expect_err("proved replay durable state writes require root authorization");
        state_tx
            .finish_execution_effect_budget()
            .expect("close supplied-replay root");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message)
                if message.contains("missing its root authorization snapshot")
        ));
        assert!(
            state_tx.world.smart_contract_state.get(&marker).is_none(),
            "rejected proved replay must apply no durable state"
        );
    }
    #[test]
    fn supplied_replay_group_limits_preserve_work_and_refuse_before_effects() {
        let instructions: Vec<InstructionBox> = ["replay_effect_first", "replay_effect_second"]
            .into_iter()
            .map(|key| {
                SetKeyValue::account(ALICE_ID.clone(), key.parse().unwrap(), Json::new(true)).into()
            })
            .collect();
        let exact_bytes: u64 = instructions
            .iter()
            .map(|instruction| u64::try_from(instruction.encode().len()).unwrap())
            .sum();
        let replay_gas = 40_000;
        for (count_cap, byte_cap, expected_error) in [
            (2, 0, None),
            (
                1,
                0,
                Some("overlay exceeds max instructions: 2 > 1".to_owned()),
            ),
            (0, exact_bytes, None),
            (
                0,
                exact_bytes - 1,
                Some(format!(
                    "overlay exceeds max bytes: more than {}",
                    exact_bytes - 1
                )),
            ),
        ] {
            let state = state_after_genesis(World::with(
                [],
                [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
                [],
            ));
            let signed = supplied_replay_fixture_source(
                &state,
                &ALICE_ID,
                &ALICE_KEYPAIR,
                instructions.clone(),
            );
            let replay = crate::pipeline::overlay::IvmProvedReplay {
                queued: instructions
                    .iter()
                    .cloned()
                    .map(
                        |instruction| crate::smartcontracts::ivm::host::QueuedEffect {
                            payload:
                                crate::smartcontracts::ivm::host::QueuedEffectPayload::Instruction(
                                    instruction,
                                ),
                            authority: ALICE_ID.clone(),
                            contract_runtime_context: None,
                            entrypoint_authorization: None,
                        },
                    )
                    .collect(),
                completed_axt: Vec::new(),
                durable_state_overlay: BTreeMap::new(),
                durable_state_authorizations: BTreeMap::new(),
                access_log: None,
                gas_used: replay_gas,
            };
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                Some(
                    state
                        .view()
                        .latest_block_hash()
                        .expect("genuine genesis parent"),
                ),
                None,
                0,
                0,
            ));
            let fragments = block.committed_fragment_count();
            let mut transaction = block.transaction();
            transaction.pipeline.overlay_max_instructions = count_cap;
            transaction.pipeline.overlay_max_bytes = byte_cap;
            bind_supplied_replay_fixture_root(&mut transaction, &signed, &replay);
            let result = super::Executor::Initial.execute_metered_instructions(
                &mut transaction,
                &ALICE_ID,
                &signed,
                instructions.clone(),
                Some(replay),
                None,
                None,
                0,
                Some(50_000),
                true,
                None,
                None,
                true,
            );
            let finished = transaction.finish_execution_effect_budget();
            assert_eq!(
                transaction.last_tx_gas_used, replay_gas,
                "supplied completed replay work survives later group admission refusal"
            );
            let rejected = expected_error.is_some();
            if let Some(expected) = expected_error {
                for error in [
                    result.expect_err("one-below replay group refuses"),
                    finished.expect_err("refusal remains sticky at close"),
                ] {
                    assert!(
                        matches!(error, ValidationFail::NotPermitted(ref actual) if actual == &expected),
                        "{error:?}"
                    );
                }
                assert!(transaction.execution_effect_limit_exceeded());
                for key in ["replay_effect_first", "replay_effect_second"] {
                    assert!(
                        transaction
                            .world
                            .account(&ALICE_ID)
                            .unwrap()
                            .metadata()
                            .get(key)
                            .is_none(),
                        "refused replay group must execute no first instruction"
                    );
                }
                drop(transaction);
            } else {
                result.expect("exact replay group fits");
                finished.expect("exact replay root closes");
                assert!(!transaction.execution_effect_limit_exceeded());
                for key in ["replay_effect_first", "replay_effect_second"] {
                    assert_eq!(
                        transaction
                            .world
                            .account(&ALICE_ID)
                            .unwrap()
                            .metadata()
                            .get(key),
                        Some(&Json::new(true))
                    );
                }
                transaction.apply();
            }
            assert_eq!(
                block.committed_fragment_count(),
                fragments + usize::from(!rejected)
            );
            for key in ["replay_effect_first", "replay_effect_second"] {
                assert_eq!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get(key)
                        .is_some(),
                    !rejected
                );
            }
        }
    }
    fn make_peer_id() -> iroha_model_base::peer::PeerId {
        let kp = checked_keypair_with_algorithm(Algorithm::BlsNormal);
        iroha_model_base::peer::PeerId::new(kp.public_key().clone())
    }
    #[test]
    fn checked_keypair_helpers_preserve_requested_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        assert_eq!(
            checked_keypair_with_algorithm(Algorithm::Ed25519).algorithm(),
            Algorithm::Ed25519
        );
        assert_eq!(
            checked_keypair_with_algorithm(Algorithm::BlsNormal).algorithm(),
            Algorithm::BlsNormal
        );
    }
    fn alice() -> AccountId {
        iroha_test_samples::ALICE_ID.clone()
    }
    fn pipeline_fee_state_fixture(
        state_constructor: fn(World) -> State,
    ) -> (
        State,
        KeyPair,
        AccountId,
        AccountId,
        AccountId,
        AssetDefinitionId,
        AssetDefinitionId,
    ) {
        let (world, keypair, authority, initial_tech, updated_tech, fee_asset, alternate_asset) =
            pipeline_fee_world_fixture();
        (
            state_constructor(world),
            keypair,
            authority,
            initial_tech,
            updated_tech,
            fee_asset,
            alternate_asset,
        )
    }
    fn pipeline_fee_world_fixture() -> (
        World,
        KeyPair,
        AccountId,
        AccountId,
        AccountId,
        AssetDefinitionId,
        AssetDefinitionId,
    ) {
        let (authority, authority_keypair) = gen_account_in("pipeline_fee");
        let (initial_tech, _) = gen_account_in("pipeline_fee");
        let (updated_tech, _) = gen_account_in("pipeline_fee");
        let domain_id =
            DomainId::try_new("pipeline_fee", "universal").expect("pipeline fee domain");
        let gas_asset = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "gas".parse().expect("pipeline gas asset name"),
        );
        let alternate_asset = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "alternate".parse().expect("alternate gas asset name"),
        );
        let mut world = World::with_assets(
            [Domain::new(domain_id).build(&authority)],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(initial_tech.clone()).build(&authority),
                Account::new(updated_tech.clone()).build(&authority),
            ],
            [
                AssetDefinition::numeric(
                    gas_asset.clone(),
                    "pipeline gas".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&authority),
                AssetDefinition::numeric(
                    alternate_asset.clone(),
                    "alternate gas".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&authority),
            ],
            [Asset::new(
                AssetId::new(gas_asset.clone(), authority.clone()),
                Quantity::from(1_000_000_u32),
            )],
            [],
        );
        seed_test_asset_supply(&mut world, &gas_asset);
        seed_test_asset_supply(&mut world, &alternate_asset);
        world.account_permissions.insert(
            authority.clone(),
            BTreeSet::from([executor_permission::parameter::CanSetParameters.into()]),
        );
        (
            world,
            authority_keypair,
            authority,
            initial_tech,
            updated_tech,
            gas_asset,
            alternate_asset,
        )
    }
    fn configure_pipeline_fee_snapshot(
        state_transaction: &mut StateTransaction<'_, '_>,
        tech_account: &AccountId,
        gas_asset: &AssetDefinitionId,
        units_per_gas: u64,
    ) {
        let gas_asset = gas_asset.canonical_address();
        state_transaction.pipeline.gas.tech_account_id = tech_account.to_string();
        state_transaction.pipeline.gas.accepted_assets = vec![gas_asset.clone()];
        state_transaction.pipeline.gas.units_per_gas =
            vec![iroha_config::parameters::actual::GasRate {
                asset: gas_asset,
                units_per_gas,
                twap_local_per_xor: Numeric::one(),
                liquidity: GasLiquidity::Tier1,
                volatility: GasVolatility::Stable,
            }];
    }
    pub(super) fn sponsored_pipeline_fee_fixture(
        lease_allocation: Option<Quantity>,
    ) -> (
        State,
        SignedTransaction,
        AccountId,
        AccountId,
        AccountId,
        AssetDefinitionId,
        FeeSponsorProgramId,
        Hash,
    ) {
        let (sponsor, _) = gen_account_in("sponsored_pipeline_fee");
        let (beneficiary, beneficiary_keypair) = gen_account_in("sponsored_pipeline_fee");
        let (custody, _) = gen_account_in("sponsored_pipeline_fee");
        let (tech_account, _) = gen_account_in("sponsored_pipeline_fee");
        let domain_id = DomainId::try_new("sponsored_pipeline_fee", "universal")
            .expect("sponsored pipeline fee domain");
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "gas".parse().expect("sponsored pipeline gas asset name"),
        );
        let instruction =
            InstructionBox::from(Log::new(Level::INFO, "sponsored pipeline gas".to_owned()));
        let wire_id = iroha_data_model::isi::instruction_wire_id(&instruction)
            .expect("Log instruction has a registered wire id")
            .to_owned();
        let program_id = FeeSponsorProgramId::new(
            sponsor.clone(),
            "pipeline".parse().expect("sponsor program name"),
        );
        let mut world = World::with_assets(
            [Domain::new(domain_id.clone()).build(&sponsor)],
            [
                Account::new(sponsor.clone()).build(&sponsor),
                Account::new(beneficiary.clone()).build(&sponsor),
                Account::new(custody.clone()).build(&sponsor),
                Account::new(tech_account.clone()).build(&sponsor),
            ],
            [AssetDefinition::numeric(
                asset_definition_id.clone(),
                "sponsored pipeline gas".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sponsor)],
            [Asset::new(
                AssetId::new(asset_definition_id.clone(), custody.clone()),
                Quantity::from(10_u32),
            )],
            [],
        );
        seed_test_asset_supply(&mut world, &asset_definition_id);
        let mut program = iroha_data_model::nexus::FeeSponsorProgram::new(
            program_id.clone(),
            program_id.sponsor.clone(),
        );
        program.lifecycle = FeeSponsorProgramLifecycle::Active;
        program.active_revision = Some(1);
        world
            .fee_sponsor_programs
            .insert(program_id.clone(), program);
        world.fee_sponsor_program_revisions.insert(
            FeeSponsorProgramRevisionKey::new(program_id.clone(), 1),
            FeeSponsorProgramRevision {
                program_id: program_id.clone(),
                revision: 1,
                eligibility: FeeSponsorEligibility::EnrolledOnly,
                rules: vec![iroha_data_model::nexus::FeeSponsorRule {
                    id: "allow_log".parse().expect("sponsor rule id"),
                    effect: FeeSponsorRuleEffect::Allow,
                    selectors: vec![FeeSponsorRuleSelector::NativeInstruction(
                        iroha_data_model::nexus::FeeSponsorNativeInstructionSelector {
                            wire_id,
                            asset_definition_id: None,
                        },
                    )],
                }],
                asset_budgets: vec![iroha_data_model::nexus::FeeSponsorAssetBudget {
                    asset_definition_id: asset_definition_id.clone(),
                    per_transaction: Quantity::from(10_u32),
                    per_block: Quantity::from(10_u32),
                    per_program_epoch: Quantity::from(10_u32),
                    per_beneficiary_epoch: Quantity::from(10_u32),
                    reserve_floor: Quantity::zero(),
                    epoch_length_blocks: nonzero!(1_u64),
                }],
            },
        );
        let enrollment_key = FeeSponsorEnrollmentKey {
            program_id: program_id.clone(),
            beneficiary: beneficiary.clone(),
        };
        world.fee_sponsor_enrollments.insert(
            enrollment_key.clone(),
            iroha_data_model::nexus::FeeSponsorEnrollment {
                key: enrollment_key,
                enrolled_at_height: 1,
            },
        );
        let vault_key = FeeSponsorVaultKey {
            program_id: program_id.clone(),
            asset_definition_id: asset_definition_id.clone(),
        };
        world.fee_sponsor_vaults.insert(
            vault_key.clone(),
            iroha_data_model::nexus::FeeSponsorVault {
                key: vault_key,
                balance: Quantity::from(10_u32),
            },
        );
        let lease_id = Hash::new(b"sponsored-pipeline-fee-lease");
        if let Some(allocation) = lease_allocation {
            insert_relay_allocation(
                &mut world,
                &relay_allocation_fixture(
                    program_id.clone(),
                    1,
                    asset_definition_id.clone(),
                    allocation,
                    DataSpaceId::UNIVERSAL,
                    20,
                    lease_id,
                ),
            );
        }
        let state = state_after_genesis(world);
        let transaction = TransactionBuilder::new(
            state.network_id,
            beneficiary.clone(),
            FeePaymentIntent::sponsor(
                program_id.clone(),
                1,
                vec![FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    asset_definition_id.clone(),
                    Quantity::from(2_u32),
                )],
                None,
            ),
        )
        .with_instructions([instruction])
        .sign(beneficiary_keypair.private_key());
        (
            state,
            transaction,
            beneficiary,
            custody,
            tech_account,
            asset_definition_id,
            program_id,
            lease_id,
        )
    }
    fn configure_sponsored_pipeline_fee_transaction(
        state_transaction: &mut StateTransaction<'_, '_>,
        custody: &AccountId,
        tech_account: &AccountId,
        asset_definition_id: &AssetDefinitionId,
        settlement_mode: iroha_config::parameters::actual::NexusFeeSettlementMode,
    ) {
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.nexus.fees.per_gas_unit_fee = Quantity::zero();
        state_transaction
            .nexus
            .fees
            .sponsor_vault_custody_account_id = custody.clone();
        state_transaction.nexus.fees.settlement_mode = settlement_mode;
        configure_pipeline_fee_snapshot(state_transaction, tech_account, asset_definition_id, 1);
    }
    fn install_fee_fixture_network_currency(
        state_transaction: &mut StateTransaction<'_, '_>,
        fee_asset: &AssetDefinitionId,
    ) {
        let mut parameters = state_transaction
            .world
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .unwrap_or_default();
        parameters.xor_asset_definition_id = fee_asset.clone();
        state_transaction.world.parameters.get_mut().set_parameter(
            iroha_data_model::parameter::Parameter::Custom(parameters.into_custom_parameter()),
        );
    }
    fn configure_direct_nexus_fee_snapshot(
        state_transaction: &mut StateTransaction<'_, '_>,
        fee_asset: &AssetDefinitionId,
    ) {
        state_transaction.nexus.fees.settlement_mode =
            iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
        state_transaction.nexus.fees.fee_asset_id = fee_asset.canonical_address();
        install_fee_fixture_network_currency(state_transaction, fee_asset);
        state_transaction.nexus.fees.base_fee = Quantity::from(2_u32);
        state_transaction.nexus.fees.per_byte_fee = Quantity::zero();
        state_transaction.nexus.fees.per_instruction_fee = Quantity::zero();
        state_transaction.nexus.fees.per_gas_unit_fee = Quantity::zero();
    }
    fn test_asset_balance(
        state_transaction: &StateTransaction<'_, '_>,
        asset_id: &AssetId,
    ) -> Quantity {
        state_transaction
            .world
            .assets()
            .get(asset_id)
            .map(|asset| asset.as_ref().clone())
            .unwrap_or_else(Quantity::zero)
    }
    fn configure_direct_ivm_fee_fixture(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        fee_asset: &AssetDefinitionId,
    ) -> (AssetId, Quantity, Quantity) {
        configure_direct_nexus_fee_snapshot(state_transaction, fee_asset);
        let payer_asset_id = AssetId::new(fee_asset.clone(), authority.clone());
        let payer_before = test_asset_balance(state_transaction, &payer_asset_id);
        let supply_before = state_transaction
            .world
            .asset_definition(fee_asset)
            .expect("direct-fee asset definition")
            .total_quantity()
            .clone();
        (payer_asset_id, payer_before, supply_before)
    }
    // The signed producer owns every bootstrap input and its execution/fee configuration.
    // Neither a fake H1 carrier nor a caller-built Genesis-domain IVM transaction is admitted.
    fn authenticated_genesis_fee_config() -> (
        crate::sumeragi::test_chain::TestChainConfig,
        AccountId,
        AssetDefinitionId,
    ) {
        let (world, keypair, authority, _, _, fee_asset, _) = pipeline_fee_world_fixture();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
        config.genesis_key = keypair;
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.fees.settlement_mode =
            iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
        nexus.fees.fee_asset_id = fee_asset.canonical_address();
        nexus.fees.base_fee = Quantity::from(2_u32);
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        config.nexus = Some(nexus);
        (config, authority, fee_asset)
    }

    fn execute_authenticated_genesis_fee_fixture<'state>(
        prepared: &'state crate::sumeragi::test_chain::PreparedTestChainConfig,
        authority: &AccountId,
    ) -> Box<crate::state::StateBlock<'state>> {
        let topology = crate::sumeragi::network_topology::Topology::new(
            prepared
                .validator_keys
                .iter()
                .map(|key| PeerId::new(key.public_key().clone())),
        );
        let (valid, block) = crate::block::ValidBlock::validate_signed_genesis(
            prepared.genesis.block().clone(),
            &topology,
            authority,
            &iroha_primitives::time::TimeSource::new_system(),
            &prepared.state,
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
        )
        .unpack(|_| {})
        .expect("execute the exact validated signed fee fixture genesis");
        assert!(
            valid
                .as_ref()
                .execution_outputs()
                .iter()
                .all(|output| output.result().is_ok())
        );
        block
    }

    #[test]
    fn stateful_fee_admission_exempts_authenticated_genesis_with_missing_limit() {
        let (mut config, authority, _) = authenticated_genesis_fee_config();
        config
            .genesis_instructions
            .push(Log::new(Level::INFO, "genesis fee exemption".to_owned()).into());
        let prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
            .expect("prepare original signed fee-exempt genesis without fee limits");
        let mut block = execute_authenticated_genesis_fee_fixture(&prepared, &authority);
        let state_transaction = block.transaction();
        assert!(is_initial_genesis_context(&state_transaction));
    }
    #[test]
    fn initial_genesis_context_rejects_height_one_replay_over_committed_history() {
        let (state, _, _, _, _, _, _) = pipeline_fee_state_fixture(state_for_testing);
        state
            .block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0))
            .commit_empty_block_for_testing()
            .expect("commit the prior authenticated genesis block");
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let state_transaction = block.transaction();
        assert!(state_transaction._curr_block.is_genesis());
        assert!(
            !is_initial_genesis_context(&state_transaction),
            "a genesis-shaped header over committed state must not regain bootstrap authority"
        );
    }
    #[test]
    fn transaction_execution_keeps_authenticated_genesis_fee_free() {
        let (mut config, authority, fee_asset) = authenticated_genesis_fee_config();
        config
            .genesis_instructions
            .push(Log::new(Level::INFO, "fee-free genesis execution".to_owned()).into());
        let payer_asset_id = AssetId::new(fee_asset.clone(), authority.clone());
        let payer_before = config
            .world
            .assets
            .view()
            .get(&payer_asset_id)
            .unwrap()
            .as_ref()
            .clone();
        let supply_before = config
            .world
            .asset_definitions
            .view()
            .get(&fee_asset)
            .unwrap()
            .total_quantity()
            .clone();
        let prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
            .expect("prepare original signed native fee fixture");
        assert!(
            prepared
                .genesis
                .block()
                .external_transactions()
                .all(|transaction| transaction.fee_payment_intent().charge_limits().is_empty())
        );
        let mut block = execute_authenticated_genesis_fee_fixture(&prepared, &authority);
        let state_transaction = block.transaction();
        assert_eq!(
            test_asset_balance(&state_transaction, &payer_asset_id),
            payer_before,
            "native genesis execution must not debit its payer"
        );
        assert_eq!(
            state_transaction
                .world
                .asset_definition(&fee_asset)
                .expect("direct-fee asset definition")
                .total_quantity(),
            &supply_before,
            "native genesis execution must not burn fee-asset supply"
        );
    }
    #[test]
    fn genesis_raw_ivm_carriers_reject_before_debit_or_supply_change() {
        let (prepared, _) = contract_program_with_entrypoint("run", None);
        for program in [generate_ok_program(), prepared] {
            let (world, keypair, authority, _, _, fee_asset, _) = pipeline_fee_world_fixture();
            let payer = AssetId::new(fee_asset.clone(), authority.clone());
            let payer_before = world.assets.view().get(&payer).unwrap().as_ref().clone();
            let supply_before = world
                .asset_definitions
                .view()
                .get(&fee_asset)
                .unwrap()
                .total_quantity()
                .clone();
            let signed = TransactionBuilder::new_genesis(
                authority.clone(),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
            .sign(keypair.private_key());
            let original = iroha_data_model::block::SignedBlock::genesis(
                vec![signed.clone()],
                keypair.private_key(),
                None,
                None,
            );
            assert_eq!(
                crate::block::authenticate_genesis_block_intents(&original, &authority)
                    .unwrap_err(),
                crate::block::InvalidGenesisError::NotInstructions
            );
            let state = state_for_testing(world);
            let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let mut transaction = block.transaction();
            let error = super::Executor::Initial
                .execute_transaction(&mut transaction, &authority, signed, &mut IvmCache::new())
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("raw IVM cannot acquire an original native genesis capability");
            assert!(matches!(error, ValidationFail::NotPermitted(reason)
                if reason == "genesis instruction execution requires its authenticated source capability"));
            assert_eq!(transaction.last_tx_gas_used, 0);
            assert_eq!(
                transaction.world.assets.get(&payer).unwrap().as_ref(),
                &payer_before
            );
            assert_eq!(
                transaction
                    .world
                    .asset_definitions
                    .get(&fee_asset)
                    .unwrap()
                    .total_quantity(),
                &supply_before
            );
            drop(transaction);
            assert_eq!(block.committed_fragment_count(), 0);
        }
    }
    #[test]
    fn transaction_execution_keeps_authenticated_genesis_generic_ivm_fee_free() {
        let (mut config, authority, fee_asset) = authenticated_genesis_fee_config();
        let trigger_id: TriggerId = "authenticated_genesis_generic_ivm".parse().unwrap();
        let mut program = ivm::ProgramMetadata {
            max_cycles: 100,
            ..Default::default()
        }
        .encode();
        program.extend_from_slice(
            &ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 5, 0, 1)
                .to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::Ivm(IvmBytecode::from_compiled(program)),
                Repeats::Exactly(1),
                authority.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(authority.clone()),
            )
            .expect("supported generic IVM genesis trigger"),
        );
        config.genesis_instructions = vec![
            Register::trigger(trigger).into(),
            ExecuteTrigger::new(trigger_id.clone()).into(),
        ];
        let payer_asset_id = AssetId::new(fee_asset.clone(), authority.clone());
        let payer_before = config
            .world
            .assets
            .view()
            .get(&payer_asset_id)
            .unwrap()
            .as_ref()
            .clone();
        let supply_before = config
            .world
            .asset_definitions
            .view()
            .get(&fee_asset)
            .unwrap()
            .total_quantity()
            .clone();
        let prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
            .expect("prepare exact signed generic trigger genesis");
        let mut block = execute_authenticated_genesis_fee_fixture(&prepared, &authority);
        assert!(
            block.gas_used_in_block > 0,
            "authentic genesis callback retains measured work"
        );
        let events = block.world.take_external_events();
        assert!(events.iter().any(|event| matches!(event,
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id &&
                event.outcome() == &iroha_data_model::events::trigger_completed::TriggerCompletedOutcome::Success
        )), "the actual generic IVM callback completed successfully");
        let state_transaction = block.transaction();
        assert_eq!(
            test_asset_balance(&state_transaction, &payer_asset_id),
            payer_before,
            "generic IVM genesis execution must not debit its payer"
        );
        assert_eq!(
            state_transaction
                .world
                .asset_definition(&fee_asset)
                .expect("direct-fee asset definition")
                .total_quantity(),
            &supply_before,
            "generic IVM genesis execution must not burn fee-asset supply"
        );
    }
    #[test]
    fn local_checkout_deferral_abandons_transaction_without_gas_or_fee() {
        check_local_checkout_abandons_transaction(
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
        );
    }
    #[test]
    fn local_custody_invariant_abandons_transaction_without_gas_or_fee() {
        check_local_checkout_abandons_transaction(
            ivm::error::ExecutionDeferral::LocalInvariantViolation,
        );
    }
    fn check_local_checkout_abandons_transaction(reason: ivm::error::ExecutionDeferral) {
        let (state, keypair, authority, _, _, fee_asset, _) =
            pipeline_fee_state_fixture(state_after_genesis);
        let mut program = ivm::ProgramMetadata {
            max_cycles: 100,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        program.extend_from_slice(
            &ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 5, 0, 1)
                .to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    fee_asset.clone(),
                    Quantity::from(2_u32),
                )],
                core::num::NonZeroU64::new(1_000_000),
            ),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(keypair.private_key());
        let entrypoint_hash = transaction.hash_as_entrypoint();
        let signed_hash = transaction.hash();
        // This direct component test supplies the exact signed source fields that
        // the Network producer captures before execution and fee settlement.
        let bind_source = |child: &mut StateTransaction<'_, '_>| {
            child.current_entrypoint_index = Some(0);
            child.current_network_entrypoint_hash = Some(entrypoint_hash);
            child.current_tx_hash = Some(signed_hash);
            child.current_lane_id = Some(iroha_model_base::topology::LaneId::SINGLE);
            child.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            child.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        };
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        let (payer_asset_id, payer_before, supply_before) =
            configure_direct_ivm_fee_fixture(&mut state_transaction, &authority, &fee_asset);
        bind_source(&mut state_transaction);
        let retry_transaction = transaction.clone();
        let mut ivm_cache = IvmCache::new();
        let shared_cache = ivm_cache.prepared_contract_cache();
        shared_cache.set_checkout_refusal_for_test(Some(reason));
        let result = super::Executor::Initial.execute_transaction(
            &mut state_transaction,
            &authority,
            transaction,
            &mut ivm_cache,
        );
        assert_eq!(
            result,
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                reason.into()
            ))
        );
        assert_eq!(state_transaction.last_tx_gas_used, 0);
        assert_eq!(state_transaction.execution_deferral(), Some(reason.into()));
        // Releasing local pressure cannot bless this already incomplete overlay.
        shared_cache.set_checkout_refusal_for_test(None);
        assert_eq!(
            test_asset_balance(&state_transaction, &payer_asset_id),
            payer_before,
            "deferred generic IVM execution must not debit its payer"
        );
        assert_eq!(
            state_transaction
                .world
                .asset_definition(&fee_asset)
                .expect("direct-fee asset definition")
                .total_quantity(),
            &supply_before,
            "deferred generic IVM execution must not burn fee-asset supply"
        );
        drop(state_transaction);
        let mut retry = block
            .transaction_for_fastpq_testing(Hash::from(retry_transaction.hash_as_entrypoint()));
        configure_direct_ivm_fee_fixture(&mut retry, &authority, &fee_asset);
        bind_source(&mut retry);
        super::Executor::Initial
            .execute_transaction(
                &mut retry,
                &authority,
                retry_transaction.clone(),
                &mut ivm_cache,
            )
            .expect("fresh attempt executes after local capacity returns");
        let retry_gas = retry.last_tx_gas_used;
        let retry_balance = test_asset_balance(&retry, &payer_asset_id);
        drop(retry);
        let mut cold = block
            .transaction_for_fastpq_testing(Hash::from(retry_transaction.hash_as_entrypoint()));
        configure_direct_ivm_fee_fixture(&mut cold, &authority, &fee_asset);
        bind_source(&mut cold);
        super::Executor::Initial
            .execute_transaction(
                &mut cold,
                &authority,
                retry_transaction,
                &mut IvmCache::new(),
            )
            .expect("cold attempt executes identically");
        assert_eq!(cold.last_tx_gas_used, retry_gas);
        assert!(
            retry_gas > 0,
            "the compared successful executions actually consumed gas"
        );
        assert_eq!(test_asset_balance(&cold, &payer_asset_id), retry_balance);
    }
    #[test]
    fn transaction_execution_keeps_rejected_genesis_prepared_contract_fee_free() {
        let (mut config, authority, fee_asset) = authenticated_genesis_fee_config();
        let (program, _) =
            contract_program_with_entrypoint("run", Some("CanRunGenesisPreparedContract"));
        ivm::verify_contract_artifact(&program).expect("verify current prepared artifact");
        let trigger_id: TriggerId = "authenticated_genesis_prepared_ivm".parse().unwrap();
        let mut metadata = Metadata::default();
        metadata.insert("contract_entrypoint".parse().unwrap(), Json::new("run"));
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::Ivm(IvmBytecode::from_compiled(program)),
                Repeats::Exactly(1),
                authority.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(authority.clone()),
            )
            .expect("schema-valid prepared genesis trigger")
            .with_metadata(metadata),
        );
        config.genesis_instructions = vec![
            Register::trigger(trigger).into(),
            ExecuteTrigger::new(trigger_id).into(),
        ];
        let payer_asset_id = AssetId::new(fee_asset.clone(), authority.clone());
        let payer_before = config
            .world
            .assets
            .view()
            .get(&payer_asset_id)
            .unwrap()
            .as_ref()
            .clone();
        let supply_before = config
            .world
            .asset_definitions
            .view()
            .get(&fee_asset)
            .unwrap()
            .total_quantity()
            .clone();
        let failure = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
            .expect_err("signed genesis cannot invent a committed prepared-contract identity");
        assert!(
            matches!(&failure.error,
                crate::sumeragi::test_chain::TestChainError::OriginalGenesisExecution(error)
                if matches!(error.as_ref(),
                    crate::block::BlockValidationError::InvalidGenesis(
                        crate::block::InvalidGenesisError::RejectedOutput(_)
                    )
                )
            ),
            "unexpected authentic producer refusal: {}",
            failure.error
        );
        assert_eq!(
            failure.state.committed_height(),
            0,
            "rejected genesis publishes no effects"
        );
        let mut block = failure
            .state
            .block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        assert_eq!(
            block.gas_used_in_block, 0,
            "rejected genesis retains no gas effects"
        );
        let state_transaction = block.transaction();
        assert_eq!(
            test_asset_balance(&state_transaction, &payer_asset_id),
            payer_before,
            "prepared-contract IVM genesis execution must not debit its payer"
        );
        assert_eq!(
            state_transaction
                .world
                .asset_definition(&fee_asset)
                .expect("direct-fee asset definition")
                .total_quantity(),
            &supply_before,
            "prepared-contract IVM genesis execution must not burn fee-asset supply"
        );
    }
    #[test]
    fn stateful_fee_admission_does_not_exempt_non_genesis_with_missing_limit() {
        let (state, keypair, authority, _, _, fee_asset, _) =
            pipeline_fee_state_fixture(state_after_genesis);
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "non-genesis fee validation".to_owned(),
        )])
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        configure_direct_nexus_fee_snapshot(&mut state_transaction, &fee_asset);
        assert!(!is_initial_genesis_context(&state_transaction));
        let error = validate_transaction_fee_admission(&mut state_transaction, &transaction)
            .expect_err("non-genesis must validate its signed Nexus fee limit");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(reason)
                if reason.contains("signed fee intent is missing Nexus charge limit")
        ));
    }
    #[test]
    fn stateful_fee_admission_rejects_understated_authority_limit_before_effects() {
        let (state, keypair, authority, tech_account, _, gas_asset, _) =
            pipeline_fee_state_fixture(state_after_genesis);
        let effect_parameter_id: CustomParameterId = "fee_admission_business_effect"
            .parse()
            .expect("effect parameter id");
        let instructions = vec![InstructionBox::from(
            iroha_data_model::isi::SetParameter::new(
                iroha_data_model::parameter::Parameter::Custom(CustomParameter::new(
                    effect_parameter_id.clone(),
                    Json::new(1_u32),
                )),
            ),
        )];
        assert!(isi_gas::meter_instructions(&instructions) > 0);
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    gas_asset.clone(),
                    Quantity::from(1_u32),
                )],
                None,
            ),
        )
        .with_instructions(instructions)
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        configure_pipeline_fee_snapshot(&mut state_transaction, &tech_account, &gas_asset, 2);
        let error = validate_transaction_fee_admission(&mut state_transaction, &transaction)
            .expect_err("an understated signed limit must fail stateful admission");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(reason)
                if reason.contains("exceeds signed maximum")
        ));
        assert!(
            state_transaction
                .world
                .parameters
                .get()
                .custom()
                .get(&effect_parameter_id)
                .is_none(),
            "fee rejection must precede transaction business effects"
        );
        assert_eq!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(gas_asset.clone(), authority))
                .expect("authority gas balance")
                .as_ref(),
            &Quantity::from(1_000_000_u32),
            "fee admission must not debit the authority"
        );
        assert!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(gas_asset, tech_account))
                .is_none(),
            "fee admission must not credit the fee destination"
        );
    }
    #[test]
    fn pipeline_fee_charge_defensively_rejects_understated_authority_limit() {
        let (state, keypair, authority, tech_account, _, gas_asset, _) =
            pipeline_fee_state_fixture(state_after_genesis);
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    gas_asset.clone(),
                    Quantity::from(1_u32),
                )],
                None,
            ),
        )
        .with_instructions([Log::new(Level::INFO, "bounded".to_owned())])
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        configure_pipeline_fee_snapshot(&mut state_transaction, &tech_account, &gas_asset, 2);
        let error = super::Executor::charge_pipeline_gas_asset_fee(
            &mut state_transaction,
            &authority,
            &transaction,
            &gas_asset.canonical_address(),
            1,
            None,
        )
        .expect_err("actual authority charge must be checked against the signed limit");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(reason)
                if reason.contains("exceeds signed maximum")
        ));
        assert_eq!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(gas_asset.clone(), authority))
                .expect("authority gas balance")
                .as_ref(),
            &Quantity::from(1_000_000_u32)
        );
        assert!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(gas_asset, tech_account))
                .is_none()
        );
    }
    #[test]
    fn sponsored_pipeline_gas_direct_fee_preserves_unrelated_lease() {
        let (
            state,
            transaction,
            beneficiary,
            custody,
            tech_account,
            asset_definition_id,
            program_id,
            lease_id,
        ) = sponsored_pipeline_fee_fixture(Some(Quantity::from(10_u32)));
        let mut block = state.block(BlockHeader::new(
            nonzero!(10_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        configure_sponsored_pipeline_fee_transaction(
            &mut state_transaction,
            &custody,
            &tech_account,
            &asset_definition_id,
            iroha_config::parameters::actual::NexusFeeSettlementMode::Direct,
        );
        super::Executor::charge_pipeline_gas_asset_fee(
            &mut state_transaction,
            &beneficiary,
            &transaction,
            &asset_definition_id.canonical_address(),
            2,
            Some(&program_id),
        )
        .expect("sponsored direct PipelineGas settles actual custody");
        let executed_key =
            fee_sponsor_vault_allocation_usage_state_key(&lease_id).expect("executed usage key");
        let settled_key = fee_sponsor_vault_allocation_settled_usage_state_key(&lease_id)
            .expect("settled usage key");
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                .expect("executed usage"),
            Quantity::zero()
        );
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                .expect("settled usage"),
            Quantity::zero()
        );
        let vault_key = FeeSponsorVaultKey {
            program_id,
            asset_definition_id: asset_definition_id.clone(),
        };
        assert_eq!(
            state_transaction
                .world
                .fee_sponsor_vaults
                .get(&vault_key)
                .expect("sponsor vault")
                .balance,
            Quantity::from(8_u32)
        );
        assert_eq!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(asset_definition_id.clone(), custody))
                .expect("custody balance")
                .as_ref(),
            &Quantity::from(8_u32)
        );
        assert_eq!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(asset_definition_id, tech_account))
                .expect("technical-account balance")
                .as_ref(),
            &Quantity::from(2_u32)
        );
    }
    #[test]
    fn sponsored_pipeline_gas_direct_mode_does_not_require_or_consume_lease() {
        let (
            state,
            transaction,
            beneficiary,
            custody,
            tech_account,
            asset_definition_id,
            program_id,
            lease_id,
        ) = sponsored_pipeline_fee_fixture(None);
        let mut block = state.block(BlockHeader::new(
            nonzero!(10_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        configure_sponsored_pipeline_fee_transaction(
            &mut state_transaction,
            &custody,
            &tech_account,
            &asset_definition_id,
            iroha_config::parameters::actual::NexusFeeSettlementMode::Direct,
        );
        super::Executor::charge_pipeline_gas_asset_fee(
            &mut state_transaction,
            &beneficiary,
            &transaction,
            &asset_definition_id.canonical_address(),
            2,
            Some(&program_id),
        )
        .expect("direct-settled sponsored PipelineGas does not require a spend lease");
        let executed_key =
            fee_sponsor_vault_allocation_usage_state_key(&lease_id).expect("executed usage key");
        let settled_key = fee_sponsor_vault_allocation_settled_usage_state_key(&lease_id)
            .expect("settled usage key");
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                .expect("executed usage"),
            Quantity::zero()
        );
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                .expect("settled usage"),
            Quantity::zero()
        );
        let vault_key = FeeSponsorVaultKey {
            program_id,
            asset_definition_id: asset_definition_id.clone(),
        };
        assert_eq!(
            state_transaction
                .world
                .fee_sponsor_vaults
                .get(&vault_key)
                .unwrap()
                .balance,
            Quantity::from(8_u32)
        );
        assert_eq!(
            test_asset_balance(
                &state_transaction,
                &AssetId::new(asset_definition_id.clone(), custody)
            ),
            Quantity::from(8_u32)
        );
        assert_eq!(
            test_asset_balance(
                &state_transaction,
                &AssetId::new(asset_definition_id, tech_account)
            ),
            Quantity::from(2_u32)
        );
    }
    #[test]
    fn retired_sponsored_pipeline_mode_fails_before_debit_or_transfer() {
        for allocation in [1_u32, 10_u32] {
            let (
                state,
                transaction,
                beneficiary,
                custody,
                tech_account,
                asset_definition_id,
                program_id,
                lease_id,
            ) = sponsored_pipeline_fee_fixture(Some(Quantity::from(allocation)));
            let mut block = state.block(BlockHeader::new(
                nonzero!(10_u64),
                Some(
                    state
                        .view()
                        .latest_block_hash()
                        .expect("genuine genesis parent"),
                ),
                None,
                0,
                0,
            ));
            let mut state_transaction =
                block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
            configure_sponsored_pipeline_fee_transaction(
                &mut state_transaction,
                &custody,
                &tech_account,
                &asset_definition_id,
                iroha_config::parameters::actual::NexusFeeSettlementMode::LaneRelayBurn,
            );
            let error = super::Executor::charge_pipeline_gas_asset_fee(
                &mut state_transaction,
                &beneficiary,
                &transaction,
                &asset_definition_id.canonical_address(),
                2,
                Some(&program_id),
            )
            .expect_err("retired receipt mode rejects even a fully funded spend lease");
            assert!(
                matches!(error, ValidationFail::InternalError(reason) if reason.contains("retired lane-relay-burn fee settlement"))
            );
            let vault_key = FeeSponsorVaultKey {
                program_id,
                asset_definition_id: asset_definition_id.clone(),
            };
            assert_eq!(
                state_transaction
                    .world
                    .fee_sponsor_vaults
                    .get(&vault_key)
                    .expect("sponsor vault")
                    .balance,
                Quantity::from(10_u32)
            );
            assert_eq!(
                state_transaction
                    .world
                    .assets()
                    .get(&AssetId::new(asset_definition_id.clone(), custody))
                    .expect("custody balance")
                    .as_ref(),
                &Quantity::from(10_u32)
            );
            assert!(
                state_transaction
                    .world
                    .assets()
                    .get(&AssetId::new(asset_definition_id.clone(), tech_account))
                    .is_none()
            );
            let executed_key = fee_sponsor_vault_allocation_usage_state_key(&lease_id)
                .expect("executed usage key");
            let settled_key = fee_sponsor_vault_allocation_settled_usage_state_key(&lease_id)
                .expect("settled usage key");
            assert_eq!(
                fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                    .expect("executed usage"),
                Quantity::zero()
            );
            assert_eq!(
                fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                    .expect("settled usage"),
                Quantity::zero()
            );
        }
    }
    #[test]
    fn sponsor_resolution_predicts_scheduled_revision_only_after_old_leases_drain() {
        let (
            state,
            transaction,
            beneficiary,
            custody,
            tech_account,
            asset_definition_id,
            program_id,
            _,
        ) = sponsored_pipeline_fee_fixture(Some(Quantity::from(10_u32)));
        let mut block = state.block(BlockHeader::new(
            nonzero!(10_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        configure_sponsored_pipeline_fee_transaction(
            &mut state_transaction,
            &custody,
            &tech_account,
            &asset_definition_id,
            iroha_config::parameters::actual::NexusFeeSettlementMode::LaneRelayBurn,
        );
        let revision_one = state_transaction
            .world
            .fee_sponsor_program_revisions
            .get(&FeeSponsorProgramRevisionKey::new(program_id.clone(), 1))
            .cloned()
            .expect("revision one");
        let mut revision_two = revision_one;
        revision_two.revision = 2;
        state_transaction
            .world
            .fee_sponsor_program_revisions
            .insert(
                FeeSponsorProgramRevisionKey::new(program_id.clone(), 2),
                revision_two,
            );
        let mut program = state_transaction
            .world
            .fee_sponsor_programs
            .get(&program_id)
            .cloned()
            .expect("sponsor program");
        program.staged_revision = Some(2);
        program.scheduled_activation = Some(iroha_data_model::nexus::FeeSponsorProgramActivation {
            revision: 2,
            activate_at_height: 10,
        });
        state_transaction
            .world
            .fee_sponsor_programs
            .insert(program_id.clone(), program);
        let current = resolve_fee_sponsor_program(
            &state_transaction.world,
            &state_transaction.nexus,
            &program_id,
            1,
            &beneficiary,
            transaction.payload(),
            Some(DataSpaceId::UNIVERSAL),
            10,
            fee_sponsor_multisig::RuleContext::admission(1),
        )
        .expect("old revision stays effective while its lease is live");
        assert_eq!(current.revision.revision, 1);
        let early_error = resolve_fee_sponsor_program(
            &state_transaction.world,
            &state_transaction.nexus,
            &program_id,
            2,
            &beneficiary,
            transaction.payload(),
            Some(DataSpaceId::UNIVERSAL),
            10,
            fee_sponsor_multisig::RuleContext::admission(1),
        )
        .expect_err("scheduled revision must not be predicted before old leases drain");
        let crate::execution_attempt::ExecutionAttemptError::Rejected(early_error) = early_error
        else {
            panic!("revision mismatch must be a completed rejection");
        };
        assert_eq!(early_error.code(), FeeRejectionCode::RevisionNotActive);
        let drained = resolve_fee_sponsor_program(
            &state_transaction.world,
            &state_transaction.nexus,
            &program_id,
            2,
            &beneficiary,
            transaction.payload(),
            Some(DataSpaceId::UNIVERSAL),
            21,
            fee_sponsor_multisig::RuleContext::admission(1),
        )
        .expect("scheduled revision becomes effective after the old lease expiry");
        assert_eq!(drained.revision.revision, 2);
    }
    #[test]
    fn overlay_fee_uses_pre_effect_gas_policy_snapshot() {
        let (state, keypair, authority, initial_tech, updated_tech, gas_asset, alternate_asset) =
            pipeline_fee_state_fixture(state_after_genesis);
        let gas_asset_address = gas_asset.canonical_address();
        let alternate_asset_address = alternate_asset.canonical_address();
        let governed_rates = Json::from_str_norito(&format!(
            concat!(
                r#"[{{"asset":"{gas_asset}","liquidity_profile":"tier1","twap_local_per_xor":"1","units_per_gas":9,"volatility_class":"stable"}},"#,
                r#"{{"asset":"{alternate_asset}","liquidity_profile":"tier1","twap_local_per_xor":"1","units_per_gas":1,"volatility_class":"stable"}}]"#
            ),
            gas_asset = gas_asset_address,
            alternate_asset = alternate_asset_address,
        ))
        .expect("valid governed gas rates");
        let parameter_instruction = |id: &str, payload: Json| {
            InstructionBox::from(iroha_data_model::isi::SetParameter::new(
                iroha_data_model::parameter::Parameter::Custom(CustomParameter::new(
                    id.parse().expect("governed gas parameter id"),
                    payload,
                )),
            ))
        };
        let instructions = vec![
            parameter_instruction(
                "ivm_gas_tech_account_id",
                Json::new(updated_tech.to_string()),
            ),
            parameter_instruction(
                "ivm_gas_accepted_assets",
                Json::new(vec![gas_asset_address.clone(), alternate_asset_address]),
            ),
            parameter_instruction("ivm_gas_units_per_gas", governed_rates),
        ];
        let gas_used = isi_gas::meter_instructions(&instructions);
        assert!(gas_used > 0);
        let expected_fee = Quantity::from(u128::from(gas_used));
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    gas_asset.clone(),
                    expected_fee.clone(),
                )],
                None,
            ),
        )
        .with_instructions(instructions.clone())
        .sign(keypair.private_key());
        let overlay = crate::pipeline::overlay::TxOverlay::from_instructions(instructions);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        configure_pipeline_fee_snapshot(&mut state_transaction, &initial_tech, &gas_asset, 1);
        state_transaction.current_tx_hash = Some(transaction.hash());
        validate_transaction_fee_admission(&mut state_transaction, &transaction)
            .expect("pre-effect policy accepts its exact signed limit");
        let (gas_used, instruction_count) = applied_overlay_base_gas(&transaction, &overlay)
            .expect("meter the owned overlay before applying its effects");
        overlay
            .apply_with_chunk(&mut state_transaction, &authority, instruction_count)
            .expect("apply governed gas parameter effects");
        charge_fees_for_applied_overlay(
            &mut state_transaction,
            &authority,
            &transaction,
            gas_used,
            instruction_count,
        )
        .expect("settle against the pre-effect gas policy snapshot");
        assert_eq!(
            state_transaction.pipeline.gas.tech_account_id,
            initial_tech.to_string()
        );
        assert_eq!(
            state_transaction.pipeline.gas.accepted_assets,
            vec![gas_asset_address]
        );
        assert_eq!(
            state_transaction.pipeline.gas.units_per_gas[0].units_per_gas,
            1
        );
        assert_eq!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(gas_asset.clone(), initial_tech))
                .expect("pre-effect fee destination balance")
                .as_ref(),
            &expected_fee
        );
        assert!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(gas_asset.clone(), updated_tech))
                .is_none(),
            "the transaction must not redirect its own fee"
        );
        let expected_authority_balance = Quantity::from(1_000_000_u32)
            .checked_sub(&expected_fee)
            .expect("fixture balance covers fee");
        assert_eq!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(gas_asset, authority))
                .expect("authority gas balance")
                .as_ref(),
            &expected_authority_balance
        );
    }
    #[test]
    fn governed_gas_rate_refresh_rejects_malformed_strings_without_partial_update() {
        for (label, twap, liquidity, volatility, expected_error) in [
            (
                "twap",
                "not-a-number",
                "tier1",
                "stable",
                "twap `not-a-number`",
            ),
            (
                "liquidity",
                "1",
                "not-a-tier",
                "stable",
                "liquidity `not-a-tier`",
            ),
            (
                "volatility",
                "1",
                "tier1",
                "not-a-class",
                "volatility `not-a-class`",
            ),
        ] {
            let (state, _, _, tech_account, _, gas_asset, _) =
                pipeline_fee_state_fixture(state_after_genesis);
            let gas_asset_address = gas_asset.canonical_address();
            let payload = Json::from_str_norito(&format!(
                concat!(
                    r#"[{{"asset":"{asset}","liquidity_profile":"{liquidity}","#,
                    r#""twap_local_per_xor":"{twap}","units_per_gas":9,"volatility_class":"{volatility}"}}]"#
                ),
                asset = gas_asset_address,
                twap = twap,
                liquidity = liquidity,
                volatility = volatility,
            ))
            .expect("well-formed gas-rate JSON");
            let parameter_id: CustomParameterId = "ivm_gas_units_per_gas"
                .parse()
                .expect("gas rate parameter id");
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                Some(
                    state
                        .view()
                        .latest_block_hash()
                        .expect("genuine genesis parent"),
                ),
                None,
                0,
                0,
            ));
            let mut state_transaction = block.transaction();
            configure_pipeline_fee_snapshot(&mut state_transaction, &tech_account, &gas_asset, 1);
            state_transaction.world.parameters.get_mut().set_parameter(
                iroha_data_model::parameter::Parameter::Custom(CustomParameter::new(
                    parameter_id,
                    payload,
                )),
            );
            let error = super::Executor::refresh_gas_from_parameters(&mut state_transaction)
                .expect_err("malformed governed rate must fail closed");
            assert!(
                matches!(
                    error,
                    ValidationFail::InternalError(reason)
                        if reason.contains(expected_error)
                ),
                "unexpected {label} refresh error"
            );
            assert_eq!(
                state_transaction.pipeline.gas.tech_account_id,
                tech_account.to_string()
            );
            assert_eq!(
                state_transaction.pipeline.gas.accepted_assets,
                vec![gas_asset_address.clone()]
            );
            assert_eq!(state_transaction.pipeline.gas.units_per_gas.len(), 1);
            assert_eq!(
                state_transaction.pipeline.gas.units_per_gas[0].asset,
                gas_asset_address
            );
            assert_eq!(
                state_transaction.pipeline.gas.units_per_gas[0].units_per_gas,
                1
            );
        }
    }
    #[test]
    fn pipeline_gas_asset_charge_is_disabled_when_nexus_gas_fee_is_active() {
        let mut nexus_fees = NexusFees::default();
        let gas_asset = Some("xor#universal".to_owned());
        nexus_fees.per_gas_unit_fee = Quantity::zero();
        assert!(should_charge_pipeline_gas_asset(
            false,
            &nexus_fees,
            &gas_asset
        ));
        nexus_fees.per_gas_unit_fee = "0.001".parse().expect("valid gas fee");
        assert!(!should_charge_pipeline_gas_asset(
            false,
            &nexus_fees,
            &gas_asset
        ));
        assert!(!should_charge_pipeline_gas_asset(
            true,
            &nexus_fees,
            &gas_asset
        ));
        assert!(!should_charge_pipeline_gas_asset(false, &nexus_fees, &None));
    }
    fn multi_component_fee_quote_fixture() -> (
        World,
        iroha_config::parameters::actual::Nexus,
        Pipeline,
        TransactionPayload,
    ) {
        let (authority, _) = gen_account_in("fee_quote");
        let (sink, _) = gen_account_in("fee_quote");
        let domain_id = DomainId::try_new("fee_quote", "universal").expect("fee quote domain");
        let nexus_asset = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "nexus".parse().expect("nexus asset name"),
        );
        let gas_asset = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "gas".parse().expect("gas asset name"),
        );
        let mut world = World::with_assets(
            [Domain::new(domain_id).build(&authority)],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(sink.clone()).build(&sink),
            ],
            [
                AssetDefinition::numeric(
                    nexus_asset.clone(),
                    "nexus".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
                .build(&authority),
                AssetDefinition::numeric(
                    gas_asset.clone(),
                    "gas".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
                .build(&authority),
            ],
            [
                Asset::new(
                    AssetId::new(nexus_asset.clone(), authority.clone()),
                    Quantity::from(1_000_000_u32),
                ),
                Asset::new(
                    AssetId::new(gas_asset.clone(), authority.clone()),
                    Quantity::from(1_000_000_u32),
                ),
            ],
            [],
        );
        seed_test_asset_supply(&mut world, &nexus_asset);
        seed_test_asset_supply(&mut world, &gas_asset);
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.fees.base_fee = Quantity::from(2_u32);
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        nexus.fees.fee_asset_id = nexus_asset.canonical_address();
        let mut params = iroha_data_model::parameter::system::SumeragiNposParameters::default();
        params.xor_asset_definition_id = nexus_asset.clone();
        let mut parameter_block = world.parameters.block();
        parameter_block.set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ));
        parameter_block.set_parameter(iroha_data_model::parameter::Parameter::Custom(
            params.into_custom_parameter(),
        ));
        parameter_block.commit();
        nexus.fees.fee_sink_account_id = sink.to_string();
        let mut pipeline = Pipeline::default();
        pipeline.gas.accepted_assets = vec![gas_asset.canonical_address()];
        pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
            asset: gas_asset.canonical_address(),
            units_per_gas: 3,
            twap_local_per_xor: Numeric::from(1_u32),
            liquidity: GasLiquidity::Tier1,
            volatility: GasVolatility::Stable,
        }];
        let payload = TransactionBuilder::new(
            executor_test_network_id(b"fee-quote"),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "quoted".to_owned())])
        .into_payload()
        .expect("canonical unsigned payload");
        (world, nexus, pipeline, payload)
    }
    fn assert_direct_fee_exempt_draft(
        world: World,
        nexus: &iroha_config::parameters::actual::Nexus,
        pipeline: &Pipeline,
        mut payload: TransactionPayload,
    ) {
        let authority = payload.authority.clone();
        let world = world.block();
        let draft = quote_nexus_fee_admission_draft(
            &world,
            nexus,
            pipeline,
            &payload,
            0,
            1,
            Some(DataSpaceId::UNIVERSAL),
        )
        .expect("fee-exempt draft must retain its zero direct fee plan");
        assert!(draft.quote.charges.is_empty());
        assert!(draft.quote.capacities.is_empty());
        assert!(draft.quote.authority_balances.is_empty());
        assert!(draft.quote.authority_charge_assets.is_empty());
        assert!(draft.quote.relay_leases.is_empty());
        assert_eq!(draft.quote.program_revision, None);
        assert_eq!(draft.quote.debit_source, FeeDebitSource::Account(authority));
        assert_eq!(
            draft.recommended_intent,
            FeePaymentIntent::authority(Vec::new(), None)
        );
        payload.fee_payment = draft.recommended_intent.clone();
        let strict = quote_nexus_fee_admission_payload(
            &world,
            nexus,
            pipeline,
            &payload,
            0,
            1,
            Some(DataSpaceId::UNIVERSAL),
        )
        .expect("the recommended empty intent must pass strict quoting");
        assert_eq!(strict, draft.quote);
    }
    #[test]
    fn protocol_fee_exempt_draft_returns_zero_quote_in_direct_mode() {
        let (world, mut nexus, pipeline, mut payload) = multi_component_fee_quote_fixture();
        let fee_asset = AssetDefinitionId::parse_address_literal(&nexus.fees.fee_asset_id)
            .expect("fixture fee asset address");
        payload.fee_payment = FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset.clone(),
                Quantity::from(9_u32),
            )],
            None,
        );
        payload.instructions = vec![InstructionBox::from(
            iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation {
                program_id: FeeSponsorProgramId::new(
                    payload.authority.clone(),
                    "quote_exempt".parse().expect("program name"),
                ),
                program_revision: 1,
                asset_definition_id: fee_asset,
                verified_allocation: Quantity::from(1_u32),
                source_dataspace_id: DataSpaceId::UNIVERSAL,
                source_height: 1,
                source_state_root: Hash::new(b"quote-source"),
                expires_at_height: 2,
                lease_id: Hash::new(b"quote-lease"),
                manifest_root: [1; 32],
                proof_blob: iroha_data_model::nexus::ProofBlob {
                    payload: vec![1],
                    expiry_slot: None,
                },
            },
        )]
        .into();
        nexus.fees.settlement_mode =
            iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
        assert_direct_fee_exempt_draft(world, &nexus, &pipeline, payload);
    }
    include!("executor_fee_quote_tests.rs");
    #[test]
    fn retired_receipt_mode_rejects_quotes_before_signing() {
        let (world, mut nexus, pipeline, payload) = multi_component_fee_quote_fixture();
        nexus.fees.settlement_mode =
            iroha_config::parameters::actual::NexusFeeSettlementMode::LaneRelayBurn;
        let world = world.block();
        let error = quote_nexus_fee_admission_draft(
            &world,
            &nexus,
            &pipeline,
            &payload,
            0,
            1,
            Some(DataSpaceId::UNIVERSAL),
        )
        .expect_err("receipt-settled quotes must require an exact sponsor program");
        assert!(
            matches!(crate::execution_attempt::expect_completed_rejection(error), NexusFeeAdmissionError::ConfigInvalid(reason)
            if reason.contains("retired lane-relay-burn fee settlement"))
        );
    }
    #[test]
    fn retired_receipt_mode_rejects_execution_before_actual_fee_debit() {
        let authority = ALICE_ID.clone();
        let domain_id = DomainId::try_new("receipt_execution", "universal").expect("fee domain id");
        let fee_asset = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "xor".parse().expect("fee asset name"),
        );
        let mut world = World::with_assets(
            [Domain::new(domain_id).build(&authority)],
            [Account::new(authority.clone()).build(&authority)],
            [AssetDefinition::numeric(
                fee_asset.clone(),
                "fee XOR".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&authority)],
            [Asset::new(
                AssetId::new(fee_asset.clone(), authority.clone()),
                Quantity::from(100_u32),
            )],
            [],
        );
        seed_test_asset_supply(&mut world, &fee_asset);
        let state = state_after_genesis(world);
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "receipt guard".to_owned())])
        .sign(ALICE_KEYPAIR.private_key());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_tx = block.transaction();
        state_tx.nexus.fees.settlement_mode =
            iroha_config::parameters::actual::NexusFeeSettlementMode::LaneRelayBurn;
        state_tx.nexus.fees.fee_asset_id = fee_asset.canonical_address();
        install_fee_fixture_network_currency(&mut state_tx, &fee_asset);
        state_tx.nexus.fees.base_fee = Quantity::from(1_u32);
        state_tx.nexus.fees.per_byte_fee = Quantity::zero();
        state_tx.nexus.fees.per_instruction_fee = Quantity::zero();
        state_tx.nexus.fees.per_gas_unit_fee = Quantity::zero();
        let error = super::Executor::charge_nexus_fees(
            &mut state_tx,
            &authority,
            &transaction,
            None,
            1,
            1,
            0,
        )
        .expect_err("execution must defensively reject an authority-paid receipt");
        assert!(matches!(
            error,
            ValidationFail::InternalError(reason)
                if reason.contains("retired lane-relay-burn fee settlement")
        ));
        assert_eq!(
            state_tx
                .world
                .assets()
                .get(&AssetId::new(fee_asset, authority))
                .expect("authority fee balance")
                .as_ref(),
            &Quantity::from(100_u32),
            "the rejected receipt path must not debit public XOR locally"
        );
    }
    #[test]
    fn nexus_fee_charge_defensively_rejects_understated_authority_limit() {
        let (authority, keypair) = gen_account_in("nexus_actual_bound");
        let domain_id =
            DomainId::try_new("nexus_actual_bound", "universal").expect("Nexus fee domain id");
        let fee_asset = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "xor".parse().expect("fee asset name"),
        );
        let mut world = World::with_assets(
            [Domain::new(domain_id).build(&authority)],
            [Account::new(authority.clone()).build(&authority)],
            [AssetDefinition::numeric(
                fee_asset.clone(),
                "fee XOR".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&authority)],
            [Asset::new(
                AssetId::new(fee_asset.clone(), authority.clone()),
                Quantity::from(100_u32),
            )],
            [],
        );
        seed_test_asset_supply(&mut world, &fee_asset);
        let state = state_for_testing(world);
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    fee_asset.clone(),
                    Quantity::from(1_u32),
                )],
                None,
            ),
        )
        .with_instructions([Log::new(Level::INFO, "bounded Nexus fee".to_owned())])
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let mut state_transaction = block.transaction();
        state_transaction.nexus.fees.fee_asset_id = fee_asset.canonical_address();
        install_fee_fixture_network_currency(&mut state_transaction, &fee_asset);
        state_transaction.nexus.fees.base_fee = Quantity::from(2_u32);
        state_transaction.nexus.fees.per_byte_fee = Quantity::zero();
        state_transaction.nexus.fees.per_instruction_fee = Quantity::zero();
        state_transaction.nexus.fees.per_gas_unit_fee = Quantity::zero();
        let error = super::Executor::charge_nexus_fees(
            &mut state_transaction,
            &authority,
            &transaction,
            None,
            1,
            1,
            0,
        )
        .expect_err("actual Nexus charge must be checked against the signed limit");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(reason)
                if reason.contains("exceeds signed maximum")
        ));
        assert_eq!(
            state_transaction
                .world
                .assets()
                .get(&AssetId::new(fee_asset, authority))
                .expect("authority fee balance")
                .as_ref(),
            &Quantity::from(100_u32)
        );
    }
    #[test]
    fn fee_quote_configuration_failure_has_stable_rejection_code() {
        let (world, nexus, mut pipeline, payload) = multi_component_fee_quote_fixture();
        let world = world.block();
        pipeline.gas.units_per_gas.clear();
        let err = quote_nexus_fee_admission_draft(
            &world,
            &nexus,
            &pipeline,
            &payload,
            0,
            1,
            Some(DataSpaceId::UNIVERSAL),
        )
        .expect_err("missing conversion rate must reject the quote");
        assert_eq!(
            crate::execution_attempt::expect_completed_rejection(err).code(),
            FeeRejectionCode::InvalidProgramConfiguration
        );
    }
    #[test]
    fn sponsor_capacity_rejects_dataspace_scoped_fee_assets() {
        let (sponsor, _) = gen_account_in("sponsor_scope");
        let domain_id =
            DomainId::try_new("sponsor_scope", "universal").expect("sponsor scope domain");
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "fee".parse().expect("sponsor fee asset name"),
        );
        let world = World::with_assets(
            [Domain::new(domain_id.clone()).build(&sponsor)],
            [Account::new(sponsor.clone()).build(&sponsor)],
            [AssetDefinition::numeric(
                asset_definition_id.clone(),
                "scoped fee".to_owned(),
                AssetBalancePolicy::DataspaceRestricted,
                Some(domain_id),
            )
            .build(&sponsor)],
            [],
            [],
        );
        let program_id = FeeSponsorProgramId::new(
            sponsor.clone(),
            "scoped_fee".parse().expect("sponsor program name"),
        );
        let resolved = ResolvedSponsorProgram {
            id: program_id.clone(),
            revision: FeeSponsorProgramRevision {
                program_id,
                revision: 1,
                eligibility: FeeSponsorEligibility::EnrolledOnly,
                rules: Vec::new(),
                asset_budgets: vec![iroha_data_model::nexus::FeeSponsorAssetBudget {
                    asset_definition_id: asset_definition_id.clone(),
                    per_transaction: Quantity::from(10_u32),
                    per_block: Quantity::from(10_u32),
                    per_program_epoch: Quantity::from(10_u32),
                    per_beneficiary_epoch: Quantity::from(10_u32),
                    reserve_floor: Quantity::zero(),
                    epoch_length_blocks: nonzero!(1_u64),
                }],
            },
        };
        let charge = FeeChargeBound {
            kind: FeeChargeKind::PipelineGas,
            asset_definition_id,
            max_bound: Quantity::from(1_u32),
        };
        let world = world.block();
        let error = evaluate_fee_sponsor_capacity(&world, &resolved, &sponsor, 1, &[charge])
            .expect_err("sponsor accounting must reject dataspace-scoped fee assets");
        assert_eq!(error.code(), FeeRejectionCode::InvalidProgramConfiguration);
        assert!(error.reason().contains("Global balance scope"));
    }
    fn relay_allocation_fixture(
        program_id: FeeSponsorProgramId,
        program_revision: u64,
        asset_definition_id: AssetDefinitionId,
        verified_allocation: Quantity,
        source_dataspace_id: DataSpaceId,
        expires_at_height: u64,
        lease_id: Hash,
    ) -> VerifiedFeeSponsorVaultAllocation {
        VerifiedFeeSponsorVaultAllocation::new(
            program_id,
            program_revision,
            asset_definition_id,
            verified_allocation,
            source_dataspace_id,
            2,
            Hash::new(b"relay-allocation-source-state"),
            expires_at_height,
            lease_id,
            Hash::new(b"relay-allocation-proof"),
            *Hash::new(b"relay-allocation-statement").as_ref(),
            Hash::new(b"relay-allocation-proof-digest"),
            3,
            *Hash::new(b"relay-allocation-manifest").as_ref(),
            iroha_data_model::nexus::AxtFastpqBinding {
                parameter: "fastpq-state-transition-stark-v1".to_owned(),
                source_dsid: source_dataspace_id.as_u64(),
                source_dataspace: format!("dataspace-{}", source_dataspace_id.as_u64()),
                source_receipt_id: "relay-allocation-receipt".to_owned(),
                source_tx_commitment: "aa".repeat(32),
                claim_type: "fee_sponsor_vault_allocation".to_owned(),
                claim_digest: "bb".repeat(32),
                witness_commitment: "cc".repeat(32),
                policy_commitment: "dd".repeat(32),
                verified_effect_type: "fee_sponsor_vault_allocation".to_owned(),
                corridor: "fee-sponsor".to_owned(),
                verifier_id: "fastpq".to_owned(),
                verifier_version: "v1".to_owned(),
                target_dsids: vec![DataSpaceId::UNIVERSAL.as_u64()],
                effect_binding: None,
                remote_spend_intent_commitments: Vec::new(),
            },
        )
    }
    fn insert_relay_allocation(world: &mut World, record: &VerifiedFeeSponsorVaultAllocation) {
        let key: StatePath = VerifiedFeeSponsorVaultAllocation::state_key_for(
            &record.program_id,
            &record.asset_definition_id,
            &record.lease_id,
        )
        .parse()
        .expect("canonical relay allocation key");
        let json = Json::try_new(record.clone()).expect("encode relay allocation JSON");
        let payload = norito::to_bytes(&json).expect("encode relay allocation state");
        world
            .smart_contract_state_mut_for_testing()
            .insert(key, payload);
    }
    #[test]
    fn sponsor_relay_lease_selection_is_exact_canonical_and_capacity_aware() {
        let program_id = FeeSponsorProgramId::new(
            checked_account_id(),
            "relay-program".parse().expect("program name"),
        );
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("relay", "universal").expect("relay domain"),
            "xor".parse().expect("asset name"),
        );
        let dataspace_id = DataSpaceId::new(17);
        let lease_a = Hash::new(b"relay-lease-a");
        let lease_b = Hash::new(b"relay-lease-b");
        let matching_a = relay_allocation_fixture(
            program_id.clone(),
            4,
            asset_definition_id.clone(),
            Quantity::from(10_u32),
            dataspace_id,
            20,
            lease_a,
        );
        let matching_b = relay_allocation_fixture(
            program_id.clone(),
            4,
            asset_definition_id.clone(),
            Quantity::from(10_u32),
            dataspace_id,
            20,
            lease_b,
        );
        let wrong_revision = relay_allocation_fixture(
            program_id.clone(),
            3,
            asset_definition_id.clone(),
            Quantity::from(100_u32),
            dataspace_id,
            20,
            Hash::new(b"wrong-revision-lease"),
        );
        let mut world = World::default();
        insert_relay_allocation(&mut world, &matching_a);
        insert_relay_allocation(&mut world, &matching_b);
        insert_relay_allocation(&mut world, &wrong_revision);
        let selected_lease = if lease_a.as_ref() < lease_b.as_ref() {
            lease_a
        } else {
            lease_b
        };
        for lease_id in [lease_a, lease_b] {
            let executed_key: StatePath =
                VerifiedFeeSponsorVaultAllocation::usage_state_key_for(&lease_id)
                    .parse()
                    .expect("executed usage key");
            let settled_key: StatePath =
                VerifiedFeeSponsorVaultAllocation::settled_usage_state_key_for(&lease_id)
                    .parse()
                    .expect("settled usage key");
            world.smart_contract_state_mut_for_testing().insert(
                executed_key,
                norito::to_bytes(&Quantity::from(3_u32)).expect("executed usage"),
            );
            world.smart_contract_state_mut_for_testing().insert(
                settled_key,
                norito::to_bytes(&Quantity::from(6_u32)).expect("settled usage"),
            );
        }
        let world = world.block();
        let (selected, remaining) = select_fee_sponsor_relay_lease(
            &world,
            &program_id,
            4,
            &asset_definition_id,
            Some(dataspace_id),
            10,
            &Quantity::from(4_u32),
        )
        .expect("exact lease has four units remaining");
        assert_eq!(selected.lease_id, selected_lease);
        assert_eq!(remaining, Quantity::from(4_u32));
        let error = select_fee_sponsor_relay_lease(
            &world,
            &program_id,
            4,
            &asset_definition_id,
            Some(dataspace_id),
            10,
            &Quantity::from(5_u32),
        )
        .expect_err("settled usage must cap the proof-bound allocation");
        assert_eq!(error.code(), FeeRejectionCode::RelayCapacityUnavailable);
    }
    #[test]
    fn sponsor_relay_lease_selection_aggregates_same_asset_and_selects_distinct_assets() {
        let program_id = FeeSponsorProgramId::new(
            checked_account_id(),
            "multi-asset-relay".parse().expect("program name"),
        );
        let domain_id = DomainId::try_new("relay_multi", "universal").expect("relay domain");
        let shared_asset = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "shared".parse().expect("shared asset name"),
        );
        let distinct_asset = AssetDefinitionId::derive_from_components(
            domain_id,
            "distinct".parse().expect("distinct asset name"),
        );
        let dataspace_id = DataSpaceId::new(23);
        let shared_lease = Hash::new(b"shared-component-relay-lease");
        let distinct_lease = Hash::new(b"distinct-component-relay-lease");
        let mut world = World::default();
        insert_relay_allocation(
            &mut world,
            &relay_allocation_fixture(
                program_id.clone(),
                7,
                shared_asset.clone(),
                Quantity::from(10_u32),
                dataspace_id,
                20,
                shared_lease,
            ),
        );
        insert_relay_allocation(
            &mut world,
            &relay_allocation_fixture(
                program_id.clone(),
                7,
                distinct_asset.clone(),
                Quantity::from(8_u32),
                dataspace_id,
                20,
                distinct_lease,
            ),
        );
        let world = world.block();
        let same_asset_charges = [
            FeeChargeBound {
                kind: FeeChargeKind::Nexus,
                asset_definition_id: shared_asset.clone(),
                max_bound: Quantity::from(4_u32),
            },
            FeeChargeBound {
                kind: FeeChargeKind::PipelineGas,
                asset_definition_id: shared_asset.clone(),
                max_bound: Quantity::from(6_u32),
            },
        ];
        let same_asset_selection = select_fee_sponsor_relay_leases(
            &world,
            &program_id,
            7,
            Some(dataspace_id),
            10,
            &same_asset_charges,
        )
        .expect("aggregate lease capacity covers both same-asset components");
        assert_eq!(same_asset_selection.len(), 1);
        assert_eq!(same_asset_selection[&shared_asset].lease_id, shared_lease);
        assert_eq!(
            same_asset_selection[&shared_asset].remaining,
            Quantity::from(10_u32)
        );
        let distinct_asset_charges = [
            FeeChargeBound {
                kind: FeeChargeKind::Nexus,
                asset_definition_id: shared_asset.clone(),
                max_bound: Quantity::from(4_u32),
            },
            FeeChargeBound {
                kind: FeeChargeKind::PipelineGas,
                asset_definition_id: distinct_asset.clone(),
                max_bound: Quantity::from(7_u32),
            },
        ];
        let distinct_asset_selections = select_fee_sponsor_relay_leases(
            &world,
            &program_id,
            7,
            Some(dataspace_id),
            10,
            &distinct_asset_charges,
        )
        .expect("each distinct charged asset has its own lease capacity");
        assert_eq!(distinct_asset_selections.len(), 2);
        assert_eq!(
            distinct_asset_selections[&shared_asset].lease_id,
            shared_lease
        );
        assert_eq!(
            distinct_asset_selections[&distinct_asset].lease_id,
            distinct_lease
        );
        let over_capacity = [
            FeeChargeBound {
                kind: FeeChargeKind::Nexus,
                asset_definition_id: shared_asset.clone(),
                max_bound: Quantity::from(5_u32),
            },
            FeeChargeBound {
                kind: FeeChargeKind::PipelineGas,
                asset_definition_id: shared_asset,
                max_bound: Quantity::from(6_u32),
            },
        ];
        let error = select_fee_sponsor_relay_leases(
            &world,
            &program_id,
            7,
            Some(dataspace_id),
            10,
            &over_capacity,
        )
        .expect_err("same-asset components must be checked as one lease charge");
        assert_eq!(error.code(), FeeRejectionCode::RelayCapacityUnavailable);
    }
    #[test]
    fn sponsor_relay_lease_selection_rejects_noncanonical_record_key() {
        let program_id = FeeSponsorProgramId::new(
            checked_account_id(),
            "relay-program".parse().expect("program name"),
        );
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("relay", "universal").expect("relay domain"),
            "xor".parse().expect("asset name"),
        );
        let record = relay_allocation_fixture(
            program_id.clone(),
            1,
            asset_definition_id.clone(),
            Quantity::from(10_u32),
            DataSpaceId::UNIVERSAL,
            20,
            Hash::new(b"noncanonical-relay-lease"),
        );
        let mut world = World::default();
        let key: StatePath =
            format!("{VERIFIED_FEE_SPONSOR_VAULT_ALLOCATION_STATE_KEY_PREFIX}_noncanonical")
                .parse()
                .expect("noncanonical fixture key");
        let json = Json::try_new(record).expect("encode relay allocation JSON");
        world.smart_contract_state_mut_for_testing().insert(
            key,
            norito::to_bytes(&json).expect("encode relay allocation state"),
        );
        let world = world.block();
        let error = select_fee_sponsor_relay_lease(
            &world,
            &program_id,
            1,
            &asset_definition_id,
            Some(DataSpaceId::UNIVERSAL),
            10,
            &Quantity::from(1_u32),
        )
        .expect_err("noncanonical allocation state must fail closed");
        assert_eq!(error.code(), FeeRejectionCode::InvalidProgramConfiguration);
    }
    #[test]
    fn sponsor_relay_lease_consumption_tracks_direct_and_receipt_settlement() {
        let program_id = FeeSponsorProgramId::new(
            checked_account_id(),
            "relay-consumption".parse().expect("program name"),
        );
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("relay_consumption", "universal").expect("relay domain"),
            "xor".parse().expect("asset name"),
        );
        let lease_id = Hash::new(b"relay-consumption-lease");
        let mut world = World::default();
        insert_relay_allocation(
            &mut world,
            &relay_allocation_fixture(
                program_id.clone(),
                9,
                asset_definition_id.clone(),
                Quantity::from(10_u32),
                DataSpaceId::UNIVERSAL,
                20,
                lease_id,
            ),
        );
        let state = state_for_testing(world);
        let mut block = state.block(BlockHeader::new(nonzero!(10_u64), None, None, 0, 0));
        let mut state_transaction = block.transaction();
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        super::Executor::consume_fee_sponsor_relay_lease(
            &mut state_transaction,
            &program_id,
            9,
            &asset_definition_id,
            &Quantity::from(3_u32),
            true,
        )
        .expect("direct-settled PipelineGas consumes both usage counters");
        let executed_key =
            fee_sponsor_vault_allocation_usage_state_key(&lease_id).expect("executed usage key");
        let settled_key = fee_sponsor_vault_allocation_settled_usage_state_key(&lease_id)
            .expect("settled usage key");
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                .expect("executed usage"),
            Quantity::from(3_u32)
        );
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                .expect("settled usage"),
            Quantity::from(3_u32)
        );
        super::Executor::consume_fee_sponsor_relay_lease(
            &mut state_transaction,
            &program_id,
            9,
            &asset_definition_id,
            &Quantity::from(2_u32),
            false,
        )
        .expect("receipt-settled Nexus charge advances executed usage only");
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                .expect("executed usage"),
            Quantity::from(5_u32)
        );
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                .expect("settled usage"),
            Quantity::from(3_u32)
        );
        super::Executor::consume_fee_sponsor_relay_lease(
            &mut state_transaction,
            &program_id,
            9,
            &asset_definition_id,
            &Quantity::from(1_u32),
            true,
        )
        .expect("a later direct charge must not mark the pending receipt as settled");
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                .expect("executed usage"),
            Quantity::from(6_u32)
        );
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                .expect("settled usage"),
            Quantity::from(4_u32)
        );
        let error = super::Executor::consume_fee_sponsor_relay_lease(
            &mut state_transaction,
            &program_id,
            9,
            &asset_definition_id,
            &Quantity::from(5_u32),
            true,
        )
        .expect_err("insufficient remaining capacity must reject before usage mutation");
        assert!(matches!(error, ValidationFail::NotPermitted(_)));
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &executed_key)
                .expect("executed usage"),
            Quantity::from(6_u32)
        );
        assert_eq!(
            fee_sponsor_vault_allocation_quantity_at(&state_transaction.world, &settled_key)
                .expect("settled usage"),
            Quantity::from(4_u32)
        );
    }
    #[test]
    fn detached_register_peer_forces_sequential_path() {
        let peer_id = make_peer_id();
        let isi = iroha_data_model::isi::register::RegisterPeerWithPop::new(peer_id, Vec::new());
        let mut delta = crate::state::DetachedStateTransactionDelta::default();
        let err = execute_instruction_detached(&alice(), &InstructionBox::from(isi), &mut delta)
            .expect_err("peer registration must be unsupported in detached mode");
        assert!(matches!(err, ValidationFail::InternalError(msg) if msg.contains("registration")));
    }
    #[test]
    fn detached_register_committee_peer_forces_sequential_path() {
        let peer_id = make_peer_id();
        let isi =
            iroha_data_model::isi::register::RegisterCommitteePeerWithPop::new(peer_id, Vec::new());
        let mut delta = crate::state::DetachedStateTransactionDelta::default();
        let err = execute_instruction_detached(&alice(), &InstructionBox::from(isi), &mut delta)
            .expect_err("committee peer registration must be unsupported in detached mode");
        assert!(matches!(err, ValidationFail::InternalError(msg) if msg.contains("registration")));
    }
    #[test]
    fn detached_unregister_peer_forces_sequential_path() {
        let peer_id = make_peer_id();
        let isi = iroha_data_model::isi::Unregister::peer(peer_id);
        let mut delta = crate::state::DetachedStateTransactionDelta::default();
        let err = execute_instruction_detached(&alice(), &InstructionBox::from(isi), &mut delta)
            .expect_err("peer removal must be unsupported in detached mode");
        assert!(matches!(err, ValidationFail::InternalError(msg) if msg.contains("removal")));
    }
    #[test]
    fn detached_execute_trigger_forces_sequential_path() {
        let trigger_id = "detached_trigger".parse().expect("valid trigger id");
        let instruction =
            InstructionBox::from(iroha_data_model::isi::ExecuteTrigger::new(trigger_id));
        let mut delta = crate::state::DetachedStateTransactionDelta::default();
        let error = execute_instruction_detached(&alice(), &instruction, &mut delta)
            .expect_err("trigger execution needs the live executor and trigger state");
        assert!(matches!(error, ValidationFail::InternalError(message) if
            message.contains("live authorization") && message.contains("sequential")));
    }
    #[test]
    fn detached_supply_changes_force_sequential_path() {
        let definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("wonderland", "universal")
                .expect("valid domain id"),
            "rose".parse().expect("valid asset name"),
        );
        let asset_id = iroha_data_model::asset::AssetId::new(definition_id, alice());
        let instructions = [
            InstructionBox::from(iroha_data_model::isi::Mint::asset_quantity(
                1_u32,
                asset_id.clone(),
            )),
            InstructionBox::from(iroha_data_model::isi::Burn::asset_quantity(1_u32, asset_id)),
        ];
        for instruction in instructions {
            let mut delta = crate::state::DetachedStateTransactionDelta::default();
            let error = execute_instruction_detached(&alice(), &instruction, &mut delta)
                .expect_err("supply changes need canonical sequential execution");
            assert!(matches!(error, ValidationFail::InternalError(message) if
                message.contains("live authorization") && message.contains("sequential")));
        }
    }
    #[test]
    fn detached_transfers_keep_authorization_in_the_canonical_executor() {
        let authority = alice();
        let other = checked_account_id();
        let destination = checked_account_id();
        let domain_id =
            DomainId::try_new("wonderland", "universal").expect("valid domain identifier");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "rose".parse().expect("valid asset name"),
        );
        let delegated_asset = InstructionBox::from(Transfer::asset_quantity(
            AssetId::new(definition_id.clone(), other.clone()),
            1_u32,
            destination.clone(),
        ));
        let domain = InstructionBox::from(Transfer::domain(
            authority.clone(),
            domain_id.clone(),
            destination.clone(),
        ));
        let asset_definition = InstructionBox::from(Transfer::asset_definition(
            authority.clone(),
            definition_id,
            destination.clone(),
        ));
        let nft = InstructionBox::from(Transfer::nft(
            authority.clone(),
            NftId::new(domain_id, "ticket".parse().expect("valid NFT name")),
            destination,
        ));
        for instruction in [delegated_asset, domain, asset_definition, nft] {
            let mut delta = crate::state::DetachedStateTransactionDelta::default();
            let error = execute_instruction_detached(&authority, &instruction, &mut delta)
                .expect_err("authorization-sensitive transfers must execute sequentially");
            assert!(matches!(error, ValidationFail::InternalError(message) if
                message.contains("sequential authorization")));
        }
        let owned_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain identifier"),
            "owned".parse().expect("valid asset name"),
        );
        let owned_source = AssetId::new(owned_definition, authority.clone());
        let owned_transfer = InstructionBox::from(Transfer::asset_quantity(
            owned_source.clone(),
            1_u32,
            other.clone(),
        ));
        let mut delta = crate::state::DetachedStateTransactionDelta::default();
        execute_instruction_detached(&authority, &owned_transfer, &mut delta)
            .expect("source-owned transparent transfer may use canonical detached replay");
        assert_eq!(
            delta.single_transfer_delta(),
            Some((owned_source, other, Quantity::from(1_u32)))
        );
    }
    #[test]
    fn detached_contract_deployment_permission_mutation_forces_sequential_path() {
        let authority = alice();
        let instruction: InstructionBox =
            Grant::account_permission(contract_deployment_permission(), authority.clone()).into();
        let mut delta = crate::state::DetachedStateTransactionDelta::default();
        let error = execute_instruction_detached(&authority, &instruction, &mut delta)
            .expect_err("deployment permission mutation must fall back to the consensus gate");
        assert!(matches!(error, ValidationFail::InternalError(message) if
            message.contains("CanManageSmartContractCode")
                && message.contains("sequential consensus gate")));
    }
    #[test]
    fn detached_asset_instructions_cannot_be_constructed_with_negative_quantities() {
        let negative = Numeric::new(-1_i32, 0);
        assert!(Quantity::try_from_numeric(negative).is_err());
    }
    #[test]
    fn detached_nft_metadata_forces_sequential_authorization() {
        let nft_id: NftId = "nft_detached$wonderland.universal".parse().expect("nft id");
        let key: Name = "meta".parse().expect("key");
        let set = SetKeyValue::nft(nft_id, key, "value");
        let mut delta = crate::state::DetachedStateTransactionDelta::default();
        let error = execute_instruction_detached(&alice(), &InstructionBox::from(set), &mut delta)
            .expect_err("metadata authorization requires the live sequential world");
        assert!(matches!(error, ValidationFail::InternalError(message) if
            message.contains("live authorization") && message.contains("sequential")));
    }
    use std::collections::{BTreeMap, BTreeSet};
    #[allow(dead_code)]
    fn encode_load(rd: u8, base: u8, imm12: u16, funct3: u8) -> u32 {
        let imm = u32::from(imm12 & 0x0fff);
        (imm << 20)
            | ((u32::from(base) & 0x1f) << 15)
            | ((u32::from(funct3) & 0x7) << 12)
            | ((u32::from(rd) & 0x1f) << 7)
            | 0x03
    }
    #[allow(dead_code)]
    fn encode_store(base: u8, rs: u8, imm12: u16, funct3: u8) -> u32 {
        let imm = u32::from(imm12 & 0x0fff);
        let imm_hi = (imm >> 5) & 0x7f;
        let imm_lo = imm & 0x1f;
        (imm_hi << 25)
            | ((u32::from(rs) & 0x1f) << 20)
            | ((u32::from(base) & 0x1f) << 15)
            | ((u32::from(funct3) & 0x7) << 12)
            | (imm_lo << 7)
            | 0x23
    }
    #[cfg(all(feature = "zk-preverify", feature = "zk-stark"))]
    fn preverify_stark_fixture() -> (
        String,
        iroha_data_model::proof::VerifyingKeyBox,
        iroha_data_model::proof::ProofBox,
    ) {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:executor-preverify-v1");
        let key = crate::zk_stark::StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id: circuit_id.clone(),
            n_log2: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
            blowup_log2: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
            fold_arity: 2,
            queries: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
            merkle_arity: 2,
        };
        let vk = iroha_data_model::proof::VerifyingKeyBox::new(
            backend.into(),
            norito::encode_canonical(&key).expect("canonical STARK verifier key"),
        );
        let proof = crate::zk::prove_stark_fri_open_verify_envelope(
            backend,
            &circuit_id,
            &vk,
            b"executor-preverify-v1",
            vec![vec![[0x11; 32]]],
        )
        .expect("native STARK preverify fixture");
        (circuit_id, vk, proof)
    }
    #[cfg(all(feature = "zk-preverify", feature = "zk-stark"))]
    #[test]
    fn preverify_and_dedup_across_transactions_in_block() {
        use iroha_data_model::{
            isi::verifying_keys::RegisterVerifyingKey,
            proof::{ProofAttachment, ProofAttachmentList, VerifyingKeyId, VerifyingKeyRecord},
            transaction::{Executable, TransactionBuilder},
            zk::BackendTag,
        };
        use iroha_executor_data_model::permission::governance::CanManageVerifyingKeys;
        use iroha_schema::Ident;
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        let (_sink_id, _sink_kp) = gen_account_in("wonderland");
        let (_sponsor_id, _sponsor_kp) = gen_account_in("wonderland");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain: Domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([domain], [alice_account], []);
        let backend: Ident = "stark/fri/poseidon-x7-goldilocks-6x64-v1"
            .parse()
            .expect("backend ident");
        let (circuit_id, vk, proof) = preverify_stark_fixture();
        let vk_id = VerifyingKeyId::new(backend.clone(), "vk_preverify");
        let vk_commitment = crate::zk::hash_vk(&vk);
        let mut vk_record = VerifyingKeyRecord::new_with_owner(
            1,
            circuit_id,
            None,
            "test",
            BackendTag::Stark,
            "goldilocks",
            iroha_crypto::Hash::new(b"executor-preverify-v1").into(),
            vk_commitment,
        );
        vk_record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
        vk_record.vk_len = u32::try_from(vk.bytes.len()).expect("fixture vk length fits");
        vk_record.max_proof_bytes = u32::try_from(proof.bytes.len()).expect("bounded proof size");
        vk_record.gas_schedule_id = Some("stark_default".to_owned());
        vk_record.key = Some(vk);
        let state = state_after_genesis_with_instructions(world, |genesis_account| {
            vec![
                Grant::account_permission(CanManageVerifyingKeys, genesis_account.clone()).into(),
                RegisterVerifyingKey {
                    id: vk_id.clone(),
                    record: vk_record,
                }
                .into(),
            ]
        });
        let block_header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(block_header);
        let mut attachment = ProofAttachment::new_ref(backend, proof, vk_id);
        attachment.vk_commitment = Some(vk_commitment);
        let attachments = ProofAttachmentList::try_from(vec![attachment.clone()])
            .expect("one attachment is a valid bounded proof list");
        let attachments_dup = ProofAttachmentList::try_from(vec![attachment])
            .expect("one attachment is a valid bounded proof list");
        let tx1 = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Instructions(Vec::new().into()))
        .with_attachments(attachments)
        .sign(ALICE_KEYPAIR.private_key());
        let tx2 = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Instructions(Vec::new().into()))
        .with_attachments(attachments_dup)
        .sign(ALICE_KEYPAIR.private_key());
        let executor = super::Executor::Initial;
        let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
        // First transaction preverify accepted
        {
            let mut state_tx =
                block.transaction_for_fastpq_testing(Hash::from(tx1.hash_as_entrypoint()));
            state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            executor
                .execute_transaction(&mut state_tx, &ALICE_ID.clone(), tx1, &mut ivm_cache)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect("preverify accepted");
        }
        // Second identical proof should be flagged as duplicate by per-block dedup
        {
            let mut state_tx =
                block.transaction_for_fastpq_testing(Hash::from(tx2.hash_as_entrypoint()));
            state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let res = executor
                .execute_transaction(&mut state_tx, &ALICE_ID.clone(), tx2, &mut ivm_cache)
                .map_err(crate::execution_attempt::expect_completed_rejection);
            assert!(res.is_err(), "duplicate proof should be rejected");
        }
    }
    #[cfg(all(feature = "zk-preverify", feature = "zk-stark"))]
    #[test]
    fn preverify_attachments_enforce_verifying_key_height_window() {
        use iroha_data_model::{
            isi::verifying_keys::RegisterVerifyingKey,
            proof::{ProofAttachment, ProofAttachmentList, VerifyingKeyId, VerifyingKeyRecord},
            transaction::{Executable, TransactionBuilder},
            zk::BackendTag,
        };
        use iroha_executor_data_model::permission::governance::CanManageVerifyingKeys;
        use iroha_schema::Ident;
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        fn execute_with_window(
            activation_height: Option<u64>,
            withdraw_height: Option<u64>,
            block_height: u64,
        ) -> Result<(), ValidationFail> {
            let domain_id: DomainId =
                DomainId::try_new("wonderland", "universal").expect("domain id");
            let domain: Domain = Domain::new(domain_id).build(&ALICE_ID);
            let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
            let world = World::with([domain], [alice_account], []);
            let backend: Ident = "stark/fri/poseidon-x7-goldilocks-6x64-v1"
                .parse()
                .expect("backend ident");
            let (circuit_id, vk, proof) = preverify_stark_fixture();
            let vk_id = VerifyingKeyId::new(backend.clone(), "vk_height_window");
            let vk_commitment = crate::zk::hash_vk(&vk);
            let mut vk_record = VerifyingKeyRecord::new_with_owner(
                1,
                circuit_id,
                None,
                "test",
                BackendTag::Stark,
                "goldilocks",
                iroha_crypto::Hash::new(b"executor-preverify-v1").into(),
                vk_commitment,
            );
            vk_record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
            vk_record.activation_height = activation_height;
            vk_record.withdraw_height = withdraw_height;
            vk_record.vk_len = u32::try_from(vk.bytes.len()).expect("fixture vk length fits");
            vk_record.max_proof_bytes =
                u32::try_from(proof.bytes.len()).expect("bounded proof size");
            vk_record.gas_schedule_id = Some("stark_default".to_owned());
            vk_record.key = Some(vk);
            let state = state_after_genesis_with_instructions(world, |genesis_account| {
                vec![
                    Grant::account_permission(CanManageVerifyingKeys, genesis_account.clone())
                        .into(),
                    RegisterVerifyingKey {
                        id: vk_id.clone(),
                        record: vk_record,
                    }
                    .into(),
                ]
            });
            let mut attachment = ProofAttachment::new_ref(backend, proof, vk_id);
            attachment.vk_commitment = Some(vk_commitment);
            let tx = TransactionBuilder::new(
                state.network_id,
                ALICE_ID.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_executable(Executable::Instructions(Vec::new().into()))
            .with_attachments(
                ProofAttachmentList::try_from(vec![attachment])
                    .expect("one attachment is a valid bounded proof list"),
            )
            .sign(ALICE_KEYPAIR.private_key());
            let block_header = BlockHeader::new(
                std::num::NonZeroU64::new(block_height).expect("nonzero block height"),
                Some(
                    state
                        .view()
                        .latest_block_hash()
                        .expect("genuine genesis parent"),
                ),
                None,
                0,
                0,
            );
            let mut block = state.block(block_header);
            let mut state_tx =
                block.transaction_for_fastpq_testing(Hash::from(tx.hash_as_entrypoint()));
            state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let executor = super::Executor::Initial;
            let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
            executor
                .execute_transaction(&mut state_tx, &ALICE_ID.clone(), tx, &mut ivm_cache)
                .map_err(crate::execution_attempt::expect_completed_rejection)
        }
        for (label, activation_height, withdraw_height, block_height) in [
            ("future", Some(3), None, 2),
            ("withdrawn", Some(1), Some(2), 2),
            ("expired", Some(2), Some(3), 3),
        ] {
            let err = execute_with_window(activation_height, withdraw_height, block_height)
                .expect_err("out-of-window verifying key must reject");
            match err {
                ValidationFail::NotPermitted(msg) => assert!(
                    msg.contains("verifying key inactive"),
                    "case {label}: unexpected error: {msg}"
                ),
                other => panic!("case {label}: unexpected error: {other:?}"),
            }
        }
        execute_with_window(Some(2), Some(3), 2)
            .expect("in-window active verifying key must preverify");
    }
    #[cfg(feature = "zk-preverify")]
    #[test]
    fn preverify_attachments_reject_non_production_backend_labels_before_vk_lookup() {
        use iroha_data_model::{
            proof::{ProofAttachment, ProofAttachmentList, ProofBox, VerifyingKeyId},
            transaction::{Executable, TransactionBuilder},
        };
        use iroha_schema::Ident;
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain: Domain = Domain::new(domain_id).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([domain], [alice_account], []);
        let state = state_after_genesis(world);
        let block_header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(block_header);
        let executor = super::Executor::Initial;
        let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
        for (idx, (backend, expected_msg)) in [
            (
                "halo2/ipa:production-ready",
                "readiness-claim proof backends",
            ),
            ("halo2/ipa:kzg", "trusted-setup proof backends"),
            ("halo2/ipa:dev-fixture", "developer-only proof backends"),
            ("halo2/unknown-native-v1", "unsupported proof backends"),
        ]
        .into_iter()
        .enumerate()
        {
            let backend_ident: Ident = backend.parse().expect("backend ident");
            let proof = ProofBox::new(
                backend_ident.clone(),
                vec![0xA0 | u8::try_from(idx).unwrap()],
            );
            let attachment = ProofAttachment::new_ref(
                backend_ident.clone(),
                proof,
                VerifyingKeyId::new(backend_ident, format!("missing_vk_{idx}")),
            );
            let tx = TransactionBuilder::new(
                state.network_id,
                ALICE_ID.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_executable(Executable::Instructions(Vec::new().into()))
            .with_attachments(
                ProofAttachmentList::try_from(vec![attachment])
                    .expect("one attachment is a valid bounded proof list"),
            )
            .sign(ALICE_KEYPAIR.private_key());
            let mut state_tx =
                block.transaction_for_fastpq_testing(Hash::from(tx.hash_as_entrypoint()));
            state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let err = executor
                .execute_transaction(&mut state_tx, &ALICE_ID.clone(), tx, &mut ivm_cache)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("non-production proof backend label must fail before vk lookup");
            match err {
                ValidationFail::NotPermitted(msg) => {
                    assert!(
                        msg.contains(expected_msg),
                        "unexpected msg for {backend}: {msg}"
                    );
                    assert!(
                        !msg.contains("referenced verifying key missing"),
                        "backend classification for {backend} must precede vk lookup: {msg}"
                    );
                }
                other => panic!("unexpected error for {backend}: {other:?}"),
            }
        }
    }
    #[cfg(feature = "zk-preverify")]
    #[test]
    fn preverify_attachments_reject_malformed_attachment_shapes_before_vk_lookup() {
        use iroha_data_model::{
            proof::{ProofAttachment, ProofAttachmentList, ProofBox, VerifyingKeyId},
            transaction::{Executable, TransactionBuilder},
        };
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain: Domain = Domain::new(domain_id).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([domain], [alice_account], []);
        let state = state_after_genesis(world);
        let block_header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(block_header);
        let executor = super::Executor::Initial;
        let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
        let mut zero_vk_commitment = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_preverify"),
        );
        zero_vk_commitment.vk_commitment = Some([0u8; 32]);
        let mut zero_envelope_hash = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_preverify"),
        );
        zero_envelope_hash.envelope_hash = Some([0u8; 32]);
        let mut forged_envelope_hash = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_preverify"),
        );
        let mut forged_hash: [u8; 32] =
            iroha_crypto::Hash::new(&forged_envelope_hash.proof.bytes).into();
        forged_hash[0] ^= 0x80;
        forged_envelope_hash.envelope_hash = Some(forged_hash);
        assert!(matches!(
            ProofAttachmentList::try_from(Vec::new()),
            Err(iroha_data_model::proof::ProofAttachmentListError::Empty)
        ));
        let cases = [
            (
                "proof-backend-mismatch",
                ProofAttachmentList::try_from(vec![ProofAttachment::new_ref(
                    "halo2/ipa".into(),
                    ProofBox::new("stark/fri".into(), vec![1, 2, 3]),
                    VerifyingKeyId::new("halo2/ipa", "vk_preverify"),
                )])
                .expect("one attachment is a valid bounded proof list"),
                "proof.backend",
            ),
            (
                "nonportable-vk-ref-name",
                ProofAttachmentList::try_from(vec![ProofAttachment::new_ref(
                    "halo2/ipa".into(),
                    ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                    VerifyingKeyId::new("halo2/ipa", "VkPreverify"),
                )])
                .expect("one attachment is a valid bounded proof list"),
                "vk_ref",
            ),
            (
                "empty-proof-bytes",
                ProofAttachmentList::try_from(vec![ProofAttachment::new_ref(
                    "halo2/ipa".into(),
                    ProofBox::new("halo2/ipa".into(), Vec::new()),
                    VerifyingKeyId::new("halo2/ipa", "vk_preverify"),
                )])
                .expect("one attachment is a valid bounded proof list"),
                "proof.bytes",
            ),
            (
                "zero-vk-commitment",
                ProofAttachmentList::try_from(vec![zero_vk_commitment])
                    .expect("one attachment is a valid bounded proof list"),
                "vk_commitment",
            ),
            (
                "zero-envelope-hash",
                ProofAttachmentList::try_from(vec![zero_envelope_hash])
                    .expect("one attachment is a valid bounded proof list"),
                "envelope_hash",
            ),
            (
                "forged-envelope-hash",
                ProofAttachmentList::try_from(vec![forged_envelope_hash])
                    .expect("one attachment is a valid bounded proof list"),
                "envelope_hash",
            ),
        ];
        for (label, attachments, expected_msg) in cases {
            let tx = TransactionBuilder::new(
                state.network_id,
                ALICE_ID.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_executable(Executable::Instructions(Vec::new().into()))
            .with_attachments(attachments)
            .sign(ALICE_KEYPAIR.private_key());
            let mut state_tx =
                block.transaction_for_fastpq_testing(Hash::from(tx.hash_as_entrypoint()));
            state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let err = executor
                .execute_transaction(&mut state_tx, &ALICE_ID.clone(), tx, &mut ivm_cache)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("malformed proof attachment must fail before vk lookup");
            match err {
                ValidationFail::NotPermitted(msg) => {
                    assert!(
                        msg.contains(expected_msg),
                        "case {label}: expected {expected_msg:?} in error message: {msg}"
                    );
                    assert!(
                        !msg.contains("referenced verifying key missing"),
                        "case {label}: malformed attachment shape must reject before vk lookup: {msg}"
                    );
                }
                other => panic!("case {label}: unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn initial_executor_denies_asset_definition_without_permission() {
        let alice_id = ALICE_ID.clone();
        let genesis_id = SAMPLE_GENESIS_ACCOUNT_ID.clone();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain: Domain = Domain::new(domain_id.clone()).build(&genesis_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let genesis_account = Account::new(genesis_id.clone()).build(&genesis_id);
        let world = World::with([domain], [alice_account, genesis_account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = query::store::LiveQueryStore::start_test();
        let state = State::new(world, kura, query_handle);
        state
            .block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0))
            .commit_empty_block_for_testing()
            .expect("commit bootstrap block");
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(header);
        {
            let mut stx = block.transaction();
            Transfer::domain(genesis_id.clone(), domain_id.clone(), alice_id.clone())
                .execute(&genesis_id, &mut stx)
                .expect("domain transfer to succeed");
            stx.apply();
        }
        let executor = super::Executor::Initial;
        let asset_definition_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "invalid".parse().unwrap(),
            );
        let instruction = InstructionBox::from(Register::asset_definition({
            let __asset_definition_id = asset_definition_id;
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "invalid".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }));
        let mut stx = block.transaction();
        let res = executor.execute_instruction(&mut stx, &genesis_id, instruction);
        assert!(
            matches!(res, Err(ValidationFail::NotPermitted(_))),
            "initial executor should deny registering asset definition without permission"
        );
    }
    #[test]
    fn borrowed_overlay_apply_matches_owned_initial_executor_for_register_domain() {
        let executor = super::Executor::Initial;
        let domain_id: DomainId =
            DomainId::try_new("borrowed-overlay", "universal").expect("domain id");
        let owned = prepared_native_domain_genesis_fixture(&domain_id);
        let source = owned.genesis.block();
        let owned_instruction: InstructionBox =
            Register::domain(Domain::new(domain_id.clone())).into();
        let index = exact_native_genesis_fixture_index(source, &owned_instruction);
        let mut owned_block = owned
            .state
            .block_with_pristine_carrier_stage(source, |_| Ok::<_, String>(()))
            .expect("capture exact owned native genesis carrier");
        let mut owned_tx = owned_block
            .transaction_for_original_genesis_testing(source, index, &ALICE_ID, &owned_instruction)
            .expect("authenticate actual owned RegisterDomain input");
        executor
            .execute_instruction(&mut owned_tx, &ALICE_ID.clone(), owned_instruction)
            .expect("owned initial executor applies instruction");
        assert!(owned_tx.world.domains.get(&domain_id).is_some());
        let overlay_state = prepared_native_domain_genesis_fixture(&domain_id);
        let source = overlay_state.genesis.block();
        let overlay_instruction: InstructionBox =
            Register::domain(Domain::new(domain_id.clone())).into();
        let index = exact_native_genesis_fixture_index(source, &overlay_instruction);
        let mut overlay_block = overlay_state
            .state
            .block_with_pristine_carrier_stage(source, |_| Ok::<_, String>(()))
            .expect("capture exact borrowed native genesis carrier");
        let mut overlay_tx = overlay_block
            .transaction_for_original_genesis_testing(
                source,
                index,
                &ALICE_ID,
                &overlay_instruction,
            )
            .expect("authenticate actual borrowed RegisterDomain input");
        let overlay =
            crate::pipeline::overlay::TxOverlay::from_instructions(vec![overlay_instruction]);
        overlay
            .apply_with_chunk(&mut overlay_tx, &ALICE_ID.clone(), 1)
            .expect("borrowed overlay applies instruction");
        assert!(overlay_tx.world.domains.get(&domain_id).is_some());
    }
    #[test]
    fn borrowed_overlay_apply_matches_owned_initial_executor_for_register_account() {
        let account = checked_account_id();
        let instruction: InstructionBox = Register::account(Account::new(account.clone())).into();
        let mut outcomes = Vec::new();
        for borrowed in [false, true] {
            let state = state_after_genesis(World::with(
                [],
                [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
                [],
            ));
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                state.view().latest_block_hash(),
                None,
                0,
                0,
            ));
            let mut tx = block
                .transaction_for_fastpq_testing(Hash::new(b"owned-borrowed account registration"));
            if borrowed {
                let overlay = crate::pipeline::overlay::TxOverlay::from_instructions(vec![
                    instruction.clone(),
                ]);
                overlay
                    .apply_with_chunk(&mut tx, &ALICE_ID, 1)
                    .expect("borrowed account registration");
            } else {
                super::Executor::Initial
                    .execute_instruction(&mut tx, &ALICE_ID, instruction.clone())
                    .expect("owned account registration");
            }
            assert!(tx.world.accounts.get(&account).is_some());
            let account_value = tx.world.accounts.get(&account).unwrap().clone();
            tx.apply();
            outcomes.push((account_value, block.world.take_external_events()));
            assert_eq!(block.committed_fragment_count(), 1);
            assert!(block.world.accounts.get(&account).is_some());
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }
    #[test]
    fn original_native_genesis_requires_source_capability_for_owned_and_borrowed_execution() {
        let world = || World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        let domain_id = DomainId::try_new("borrowed-overlay", "universal").unwrap();
        let instruction: InstructionBox = Register::domain(Domain::new(domain_id.clone())).into();
        // Height-only component overlays cannot execute genesis through either API.
        for borrowed in [false, true] {
            let state = component_state_for_testing(world());
            let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let mut tx = block.transaction();
            let error = if borrowed {
                super::Executor::Initial.execute_borrowed_overlay_instruction(
                    &mut tx,
                    &ALICE_ID,
                    &instruction,
                    None,
                )
            } else {
                super::Executor::Initial.execute_instruction(
                    &mut tx,
                    &ALICE_ID,
                    instruction.clone(),
                )
            }
            .expect_err("missing original genesis capability rejects");
            assert!(
                matches!(&error, ValidationFail::NotPermitted(reason)
                if reason == "genesis instruction execution requires its authenticated source capability"),
                "{error:?}"
            );
            assert!(tx.world.domains.get(&domain_id).is_none());
            drop(tx);
            assert_eq!(block.committed_fragment_count(), 0);
        }
    }
    fn prepared_native_domain_genesis_fixture(
        domain_id: &DomainId,
    ) -> crate::sumeragi::test_chain::PreparedTestChainConfig {
        let wonderland = DomainId::try_new("wonderland", "universal").expect("domain id");
        let world = World::with(
            [Domain::new(wonderland).build(&ALICE_ID)],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [],
        );
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
        config.genesis_key = ALICE_KEYPAIR.clone();
        config
            .genesis_instructions
            .push(Register::domain(Domain::new(domain_id.clone())).into());
        crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
            .expect("prepare genuinely validated native domain genesis")
    }

    fn exact_native_genesis_fixture_index(
        source: &iroha_data_model::block::SignedBlock,
        instruction: &InstructionBox,
    ) -> usize {
        source.external_transactions().position(|signed| matches!(signed.instructions(),
            Executable::Instructions(instructions) if instructions.iter().eq(core::iter::once(instruction))
        )).expect("original signed input contains exactly the component instruction")
    }

    #[test]
    fn original_native_genesis_component_refuses_source_and_instruction_substitution() {
        let domain_id = DomainId::try_new("source-custody", "universal").unwrap();
        let prepared = prepared_native_domain_genesis_fixture(&domain_id);
        let source = prepared.genesis.block();
        let instruction: InstructionBox = Register::domain(Domain::new(domain_id)).into();
        let index = exact_native_genesis_fixture_index(source, &instruction);
        // Each phase retains one original acquisition in its own debug stack frame
        // while checking the same signed sources and refusal assertions.
        assert_native_genesis_absent_original_source(&prepared, &instruction, index);
        assert_native_genesis_component_identity_refusals(&prepared, &instruction, index);
        assert_native_genesis_foreign_signed_source(&prepared);
        assert_native_genesis_foreign_state_network(&prepared, &instruction, index);
        assert_native_genesis_successor_header(&prepared, &instruction, index);
        assert_native_genesis_committed_bootstrap_refusal(&prepared, &instruction, index);
    }

    #[inline(never)]
    fn assert_native_genesis_absent_original_source(
        prepared: &crate::sumeragi::test_chain::PreparedTestChainConfig,
        instruction: &InstructionBox,
        index: usize,
    ) {
        let source = prepared.genesis.block();
        let mut absent = prepared.state.block(source.header());
        assert!(
            absent
                .transaction_for_original_genesis_testing(source, index, &ALICE_ID, instruction)
                .is_err(),
            "H1 without retained original route must refuse"
        );
        drop(absent);
    }

    #[inline(never)]
    fn assert_native_genesis_component_identity_refusals(
        prepared: &crate::sumeragi::test_chain::PreparedTestChainConfig,
        instruction: &InstructionBox,
        index: usize,
    ) {
        let source = prepared.genesis.block();
        let mut block = prepared
            .state
            .block_with_pristine_carrier_stage(source, |_| Ok::<_, String>(()))
            .unwrap();
        assert!(
            block
                .transaction_for_original_genesis_testing(source, index, &BOB_ID, instruction)
                .is_err(),
            "configured signer mismatch must refuse"
        );
        assert!(
            block
                .transaction_for_original_genesis_testing(
                    source,
                    source.network_entrypoint_count(),
                    &ALICE_ID,
                    instruction
                )
                .is_err(),
            "absent original ordinal must refuse"
        );
        assert!(
            block
                .transaction_for_original_genesis_testing(source, 0, &ALICE_ID, instruction)
                .is_err(),
            "a different valid original ordinal must not authenticate the tested instruction"
        );
        let substituted: InstructionBox =
            Log::new(Level::INFO, "substituted component effect".to_owned()).into();
        assert!(
            block
                .transaction_for_original_genesis_testing(source, index, &ALICE_ID, &substituted)
                .is_err(),
            "authentic RegisterDomain must not bless a substituted Log"
        );
        drop(block);
    }

    #[inline(never)]
    fn assert_native_genesis_foreign_signed_source(
        prepared: &crate::sumeragi::test_chain::PreparedTestChainConfig,
    ) {
        let source = prepared.genesis.block();
        let other_domain = DomainId::try_new("foreign-source", "universal").unwrap();
        let foreign = prepared_native_domain_genesis_fixture(&other_domain);
        let foreign_instruction: InstructionBox =
            Register::domain(Domain::new(other_domain)).into();
        let foreign_index =
            exact_native_genesis_fixture_index(foreign.genesis.block(), &foreign_instruction);
        let mut block = prepared
            .state
            .block_with_pristine_carrier_stage(source, |_| Ok::<_, String>(()))
            .unwrap();
        assert!(
            block
                .transaction_for_original_genesis_testing(
                    foreign.genesis.block(),
                    foreign_index,
                    &ALICE_ID,
                    &foreign_instruction
                )
                .is_err(),
            "foreign signed source/hash must refuse"
        );
        drop(block);
    }

    #[inline(never)]
    fn assert_native_genesis_foreign_state_network(
        prepared: &crate::sumeragi::test_chain::PreparedTestChainConfig,
        instruction: &InstructionBox,
        index: usize,
    ) {
        let source = prepared.genesis.block();
        let foreign_network_state = state_for_testing(World::new());
        let mut foreign_network_block = foreign_network_state
            .block_with_pristine_carrier_stage(source, |_| Ok::<_, String>(()))
            .unwrap();
        let network_error = foreign_network_block
            .transaction_for_original_genesis_testing(source, index, &ALICE_ID, instruction)
            .err()
            .expect("a source cannot grant bootstrap scope to another State network");
        assert!(network_error.contains("another State network"));
        drop(foreign_network_block);
    }

    #[inline(never)]
    fn assert_native_genesis_successor_header(
        prepared: &crate::sumeragi::test_chain::PreparedTestChainConfig,
        instruction: &InstructionBox,
        index: usize,
    ) {
        let source = prepared.genesis.block();
        let mut wrong_header = prepared.state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(source.hash()),
            None,
            0,
            0,
        ));
        let header_error = wrong_header
            .transaction_for_original_genesis_testing(source, index, &ALICE_ID, instruction)
            .err()
            .expect("a source cannot grant bootstrap scope to a successor header");
        assert!(header_error.contains("another block header"));
        drop(wrong_header);
    }

    #[inline(never)]
    fn assert_native_genesis_committed_bootstrap_refusal(
        prepared: &crate::sumeragi::test_chain::PreparedTestChainConfig,
        instruction: &InstructionBox,
        index: usize,
    ) {
        let source = prepared.genesis.block();
        crate::sumeragi::startup::apply_genesis(
            &prepared.state,
            source.clone(),
            &ALICE_ID,
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            None,
        )
        .unwrap();
        let mut replay = prepared
            .state
            .block_with_pristine_carrier_stage(source, |_| Ok::<_, String>(()))
            .unwrap();
        assert!(
            replay
                .transaction_for_original_genesis_testing(source, index, &ALICE_ID, instruction)
                .is_err(),
            "committed history must not regain original bootstrap scope"
        );
    }

    #[test]
    fn initial_executor_rejects_raw_domain_registration_after_genesis() {
        use iroha_executor_data_model::permission::domain::CanRegisterDomain;
        let existing_domain =
            DomainId::try_new("wonderland", "universal").expect("existing domain id");
        let world = World::with(
            [Domain::new(existing_domain).build(&ALICE_ID)],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [],
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        Grant::account_permission(CanRegisterDomain, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut state_transaction)
            .expect("seed legacy permission directly");
        let domain_id = DomainId::try_new("planned", "universal").expect("planned domain id");
        let error = super::Executor::Initial
            .execute_instruction(
                &mut state_transaction,
                &ALICE_ID,
                Register::domain(Domain::new(domain_id)).into(),
            )
            .expect_err("raw domain registration must be denied after genesis");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message) if message.contains("reserved for genesis"))
        );
    }
    #[test]
    fn initial_executor_allows_native_escrow_open_without_transfer_permission() {
        let seller = ALICE_ID.clone();
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "xor".parse().expect("asset name"),
        );
        let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
            .build(&seller);
        let seller_account = Account::new(seller.clone()).build(&seller);
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&seller);
        let seller_asset_id = AssetId::of(asset_definition_id.clone(), seller.clone());
        let seller_asset = Asset::new(seller_asset_id.clone(), Quantity::from(100_u64));
        let world = World::with_assets(
            [domain],
            [seller_account, Account::new(BOB_ID.clone()).build(&seller)],
            [asset_definition],
            [seller_asset],
            [],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xE5; Hash::LENGTH]));
        let escrow_id = EscrowId::new(Hash::new("executor-native-escrow-open"));
        let instruction = iroha_data_model::isi::escrow::OpenAssetEscrow::new(
            escrow_id,
            asset_definition_id.clone(),
            Quantity::from(40_u64),
        );
        let res = super::Executor::Initial.execute_instruction(
            &mut stx,
            &seller,
            InstructionBox::from(instruction),
        );
        assert!(
            res.is_ok(),
            "native escrow opening should not require generic CanTransferAsset permission: {res:?}"
        );
        let record = stx
            .world
            .asset_escrows
            .get(&escrow_id)
            .expect("escrow record");
        let custody_asset_id = AssetId::of(asset_definition_id, record.custody.clone());
        let seller_balance = stx
            .world
            .assets
            .get(&seller_asset_id)
            .map(|value| value.as_ref().clone())
            .expect("seller balance");
        let custody_balance = stx
            .world
            .assets
            .get(&custody_asset_id)
            .map(|value| value.as_ref().clone())
            .expect("custody balance");
        assert_eq!(seller_balance, Quantity::from(60_u64));
        assert_eq!(custody_balance, Quantity::from(40_u64));
        let cancel = iroha_data_model::isi::escrow::CancelAssetEscrow::new(escrow_id);
        let error = super::Executor::Initial
            .execute_instruction(&mut stx, &BOB_ID, cancel.clone().into())
            .expect_err("a different authority cannot refund the seller's escrow");
        assert!(
            format!("{error:?}").contains("only seller may cancel escrow"),
            "the escrow must reach its native ownership guard: {error:?}"
        );
        assert_eq!(
            stx.world
                .assets
                .get(&custody_asset_id)
                .map(|value| value.as_ref().clone()),
            Some(Quantity::from(40_u64)),
            "a denied refund leaves custody untouched"
        );
        super::Executor::Initial
            .execute_instruction(&mut stx, &seller, cancel.into())
            .expect("the seller can terminalize native escrow custody");
        assert_eq!(
            stx.world
                .assets
                .get(&seller_asset_id)
                .map(|value| value.as_ref().clone()),
            Some(Quantity::from(100_u64))
        );
    }
    #[test]
    fn initial_executor_rejects_domainless_asset_definition_registration_after_genesis() {
        let alice_id = ALICE_ID.clone();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain: Domain = Domain::new(domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let world = World::with([domain], [alice_account], []);
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let executor = super::Executor::Initial;
        let asset_definition_id = AssetDefinitionId::from_uuid_bytes([
            0x2e, 0x3d, 0x34, 0xbe, 0xb8, 0xa8, 0x42, 0x39, 0xb3, 0xd9, 0x59, 0x07, 0x70, 0xf1,
            0x18, 0x9e,
        ])
        .expect("opaque asset definition id");
        let instruction =
            InstructionBox::from(Register::asset_definition(AssetDefinition::numeric(
                asset_definition_id.clone(),
                "cbdc".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )));
        let mut stx = block.transaction();
        let result = executor.execute_instruction(&mut stx, &alice_id, instruction);
        assert!(
            matches!(
                result,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains("domainless asset definitions may only be registered in genesis")
            ),
            "post-genesis opaque asset registration must fail closed: {result:?}"
        );
        assert!(
            stx.world.asset_definition(&asset_definition_id).is_err(),
            "a rejected opaque asset definition must not enter world state"
        );
    }
    #[test]
    fn initial_executor_authorizes_wire_decoded_asset_definition_from_explicit_owner() {
        let domain_id =
            DomainId::try_new("wire_registration", "universal").expect("domain identifier");
        let projected_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "coin".parse().expect("asset name"),
        );
        let world = World::with(
            [Domain::new(domain_id.clone()).build(&ALICE_ID)],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [],
        );
        let state = state_after_genesis(world);
        let registration = Register::asset_definition(AssetDefinition::numeric(
            projected_id,
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ));
        let encoded = registration.encode();
        let mut input = encoded.as_slice();
        let decoded = Register::<AssetDefinition>::decode(&mut input)
            .expect("decode asset-definition registration");
        assert!(input.is_empty());
        let opaque_id = decoded.object().id().clone();
        assert_eq!(decoded.object().owning_domain.as_ref(), Some(&domain_id));
        assert!(decoded.object().alias.is_none());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        super::Executor::Initial
            .execute_instruction(&mut transaction, &ALICE_ID, InstructionBox::from(decoded))
            .expect("explicit owning domain must authorize after wire decoding");
        assert!(transaction.world.asset_definition(&opaque_id).is_ok());
        assert_eq!(
            transaction.world.asset_definition_domains.get(&opaque_id),
            Some(&domain_id),
            "registration must derive the domain index from explicit ownership"
        );
    }
    #[test]
    fn asset_definition_registration_alias_cannot_supply_owning_domain_authority() {
        let owned_domain = DomainId::try_new("owned", "universal").expect("owned domain");
        let foreign_domain = DomainId::try_new("foreign", "universal").expect("foreign domain");
        let foreign_owner = checked_account_id();
        let state = state_after_genesis(World::with(
            [
                Domain::new(owned_domain.clone()).build(&ALICE_ID),
                Domain::new(foreign_domain.clone()).build(&foreign_owner),
            ],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(foreign_owner.clone()).build(&foreign_owner),
            ],
            [],
        ));
        let asset_id = AssetDefinitionId::derive_from_components(
            owned_domain,
            "coin".parse().expect("asset name"),
        );
        let owned_alias: iroha_data_model::asset::AssetDefinitionAlias =
            "coin#owned.universal".parse().expect("asset alias");
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        for (owning_domain, alias, expected) in [
            (
                None,
                Some(owned_alias.clone()),
                "domainless asset definitions may only be registered in genesis",
            ),
            (
                Some(foreign_domain.clone()),
                Some(owned_alias),
                "Can't register asset definition",
            ),
            (
                Some(foreign_domain),
                None,
                "Can't register asset definition",
            ),
        ] {
            let registration = Register::asset_definition(
                AssetDefinition::numeric(
                    asset_id.clone(),
                    "coin",
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    owning_domain,
                )
                .with_alias(alias),
            );
            let mut transaction = block.transaction();
            let error = super::ensure_asset_definition_registration_allowed(
                &mut transaction,
                &ALICE_ID,
                &registration,
            )
            .expect_err("only the owner of the explicit owning domain may register an asset");
            assert!(matches!(error, ValidationFail::NotPermitted(message) if message == expected));
            assert!(transaction.world.asset_definition(&asset_id).is_err());
            assert!(
                transaction
                    .world
                    .asset_definition_domains
                    .get(&asset_id)
                    .is_none()
            );
        }
    }
    #[test]
    fn initial_executor_enforces_exact_pkr_mint_and_metadata_permissions() {
        let owner = ALICE_ID.clone();
        let retail = checked_account_id();
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
        let pkr = AssetDefinitionId::from_uuid_bytes([
            0x5d, 0x9f, 0x4d, 0x8d, 0x11, 0x5a, 0x49, 0xc0, 0x95, 0x3a, 0x6a, 0x9b, 0xe8, 0x22,
            0x77, 0x01,
        ])
        .expect("opaque PKR definition id");
        let world = World::with(
            [Domain::new(domain_id).build(&owner)],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(retail.clone()).build(&retail),
            ],
            [AssetDefinition::numeric(
                pkr.clone(),
                "PKR".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&owner)],
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut stx = block.transaction();
        let executor = super::Executor::Initial;
        let retail_pkr = AssetId::new(pkr.clone(), retail.clone());
        stx.world.account_permissions.insert(
            retail.clone(),
            BTreeSet::from([Permission::new(
                "CanMintAsset".to_owned(),
                norito::json!({"asset": (retail_pkr.to_string())}),
            )]),
        );
        let legacy_permission_mint = executor.execute_instruction(
            &mut stx,
            &retail,
            InstructionBox::from(Mint::asset_quantity(1_u32, retail_pkr.clone())),
        );
        assert!(
            matches!(
                legacy_permission_mint,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains("exact mint permission")
            ),
            "the retired CanMintAsset token must be inert"
        );
        stx.world.account_permissions.insert(
            retail.clone(),
            BTreeSet::from([Permission::from(
                executor_permission::asset::CanMintAssetToAccount {
                    asset_definition: pkr.clone(),
                    account: owner.clone(),
                },
            )]),
        );
        let wrong_destination_mint = executor.execute_instruction(
            &mut stx,
            &retail,
            InstructionBox::from(Mint::asset_quantity(1_u32, retail_pkr.clone())),
        );
        assert!(
            matches!(
                wrong_destination_mint,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains("exact mint permission")
            ),
            "a destination-scoped permission must not authorize another account"
        );
        let metadata_key: Name = "display.category".parse().expect("metadata key");
        let unprivileged_metadata = executor.execute_instruction(
            &mut stx,
            &retail,
            InstructionBox::from(iroha_data_model::isi::SetKeyValue::asset_definition(
                pkr.clone(),
                metadata_key.clone(),
                Json::new("retail"),
            )),
        );
        assert!(
            matches!(
                unprivileged_metadata,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains("metadata")
            ),
            "unexpected unprivileged PKR metadata result: {unprivileged_metadata:?}"
        );
        stx.world.account_permissions.insert(
            retail.clone(),
            BTreeSet::from([
                Permission::from(executor_permission::asset::CanMintAssetToAccount {
                    asset_definition: pkr.clone(),
                    account: retail.clone(),
                }),
                Permission::from(
                    executor_permission::asset_definition::CanModifyAssetDefinitionMetadata {
                        asset_definition: pkr.clone(),
                    },
                ),
            ]),
        );
        executor
            .execute_instruction(
                &mut stx,
                &retail,
                InstructionBox::from(Mint::asset_quantity(1_u32, retail_pkr.clone())),
            )
            .expect("the exact PKR destination mint grant must authorize minting");
        executor
            .execute_instruction(
                &mut stx,
                &retail,
                InstructionBox::from(iroha_data_model::isi::SetKeyValue::asset_definition(
                    pkr.clone(),
                    metadata_key,
                    Json::new("retail"),
                )),
            )
            .expect("the exact PKR metadata grant must authorize metadata changes");
        assert_eq!(
            stx.world
                .assets
                .get(&retail_pkr)
                .expect("minted retail PKR balance")
                .as_ref(),
            &Quantity::from(1_u32),
        );
        assert_eq!(
            stx.world
                .asset_definition(&pkr)
                .expect("PKR definition")
                .metadata()
                .get(&"display.category".parse::<Name>().expect("metadata key")),
            Some(&Json::new("retail")),
        );
    }
    #[test]
    fn extract_transfer_asset_definition_ignores_register_asset_definition_instruction() {
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("defs", "universal").expect("defs domain id"),
            "bond".parse().expect("asset definition name"),
        );
        let instruction =
            InstructionBox::from(Register::asset_definition(AssetDefinition::numeric(
                asset_definition_id,
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )));
        assert!(
            extract_transfer_asset_definition(&instruction).is_none(),
            "register asset-definition instruction must not decode as transfer"
        );
    }
    #[test]
    fn direct_dataspace_registration_extracts_only_its_distinct_instruction() {
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("defs", "universal").expect("domain id"),
            "bond".parse().expect("name"),
        );
        let object = AssetDefinition::numeric(
            id,
            "Bond".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
            None,
        );
        let direct = iroha_data_model::isi::RegisterDataspaceAssetDefinition::new(
            DataSpaceId::new(7),
            object.clone(),
        )
        .expect("direct registration");
        let instruction = InstructionBox::from(direct.clone());
        assert_eq!(
            extract_register_dataspace_asset_definition(&instruction),
            Some(direct)
        );
        assert!(extract_register_asset_definition(&instruction).is_none());
        let original = InstructionBox::from(Register::asset_definition(object));
        assert!(extract_register_dataspace_asset_definition(&original).is_none());
    }
    #[test]
    fn extract_register_asset_definition_accepts_register_asset_definition_instruction() {
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("defs", "universal").expect("defs domain id"),
            "bond".parse().expect("asset definition name"),
        );
        let instruction =
            InstructionBox::from(Register::asset_definition(AssetDefinition::numeric(
                asset_definition_id.clone(),
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )));
        let reg = extract_register_asset_definition(&instruction)
            .expect("expected to extract register asset-definition instruction");
        assert_eq!(reg.object().id(), &asset_definition_id);
    }
    #[test]
    fn initial_executor_denies_transfer_domain_without_ownership() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let foo_domain_id: DomainId = DomainId::try_new("foo", "universal").expect("foo domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let users_domain = Domain::new(users_domain_id.clone()).build(&user1);
        let foo_domain = Domain::new(foo_domain_id.clone()).build(&user1);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let world = World::with(
            [users_domain, foo_domain],
            [alice_account, user1_account, user2_account],
            [],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let executor = super::Executor::Initial;
        let instruction = InstructionBox::from(Transfer::domain(
            user1.clone(),
            foo_domain_id,
            user2.clone(),
        ));
        let transfer = extract_transfer_domain(&instruction)
            .expect("expected to extract domain transfer from instruction");
        let mut stx = block.transaction();
        assert_eq!(
            stx.world
                .domain(&users_domain_id)
                .expect("users domain should exist")
                .owned_by(),
            &user1
        );
        assert_eq!(
            stx.world
                .domain(transfer.object())
                .expect("foo domain should exist")
                .owned_by(),
            &user1
        );
        let allowed = can_transfer_domain(&stx.world, &alice_id, &transfer, 0)
            .expect("domain transfer permission check");
        assert!(
            !allowed,
            "alice should not be allowed to transfer foo domain"
        );
        assert!(
            !(stx._curr_block.is_genesis() && stx.block_hashes.is_empty()),
            "test must execute in non-genesis context"
        );
        let res = executor.execute_instruction(&mut stx, &alice_id, instruction);
        assert!(
            matches!(res, Err(ValidationFail::NotPermitted(_))),
            "initial executor should deny domain transfer from another account, got: {res:?}"
        );
    }
    #[test]
    fn initial_executor_denies_transfer_asset_by_asset_definition_domain_owner() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let users_domain = Domain::new(users_domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            users_domain_id.clone(),
            "coin".parse().unwrap(),
        );
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&user1);
        let transfer_asset_id = AssetId::new(asset_definition_id, user1.clone());
        let source_balance = Asset::new(transfer_asset_id.clone(), Quantity::from(10_u64));
        let world = World::with_assets(
            [users_domain],
            [alice_account, user1_account, user2_account],
            [asset_definition],
            [source_balance],
            [],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let instruction = InstructionBox::from(Transfer::asset_quantity(
            transfer_asset_id,
            1_u32,
            user2.clone(),
        ));
        let transfer = extract_transfer_asset(&instruction)
            .expect("expected to extract asset transfer from instruction");
        let mut stx = block.transaction();
        let allowed = can_transfer_asset(&stx.world, &alice_id, None, &transfer)
            .expect("asset transfer permission check");
        assert!(
            !allowed,
            "asset-definition domain ownership must not authorize transfers from another account"
        );
        let result = super::Executor::Initial.execute_instruction(&mut stx, &alice_id, instruction);
        assert!(
            matches!(
                result,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains("source asset owner must sign")
            ),
            "asset-definition domain owner bypass must fail before applying the transfer: {result:?}"
        );
    }
    #[test]
    fn initial_executor_denies_transfer_asset_by_active_alias_domain_owner_for_all_shapes() {
        use iroha_data_model::{
            account::{
                AccountAddress,
                rekey::{AccountAlias, AccountAliasDomain},
            },
            nexus::DataSpaceCatalog,
            sns::{NameControllerV1, NameRecordV1},
        };
        let alias_domain_owner = ALICE_ID.clone();
        let source = checked_account_id();
        let destination = checked_account_id();
        let alias_domain_id = DomainId::try_new("fi", "universal").expect("alias domain id");
        let asset_domain_id = DomainId::try_new("assets", "universal").expect("asset domain id");
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            asset_domain_id.clone(),
            "coin".parse().unwrap(),
        );
        let source_asset_id = AssetId::new(asset_definition_id.clone(), source.clone());
        let mut world = World::with_assets(
            [
                Domain::new(alias_domain_id).build(&alias_domain_owner),
                Domain::new(asset_domain_id).build(&source),
            ],
            [
                Account::new(alias_domain_owner.clone()).build(&alias_domain_owner),
                Account::new(source.clone()).build(&source),
                Account::new(destination.clone()).build(&destination),
            ],
            [AssetDefinition::numeric(
                asset_definition_id,
                "coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&source)],
            [Asset::new(source_asset_id.clone(), Quantity::from(10_u64))],
            [],
        );
        let alias = AccountAlias::new(
            "customer".parse().expect("alias label"),
            Some(AccountAliasDomain::new("fi".parse().expect("alias domain"))),
            DataSpaceId::UNIVERSAL,
        );
        let selector = crate::sns::selector_for_account_alias(&alias, &DataSpaceCatalog::default())
            .expect("account alias selector");
        let address = AccountAddress::from_account_id(&source).expect("source address");
        let lease = NameRecordV1::new(
            selector.clone(),
            source.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            100,
            200,
            300,
            Metadata::default(),
        );
        world
            .smart_contract_state_mut_for_testing()
            .insert(crate::sns::record_storage_key(&selector), lease.encode());
        world.account_aliases.insert(alias.clone(), source.clone());
        world
            .account_aliases_by_account
            .insert(source.clone(), BTreeSet::from([alias.clone()]));
        world.replace_account_rekey_record_for_testing(
            iroha_data_model::account::rekey::AccountRekeyRecord::new(alias, source.clone()),
        );
        assert!(
            authority_owns_any_alias_domain(&world.view(), &alias_domain_owner, &source, 50)
                .expect("active alias-domain ownership check"),
            "fixture must prove that the attacker owns an active alias domain for the source"
        );
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            50,
            0,
        ));
        let mut transaction = block.transaction();
        let transfer = Transfer::asset_quantity(source_asset_id, 1_u32, destination.clone());
        let boxed = InstructionBox::from(transfer.clone());
        let concrete = concrete_instruction_box!(Transfer<Asset, Quantity, Account>, transfer);
        let boxed_result = super::Executor::Initial.execute_instruction(
            &mut transaction,
            &alias_domain_owner,
            boxed,
        );
        assert!(
            matches!(
                boxed_result,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains("source asset owner must sign")
            ),
            "active alias-domain ownership must not authorize TransferBox::Asset: {boxed_result:?}"
        );
        let concrete_result = super::Executor::Initial.execute_borrowed_overlay_instruction(
            &mut transaction,
            &alias_domain_owner,
            &concrete,
            None,
        );
        assert!(
            matches!(concrete_result, Err(ValidationFail::NotPermitted(_))),
            "active alias-domain ownership must not authorize a borrowed concrete transfer: {concrete_result:?}"
        );
    }
    #[test]
    fn initial_executor_trigger_registration_requires_exact_canonical_authority() {
        use crate::smartcontracts::triggers::set::SetReadOnly as _;
        use iroha_data_model::{
            account::{
                AccountAddress,
                rekey::{AccountAlias, AccountAliasDomain},
            },
            events::execute_trigger::ExecuteTriggerEventFilter,
            nexus::DataSpaceCatalog,
            sns::{NameControllerV1, NameRecordV1},
        };

        let alias_domain_owner = ALICE_ID.clone();
        let trigger_owner = checked_account_id();
        let alias_domain_id =
            DomainId::try_new("triggerbank", "universal").expect("alias domain id");
        let mut world = World::with(
            [Domain::new(alias_domain_id).build(&alias_domain_owner)],
            [
                Account::new(alias_domain_owner.clone()).build(&alias_domain_owner),
                Account::new(trigger_owner.clone()).build(&trigger_owner),
            ],
            [],
        );
        let alias = AccountAlias::new(
            "customer".parse().expect("alias label"),
            Some(AccountAliasDomain::new(
                "triggerbank".parse().expect("alias domain"),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let selector = crate::sns::selector_for_account_alias(&alias, &DataSpaceCatalog::default())
            .expect("account alias selector");
        let address = AccountAddress::from_account_id(&trigger_owner).expect("owner address");
        let lease = NameRecordV1::new(
            selector.clone(),
            trigger_owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            100,
            200,
            300,
            Metadata::default(),
        );
        world
            .smart_contract_state_mut_for_testing()
            .insert(crate::sns::record_storage_key(&selector), lease.encode());
        world
            .account_aliases
            .insert(alias.clone(), trigger_owner.clone());
        world
            .account_aliases_by_account
            .insert(trigger_owner.clone(), BTreeSet::from([alias.clone()]));
        world.replace_account_rekey_record_for_testing(
            iroha_data_model::account::rekey::AccountRekeyRecord::new(alias, trigger_owner.clone()),
        );
        assert!(
            authority_owns_any_alias_domain(
                &world.view(),
                &alias_domain_owner,
                &trigger_owner,
                50,
            )
            .expect("active alias-domain ownership check"),
            "fixture must expose the retired authorization shortcut",
        );

        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            50,
            0,
        ));
        let mut transaction = block.transaction();
        let trigger_id: TriggerId = "initial_exact_trigger_owner".parse().expect("trigger id");
        let registration = || {
            Register::trigger(Trigger::new(
                trigger_id.clone(),
                Action::new(
                    Vec::<InstructionBox>::new(),
                    Repeats::Indefinitely,
                    trigger_owner.clone(),
                    ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
                )
                .expect("valid trigger action"),
            ))
            .into()
        };

        let attacker_result = super::Executor::Initial.execute_instruction(
            &mut transaction,
            &alias_domain_owner,
            registration(),
        );
        assert!(
            matches!(
                &attacker_result,
                Err(ValidationFail::InstructionFailed(
                    InstructionExecutionError::InvalidParameter(
                        iroha_data_model::isi::error::InvalidParameterError::SmartContract(message)
                    )
                )) if message.contains("Missing CanRegisterTrigger")
            ),
            "alias-domain owner must not install code for the canonical account: {attacker_result:?}",
        );
        super::Executor::Initial
            .execute_instruction(&mut transaction, &trigger_owner, registration())
            .expect("the exact trigger owner must not need an alias or self-grant");
        assert!(
            transaction
                .world
                .triggers
                .inspect_by_id(&trigger_id, |_| ())
                .is_some(),
            "exact-owner registration must reach trigger storage",
        );
    }
    include!("executor_initial_batch_authorization_tests.rs");
    #[test]
    fn initial_executor_transfer_asset_batch_requires_active_canonical_contract_context_for_both_modes()
     {
        #[derive(Clone, Copy, core::fmt::Debug)]
        enum Provenance {
            Active,
            MissingReverse,
            InactiveAddress,
        }
        for independent in [false, true] {
            for provenance in [
                Provenance::Active,
                Provenance::MissingReverse,
                Provenance::InactiveAddress,
            ] {
                let deployer = checked_account_id();
                let destination = checked_account_id();
                let state = state_after_genesis(World::with(
                    [],
                    [
                        Account::new(deployer.clone()).build(&deployer),
                        Account::new(destination.clone()).build(&destination),
                    ],
                    [],
                ));
                let network_id = state.network_id;
                let contract_address =
                    ContractAddress::derive(&network_id, &deployer, 810, DataSpaceId::UNIVERSAL)
                        .expect("contract address");
                let contract_subject = contract_address.subject_id();
                let asset_definition = AssetDefinitionId::from_uuid_bytes([
                    0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0x48, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8,
                    0xb8, 0xb8, 0xb8,
                ])
                .expect("opaque asset definition");
                let source_asset = AssetId::new(asset_definition.clone(), contract_subject.clone());
                let mut world = World::with_assets(
                    [],
                    [
                        Account::new(deployer.clone()).build(&deployer),
                        Account::new(contract_subject.clone()).build(&contract_subject),
                        Account::new(destination.clone()).build(&destination),
                    ],
                    [AssetDefinition::numeric(
                        asset_definition.clone(),
                        "contract batch coin".to_owned(),
                        iroha_data_model::asset::AssetBalancePolicy::Global,
                        None,
                    )
                    .build(&deployer)],
                    [Asset::new(source_asset.clone(), Quantity::from(10_u32))],
                    [],
                );
                seed_test_asset_supply(&mut world, &asset_definition);
                let contract_code_hash = Hash::new(b"contract-batch-code");
                world
                    .contract_instances
                    .insert(contract_address.clone(), contract_code_hash);
                world.contract_subject_bindings.insert(
                    contract_address.clone(),
                    crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                        &contract_address,
                        deployer.clone(),
                    )
                    .with_active_code_hash(contract_code_hash),
                );
                world
                    .contract_subject_addresses
                    .insert(contract_subject.clone(), contract_address.clone());
                let context_address = if matches!(provenance, Provenance::InactiveAddress) {
                    ContractAddress::derive(&network_id, &deployer, 811, DataSpaceId::UNIVERSAL)
                        .expect("inactive contract address")
                } else {
                    contract_address.clone()
                };
                let context = ContractRuntimeExecutionContext {
                    contract_address: context_address,
                    contract_subject: contract_subject.clone(),
                    contract_alias: None,
                    entrypoint: "execute_batch".to_owned(),
                };
                let mut seeded = state.world.block();
                seeded.asset_definitions.insert(
                    asset_definition.clone(),
                    world
                        .asset_definitions
                        .view()
                        .get(&asset_definition)
                        .unwrap()
                        .clone(),
                );
                seeded.assets.insert(
                    source_asset.clone(),
                    world.assets.view().get(&source_asset).unwrap().clone(),
                );
                seeded.commit();
                bind_executor_test_contract_after_genesis(
                    &state,
                    &contract_address,
                    &deployer,
                    contract_code_hash,
                );
                let mut block = state.block(BlockHeader::new(
                    nonzero!(2_u64),
                    Some(
                        state
                            .view()
                            .latest_block_hash()
                            .expect("genuine genesis parent"),
                    ),
                    None,
                    0,
                    0,
                ));
                let mut transaction = block.transaction_for_fastpq_testing(Hash::new(
                    format!("contract-batch-{independent}-{provenance:?}").as_bytes(),
                ));
                if matches!(provenance, Provenance::MissingReverse) {
                    transaction
                        .world
                        .contract_subject_addresses
                        .remove(contract_subject.clone());
                }
                let entries = vec![TransferAssetBatchEntry::with_leg_id(
                    "contract-owned",
                    contract_subject.clone(),
                    destination.clone(),
                    asset_definition.clone(),
                    2_u32,
                )];
                let batch = if independent {
                    TransferAssetBatch::independent(entries)
                } else {
                    TransferAssetBatch::new(entries)
                };
                let result = super::Executor::Initial
                    .execute_instruction_with_contract_runtime_context(
                        &mut transaction,
                        &contract_subject,
                        batch.into(),
                        Some(&context),
                    );
                if matches!(provenance, Provenance::Active) {
                    result.unwrap_or_else(|error| {
                        panic!(
                            "active contract batch (independent={independent}) was rejected: {error:?}"
                        )
                    });
                    assert_eq!(
                        initial_batch_balance(&transaction.world, &source_asset),
                        Quantity::from(8_u32)
                    );
                } else {
                    assert!(
                        matches!(result, Err(ValidationFail::NotPermitted(_))),
                        "invalid {provenance:?} context (independent={independent}) must reject the whole batch: {result:?}"
                    );
                    assert_eq!(
                        initial_batch_balance(&transaction.world, &source_asset),
                        Quantity::from(10_u32),
                        "provenance rejection must precede either settlement mode"
                    );
                }
            }
        }
    }
    #[test]
    fn initial_executor_requires_an_active_consistent_contract_context_for_contract_assets() {
        let deployer = checked_account_id();
        let destination = checked_account_id();
        let state = state_after_genesis(World::with(
            [],
            [
                Account::new(deployer.clone()).build(&deployer),
                Account::new(destination.clone()).build(&destination),
            ],
            [],
        ));
        let contract_address =
            ContractAddress::derive(&state.network_id, &deployer, 808, DataSpaceId::UNIVERSAL)
                .expect("contract address");
        let contract_subject = contract_address.subject_id();
        let asset_definition_id = AssetDefinitionId::from_uuid_bytes([
            0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0x48, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8,
            0xa8, 0xa8,
        ])
        .expect("opaque asset definition");
        let source_asset_id = AssetId::new(asset_definition_id.clone(), contract_subject.clone());
        let mut world = World::with_assets(
            [],
            [
                Account::new(deployer.clone()).build(&deployer),
                Account::new(contract_subject.clone()).build(&contract_subject),
                Account::new(destination.clone()).build(&destination),
            ],
            [AssetDefinition::numeric(
                asset_definition_id,
                "contract coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&deployer)],
            [Asset::new(source_asset_id.clone(), Quantity::from(10_u64))],
            [],
        );
        let code_hash = Hash::new(b"contract-transfer-context");
        world
            .contract_instances
            .insert(contract_address.clone(), code_hash);
        world.contract_subject_bindings.insert(
            contract_address.clone(),
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &contract_address,
                deployer.clone(),
            )
            .with_active_code_hash(code_hash),
        );
        world
            .contract_subject_addresses
            .insert(contract_subject.clone(), contract_address.clone());
        let mut seeded = state.world.block();
        seeded.asset_definitions.insert(
            source_asset_id.definition().clone(),
            world
                .asset_definitions
                .view()
                .get(source_asset_id.definition())
                .unwrap()
                .clone(),
        );
        seeded.assets.insert(
            source_asset_id.clone(),
            world.assets.view().get(&source_asset_id).unwrap().clone(),
        );
        seeded.commit();
        bind_executor_test_contract_after_genesis(&state, &contract_address, &deployer, code_hash);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::new(b"contract-transfer-test"));
        let context = ContractRuntimeExecutionContext {
            contract_address: contract_address.clone(),
            contract_subject: contract_subject.clone(),
            contract_alias: None,
            entrypoint: "execute".to_owned(),
        };
        let transfer =
            Transfer::asset_quantity(source_asset_id.clone(), 1_u32, destination.clone());
        let boxed = InstructionBox::from(transfer.clone());
        let concrete = concrete_instruction_box!(Transfer<Asset, Quantity, Account>, transfer);
        super::Executor::Initial
            .execute_borrowed_overlay_instruction(
                &mut transaction,
                &contract_subject,
                &boxed,
                Some(&context),
            )
            .expect("active contract subject must be able to transfer its own asset");
        let concrete_result = super::Executor::Initial.execute_borrowed_overlay_instruction(
            &mut transaction,
            &contract_subject,
            &concrete,
            Some(&context),
        );
        assert!(
            matches!(concrete_result, Err(ValidationFail::NotPermitted(_))),
            "borrowed concrete transfers must remain outside the admitted native surface: \
             {concrete_result:?}"
        );
        transaction
            .world
            .contract_subject_addresses
            .remove(contract_subject.clone());
        let missing_reverse_binding = super::Executor::Initial
            .execute_instruction_with_contract_runtime_context(
                &mut transaction,
                &contract_subject,
                Transfer::asset_quantity(source_asset_id.clone(), 1_u32, destination.clone())
                    .into(),
                Some(&context),
            );
        assert!(
            matches!(
                missing_reverse_binding,
                Err(ValidationFail::NotPermitted(_))
            ),
            "a contract context without the canonical reverse subject binding must fail closed: \
             {missing_reverse_binding:?}"
        );
        transaction
            .world
            .contract_subject_addresses
            .insert(contract_subject.clone(), contract_address.clone());
        let inactive_address =
            ContractAddress::derive(&state.network_id, &deployer, 809, DataSpaceId::UNIVERSAL)
                .expect("inactive contract address");
        let inconsistent_context = ContractRuntimeExecutionContext {
            contract_address: inactive_address,
            contract_subject: contract_subject.clone(),
            contract_alias: None,
            entrypoint: "execute".to_owned(),
        };
        let rejected = super::Executor::Initial.execute_instruction_with_contract_runtime_context(
            &mut transaction,
            &contract_subject,
            Transfer::asset_quantity(source_asset_id, 1_u32, destination).into(),
            Some(&inconsistent_context),
        );
        assert!(
            matches!(rejected, Err(ValidationFail::NotPermitted(_))),
            "an inactive or inconsistent contract context must fail closed: {rejected:?}"
        );
    }
    #[test]
    fn contract_runtime_context_alias_does_not_bypass_asset_transfer_authorization() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let defs_domain_id: DomainId =
            DomainId::try_new("defs", "universal").expect("defs domain id");
        let alice_domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let users_domain = Domain::new(users_domain_id.clone()).build(&user1);
        let defs_domain = Domain::new(defs_domain_id.clone()).build(&user1);
        let alice_domain = Domain::new(alice_domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            defs_domain_id.clone(),
            "coin".parse().unwrap(),
        );
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&user1);
        let transfer_asset_id = AssetId::new(asset_definition_id.clone(), user1.clone());
        let source_balance = Asset::new(transfer_asset_id.clone(), Quantity::from(10_u64));
        let world = World::with_assets(
            [alice_domain, users_domain, defs_domain],
            [alice_account, user1_account, user2_account],
            [asset_definition],
            [source_balance],
            [],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let executor = super::Executor::Initial;
        let instruction = InstructionBox::from(Transfer::asset_quantity(
            transfer_asset_id,
            1_u32,
            user2.clone(),
        ));
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &alice_id,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("benefit contract address");
        let context = ContractRuntimeExecutionContext {
            contract_subject: contract_address.subject_id(),
            contract_address,
            contract_alias: Some("benefit::benefit".parse().expect("benefit alias")),
            entrypoint: "spend_to_merchant".to_owned(),
        };
        let mut stx = block.transaction();
        stx.tx_call_hash = Some(Hash::prehashed([0xE6; Hash::LENGTH]));
        let result = executor.execute_instruction_with_contract_runtime_context(
            &mut stx,
            &alice_id,
            instruction,
            Some(&context),
        );
        assert!(
            matches!(
                result,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains("source asset owner must sign the transaction")
            ),
            "contract alias must not bypass source-owner authorization: {result:?}"
        );
    }
    #[test]
    fn contract_runtime_context_does_not_bypass_non_benefit_spend_entrypoints() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let defs_domain_id: DomainId =
            DomainId::try_new("defs", "universal").expect("defs domain id");
        let alice_domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let users_domain = Domain::new(users_domain_id.clone()).build(&user1);
        let defs_domain = Domain::new(defs_domain_id.clone()).build(&user1);
        let alice_domain = Domain::new(alice_domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            defs_domain_id.clone(),
            "coin".parse().unwrap(),
        );
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&user1);
        let transfer_asset_id = AssetId::new(asset_definition_id.clone(), user1.clone());
        let source_balance = Asset::new(transfer_asset_id.clone(), Quantity::from(10_u64));
        let world = World::with_assets(
            [alice_domain, users_domain, defs_domain],
            [alice_account, user1_account, user2_account],
            [asset_definition],
            [source_balance],
            [],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let executor = super::Executor::Initial;
        let instruction = InstructionBox::from(Transfer::asset_quantity(
            transfer_asset_id,
            1_u32,
            user2.clone(),
        ));
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &alice_id,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("benefit contract address");
        let context = ContractRuntimeExecutionContext {
            contract_subject: contract_address.subject_id(),
            contract_address,
            contract_alias: Some("benefit::benefit".parse().expect("benefit alias")),
            entrypoint: "create_tranche".to_owned(),
        };
        let mut stx = block.transaction();
        let res = executor.execute_instruction_with_contract_runtime_context(
            &mut stx,
            &alice_id,
            instruction,
            Some(&context),
        );
        match res {
            Err(ValidationFail::NotPermitted(msg)) => assert!(
                msg.contains("source asset owner must sign the transaction"),
                "unexpected rejection message: {msg}"
            ),
            other => panic!(
                "non-spend contract runtime context must not bypass asset transfer checks, got: {other:?}"
            ),
        }
    }
    #[test]
    fn contract_runtime_context_alias_does_not_bypass_permission_grant_authorization() {
        let alice_id = ALICE_ID.clone();
        let beneficiary = checked_account_id();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let beneficiary_account = Account::new(beneficiary.clone()).build(&beneficiary);
        let world = World::with([domain], [alice_account, beneficiary_account], []);
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(
            generate_denied_program("executor denies permission grants"),
        ));
        let executor = super::Executor::UserProvided(
            super::LoadedExecutor::load(raw).expect("load denying executor"),
        );
        let instruction = InstructionBox::from(Grant::account_permission(
            Permission::new("BispSpend".to_owned(), Json::new(())),
            beneficiary.clone(),
        ));
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &alice_id,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("bisp contract address");
        let context = ContractRuntimeExecutionContext {
            contract_subject: contract_address.subject_id(),
            contract_address,
            contract_alias: Some("bisp_bisp::sbp".parse().expect("bisp alias")),
            entrypoint: "create_tranche".to_owned(),
        };
        let mut stx = block.transaction();
        stx.tx_call_hash = Some(Hash::prehashed([0xE7; Hash::LENGTH]));
        let result = executor.execute_instruction_with_contract_runtime_context(
            &mut stx,
            &alice_id,
            instruction,
            Some(&context),
        );
        assert!(
            matches!(
                result,
                Err(ValidationFail::NotPermitted(ref message))
                    if message.contains(
                        "deployed contracts may grant or revoke only exact CanUseContractPermission tokens"
                    )
            ),
            "contract alias must not bypass the common permission boundary: {result:?}"
        );
    }
    #[test]
    fn initial_executor_contract_alias_never_bypasses_permission_grant_validation() {
        fn execute_case(
            alias: &str,
            entrypoint: &str,
            permission_name: &str,
        ) -> Result<(), ValidationFail> {
            let alice_id = ALICE_ID.clone();
            let beneficiary = checked_account_id();
            let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
            let world = World::with(
                [Domain::new(domain_id).build(&alice_id)],
                [
                    Account::new(alice_id.clone()).build(&alice_id),
                    Account::new(beneficiary.clone()).build(&beneficiary),
                ],
                [],
            );
            let state = state_after_genesis(world);
            let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
            let contract_address = ContractAddress::derive(
                &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                    .parse()
                    .expect("canonical test network id"),
                &alice_id,
                0,
                DataSpaceId::UNIVERSAL,
            )
            .expect("contract address");
            let context = ContractRuntimeExecutionContext {
                contract_subject: contract_address.subject_id(),
                contract_address,
                contract_alias: Some(alias.parse().expect("contract alias")),
                entrypoint: entrypoint.to_owned(),
            };
            let instruction = InstructionBox::from(Grant::account_permission(
                Permission::new(permission_name.to_owned(), Json::new(())),
                beneficiary,
            ));
            super::Executor::Initial.execute_instruction_with_contract_runtime_context(
                &mut block.transaction(),
                &alice_id,
                instruction,
                Some(&context),
            )
        }
        for entrypoint in ["create_tranche", "set_beneficiary_spend_authority"] {
            assert!(matches!(
                execute_case("bisp_bisp::sbp", entrypoint, "BispSpend"),
                Err(ValidationFail::NotPermitted(_))
            ));
        }
        for (alias, entrypoint, permission) in [
            (
                "bisp_bisp::sbp",
                "grant_beneficiary_spend_permission",
                "BispSpend",
            ),
            ("bisp_bisp::sbp", "unrelated", "BispSpend"),
            ("unrelated::sbp", "create_tranche", "BispSpend"),
            ("bisp_bisp::sbp", "create_tranche", "CanSetParameters"),
        ] {
            assert!(
                matches!(
                    execute_case(alias, entrypoint, permission),
                    Err(ValidationFail::NotPermitted(_))
                ),
                "contract {alias}/{entrypoint} must not grant {permission}"
            );
        }
    }
    #[test]
    fn initial_executor_contract_alias_never_bypasses_transfer_control_validation() {
        fn assert_rejected(result: Result<(), ValidationFail>, context: &str) {
            assert!(
                matches!(
                    &result,
                    Err(ValidationFail::NotPermitted(_)
                        | ValidationFail::InstructionFailed(
                            InstructionExecutionError::InvariantViolation(_)
                        ))
                ),
                "{context} must be rejected by authorization or the matching execution invariant: {result:?}"
            );
        }
        fn execute_case(
            alias: &str,
            entrypoint: &str,
            instruction_kind: &str,
            window: AssetTransferControlWindow,
        ) -> Result<(), ValidationFail> {
            let caller = ALICE_ID.clone();
            let owner = checked_account_id();
            let target = checked_account_id();
            let domain_id = DomainId::try_new("cbdc", "sbp").expect("domain id");
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                domain_id.clone(),
                "pkr".parse().expect("asset name"),
            );
            let world = World::with(
                [Domain::new(domain_id).build(&owner)],
                [
                    Account::new(caller.clone()).build(&caller),
                    Account::new(owner.clone()).build(&owner),
                    Account::new(target.clone()).build(&target),
                ],
                [AssetDefinition::numeric(
                    asset_definition_id.clone(),
                    "PKR".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
                .build(&owner)],
            );
            let state = state_after_genesis(world);
            let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
            let instruction = match instruction_kind {
                "availability" => InstructionBox::from(SetAssetTransferAvailability::new(
                    target,
                    asset_definition_id,
                    0,
                    AssetTransferAvailability::Enabled,
                    AssetTransferAvailability::Disabled,
                    Some("branded contract availability fixture".to_owned()),
                )),
                "limit" => InstructionBox::from(SetAssetTransferControl::new(
                    target,
                    asset_definition_id,
                    vec![iroha_data_model::asset::AssetTransferLimit {
                        window,
                        cap_amount: Some(Quantity::from(100_u32)),
                    }],
                )),
                other => panic!("unsupported test instruction kind {other}"),
            };
            let contract_address = ContractAddress::derive(
                &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                    .parse()
                    .expect("canonical test network id"),
                &caller,
                0,
                DataSpaceId::UNIVERSAL,
            )
            .expect("contract address");
            let context = ContractRuntimeExecutionContext {
                contract_subject: contract_address.subject_id(),
                contract_address,
                contract_alias: Some(alias.parse().expect("contract alias")),
                entrypoint: entrypoint.to_owned(),
            };
            super::Executor::Initial.execute_instruction_with_contract_runtime_context(
                &mut block.transaction(),
                &caller,
                instruction,
                Some(&context),
            )
        }
        assert_rejected(
            execute_case(
                "apps_freeze::sbp",
                "apply_freeze",
                "availability",
                AssetTransferControlWindow::Day,
            ),
            "unprivileged branded freeze",
        );
        assert_rejected(
            execute_case(
                "apps_limits_update::sbp",
                "apply_limits",
                "limit",
                AssetTransferControlWindow::Day,
            ),
            "unprivileged branded limit update",
        );
        for (alias, entrypoint, kind, window) in [
            (
                "apps_freeze::sbp",
                "wrong",
                "availability",
                AssetTransferControlWindow::Day,
            ),
            (
                "wrong::sbp",
                "apply_freeze",
                "availability",
                AssetTransferControlWindow::Day,
            ),
            (
                "apps_freeze::sbp",
                "apply_freeze",
                "limit",
                AssetTransferControlWindow::Day,
            ),
            (
                "apps_limits_update::sbp",
                "apply_limits",
                "availability",
                AssetTransferControlWindow::Day,
            ),
            (
                "apps_limits_update::sbp",
                "apply_limits",
                "limit",
                AssetTransferControlWindow::Week,
            ),
        ] {
            assert_rejected(
                execute_case(alias, entrypoint, kind, window),
                &format!("contract {alias}/{entrypoint} must not emit {kind}/{window}"),
            );
        }
    }
    #[test]
    fn initial_executor_denies_transfer_asset_definition_without_ownership() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let defs_domain_id: DomainId =
            DomainId::try_new("defs", "universal").expect("defs domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let alice_domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let users_domain = Domain::new(users_domain_id.clone()).build(&user1);
        let defs_domain = Domain::new(defs_domain_id.clone()).build(&user1);
        let alice_domain = Domain::new(alice_domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            defs_domain_id.clone(),
            "bond".parse().expect("asset definition name"),
        );
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            "bond".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&user1);
        let world = World::with(
            [alice_domain, users_domain, defs_domain],
            [alice_account, user1_account, user2_account],
            [asset_definition],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let executor = super::Executor::Initial;
        let instruction = InstructionBox::from(Transfer::asset_definition(
            user1.clone(),
            asset_definition_id.clone(),
            user2.clone(),
        ));
        let transfer = extract_transfer_asset_definition(&instruction)
            .expect("expected to extract asset-definition transfer from instruction");
        let mut stx = block.transaction();
        let allowed = can_transfer_asset_definition(&stx.world, &alice_id, &transfer)
            .expect("asset-definition transfer permission check");
        assert!(
            !allowed,
            "alice should not be allowed to transfer user1-owned asset definition"
        );
        let res = executor.execute_instruction(&mut stx, &alice_id, instruction);
        match res {
            Err(ValidationFail::NotPermitted(msg)) => assert!(
                msg.contains("Can't transfer asset definition"),
                "unexpected rejection message: {msg}"
            ),
            other => panic!(
                "initial executor should deny asset-definition transfer from another account, got: {other:?}"
            ),
        }
    }
    #[test]
    fn initial_executor_denies_transfer_asset_definition_by_definition_domain_owner() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let defs_domain_id: DomainId =
            DomainId::try_new("defs", "universal").expect("defs domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let alice_domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let users_domain = Domain::new(users_domain_id.clone()).build(&user1);
        let defs_domain = Domain::new(defs_domain_id.clone()).build(&alice_id);
        let alice_domain = Domain::new(alice_domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            defs_domain_id.clone(),
            "bond".parse().expect("asset definition name"),
        );
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            "bond".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&user1);
        let world = World::with(
            [alice_domain, users_domain, defs_domain],
            [alice_account, user1_account, user2_account],
            [asset_definition],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let instruction = InstructionBox::from(Transfer::asset_definition(
            user1.clone(),
            asset_definition_id.clone(),
            user2.clone(),
        ));
        let transfer = extract_transfer_asset_definition(&instruction)
            .expect("expected to extract asset-definition transfer from instruction");
        let mut stx = block.transaction();
        let allowed = can_transfer_asset_definition(&stx.world, &alice_id, &transfer)
            .expect("asset-definition transfer permission check");
        assert!(
            !allowed,
            "definition-domain ownership must not authorize transfer without source ownership"
        );
        let res = super::Executor::Initial.execute_instruction(&mut stx, &alice_id, instruction);
        match res {
            Err(ValidationFail::NotPermitted(msg)) => assert!(
                msg.contains("Can't transfer asset definition"),
                "unexpected rejection message: {msg}"
            ),
            other => panic!(
                "initial executor should deny asset-definition transfer by non-source owner, got: {other:?}"
            ),
        }
    }
    #[test]
    fn initial_executor_denies_transfer_nft_without_ownership() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let alice_domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let users_domain = Domain::new(users_domain_id.clone()).build(&user1);
        let alice_domain = Domain::new(alice_domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let nft_id: NftId = "ticket$users.universal".parse().expect("nft id");
        let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&user1);
        let world = World::with_assets(
            [alice_domain, users_domain],
            [alice_account, user1_account, user2_account],
            [],
            [],
            [nft],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let executor = super::Executor::Initial;
        let instruction =
            InstructionBox::from(Transfer::nft(user1.clone(), nft_id.clone(), user2.clone()));
        let transfer = extract_transfer_nft(&instruction)
            .expect("expected to extract nft transfer from instruction");
        let mut stx = block.transaction();
        let allowed = can_transfer_nft(&stx.world, &alice_id, &transfer)
            .expect("nft transfer permission check");
        assert!(
            !allowed,
            "alice should not be allowed to transfer user1-owned nft"
        );
        let res = executor.execute_instruction(&mut stx, &alice_id, instruction);
        match res {
            Err(ValidationFail::NotPermitted(msg)) => assert!(
                msg.contains("Can't transfer NFT"),
                "unexpected rejection message: {msg}"
            ),
            other => panic!(
                "initial executor should deny nft transfer from another account, got: {other:?}"
            ),
        }
    }
    #[test]
    fn initial_executor_allows_transfer_nft_by_nft_domain_owner() {
        let alice_id = ALICE_ID.clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let user1 = checked_account_id();
        let user2 = checked_account_id();
        let alice_domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let users_domain = Domain::new(users_domain_id.clone()).build(&alice_id);
        let alice_domain = Domain::new(alice_domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let user1_account = Account::new(user1.clone()).build(&user1);
        let user2_account = Account::new(user2.clone()).build(&user2);
        let nft_id: NftId = "ticket$users.universal".parse().expect("nft id");
        let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&user1);
        let world = World::with_assets(
            [alice_domain, users_domain],
            [alice_account, user1_account, user2_account],
            [],
            [],
            [nft],
        );
        let state = state_after_genesis(world);
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let instruction =
            InstructionBox::from(Transfer::nft(user1.clone(), nft_id.clone(), user2.clone()));
        let transfer = extract_transfer_nft(&instruction)
            .expect("expected to extract nft transfer from instruction");
        let mut stx = block.transaction();
        let allowed = can_transfer_nft(&stx.world, &alice_id, &transfer)
            .expect("nft transfer permission check");
        assert!(
            allowed,
            "nft-domain owner should be allowed to transfer ownership"
        );
        let res = super::Executor::Initial.execute_instruction(&mut stx, &alice_id, instruction);
        assert!(res.is_ok(), "expected transfer to succeed, got {res:?}");
    }
    #[test]
    fn initial_executor_denies_nft_metadata_edit_in_transaction() {
        let (bob_id, bob_kp) = gen_account_in("wonderland");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain: Domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob_account = Account::new(bob_id.clone()).build(&bob_id);
        let nft_id: NftId = "nft_owner_modify$wonderland.universal"
            .parse()
            .expect("nft id");
        let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&bob_id);
        let world = World::with_assets([domain], [alice_account, bob_account], [], [], [nft]);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = query::store::LiveQueryStore::start_test();
        let chain: ChainId = "test-chain".parse().unwrap();
        let state = State::new_with_chain(world, kura, query_handle, chain);
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let instruction = SetKeyValue::nft(nft_id, "foo".parse().expect("key"), "value");
        let tx = TransactionBuilder::new(
            state.network_id,
            bob_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(bob_kp.private_key());
        let executor = super::Executor::Initial;
        let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
        let mut stx = block.transaction_for_fastpq_testing(Hash::from(tx.hash_as_entrypoint()));
        let res = executor
            .execute_transaction(&mut stx, &bob_id, tx, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection);
        assert!(
            matches!(res, Err(ValidationFail::NotPermitted(_))),
            "initial executor should deny NFT metadata edits by non-domain owners"
        );
    }
    #[test]
    fn bench_profile_runs_without_logger() {
        let authority = ALICE_ID.clone();
        let account = Account::new(authority.clone()).build(&authority);
        let world = World::with([], [account], []);
        let state = state_after_genesis(world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut tx = block.transaction();
        let executor = super::Executor::default();
        let instr: InstructionBox = Log::new(Level::INFO, "bench profile".to_owned()).into();
        executor
            .execute_instruction_with_profile(
                &mut tx,
                &authority,
                instr,
                InstructionExecutionProfile::Bench,
            )
            .expect("bench profile should execute without logger");
    }
    #[test]
    fn multisig_account_direct_signing_is_rejected() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let signer = checked_keypair();
        let member = iroha_data_model::account::MultisigMember::new(signer.public_key().clone(), 1)
            .expect("valid member");
        let policy =
            iroha_data_model::account::MultisigPolicy::new(1, vec![member]).expect("policy");
        let multisig_id = AccountId::new_multisig(policy);
        let domain: Domain = Domain::new(domain_id.clone()).build(&multisig_id);
        let multisig_account = Account::new(multisig_id.clone()).build(&multisig_id);
        let world = World::with([domain], [multisig_account], []);
        let state = state_after_genesis(world);
        let block_header = BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        );
        let mut block = state.block(block_header);
        let builder = TransactionBuilder::new(
            state.network_id,
            multisig_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Instructions(Vec::new().into()));
        let signature = Signature::try_new(signer.private_key(), &builder.payload_hash_bytes())
            .expect("fixture signer should sign the multisig-authority payload prehash");
        let tx = builder.build_with_signature(signature);
        let executor = super::Executor::Initial;
        let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
        let mut stx = block.transaction_for_fastpq_testing(Hash::from(tx.hash_as_entrypoint()));
        stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let res = executor
            .execute_transaction(&mut stx, &multisig_id, tx, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection);
        match res {
            Err(ValidationFail::NotPermitted(msg)) => assert!(
                msg.contains("direct signing with multisig accounts is forbidden"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected multisig direct signing rejection, got {other:?}"),
        }
        #[cfg(feature = "telemetry")]
        {
            assert_eq!(
                stx.telemetry
                    .metrics_ref()
                    .multisig_direct_sign_reject_total
                    .get(),
                1
            );
        }
    }
    // Shared test helpers for generating or loading executor bytecode
    fn read_default_bytecode() -> Option<Vec<u8>> {
        std::env::var_os("IROHA_TEST_USE_DEFAULT_EXECUTOR")?;
        let path1 =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../defaults/executor.to");
        if let Ok(b) = std::fs::read(&path1) {
            return Some(b);
        }
        if let Ok(b) = std::fs::read("defaults/executor.to") {
            return Some(b);
        }
        None
    }
    fn generate_migration_program(
        verdict: &Result<ExecutorDataModel, iroha_data_model::ValidationFail>,
    ) -> Vec<u8> {
        use norito::codec::Encode as _;
        let payload = match verdict {
            Ok(model) => MigrationResultPayload::Ok(model.clone()),
            Err(err) => MigrationResultPayload::Err(err.clone()),
        };
        let verdict_bytes = payload.encode();
        build_program_from_encoded_result(&verdict_bytes)
    }
    fn generate_ok_program() -> Vec<u8> {
        let verdict = Ok(());
        generate_verdict_program(&verdict)
    }
    fn executor_result_test_context() -> ExecutorContext {
        ExecutorContext {
            authority: ALICE_ID.clone(),
            curr_block: BlockHeader::new(nonzero!(1_u64), None, None, 0, 0),
        }
    }
    fn loaded_executor_with_result_prefix(
        declared_len: u64,
        encoded_payload: &[u8],
    ) -> LoadedExecutor {
        let mut program = build_program_from_encoded_result(encoded_payload);
        let parsed = ivm::ProgramMetadata::parse(&program).expect("parse executor test program");
        let literal_section = parsed
            .literal_section
            .expect("encoded result program has a literal section");
        program[literal_section.data_start..literal_section.data_start + 8]
            .copy_from_slice(&declared_len.to_le_bytes());
        let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(program));
        LoadedExecutor::load(raw).expect("load executor test program")
    }
    #[test]
    fn executor_pool_eviction_keeps_active_borrower_and_releases_indexes() {
        let loaded = LoadedExecutor::load(data_model_executor::Executor::new(
            IvmBytecode::from_compiled(generate_ok_program()),
        ))
        .unwrap();
        let parameters = iroha_data_model::parameter::SmartContractParameters::default();
        let mut lease = loaded
            .checkout_runtime_for_gas_limit(
                parameters.fuel().get(),
                parameters.memory().get(),
                &executor_test_budget(),
            )
            .unwrap();
        {
            let mut pool = loaded.runtime_pool.lock().unwrap();
            pool.clear_storage();
            assert_eq!(pool.index_memory.bytes(), 0);
            assert_eq!(pool.order.capacity(), 0);
            assert!(pool.variants.is_empty());
        }
        lease.memory.preload_input(0, &[0x5a]).unwrap();
        assert_eq!(
            lease.memory.load_region(Memory::INPUT_START, 1).unwrap(),
            &[0x5a]
        );
        drop(lease);
        assert!(
            loaded.runtime_pool.lock().unwrap().variants.is_empty(),
            "an evicted borrower cannot republish its stale pool identity"
        );
        loaded
            .checkout_runtime_for_gas_limit(
                parameters.fuel().get(),
                parameters.memory().get(),
                &executor_test_budget(),
            )
            .unwrap();
    }
    #[test]
    fn executor_pool_unwind_returns_reset_runtime_and_zero_capacity_stays_cold() {
        let loaded = LoadedExecutor::load(data_model_executor::Executor::new(
            IvmBytecode::from_compiled(generate_ok_program()),
        ))
        .unwrap();
        let parameters = iroha_data_model::parameter::SmartContractParameters::default();
        assert!(
            iroha_panic_hook::catch_unwind_suppressed(std::panic::AssertUnwindSafe(|| {
                let mut lease = loaded
                    .checkout_runtime_for_gas_limit(
                        parameters.fuel().get(),
                        parameters.memory().get(),
                        &executor_test_budget(),
                    )
                    .unwrap();
                lease.memory.preload_input(0, &[0x5a]).unwrap();
                panic!("unwind through executor lease");
            }))
            .is_err()
        );
        let lease = loaded
            .checkout_runtime_for_gas_limit(
                parameters.fuel().get(),
                parameters.memory().get(),
                &executor_test_budget(),
            )
            .unwrap();
        assert_eq!(
            lease.memory.load_region(Memory::INPUT_START, 1).unwrap(),
            &[0]
        );
        drop(lease);
        {
            let mut pool = loaded.runtime_pool.lock().unwrap();
            pool.clear_storage();
            pool.capacity = 0;
        }
        for _ in 0..2 {
            let mut lease = loaded
                .checkout_runtime_for_gas_limit(
                    parameters.fuel().get(),
                    parameters.memory().get(),
                    &executor_test_budget(),
                )
                .unwrap();
            lease.set_register(10, Memory::OUTPUT_START);
            lease.run().unwrap();
            let verdict: Result<(), ValidationFail> = Ok(());
            assert_eq!(
                executor_output_payload(&lease, Memory::OUTPUT_START, "verdict").unwrap(),
                verdict.encode(),
                "cold execution must still publish the complete encoded verdict"
            );
            drop(lease);
            let pool = loaded.runtime_pool.lock().unwrap();
            assert!(pool.variants.is_empty());
            assert_eq!(pool.index_memory.bytes(), 0);
        }
    }
    #[test]
    fn overlapping_executor_runtimes_return_with_their_own_baselines() {
        if executor_cache_test_in_child(
            "overlapping_executor_runtimes_return_with_their_own_baselines",
        ) {
            return;
        }
        // Hold the real default retention policy while asserting cache reuse;
        // other State fixtures may deliberately configure a cold-only budget.
        let _cache_limits = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
            capacity: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
            max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
            max_decoded_ops:
                iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
        });
        let verdict: Result<(), ValidationFail> = Ok(());
        let encoded = verdict.encode();
        let loaded = loaded_executor_with_result_prefix(
            EXECUTOR_LENGTH_PREFIX_BYTES_U64
                + u64::try_from(encoded.len()).expect("bounded verdict"),
            &encoded,
        );
        let parameters = iroha_data_model::parameter::SmartContractParameters::default();
        // Keep the two immutable baselines and the returned VM within the real
        // aggregate retention budget while the first VM remains borrowed. The
        // maximum-stack default can legitimately force this overlap cold.
        let gas_limit = 10_000;
        let heap_limit = parameters.memory().get();
        loaded.runtime_pool.lock().unwrap().clear_storage();
        drop(
            loaded
                .checkout_runtime_for_gas_limit(gas_limit, heap_limit, &executor_test_budget())
                .expect("warm bounded-stack executor runtime"),
        );
        let (before, variants) = loaded.runtime_pool_snapshot();
        assert_eq!(variants, 1);
        let first = loaded
            .checkout_runtime_for_gas_limit(gas_limit, heap_limit, &executor_test_budget())
            .expect("first pooled executor runtime");
        let second_allocation = {
            let mut second = loaded
                .checkout_runtime_for_gas_limit(gas_limit, heap_limit, &executor_test_budget())
                .expect("overlapping cold executor runtime");
            let allocation = second
                .memory
                .load_region(0, 1)
                .expect("second code memory")
                .as_ptr();
            second
                .memory
                .preload_input(0, &[0xA5])
                .expect("dirty second input");
            allocation
        };
        let third = loaded
            .checkout_runtime_for_gas_limit(gas_limit, heap_limit, &executor_test_budget())
            .expect("second runtime must be reusable while first remains leased");
        assert_eq!(
            third
                .memory
                .load_region(0, 1)
                .expect("third code memory")
                .as_ptr(),
            second_allocation
        );
        assert_eq!(
            third
                .memory
                .load_region(Memory::INPUT_START, 1)
                .expect("third input memory"),
            [0]
        );
        let (stats, variants) = loaded.runtime_pool_snapshot();
        assert_eq!(variants, 1);
        assert_eq!(stats.hits - before.hits, 2);
        assert_eq!(stats.misses - before.misses, 1);
        assert_eq!(stats.program_loads - before.program_loads, 1);
        assert_eq!(stats.template_builds - before.template_builds, 1);
        assert_eq!(stats.dirty_resets - before.dirty_resets, 1);
        drop((third, first));
    }
    fn loaded_executor_returning_past_heap_result() -> LoadedExecutor {
        let metadata = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 100_000,
            abi_version: 1,
        };
        let mut program = metadata.encode();
        let mut displacement = Memory::HEAP_MAX_SIZE - EXECUTOR_LENGTH_PREFIX_BYTES_U64;
        while displacement != 0 {
            let chunk = displacement.min(127);
            program.extend_from_slice(
                &ivm::encoding::wide::encode_ri(
                    ivm::instruction::wide::arithmetic::ADDI,
                    10,
                    10,
                    i8::try_from(chunk).expect("bounded ADDI chunk"),
                )
                .to_le_bytes(),
            );
            displacement -= chunk;
        }
        program.extend_from_slice(
            &ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 0)
                .to_le_bytes(),
        );
        program.extend_from_slice(
            &ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 11, 16)
                .to_le_bytes(),
        );
        program.extend_from_slice(
            &ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 10, 11, 0)
                .to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(program));
        LoadedExecutor::load(raw).expect("load past-heap executor test program")
    }
    fn assert_executor_result_length_rejected_by_validation_and_migration(
        declared_len: u64,
        expected_message: &str,
    ) {
        let loaded = loaded_executor_with_result_prefix(declared_len, &[]);
        let context = executor_result_test_context();
        let validation_payload = ValidatePayload {
            context: context.clone(),
            target: 0_u8,
        };
        let validation_result = run_executor_validation(
            &loaded,
            &validation_payload,
            "hostile-output-test",
            1_000_000,
            Memory::HEAP_MAX_SIZE,
            &executor_test_budget(),
        );
        let validation_error = match validation_result {
            Err(error) => error,
            Ok(_) => panic!("hostile validation result must be rejected"),
        };
        assert!(
            validation_error.to_string().contains(expected_message),
            "unexpected validation error: {validation_error}"
        );
        let migration_error = run_executor_migration(
            &loaded,
            &context,
            1_000_000,
            Memory::HEAP_MAX_SIZE,
            &executor_test_budget(),
        )
        .expect_err("hostile migration result must be rejected");
        assert!(
            migration_error.to_string().contains(expected_message),
            "unexpected migration error: {migration_error}"
        );
    }
    #[test]
    fn executor_result_reader_rejects_short_and_gigabyte_prefixes_in_both_paths() {
        assert_executor_result_length_rejected_by_validation_and_migration(
            EXECUTOR_LENGTH_PREFIX_BYTES_U64 - 1,
            "shorter than its fixed u64 length prefix",
        );
        assert_executor_result_length_rejected_by_validation_and_migration(
            u64::from(u32::MAX),
            "length exceeds the 1048576-byte limit",
        );
        assert_executor_result_length_rejected_by_validation_and_migration(
            1_u64 << 32,
            "length exceeds the 1048576-byte limit",
        );
    }
    #[test]
    fn executor_result_reader_rejects_ranges_past_readable_memory_in_both_paths() {
        let loaded = loaded_executor_returning_past_heap_result();
        let context = executor_result_test_context();
        let validation_result = run_executor_validation(
            &loaded,
            &ValidatePayload {
                context: context.clone(),
                target: 0_u8,
            },
            "past-heap-output-test",
            100_000,
            Memory::HEAP_MAX_SIZE,
            &executor_test_budget(),
        );
        let validation_error = match validation_result {
            Err(error) => error,
            Ok(_) => panic!("past-heap validation result must be rejected"),
        };
        assert!(
            validation_error
                .to_string()
                .contains("is not fully readable"),
            "unexpected validation error: {validation_error}"
        );
        let migration_error = run_executor_migration(
            &loaded,
            &context,
            100_000,
            Memory::HEAP_MAX_SIZE,
            &executor_test_budget(),
        )
        .expect_err("past-heap migration result must be rejected");
        assert!(
            migration_error
                .to_string()
                .contains("is not fully readable"),
            "unexpected migration error: {migration_error}"
        );
    }
    #[test]
    fn migration_result_requires_a_canonical_complete_payload() {
        let discriminant_only = [0_u8; 4];
        let mut discriminant_only_slice = discriminant_only.as_slice();
        assert!(
            MigrationResultPayload::decode(&mut discriminant_only_slice).is_err(),
            "an Ok discriminant without an ExecutorDataModel must not decode"
        );
        let canonical_unit = MigrationUnitPayload::Ok(()).encode();
        assert_ne!(
            canonical_unit.as_slice(),
            discriminant_only.as_slice(),
            "canonical unit success includes its Norito payload framing"
        );
        let context = executor_result_test_context();
        let declared_len = EXECUTOR_LENGTH_PREFIX_BYTES_U64
            + u64::try_from(canonical_unit.len()).expect("bounded migration result");
        let unit_success =
            loaded_executor_with_result_prefix(declared_len, canonical_unit.as_slice());
        assert_eq!(
            run_executor_migration(
                &unit_success,
                &context,
                1_000_000,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget()
            )
            .expect("a canonical unit-success migration result must be accepted"),
            None,
            "the unit-success payload must not install an empty data model"
        );
        let model = initial_executor_data_model_fallback();
        let canonical = MigrationResultPayload::Ok(model.clone()).encode();
        let declared_len = EXECUTOR_LENGTH_PREFIX_BYTES_U64
            + u64::try_from(canonical.len()).expect("bounded migration result");
        let complete = loaded_executor_with_result_prefix(declared_len, canonical.as_slice());
        assert_eq!(
            run_executor_migration(
                &complete,
                &context,
                1_000_000,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget()
            )
            .expect("a canonical complete migration result must be accepted"),
            Some(model)
        );
        let mut non_canonical = canonical;
        non_canonical.push(0);
        let declared_len = EXECUTOR_LENGTH_PREFIX_BYTES_U64
            + u64::try_from(non_canonical.len()).expect("bounded migration result");
        let trailing = loaded_executor_with_result_prefix(declared_len, non_canonical.as_slice());
        let trailing_error = run_executor_migration(
            &trailing,
            &context,
            1_000_000,
            Memory::HEAP_MAX_SIZE,
            &executor_test_budget(),
        )
        .expect_err("a migration result with trailing bytes must be rejected");
        assert!(
            trailing_error
                .to_string()
                .contains("undecodable or non-canonical"),
            "unexpected non-canonical migration result error: {trailing_error}"
        );
    }
    #[test]
    fn executor_result_reader_preserves_legitimate_validation_and_migration_results() {
        let context = executor_result_test_context();
        let validation_verdict: Result<(), ValidationFail> = Ok(());
        let validation = loaded_executor_with_result_prefix(
            EXECUTOR_LENGTH_PREFIX_BYTES_U64
                + u64::try_from(validation_verdict.encode().len()).expect("bounded verdict"),
            &validation_verdict.encode(),
        );
        let report = run_executor_validation(
            &validation,
            &ValidatePayload {
                context: context.clone(),
                target: 0_u8,
            },
            "legitimate-output-test",
            1_000_000,
            Memory::HEAP_MAX_SIZE,
            &executor_test_budget(),
        )
        .expect("legitimate validation result is readable");
        assert!(report.verdict.is_ok());
        let migration_verdict = MigrationUnitPayload::Ok(()).encode();
        let migration = loaded_executor_with_result_prefix(
            EXECUTOR_LENGTH_PREFIX_BYTES_U64
                + u64::try_from(migration_verdict.len()).expect("bounded migration result"),
            &migration_verdict,
        );
        assert_eq!(
            run_executor_migration(
                &migration,
                &context,
                1_000_000,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget()
            )
            .expect("legitimate migration result is readable"),
            None
        );
    }
    fn contract_program_with_entrypoint(
        entrypoint: &str,
        permission: Option<&str>,
    ) -> (Vec<u8>, u64) {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        contract_program_with_entrypoint_kind(entrypoint, EntryPointKind::Kotoage, permission)
    }
    fn contract_program_with_entrypoint_kind(
        entrypoint: &str,
        kind: iroha_data_model::smart_contract::manifest::EntryPointKind,
        permission: Option<&str>,
    ) -> (Vec<u8>, u64) {
        use ivm::{EmbeddedContractInterfaceV1, EmbeddedEntrypointDescriptor, ProgramMetadata};
        let descriptor = EmbeddedEntrypointDescriptor {
            name: entrypoint.to_owned(),
            kind,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: if matches!(kind, iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari | iroha_data_model::smart_contract::manifest::EntryPointKind::Kaizen) {
                EntrypointAuthorizationV1::RuntimeLifecycle
            } else { permission.map_or(EntrypointAuthorizationV1::Anyone, |name| EntrypointAuthorizationV1::Permission(name.parse().unwrap())) },
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        };
        let interface = EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: permission
                .into_iter()
                .map(|name| {
                    iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 {
                        name: name.parse().unwrap(),
                        scope: ContractPermissionScopeV1::Instance,
                    }
                })
                .collect(),
            callables: vec![crate::ivm_test_support::unit_callable(0)],
            seiyaku_name: "TestContract".to_owned(),
            compiler_fingerprint: "executor-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![descriptor],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let interface_section = interface.encode_section();
        let expected_entrypoint_pc =
            u64::try_from(interface_section.len()).expect("section length fits u64");
        let metadata = ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 1_000_000,
            abi_version: 1,
        };
        let mut program = metadata.encode();
        program.extend_from_slice(&interface_section);
        program.extend_from_slice(&crate::ivm_test_support::unit_return());
        (program, expected_entrypoint_pc)
    }
    fn contract_program_with_private_input_entrypoint(
        entrypoint: &str,
        kind: iroha_data_model::smart_contract::manifest::EntryPointKind,
    ) -> Vec<u8> {
        use ivm::{EmbeddedContractInterfaceV1, EmbeddedEntrypointDescriptor, ProgramMetadata};
        let descriptor = EmbeddedEntrypointDescriptor {
            name: entrypoint.to_owned(),
            kind,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: if matches!(kind, iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari | iroha_data_model::smart_contract::manifest::EntryPointKind::Kaizen) { EntrypointAuthorizationV1::RuntimeLifecycle } else { EntrypointAuthorizationV1::Anyone },
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        };
        let interface = EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            callables: vec![crate::ivm_test_support::unit_callable(0)],
            seiyaku_name: "PrivateInputContract".to_owned(),
            compiler_fingerprint: "executor-private-input-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: ivm::CONTRACT_FEATURE_BIT_ZK,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![descriptor],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let metadata = ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: ivm::ivm_mode::ZK,
            vector_length: 0,
            max_cycles: 1_000_000,
            abi_version: 1,
        };
        let mut program = metadata.encode();
        program.extend_from_slice(&interface.encode_section());
        program.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                ivm::syscalls::SYSCALL_GET_PRIVATE_INPUT as u8,
            )
            .to_le_bytes(),
        );
        program.extend_from_slice(&crate::ivm_test_support::unit_return());
        program
    }
    fn prepared_parameterized_trigger_contract() -> ivm::PreparedContract {
        let source = r#"
seiyaku TriggerArguments { permission Admin;
  kotoage fn run(quantity val) authorize(Admin) {
    let _val = val;
  }
}
"#;
        let code = kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .expect("compile parameterized trigger callback");
        ivm::prepare_contract(Arc::<[u8]>::from(code))
            .expect("prepare parameterized trigger callback")
    }
    #[test]
    fn contract_call_enforces_entrypoint_and_hold_before_argument_decode() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        const REQUIRED_PERMISSION: &str = "CanInvokeContractEntrypoint";
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku GuardedValue { permission CanInvokeContractEntrypoint;
  kotoage fn write(int value) authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("guarded_value"),
      value: Json::parse("{\"authorized\":true}")
    );
  }
}
"#,
            )
            .expect("compile parameterized protected contract");
        let parsed = ivm::ProgramMetadata::parse(&program).expect("parse protected contract");
        let schema = parsed
            .contract_interface
            .as_ref()
            .and_then(|interface| {
                interface
                    .entrypoints
                    .iter()
                    .find(|entry| entry.name == "write")
            })
            .and_then(|entry| entry.argument_schema.as_ref())
            .expect("write argument schema");
        let arguments = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({ "value": "7" })),
        )
        .expect("encode valid protected arguments");
        let arguments =
            iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(arguments)
                .expect("bounded protected arguments");
        let authority = ALICE_ID.clone();
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").expect("valid domain id"))
                .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let state = state_after_genesis(World::with([domain], [account], []));
        let code_hash = ivm::contract_code_hash(&program);
        let contract_address =
            ContractAddress::derive(&state.network_id, &authority, 0, DataSpaceId::UNIVERSAL)
                .expect("derive contract address");
        let metadata_marker: Name = "guarded_value"
            .parse()
            .expect("valid direct-call metadata marker");
        let mut world = state.world.block();
        world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            program.clone(),
        );
        world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &ALICE_KEYPAIR,
                )
                .expect("sign bounded fixture manifest"),
        );
        // The invoked contract's subject needs its own exact grant for caller metadata.
        world.account_permissions.insert(
            contract_address.subject_id(),
            BTreeSet::from([executor_permission::account::CanModifyAccountMetadata {
                account: authority.clone(),
            }
            .into()]),
        );
        world.commit();
        bind_executor_test_contract_after_genesis(&state, &contract_address, &authority, code_hash);
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(50_000_000),
            ),
        )
        .with_executable(Executable::ContractCall(ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: code_hash,
            entrypoint: "write".to_owned(),
            arguments: Some(arguments),
        }))
        .sign(ALICE_KEYPAIR.private_key());
        let mut raw_metadata = Metadata::default();
        raw_metadata.insert(
            "contract_address"
                .parse()
                .expect("static contract address key"),
            Json::new(contract_address.to_string()),
        );
        raw_metadata.insert(
            "contract_entrypoint"
                .parse()
                .expect("static contract entrypoint key"),
            Json::new("write"),
        );
        raw_metadata.insert(
            "contract_payload"
                .parse()
                .expect("static contract payload key"),
            Json::from(norito::json!({ "value": "7" })),
        );
        let raw_transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(50_000_000),
            ),
        )
        .with_metadata(raw_metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(ALICE_KEYPAIR.private_key());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let mut ivm_cache = IvmCache::new();
        ivm::reset_argument_record_decode_count();
        let error = super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("missing entrypoint permission must deny the direct call");
        assert!(
            error.to_string().contains(REQUIRED_PERMISSION),
            "unexpected direct contract authorization error: {error}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "denied direct-call arguments must remain undecoded"
        );
        assert!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker)
                .is_none(),
            "denied direct contract call must apply no queued effect"
        );
        drop(state_tx);
        let mut state_tx = block.transaction();
        let entrypoint_authorization: Permission =
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: contract_address.clone(),
                permission: "CanInvokeContractEntrypoint".parse().unwrap(),
            }
            .into();
        Grant::account_permission(entrypoint_authorization.clone(), authority.clone())
            .execute(&authority, &mut state_tx)
            .expect("grant direct-call entrypoint permission");
        state_tx.apply();
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect("granted direct contract call must execute");
        assert_eq!(
            ivm::argument_record_decode_count(),
            1,
            "granted direct-call arguments must be prepared exactly once"
        );
        let authorized_marker = state_tx
            .world
            .account(&authority)
            .expect("authority account")
            .metadata()
            .get(&metadata_marker)
            .cloned()
            .expect("authorized direct call writes its metadata marker");
        state_tx.apply();
        let mut state_tx = block.transaction();
        {
            let binding = state_tx
                .world
                .contract_subject_bindings
                .get_mut(&contract_address)
                .expect("active contract retains its lifecycle binding");
            binding.lifecycle.emergency_hold = Some(ContractEmergencyHoldV1 {
                incident_digest: [0xA1; 32],
                proposal_content_id: [0xA2; 32],
                governance_attempt_id: [0xA3; 32],
                reason: "contain direct contract execution".to_owned(),
                imposed_at_height: 2,
                expires_at_height: 3,
            });
            binding.lifecycle.revision = binding
                .lifecycle
                .revision
                .checked_add(1)
                .expect("test lifecycle revision advances");
        }
        let preproof_held = enforce_transaction_contract_permission_before_proof_verification(
            &state_tx,
            &authority,
            &raw_transaction,
            &mut ivm_cache,
            state_tx.block_height(),
            contract_address.dataspace_id().unwrap(),
        )
        .expect_err("raw-IVM pre-proof admission must observe the execution block height");
        assert!(
            matches!(crate::execution_attempt::expect_completed_rejection(preproof_held.clone()), ValidationFail::NotPermitted(ref message)
                if message.contains("held by Parliament")),
            "unexpected raw-IVM pre-proof emergency-hold error: {preproof_held}"
        );
        enforce_transaction_contract_permission_before_proof_verification(
            &state_tx,
            &authority,
            &raw_transaction,
            &mut ivm_cache,
            3,
            contract_address.dataspace_id().unwrap(),
        )
        .expect("the half-open hold must not deny raw-IVM admission at its expiry height");
        state_tx.apply();
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        let held = super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("an active Parliament hold must suspend the direct contract call");
        assert!(
            matches!(held, ValidationFail::NotPermitted(ref message)
                if message.contains("held by Parliament")),
            "unexpected emergency-hold error: {held}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "a held direct call must fail before decoding its arguments"
        );
        assert_eq!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker),
            Some(&authorized_marker),
            "a held direct call must apply no queued effect"
        );
        drop(state_tx);
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(raw_transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        let held_raw = super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                raw_transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("an active Parliament hold must suspend raw-IVM contract dispatch");
        assert!(
            matches!(held_raw, ValidationFail::NotPermitted(ref message)
                if message.contains("held by Parliament")),
            "unexpected raw-IVM emergency-hold error: {held_raw}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "held raw-IVM dispatch must fail before decoding its argument record"
        );
        assert_eq!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker),
            Some(&authorized_marker),
            "held raw-IVM dispatch must apply no queued effect"
        );
        drop(state_tx);
        let mut state_tx = block.transaction();
        {
            let binding = state_tx
                .world
                .contract_subject_bindings
                .get_mut(&contract_address)
                .expect("held contract retains its lifecycle binding");
            binding.lifecycle.emergency_hold = None;
            binding.lifecycle.revision = binding
                .lifecycle
                .revision
                .checked_add(1)
                .expect("test lifecycle revision advances");
        }
        let live_code = state_tx
            .world
            .contract_code
            .remove(iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ))
            .expect("remove live bytecode for warm-cache adversarial check");
        state_tx.apply();
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        let missing_code = super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("a warm cache must not substitute for missing live bytecode");
        assert!(missing_code.to_string().contains("not found in WSV"));
        assert_eq!(ivm::argument_record_decode_count(), 0);
        assert_eq!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker),
            Some(&authorized_marker),
            "missing live bytecode must apply no queued effect"
        );
        drop(state_tx);
        let mut state_tx = block.transaction();
        state_tx.world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            live_code,
        );
        let live_manifest = state_tx
            .world
            .contract_manifests
            .remove(iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ))
            .expect("remove live manifest for warm-cache adversarial check");
        state_tx.apply();
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        let missing_manifest = super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("a warm cache must not substitute for a missing live manifest");
        assert!(
            matches!(&missing_manifest, ValidationFail::NotPermitted(reason)
                if reason == "contract permission requires the current signed manifest"),
            "{missing_manifest:?}"
        );
        assert_eq!(ivm::argument_record_decode_count(), 0);
        assert_eq!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker),
            Some(&authorized_marker),
            "missing live manifest must apply no queued effect"
        );
        drop(state_tx);
        let mut state_tx = block.transaction();
        state_tx.world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            live_manifest,
        );
        Revoke::account_permission(entrypoint_authorization.clone(), authority.clone())
            .execute(&authority, &mut state_tx)
            .expect("revoke direct-call entrypoint permission");
        state_tx.apply();
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        let revoked = super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("revoked direct-call permission must deny execution");
        assert!(revoked.to_string().contains(REQUIRED_PERMISSION));
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "revoked direct-call arguments must remain undecoded"
        );
        assert_eq!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker),
            Some(&authorized_marker),
            "revoked direct contract call must preserve authorized state"
        );
        drop(state_tx);
        let mut state_tx = block.transaction();
        Grant::account_permission(entrypoint_authorization, authority.clone())
            .execute(&authority, &mut state_tx)
            .expect("restore direct-call entrypoint permission");
        let (rebound_program, rebound_manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku GuardedValueRebound { permission CanInvokeContractEntrypoint;
  kotoage fn write(int value) authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("guarded_value"),
      value: Json::parse("{\"authorized\":\"rebound\"}")
    );
  }
}
"#,
            )
            .expect("compile a fully valid rebound contract");
        let rebound_code_hash = ivm::contract_code_hash(&rebound_program);
        state_tx.world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                rebound_code_hash,
            ),
            rebound_program,
        );
        state_tx.world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                rebound_code_hash,
            ),
            rebound_manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &ALICE_KEYPAIR,
                )
                .expect("sign bounded fixture manifest"),
        );
        state_tx
            .world
            .contract_instances
            .insert(contract_address.clone(), rebound_code_hash);
        {
            let binding = state_tx
                .world
                .contract_subject_bindings
                .get_mut(&contract_address)
                .expect("rebound contract retains its lifecycle binding");
            binding.lifecycle.active_code_hash = Some(rebound_code_hash);
            binding.lifecycle.retained_code_hash = Some(rebound_code_hash);
            binding.lifecycle.revision += 1;
        }
        state_tx.apply();
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        let rebound = super::Executor::Initial
            .execute_transaction(
                &mut state_tx,
                &authority,
                transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("a signed direct call must not cross a live code rebind");
        assert!(
            matches!(rebound, ValidationFail::NotPermitted(ref message)
                if message.contains(&contract_address.to_string())
                    && message.contains(&code_hash.to_string())
                    && message.contains(&rebound_code_hash.to_string())),
            "unexpected live-rebind error: {rebound}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "a live code rebind must be rejected before argument decoding"
        );
        assert_eq!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker),
            Some(&authorized_marker),
            "a live code rebind must apply no queued contract effect"
        );
        drop(state_tx);
        let mut state_tx = block.transaction();
        state_tx
            .world
            .contract_instances
            .insert(contract_address.clone(), code_hash);
        {
            let binding = state_tx
                .world
                .contract_subject_bindings
                .get_mut(&contract_address)
                .expect("restored contract retains its lifecycle binding");
            binding.lifecycle.active_code_hash = Some(code_hash);
            binding.lifecycle.retained_code_hash = Some(code_hash);
            binding.lifecycle.revision += 1;
        }
        state_tx
            .world
            .contract_code
            .remove(iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                rebound_code_hash,
            ))
            .expect("remove rebound bytecode after restoring the original binding");
        state_tx
            .world
            .contract_manifests
            .remove(iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                rebound_code_hash,
            ))
            .expect("remove rebound manifest after restoring the original binding");
        state_tx
            .world
            .contract_instances
            .remove(contract_address.clone());
        {
            let binding = state_tx
                .world
                .contract_subject_bindings
                .get_mut(&contract_address)
                .expect("deactivated contract retains its lifecycle binding");
            binding.lifecycle.active_code_hash = None;
            binding.lifecycle.revision += 1;
        }
        state_tx.apply();
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        ivm::reset_argument_record_decode_count();
        let deactivated = super::Executor::Initial
            .execute_transaction(&mut state_tx, &authority, transaction, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("deactivated direct-call target must deny execution");
        assert!(
            deactivated.to_string().contains("not found"),
            "unexpected deactivated direct-call error: {deactivated}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "deactivated direct-call arguments must remain undecoded"
        );
        assert_eq!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&metadata_marker),
            Some(&authorized_marker),
            "deactivated direct contract call must apply no queued effect"
        );
    }
    #[test]
    fn mixed_batch_next_contract_reserves_accountable_nested_block_gas() {
        assert_eq!(
            super::live_batch_contract_execution_limit(Some(100), 20, 80, 70),
            10,
            "nested trigger/host work must reduce the next contract's block allowance"
        );
        assert_eq!(
            super::live_batch_contract_execution_limit(Some(30), 20, 80, 25),
            10,
            "the signature-bound direct-gas allowance remains independently enforced"
        );
        assert_eq!(
            super::live_batch_contract_execution_limit(None, 20, u64::MAX, 25),
            u64::MAX - 25,
            "an unlimited block still accounts already-retained work"
        );
    }
    #[test]
    fn mixed_batch_observes_ordered_permission_state_and_rolls_back_on_failure() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku OrderedBatchGuard { permission CanInvokeContractEntrypoint;
  kotoage fn write(int value) authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("mixed_batch_marker"),
      value: Json::parse("{\"written\":true}")
    );
  }
}
"#,
            )
            .expect("compile ordered mixed-batch contract");
        let parsed = ivm::ProgramMetadata::parse(&program).expect("parse mixed-batch contract");
        let schema = parsed
            .contract_interface
            .as_ref()
            .and_then(|interface| {
                interface
                    .entrypoints
                    .iter()
                    .find(|entry| entry.name == "write")
            })
            .and_then(|entry| entry.argument_schema.as_ref())
            .expect("write argument schema");
        let arguments = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({ "value": "9" })),
        )
        .expect("encode mixed-batch arguments");
        let arguments =
            iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(arguments)
                .expect("bounded mixed-batch arguments");
        let authority = ALICE_ID.clone();
        let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
            .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let state = state_after_genesis(World::with([domain], [account], []));
        let code_hash = ivm::contract_code_hash(&program);
        let contract_address =
            ContractAddress::derive(&state.network_id, &authority, 93, DataSpaceId::UNIVERSAL)
                .expect("derive contract address");
        let mut world = state.world.block();
        world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            program,
        );
        world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &ALICE_KEYPAIR,
                )
                .expect("sign bounded fixture manifest"),
        );
        // The invoked contract's subject needs its own exact grant for caller metadata.
        world.account_permissions.insert(
            contract_address.subject_id(),
            BTreeSet::from([executor_permission::account::CanModifyAccountMetadata {
                account: authority.clone(),
            }
            .into()]),
        );
        world.commit();
        bind_executor_test_contract_after_genesis(&state, &contract_address, &authority, code_hash);
        let entrypoint_authorization: Permission =
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: contract_address.clone(),
                permission: "CanInvokeContractEntrypoint".parse().unwrap(),
            }
            .into();
        let invocation = ContractInvocation {
            contract_address,
            expected_code_hash: code_hash,
            entrypoint: "write".to_owned(),
            arguments: Some(arguments),
        };
        let explicit_instructions = vec![
            InstructionBox::from(Grant::account_permission(
                entrypoint_authorization.clone(),
                authority.clone(),
            )),
            InstructionBox::from(Revoke::account_permission(
                entrypoint_authorization.clone(),
                authority.clone(),
            )),
        ];
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000_000)),
        )
        .with_executable(Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(explicit_instructions[0].clone()),
                ExecutableBatchItem::ContractCall(invocation.clone()),
                ExecutableBatchItem::Instruction(explicit_instructions[1].clone()),
            ]
            .into(),
        ))
        .sign(ALICE_KEYPAIR.private_key());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let mut ivm_cache = IvmCache::new();
        super::Executor::Initial
            .execute_transaction(&mut state_tx, &authority, transaction, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect("grant-call-revoke batch must execute in order");
        let marker: Name = "mixed_batch_marker".parse().expect("marker name");
        assert!(
            state_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&marker)
                .is_some(),
            "the contract call must observe the preceding permission grant"
        );
        assert!(
            !state_tx
                .world
                .account_permissions_iter(&authority)
                .expect("authority permissions")
                .any(|permission| permission == &entrypoint_authorization),
            "the trailing revoke must remain visible after the call"
        );
        assert!(
            state_tx.last_tx_gas_used > isi_gas::meter_instructions(&explicit_instructions),
            "aggregate batch gas must include contract execution"
        );
        state_tx.apply();
        let capped_transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000_000)),
        )
        .with_executable(Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(explicit_instructions[0].clone()),
                ExecutableBatchItem::ContractCall(invocation.clone()),
            ]
            .into(),
        ))
        .sign(ALICE_KEYPAIR.private_key());
        let mut instruction_capped_state_tx = block
            .transaction_for_fastpq_testing(Hash::from(capped_transaction.hash_as_entrypoint()));
        instruction_capped_state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        instruction_capped_state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        instruction_capped_state_tx
            .pipeline
            .overlay_max_instructions = 1;
        let instruction_cap_error = super::Executor::Initial
            .execute_transaction(
                &mut instruction_capped_state_tx,
                &authority,
                capped_transaction.clone(),
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("contract-emitted ISIs must count toward the mixed-batch overlay cap");
        assert!(
            matches!(instruction_cap_error, ValidationFail::NotPermitted(ref message)
                if message == "overlay exceeds max instructions: 2 > 1"),
            "unexpected mixed-batch instruction-cap error: {instruction_cap_error}"
        );
        assert!(
            instruction_capped_state_tx.last_tx_gas_used
                > isi_gas::meter_instructions(&explicit_instructions[..1]),
            "overlay-cap rejection must retain the completed contract attempt"
        );
        drop(instruction_capped_state_tx);
        let explicit_overlay_bytes =
            super::live_batch_overlay_byte_size(&explicit_instructions[..1]);
        let mut byte_capped_state_tx = block
            .transaction_for_fastpq_testing(Hash::from(capped_transaction.hash_as_entrypoint()));
        byte_capped_state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        byte_capped_state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        byte_capped_state_tx.pipeline.overlay_max_instructions = 0;
        byte_capped_state_tx.pipeline.overlay_max_bytes = explicit_overlay_bytes;
        let byte_cap_error = super::Executor::Initial
            .execute_transaction(
                &mut byte_capped_state_tx,
                &authority,
                capped_transaction,
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("contract-emitted ISIs must count toward the mixed-batch byte cap");
        assert!(
            matches!(byte_cap_error, ValidationFail::NotPermitted(ref message)
                if message.starts_with("overlay exceeds max bytes: ")
                    && message == &format!("overlay exceeds max bytes: more than {explicit_overlay_bytes}")),
            "unexpected mixed-batch byte-cap error: {byte_cap_error}"
        );
        drop(byte_capped_state_tx);
        let cap_verification_tx = block.transaction();
        assert!(
            !cap_verification_tx
                .world
                .account_permissions_iter(&authority)
                .expect("authority permissions")
                .any(|permission| permission == &entrypoint_authorization),
            "dropping a cap-rejected mixed batch must roll back its permission grant"
        );
        drop(cap_verification_tx);
        let rollback_marker: Name = "mixed_batch_rollback_marker"
            .parse()
            .expect("rollback marker name");
        let failing_transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000_000)),
        )
        .with_executable(Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(InstructionBox::from(SetKeyValue::account(
                    authority.clone(),
                    rollback_marker.clone(),
                    Json::new(true),
                ))),
                ExecutableBatchItem::ContractCall(invocation),
            ]
            .into(),
        ))
        .sign(ALICE_KEYPAIR.private_key());
        let mut failed_state_tx = block
            .transaction_for_fastpq_testing(Hash::from(failing_transaction.hash_as_entrypoint()));
        failed_state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        failed_state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let error = super::Executor::Initial
            .execute_transaction(
                &mut failed_state_tx,
                &authority,
                failing_transaction,
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("the revoked permission must reject the later call");
        assert!(error.to_string().contains("CanInvokeContractEntrypoint"));
        drop(failed_state_tx);
        let verification_tx = block.transaction();
        assert!(
            verification_tx
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&rollback_marker)
                .is_none(),
            "dropping the failed batch transaction must roll back its preceding native write"
        );
    }
    #[test]
    fn resolved_contract_invocation_releases_cache_and_records_vm_error_gas() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku MeteredFailure { permission CanInvokeContractEntrypoint;
  kotoage fn run() authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("must_not_be_written"),
      value: Json::parse("true")
    );
  }
}
"#,
            )
            .expect("compile metered failure contract");
        let authority = ALICE_ID.clone();
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").expect("valid domain id"))
                .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let state = state_after_genesis(World::with([domain], [account], []));
        let code_hash = ivm::contract_code_hash(&program);
        let contract_address =
            ContractAddress::derive(&state.network_id, &authority, 94, DataSpaceId::UNIVERSAL)
                .expect("derive metered failure contract address");
        let mut world = state.world.block();
        world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            program,
        );
        world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                contract_address.dataspace_id().unwrap(),
                code_hash,
            ),
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &ALICE_KEYPAIR,
                )
                .expect("sign bounded fixture manifest"),
        );
        world.commit();
        bind_executor_test_contract_after_genesis(&state, &contract_address, &authority, code_hash);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        let entrypoint_authorization: Permission =
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: contract_address.clone(),
                permission: "CanInvokeContractEntrypoint".parse().unwrap(),
            }
            .into();
        Grant::account_permission(entrypoint_authorization, authority.clone())
            .execute(&authority, &mut state_transaction)
            .expect("grant metered failure entrypoint permission");
        let invocation = ContractInvocation {
            contract_address,
            expected_code_hash: code_hash,
            entrypoint: "run".to_owned(),
            arguments: None,
        };
        // This private resolved-call fixture still owns one actual signed root;
        // it tests cache release and failed VM work, not full source admission.
        let signed = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(10)),
        )
        .with_executable(Executable::ContractCall(invocation.clone()))
        .sign(ALICE_KEYPAIR.private_key());
        state_transaction.current_tx_hash = Some(signed.hash());
        state_transaction.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
        state_transaction
            .begin_execution_effect_budget(&signed)
            .unwrap();
        let executor = state_transaction.world.executor.clone();
        let cache = state_transaction.ivm_cache;
        let resolved = {
            let mut guard = cache.lock();
            executor
                .resolve_contract_invocation(&mut state_transaction, &invocation, &mut guard)
                .expect("resolve deployed contract while the cache is locked")
        };
        assert!(
            cache.try_lock().is_some(),
            "the resolved invocation must not retain the outer cache mutex"
        );
        let error = executor
            .execute_resolved_contract_invocation(
                &mut state_transaction,
                &authority,
                &invocation,
                resolved,
                10,
                0,
                None,
            )
            .expect_err("ten units of gas cannot complete the contract");
        state_transaction.finish_execution_effect_budget().unwrap();
        let ValidationFail::IvmFault(fault) = error else {
            panic!("expected a typed gas-exhaustion fault, got {error}");
        };
        assert_eq!(
            fault.kind,
            iroha_data_model::executor::fault::IvmFaultKindV1::OutOfGas
        );
        assert_eq!(fault.site.code_hash, code_hash);
        assert_eq!(
            fault.site.selector,
            iroha_data_model::executor::fault::IvmInvocationSelectorV1::Entrypoint(0)
        );
        assert!(
            (1..=10).contains(&state_transaction.last_tx_gas_used),
            "failed VM execution must retain its chargeable gas, observed {}",
            state_transaction.last_tx_gas_used
        );
    }
    #[test]
    fn identityless_raw_and_proved_dispatch_reject_before_argument_decode_or_proof_work() {
        let program = kotodama_lang::compiler::Compiler::new_with_options(
            kotodama_lang::compiler::CompilerOptions {
                force_zk: true,
                max_cycles: 10_000,
                ..kotodama_lang::compiler::CompilerOptions::default()
            },
        )
        .compile_source(
            r#"
seiyaku IdentityRequired {
  view fn write(int value) authorize(anyone) -> int {
    return value;
  }
}
"#,
        )
        .expect("compile identity-required raw contract");
        let authority = ALICE_ID.clone();
        let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
            .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let state = state_after_genesis(World::with([domain], [account], []));
        let mut metadata = Metadata::default();
        metadata.insert(
            "contract_entrypoint".parse().expect("entrypoint key"),
            Json::new("write"),
        );
        metadata.insert(
            "contract_payload".parse().expect("payload key"),
            Json::from(norito::json!({ "value": "7" })),
        );
        let bytecode = IvmBytecode::from_compiled(program);
        let raw = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(1_000_000),
            ),
        )
        .with_metadata(metadata.clone())
        .with_executable(Executable::Ivm(bytecode.clone()))
        .sign(ALICE_KEYPAIR.private_key());
        let proved = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(1_000_000),
            ),
        )
        .with_metadata(metadata)
        .with_executable(Executable::IvmProved(
            iroha_data_model::transaction::IvmProved {
                bytecode,
                overlay: Vec::<InstructionBox>::new().into(),
                events_commitment: Hash::new(b"identityless-events"),
                gas_policy_commitment: Hash::new(b"identityless-gas"),
            },
        ))
        .sign(ALICE_KEYPAIR.private_key());
        let initial_durable_state = {
            let view = state.view();
            view.world()
                .smart_contract_state()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>()
        };
        for (label, transaction) in [("raw", raw), ("proved", proved)] {
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                Some(
                    state
                        .view()
                        .latest_block_hash()
                        .expect("genuine genesis parent"),
                ),
                None,
                0,
                0,
            ));
            let mut state_tx =
                block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
            state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let mut ivm_cache = IvmCache::new();
            ivm::reset_argument_record_decode_count();
            let error = super::Executor::Initial
                .execute_transaction(&mut state_tx, &authority, transaction, &mut ivm_cache)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("identity-less raw contract dispatch must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("requires a live contract_address or contract_alias"),
                "unexpected identity-less {label} dispatch error: {error}"
            );
            assert_eq!(
                ivm::argument_record_decode_count(),
                0,
                "identity-less {label} dispatch must not decode its argument record"
            );
            let observed_durable_state = state_tx
                .world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            assert_eq!(
                observed_durable_state, initial_durable_state,
                "identity-less {label} dispatch must not change durable state"
            );
        }
    }
    fn contract_permission_context(
        contract_address: ContractAddress,
        entrypoint: &str,
        permission: &str,
    ) -> ContractCallExecutionContext {
        ContractCallExecutionContext {
            contract_subject: Some(contract_address.subject_id()),
            contract_address: Some(contract_address),
            contract_alias: None,
            entrypoint: Some(entrypoint.to_owned()),
            entrypoint_pc: Some(0),
            entrypoint_authorization: EntrypointAuthorizationV1::Permission(
                permission.parse().expect("permission name"),
            ),
            args: Json::new(()),
            argument_record: None,
        }
    }
    #[test]
    fn contract_invocation_rejects_a_live_code_rebind() {
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &ALICE_ID,
            77,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let signed_hash = iroha_crypto::Hash::new(b"signed-contract-code");
        let live_hash = iroha_crypto::Hash::new(b"rebound-contract-code");
        let invocation = ContractInvocation {
            contract_address,
            expected_code_hash: signed_hash,
            entrypoint: "run".to_owned(),
            arguments: None,
        };
        let error = ensure_contract_invocation_code_hash(&invocation, live_hash)
            .expect_err("a signed call must not cross a live code rebind");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message)
                if message.contains(&signed_hash.to_string())
                    && message.contains(&live_hash.to_string())),
            "unexpected binding error: {error}"
        );
    }
    #[test]
    fn reviewable_contract_metadata_binds_exact_invocation_arguments() {
        let (program, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku ReviewedValue { permission CanInvokeContractEntrypoint;
  kotoage fn write(int value) authorize(CanInvokeContractEntrypoint) {}
}
"#,
            )
            .expect("compile reviewed contract");
        let prepared = ivm::prepare_contract(Arc::<[u8]>::from(program.clone()))
            .expect("prepare reviewed contract");
        let schema = prepared
            .entrypoint_descriptor("write")
            .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
            .expect("reviewed argument schema");
        let reviewed_payload = Json::from(norito::json!({ "value": "7" }));
        let reviewed_arguments =
            ivm_abi::arguments::encode_argument_record_from_json(schema, &reviewed_payload)
                .expect("encode reviewed arguments");
        let swapped_arguments = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({ "value": "8" })),
        )
        .expect("encode swapped arguments");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &ALICE_ID,
            78,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let code_hash = ivm::contract_code_hash(&program);
        let mut metadata = Metadata::default();
        for (key, value) in [
            ("contract_address", Json::new(contract_address.to_string())),
            ("contract_code_hash", Json::new(code_hash.to_string())),
            ("contract_entrypoint", Json::new("write".to_owned())),
        ] {
            metadata.insert(key.parse().expect("static contract metadata key"), value);
        }
        metadata.insert(
            "contract_payload"
                .parse()
                .expect("static contract payload metadata key"),
            reviewed_payload,
        );
        let invocation = |arguments: Vec<u8>| ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: code_hash,
            entrypoint: "write".to_owned(),
            arguments: Some(
                iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(
                    arguments,
                )
                .expect("bounded reviewed arguments"),
            ),
        };
        let live_alias: iroha_data_model::smart_contract::ContractAlias =
            "reviewed_value::apps.universal"
                .parse()
                .expect("live contract alias");
        super::ensure_contract_invocation_metadata_binding(
            &invocation(reviewed_arguments.clone()),
            &metadata,
            &prepared,
            Some(&live_alias),
        )
        .expect("matching reviewed metadata and arguments");
        let error = super::ensure_contract_invocation_metadata_binding(
            &invocation(swapped_arguments),
            &metadata,
            &prepared,
            Some(&live_alias),
        )
        .expect_err("swapped argument bytes must be rejected");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message)
                if message.contains("arguments differ from the canonical contract_payload")),
            "unexpected swapped-arguments error: {error}"
        );
        // Indexers attribute a call to its `contract_alias`, so the claim must
        // name the address's live alias.
        let alias_key: Name = "contract_alias"
            .parse()
            .expect("static contract alias metadata key");
        let mut aliased = metadata.clone();
        aliased.insert(alias_key.clone(), Json::new(live_alias.to_string()));
        super::ensure_contract_invocation_metadata_binding(
            &invocation(reviewed_arguments.clone()),
            &aliased,
            &prepared,
            Some(&live_alias),
        )
        .expect("the live alias binds");
        let other_alias: iroha_data_model::smart_contract::ContractAlias =
            "forged_router::apps.universal"
                .parse()
                .expect("other contract alias");
        for live in [None, Some(&other_alias)] {
            let error = super::ensure_contract_invocation_metadata_binding(
                &invocation(reviewed_arguments.clone()),
                &aliased,
                &prepared,
                live,
            )
            .expect_err("an alias claim must name the live alias");
            assert!(
                matches!(error, ValidationFail::NotPermitted(ref message)
                    if message.contains("is not the live alias")),
                "unexpected alias error: {error}"
            );
        }
        let mut alias_only = Metadata::default();
        alias_only.insert(alias_key, Json::new(live_alias.to_string()));
        let error = super::ensure_contract_invocation_metadata_binding(
            &invocation(reviewed_arguments),
            &alias_only,
            &prepared,
            Some(&live_alias),
        )
        .expect_err("an alias claim requires the full identity binding");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message)
                if message.contains("requires contract_address metadata")),
            "unexpected alias-only error: {error}"
        );
    }
    #[test]
    fn contract_dispatch_context_carries_entrypoint_authorization() {
        let (program, expected_entrypoint_pc) =
            contract_program_with_entrypoint("admin", Some("ContractAdmin"));
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("contract_entrypoint").expect("static name"),
            Json::new("admin".to_owned()),
        );
        let metadata_context = parse_contract_call_execution_context(&metadata, &program)
            .expect("parse metadata dispatch")
            .expect("metadata dispatch context");
        assert_eq!(metadata_context.entrypoint.as_deref(), Some("admin"));
        assert_eq!(
            metadata_context.entrypoint_pc(),
            Some(expected_entrypoint_pc)
        );
        assert_eq!(
            metadata_context.entrypoint_authorization(),
            &EntrypointAuthorizationV1::Permission("ContractAdmin".parse().unwrap())
        );
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &ALICE_ID,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let invocation = ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: iroha_crypto::Hash::new(b"admin-contract-code"),
            entrypoint: "admin".to_owned(),
            arguments: None,
        };
        let invocation_context = parse_contract_invocation_execution_context(
            &invocation,
            &program,
            None,
            contract_address.subject_id(),
        )
        .expect("parse contract invocation");
        assert_eq!(
            invocation_context.entrypoint_pc(),
            Some(expected_entrypoint_pc)
        );
        assert_eq!(
            invocation_context.entrypoint_authorization(),
            &EntrypointAuthorizationV1::Permission("ContractAdmin".parse().unwrap())
        );
    }
    #[test]
    fn nested_contract_dispatch_accepts_view_without_relaxing_top_level_calls() {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        let (program, expected_entrypoint_pc) = contract_program_with_entrypoint_kind(
            "configuration",
            EntryPointKind::View,
            Some("CanInspectConfiguration"),
        );
        let prepared = ivm::prepare_contract(Arc::<[u8]>::from(program))
            .expect("prepare nested-view contract");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &ALICE_ID,
            2,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let invocation = ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: iroha_crypto::Hash::new(b"configuration-contract-code"),
            entrypoint: "configuration".to_owned(),
            arguments: None,
        };
        let top_level_err = parse_prepared_contract_invocation_execution_context(
            &invocation,
            &prepared,
            None,
            contract_address.subject_id(),
            u64::MAX,
        )
        .expect_err("top-level transaction dispatch must remain public-only");
        assert!(matches!(
            top_level_err,
            ValidationFail::NotPermitted(message) if message.contains("read-only")
        ));
        let descriptor = prepared.entrypoint_descriptor("configuration").unwrap();
        let permission = nested_contract_entrypoint_authorization(descriptor, "configuration")
            .expect("nested dispatch should accept a declared view");
        assert_eq!(
            prepared.entrypoint_pc("configuration"),
            Some(expected_entrypoint_pc)
        );
        assert_eq!(
            permission,
            EntrypointAuthorizationV1::Permission("CanInspectConfiguration".parse().unwrap())
        );
        for (selector, kind) in [
            ("hajimari", EntryPointKind::Hajimari),
            ("始まり", EntryPointKind::Hajimari),
            ("kaizen", EntryPointKind::Kaizen),
            ("改善", EntryPointKind::Kaizen),
        ] {
            let (program, _) = contract_program_with_entrypoint_kind(selector, kind, None);
            let prepared = ivm::prepare_contract(Arc::<[u8]>::from(program))
                .expect("prepare lifecycle contract");
            let descriptor = prepared.entrypoint_descriptor(selector).unwrap();
            let error = nested_contract_entrypoint_authorization(descriptor, selector)
                .expect_err("nested dispatch must reject lifecycle entrypoints");
            assert!(
                matches!(error, ValidationFail::NotPermitted(ref message) if message.contains("cannot be invoked by a nested call")),
                "unexpected {kind:?} nested-dispatch error: {error}"
            );
        }
    }
    #[test]
    fn prepared_view_resolver_accepts_only_views_and_preserves_exact_permission() {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        let (program, expected_pc) = contract_program_with_entrypoint_kind(
            "inspect",
            EntryPointKind::View,
            Some("CanInspectContract"),
        );
        let prepared =
            ivm::prepare_contract(Arc::<[u8]>::from(program)).expect("prepare view contract");
        let (pc, permission, arguments) =
            resolve_prepared_contract_view_entrypoint(&prepared, "inspect")
                .expect("declared view resolves");
        assert_eq!(pc, expected_pc);
        assert_eq!(
            permission,
            EntrypointAuthorizationV1::Permission("CanInspectContract".parse().unwrap())
        );
        assert!(arguments.is_none());
        assert!(
            resolve_prepared_contract_entrypoint(&prepared, "inspect").is_err(),
            "transaction resolution must continue to reject read-only views"
        );
        for (selector, kind) in [
            ("write", EntryPointKind::Kotoage),
            ("hajimari", EntryPointKind::Hajimari),
            ("始まり", EntryPointKind::Hajimari),
            ("kaizen", EntryPointKind::Kaizen),
            ("改善", EntryPointKind::Kaizen),
        ] {
            let permission =
                (kind == EntryPointKind::Kotoage).then_some("CanInvokeContractEntrypoint");
            let (program, _) = contract_program_with_entrypoint_kind(selector, kind, permission);
            let prepared = ivm::prepare_contract(Arc::<[u8]>::from(program))
                .expect("prepare non-view contract");
            let error = resolve_prepared_contract_view_entrypoint(&prepared, selector)
                .expect_err("the view boundary must reject every non-view entrypoint kind");
            assert!(
                matches!(error, ValidationFail::NotPermitted(ref message) if message.contains("not a read-only view")),
                "unexpected {kind:?} view-resolution error: {error}"
            );
        }
    }
    #[test]
    fn prepared_resolvers_reject_private_witness_entrypoints_before_host_execution() {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        let transaction_program =
            contract_program_with_private_input_entrypoint("commit", EntryPointKind::Kotoage);
        let transaction_contract = ivm::prepare_contract(Arc::<[u8]>::from(transaction_program))
            .expect("prepare ZK private-input contract");
        for error in [
            resolve_prepared_contract_entrypoint(&transaction_contract, "commit")
                .expect_err("top-level transaction resolver must reject raw private witnesses"),
            reject_unavailable_private_input_entrypoint(&transaction_contract, "commit")
                .expect_err("prepared contracts must reject raw private witnesses"),
            resolve_prepared_raw_contract_entrypoint(&transaction_contract, "commit")
                .expect_err("raw contract resolver must reject raw private witnesses"),
        ] {
            assert!(
                matches!(error, ValidationFail::NotPermitted(ref message)
                    if message.contains("complete proof-carrying invocation statement")
                        && message.contains("Secret<T>")
                        && message.contains("seiyaku declaration")),
                "unexpected private-input admission error: {error}"
            );
        }
        let view_program =
            contract_program_with_private_input_entrypoint("inspect", EntryPointKind::View);
        let view_contract = ivm::prepare_contract(Arc::<[u8]>::from(view_program))
            .expect("prepare ZK private-input view");
        let error = resolve_prepared_contract_view_entrypoint(&view_contract, "inspect")
            .expect_err("view resolver must reject raw private witnesses");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message)
                if message.contains("complete proof-carrying invocation statement")
                    && message.contains("Secret<T>")
                    && message.contains("seiyaku declaration")),
            "unexpected private-input view error: {error}"
        );
    }
    #[test]
    fn raw_contract_dispatch_rejects_lifecycle_entrypoints() {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        for (selector, kind) in [
            ("hajimari", EntryPointKind::Hajimari),
            ("kaizen", EntryPointKind::Kaizen),
        ] {
            let (program, _) = contract_program_with_entrypoint_kind(selector, kind, None);
            let mut metadata = Metadata::default();
            metadata.insert(
                Name::from_str("contract_entrypoint").expect("static name"),
                Json::new(selector.to_owned()),
            );
            let error = parse_contract_call_execution_context(&metadata, &program)
                .expect_err("raw transaction dispatch must not invoke lifecycle hooks");
            assert!(
                matches!(error, ValidationFail::NotPermitted(message) if message.contains("top-level deployed ContractCall") && message.contains(selector))
            );
        }
    }
    #[test]
    fn top_level_contract_invocation_uses_branded_lifecycle_permissions() {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &ALICE_ID,
            44,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        for (selector, kind, expected_permission) in [
            (
                "hajimari",
                EntryPointKind::Hajimari,
                EntrypointAuthorizationV1::RuntimeLifecycle,
            ),
            (
                "kaizen",
                EntryPointKind::Kaizen,
                EntrypointAuthorizationV1::RuntimeLifecycle,
            ),
        ] {
            let (program, _) = contract_program_with_entrypoint_kind(selector, kind, None);
            let invocation = ContractInvocation {
                contract_address: contract_address.clone(),
                expected_code_hash: iroha_crypto::Hash::new(selector.as_bytes()),
                entrypoint: selector.to_owned(),
                arguments: None,
            };
            let context = parse_contract_invocation_execution_context(
                &invocation,
                &program,
                None,
                contract_address.subject_id(),
            )
            .expect("top-level lifecycle invocation resolves");
            assert_eq!(
                context.entrypoint_authorization(),
                &expected_permission,
                "{selector} must use its runtime-defined branded lifecycle permission"
            );
        }
    }
    #[test]
    fn contract_transaction_dispatch_rejects_view_entrypoints() {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        let (program, _) =
            contract_program_with_entrypoint_kind("inspect", EntryPointKind::View, None);
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("contract_entrypoint").expect("static name"),
            Json::new("inspect".to_owned()),
        );
        let err = parse_contract_call_execution_context(&metadata, &program)
            .expect_err("view transaction dispatch must reject");
        assert!(matches!(
            err,
            ValidationFail::NotPermitted(message)
                if message.contains("read-only")
        ));
    }
    #[test]
    fn contract_dispatch_context_rejects_implicit_main_for_self_describing_artifact() {
        let (program, _) = contract_program_with_entrypoint("main", Some("ContractAdmin"));
        let metadata = Metadata::default();
        let err = parse_contract_call_execution_context(&metadata, &program)
            .expect_err("implicit main dispatch must reject");
        assert!(matches!(
            err,
            ValidationFail::NotPermitted(message)
                if message.contains("require explicit contract_entrypoint")
        ));
    }
    #[test]
    fn contract_dispatch_context_keeps_generic_raw_ivm_without_selector_unclassified() {
        let metadata = Metadata::default();
        let context = parse_contract_call_execution_context(&metadata, &generate_ok_program())
            .expect("parse generic raw ivm context");
        assert!(context.is_none());
    }
    #[test]
    fn direct_generic_ivm_remains_reachable_and_rejects_contract_metadata() {
        let authority = ALICE_ID.clone();
        let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
            .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let state = state_after_genesis(World::with([domain], [account], []));
        let mut program = ivm::ProgramMetadata {
            max_cycles: 100,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let generic_code_hash = ivm::contract_code_hash(&program);
        let executable = Executable::Ivm(IvmBytecode::from_compiled(program));
        let transaction = |metadata: Metadata| {
            TransactionBuilder::new(
                state.network_id,
                authority.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(
                    Vec::new(),
                    core::num::NonZeroU64::new(1_000_000),
                ),
            )
            .with_metadata(metadata)
            .with_executable(executable.clone())
            .sign(ALICE_KEYPAIR.private_key())
        };
        let generic_metadata = Metadata::default();
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("genuine genesis parent"),
            ),
            None,
            0,
            0,
        ));
        let signed = transaction(generic_metadata.clone());
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let mut ivm_cache = IvmCache::new();
        super::Executor::Initial
            .execute_transaction(&mut state_transaction, &authority, signed, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect("contract-less generic IVM must execute at pc zero");
        state_transaction.apply();
        let mut reserved_metadata = generic_metadata;
        reserved_metadata.insert(
            "contract_manifest"
                .parse()
                .expect("contract-manifest metadata key"),
            Json::new("malformed-reserved-value"),
        );
        let signed = transaction(reserved_metadata);
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let error = super::Executor::Initial
            .execute_transaction(&mut state_transaction, &authority, signed, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("generic IVM must not accept contract metadata");
        assert!(
            error.to_string().contains("reserved `contract_manifest`"),
            "unexpected generic-metadata rejection: {error}"
        );
        drop(state_transaction);
        let mut state_transaction = block.transaction();
        state_transaction.world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                DataSpaceId::UNIVERSAL,
                generic_code_hash,
            ),
            iroha_data_model::smart_contract::manifest::ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(generic_code_hash),
                abi_hash: Some(Hash::prehashed(ivm::syscalls::compute_abi_hash(
                    ivm::SyscallPolicy::AbiV1,
                ))),
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            },
        );
        state_transaction.apply();
        let signed = transaction(Metadata::default());
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let error = super::Executor::Initial
            .execute_transaction(&mut state_transaction, &authority, signed, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("a manifest-bound hash must not execute as generic IVM");
        assert!(error.to_string().contains("contract manifest"));
        drop(state_transaction);
        let mut state_transaction = block.transaction();
        state_transaction.world.contract_manifests.remove(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                DataSpaceId::UNIVERSAL,
                generic_code_hash,
            ),
        );
        state_transaction.apply();
        let signed = transaction(Metadata::default());
        let mut state_transaction =
            block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.pipeline.ivm_max_cycles_upper_bound = nonzero!(50_u64);
        let error = super::Executor::Initial
            .execute_transaction(&mut state_transaction, &authority, signed, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("direct generic IVM must honor the live cycle ceiling");
        assert!(matches!(
            error,
            ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::MaxCyclesExceedsUpperBound(_)
            )
        ));
    }
    include!("executor_contract_dispatch_tests.rs");
}

#[cfg(test)]
mod resource_return_tests;

#[cfg(test)]
mod runtime_fault_origin_tests {
    //! Executor verdicts cannot forge native execution-fault provenance.
    use super::*;
    use iroha_data_model::executor::fault::{
        IvmFaultKindV1, IvmFaultPositionV1, IvmFaultSiteV1, IvmFaultV1, IvmInvocationSelectorV1,
    };
    #[test]
    fn executor_verdict_rejects_guest_supplied_runtime_origin() {
        let forged = ValidationFail::IvmFault(IvmFaultV1 {
            kind: IvmFaultKindV1::PermissionDenied,
            site: IvmFaultSiteV1 {
                code_hash: Hash::new(b"unrelated artifact"),
                selector: IvmInvocationSelectorV1::Entrypoint(3),
                position: IvmFaultPositionV1::Execute { pc_offset: 16 },
            },
        });
        assert!(
            matches!(validate_executor_rejection_origin(forged), ValidationFail::InternalError(message) if message.contains("cannot supply a runtime fault origin"))
        );
        let native_permission = ValidationFail::NotPermitted("actual executor policy".into());
        assert_eq!(
            validate_executor_rejection_origin(native_permission.clone()),
            native_permission
        );
    }
}
