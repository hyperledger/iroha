//! Lane and dataspace routing utilities for the transaction queue.
//!
//! These helpers translate pending transactions into the lane/dataspace identifiers that the Nexus
//! scheduler expects, based on the runtime configuration. The router abstraction keeps the queue
//! decoupled from the exact routing policy while allowing metrics to reflect the real assignments
//! instead of collapsing metrics to the primary lane.
mod settlement_atomic;
mod settlement_pair;

use crate::execution_attempt::ExecutionDeferred;
use crate::governance::manifest::lane_uses_reserved_autoscale_metadata;
use crate::{
    state::{State, StateReadOnly, StateView, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_config::parameters::actual::{
    LaneRoutingMatcher, LaneRoutingPolicy, LaneRoutingRule, Nexus,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::{AccountAlias, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionAlias, AssetDefinitionId},
    isi::{
        BurnBox, CustomInstruction, GrantBox, Instruction, InstructionBox, MintBox, RegisterBox,
        RemoveKeyValueBox, RevokeBox, SetKeyValueBox, TransferAssetBatch, TransferBox,
        UnregisterBox,
        contract_alias::SetContractAlias,
        musubi::{
            AcceptMusubiPackageMaintainerV1, AddMusubiArchiveLocationV1, AdvanceMusubiPinOutboxV1,
            AssertMusubiReleaseDigestV1, CheckMusubiPinOutboxV1, InviteMusubiPackageMaintainerV1,
            PublishMusubiReleaseV1, RecoverMusubiPackageV1, RegisterMusubiAliasV1,
            RegisterMusubiArchiveV1, RegisterMusubiNamespaceBindingV1,
            RegisterMusubiProviderBundleAttestationV1, RemoveMusubiPackageMaintainerV1,
            RetargetMusubiAliasV1, RetireMusubiArchiveLocationV1,
            RevokeMusubiPackageMaintainerInvitationV1, SetMusubiArtifactTakedownV1,
            SetMusubiPackageMaintainerRoleV1, SetMusubiPackageMetadataV1,
            SetMusubiRegistryPolicyV1, SetMusubiReleaseYankV1,
        },
        private_settlement::{
            AbortAtomicPrivateSettlementV1, ActivatePrivateSettlementPoolV1,
            FinalizeAtomicPrivateSettlementV1, RegisterAtomicPrivateSettlementPrepareV1,
        },
        settlement::{
            DvpIsi, FundFxCorridorEscrow, FxCorridorPolicy, FxCorridorPolicyRegistry, PvpIsi,
            RefundFxCorridorEscrow, SetFxCorridorPolicy, SettleFxCorridor,
            SettlementInstructionBox,
        },
        smart_contract_code::{
            ActivateContractInstance, CommitContractDeployment, DeactivateContractInstance,
            FinalizeSmartContractCodeUpload, RegisterSmartContractBytes, RegisterSmartContractCode,
            UploadSmartContractCodeChunk,
        },
        space_directory::{
            ExpireSpaceDirectoryManifest, PublishSpaceDirectoryManifest,
            RevokeSpaceDirectoryManifest,
        },
        zk::{
            CancelConfidentialPolicyTransition, RegisterZkAsset,
            ScheduleConfidentialPolicyTransition,
        },
    },
    musubi::MusubiPackageIdV1,
    nexus::{DataSpaceCatalog, LaneCatalog},
    permission::Permission,
    smart_contract::ContractAddress,
    transaction::{Executable, ExecutableBatchItem, signed::TransactionPayload},
};
use iroha_executor_data_model::isi::multisig::{
    MultisigApprove, MultisigInstructionBox, MultisigProposalState, MultisigPropose,
};
use iroha_executor_data_model::permission::{
    account::{
        AccountAliasPermissionScope, CanDelegateAccountAliasResolution, CanManageAccountAlias,
        CanResolveAccountAlias,
    },
    asset::{
        CanBurnAssetWithDefinition, CanMintAssetToAccount, CanMintAssetWithDefinition,
        CanModifyAssetMetadataWithDefinition, CanTransferAssetWithDefinition,
    },
    asset_definition::{
        AssetDefinitionAliasPermissionScope, CanManageAssetDefinitionAlias,
        CanManageAssetDefinitionConfidentialPolicy, CanManageKagemushaWallet,
        CanModifyAssetDefinitionMetadata, CanUnregisterAssetDefinition,
    },
    nexus::{
        CanEnrollFeeSponsorProgram, CanManageFeeSponsorProgram, CanPublishSpaceDirectoryManifest,
        CanPublishSpaceDirectoryManifestForAccountDomain, CanPublishSpaceDirectoryManifestForUaid,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
#[cfg(test)]
use iroha_model_base::state_path::StatePath;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use mv::storage::StorageReadOnly;
#[cfg(test)]
use std::str::FromStr;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use thiserror::Error;

const AMX_POLICY_METADATA_KEY: &str = "amx_policy";
const AMX_POLICY_REJECT_CROSS_DATASPACE: &str = "reject_cross_dataspace";
/// Read-only transaction fields consumed by deterministic lane and dataspace routing.
///
/// Both accepted transactions and canonical unsigned payloads implement this view so
/// quote discovery and queue admission execute the same routing code. Signatures and
/// envelope attachments deliberately do not participate in routing.
pub trait TransactionRoutingView {
    /// Return the authority when this entrypoint has one.
    fn authority_opt(&self) -> Option<&AccountId>;
    /// Return routing metadata when this entrypoint has it.
    fn metadata(&self) -> Option<&Metadata>;
    /// Return the executable used for native routing inspection.
    fn executable(&self) -> Option<&Executable>;
    /// Evaluate a predicate over the instruction batch used by matcher rules.
    fn any_matching_instruction(&self, predicate: &mut dyn FnMut(&dyn Instruction) -> bool)
    -> bool;
    /// Return the signature-independent hash used for elastic default-lane sharding.
    fn routing_hash(&self) -> Hash;
}
fn executable_any_matching_instruction(
    executable: &Executable,
    predicate: &mut dyn FnMut(&dyn Instruction) -> bool,
) -> bool {
    executable
        .explicit_instructions()
        .any(|instruction| predicate(&**instruction))
}
impl TransactionRoutingView for AcceptedTransaction<'_> {
    fn authority_opt(&self) -> Option<&AccountId> {
        AcceptedTransaction::authority_opt(self)
    }
    fn metadata(&self) -> Option<&Metadata> {
        AcceptedTransaction::metadata(self)
    }
    fn executable(&self) -> Option<&Executable> {
        match self.entrypoint() {
            iroha_data_model::transaction::TransactionEntrypoint::External(signed) => {
                Some(signed.instructions())
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedReveal(reveal) => {
                Some(reveal.signed_transaction().instructions())
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedCommitment(_) => None,
        }
    }
    fn any_matching_instruction(
        &self,
        predicate: &mut dyn FnMut(&dyn Instruction) -> bool,
    ) -> bool {
        match self.entrypoint() {
            iroha_data_model::transaction::TransactionEntrypoint::External(signed) => {
                executable_any_matching_instruction(signed.instructions(), predicate)
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedReveal(reveal) => {
                executable_any_matching_instruction(
                    reveal.signed_transaction().instructions(),
                    predicate,
                )
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedCommitment(_) => false,
        }
    }
    fn routing_hash(&self) -> Hash {
        self.external().map_or_else(
            || self.hash_as_entrypoint().into(),
            |signed| HashOf::new(signed.payload()).into(),
        )
    }
}
impl TransactionRoutingView for TransactionPayload {
    fn authority_opt(&self) -> Option<&AccountId> {
        Some(&self.authority)
    }
    fn metadata(&self) -> Option<&Metadata> {
        Some(&self.metadata)
    }
    fn executable(&self) -> Option<&Executable> {
        Some(&self.instructions)
    }
    fn any_matching_instruction(
        &self,
        predicate: &mut dyn FnMut(&dyn Instruction) -> bool,
    ) -> bool {
        executable_any_matching_instruction(&self.instructions, predicate)
    }
    fn routing_hash(&self) -> Hash {
        HashOf::new(self).into()
    }
}
pub use iroha_data_model::block::lane_admission::{
    NativeAmxRoutingPlan, RouteLeg, RouteLegRole, RoutingDecision, RoutingPlan,
};
/// Routing resolution failure or unfinished local read against configured Nexus catalogs.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RoutingResolveError {
    /// An original local routing read did not complete; this is never a route rejection.
    #[error("routing deferred: {0}")]
    Deferred(#[from] crate::execution_attempt::ExecutionDeferred),
    /// Immutable signed-genesis root scope is missing, malformed, or unsupported.
    #[error("routing requires authenticated signed-genesis root scope")]
    UnauthenticatedRootScope,
    /// An atomic settlement cannot be routed because its signed movement list is invalid.
    #[error("invalid atomic settlement movements: {reason}")]
    InvalidAtomicSettlement {
        /// Bounded deterministic model validation error.
        reason: &'static str,
    },
    /// lane {lane_id} is not present in the lane catalog
    #[error("lane {lane_id} is not present in the lane catalog")]
    UnknownLane {
        /// Lane selected by the routing policy.
        lane_id: LaneId,
    },
    /// dataspace {dataspace_id} is not present in the dataspace catalog
    #[error("dataspace {dataspace_id} is not present in the dataspace catalog")]
    UnknownDataspace {
        /// Dataspace selected by the routing policy.
        dataspace_id: DataSpaceId,
    },
    /// lane {lane_id} is bound to dataspace {lane_dataspace_id}, but resolved dataspace is {dataspace_id}
    #[error(
        "lane {lane_id} is bound to dataspace {lane_dataspace_id}, but resolved dataspace is {dataspace_id}"
    )]
    LaneDataspaceMismatch {
        /// Lane selected by the routing policy.
        lane_id: LaneId,
        /// Dataspace configured for the resolved lane.
        lane_dataspace_id: DataSpaceId,
        /// Dataspace selected by the routing policy.
        dataspace_id: DataSpaceId,
    },
    /// lane {lane_id} is not active for dataspace {dataspace_id} at the current block height
    #[error(
        "lane {lane_id} is not active for dataspace {dataspace_id} at the current block height"
    )]
    InactiveLane {
        /// Lane selected by the routing policy.
        lane_id: LaneId,
        /// Dataspace selected by the routing policy.
        dataspace_id: DataSpaceId,
    },
    /// no lane is bound to dataspace {dataspace_id}
    #[error("no lane is bound to dataspace {dataspace_id}")]
    NoLaneForDataspace {
        /// Dataspace selected by the routing policy.
        dataspace_id: DataSpaceId,
    },
    /// routing rule lane {lane_id} uses reserved autoscale metadata and cannot be an explicit rule target
    #[error(
        "routing rule lane {lane_id} uses reserved autoscale metadata and cannot be an explicit rule target"
    )]
    AutoscaleOwnedRuleLane {
        /// Lane selected by the matched routing rule.
        lane_id: LaneId,
    },
    /// default lane {lane_id} uses reserved autoscale metadata and cannot be the default route anchor
    #[error(
        "default lane {lane_id} uses reserved autoscale metadata and cannot be the default route anchor"
    )]
    AutoscaleOwnedDefaultLane {
        /// Lane selected by the default routing policy.
        lane_id: LaneId,
    },
    /// transaction mixes dataspace-scoped permission targets {first_dataspace_id} and {second_dataspace_id}
    #[error(
        "transaction mixes dataspace-scoped permission targets {first_dataspace_id} and {second_dataspace_id}"
    )]
    ConflictingDataspaceScopedPermissions {
        /// First dataspace target found in the transaction.
        first_dataspace_id: DataSpaceId,
        /// Conflicting dataspace target found in the transaction.
        second_dataspace_id: DataSpaceId,
    },
    /// transaction mixes dataspace-routed write targets {first_dataspace_id} and {second_dataspace_id}
    #[error(
        "transaction mixes dataspace-routed write targets {first_dataspace_id} and {second_dataspace_id}"
    )]
    ConflictingTransactionDataspaceTargets {
        /// First dataspace-routed write target found in the transaction.
        first_dataspace_id: DataSpaceId,
        /// Conflicting dataspace-routed write target found in the transaction.
        second_dataspace_id: DataSpaceId,
    },
    /// dataspace alias `{alias}` could not be resolved against authoritative SNS state: {reason}
    #[error(
        "dataspace alias `{alias}` could not be resolved against authoritative SNS state: {reason}"
    )]
    DataspaceAliasResolution {
        /// Canonical dataspace alias supplied by the routed transaction.
        alias: String,
        /// Deterministic SNS resolution failure.
        reason: String,
    },
    /// FX corridor routing requires a world snapshot containing governed policy state.
    #[error("FX corridor policy `{policy_id}` cannot be routed without governed policy state")]
    FxCorridorPolicyStateUnavailable {
        /// Policy selected by the settlement instruction.
        policy_id: Name,
    },
    /// The protected FX corridor policy registry has not been initialized.
    #[error("the protected FX corridor policy registry is missing")]
    FxCorridorPolicyRegistryMissing,
    /// The protected FX corridor policy registry payload is malformed.
    #[error("the protected FX corridor policy registry is malformed")]
    FxCorridorPolicyRegistryMalformed,
    /// The selected FX corridor policy does not exist.
    #[error("FX corridor policy `{policy_id}` was not found")]
    FxCorridorPolicyNotFound {
        /// Policy selected by the settlement instruction.
        policy_id: Name,
    },
    /// A retained native proposal does not reproduce its exact approved account and body.
    #[error(
        "invalid persisted multisig proposal `{instructions_hash}` for account `{account}`: {reason}"
    )]
    InvalidMultisigProposal {
        /// Canonical account used to look up the row.
        account: AccountId,
        /// Signed instruction-list digest used to look up the row.
        instructions_hash: HashOf<Vec<InstructionBox>>,
        /// Completed binding or decoding error.
        reason: String,
    },
    /// A persisted multisig proposal graph recursively approves the same proposal.
    #[error(
        "persisted multisig proposal `{instructions_hash}` for account `{account}` contains an approval cycle"
    )]
    MultisigProposalCycle {
        /// Multisig account that owns the cyclic proposal.
        account: AccountId,
        /// Instruction-list digest used to address the cyclic proposal.
        instructions_hash: HashOf<Vec<InstructionBox>>,
    },
    /// provided routing plan does not match the current Nexus routing policy
    #[error("provided routing plan does not match the current Nexus routing policy")]
    StaleRoutingPlan,
    /// An authenticated Ordinary input has no currently executable single route.
    #[error("Ordinary input has no current executable single route: {reason}")]
    OrdinaryRouteUnavailable {
        /// Current committed-policy routing refusal.
        reason: String,
    },
}
impl RoutingResolveError {
    /// Stable telemetry label for deterministic routing failures.
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::Deferred(_) => "routing_deferred",
            Self::UnauthenticatedRootScope => "unauthenticated_root_scope",
            Self::InvalidAtomicSettlement { .. } => "invalid_atomic_settlement",
            Self::UnknownLane { .. } => "unknown_lane",
            Self::UnknownDataspace { .. } => "unknown_dataspace",
            Self::LaneDataspaceMismatch { .. } => "lane_dataspace_mismatch",
            Self::InactiveLane { .. } => "inactive_lane",
            Self::NoLaneForDataspace { .. } => "no_lane_for_dataspace",
            Self::AutoscaleOwnedRuleLane { .. } => "autoscale_owned_rule_lane",
            Self::AutoscaleOwnedDefaultLane { .. } => "autoscale_owned_default_lane",
            Self::ConflictingDataspaceScopedPermissions { .. } => {
                "conflicting_dataspace_scoped_permissions"
            }
            Self::ConflictingTransactionDataspaceTargets { .. } => {
                "conflicting_transaction_dataspace_targets"
            }
            Self::DataspaceAliasResolution { .. } => "dataspace_alias_resolution",
            Self::FxCorridorPolicyStateUnavailable { .. } => "fx_corridor_policy_state_unavailable",
            Self::FxCorridorPolicyRegistryMissing => "fx_corridor_policy_registry_missing",
            Self::FxCorridorPolicyRegistryMalformed => "fx_corridor_policy_registry_malformed",
            Self::FxCorridorPolicyNotFound { .. } => "fx_corridor_policy_not_found",
            Self::InvalidMultisigProposal { .. } => "invalid_multisig_proposal",
            Self::MultisigProposalCycle { .. } => "multisig_proposal_cycle",
            Self::StaleRoutingPlan => "stale_routing_plan",
            Self::OrdinaryRouteUnavailable { .. } => "ordinary_route_unavailable",
        }
    }
}
/// Evaluate the routing policy and resolve it against the configured catalogs.
pub fn evaluate_policy_with_catalog(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
) -> Result<RoutingDecision, RoutingResolveError> {
    evaluate_policy_plan_with_catalog(policy, lane_catalog, dataspace_catalog, tx)
        .map(|plan| plan.coordinator_route())
}
/// Evaluate the routing policy and resolve the full routing plan against the configured catalogs.
pub fn evaluate_policy_plan_with_catalog(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
) -> Result<RoutingPlan, RoutingResolveError> {
    let matched_rule = first_matching_rule(&policy.rules, |rule| rule_matches(rule, tx, None))?;
    if transaction_contains_fx_corridor_settlement(tx)?
        && let Some(decision) =
            settlement_routing_decision(tx, lane_catalog, dataspace_catalog, None)?
    {
        return Ok(RoutingPlan::single(decision));
    }
    if let Some(plan) = dataspace_scoped_permission_routing_plan(
        tx,
        matched_rule,
        lane_catalog,
        dataspace_catalog,
        None,
    )? {
        return Ok(plan);
    }
    if let Some(decision) = settlement_routing_decision(tx, lane_catalog, dataspace_catalog, None)?
    {
        let target = transaction_dataspace_routing_target_info(tx, Some(dataspace_catalog), None)?;
        if target.participants.is_empty()
            || (target.participants.len() == 1 && !target.coordinator_route)
        {
            return Ok(RoutingPlan::single(decision));
        }
    }
    if let Some(account_id) = account_permission_holder_routing_target(tx) {
        return resolve_query_routing_decision(
            policy,
            lane_catalog,
            dataspace_catalog,
            account_id,
            None,
        )
        .map(RoutingPlan::single);
    }
    let target = transaction_dataspace_routing_target_info(tx, Some(dataspace_catalog), None)?;
    resolve_policy_routing_plan(
        policy,
        matched_rule,
        target,
        lane_catalog,
        dataspace_catalog,
        Some(tx),
        None,
    )
}
/// Evaluate the routing policy against catalogs, resolving opaque dataspace-scoped
/// permissions from the current world snapshot when possible.
pub fn evaluate_policy_with_catalog_and_world<W: WorldReadOnly>(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
    world: &W,
) -> Result<RoutingDecision, RoutingResolveError> {
    evaluate_policy_with_catalog_and_world_at_opt(
        policy,
        lane_catalog,
        dataspace_catalog,
        tx,
        world,
        None,
    )
}
/// Evaluate the routing policy against catalogs and the current world at a deterministic ledger time.
pub fn evaluate_policy_with_catalog_and_world_at<W: WorldReadOnly>(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
    world: &W,
    ledger_time_ms: u64,
) -> Result<RoutingDecision, RoutingResolveError> {
    evaluate_policy_with_catalog_and_world_at_opt(
        policy,
        lane_catalog,
        dataspace_catalog,
        tx,
        world,
        Some(ledger_time_ms),
    )
}
fn evaluate_policy_with_catalog_and_world_at_opt<W: WorldReadOnly>(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<RoutingDecision, RoutingResolveError> {
    evaluate_policy_plan_with_catalog_and_world_at_opt(
        policy,
        lane_catalog,
        dataspace_catalog,
        tx,
        world,
        ledger_time_ms,
        None,
    )
    .map(|plan| plan.coordinator_route())
}
/// Evaluate the routing policy and resolve the full routing plan against catalogs/world state.
pub fn evaluate_policy_plan_with_catalog_and_world<W: WorldReadOnly>(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
    world: &W,
) -> Result<RoutingPlan, RoutingResolveError> {
    evaluate_policy_plan_with_catalog_and_world_at_opt(
        policy,
        lane_catalog,
        dataspace_catalog,
        tx,
        world,
        None,
        None,
    )
}
/// Evaluate the routing policy and resolve the full plan at a deterministic ledger time.
pub fn evaluate_policy_plan_with_catalog_and_world_at<W: WorldReadOnly>(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
    world: &W,
    ledger_time_ms: u64,
) -> Result<RoutingPlan, RoutingResolveError> {
    evaluate_policy_plan_with_catalog_and_world_at_opt(
        policy,
        lane_catalog,
        dataspace_catalog,
        tx,
        world,
        Some(ledger_time_ms),
        None,
    )
}
/// Evaluate the active Nexus routing policy and resolve the full plan at a deterministic ledger
/// time.
///
/// Autoscale elastic default-route sharding requires a candidate block height; this heightless
/// helper therefore fails closed to non-elastic/default routing for no-target default traffic.
pub fn evaluate_policy_plan_with_nexus_and_world_at<W: WorldReadOnly>(
    nexus: &Nexus,
    tx: &dyn TransactionRoutingView,
    world: &W,
    ledger_time_ms: u64,
) -> Result<RoutingPlan, RoutingResolveError> {
    evaluate_policy_plan_with_catalog_and_world_at_opt(
        &nexus.routing_policy,
        &nexus.lane_catalog,
        &nexus.dataspace_catalog,
        tx,
        world,
        Some(ledger_time_ms),
        None,
    )
}
/// Evaluate the active Nexus routing policy and resolve the full plan at a deterministic ledger
/// time and block height.
pub fn evaluate_policy_plan_with_nexus_and_world_at_block_height<W: WorldReadOnly>(
    nexus: &Nexus,
    tx: &dyn TransactionRoutingView,
    world: &W,
    ledger_time_ms: u64,
    block_height: u64,
) -> Result<RoutingPlan, RoutingResolveError> {
    evaluate_policy_plan_with_catalog_and_world_at_opt(
        &nexus.routing_policy,
        &nexus.lane_catalog,
        &nexus.dataspace_catalog,
        tx,
        world,
        Some(ledger_time_ms),
        Some(AutoscaleElasticRange::from_nexus_at_height(
            nexus,
            block_height,
        )),
    )
}
fn evaluate_policy_plan_with_catalog_and_world_at_opt<W: WorldReadOnly>(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
    world: &W,
    ledger_time_ms: Option<u64>,
    autoscale_range: Option<AutoscaleElasticRange>,
) -> Result<RoutingPlan, RoutingResolveError> {
    let matched_rule = first_matching_rule(&policy.rules, |rule| {
        rule_matches_with_world(rule, tx, dataspace_catalog, world, ledger_time_ms)
    })?;
    if let Some(plan) = native_amx_fx_routing_plan_with_world(
        tx,
        matched_rule,
        lane_catalog,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )? {
        return Ok(plan);
    }
    if let Some(plan) = dataspace_scoped_permission_routing_plan_with_world(
        tx,
        matched_rule,
        lane_catalog,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )? {
        return Ok(plan);
    }
    if let Some(account_id) = account_permission_holder_routing_target(tx) {
        return resolve_query_routing_decision_with_world(
            policy,
            lane_catalog,
            dataspace_catalog,
            account_id,
            world,
            ledger_time_ms,
            autoscale_range,
        )
        .map(RoutingPlan::single);
    }
    let mut target = transaction_dataspace_routing_target_info_with_world(
        tx,
        Some(dataspace_catalog),
        world,
        ledger_time_ms,
    )?;
    target = reconcile_native_amx_participants_with_world(
        target,
        tx,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )?;
    apply_authority_dataspace_target(
        &mut target,
        authority_dataspace_target_with_world(Some(world), tx, ledger_time_ms)?,
        matched_rule.is_some_and(|rule| rule.matcher.account.is_some()),
    );
    resolve_policy_routing_plan(
        policy,
        matched_rule,
        target,
        lane_catalog,
        dataspace_catalog,
        Some(tx),
        autoscale_range,
    )
}
fn dataspace_scoped_permission_routing_decision(
    tx: &dyn TransactionRoutingView,
    lane_catalog: Option<&LaneCatalog>,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<RoutingDecision>, RoutingResolveError> {
    let mut target_dataspace: Option<DataSpaceId> = None;
    let reject_cross_dataspace = amx_policy_rejects_cross_dataspace(tx);
    let Some(executable) = transaction_executable(tx) else {
        return Ok(None);
    };
    match executable {
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                merge_native_target_dataspace(
                    &mut target_dataspace,
                    instruction_dataspace_scoped_permission_target(
                        &**instruction,
                        dataspace_catalog,
                        state_view,
                    )?,
                    reject_cross_dataspace,
                    NativeDataspaceConflict::Permission,
                )?;
            }
        }
        Executable::ContractCall(call) => {
            merge_native_target_dataspace(
                &mut target_dataspace,
                contract_address_dataspace_target(&call.contract_address),
                reject_cross_dataspace,
                NativeDataspaceConflict::Transaction,
            )?;
        }
        Executable::Batch(items) => {
            // A mixed native/contract batch must be routed from the complete target set below.
            // Returning the contract target from this permission shortcut would discard ordinary
            // native targets and collapse a cross-dataspace batch onto the contract lane.
            if items
                .iter()
                .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)))
            {
                return Ok(None);
            }
            for item in items {
                let ExecutableBatchItem::Instruction(instruction) = item else {
                    unreachable!("contract-call batches return before the permission shortcut");
                };
                merge_native_target_dataspace(
                    &mut target_dataspace,
                    instruction_dataspace_scoped_permission_target(
                        &**instruction,
                        dataspace_catalog,
                        state_view,
                    )?,
                    reject_cross_dataspace,
                    NativeDataspaceConflict::Permission,
                )?;
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                merge_native_target_dataspace(
                    &mut target_dataspace,
                    instruction_dataspace_scoped_permission_target(
                        &**instruction,
                        dataspace_catalog,
                        state_view,
                    )?,
                    reject_cross_dataspace,
                    NativeDataspaceConflict::Permission,
                )?;
            }
        }
    }
    let Some(dataspace_id) = target_dataspace else {
        return Ok(None);
    };
    match (lane_catalog, dataspace_catalog) {
        (Some(lane_catalog), Some(dataspace_catalog)) => {
            canonical_dataspace_route(dataspace_id, lane_catalog, dataspace_catalog).map(Some)
        }
        _ => Ok(None),
    }
}
fn dataspace_scoped_permission_routing_decision_with_world<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    lane_catalog: Option<&LaneCatalog>,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<RoutingDecision>, RoutingResolveError> {
    let mut target_dataspace: Option<DataSpaceId> = None;
    let reject_cross_dataspace = amx_policy_rejects_cross_dataspace(tx);
    let Some(executable) = transaction_executable(tx) else {
        return Ok(None);
    };
    match executable {
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                merge_native_target_dataspace(
                    &mut target_dataspace,
                    instruction_dataspace_scoped_permission_target_with_world(
                        &**instruction,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )?,
                    reject_cross_dataspace,
                    NativeDataspaceConflict::Permission,
                )?;
            }
        }
        Executable::ContractCall(call) => {
            merge_native_target_dataspace(
                &mut target_dataspace,
                contract_address_dataspace_target(&call.contract_address),
                reject_cross_dataspace,
                NativeDataspaceConflict::Transaction,
            )?;
        }
        Executable::Batch(items) => {
            // A mixed native/contract batch must be routed from the complete target set below.
            // Returning the contract target from this permission shortcut would discard ordinary
            // native targets and collapse a cross-dataspace batch onto the contract lane.
            if items
                .iter()
                .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)))
            {
                return Ok(None);
            }
            for item in items {
                let ExecutableBatchItem::Instruction(instruction) = item else {
                    unreachable!("contract-call batches return before the permission shortcut");
                };
                merge_native_target_dataspace(
                    &mut target_dataspace,
                    instruction_dataspace_scoped_permission_target_with_world(
                        &**instruction,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )?,
                    reject_cross_dataspace,
                    NativeDataspaceConflict::Permission,
                )?;
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                merge_native_target_dataspace(
                    &mut target_dataspace,
                    instruction_dataspace_scoped_permission_target_with_world(
                        &**instruction,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )?,
                    reject_cross_dataspace,
                    NativeDataspaceConflict::Permission,
                )?;
            }
        }
    }
    let Some(dataspace_id) = target_dataspace else {
        return Ok(None);
    };
    match (lane_catalog, dataspace_catalog) {
        (Some(lane_catalog), Some(dataspace_catalog)) => {
            canonical_dataspace_route(dataspace_id, lane_catalog, dataspace_catalog).map(Some)
        }
        _ => Ok(None),
    }
}
fn scoped_permission_plan_from_target(
    decision: RoutingDecision,
    mut target: TransactionDataspaceTarget,
    matched_rule: Option<&LaneRoutingRule>,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: &dyn TransactionRoutingView,
) -> Result<RoutingPlan, RoutingResolveError> {
    add_smart_contract_deploy_policy_participant(&mut target, matched_rule);
    reject_cross_dataspace_plan(
        amx_policy_rejects_cross_dataspace(tx),
        target.coordinator_route,
        target.participants.iter().copied(),
    )?;
    if target.participants.is_empty()
        || (target.participants.len() == 1 && !target.coordinator_route)
    {
        return Ok(RoutingPlan::single(decision));
    }
    // Scoped permissions override account/instruction routing rules. Preserve
    // that route as the coordinator while retaining every concrete target as a
    // participant; selecting the smallest participant here would silently
    // change permission precedence when another, lower-id dataspace is present.
    let coordinator = if target.coordinator_route {
        canonical_dataspace_route(DataSpaceId::UNIVERSAL, lane_catalog, dataspace_catalog)?
    } else {
        decision
    };
    let participants = target
        .participants
        .into_iter()
        .map(|dataspace_id| {
            canonical_dataspace_route(dataspace_id, lane_catalog, dataspace_catalog)
                .map(|route| RouteLeg::new(route, RouteLegRole::Participant))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RoutingPlan::native_amx(coordinator, participants))
}
fn dataspace_scoped_permission_routing_plan(
    tx: &dyn TransactionRoutingView,
    matched_rule: Option<&LaneRoutingRule>,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<RoutingPlan>, RoutingResolveError> {
    let Some(decision) = dataspace_scoped_permission_routing_decision(
        tx,
        Some(lane_catalog),
        Some(dataspace_catalog),
        state_view,
    )?
    else {
        return Ok(None);
    };
    let mut target =
        transaction_dataspace_routing_target_info(tx, Some(dataspace_catalog), state_view)?;
    if let Some(state_view) = state_view {
        target = reconcile_native_amx_participants_with_world(
            target,
            tx,
            dataspace_catalog,
            state_view.world(),
            Some(state_view_ledger_time_ms(state_view)),
        )?;
    }
    scoped_permission_plan_from_target(
        decision,
        target,
        matched_rule,
        lane_catalog,
        dataspace_catalog,
        tx,
    )
    .map(Some)
}
fn dataspace_scoped_permission_routing_plan_with_world<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    matched_rule: Option<&LaneRoutingRule>,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<RoutingPlan>, RoutingResolveError> {
    let Some(decision) = dataspace_scoped_permission_routing_decision_with_world(
        tx,
        Some(lane_catalog),
        Some(dataspace_catalog),
        world,
        ledger_time_ms,
    )?
    else {
        return Ok(None);
    };
    let target = transaction_dataspace_routing_target_info_with_world(
        tx,
        Some(dataspace_catalog),
        world,
        ledger_time_ms,
    )?;
    let target = reconcile_native_amx_participants_with_world(
        target,
        tx,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )?;
    scoped_permission_plan_from_target(
        decision,
        target,
        matched_rule,
        lane_catalog,
        dataspace_catalog,
        tx,
    )
    .map(Some)
}
fn settlement_routing_decision(
    tx: &dyn TransactionRoutingView,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<RoutingDecision>, RoutingResolveError> {
    let Some(dataspace_id) =
        settlement_transaction_dataspace_target(tx, Some(dataspace_catalog), state_view)?
    else {
        return Ok(None);
    };
    canonical_dataspace_route(dataspace_id, lane_catalog, dataspace_catalog).map(Some)
}
fn native_amx_fx_routing_plan_with_world<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    matched_rule: Option<&LaneRoutingRule>,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<RoutingPlan>, RoutingResolveError> {
    if !transaction_contains_fx_corridor_settlement(tx)? {
        return Ok(None);
    }
    let coordinator_route =
        canonical_dataspace_route(DataSpaceId::UNIVERSAL, lane_catalog, dataspace_catalog)?;
    let mut participant_dataspaces = native_amx_participant_dataspaces_with_world_at(
        tx,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )?;
    if let Some(policy_dataspace) = smart_contract_deploy_policy_dataspace(matched_rule) {
        participant_dataspaces.push(policy_dataspace);
        participant_dataspaces.sort_unstable();
        participant_dataspaces.dedup();
    }
    reject_cross_dataspace_plan(
        amx_policy_rejects_cross_dataspace(tx),
        true,
        participant_dataspaces.iter().copied(),
    )?;
    let participants = participant_dataspaces
        .into_iter()
        .map(|dataspace_id| {
            canonical_dataspace_route(dataspace_id, lane_catalog, dataspace_catalog)
                .map(|route| RouteLeg::new(route, RouteLegRole::Participant))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(RoutingPlan::native_amx(
        coordinator_route,
        participants,
    )))
}
fn merge_settlement_target_dataspace(
    target_dataspace: &mut Option<DataSpaceId>,
    candidate: Option<DataSpaceId>,
) {
    let Some(candidate) = candidate else {
        return;
    };
    match *target_dataspace {
        Some(existing) if existing != candidate => {
            // Mixed settlement legs require a deterministic coordinator route instead of being
            // captured by the transaction authority's ordinary account rule.
            *target_dataspace = Some(DataSpaceId::UNIVERSAL);
        }
        Some(_) => {}
        None => *target_dataspace = Some(candidate),
    }
}
fn settlement_pair_dataspace_target(
    first: Option<DataSpaceId>,
    second: Option<DataSpaceId>,
) -> Option<DataSpaceId> {
    match (first, second) {
        (Some(first), Some(second)) if first == second => Some(first),
        (Some(_), Some(_)) => Some(DataSpaceId::UNIVERSAL),
        (Some(dataspace), None) | (None, Some(dataspace)) => Some(dataspace),
        (None, None) => None,
    }
}
fn fx_corridor_policy_with_world<W: WorldReadOnly>(
    world: &W,
    policy_id: &Name,
) -> Result<FxCorridorPolicy, RoutingResolveError> {
    let custom = world
        .parameters()
        .custom()
        .get(&FxCorridorPolicyRegistry::parameter_id())
        .ok_or(RoutingResolveError::FxCorridorPolicyRegistryMissing)?;
    FxCorridorPolicyRegistry::from_custom_parameter(custom)
        .map_err(|_| RoutingResolveError::FxCorridorPolicyRegistryMalformed)?
        .ok_or(RoutingResolveError::FxCorridorPolicyRegistryMalformed)?
        .get(policy_id)
        .cloned()
        .ok_or_else(|| RoutingResolveError::FxCorridorPolicyNotFound {
            policy_id: policy_id.clone(),
        })
}
type MultisigProposalRoutingKey = (AccountId, HashOf<Vec<InstructionBox>>);
#[derive(Default)]
struct MultisigProposalRoutingStack {
    active: BTreeSet<MultisigProposalRoutingKey>,
    #[cfg(test)]
    expansions: usize,
}
impl MultisigProposalRoutingStack {
    fn with_proposal<T>(
        &mut self,
        account: &AccountId,
        instructions_hash: &HashOf<Vec<InstructionBox>>,
        resolve: impl FnOnce(&mut Self) -> Result<T, RoutingResolveError>,
    ) -> Result<T, RoutingResolveError> {
        if !cfg!(all(test, sumeragi_core_mutation = "HC70"))
            && self.active.len()
                >= crate::smartcontracts::isi::multisig::MAX_MULTISIG_DEFERRED_EXECUTION_DEPTH
        {
            return Err(RoutingResolveError::OrdinaryRouteUnavailable {
                reason: "multisig proposal exceeds the deferred execution depth bound".into(),
            });
        }
        let key = (account.clone(), *instructions_hash);
        if !self.active.insert(key.clone()) {
            return Err(RoutingResolveError::MultisigProposalCycle {
                account: account.clone(),
                instructions_hash: *instructions_hash,
            });
        }
        #[cfg(test)]
        {
            self.expansions = self.expansions.saturating_add(1);
        }
        let result = resolve(self);
        self.active.remove(&key);
        result
    }
}
#[derive(Clone, Debug, Default)]
struct FxCorridorRoutingOverlay {
    policies: BTreeMap<Name, FxCorridorPolicy>,
    executed_multisig_proposals: BTreeMap<MultisigProposalRoutingKey, Vec<InstructionBox>>,
}
impl FxCorridorRoutingOverlay {
    fn observe(&mut self, instruction: &dyn Instruction) {
        let any = instruction.as_any();
        let policy = any
            .downcast_ref::<SetFxCorridorPolicy>()
            .map(|set| &set.policy)
            .or_else(|| {
                any.downcast_ref::<SettlementInstructionBox>()
                    .and_then(|settlement| match settlement {
                        SettlementInstructionBox::SetFxCorridorPolicy(set) => Some(&set.policy),
                        SettlementInstructionBox::Atomic(_)
                        | SettlementInstructionBox::Dvp(_)
                        | SettlementInstructionBox::Pvp(_)
                        | SettlementInstructionBox::FundFxCorridorEscrow(_)
                        | SettlementInstructionBox::RefundFxCorridorEscrow(_)
                        | SettlementInstructionBox::SettleFxCorridor(_) => None,
                    })
            });
        if let Some(policy) = policy {
            // A later update cannot change a corridor's immutable identity. Keep the first
            // transaction-local registration so an invalid replacement cannot reroute siblings.
            self.policies
                .entry(policy.policy_id.clone())
                .or_insert_with(|| policy.clone());
        }
    }
    fn policy_with_world<W: WorldReadOnly>(
        &self,
        world: &W,
        policy_id: &Name,
    ) -> Result<FxCorridorPolicy, RoutingResolveError> {
        match fx_corridor_policy_with_world(world, policy_id) {
            Ok(policy) => Ok(policy),
            Err(error @ RoutingResolveError::FxCorridorPolicyRegistryMissing)
            | Err(error @ RoutingResolveError::FxCorridorPolicyNotFound { .. }) => {
                self.policies.get(policy_id).cloned().ok_or(error)
            }
            Err(error) => Err(error),
        }
    }
    fn record_executed_multisig_proposal(
        &mut self,
        propose: MultisigPropose,
    ) -> Result<(), RoutingResolveError> {
        let MultisigPropose {
            account,
            instructions,
            ..
        } = propose;
        let instructions_hash = proposal_instructions_hash(&instructions)?;
        self.executed_multisig_proposals
            .entry((account, instructions_hash))
            .or_insert(instructions);
        Ok(())
    }
    fn multisig_proposal_instructions_with_world<W: WorldReadOnly>(
        &self,
        world: &W,
        account: &AccountId,
        instructions_hash: &HashOf<Vec<InstructionBox>>,
    ) -> Result<Option<Vec<InstructionBox>>, RoutingResolveError> {
        if let Some(instructions) = self
            .executed_multisig_proposals
            .get(&(account.clone(), *instructions_hash))
        {
            return Ok(Some(instructions.clone()));
        }
        Ok(
            multisig_proposal_state_raw(world, account, instructions_hash)?
                .map(|proposal| proposal.instructions),
        )
    }
}
fn fx_corridor_policy_with_state(
    state_view: Option<&StateView<'_>>,
    policy_id: &Name,
) -> Result<FxCorridorPolicy, RoutingResolveError> {
    let state_view =
        state_view.ok_or_else(|| RoutingResolveError::FxCorridorPolicyStateUnavailable {
            policy_id: policy_id.clone(),
        })?;
    fx_corridor_policy_with_world(state_view.world(), policy_id)
}
fn asset_id_explicit_dataspace_target(
    asset_id: &iroha_data_model::asset::AssetId,
) -> Option<DataSpaceId> {
    match asset_id.scope() {
        iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace) => Some(*dataspace),
        iroha_data_model::asset::AssetBalanceScope::Global => None,
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AssetBalanceDefinitionRouteTarget {
    dataspace_id: Option<DataSpaceId>,
    balance_scope_policy: Option<AssetBalancePolicy>,
    /// Home dataspace that confines every balance of the definition, from the shared home owner.
    confined_home: Option<DataSpaceId>,
}
fn merge_instruction_dataspace_targets<I>(targets: I) -> Option<DataSpaceId>
where
    I: IntoIterator<Item = Option<DataSpaceId>>,
{
    targets.into_iter().flatten().fold(None, |acc, target| {
        settlement_pair_dataspace_target(acc, Some(target))
    })
}
fn merge_instruction_dataspace_target_results<I>(
    targets: I,
) -> Result<Option<DataSpaceId>, RoutingResolveError>
where
    I: IntoIterator<Item = Result<Option<DataSpaceId>, RoutingResolveError>>,
{
    let mut merged = None;
    for target in targets {
        merged = settlement_pair_dataspace_target(merged, target?);
    }
    Ok(merged)
}
fn merge_instruction_dataspace_targets_with_world_and_fx_overlay<'instruction, W, I>(
    instructions: I,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &mut FxCorridorRoutingOverlay,
) -> Result<Option<DataSpaceId>, RoutingResolveError>
where
    W: WorldReadOnly,
    I: IntoIterator<Item = &'instruction InstructionBox>,
{
    let mut merged = None;
    for instruction in instructions {
        let target = instruction_transaction_dataspace_target_with_world_and_fx_overlay(
            &**instruction,
            dataspace_catalog,
            world,
            ledger_time_ms,
            fx_overlay,
        )?;
        merged = settlement_pair_dataspace_target(merged, target);
        observe_top_level_instruction_fx_effects(
            fx_overlay,
            &**instruction,
            usize::MAX,
            &[],
            world,
        )?;
    }
    Ok(merged)
}
fn trigger_executable_transaction_dataspace_target(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    match executable {
        Executable::ContractCall(call) => {
            Ok(contract_address_dataspace_target(&call.contract_address))
        }
        Executable::Instructions(instructions) => {
            merge_instruction_dataspace_target_results(instructions.iter().map(|instruction| {
                instruction_transaction_dataspace_target(
                    &**instruction,
                    dataspace_catalog,
                    state_view,
                )
            }))
        }
        Executable::Batch(items) => {
            merge_instruction_dataspace_target_results(items.iter().map(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => {
                    instruction_transaction_dataspace_target(
                        &**instruction,
                        dataspace_catalog,
                        state_view,
                    )
                }
                ExecutableBatchItem::ContractCall(call) => {
                    Ok(contract_address_dataspace_target(&call.contract_address))
                }
            }))
        }
        Executable::Ivm(_) => Ok(None),
        Executable::IvmProved(proved) => {
            merge_instruction_dataspace_target_results(proved.overlay.iter().map(|instruction| {
                instruction_transaction_dataspace_target(
                    &**instruction,
                    dataspace_catalog,
                    state_view,
                )
            }))
        }
    }
}
fn trigger_executable_transaction_dataspace_target_with_world_and_fx_overlay<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &mut FxCorridorRoutingOverlay,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    match executable {
        Executable::ContractCall(call) => {
            Ok(contract_address_dataspace_target(&call.contract_address))
        }
        Executable::Instructions(instructions) => {
            merge_instruction_dataspace_targets_with_world_and_fx_overlay(
                instructions.iter(),
                dataspace_catalog,
                world,
                ledger_time_ms,
                fx_overlay,
            )
        }
        Executable::Batch(items) => {
            let mut merged = None;
            for item in items {
                let target = match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        let target =
                            instruction_transaction_dataspace_target_with_world_and_fx_overlay(
                                &**instruction,
                                dataspace_catalog,
                                world,
                                ledger_time_ms,
                                fx_overlay,
                            )?;
                        observe_top_level_instruction_fx_effects(
                            fx_overlay,
                            &**instruction,
                            usize::MAX,
                            &[],
                            world,
                        )?;
                        target
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        contract_address_dataspace_target(&call.contract_address)
                    }
                };
                merged = settlement_pair_dataspace_target(merged, target);
            }
            Ok(merged)
        }
        Executable::Ivm(_) => Ok(None),
        Executable::IvmProved(proved) => {
            merge_instruction_dataspace_targets_with_world_and_fx_overlay(
                proved.overlay.iter(),
                dataspace_catalog,
                world,
                ledger_time_ms,
                fx_overlay,
            )
        }
    }
}
fn asset_balance_operation_concrete_dataspaces(
    asset_definition_target: AssetBalanceDefinitionRouteTarget,
    explicit_asset_target: Option<DataSpaceId>,
    account_targets: impl IntoIterator<Item = Option<DataSpaceId>>,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    if let Some(home) = asset_definition_target.confined_home
        && let Some(explicit) = explicit_asset_target
        && explicit != home
    {
        return Err(RoutingResolveError::OrdinaryRouteUnavailable {
            reason: format!(
                "asset definition is confined to home dataspace {}; balance scope {} is refused",
                home.as_u64(),
                explicit.as_u64()
            ),
        });
    }
    if asset_definition_target.balance_scope_policy == Some(AssetBalancePolicy::Global)
        || explicit_asset_target == Some(DataSpaceId::UNIVERSAL)
    {
        return Ok(BTreeSet::from([DataSpaceId::UNIVERSAL]));
    }
    let effective_definition_target = if explicit_asset_target.is_some()
        && asset_definition_target.dataspace_id == Some(DataSpaceId::UNIVERSAL)
        && asset_definition_target.balance_scope_policy != Some(AssetBalancePolicy::Global)
    {
        None
    } else {
        asset_definition_target.dataspace_id
    };
    let authoritative_asset_target =
        settlement_pair_dataspace_target(effective_definition_target, explicit_asset_target);
    let ignore_universal_account_fallbacks = asset_definition_target.balance_scope_policy
        == Some(AssetBalancePolicy::DataspaceRestricted)
        && authoritative_asset_target.is_some_and(|target| target != DataSpaceId::UNIVERSAL);
    let account_targets = account_targets.into_iter().map(|target| {
        if ignore_universal_account_fallbacks && target == Some(DataSpaceId::UNIVERSAL) {
            None
        } else {
            target
        }
    });
    Ok(core::iter::once(effective_definition_target)
        .chain(core::iter::once(explicit_asset_target))
        .chain(account_targets)
        .flatten()
        .collect())
}
fn asset_balance_operation_dataspace_target(
    asset_definition_target: AssetBalanceDefinitionRouteTarget,
    explicit_asset_target: Option<DataSpaceId>,
    account_targets: impl IntoIterator<Item = Option<DataSpaceId>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    Ok(merge_instruction_dataspace_targets(
        asset_balance_operation_concrete_dataspaces(
            asset_definition_target,
            explicit_asset_target,
            account_targets,
        )?
        .into_iter()
        .map(Some),
    ))
}

fn transfer_batch_targets(
    batch: &TransferAssetBatch,
    mut definition: impl FnMut(
        &AssetDefinitionId,
    ) -> Result<AssetBalanceDefinitionRouteTarget, RoutingResolveError>,
    mut account: impl FnMut(&AccountId) -> Result<Option<DataSpaceId>, ExecutionDeferred>,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    let mut targets = BTreeSet::new();
    for entry in batch.entries() {
        // Batch entries intentionally carry no AssetId scope. The committed definition
        // policy and the two account contexts own their balance bucket selection.
        targets.extend(asset_balance_operation_concrete_dataspaces(
            definition(entry.asset_definition())?,
            None,
            [account(entry.from())?, account(entry.to())?],
        )?);
    }
    Ok(targets)
}

fn transfer_batch_targets_with_view(
    batch: &TransferAssetBatch,
    catalog: Option<&DataSpaceCatalog>,
    view: Option<&StateView<'_>>,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    transfer_batch_targets(
        batch,
        |definition| asset_balance_definition_route_target(definition, catalog, view),
        |account| {
            account_dataspace_target(
                view.map(StateView::world),
                account,
                view.map(state_view_ledger_time_ms),
            )
        },
    )
}

fn transfer_batch_targets_with_world<W: WorldReadOnly>(
    batch: &TransferAssetBatch,
    catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    transfer_batch_targets(
        batch,
        |definition| {
            asset_balance_definition_route_target_with_world(
                definition,
                catalog,
                world,
                ledger_time_ms,
            )
        },
        |account| account_dataspace_target(Some(world), account, ledger_time_ms),
    )
}

fn asset_definition_requires_universal_coordinator(
    asset_definition_id: &AssetDefinitionId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, RoutingResolveError> {
    Ok(
        asset_balance_definition_route_target(asset_definition_id, dataspace_catalog, state_view)?
            .balance_scope_policy
            == Some(AssetBalancePolicy::Global),
    )
}
fn asset_definition_requires_universal_coordinator_with_world<W: WorldReadOnly>(
    asset_definition_id: &AssetDefinitionId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, RoutingResolveError> {
    Ok(asset_balance_definition_route_target_with_world(
        asset_definition_id,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )?
    .balance_scope_policy
        == Some(AssetBalancePolicy::Global))
}
fn executable_settlement_dataspace_target(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    executable_settlement_dataspace_target_with_stack(
        executable,
        dataspace_catalog,
        state_view,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn executable_settlement_dataspace_target_with_stack(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let mut target_dataspace = None;
    match executable {
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                merge_settlement_target_dataspace(
                    &mut target_dataspace,
                    instruction_settlement_dataspace_target_with_stack(
                        &**instruction,
                        dataspace_catalog,
                        state_view,
                        stack,
                    )?,
                );
            }
        }
        Executable::ContractCall(_) | Executable::Ivm(_) => {}
        Executable::Batch(items) => {
            for item in items {
                if let ExecutableBatchItem::Instruction(instruction) = item {
                    merge_settlement_target_dataspace(
                        &mut target_dataspace,
                        instruction_settlement_dataspace_target_with_stack(
                            &**instruction,
                            dataspace_catalog,
                            state_view,
                            stack,
                        )?,
                    );
                }
            }
        }
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                merge_settlement_target_dataspace(
                    &mut target_dataspace,
                    instruction_settlement_dataspace_target_with_stack(
                        &**instruction,
                        dataspace_catalog,
                        state_view,
                        stack,
                    )?,
                );
            }
        }
    }
    Ok(target_dataspace)
}
fn executable_settlement_dataspace_target_with_world<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &mut FxCorridorRoutingOverlay,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    executable_settlement_dataspace_target_with_world_and_stack(
        executable,
        dataspace_catalog,
        world,
        ledger_time_ms,
        fx_overlay,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn executable_settlement_dataspace_target_with_world_and_stack<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &mut FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let mut target_dataspace = None;
    let instruction_refs = executable_instruction_refs(executable);
    let same_transaction_multisig_proposals =
        same_transaction_multisig_proposal_targets_with_world(
            &instruction_refs,
            dataspace_catalog,
            world,
            ledger_time_ms,
            fx_overlay,
        )?;
    match executable {
        Executable::Instructions(instructions) => {
            for (top_level_instruction_index, instruction) in instructions.iter().enumerate() {
                merge_settlement_target_dataspace(
                    &mut target_dataspace,
                    instruction_settlement_dataspace_target_with_world_and_stack(
                        &**instruction,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                        fx_overlay,
                        stack,
                    )?,
                );
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    world,
                )?;
            }
        }
        Executable::ContractCall(_) | Executable::Ivm(_) => {}
        Executable::Batch(items) => {
            let mut top_level_instruction_index = 0;
            for item in items {
                if let ExecutableBatchItem::Instruction(instruction) = item {
                    merge_settlement_target_dataspace(
                        &mut target_dataspace,
                        instruction_settlement_dataspace_target_with_world_and_stack(
                            &**instruction,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                            fx_overlay,
                            stack,
                        )?,
                    );
                    observe_top_level_instruction_fx_effects(
                        fx_overlay,
                        &**instruction,
                        top_level_instruction_index,
                        &same_transaction_multisig_proposals,
                        world,
                    )?;
                    top_level_instruction_index += 1;
                }
            }
        }
        Executable::IvmProved(proved) => {
            for (top_level_instruction_index, instruction) in proved.overlay.iter().enumerate() {
                merge_settlement_target_dataspace(
                    &mut target_dataspace,
                    instruction_settlement_dataspace_target_with_world_and_stack(
                        &**instruction,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                        fx_overlay,
                        stack,
                    )?,
                );
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    world,
                )?;
            }
        }
    }
    Ok(target_dataspace)
}
fn settlement_transaction_dataspace_target(
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let Some(executable) = transaction_executable(tx) else {
        return Ok(None);
    };
    executable_settlement_dataspace_target(executable, dataspace_catalog, state_view)
}
fn settlement_transaction_dataspace_target_with_world<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let Some(executable) = transaction_executable(tx) else {
        return Ok(None);
    };
    let mut fx_overlay = FxCorridorRoutingOverlay::default();
    executable_settlement_dataspace_target_with_world(
        executable,
        dataspace_catalog,
        world,
        ledger_time_ms,
        &mut fx_overlay,
    )
}
fn instruction_settlement_dataspace_target(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    instruction_settlement_dataspace_target_with_stack(
        instruction,
        dataspace_catalog,
        state_view,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn instruction_list_settlement_dataspace_target_with_stack(
    instructions: &[InstructionBox],
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let mut target_dataspace = None;
    for nested in instructions {
        merge_settlement_target_dataspace(
            &mut target_dataspace,
            instruction_settlement_dataspace_target_with_stack(
                &**nested,
                dataspace_catalog,
                state_view,
                stack,
            )?,
        );
    }
    Ok(target_dataspace)
}
fn instruction_settlement_dataspace_target_with_stack(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(atomic) = settlement_atomic::instruction(instruction) {
        return settlement_atomic::target(atomic);
    }

    if let Some(multisig) = multisig_instruction(instruction)? {
        return match multisig {
            MultisigInstructionBox::Propose(propose) => {
                instruction_list_settlement_dataspace_target_with_stack(
                    &propose.instructions,
                    dataspace_catalog,
                    state_view,
                    stack,
                )
            }
            MultisigInstructionBox::Approve(approve) => {
                let Some(view) = state_view else {
                    return Ok(None);
                };
                Ok(with_multisig_proposal_state(
                    view.world(),
                    &approve.account,
                    &approve.instructions_hash,
                    stack,
                    |proposal, stack| {
                        instruction_list_settlement_dataspace_target_with_stack(
                            &proposal.instructions,
                            dataspace_catalog,
                            state_view,
                            stack,
                        )
                    },
                )?
                .flatten())
            }
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => Ok(None),
        };
    }
    if let Some(RegisterBox::Trigger(register)) = any.downcast_ref::<RegisterBox>() {
        return executable_settlement_dataspace_target_with_stack(
            register.object.action().executable(),
            dataspace_catalog,
            state_view,
            stack,
        );
    }
    if let Some(activation) = any.downcast_ref::<ActivatePrivateSettlementPoolV1>() {
        return Ok(Some(activation.route.dataspace_id));
    }
    if any
        .downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
        .is_some()
        || any
            .downcast_ref::<AbortAtomicPrivateSettlementV1>()
            .is_some()
        || any
            .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
            .is_some()
    {
        return Ok(Some(DataSpaceId::UNIVERSAL));
    }
    if let Some(dvp) = any.downcast_ref::<DvpIsi>() {
        return Ok(settlement_pair_dataspace_target(
            asset_balance_definition_dataspace_target(
                dvp.delivery_leg().asset_definition_id(),
                dataspace_catalog,
                state_view,
            )?,
            asset_balance_definition_dataspace_target(
                dvp.payment_leg().asset_definition_id(),
                dataspace_catalog,
                state_view,
            )?,
        ));
    }
    if let Some(pvp) = any.downcast_ref::<PvpIsi>() {
        return Ok(settlement_pair_dataspace_target(
            asset_balance_definition_dataspace_target(
                pvp.primary_leg().asset_definition_id(),
                dataspace_catalog,
                state_view,
            )?,
            asset_balance_definition_dataspace_target(
                pvp.counter_leg().asset_definition_id(),
                dataspace_catalog,
                state_view,
            )?,
        ));
    }
    if any.downcast_ref::<SetFxCorridorPolicy>().is_some() {
        return Ok(Some(DataSpaceId::UNIVERSAL));
    }
    if let Some(fx) = any.downcast_ref::<SettleFxCorridor>() {
        let policy = fx_corridor_policy_with_state(state_view, &fx.policy_id)?;
        return Ok(settlement_pair_dataspace_target(
            Some(policy.source_dataspace),
            Some(policy.destination_dataspace),
        ));
    }
    if let Some(fx) = any.downcast_ref::<FundFxCorridorEscrow>() {
        return Ok(Some(
            fx_corridor_policy_with_state(state_view, &fx.policy_id)?.destination_dataspace,
        ));
    }
    if let Some(fx) = any.downcast_ref::<RefundFxCorridorEscrow>() {
        return Ok(Some(
            fx_corridor_policy_with_state(state_view, &fx.policy_id)?.destination_dataspace,
        ));
    }
    if let Some(settlement) = any.downcast_ref::<SettlementInstructionBox>() {
        return Ok(match settlement {
            SettlementInstructionBox::Atomic(atomic) => settlement_atomic::target(atomic)?,
            SettlementInstructionBox::Dvp(dvp) => settlement_pair_dataspace_target(
                asset_balance_definition_dataspace_target(
                    dvp.delivery_leg().asset_definition_id(),
                    dataspace_catalog,
                    state_view,
                )?,
                asset_balance_definition_dataspace_target(
                    dvp.payment_leg().asset_definition_id(),
                    dataspace_catalog,
                    state_view,
                )?,
            ),
            SettlementInstructionBox::Pvp(pvp) => settlement_pair_dataspace_target(
                asset_balance_definition_dataspace_target(
                    pvp.primary_leg().asset_definition_id(),
                    dataspace_catalog,
                    state_view,
                )?,
                asset_balance_definition_dataspace_target(
                    pvp.counter_leg().asset_definition_id(),
                    dataspace_catalog,
                    state_view,
                )?,
            ),
            SettlementInstructionBox::SetFxCorridorPolicy(_) => Some(DataSpaceId::UNIVERSAL),
            SettlementInstructionBox::FundFxCorridorEscrow(fx) => Some(
                fx_corridor_policy_with_state(state_view, &fx.policy_id)?.destination_dataspace,
            ),
            SettlementInstructionBox::RefundFxCorridorEscrow(fx) => Some(
                fx_corridor_policy_with_state(state_view, &fx.policy_id)?.destination_dataspace,
            ),
            SettlementInstructionBox::SettleFxCorridor(fx) => {
                let policy = fx_corridor_policy_with_state(state_view, &fx.policy_id)?;
                settlement_pair_dataspace_target(
                    Some(policy.source_dataspace),
                    Some(policy.destination_dataspace),
                )
            }
        });
    }
    Ok(None)
}
fn instruction_settlement_dataspace_target_with_world<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    instruction_settlement_dataspace_target_with_world_and_stack(
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        fx_overlay,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn instruction_list_settlement_dataspace_target_with_world_and_stack<W: WorldReadOnly>(
    instructions: &[InstructionBox],
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let mut target_dataspace = None;
    let mut nested_fx_overlay = fx_overlay.clone();
    for nested in instructions {
        merge_settlement_target_dataspace(
            &mut target_dataspace,
            instruction_settlement_dataspace_target_with_world_and_stack(
                &**nested,
                dataspace_catalog,
                world,
                ledger_time_ms,
                &nested_fx_overlay,
                stack,
            )?,
        );
        observe_top_level_instruction_fx_effects(
            &mut nested_fx_overlay,
            &**nested,
            usize::MAX,
            &[],
            world,
        )?;
    }
    Ok(target_dataspace)
}
fn instruction_settlement_dataspace_target_with_world_and_stack<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(atomic) = settlement_atomic::instruction(instruction) {
        return settlement_atomic::target(atomic);
    }

    if let Some(multisig) = multisig_instruction(instruction)? {
        return match multisig {
            MultisigInstructionBox::Propose(propose) => {
                instruction_list_settlement_dataspace_target_with_world_and_stack(
                    &propose.instructions,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    fx_overlay,
                    stack,
                )
            }
            MultisigInstructionBox::Approve(approve) => Ok(with_multisig_proposal_instructions(
                fx_overlay,
                world,
                &approve.account,
                &approve.instructions_hash,
                stack,
                |instructions, stack| {
                    instruction_list_settlement_dataspace_target_with_world_and_stack(
                        instructions,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                        fx_overlay,
                        stack,
                    )
                },
            )?
            .flatten()),
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => Ok(None),
        };
    }
    if let Some(RegisterBox::Trigger(register)) = any.downcast_ref::<RegisterBox>() {
        let mut nested_fx_overlay = fx_overlay.clone();
        return executable_settlement_dataspace_target_with_world_and_stack(
            register.object.action().executable(),
            dataspace_catalog,
            world,
            ledger_time_ms,
            &mut nested_fx_overlay,
            stack,
        );
    }
    if let Some(activation) = any.downcast_ref::<ActivatePrivateSettlementPoolV1>() {
        return Ok(Some(activation.route.dataspace_id));
    }
    if any
        .downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
        .is_some()
        || any
            .downcast_ref::<AbortAtomicPrivateSettlementV1>()
            .is_some()
        || any
            .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
            .is_some()
    {
        return Ok(Some(DataSpaceId::UNIVERSAL));
    }
    if let Some(dvp) = any.downcast_ref::<DvpIsi>() {
        return Ok(settlement_pair_dataspace_target(
            asset_balance_definition_dataspace_target_with_world(
                dvp.delivery_leg().asset_definition_id(),
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?,
            asset_balance_definition_dataspace_target_with_world(
                dvp.payment_leg().asset_definition_id(),
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?,
        ));
    }
    if let Some(pvp) = any.downcast_ref::<PvpIsi>() {
        return Ok(settlement_pair_dataspace_target(
            asset_balance_definition_dataspace_target_with_world(
                pvp.primary_leg().asset_definition_id(),
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?,
            asset_balance_definition_dataspace_target_with_world(
                pvp.counter_leg().asset_definition_id(),
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?,
        ));
    }
    if any.downcast_ref::<SetFxCorridorPolicy>().is_some() {
        return Ok(Some(DataSpaceId::UNIVERSAL));
    }
    if let Some(fx) = any.downcast_ref::<SettleFxCorridor>() {
        let policy = fx_overlay.policy_with_world(world, &fx.policy_id)?;
        return Ok(settlement_pair_dataspace_target(
            Some(policy.source_dataspace),
            Some(policy.destination_dataspace),
        ));
    }
    if let Some(fx) = any.downcast_ref::<FundFxCorridorEscrow>() {
        return Ok(Some(
            fx_overlay
                .policy_with_world(world, &fx.policy_id)?
                .destination_dataspace,
        ));
    }
    if let Some(fx) = any.downcast_ref::<RefundFxCorridorEscrow>() {
        return Ok(Some(
            fx_overlay
                .policy_with_world(world, &fx.policy_id)?
                .destination_dataspace,
        ));
    }
    if let Some(settlement) = any.downcast_ref::<SettlementInstructionBox>() {
        return Ok(match settlement {
            SettlementInstructionBox::Atomic(atomic) => settlement_atomic::target(atomic)?,
            SettlementInstructionBox::Dvp(dvp) => settlement_pair_dataspace_target(
                asset_balance_definition_dataspace_target_with_world(
                    dvp.delivery_leg().asset_definition_id(),
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )?,
                asset_balance_definition_dataspace_target_with_world(
                    dvp.payment_leg().asset_definition_id(),
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )?,
            ),
            SettlementInstructionBox::Pvp(pvp) => settlement_pair_dataspace_target(
                asset_balance_definition_dataspace_target_with_world(
                    pvp.primary_leg().asset_definition_id(),
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )?,
                asset_balance_definition_dataspace_target_with_world(
                    pvp.counter_leg().asset_definition_id(),
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )?,
            ),
            SettlementInstructionBox::SetFxCorridorPolicy(_) => Some(DataSpaceId::UNIVERSAL),
            SettlementInstructionBox::FundFxCorridorEscrow(fx) => Some(
                fx_overlay
                    .policy_with_world(world, &fx.policy_id)?
                    .destination_dataspace,
            ),
            SettlementInstructionBox::RefundFxCorridorEscrow(fx) => Some(
                fx_overlay
                    .policy_with_world(world, &fx.policy_id)?
                    .destination_dataspace,
            ),
            SettlementInstructionBox::SettleFxCorridor(fx) => {
                let policy = fx_overlay.policy_with_world(world, &fx.policy_id)?;
                settlement_pair_dataspace_target(
                    Some(policy.source_dataspace),
                    Some(policy.destination_dataspace),
                )
            }
        });
    }
    Ok(None)
}
fn executable_contains_fx_corridor_settlement(
    executable: &Executable,
) -> Result<bool, RoutingResolveError> {
    match executable {
        Executable::Instructions(instructions) => {
            instructions.iter().try_fold(false, |found, instruction| {
                Ok(found || instruction_contains_fx_corridor_settlement(&**instruction)?)
            })
        }
        Executable::IvmProved(proved) => {
            proved.overlay.iter().try_fold(false, |found, instruction| {
                Ok(found || instruction_contains_fx_corridor_settlement(&**instruction)?)
            })
        }
        Executable::Batch(items) => items.iter().try_fold(false, |found, item| {
            Ok(found
                || match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        instruction_contains_fx_corridor_settlement(&**instruction)?
                    }
                    ExecutableBatchItem::ContractCall(_) => false,
                })
        }),
        Executable::ContractCall(_) | Executable::Ivm(_) => Ok(false),
    }
}
fn instruction_contains_fx_corridor_settlement(
    instruction: &dyn Instruction,
) -> Result<bool, RoutingResolveError> {
    let any = instruction.as_any();
    if any.downcast_ref::<SettleFxCorridor>().is_some()
        || matches!(
            any.downcast_ref::<SettlementInstructionBox>(),
            Some(SettlementInstructionBox::SettleFxCorridor(_))
        )
    {
        return Ok(true);
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        return match multisig {
            MultisigInstructionBox::Propose(propose) => propose
                .instructions
                .iter()
                .try_fold(false, |found, nested| {
                    Ok(found || instruction_contains_fx_corridor_settlement(&**nested)?)
                }),
            MultisigInstructionBox::Approve(_)
            | MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => Ok(false),
        };
    }
    if let Some(RegisterBox::Trigger(register)) = any.downcast_ref::<RegisterBox>() {
        return executable_contains_fx_corridor_settlement(register.object.action().executable());
    }
    Ok(false)
}
fn transaction_contains_fx_corridor_settlement(
    tx: &dyn TransactionRoutingView,
) -> Result<bool, RoutingResolveError> {
    transaction_executable(tx).map_or(Ok(false), executable_contains_fx_corridor_settlement)
}
fn transaction_executable(tx: &dyn TransactionRoutingView) -> Option<&Executable> {
    tx.executable()
}
fn amx_policy_rejects_cross_dataspace(tx: &dyn TransactionRoutingView) -> bool {
    tx.metadata()
        .and_then(|metadata| metadata.get(AMX_POLICY_METADATA_KEY))
        .and_then(|raw| raw.try_into_any_norito::<String>().ok())
        .is_some_and(|policy| {
            policy
                .trim()
                .eq_ignore_ascii_case(AMX_POLICY_REJECT_CROSS_DATASPACE)
        })
}
#[derive(Clone, Copy)]
enum NativeDataspaceConflict {
    Permission,
    Transaction,
}
fn native_dataspace_conflict_error(
    kind: NativeDataspaceConflict,
    first_dataspace_id: DataSpaceId,
    second_dataspace_id: DataSpaceId,
) -> RoutingResolveError {
    match kind {
        NativeDataspaceConflict::Permission => {
            RoutingResolveError::ConflictingDataspaceScopedPermissions {
                first_dataspace_id,
                second_dataspace_id,
            }
        }
        NativeDataspaceConflict::Transaction => {
            RoutingResolveError::ConflictingTransactionDataspaceTargets {
                first_dataspace_id,
                second_dataspace_id,
            }
        }
    }
}
fn reject_cross_dataspace_plan<I>(
    reject_cross_dataspace: bool,
    universal_coordinator: bool,
    participants: I,
) -> Result<(), RoutingResolveError>
where
    I: IntoIterator<Item = DataSpaceId>,
{
    if !reject_cross_dataspace {
        return Ok(());
    }
    let mut participants = participants.into_iter();
    let Some(first_dataspace_id) = participants.next() else {
        return Ok(());
    };
    let (first_dataspace_id, second_dataspace_id) =
        if let Some(second_dataspace_id) = participants.next() {
            (first_dataspace_id, second_dataspace_id)
        } else if universal_coordinator {
            (DataSpaceId::UNIVERSAL, first_dataspace_id)
        } else {
            return Ok(());
        };
    Err(native_dataspace_conflict_error(
        NativeDataspaceConflict::Transaction,
        first_dataspace_id,
        second_dataspace_id,
    ))
}
fn merge_native_target_dataspace(
    target_dataspace: &mut Option<DataSpaceId>,
    candidate: Option<DataSpaceId>,
    reject_cross_dataspace: bool,
    conflict_kind: NativeDataspaceConflict,
) -> Result<(), RoutingResolveError> {
    // Participant descriptors are collected on `TransactionDataspaceTarget::participants` and
    // later committed through `RoutingPlan::NativeAmx` plus block execution-context receipts.
    // This merge only decides whether the coordinator must fall back to the universal route.
    let Some(candidate) = candidate else {
        return Ok(());
    };
    match *target_dataspace {
        Some(existing) if existing == candidate => {}
        Some(existing) if existing == DataSpaceId::UNIVERSAL => {}
        Some(_) if candidate == DataSpaceId::UNIVERSAL => {
            *target_dataspace = Some(DataSpaceId::UNIVERSAL);
        }
        Some(existing) => {
            if reject_cross_dataspace {
                return Err(native_dataspace_conflict_error(
                    conflict_kind,
                    existing,
                    candidate,
                ));
            }
            *target_dataspace = Some(DataSpaceId::UNIVERSAL);
        }
        None => *target_dataspace = Some(candidate),
    }
    Ok(())
}
#[derive(Clone, Debug, Default)]
struct TransactionDataspaceTarget {
    dataspace_id: Option<DataSpaceId>,
    coordinator_route: bool,
    has_universal_target: bool,
    participants: BTreeSet<DataSpaceId>,
}
struct SameTransactionMultisigProposalTarget {
    top_level_instruction_index: usize,
    account: AccountId,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    instructions: Vec<InstructionBox>,
    dataspace_id: Option<DataSpaceId>,
    concrete_dataspaces: BTreeSet<DataSpaceId>,
    requires_universal_coordinator: bool,
}
fn merge_transaction_target_dataspace(
    target: &mut TransactionDataspaceTarget,
    candidate: Option<DataSpaceId>,
    reject_cross_dataspace: bool,
) -> Result<(), RoutingResolveError> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    if candidate == DataSpaceId::UNIVERSAL {
        target.has_universal_target = true;
    } else {
        target.participants.insert(candidate);
    }
    match target.dataspace_id {
        Some(existing) if existing == candidate => {}
        Some(existing) => {
            if reject_cross_dataspace {
                return Err(native_dataspace_conflict_error(
                    NativeDataspaceConflict::Transaction,
                    existing,
                    candidate,
                ));
            }
            target.dataspace_id = Some(DataSpaceId::UNIVERSAL);
        }
        None => {
            target.dataspace_id = Some(candidate);
        }
    }
    if target.has_universal_target && !target.participants.is_empty() {
        target.coordinator_route = true;
    }
    Ok(())
}
fn merge_transaction_concrete_or_collapsed_dataspaces(
    target: &mut TransactionDataspaceTarget,
    concrete_dataspaces: Option<BTreeSet<DataSpaceId>>,
    collapsed_dataspace: Option<DataSpaceId>,
    reject_cross_dataspace: bool,
) -> Result<(), RoutingResolveError> {
    if let Some(concrete_dataspaces) =
        concrete_dataspaces.filter(|dataspaces| !dataspaces.is_empty())
    {
        for dataspace in concrete_dataspaces {
            merge_transaction_target_dataspace(target, Some(dataspace), reject_cross_dataspace)?;
        }
        return Ok(());
    }
    merge_transaction_target_dataspace(target, collapsed_dataspace, reject_cross_dataspace)
}
fn apply_authority_dataspace_target(
    target: &mut TransactionDataspaceTarget,
    authority_target: Option<DataSpaceId>,
    allow_universal_override: bool,
) {
    let Some(authority_target) = authority_target else {
        return;
    };
    if target.dataspace_id.is_none() {
        target.dataspace_id = Some(authority_target);
        target.coordinator_route = authority_target == DataSpaceId::UNIVERSAL;
        return;
    }
    if target.dataspace_id == Some(DataSpaceId::UNIVERSAL)
        && authority_target != DataSpaceId::UNIVERSAL
        && allow_universal_override
        && !target.coordinator_route
        && !target.has_universal_target
        && target.participants.is_empty()
    {
        target.dataspace_id = Some(authority_target);
    }
}
fn transaction_dataspace_routing_target(
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    transaction_dataspace_routing_target_info(tx, dataspace_catalog, state_view)
        .map(|target| target.dataspace_id)
}
fn executable_instruction_refs(executable: &Executable) -> Vec<&InstructionBox> {
    match executable {
        Executable::Instructions(instructions) => instructions.iter().collect(),
        Executable::Batch(items) => items
            .iter()
            .filter_map(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => Some(instruction),
                ExecutableBatchItem::ContractCall(_) => None,
            })
            .collect(),
        Executable::IvmProved(proved) => proved.overlay.iter().collect(),
        Executable::ContractCall(_) | Executable::Ivm(_) => Vec::new(),
    }
}
fn merge_top_level_instruction_dataspace_target(
    target: &mut TransactionDataspaceTarget,
    instruction: &dyn Instruction,
    top_level_instruction_index: usize,
    same_transaction_multisig_proposals: &[SameTransactionMultisigProposalTarget],
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
    reject_cross_dataspace: bool,
) -> Result<(), RoutingResolveError> {
    let same_transaction_approve_target = same_transaction_multisig_route_target(
        same_transaction_multisig_proposals,
        instruction,
        top_level_instruction_index,
    )?;
    let instruction_target = match same_transaction_approve_target {
        Some(proposal) => proposal.dataspace_id,
        None => {
            instruction_transaction_dataspace_target(instruction, dataspace_catalog, state_view)?
        }
    };
    let concrete_dataspaces = match same_transaction_approve_target {
        Some(proposal) => Some(proposal.concrete_dataspaces.clone()),
        None => deferred_instruction_concrete_dataspace_targets(
            instruction,
            dataspace_catalog,
            state_view,
        )?,
    };
    merge_transaction_concrete_or_collapsed_dataspaces(
        target,
        concrete_dataspaces,
        instruction_target,
        reject_cross_dataspace,
    )?;
    let requires_universal_coordinator = match same_transaction_approve_target {
        Some(proposal) => proposal.requires_universal_coordinator,
        None => instruction_transaction_target_requires_universal_coordinator(
            instruction,
            dataspace_catalog,
            state_view,
        )?,
    };
    if requires_universal_coordinator {
        target.coordinator_route = true;
    }
    Ok(())
}
fn merge_top_level_instruction_dataspace_target_with_world<W: WorldReadOnly>(
    target: &mut TransactionDataspaceTarget,
    instruction: &dyn Instruction,
    top_level_instruction_index: usize,
    same_transaction_multisig_proposals: &[SameTransactionMultisigProposalTarget],
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    reject_cross_dataspace: bool,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<(), RoutingResolveError> {
    let same_transaction_approve_target = same_transaction_multisig_route_target(
        same_transaction_multisig_proposals,
        instruction,
        top_level_instruction_index,
    )?;
    let instruction_target = match same_transaction_approve_target {
        Some(proposal) => proposal.dataspace_id,
        None => instruction_transaction_dataspace_target_with_world_and_fx_overlay(
            instruction,
            dataspace_catalog,
            world,
            ledger_time_ms,
            fx_overlay,
        )?,
    };
    let concrete_dataspaces = match same_transaction_approve_target {
        Some(proposal) => Some(proposal.concrete_dataspaces.clone()),
        None => deferred_instruction_concrete_dataspace_targets_with_world_and_fx_overlay(
            instruction,
            dataspace_catalog,
            world,
            ledger_time_ms,
            fx_overlay,
        )?,
    };
    merge_transaction_concrete_or_collapsed_dataspaces(
        target,
        concrete_dataspaces,
        instruction_target,
        reject_cross_dataspace,
    )?;
    let requires_universal_coordinator = match same_transaction_approve_target {
        Some(proposal) => proposal.requires_universal_coordinator,
        None => {
            instruction_transaction_target_requires_universal_coordinator_with_world_and_fx_overlay(
                instruction,
                dataspace_catalog,
                world,
                ledger_time_ms,
                fx_overlay,
            )?
        }
    };
    if requires_universal_coordinator {
        target.coordinator_route = true;
    }
    Ok(())
}
fn transaction_dataspace_routing_target_info(
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<TransactionDataspaceTarget, RoutingResolveError> {
    let Some(executable) = transaction_executable(tx) else {
        return Ok(TransactionDataspaceTarget::default());
    };
    let mut target = TransactionDataspaceTarget::default();
    let reject_cross_dataspace = amx_policy_rejects_cross_dataspace(tx);
    let instruction_refs = executable_instruction_refs(executable);
    let same_transaction_multisig_proposals = same_transaction_multisig_proposal_targets(
        &instruction_refs,
        dataspace_catalog,
        state_view,
    )?;
    match executable {
        Executable::Instructions(instructions) => {
            for (top_level_instruction_index, instruction) in instructions.iter().enumerate() {
                merge_top_level_instruction_dataspace_target(
                    &mut target,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    dataspace_catalog,
                    state_view,
                    reject_cross_dataspace,
                )?;
            }
        }
        Executable::ContractCall(_) | Executable::Ivm(_) => {}
        Executable::Batch(items) => {
            let mut top_level_instruction_index = 0;
            for item in items {
                let item_target = match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        merge_top_level_instruction_dataspace_target(
                            &mut target,
                            &**instruction,
                            top_level_instruction_index,
                            &same_transaction_multisig_proposals,
                            dataspace_catalog,
                            state_view,
                            reject_cross_dataspace,
                        )?;
                        top_level_instruction_index += 1;
                        continue;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        contract_address_dataspace_target(&call.contract_address)
                    }
                };
                merge_transaction_concrete_or_collapsed_dataspaces(
                    &mut target,
                    item_target.map(|dataspace| BTreeSet::from([dataspace])),
                    item_target,
                    reject_cross_dataspace,
                )?;
                if item_target == Some(DataSpaceId::UNIVERSAL) {
                    target.coordinator_route = true;
                }
            }
        }
        Executable::IvmProved(proved) => {
            for (top_level_instruction_index, instruction) in proved.overlay.iter().enumerate() {
                merge_top_level_instruction_dataspace_target(
                    &mut target,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    dataspace_catalog,
                    state_view,
                    reject_cross_dataspace,
                )?;
            }
        }
    }
    apply_settlement_routing_target(
        &mut target,
        settlement_transaction_dataspace_target(tx, dataspace_catalog, state_view)?,
    );
    Ok(target)
}
fn transaction_dataspace_routing_target_info_with_world<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<TransactionDataspaceTarget, RoutingResolveError> {
    let Some(executable) = transaction_executable(tx) else {
        return Ok(TransactionDataspaceTarget::default());
    };
    let mut target = TransactionDataspaceTarget::default();
    let mut fx_overlay = FxCorridorRoutingOverlay::default();
    let reject_cross_dataspace = amx_policy_rejects_cross_dataspace(tx);
    let instruction_refs = executable_instruction_refs(executable);
    let same_transaction_multisig_proposals =
        same_transaction_multisig_proposal_targets_with_world(
            &instruction_refs,
            dataspace_catalog,
            world,
            ledger_time_ms,
            &fx_overlay,
        )?;
    match executable {
        Executable::Instructions(instructions) => {
            for (top_level_instruction_index, instruction) in instructions.iter().enumerate() {
                merge_top_level_instruction_dataspace_target_with_world(
                    &mut target,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    reject_cross_dataspace,
                    &fx_overlay,
                )?;
                observe_top_level_instruction_fx_effects(
                    &mut fx_overlay,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    world,
                )?;
            }
        }
        Executable::ContractCall(_) | Executable::Ivm(_) => {}
        Executable::Batch(items) => {
            let mut top_level_instruction_index = 0;
            for item in items {
                let item_target = match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        merge_top_level_instruction_dataspace_target_with_world(
                            &mut target,
                            &**instruction,
                            top_level_instruction_index,
                            &same_transaction_multisig_proposals,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                            reject_cross_dataspace,
                            &fx_overlay,
                        )?;
                        observe_top_level_instruction_fx_effects(
                            &mut fx_overlay,
                            &**instruction,
                            top_level_instruction_index,
                            &same_transaction_multisig_proposals,
                            world,
                        )?;
                        top_level_instruction_index += 1;
                        continue;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        contract_address_dataspace_target(&call.contract_address)
                    }
                };
                merge_transaction_concrete_or_collapsed_dataspaces(
                    &mut target,
                    item_target.map(|dataspace| BTreeSet::from([dataspace])),
                    item_target,
                    reject_cross_dataspace,
                )?;
                if item_target == Some(DataSpaceId::UNIVERSAL) {
                    target.coordinator_route = true;
                }
            }
        }
        Executable::IvmProved(proved) => {
            for (top_level_instruction_index, instruction) in proved.overlay.iter().enumerate() {
                merge_top_level_instruction_dataspace_target_with_world(
                    &mut target,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    reject_cross_dataspace,
                    &fx_overlay,
                )?;
                observe_top_level_instruction_fx_effects(
                    &mut fx_overlay,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    world,
                )?;
            }
        }
    }
    Ok(target)
}

/// Native scope carried by a transaction before logical lane sharding.
pub(crate) struct NativeExecutionTarget {
    /// Concrete application scope, when the executable supplies one.
    pub dataspace: Option<DataSpaceId>,
    /// Registry/control-plane instructions and cross-dataspace coordinators use lane zero.
    pub global: bool,
}

/// Resolve the native instruction/address scope without treating the authority's aliases as
/// ownership of all of its transactions. Control-plane batches stay on the global chain so a
/// new dataspace can register its bootstrap grant and name before its lane is active.
pub(crate) fn native_execution_target<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    dataspaces: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: u64,
) -> Result<NativeExecutionTarget, RoutingResolveError> {
    if let Some(Executable::ContractCall(call)) = transaction_executable(tx) {
        return Ok(NativeExecutionTarget {
            dataspace: contract_address_dataspace_target(&call.contract_address),
            global: false,
        });
    }
    let mut target = transaction_dataspace_routing_target_info_with_world(
        tx,
        Some(dataspaces),
        world,
        Some(ledger_time_ms),
    )?;
    apply_settlement_routing_target(
        &mut target,
        settlement_transaction_dataspace_target_with_world(
            tx,
            Some(dataspaces),
            world,
            Some(ledger_time_ms),
        )?,
    );
    let control_plane = match transaction_executable(tx) {
        Some(Executable::Instructions(instructions)) => {
            !instructions.is_empty()
                && instructions
                    .iter()
                    .all(|instruction| instruction_routes_to_universal_dataspace(&**instruction))
        }
        _ => false,
    };
    Ok(NativeExecutionTarget {
        dataspace: target.dataspace_id,
        global: control_plane || target.coordinator_route,
    })
}
/// Resolve an actually executed instruction using the same native scope rules as admission.
/// Deferred multisig bodies and composite settlement legs retain their coordinator identity.
pub(crate) fn native_instruction_execution_target<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspaces: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: u64,
) -> Result<NativeExecutionTarget, RoutingResolveError> {
    let mut target = TransactionDataspaceTarget::default();
    let fx_overlay = FxCorridorRoutingOverlay::default();
    merge_top_level_instruction_dataspace_target_with_world(
        &mut target,
        instruction,
        0,
        &[],
        Some(dataspaces),
        world,
        Some(ledger_time_ms),
        false,
        &fx_overlay,
    )?;
    collect_instruction_native_amx_participants(
        instruction,
        dataspaces,
        world,
        Some(ledger_time_ms),
        &mut target.participants,
        &fx_overlay,
        &mut MultisigProposalRoutingStack::default(),
    )?;
    apply_settlement_routing_target(
        &mut target,
        instruction_settlement_dataspace_target_with_world(
            instruction,
            Some(dataspaces),
            world,
            Some(ledger_time_ms),
            &fx_overlay,
        )?,
    );
    if target.participants.len() > 1 {
        target.dataspace_id = Some(DataSpaceId::UNIVERSAL);
        target.coordinator_route = true;
    } else if target.dataspace_id.is_none() {
        target.dataspace_id = target.participants.iter().next().copied();
    }
    if target.has_universal_target && !target.participants.is_empty() {
        target.coordinator_route = true;
    }
    Ok(NativeExecutionTarget {
        dataspace: target.dataspace_id,
        global: target.coordinator_route || instruction_routes_to_universal_dataspace(instruction),
    })
}

/// Resolve one instruction solely for an authenticated original private genesis source.
/// Private genesis initializes its own alias registry; ordinary alias acquisition remains global.
/// This classification grants no authority: callers must retain the original genesis capability.
pub(crate) fn private_genesis_instruction_target<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspaces: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: u64,
) -> Result<NativeExecutionTarget, RoutingResolveError> {
    if let Some(alias) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::alias_setup::EnsureAlias>()
    {
        return Ok(NativeExecutionTarget {
            dataspace: Some(alias.intent.target().dataspace_id()),
            global: false,
        });
    }
    if instruction
        .as_any()
        .is::<iroha_data_model::isi::SetParameter>()
    {
        return Ok(NativeExecutionTarget {
            dataspace: None,
            global: false,
        });
    }
    native_instruction_execution_target(instruction, dataspaces, world, ledger_time_ms)
}

/// Return the concrete dataspace participants of a native AMX candidate.
///
/// This is intentionally narrower than route resolution: it preserves the
/// per-dataspace legs that make a native transaction require a coordinator
/// route so block commitments can expose deterministic prepare/commit evidence.
#[cfg(test)]
pub(crate) fn native_amx_participant_dataspaces_with_world<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
) -> Vec<DataSpaceId> {
    native_amx_participant_dataspaces_with_world_at(tx, dataspace_catalog, world, None)
        .unwrap_or_default()
}
fn native_amx_participant_dataspaces_with_world_at<W: WorldReadOnly>(
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Vec<DataSpaceId>, RoutingResolveError> {
    let mut dataspaces = std::collections::BTreeSet::new();
    let mut fx_overlay = FxCorridorRoutingOverlay::default();
    let mut multisig_stack = MultisigProposalRoutingStack::default();
    let Some(executable) = transaction_executable(tx) else {
        return Ok(Vec::new());
    };
    let instruction_refs = executable_instruction_refs(executable);
    let same_transaction_multisig_proposals =
        same_transaction_multisig_proposal_targets_with_world(
            &instruction_refs,
            Some(dataspace_catalog),
            world,
            ledger_time_ms,
            &fx_overlay,
        )?;
    match executable {
        Executable::Instructions(instructions) => {
            for (top_level_instruction_index, instruction) in instructions.iter().enumerate() {
                collect_top_level_instruction_native_amx_participants(
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    &mut dataspaces,
                    &fx_overlay,
                    &mut multisig_stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    &mut fx_overlay,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    world,
                )?;
            }
        }
        Executable::ContractCall(call) => {
            insert_native_amx_participant(
                &mut dataspaces,
                contract_address_dataspace_target(&call.contract_address),
            );
        }
        Executable::Batch(items) => {
            let mut top_level_instruction_index = 0;
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        collect_top_level_instruction_native_amx_participants(
                            &**instruction,
                            top_level_instruction_index,
                            &same_transaction_multisig_proposals,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                            &mut dataspaces,
                            &fx_overlay,
                            &mut multisig_stack,
                        )?;
                        observe_top_level_instruction_fx_effects(
                            &mut fx_overlay,
                            &**instruction,
                            top_level_instruction_index,
                            &same_transaction_multisig_proposals,
                            world,
                        )?;
                        top_level_instruction_index += 1;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        insert_native_amx_participant(
                            &mut dataspaces,
                            contract_address_dataspace_target(&call.contract_address),
                        );
                    }
                }
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for (top_level_instruction_index, instruction) in proved.overlay.iter().enumerate() {
                collect_top_level_instruction_native_amx_participants(
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    &mut dataspaces,
                    &fx_overlay,
                    &mut multisig_stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    &mut fx_overlay,
                    &**instruction,
                    top_level_instruction_index,
                    &same_transaction_multisig_proposals,
                    world,
                )?;
            }
        }
    }
    Ok(dataspaces.into_iter().collect())
}
fn collect_top_level_instruction_native_amx_participants<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    top_level_instruction_index: usize,
    same_transaction_multisig_proposals: &[SameTransactionMultisigProposalTarget],
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
    dataspaces: &mut BTreeSet<DataSpaceId>,
    fx_overlay: &FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    if let Some(proposal) = same_transaction_multisig_route_target(
        same_transaction_multisig_proposals,
        instruction,
        top_level_instruction_index,
    )? && !proposal.concrete_dataspaces.is_empty()
    {
        let has_collapsed_universal = proposal
            .concrete_dataspaces
            .contains(&DataSpaceId::UNIVERSAL);
        for dataspace in &proposal.concrete_dataspaces {
            insert_native_amx_participant(dataspaces, Some(*dataspace));
        }
        if !has_collapsed_universal {
            return Ok(());
        }
        // A universal target can be the collapsed representation of a composite
        // instruction. Reinspect the authenticated payload so its concrete legs
        // cannot disappear from the AMX plan.
    }
    collect_instruction_native_amx_participants(
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        dataspaces,
        fx_overlay,
        stack,
    )
}
fn reconcile_native_amx_participants_with_world<W: WorldReadOnly>(
    mut target: TransactionDataspaceTarget,
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<TransactionDataspaceTarget, RoutingResolveError> {
    target
        .participants
        .extend(native_amx_participant_dataspaces_with_world_at(
            tx,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?);
    apply_settlement_routing_target(
        &mut target,
        settlement_transaction_dataspace_target_with_world(
            tx,
            Some(dataspace_catalog),
            world,
            ledger_time_ms,
        )?,
    );
    if target.participants.len() > 1 {
        target.dataspace_id = Some(DataSpaceId::UNIVERSAL);
    } else if target.dataspace_id.is_none() {
        target.dataspace_id = target.participants.iter().next().copied();
    }
    if target.has_universal_target && !target.participants.is_empty() {
        target.coordinator_route = true;
    }
    reject_cross_dataspace_plan(
        amx_policy_rejects_cross_dataspace(tx),
        target.coordinator_route,
        target.participants.iter().copied(),
    )?;
    Ok(target)
}
/// Normalize settlement coordination identically for catalog-only and State-based routing.
fn apply_settlement_routing_target(
    target: &mut TransactionDataspaceTarget,
    settlement_target: Option<DataSpaceId>,
) {
    let Some(settlement_target) = settlement_target else {
        return;
    };
    if settlement_target == DataSpaceId::UNIVERSAL {
        target.dataspace_id = Some(DataSpaceId::UNIVERSAL);
        target.coordinator_route = true;
        target.has_universal_target = true;
    } else {
        target.participants.insert(settlement_target);
        if target.dataspace_id.is_none() {
            target.dataspace_id = Some(settlement_target);
        }
    }
}
fn insert_native_amx_participant(
    dataspaces: &mut std::collections::BTreeSet<DataSpaceId>,
    target: Option<DataSpaceId>,
) {
    if let Some(dataspace) = target
        && dataspace != DataSpaceId::UNIVERSAL
    {
        dataspaces.insert(dataspace);
    }
}
fn collect_asset_balance_native_amx_participants<I>(
    dataspaces: &mut std::collections::BTreeSet<DataSpaceId>,
    definition_target: AssetBalanceDefinitionRouteTarget,
    explicit_asset_target: Option<DataSpaceId>,
    account_targets: I,
) -> Result<(), RoutingResolveError>
where
    I: IntoIterator<Item = Option<DataSpaceId>>,
{
    for target in asset_balance_operation_concrete_dataspaces(
        definition_target,
        explicit_asset_target,
        account_targets,
    )? {
        insert_native_amx_participant(dataspaces, Some(target));
    }
    Ok(())
}
fn collect_trigger_executable_native_amx_participants<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
    dataspaces: &mut BTreeSet<DataSpaceId>,
    fx_overlay: &mut FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    match executable {
        Executable::ContractCall(call) => {
            insert_native_amx_participant(
                dataspaces,
                contract_address_dataspace_target(&call.contract_address),
            );
        }
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                collect_instruction_native_amx_participants(
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    dataspaces,
                    fx_overlay,
                    stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        collect_instruction_native_amx_participants(
                            &**instruction,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                            dataspaces,
                            fx_overlay,
                            stack,
                        )?;
                        observe_top_level_instruction_fx_effects(
                            fx_overlay,
                            &**instruction,
                            usize::MAX,
                            &[],
                            world,
                        )?;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        insert_native_amx_participant(
                            dataspaces,
                            contract_address_dataspace_target(&call.contract_address),
                        );
                    }
                }
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                collect_instruction_native_amx_participants(
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    dataspaces,
                    fx_overlay,
                    stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
        }
    }
    Ok(())
}
fn collect_instruction_native_amx_participants<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
    dataspaces: &mut std::collections::BTreeSet<DataSpaceId>,
    fx_overlay: &FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    insert_native_amx_participant(
        dataspaces,
        instruction_dataspace_scoped_permission_target_with_world(
            instruction,
            Some(dataspace_catalog),
            world,
            ledger_time_ms,
        )?,
    );
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        for dataspace in transfer_batch_targets_with_world(
            batch,
            Some(dataspace_catalog),
            world,
            ledger_time_ms,
        )? {
            insert_native_amx_participant(dataspaces, Some(dataspace));
        }
        return Ok(());
    }
    if let Some(atomic) = settlement_atomic::instruction(instruction) {
        for dataspace in settlement_atomic::concrete_dataspaces(atomic)? {
            insert_native_amx_participant(dataspaces, Some(dataspace));
        }
        return Ok(());
    }

    if let Some(primary) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias>()
    {
        let alias_dataspaces = compare_and_set_primary_account_alias_dataspace_targets(primary);
        if alias_dataspaces.is_empty() {
            insert_native_amx_participant(
                dataspaces,
                account_dataspace_target(Some(world), &primary.account, ledger_time_ms)?,
            );
        } else {
            for dataspace in alias_dataspaces {
                insert_native_amx_participant(dataspaces, Some(dataspace));
            }
        }
        return Ok(());
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        let collect_payload = |instructions: &[InstructionBox],
                               account: &AccountId,
                               stack: &mut MultisigProposalRoutingStack|
         -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
            let mut nested_dataspaces = BTreeSet::new();
            let mut nested_fx_overlay = fx_overlay.clone();
            for nested in instructions {
                collect_instruction_native_amx_participants(
                    &**nested,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    &mut nested_dataspaces,
                    &nested_fx_overlay,
                    stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    &mut nested_fx_overlay,
                    &**nested,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
            if nested_dataspaces.is_empty() {
                insert_native_amx_participant(
                    &mut nested_dataspaces,
                    account_dataspace_target(Some(world), account, ledger_time_ms)?,
                );
            }
            Ok(nested_dataspaces)
        };
        let nested_dataspaces = match multisig {
            MultisigInstructionBox::Propose(propose) => {
                collect_payload(&propose.instructions, &propose.account, stack)?
            }
            MultisigInstructionBox::Approve(approve) => with_multisig_proposal_instructions(
                fx_overlay,
                world,
                &approve.account,
                &approve.instructions_hash,
                stack,
                |instructions, stack| collect_payload(instructions, &approve.account, stack),
            )?
            .map_or_else(
                || -> Result<_, ExecutionDeferred> {
                    Ok(
                        account_dataspace_target(Some(world), &approve.account, ledger_time_ms)?
                            .filter(|dataspace| *dataspace != DataSpaceId::UNIVERSAL)
                            .into_iter()
                            .collect(),
                    )
                },
                Ok,
            )?,
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => BTreeSet::new(),
        };
        dataspaces.extend(nested_dataspaces);
        return Ok(());
    }
    if let Some(RegisterBox::Trigger(register)) = any.downcast_ref::<RegisterBox>() {
        let mut nested_fx_overlay = fx_overlay.clone();
        return collect_trigger_executable_native_amx_participants(
            register.object.action().executable(),
            dataspace_catalog,
            world,
            ledger_time_ms,
            dataspaces,
            &mut nested_fx_overlay,
            stack,
        );
    }
    let fx_instruction = any.downcast_ref::<SettleFxCorridor>().or_else(|| {
        any.downcast_ref::<SettlementInstructionBox>()
            .and_then(|settlement| match settlement {
                SettlementInstructionBox::SettleFxCorridor(fx) => Some(fx),
                SettlementInstructionBox::Atomic(_)
                | SettlementInstructionBox::Dvp(_)
                | SettlementInstructionBox::Pvp(_)
                | SettlementInstructionBox::SetFxCorridorPolicy(_)
                | SettlementInstructionBox::FundFxCorridorEscrow(_)
                | SettlementInstructionBox::RefundFxCorridorEscrow(_) => None,
            })
    });
    if let Some(fx) = fx_instruction {
        let policy = fx_overlay.policy_with_world(world, &fx.policy_id)?;
        insert_native_amx_participant(dataspaces, Some(policy.source_dataspace));
        insert_native_amx_participant(dataspaces, Some(policy.destination_dataspace));
        return Ok(());
    }
    let escrow_policy_id = any
        .downcast_ref::<FundFxCorridorEscrow>()
        .map(|fund| &fund.policy_id)
        .or_else(|| {
            any.downcast_ref::<RefundFxCorridorEscrow>()
                .map(|refund| &refund.policy_id)
        })
        .or_else(|| {
            any.downcast_ref::<SettlementInstructionBox>()
                .and_then(|settlement| match settlement {
                    SettlementInstructionBox::FundFxCorridorEscrow(fund) => Some(&fund.policy_id),
                    SettlementInstructionBox::RefundFxCorridorEscrow(refund) => {
                        Some(&refund.policy_id)
                    }
                    SettlementInstructionBox::Atomic(_)
                    | SettlementInstructionBox::Dvp(_)
                    | SettlementInstructionBox::Pvp(_)
                    | SettlementInstructionBox::SetFxCorridorPolicy(_)
                    | SettlementInstructionBox::SettleFxCorridor(_) => None,
                })
        });
    if let Some(policy_id) = escrow_policy_id {
        let policy = fx_overlay.policy_with_world(world, policy_id)?;
        insert_native_amx_participant(dataspaces, Some(policy.destination_dataspace));
        return Ok(());
    }
    if let Some(settlement_dataspaces) =
        settlement_pair::concrete_dataspaces(instruction, |asset_definition| {
            asset_balance_definition_dataspace_target_with_world(
                asset_definition,
                Some(dataspace_catalog),
                world,
                ledger_time_ms,
            )
        })?
    {
        for dataspace in settlement_dataspaces {
            insert_native_amx_participant(dataspaces, Some(dataspace));
        }
        return Ok(());
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>() {
        if let TransferBox::Asset(transfer) = transfer {
            collect_asset_balance_native_amx_participants(
                dataspaces,
                asset_balance_definition_route_target_with_world(
                    &transfer.source.definition,
                    Some(dataspace_catalog),
                    world,
                    ledger_time_ms,
                )?,
                asset_id_explicit_dataspace_target(&transfer.source),
                [
                    account_dataspace_target(
                        Some(world),
                        &transfer.source.account,
                        ledger_time_ms,
                    )?,
                    account_dataspace_target(Some(world), &transfer.destination, ledger_time_ms)?,
                ],
            )?;
            return Ok(());
        }
    }
    if let Some(mint) = any.downcast_ref::<MintBox>() {
        if let MintBox::Asset(mint) = mint {
            collect_asset_balance_native_amx_participants(
                dataspaces,
                asset_balance_definition_route_target_with_world(
                    &mint.destination.definition,
                    Some(dataspace_catalog),
                    world,
                    ledger_time_ms,
                )?,
                asset_id_explicit_dataspace_target(&mint.destination),
                [account_dataspace_target(
                    Some(world),
                    &mint.destination.account,
                    ledger_time_ms,
                )?],
            )?;
            return Ok(());
        }
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>() {
        if let BurnBox::Asset(burn) = burn {
            collect_asset_balance_native_amx_participants(
                dataspaces,
                asset_balance_definition_route_target_with_world(
                    &burn.destination.definition,
                    Some(dataspace_catalog),
                    world,
                    ledger_time_ms,
                )?,
                asset_id_explicit_dataspace_target(&burn.destination),
                [account_dataspace_target(
                    Some(world),
                    &burn.destination.account,
                    ledger_time_ms,
                )?],
            )?;
            return Ok(());
        }
    }
    insert_native_amx_participant(
        dataspaces,
        instruction_transaction_dataspace_target_with_world_and_fx_overlay(
            instruction,
            Some(dataspace_catalog),
            world,
            ledger_time_ms,
            fx_overlay,
        )?,
    );
    Ok(())
}
enum AccountPermissionHolderTarget<'account> {
    Holder(&'account AccountId),
    Skip,
    Abort,
}
fn account_permission_holder_routing_target<'tx>(
    tx: &'tx dyn TransactionRoutingView,
) -> Option<&'tx AccountId> {
    let Some(executable) = transaction_executable(tx) else {
        return None;
    };
    match executable {
        Executable::Instructions(instructions) => account_permission_holder_from_instructions(
            instructions.iter().map(|instruction| &**instruction),
        ),
        Executable::ContractCall(_) | Executable::Ivm(_) => None,
        Executable::IvmProved(proved) => account_permission_holder_from_instructions(
            proved.overlay.iter().map(|instruction| &**instruction),
        ),
        Executable::Batch(items) => {
            if items
                .iter()
                .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)))
            {
                return None;
            }
            account_permission_holder_from_instructions(items.iter().filter_map(
                |item| match item {
                    ExecutableBatchItem::Instruction(instruction) => Some(&**instruction),
                    ExecutableBatchItem::ContractCall(_) => None,
                },
            ))
        }
    }
}
fn account_permission_holder_from_instructions<'instruction, I>(
    instructions: I,
) -> Option<&'instruction AccountId>
where
    I: IntoIterator<Item = &'instruction dyn Instruction>,
{
    let mut holder: Option<&AccountId> = None;
    let mut saw_account_permission = false;
    for instruction in instructions {
        match instruction_account_permission_holder(instruction) {
            AccountPermissionHolderTarget::Holder(candidate) => {
                saw_account_permission = true;
                match holder {
                    Some(existing) if existing != candidate => return None,
                    Some(_) => {}
                    None => {
                        holder = Some(candidate);
                    }
                }
            }
            AccountPermissionHolderTarget::Skip | AccountPermissionHolderTarget::Abort => {
                return None;
            }
        }
    }
    if saw_account_permission { holder } else { None }
}
fn instruction_account_permission_holder(
    instruction: &dyn Instruction,
) -> AccountPermissionHolderTarget<'_> {
    let any = instruction.as_any();
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant) => {
                if dataspace_scoped_permission_target(&grant.object, None, None)
                    .is_ok_and(|target| target.is_some())
                {
                    AccountPermissionHolderTarget::Skip
                } else {
                    AccountPermissionHolderTarget::Holder(&grant.destination)
                }
            }
            GrantBox::Role(_) | GrantBox::RolePermission(_) => AccountPermissionHolderTarget::Abort,
        };
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return match revoke {
            RevokeBox::Permission(revoke) => {
                if dataspace_scoped_permission_target(&revoke.object, None, None)
                    .is_ok_and(|target| target.is_some())
                {
                    AccountPermissionHolderTarget::Skip
                } else {
                    AccountPermissionHolderTarget::Holder(&revoke.destination)
                }
            }
            RevokeBox::Role(_) | RevokeBox::RolePermission(_) => {
                AccountPermissionHolderTarget::Abort
            }
        };
    }
    AccountPermissionHolderTarget::Abort
}
fn compare_and_set_primary_account_alias_dataspace_targets(
    primary: &iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias,
) -> BTreeSet<DataSpaceId> {
    primary
        .expected_alias
        .iter()
        .chain(primary.new_alias.iter())
        .map(|alias| alias.dataspace_id)
        .collect()
}
fn compare_and_set_primary_account_alias_dataspace_target(
    primary: &iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias,
) -> Option<DataSpaceId> {
    merge_instruction_dataspace_targets(
        compare_and_set_primary_account_alias_dataspace_targets(primary)
            .into_iter()
            .map(Some),
    )
}
/// SNS lease mutations and their derived identity records can use the universal registry.
///
/// In particular, acquiring a dataspace name must not require that dataspace to already have a
/// lane/catalog entry. The native executor still validates the name/id pair, ownership, active
/// parents, quote guard, and the global lease payment before creating any records.
fn instruction_uses_universal_alias_registry(instruction: &dyn Instruction) -> bool {
    let any = instruction.as_any();
    any.is::<iroha_data_model::isi::alias_setup::EnsureAlias>()
        || any.is::<iroha_data_model::isi::alias_setup::RenewAliasLease>()
}
/// Universal control instructions share one scope across native ordering and physical policy.
/// Parameter changes, alias registry work, private-root admission and SCCP execute on the
/// global chain even when the authority has a private account route. SCCP's serial ordering
/// also preserves outbound nonces and leaf indices (`specs/sccp.md` §4.5, §4.19).
fn instruction_routes_to_universal_dataspace(instruction: &dyn Instruction) -> bool {
    (!cfg!(all(test, sumeragi_core_mutation = "HC41"))
        && instruction
            .as_any()
            .is::<iroha_data_model::isi::SetParameter>())
        || instruction_uses_universal_alias_registry(instruction)
        || crate::smartcontracts::isi::sccp::is_sccp_instruction(instruction)
        || instruction
            .as_any()
            .is::<iroha_data_model::isi::private_dataspace::RegisterPrivateDataspace>()
        || instruction
            .as_any()
            .is::<iroha_data_model::isi::private_dataspace::AnchorPrivateDataspace>()
}

/// Artifact custody is explicitly scoped even before a contract address is deployed.
fn contract_artifact_dataspace_target(instruction: &dyn Instruction) -> Option<DataSpaceId> {
    use iroha_data_model::isi::smart_contract_code::{
        CancelSmartContractCodeUpload, RemoveSmartContractBytes,
    };
    let any = instruction.as_any();
    any.downcast_ref::<RegisterSmartContractCode>()
        .map(|value| value.artifact_id.dataspace_id)
        .or_else(|| {
            any.downcast_ref::<RegisterSmartContractBytes>()
                .map(|value| value.artifact_id.dataspace_id)
        })
        .or_else(|| {
            any.downcast_ref::<UploadSmartContractCodeChunk>()
                .map(|value| value.artifact_id.dataspace_id)
        })
        .or_else(|| {
            any.downcast_ref::<FinalizeSmartContractCodeUpload>()
                .map(|value| value.artifact_id.dataspace_id)
        })
        .or_else(|| {
            any.downcast_ref::<CancelSmartContractCodeUpload>()
                .map(|value| value.artifact_id.dataspace_id)
        })
        .or_else(|| {
            any.downcast_ref::<RemoveSmartContractBytes>()
                .map(|value| value.artifact_id.dataspace_id)
        })
}

/// Retail activation and signed identity carriers bind their physical policy scope.
/// Routing does not authenticate either carrier; native execution retains every
/// policy/definition/issuer/signature check after the exact source route is captured.
fn retail_declared_dataspace_target(instruction: &dyn Instruction) -> Option<DataSpaceId> {
    use iroha_data_model::isi::retail_daily_limit::{
        ActivateRetailDailyLimitV1, BindRetailIdentityV1,
    };
    let any = instruction.as_any();
    any.downcast_ref::<ActivateRetailDailyLimitV1>()
        .map(|value| value.policy.physical_dataspace)
        .or_else(|| {
            any.downcast_ref::<BindRetailIdentityV1>()
                .map(|value| value.attestation.body.physical_dataspace)
        })
}

/// Monetary instructions carry a definition, so their scope comes from its
/// current restricted definition and exact activated native policy, never metadata.
fn retail_monetary_dataspace_target_with_world<W: WorldReadOnly>(
    movement: &iroha_data_model::isi::retail_daily_limit::RetailMonetaryMovementV1,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<DataSpaceId, RoutingResolveError> {
    let unavailable = |reason: &str| RoutingResolveError::OrdinaryRouteUnavailable {
        reason: reason.to_owned(),
    };
    let definition =
        asset_definition_for_routing(world, &movement.asset_definition_id, ledger_time_ms)
            .ok_or_else(|| unavailable("retail monetary definition is absent"))?;
    if definition.balance_scope_policy() != AssetBalancePolicy::DataspaceRestricted {
        return Err(unavailable(
            "retail monetary definition is not dataspace-restricted",
        ));
    }
    let dataspace = asset_definition_dataspace_target_with_world(
        &movement.asset_definition_id,
        None,
        None,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )?
    .ok_or_else(|| unavailable("retail monetary definition has no physical dataspace"))?;
    let policy = crate::state::retail_daily_limit_state::policy_for_exact(
        world,
        &movement.asset_definition_id,
        dataspace,
    )
    .map_err(|_| unavailable("retail monetary native policy is invalid"))?
    .ok_or_else(|| unavailable("retail monetary native policy is absent"))?;
    crate::state::retail_daily_limit_state::activation_for_exact(world, &policy)
        .map_err(|_| unavailable("retail monetary native activation is invalid"))?;
    Ok(dataspace)
}

/// Participant instructions name their exact root; global proofs do not add a second route.
fn native_amx_participant_dataspace_target(instruction: &dyn Instruction) -> Option<DataSpaceId> {
    use iroha_data_model::isi::sumeragi_amx::{
        PrepareAmxV1, RegisterAmxParticipantV1, RelayGlobalAmxHandoffV1, SettleAmxV1,
    };
    let any = instruction.as_any();
    any.downcast_ref::<RegisterAmxParticipantV1>()
        .map(|value| value.dataspace)
        .or_else(|| {
            any.downcast_ref::<PrepareAmxV1>()
                .map(|value| value.dataspace)
        })
        .or_else(|| {
            any.downcast_ref::<SettleAmxV1>()
                .map(|value| value.dataspace)
        })
        .or_else(|| {
            any.downcast_ref::<RelayGlobalAmxHandoffV1>()
                .map(|value| value.dataspace)
        })
}

fn kagemusha_dataspace_with_world(
    world: &impl WorldReadOnly,
    instruction: &iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1,
) -> Result<DataSpaceId, RoutingResolveError> {
    crate::kagemusha_wallet_v1::routing::dataspace(world, instruction).map_err(|error| {
        RoutingResolveError::OrdinaryRouteUnavailable {
            reason: format!("KAGEMUSHA permanent scope unavailable: {error}"),
        }
    })
}

fn instruction_transaction_dataspace_target(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    if let Some(register) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::RegisterDataspaceAssetDefinition>(
    ) {
        return Ok(Some(register.dataspace_id));
    }
    if let Some(operation) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1>(
    ) {
        let view = state_view.ok_or_else(|| RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "KAGEMUSHA routing requires original World state".into(),
        })?;
        let target = kagemusha_dataspace_with_world(view.world(), operation)?;
        return Ok(Some(target));
    }
    if let Some(dataspace) = native_amx_participant_dataspace_target(instruction) {
        return Ok(Some(dataspace));
    }
    if let Some(dataspace) = contract_artifact_dataspace_target(instruction) {
        return Ok(Some(dataspace));
    }
    if let Some(dataspace) = retail_declared_dataspace_target(instruction) {
        return Ok(Some(dataspace));
    }
    if let Some(movement) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::retail_daily_limit::RetailMonetaryMovementV1>(
    ) {
        let view = state_view.ok_or_else(|| RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "retail monetary routing requires current native policy state".to_owned(),
        })?;
        return retail_monetary_dataspace_target_with_world(
            movement,
            dataspace_catalog,
            view.world(),
            Some(state_view_ledger_time_ms(view)),
        )
        .map(Some);
    }
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        return Ok(merge_instruction_dataspace_targets(
            transfer_batch_targets_with_view(batch, dataspace_catalog, state_view)?
                .into_iter()
                .map(Some),
        ));
    }
    if let Some(settlement_target) =
        instruction_settlement_dataspace_target(instruction, dataspace_catalog, state_view)?
    {
        return Ok(Some(settlement_target));
    }
    if instruction_routes_to_universal_dataspace(instruction) {
        return Ok(Some(DataSpaceId::UNIVERSAL));
    }
    if let Some(configure) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::ConfigureAliasAutoRenew>()
    {
        return Ok(Some(configure.target.dataspace_id()));
    }
    if let Some(rebind) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::RebindAccountAlias>()
    {
        return Ok(Some(rebind.alias.dataspace_id));
    }
    if let Some(primary) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias>()
    {
        return Ok(
            compare_and_set_primary_account_alias_dataspace_target(primary).map_or_else(
                || {
                    account_dataspace_target(
                        state_view.map(StateView::world),
                        &primary.account,
                        state_view.map(state_view_ledger_time_ms),
                    )
                },
                |target| Ok(Some(target)),
            )?,
        );
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        return match &multisig {
            MultisigInstructionBox::Propose(propose) => {
                multisig_propose_transaction_dataspace_target(
                    propose,
                    dataspace_catalog,
                    state_view,
                )
            }
            MultisigInstructionBox::Approve(approve) => {
                multisig_approve_transaction_dataspace_target(
                    approve,
                    dataspace_catalog,
                    state_view,
                )
            }
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => Ok(None),
        };
    }
    if let Some(propose) = any.downcast_ref::<MultisigPropose>() {
        return multisig_propose_transaction_dataspace_target(
            propose,
            dataspace_catalog,
            state_view,
        );
    }
    if let Some(approve) = any.downcast_ref::<MultisigApprove>() {
        return multisig_approve_transaction_dataspace_target(
            approve,
            dataspace_catalog,
            state_view,
        );
    }
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant) => Ok(dataspace_scoped_permission_target(
                &grant.object,
                dataspace_catalog,
                state_view,
            )?
            .map_or_else(
                || {
                    account_dataspace_target(
                        state_view.map(StateView::world),
                        &grant.destination,
                        state_view.map(state_view_ledger_time_ms),
                    )
                },
                |target| Ok(Some(target)),
            )?),
            GrantBox::RolePermission(grant) => {
                dataspace_scoped_permission_target(&grant.object, dataspace_catalog, state_view)
            }
            GrantBox::Role(_) => Ok(None),
        };
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return match revoke {
            RevokeBox::Permission(revoke) => Ok(dataspace_scoped_permission_target(
                &revoke.object,
                dataspace_catalog,
                state_view,
            )?
            .map_or_else(
                || {
                    account_dataspace_target(
                        state_view.map(StateView::world),
                        &revoke.destination,
                        state_view.map(state_view_ledger_time_ms),
                    )
                },
                |target| Ok(Some(target)),
            )?),
            RevokeBox::RolePermission(revoke) => {
                dataspace_scoped_permission_target(&revoke.object, dataspace_catalog, state_view)
            }
            RevokeBox::Role(_) => Ok(None),
        };
    }
    if let Some(register) = any.downcast_ref::<RegisterBox>() {
        return match register {
            RegisterBox::Domain(register) => domain_dataspace_target_with_state(
                &register.object.id,
                dataspace_catalog,
                state_view,
            ),
            RegisterBox::Account(register) => {
                Ok(register.object.label.as_ref().map(|alias| alias.dataspace))
            }
            RegisterBox::AssetDefinition(register) => {
                if let Some(alias) = register.object.alias.as_ref()
                    && let Some(dataspace_id) = dataspace_alias_target_with_state(
                        alias.dataspace_segment(),
                        dataspace_catalog,
                        state_view,
                    )?
                {
                    return Ok(Some(dataspace_id));
                }
                asset_definition_dataspace_target(
                    &register.object.id,
                    register.object.owning_domain.as_ref(),
                    Some(register.object.balance_scope_policy),
                    dataspace_catalog,
                    state_view,
                )
            }
            RegisterBox::Trigger(register) => trigger_executable_transaction_dataspace_target(
                register.object.action().executable(),
                dataspace_catalog,
                state_view,
            ),
            RegisterBox::Nft(register) => domain_dataspace_target_with_state(
                &register.object.id.domain,
                dataspace_catalog,
                state_view,
            ),
            RegisterBox::Peer(_) | RegisterBox::Role(_) => Ok(None),
        };
    }
    if let Some(unregister) = any.downcast_ref::<UnregisterBox>() {
        return match unregister {
            UnregisterBox::Domain(unregister) => domain_dataspace_target_with_state(
                &unregister.object,
                dataspace_catalog,
                state_view,
            ),
            UnregisterBox::AssetDefinition(unregister) => asset_definition_dataspace_target(
                &unregister.object,
                None,
                None,
                dataspace_catalog,
                state_view,
            ),
            UnregisterBox::Nft(unregister) => domain_dataspace_target_with_state(
                &unregister.object.domain,
                dataspace_catalog,
                state_view,
            ),
            UnregisterBox::Peer(_)
            | UnregisterBox::Account(_)
            | UnregisterBox::Role(_)
            | UnregisterBox::Trigger(_) => Ok(None),
        };
    }
    if let Some(set_key_value) = any.downcast_ref::<SetKeyValueBox>() {
        return match set_key_value {
            SetKeyValueBox::Domain(set) => {
                domain_dataspace_target_with_state(&set.object, dataspace_catalog, state_view)
            }
            SetKeyValueBox::Account(set) => Ok(account_dataspace_target(
                state_view.map(StateView::world),
                &set.object,
                state_view.map(state_view_ledger_time_ms),
            )?),
            SetKeyValueBox::AssetDefinition(set) => asset_definition_dataspace_target(
                &set.object,
                None,
                None,
                dataspace_catalog,
                state_view,
            ),
            SetKeyValueBox::Nft(set) => domain_dataspace_target_with_state(
                &set.object.domain,
                dataspace_catalog,
                state_view,
            ),
            SetKeyValueBox::Trigger(_) => Ok(None),
        };
    }
    if let Some(remove_key_value) = any.downcast_ref::<RemoveKeyValueBox>() {
        return match remove_key_value {
            RemoveKeyValueBox::Domain(remove) => {
                domain_dataspace_target_with_state(&remove.object, dataspace_catalog, state_view)
            }
            RemoveKeyValueBox::Account(remove) => Ok(account_dataspace_target(
                state_view.map(StateView::world),
                &remove.object,
                state_view.map(state_view_ledger_time_ms),
            )?),
            RemoveKeyValueBox::AssetDefinition(remove) => asset_definition_dataspace_target(
                &remove.object,
                None,
                None,
                dataspace_catalog,
                state_view,
            ),
            RemoveKeyValueBox::Nft(remove) => domain_dataspace_target_with_state(
                &remove.object.domain,
                dataspace_catalog,
                state_view,
            ),
            RemoveKeyValueBox::Trigger(_) => Ok(None),
        };
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>() {
        return match transfer {
            TransferBox::Domain(transfer) => {
                domain_dataspace_target_with_state(&transfer.object, dataspace_catalog, state_view)
            }
            TransferBox::AssetDefinition(transfer) => asset_definition_dataspace_target(
                &transfer.object,
                None,
                None,
                dataspace_catalog,
                state_view,
            ),
            TransferBox::Asset(transfer) => asset_balance_operation_dataspace_target(
                asset_balance_definition_route_target(
                    &transfer.source.definition,
                    dataspace_catalog,
                    state_view,
                )?,
                asset_id_explicit_dataspace_target(&transfer.source),
                [
                    account_dataspace_target(
                        state_view.map(StateView::world),
                        &transfer.source.account,
                        state_view.map(state_view_ledger_time_ms),
                    )?,
                    account_dataspace_target(
                        state_view.map(StateView::world),
                        &transfer.destination,
                        state_view.map(state_view_ledger_time_ms),
                    )?,
                ],
            ),
            TransferBox::Nft(transfer) => domain_dataspace_target_with_state(
                &transfer.object.domain,
                dataspace_catalog,
                state_view,
            ),
        };
    }
    if let Some(mint) = any.downcast_ref::<MintBox>() {
        return match mint {
            MintBox::Asset(mint) => asset_balance_operation_dataspace_target(
                asset_balance_definition_route_target(
                    &mint.destination.definition,
                    dataspace_catalog,
                    state_view,
                )?,
                asset_id_explicit_dataspace_target(&mint.destination),
                [account_dataspace_target(
                    state_view.map(StateView::world),
                    &mint.destination.account,
                    state_view.map(state_view_ledger_time_ms),
                )?],
            ),
            MintBox::TriggerRepetitions(_) => Ok(None),
        };
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>() {
        return match burn {
            BurnBox::Asset(burn) => asset_balance_operation_dataspace_target(
                asset_balance_definition_route_target(
                    &burn.destination.definition,
                    dataspace_catalog,
                    state_view,
                )?,
                asset_id_explicit_dataspace_target(&burn.destination),
                [account_dataspace_target(
                    state_view.map(StateView::world),
                    &burn.destination.account,
                    state_view.map(state_view_ledger_time_ms),
                )?],
            ),
            BurnBox::TriggerRepetitions(_) => Ok(None),
        };
    }
    if let Some(register_zk_asset) = any.downcast_ref::<RegisterZkAsset>() {
        return asset_balance_definition_dataspace_target(
            &register_zk_asset.asset,
            dataspace_catalog,
            state_view,
        );
    }
    if let Some(schedule_transition) = any.downcast_ref::<ScheduleConfidentialPolicyTransition>() {
        return asset_balance_definition_dataspace_target(
            &schedule_transition.asset,
            dataspace_catalog,
            state_view,
        );
    }
    if let Some(cancel_transition) = any.downcast_ref::<CancelConfidentialPolicyTransition>() {
        return asset_balance_definition_dataspace_target(
            &cancel_transition.asset,
            dataspace_catalog,
            state_view,
        );
    }
    if let Some(target) = musubi_instruction_dataspace_target(any) {
        return Ok(Some(target));
    }
    if let Some(publish) = any.downcast_ref::<PublishSpaceDirectoryManifest>() {
        return Ok(Some(publish.manifest.dataspace));
    }
    if let Some(revoke) = any.downcast_ref::<RevokeSpaceDirectoryManifest>() {
        return Ok(Some(revoke.dataspace));
    }
    if let Some(expire) = any.downcast_ref::<ExpireSpaceDirectoryManifest>() {
        return Ok(Some(expire.dataspace));
    }
    if let Some(activate) = any.downcast_ref::<ActivateContractInstance>() {
        return Ok(contract_address_dataspace_target(
            &activate.contract_address,
        ));
    }
    if let Some(commit) = any.downcast_ref::<CommitContractDeployment>() {
        return Ok(contract_address_dataspace_target(&commit.contract_address));
    }
    if let Some(deactivate) = any.downcast_ref::<DeactivateContractInstance>() {
        return Ok(contract_address_dataspace_target(
            &deactivate.contract_address,
        ));
    }
    if let Some(set_alias) = any.downcast_ref::<SetContractAlias>() {
        return Ok(contract_address_dataspace_target(
            &set_alias.contract_address,
        ));
    }
    Ok(None)
}
fn instruction_transaction_dataspace_target_with_world<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    instruction_transaction_dataspace_target_with_world_and_fx_overlay(
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        &FxCorridorRoutingOverlay::default(),
    )
}
fn instruction_transaction_dataspace_target_with_world_and_fx_overlay<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    if let Some(register) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::RegisterDataspaceAssetDefinition>(
    ) {
        return Ok(Some(register.dataspace_id));
    }
    if let Some(operation) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1>(
    ) {
        let target = kagemusha_dataspace_with_world(world, operation)?;
        return Ok(Some(target));
    }
    if let Some(dataspace) = native_amx_participant_dataspace_target(instruction) {
        return Ok(Some(dataspace));
    }
    if let Some(dataspace) = contract_artifact_dataspace_target(instruction) {
        return Ok(Some(dataspace));
    }
    if let Some(dataspace) = retail_declared_dataspace_target(instruction) {
        return Ok(Some(dataspace));
    }
    if let Some(movement) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::retail_daily_limit::RetailMonetaryMovementV1>(
    ) {
        return retail_monetary_dataspace_target_with_world(
            movement,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )
        .map(Some);
    }
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        return Ok(merge_instruction_dataspace_targets(
            transfer_batch_targets_with_world(batch, dataspace_catalog, world, ledger_time_ms)?
                .into_iter()
                .map(Some),
        ));
    }
    if let Some(settlement_target) = instruction_settlement_dataspace_target_with_world(
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        fx_overlay,
    )? {
        return Ok(Some(settlement_target));
    }
    if instruction_routes_to_universal_dataspace(instruction) {
        return Ok(Some(DataSpaceId::UNIVERSAL));
    }
    if let Some(configure) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::ConfigureAliasAutoRenew>()
    {
        return Ok(Some(configure.target.dataspace_id()));
    }
    if let Some(rebind) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::RebindAccountAlias>()
    {
        return Ok(Some(rebind.alias.dataspace_id));
    }
    if let Some(primary) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias>()
    {
        return Ok(
            compare_and_set_primary_account_alias_dataspace_target(primary).map_or_else(
                || account_dataspace_target(Some(world), &primary.account, ledger_time_ms),
                |target| Ok(Some(target)),
            )?,
        );
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        return match &multisig {
            MultisigInstructionBox::Propose(propose) => {
                multisig_propose_transaction_dataspace_target_with_world_and_fx_overlay(
                    propose,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    fx_overlay,
                )
            }
            MultisigInstructionBox::Approve(approve) => {
                multisig_approve_transaction_dataspace_target_with_world_and_fx_overlay(
                    approve,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    fx_overlay,
                )
            }
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => Ok(None),
        };
    }
    if let Some(propose) = any.downcast_ref::<MultisigPropose>() {
        return multisig_propose_transaction_dataspace_target_with_world_and_fx_overlay(
            propose,
            dataspace_catalog,
            world,
            ledger_time_ms,
            fx_overlay,
        );
    }
    if let Some(approve) = any.downcast_ref::<MultisigApprove>() {
        return multisig_approve_transaction_dataspace_target_with_world_and_fx_overlay(
            approve,
            dataspace_catalog,
            world,
            ledger_time_ms,
            fx_overlay,
        );
    }
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant) => Ok(dataspace_scoped_permission_target_with_world(
                &grant.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?
            .map_or_else(
                || account_dataspace_target(Some(world), &grant.destination, ledger_time_ms),
                |target| Ok(Some(target)),
            )?),
            GrantBox::RolePermission(grant) => dataspace_scoped_permission_target_with_world(
                &grant.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            GrantBox::Role(_) => Ok(None),
        };
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return match revoke {
            RevokeBox::Permission(revoke) => Ok(dataspace_scoped_permission_target_with_world(
                &revoke.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?
            .map_or_else(
                || account_dataspace_target(Some(world), &revoke.destination, ledger_time_ms),
                |target| Ok(Some(target)),
            )?),
            RevokeBox::RolePermission(revoke) => dataspace_scoped_permission_target_with_world(
                &revoke.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            RevokeBox::Role(_) => Ok(None),
        };
    }
    if let Some(register) = any.downcast_ref::<RegisterBox>() {
        return match register {
            RegisterBox::Domain(register) => domain_dataspace_target_with_world(
                &register.object.id,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            RegisterBox::Account(register) => {
                Ok(register.object.label.as_ref().map(|alias| alias.dataspace))
            }
            RegisterBox::AssetDefinition(register) => {
                if let Some(alias) = register.object.alias.as_ref()
                    && let Some(dataspace_id) = dataspace_alias_target_with_world(
                        alias.dataspace_segment(),
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )?
                {
                    return Ok(Some(dataspace_id));
                }
                asset_definition_dataspace_target_with_world(
                    &register.object.id,
                    register.object.owning_domain.as_ref(),
                    Some(register.object.balance_scope_policy),
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )
            }
            RegisterBox::Trigger(register) => {
                let mut nested_fx_overlay = fx_overlay.clone();
                trigger_executable_transaction_dataspace_target_with_world_and_fx_overlay(
                    register.object.action().executable(),
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    &mut nested_fx_overlay,
                )
            }
            RegisterBox::Nft(register) => domain_dataspace_target_with_world(
                &register.object.id.domain,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            RegisterBox::Peer(_) | RegisterBox::Role(_) => Ok(None),
        };
    }
    if let Some(unregister) = any.downcast_ref::<UnregisterBox>() {
        return match unregister {
            UnregisterBox::Domain(unregister) => domain_dataspace_target_with_world(
                &unregister.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            UnregisterBox::AssetDefinition(unregister) => {
                asset_definition_dataspace_target_with_world(
                    &unregister.object,
                    None,
                    None,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )
            }
            UnregisterBox::Nft(unregister) => domain_dataspace_target_with_world(
                &unregister.object.domain,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            UnregisterBox::Peer(_)
            | UnregisterBox::Account(_)
            | UnregisterBox::Role(_)
            | UnregisterBox::Trigger(_) => Ok(None),
        };
    }
    if let Some(set_key_value) = any.downcast_ref::<SetKeyValueBox>() {
        return match set_key_value {
            SetKeyValueBox::Domain(set) => domain_dataspace_target_with_world(
                &set.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            SetKeyValueBox::Account(set) => Ok(account_dataspace_target(
                Some(world),
                &set.object,
                ledger_time_ms,
            )?),
            SetKeyValueBox::AssetDefinition(set) => asset_definition_dataspace_target_with_world(
                &set.object,
                None,
                None,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            SetKeyValueBox::Nft(set) => domain_dataspace_target_with_world(
                &set.object.domain,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            SetKeyValueBox::Trigger(_) => Ok(None),
        };
    }
    if let Some(remove_key_value) = any.downcast_ref::<RemoveKeyValueBox>() {
        return match remove_key_value {
            RemoveKeyValueBox::Domain(remove) => domain_dataspace_target_with_world(
                &remove.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            RemoveKeyValueBox::Account(remove) => Ok(account_dataspace_target(
                Some(world),
                &remove.object,
                ledger_time_ms,
            )?),
            RemoveKeyValueBox::AssetDefinition(remove) => {
                asset_definition_dataspace_target_with_world(
                    &remove.object,
                    None,
                    None,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )
            }
            RemoveKeyValueBox::Nft(remove) => domain_dataspace_target_with_world(
                &remove.object.domain,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            RemoveKeyValueBox::Trigger(_) => Ok(None),
        };
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>() {
        return match transfer {
            TransferBox::Domain(transfer) => domain_dataspace_target_with_world(
                &transfer.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            TransferBox::AssetDefinition(transfer) => asset_definition_dataspace_target_with_world(
                &transfer.object,
                None,
                None,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            TransferBox::Asset(transfer) => asset_balance_operation_dataspace_target(
                asset_balance_definition_route_target_with_world(
                    &transfer.source.definition,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )?,
                asset_id_explicit_dataspace_target(&transfer.source),
                [
                    account_dataspace_target(
                        Some(world),
                        &transfer.source.account,
                        ledger_time_ms,
                    )?,
                    account_dataspace_target(Some(world), &transfer.destination, ledger_time_ms)?,
                ],
            ),
            TransferBox::Nft(transfer) => domain_dataspace_target_with_world(
                &transfer.object.domain,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
        };
    }
    if let Some(mint) = any.downcast_ref::<MintBox>() {
        return match mint {
            MintBox::Asset(mint) => asset_balance_operation_dataspace_target(
                asset_balance_definition_route_target_with_world(
                    &mint.destination.definition,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )?,
                asset_id_explicit_dataspace_target(&mint.destination),
                [account_dataspace_target(
                    Some(world),
                    &mint.destination.account,
                    ledger_time_ms,
                )?],
            ),
            MintBox::TriggerRepetitions(_) => Ok(None),
        };
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>() {
        return match burn {
            BurnBox::Asset(burn) => asset_balance_operation_dataspace_target(
                asset_balance_definition_route_target_with_world(
                    &burn.destination.definition,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )?,
                asset_id_explicit_dataspace_target(&burn.destination),
                [account_dataspace_target(
                    Some(world),
                    &burn.destination.account,
                    ledger_time_ms,
                )?],
            ),
            BurnBox::TriggerRepetitions(_) => Ok(None),
        };
    }
    if let Some(register_zk_asset) = any.downcast_ref::<RegisterZkAsset>() {
        return asset_balance_definition_dataspace_target_with_world(
            &register_zk_asset.asset,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    if let Some(schedule_transition) = any.downcast_ref::<ScheduleConfidentialPolicyTransition>() {
        return asset_balance_definition_dataspace_target_with_world(
            &schedule_transition.asset,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    if let Some(cancel_transition) = any.downcast_ref::<CancelConfidentialPolicyTransition>() {
        return asset_balance_definition_dataspace_target_with_world(
            &cancel_transition.asset,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    if let Some(target) = musubi_instruction_dataspace_target(any) {
        return Ok(Some(target));
    }
    if let Some(publish) = any.downcast_ref::<PublishSpaceDirectoryManifest>() {
        return Ok(Some(publish.manifest.dataspace));
    }
    if let Some(revoke) = any.downcast_ref::<RevokeSpaceDirectoryManifest>() {
        return Ok(Some(revoke.dataspace));
    }
    if let Some(expire) = any.downcast_ref::<ExpireSpaceDirectoryManifest>() {
        return Ok(Some(expire.dataspace));
    }
    if let Some(activate) = any.downcast_ref::<ActivateContractInstance>() {
        return Ok(contract_address_dataspace_target(
            &activate.contract_address,
        ));
    }
    if let Some(commit) = any.downcast_ref::<CommitContractDeployment>() {
        return Ok(contract_address_dataspace_target(&commit.contract_address));
    }
    if let Some(deactivate) = any.downcast_ref::<DeactivateContractInstance>() {
        return Ok(contract_address_dataspace_target(
            &deactivate.contract_address,
        ));
    }
    if let Some(set_alias) = any.downcast_ref::<SetContractAlias>() {
        return Ok(contract_address_dataspace_target(
            &set_alias.contract_address,
        ));
    }
    Ok(None)
}
fn proposal_instructions_hash(
    instructions: &Vec<InstructionBox>,
) -> Result<HashOf<Vec<InstructionBox>>, RoutingResolveError> {
    HashOf::try_new(instructions).map_err(|error| {
        match crate::smartcontracts::isi::multisig::multisig_instruction_decode_attempt(
            error,
            |error| RoutingResolveError::OrdinaryRouteUnavailable {
                reason: error.to_string(),
            },
        ) {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                RoutingResolveError::Deferred(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
        }
    })
}
fn multisig_instruction(
    instruction: &dyn Instruction,
) -> Result<Option<MultisigInstructionBox>, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(multisig) = any.downcast_ref::<MultisigInstructionBox>() {
        return Ok(Some(multisig.clone()));
    }
    if let Some(propose) = any.downcast_ref::<MultisigPropose>() {
        return Ok(Some(MultisigInstructionBox::Propose(propose.clone())));
    }
    if let Some(approve) = any.downcast_ref::<MultisigApprove>() {
        return Ok(Some(MultisigInstructionBox::Approve(approve.clone())));
    }
    let Some(custom) = any.downcast_ref::<CustomInstruction>() else {
        return Ok(None);
    };
    match MultisigInstructionBox::try_from(custom.payload()) {
        Ok(multisig) => Ok(Some(multisig)),
        Err(error) => {
            match crate::smartcontracts::isi::multisig::multisig_instruction_decode_attempt(
                error,
                |_| (),
            ) {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    Err(RoutingResolveError::Deferred(reason))
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(()) => Ok(None),
            }
        }
    }
}
#[cfg(test)]
fn multisig_proposal_state_key(
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> StatePath {
    const DELIMITER: char = '/';
    const MULTISIG: &str = "multisig";
    const MULTISIG_PROPOSAL_STATE: &str = "proposal";
    StatePath::from_str(&format!(
        "{MULTISIG}{DELIMITER}{MULTISIG_PROPOSAL_STATE}{DELIMITER}{}{DELIMITER}{}",
        HashOf::new(multisig_account),
        instructions_hash
    ))
    .expect("multisig proposal state path must be valid")
}
// Decode only one proposal node. Any caller that recursively visits the payload must either use
// `with_multisig_proposal_state` or complete a guarded recursive pre-walk before expansion.
fn multisig_proposal_state_raw<W: WorldReadOnly>(
    world: &W,
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> Result<Option<MultisigProposalState>, RoutingResolveError> {
    crate::smartcontracts::isi::multisig::read_proposal_state(
        world,
        multisig_account,
        instructions_hash,
    )
    .map_err(|error| match error {
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            RoutingResolveError::Deferred(reason)
        }
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
            RoutingResolveError::InvalidMultisigProposal {
                account: multisig_account.clone(),
                instructions_hash: *instructions_hash,
                reason: error.to_string(),
            }
        }
    })
}
fn with_multisig_proposal_state<W: WorldReadOnly, T>(
    world: &W,
    account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
    stack: &mut MultisigProposalRoutingStack,
    resolve: impl FnOnce(
        &MultisigProposalState,
        &mut MultisigProposalRoutingStack,
    ) -> Result<T, RoutingResolveError>,
) -> Result<Option<T>, RoutingResolveError> {
    let Some(proposal) = multisig_proposal_state_raw(world, account, instructions_hash)? else {
        return Ok(None);
    };
    stack
        .with_proposal(account, instructions_hash, |stack| {
            resolve(&proposal, stack)
        })
        .map(Some)
}
fn with_multisig_proposal_instructions<W: WorldReadOnly, T>(
    fx_overlay: &FxCorridorRoutingOverlay,
    world: &W,
    account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
    stack: &mut MultisigProposalRoutingStack,
    resolve: impl FnOnce(
        &[InstructionBox],
        &mut MultisigProposalRoutingStack,
    ) -> Result<T, RoutingResolveError>,
) -> Result<Option<T>, RoutingResolveError> {
    let Some(instructions) =
        fx_overlay.multisig_proposal_instructions_with_world(world, account, instructions_hash)?
    else {
        return Ok(None);
    };
    stack
        .with_proposal(account, instructions_hash, |stack| {
            resolve(&instructions, stack)
        })
        .map(Some)
}
fn extend_instruction_concrete_dataspace_targets(
    targets: &mut BTreeSet<DataSpaceId>,
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<(), RoutingResolveError> {
    extend_instruction_concrete_dataspace_targets_with_stack(
        targets,
        instruction,
        dataspace_catalog,
        state_view,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn extend_instruction_concrete_dataspace_targets_with_stack(
    targets: &mut BTreeSet<DataSpaceId>,
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    if let Some(nested_targets) = deferred_instruction_concrete_dataspace_targets_with_stack(
        instruction,
        dataspace_catalog,
        state_view,
        stack,
    )? && !nested_targets.is_empty()
    {
        targets.extend(nested_targets);
        return Ok(());
    }
    if let Some(target) =
        instruction_transaction_dataspace_target(instruction, dataspace_catalog, state_view)?
    {
        targets.insert(target);
    }
    Ok(())
}
fn trigger_executable_concrete_dataspace_targets(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    trigger_executable_concrete_dataspace_targets_with_stack(
        executable,
        dataspace_catalog,
        state_view,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn trigger_executable_concrete_dataspace_targets_with_stack(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    let mut targets = BTreeSet::new();
    match executable {
        Executable::ContractCall(call) => {
            if let Some(target) = contract_address_dataspace_target(&call.contract_address) {
                targets.insert(target);
            }
        }
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                extend_instruction_concrete_dataspace_targets_with_stack(
                    &mut targets,
                    &**instruction,
                    dataspace_catalog,
                    state_view,
                    stack,
                )?;
            }
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        extend_instruction_concrete_dataspace_targets_with_stack(
                            &mut targets,
                            &**instruction,
                            dataspace_catalog,
                            state_view,
                            stack,
                        )?;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        if let Some(target) =
                            contract_address_dataspace_target(&call.contract_address)
                        {
                            targets.insert(target);
                        }
                    }
                }
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                extend_instruction_concrete_dataspace_targets_with_stack(
                    &mut targets,
                    &**instruction,
                    dataspace_catalog,
                    state_view,
                    stack,
                )?;
            }
        }
    }
    Ok(targets)
}
fn deferred_instruction_concrete_dataspace_targets(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<BTreeSet<DataSpaceId>>, RoutingResolveError> {
    deferred_instruction_concrete_dataspace_targets_with_stack(
        instruction,
        dataspace_catalog,
        state_view,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn deferred_instruction_concrete_dataspace_targets_with_stack(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<BTreeSet<DataSpaceId>>, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        return Ok(Some(transfer_batch_targets_with_view(
            batch,
            dataspace_catalog,
            state_view,
        )?));
    }
    if let Some(atomic) = settlement_atomic::instruction(instruction) {
        return settlement_atomic::concrete_dataspaces(atomic).map(Some);
    }

    if let Some(dataspaces) =
        settlement_pair::concrete_dataspaces(instruction, |asset_definition| {
            asset_balance_definition_dataspace_target(
                asset_definition,
                dataspace_catalog,
                state_view,
            )
        })?
    {
        return Ok(Some(dataspaces));
    }
    if let Some(TransferBox::Asset(transfer)) = any.downcast_ref::<TransferBox>() {
        return Ok(Some(asset_balance_operation_concrete_dataspaces(
            asset_balance_definition_route_target(
                &transfer.source.definition,
                dataspace_catalog,
                state_view,
            )?,
            asset_id_explicit_dataspace_target(&transfer.source),
            [
                account_dataspace_target(
                    state_view.map(StateView::world),
                    &transfer.source.account,
                    state_view.map(state_view_ledger_time_ms),
                )?,
                account_dataspace_target(
                    state_view.map(StateView::world),
                    &transfer.destination,
                    state_view.map(state_view_ledger_time_ms),
                )?,
            ],
        )?));
    }
    if let Some(MintBox::Asset(mint)) = any.downcast_ref::<MintBox>() {
        return Ok(Some(asset_balance_operation_concrete_dataspaces(
            asset_balance_definition_route_target(
                &mint.destination.definition,
                dataspace_catalog,
                state_view,
            )?,
            asset_id_explicit_dataspace_target(&mint.destination),
            [account_dataspace_target(
                state_view.map(StateView::world),
                &mint.destination.account,
                state_view.map(state_view_ledger_time_ms),
            )?],
        )?));
    }
    if let Some(BurnBox::Asset(burn)) = any.downcast_ref::<BurnBox>() {
        return Ok(Some(asset_balance_operation_concrete_dataspaces(
            asset_balance_definition_route_target(
                &burn.destination.definition,
                dataspace_catalog,
                state_view,
            )?,
            asset_id_explicit_dataspace_target(&burn.destination),
            [account_dataspace_target(
                state_view.map(StateView::world),
                &burn.destination.account,
                state_view.map(state_view_ledger_time_ms),
            )?],
        )?));
    }
    if let Some(primary) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias>()
    {
        return Ok(Some(
            compare_and_set_primary_account_alias_dataspace_targets(primary),
        ));
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        let collect = |instructions: &[InstructionBox],
                       stack: &mut MultisigProposalRoutingStack|
         -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
            let mut targets = BTreeSet::new();
            for nested in instructions {
                extend_instruction_concrete_dataspace_targets_with_stack(
                    &mut targets,
                    &**nested,
                    dataspace_catalog,
                    state_view,
                    stack,
                )?;
            }
            Ok(targets)
        };
        return match &multisig {
            MultisigInstructionBox::Propose(propose) => {
                collect(&propose.instructions, stack).map(Some)
            }
            MultisigInstructionBox::Approve(approve) => {
                let Some(view) = state_view else {
                    return Ok(Some(BTreeSet::new()));
                };
                Ok(Some(
                    with_multisig_proposal_state(
                        view.world(),
                        &approve.account,
                        &approve.instructions_hash,
                        stack,
                        |proposal, stack| collect(&proposal.instructions, stack),
                    )?
                    .unwrap_or_default(),
                ))
            }
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => Ok(None),
        };
    }
    let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() else {
        return Ok(None);
    };
    let RegisterBox::Trigger(register) = register else {
        return Ok(None);
    };
    trigger_executable_concrete_dataspace_targets_with_stack(
        register.object.action().executable(),
        dataspace_catalog,
        state_view,
        stack,
    )
    .map(Some)
}
fn extend_instruction_concrete_dataspace_targets_with_world<W: WorldReadOnly>(
    targets: &mut BTreeSet<DataSpaceId>,
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<(), RoutingResolveError> {
    extend_instruction_concrete_dataspace_targets_with_world_and_stack(
        targets,
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn extend_instruction_concrete_dataspace_targets_with_world_and_stack<W: WorldReadOnly>(
    targets: &mut BTreeSet<DataSpaceId>,
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    if let Some(nested_targets) =
        deferred_instruction_concrete_dataspace_targets_with_world_and_stack(
            instruction,
            dataspace_catalog,
            world,
            ledger_time_ms,
            stack,
        )?
        && !nested_targets.is_empty()
    {
        targets.extend(nested_targets);
        return Ok(());
    }
    if let Some(target) = instruction_transaction_dataspace_target_with_world(
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )? {
        targets.insert(target);
    }
    Ok(())
}
fn trigger_executable_concrete_dataspace_targets_with_world<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    trigger_executable_concrete_dataspace_targets_with_world_and_stack(
        executable,
        dataspace_catalog,
        world,
        ledger_time_ms,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn trigger_executable_concrete_dataspace_targets_with_world_and_stack<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    let mut targets = BTreeSet::new();
    match executable {
        Executable::ContractCall(call) => {
            if let Some(target) = contract_address_dataspace_target(&call.contract_address) {
                targets.insert(target);
            }
        }
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                extend_instruction_concrete_dataspace_targets_with_world_and_stack(
                    &mut targets,
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    stack,
                )?;
            }
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        extend_instruction_concrete_dataspace_targets_with_world_and_stack(
                            &mut targets,
                            &**instruction,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                            stack,
                        )?;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        if let Some(target) =
                            contract_address_dataspace_target(&call.contract_address)
                        {
                            targets.insert(target);
                        }
                    }
                }
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                extend_instruction_concrete_dataspace_targets_with_world_and_stack(
                    &mut targets,
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    stack,
                )?;
            }
        }
    }
    Ok(targets)
}
fn deferred_instruction_concrete_dataspace_targets_with_world<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<BTreeSet<DataSpaceId>>, RoutingResolveError> {
    deferred_instruction_concrete_dataspace_targets_with_world_and_stack(
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn deferred_instruction_concrete_dataspace_targets_with_world_and_stack<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<Option<BTreeSet<DataSpaceId>>, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        return Ok(Some(transfer_batch_targets_with_world(
            batch,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?));
    }
    if let Some(atomic) = settlement_atomic::instruction(instruction) {
        return settlement_atomic::concrete_dataspaces(atomic).map(Some);
    }

    if let Some(dataspaces) =
        settlement_pair::concrete_dataspaces(instruction, |asset_definition| {
            asset_balance_definition_dataspace_target_with_world(
                asset_definition,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )
        })?
    {
        return Ok(Some(dataspaces));
    }
    if let Some(TransferBox::Asset(transfer)) = any.downcast_ref::<TransferBox>() {
        return Ok(Some(asset_balance_operation_concrete_dataspaces(
            asset_balance_definition_route_target_with_world(
                &transfer.source.definition,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?,
            asset_id_explicit_dataspace_target(&transfer.source),
            [
                account_dataspace_target(Some(world), &transfer.source.account, ledger_time_ms)?,
                account_dataspace_target(Some(world), &transfer.destination, ledger_time_ms)?,
            ],
        )?));
    }
    if let Some(MintBox::Asset(mint)) = any.downcast_ref::<MintBox>() {
        return Ok(Some(asset_balance_operation_concrete_dataspaces(
            asset_balance_definition_route_target_with_world(
                &mint.destination.definition,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?,
            asset_id_explicit_dataspace_target(&mint.destination),
            [account_dataspace_target(
                Some(world),
                &mint.destination.account,
                ledger_time_ms,
            )?],
        )?));
    }
    if let Some(BurnBox::Asset(burn)) = any.downcast_ref::<BurnBox>() {
        return Ok(Some(asset_balance_operation_concrete_dataspaces(
            asset_balance_definition_route_target_with_world(
                &burn.destination.definition,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?,
            asset_id_explicit_dataspace_target(&burn.destination),
            [account_dataspace_target(
                Some(world),
                &burn.destination.account,
                ledger_time_ms,
            )?],
        )?));
    }
    if let Some(primary) =
        any.downcast_ref::<iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias>()
    {
        return Ok(Some(
            compare_and_set_primary_account_alias_dataspace_targets(primary),
        ));
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        let collect = |instructions: &[InstructionBox],
                       stack: &mut MultisigProposalRoutingStack|
         -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
            let mut targets = BTreeSet::new();
            for nested in instructions {
                extend_instruction_concrete_dataspace_targets_with_world_and_stack(
                    &mut targets,
                    &**nested,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    stack,
                )?;
            }
            Ok(targets)
        };
        return match &multisig {
            MultisigInstructionBox::Propose(propose) => {
                collect(&propose.instructions, stack).map(Some)
            }
            MultisigInstructionBox::Approve(approve) => Ok(Some(
                with_multisig_proposal_state(
                    world,
                    &approve.account,
                    &approve.instructions_hash,
                    stack,
                    |proposal, stack| collect(&proposal.instructions, stack),
                )?
                .unwrap_or_default(),
            )),
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => Ok(None),
        };
    }
    let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() else {
        return Ok(None);
    };
    let RegisterBox::Trigger(register) = register else {
        return Ok(None);
    };
    trigger_executable_concrete_dataspace_targets_with_world_and_stack(
        register.object.action().executable(),
        dataspace_catalog,
        world,
        ledger_time_ms,
        stack,
    )
    .map(Some)
}
fn fx_corridor_instruction_concrete_dataspace_targets_with_world<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    world: &W,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<Option<BTreeSet<DataSpaceId>>, RoutingResolveError> {
    let any = instruction.as_any();
    let settle = any.downcast_ref::<SettleFxCorridor>().or_else(|| {
        any.downcast_ref::<SettlementInstructionBox>()
            .and_then(|settlement| match settlement {
                SettlementInstructionBox::SettleFxCorridor(settle) => Some(settle),
                SettlementInstructionBox::Atomic(_)
                | SettlementInstructionBox::Dvp(_)
                | SettlementInstructionBox::Pvp(_)
                | SettlementInstructionBox::SetFxCorridorPolicy(_)
                | SettlementInstructionBox::FundFxCorridorEscrow(_)
                | SettlementInstructionBox::RefundFxCorridorEscrow(_) => None,
            })
    });
    if let Some(settle) = settle {
        let policy = fx_overlay.policy_with_world(world, &settle.policy_id)?;
        return Ok(Some(BTreeSet::from([
            policy.source_dataspace,
            policy.destination_dataspace,
        ])));
    }
    let escrow_policy_id = any
        .downcast_ref::<FundFxCorridorEscrow>()
        .map(|fund| &fund.policy_id)
        .or_else(|| {
            any.downcast_ref::<RefundFxCorridorEscrow>()
                .map(|refund| &refund.policy_id)
        })
        .or_else(|| {
            any.downcast_ref::<SettlementInstructionBox>()
                .and_then(|settlement| match settlement {
                    SettlementInstructionBox::FundFxCorridorEscrow(fund) => Some(&fund.policy_id),
                    SettlementInstructionBox::RefundFxCorridorEscrow(refund) => {
                        Some(&refund.policy_id)
                    }
                    SettlementInstructionBox::Atomic(_)
                    | SettlementInstructionBox::Dvp(_)
                    | SettlementInstructionBox::Pvp(_)
                    | SettlementInstructionBox::SetFxCorridorPolicy(_)
                    | SettlementInstructionBox::SettleFxCorridor(_) => None,
                })
        });
    let Some(policy_id) = escrow_policy_id else {
        return Ok(None);
    };
    let policy = fx_overlay.policy_with_world(world, policy_id)?;
    Ok(Some(BTreeSet::from([policy.destination_dataspace])))
}
fn extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay<W: WorldReadOnly>(
    targets: &mut BTreeSet<DataSpaceId>,
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<(), RoutingResolveError> {
    extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay_and_stack(
        targets,
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        fx_overlay,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay_and_stack<
    W: WorldReadOnly,
>(
    targets: &mut BTreeSet<DataSpaceId>,
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    if instruction_routes_to_universal_dataspace(instruction) {
        targets.extend(
            instruction_transaction_dataspace_target_with_world_and_fx_overlay(
                instruction,
                dataspace_catalog,
                world,
                ledger_time_ms,
                fx_overlay,
            )?,
        );
        return Ok(());
    }
    if let Some(fx_targets) = fx_corridor_instruction_concrete_dataspace_targets_with_world(
        instruction,
        world,
        fx_overlay,
    )? {
        targets.extend(fx_targets);
        return Ok(());
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        let mut collect = |instructions: &[InstructionBox],
                           stack: &mut MultisigProposalRoutingStack|
         -> Result<(), RoutingResolveError> {
            let mut nested_fx_overlay = fx_overlay.clone();
            for nested in instructions {
                extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay_and_stack(
                    targets,
                    &**nested,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    &nested_fx_overlay,
                    stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    &mut nested_fx_overlay,
                    &**nested,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
            Ok(())
        };
        match multisig {
            MultisigInstructionBox::Propose(propose) => collect(&propose.instructions, stack)?,
            MultisigInstructionBox::Approve(approve) => {
                let _ = with_multisig_proposal_instructions(
                    fx_overlay,
                    world,
                    &approve.account,
                    &approve.instructions_hash,
                    stack,
                    collect,
                )?;
            }
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => {}
        }
        return Ok(());
    }
    if let Some(RegisterBox::Trigger(register)) = instruction.as_any().downcast_ref::<RegisterBox>()
    {
        let mut nested_fx_overlay = fx_overlay.clone();
        return extend_trigger_executable_concrete_dataspace_targets_with_world_and_fx_overlay(
            targets,
            register.object.action().executable(),
            dataspace_catalog,
            world,
            ledger_time_ms,
            &mut nested_fx_overlay,
            stack,
        );
    }
    extend_instruction_concrete_dataspace_targets_with_world(
        targets,
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )
}
fn extend_trigger_executable_concrete_dataspace_targets_with_world_and_fx_overlay<
    W: WorldReadOnly,
>(
    targets: &mut BTreeSet<DataSpaceId>,
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &mut FxCorridorRoutingOverlay,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    match executable {
        Executable::ContractCall(call) => {
            if let Some(target) = contract_address_dataspace_target(&call.contract_address) {
                targets.insert(target);
            }
        }
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay_and_stack(
                    targets,
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    fx_overlay,
                    stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay_and_stack(
                            targets,
                            &**instruction,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                            fx_overlay,
                            stack,
                        )?;
                        observe_top_level_instruction_fx_effects(
                            fx_overlay,
                            &**instruction,
                            usize::MAX,
                            &[],
                            world,
                        )?;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        if let Some(target) =
                            contract_address_dataspace_target(&call.contract_address)
                        {
                            targets.insert(target);
                        }
                    }
                }
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay_and_stack(
                    targets,
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    fx_overlay,
                    stack,
                )?;
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
        }
    }
    Ok(())
}
fn deferred_instruction_concrete_dataspace_targets_with_world_and_fx_overlay<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<Option<BTreeSet<DataSpaceId>>, RoutingResolveError> {
    let is_nested_scope = multisig_instruction(instruction)?.is_some()
        || matches!(
            instruction.as_any().downcast_ref::<RegisterBox>(),
            Some(RegisterBox::Trigger(_))
        );
    if !is_nested_scope {
        return deferred_instruction_concrete_dataspace_targets_with_world(
            instruction,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    let mut targets = BTreeSet::new();
    extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay(
        &mut targets,
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
        fx_overlay,
    )?;
    Ok(Some(targets))
}
fn same_transaction_multisig_proposal_targets(
    instructions: &[&InstructionBox],
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Vec<SameTransactionMultisigProposalTarget>, RoutingResolveError> {
    let mut proposals = Vec::new();
    for (top_level_instruction_index, instruction) in instructions.iter().copied().enumerate() {
        let Some(MultisigInstructionBox::Propose(propose)) = multisig_instruction(&**instruction)?
        else {
            continue;
        };
        let dataspace_id =
            multisig_propose_transaction_dataspace_target(&propose, dataspace_catalog, state_view)?;
        let mut concrete_dataspaces = BTreeSet::new();
        let mut requires_universal_coordinator = false;
        for nested in &propose.instructions {
            extend_instruction_concrete_dataspace_targets(
                &mut concrete_dataspaces,
                &**nested,
                dataspace_catalog,
                state_view,
            )?;
            requires_universal_coordinator |=
                instruction_transaction_target_requires_universal_coordinator(
                    &**nested,
                    dataspace_catalog,
                    state_view,
                )?;
        }
        proposals.push(SameTransactionMultisigProposalTarget {
            top_level_instruction_index,
            account: propose.account,
            instructions_hash: proposal_instructions_hash(&propose.instructions)?,
            instructions: propose.instructions,
            dataspace_id,
            concrete_dataspaces,
            requires_universal_coordinator,
        });
    }
    Ok(proposals)
}
fn same_transaction_multisig_proposal_targets_with_world<W: WorldReadOnly>(
    instructions: &[&InstructionBox],
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<Vec<SameTransactionMultisigProposalTarget>, RoutingResolveError> {
    let mut proposals = Vec::new();
    let mut outer_fx_overlay = fx_overlay.clone();
    for (top_level_instruction_index, instruction) in instructions.iter().copied().enumerate() {
        if let Some(MultisigInstructionBox::Propose(propose)) =
            multisig_instruction(&**instruction)?
        {
            let mut target_fx_overlay = outer_fx_overlay.clone();
            let instruction_target = merge_instruction_dataspace_targets_with_world_and_fx_overlay(
                propose.instructions.iter(),
                dataspace_catalog,
                world,
                ledger_time_ms,
                &mut target_fx_overlay,
            )?;
            let dataspace_id = instruction_target.map_or_else(
                || account_dataspace_target(Some(world), &propose.account, ledger_time_ms),
                |target| Ok(Some(target)),
            )?;
            let mut concrete_dataspaces = BTreeSet::new();
            let mut concrete_fx_overlay = outer_fx_overlay.clone();
            let mut requires_universal_coordinator = false;
            for nested in &propose.instructions {
                extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay(
                    &mut concrete_dataspaces,
                    &**nested,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    &concrete_fx_overlay,
                )?;
                requires_universal_coordinator |=
                    instruction_transaction_target_requires_universal_coordinator_with_world_and_fx_overlay(
                        &**nested,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                        &concrete_fx_overlay,
                    )?;
                observe_top_level_instruction_fx_effects(
                    &mut concrete_fx_overlay,
                    &**nested,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
            requires_universal_coordinator |= concrete_dataspaces.len() > 1;
            proposals.push(SameTransactionMultisigProposalTarget {
                top_level_instruction_index,
                account: propose.account,
                instructions_hash: proposal_instructions_hash(&propose.instructions)?,
                instructions: propose.instructions,
                dataspace_id,
                concrete_dataspaces,
                requires_universal_coordinator,
            });
        }
        observe_top_level_instruction_fx_effects(
            &mut outer_fx_overlay,
            &**instruction,
            top_level_instruction_index,
            &proposals,
            world,
        )?;
    }
    Ok(proposals)
}
fn same_transaction_multisig_route_target<'a>(
    proposals: &'a [SameTransactionMultisigProposalTarget],
    instruction: &dyn Instruction,
    top_level_instruction_index: usize,
) -> Result<Option<&'a SameTransactionMultisigProposalTarget>, RoutingResolveError> {
    let Some(multisig) = multisig_instruction(instruction)? else {
        return Ok(None);
    };
    let (account, instructions_hash, must_precede) = match multisig {
        MultisigInstructionBox::Propose(propose) => (
            propose.account,
            proposal_instructions_hash(&propose.instructions)?,
            false,
        ),
        MultisigInstructionBox::Approve(approve) => {
            (approve.account, approve.instructions_hash, true)
        }
        MultisigInstructionBox::Register(_)
        | MultisigInstructionBox::Cancel(_)
        | MultisigInstructionBox::InvalidateOutstanding(_) => return Ok(None),
    };
    Ok(proposals.iter().find(|proposal| {
        proposal.account == account
            && proposal.instructions_hash == instructions_hash
            && if must_precede {
                proposal.top_level_instruction_index < top_level_instruction_index
            } else {
                proposal.top_level_instruction_index == top_level_instruction_index
            }
    }))
}
fn observe_top_level_instruction_fx_effects<W: WorldReadOnly>(
    fx_overlay: &mut FxCorridorRoutingOverlay,
    instruction: &dyn Instruction,
    top_level_instruction_index: usize,
    same_transaction_multisig_proposals: &[SameTransactionMultisigProposalTarget],
    world: &W,
) -> Result<(), RoutingResolveError> {
    observe_authenticated_instruction_fx_effects(
        fx_overlay,
        instruction,
        top_level_instruction_index,
        same_transaction_multisig_proposals,
        world,
        &mut MultisigProposalRoutingStack::default(),
    )
}
fn observe_authenticated_instruction_fx_effects<W: WorldReadOnly>(
    fx_overlay: &mut FxCorridorRoutingOverlay,
    instruction: &dyn Instruction,
    top_level_instruction_index: usize,
    same_transaction_multisig_proposals: &[SameTransactionMultisigProposalTarget],
    world: &W,
    stack: &mut MultisigProposalRoutingStack,
) -> Result<(), RoutingResolveError> {
    fx_overlay.observe(instruction);
    let Some(multisig) = multisig_instruction(instruction)? else {
        return Ok(());
    };
    let approve = match multisig {
        MultisigInstructionBox::Propose(propose) => {
            // Only a proposal actually reached in the authenticated branch can affect later approval.
            return fx_overlay.record_executed_multisig_proposal(propose);
        }
        MultisigInstructionBox::Approve(approve) => approve,
        _ => return Ok(()),
    };
    let key = (approve.account.clone(), approve.instructions_hash);
    let instructions = if let Some(instructions) = fx_overlay.executed_multisig_proposals.get(&key)
    {
        Some(instructions.clone())
    } else if let Some(proposal) = same_transaction_multisig_route_target(
        same_transaction_multisig_proposals,
        instruction,
        top_level_instruction_index,
    )? {
        Some(proposal.instructions.clone())
    } else {
        multisig_proposal_state_raw(world, &approve.account, &approve.instructions_hash)?
            .map(|proposal| proposal.instructions)
    };
    // Any vote may complete quorum. Project its exact authenticated branch with the same
    // cycle/depth bound as other routing walks, including otherwise non-settlement proposals.
    if let Some(instructions) = instructions {
        stack.with_proposal(&approve.account, &approve.instructions_hash, |stack| {
            for nested in &instructions {
                observe_authenticated_instruction_fx_effects(
                    fx_overlay,
                    &**nested,
                    top_level_instruction_index,
                    same_transaction_multisig_proposals,
                    world,
                    stack,
                )?;
            }
            Ok(())
        })?;
    }
    Ok(())
}
fn multisig_propose_transaction_dataspace_target(
    propose: &MultisigPropose,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let instruction_target = merge_instruction_dataspace_target_results(
        propose.instructions.iter().map(|instruction| {
            instruction_transaction_dataspace_target(&**instruction, dataspace_catalog, state_view)
        }),
    )?;
    Ok(instruction_target.map_or_else(
        || {
            account_dataspace_target(
                state_view.map(StateView::world),
                &propose.account,
                state_view.map(state_view_ledger_time_ms),
            )
        },
        |target| Ok(Some(target)),
    )?)
}
fn multisig_approve_transaction_dataspace_target(
    approve: &MultisigApprove,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let Some(world) = state_view.map(StateView::world) else {
        return Ok(None);
    };
    // The instruction-target entry point completes its guarded settlement pre-walk before this
    // helper is reached, so a cyclic graph cannot enter this unguarded result fold.
    let proposal_target =
        match multisig_proposal_state_raw(world, &approve.account, &approve.instructions_hash)? {
            Some(proposal_state) => merge_instruction_dataspace_target_results(
                proposal_state.instructions.iter().map(|instruction| {
                    instruction_transaction_dataspace_target(
                        &**instruction,
                        dataspace_catalog,
                        state_view,
                    )
                }),
            )?,
            None => None,
        };
    Ok(proposal_target.map_or_else(
        || {
            account_dataspace_target(
                Some(world),
                &approve.account,
                state_view.map(state_view_ledger_time_ms),
            )
        },
        |target| Ok(Some(target)),
    )?)
}
fn multisig_approve_transaction_dataspace_target_with_world_and_fx_overlay<W: WorldReadOnly>(
    approve: &MultisigApprove,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let proposal_target = match fx_overlay.multisig_proposal_instructions_with_world(
        world,
        &approve.account,
        &approve.instructions_hash,
    )? {
        Some(instructions) => {
            let mut nested_fx_overlay = fx_overlay.clone();
            merge_instruction_dataspace_targets_with_world_and_fx_overlay(
                instructions.iter(),
                dataspace_catalog,
                world,
                ledger_time_ms,
                &mut nested_fx_overlay,
            )?
        }
        None => None,
    };
    Ok(proposal_target.map_or_else(
        || account_dataspace_target(Some(world), &approve.account, ledger_time_ms),
        |target| Ok(Some(target)),
    )?)
}
fn multisig_propose_transaction_dataspace_target_with_world_and_fx_overlay<W: WorldReadOnly>(
    propose: &MultisigPropose,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let mut nested_fx_overlay = fx_overlay.clone();
    let instruction_target = merge_instruction_dataspace_targets_with_world_and_fx_overlay(
        propose.instructions.iter(),
        dataspace_catalog,
        world,
        ledger_time_ms,
        &mut nested_fx_overlay,
    )?;
    Ok(instruction_target.map_or_else(
        || account_dataspace_target(Some(world), &propose.account, ledger_time_ms),
        |target| Ok(Some(target)),
    )?)
}
fn trigger_executable_requires_universal_coordinator(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, RoutingResolveError> {
    match executable {
        Executable::ContractCall(call) => {
            Ok(contract_address_dataspace_target(&call.contract_address)
                == Some(DataSpaceId::UNIVERSAL))
        }
        Executable::Instructions(instructions) => {
            if trigger_executable_concrete_dataspace_targets(
                executable,
                dataspace_catalog,
                state_view,
            )?
            .len()
                > 1
            {
                return Ok(true);
            }
            for instruction in instructions {
                if instruction_transaction_target_requires_universal_coordinator(
                    &**instruction,
                    dataspace_catalog,
                    state_view,
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Executable::Batch(items) => {
            if trigger_executable_concrete_dataspace_targets(
                executable,
                dataspace_catalog,
                state_view,
            )?
            .len()
                > 1
            {
                return Ok(true);
            }
            for item in items {
                let requires_coordinator = match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        instruction_transaction_target_requires_universal_coordinator(
                            &**instruction,
                            dataspace_catalog,
                            state_view,
                        )?
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        contract_address_dataspace_target(&call.contract_address)
                            == Some(DataSpaceId::UNIVERSAL)
                    }
                };
                if requires_coordinator {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Executable::Ivm(_) => Ok(false),
        Executable::IvmProved(proved) => {
            if trigger_executable_concrete_dataspace_targets(
                executable,
                dataspace_catalog,
                state_view,
            )?
            .len()
                > 1
            {
                return Ok(true);
            }
            for instruction in &proved.overlay {
                if instruction_transaction_target_requires_universal_coordinator(
                    &**instruction,
                    dataspace_catalog,
                    state_view,
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}
fn trigger_executable_requires_universal_coordinator_with_world<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, RoutingResolveError> {
    match executable {
        Executable::ContractCall(call) => {
            Ok(contract_address_dataspace_target(&call.contract_address)
                == Some(DataSpaceId::UNIVERSAL))
        }
        Executable::Instructions(instructions) => {
            if trigger_executable_concrete_dataspace_targets_with_world(
                executable,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?
            .len()
                > 1
            {
                return Ok(true);
            }
            for instruction in instructions {
                if instruction_transaction_target_requires_universal_coordinator_with_world(
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Executable::Batch(items) => {
            if trigger_executable_concrete_dataspace_targets_with_world(
                executable,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?
            .len()
                > 1
            {
                return Ok(true);
            }
            for item in items {
                let requires_coordinator = match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        instruction_transaction_target_requires_universal_coordinator_with_world(
                            &**instruction,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                        )?
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        contract_address_dataspace_target(&call.contract_address)
                            == Some(DataSpaceId::UNIVERSAL)
                    }
                };
                if requires_coordinator {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Executable::Ivm(_) => Ok(false),
        Executable::IvmProved(proved) => {
            if trigger_executable_concrete_dataspace_targets_with_world(
                executable,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?
            .len()
                > 1
            {
                return Ok(true);
            }
            for instruction in &proved.overlay {
                if instruction_transaction_target_requires_universal_coordinator_with_world(
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}
fn instruction_transaction_target_requires_universal_coordinator(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, RoutingResolveError> {
    if let Some(operation) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1>(
    ) {
        let view = state_view.ok_or_else(|| RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "KAGEMUSHA routing requires original World state".into(),
        })?;
        let target = kagemusha_dataspace_with_world(view.world(), operation)?;
        return Ok(target == DataSpaceId::UNIVERSAL);
    }
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        let targets = transfer_batch_targets_with_view(batch, dataspace_catalog, state_view)?;
        return Ok(targets.len() > 1 || targets.contains(&DataSpaceId::UNIVERSAL));
    }
    if let Some(atomic) = settlement_atomic::instruction(instruction) {
        return settlement_atomic::requires_universal_coordinator(atomic);
    }

    if instruction_routes_to_universal_dataspace(instruction) {
        return Ok(true);
    }
    if musubi_instruction_requires_universal_coordinator(any) {
        return Ok(true);
    }
    if any
        .downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
        .is_some()
        || any
            .downcast_ref::<AbortAtomicPrivateSettlementV1>()
            .is_some()
        || any
            .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
            .is_some()
    {
        return Ok(true);
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        // Concrete-target collection below is cycle-guarded and completes before the recursive
        // coordinator scan, preventing a cyclic payload from reaching that scan.
        let instructions = match multisig {
            MultisigInstructionBox::Propose(propose) => Some(propose.instructions),
            MultisigInstructionBox::Approve(approve) => match state_view {
                Some(view) => multisig_proposal_state_raw(
                    view.world(),
                    &approve.account,
                    &approve.instructions_hash,
                )?
                .map(|proposal| proposal.instructions),
                None => None,
            },
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => None,
        };
        let Some(instructions) = instructions else {
            return Ok(false);
        };
        let mut concrete_dataspaces = BTreeSet::new();
        for nested in &instructions {
            extend_instruction_concrete_dataspace_targets(
                &mut concrete_dataspaces,
                &**nested,
                dataspace_catalog,
                state_view,
            )?;
        }
        if concrete_dataspaces.len() > 1 {
            return Ok(true);
        }
        for nested in &instructions {
            if instruction_transaction_target_requires_universal_coordinator(
                &**nested,
                dataspace_catalog,
                state_view,
            )? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if let Some(RegisterBox::Trigger(register)) = any.downcast_ref::<RegisterBox>() {
        return trigger_executable_requires_universal_coordinator(
            register.object.action().executable(),
            dataspace_catalog,
            state_view,
        );
    }
    if any.is::<SetFxCorridorPolicy>()
        || matches!(
            any.downcast_ref::<SettlementInstructionBox>(),
            Some(SettlementInstructionBox::SetFxCorridorPolicy(_))
        )
    {
        return Ok(true);
    }
    if let Some(fx) = any.downcast_ref::<SettleFxCorridor>() {
        return fx_corridor_policy_with_state(state_view, &fx.policy_id)
            .map(|policy| policy.source_dataspace != policy.destination_dataspace);
    }
    if let Some(SettlementInstructionBox::SettleFxCorridor(fx)) =
        any.downcast_ref::<SettlementInstructionBox>()
    {
        return fx_corridor_policy_with_state(state_view, &fx.policy_id)
            .map(|policy| policy.source_dataspace != policy.destination_dataspace);
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>()
        && let TransferBox::Asset(transfer) = transfer
    {
        let definition_target = asset_balance_definition_route_target(
            &transfer.source.definition,
            dataspace_catalog,
            state_view,
        )?;
        return Ok(asset_id_explicit_dataspace_target(&transfer.source)
            == Some(DataSpaceId::UNIVERSAL)
            || definition_target.balance_scope_policy == Some(AssetBalancePolicy::Global));
    }
    if let Some(mint) = any.downcast_ref::<MintBox>()
        && let MintBox::Asset(mint) = mint
    {
        let definition_target = asset_balance_definition_route_target(
            &mint.destination.definition,
            dataspace_catalog,
            state_view,
        )?;
        return Ok(asset_id_explicit_dataspace_target(&mint.destination)
            == Some(DataSpaceId::UNIVERSAL)
            || definition_target.balance_scope_policy == Some(AssetBalancePolicy::Global));
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>()
        && let BurnBox::Asset(burn) = burn
    {
        let definition_target = asset_balance_definition_route_target(
            &burn.destination.definition,
            dataspace_catalog,
            state_view,
        )?;
        return Ok(asset_id_explicit_dataspace_target(&burn.destination)
            == Some(DataSpaceId::UNIVERSAL)
            || definition_target.balance_scope_policy == Some(AssetBalancePolicy::Global));
    }
    if let Some(register_zk_asset) = any.downcast_ref::<RegisterZkAsset>() {
        return asset_definition_requires_universal_coordinator(
            &register_zk_asset.asset,
            dataspace_catalog,
            state_view,
        );
    }
    if let Some(schedule_transition) = any.downcast_ref::<ScheduleConfidentialPolicyTransition>() {
        return asset_definition_requires_universal_coordinator(
            &schedule_transition.asset,
            dataspace_catalog,
            state_view,
        );
    }
    if let Some(cancel_transition) = any.downcast_ref::<CancelConfidentialPolicyTransition>() {
        return asset_definition_requires_universal_coordinator(
            &cancel_transition.asset,
            dataspace_catalog,
            state_view,
        );
    }
    Ok(false)
}
fn instruction_transaction_target_requires_universal_coordinator_with_world<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        let targets =
            transfer_batch_targets_with_world(batch, dataspace_catalog, world, ledger_time_ms)?;
        return Ok(targets.len() > 1 || targets.contains(&DataSpaceId::UNIVERSAL));
    }
    if let Some(atomic) = settlement_atomic::instruction(instruction) {
        return settlement_atomic::requires_universal_coordinator(atomic);
    }

    if instruction_routes_to_universal_dataspace(instruction) {
        return Ok(true);
    }
    if musubi_instruction_requires_universal_coordinator(any) {
        return Ok(true);
    }
    if any
        .downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
        .is_some()
        || any
            .downcast_ref::<AbortAtomicPrivateSettlementV1>()
            .is_some()
        || any
            .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
            .is_some()
    {
        return Ok(true);
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        // Concrete-target collection below is cycle-guarded and completes before the recursive
        // coordinator scan, preventing a cyclic payload from reaching that scan.
        let instructions = match multisig {
            MultisigInstructionBox::Propose(propose) => Some(propose.instructions),
            MultisigInstructionBox::Approve(approve) => {
                multisig_proposal_state_raw(world, &approve.account, &approve.instructions_hash)?
                    .map(|proposal| proposal.instructions)
            }
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => None,
        };
        let Some(instructions) = instructions else {
            return Ok(false);
        };
        let mut concrete_dataspaces = BTreeSet::new();
        for nested in &instructions {
            extend_instruction_concrete_dataspace_targets_with_world(
                &mut concrete_dataspaces,
                &**nested,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )?;
        }
        if concrete_dataspaces.len() > 1 {
            return Ok(true);
        }
        for nested in &instructions {
            if instruction_transaction_target_requires_universal_coordinator_with_world(
                &**nested,
                dataspace_catalog,
                world,
                ledger_time_ms,
            )? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if let Some(RegisterBox::Trigger(register)) = any.downcast_ref::<RegisterBox>() {
        return trigger_executable_requires_universal_coordinator_with_world(
            register.object.action().executable(),
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    if any.is::<SetFxCorridorPolicy>()
        || matches!(
            any.downcast_ref::<SettlementInstructionBox>(),
            Some(SettlementInstructionBox::SetFxCorridorPolicy(_))
        )
    {
        return Ok(true);
    }
    if let Some(fx) = any.downcast_ref::<SettleFxCorridor>() {
        return fx_corridor_policy_with_world(world, &fx.policy_id)
            .map(|policy| policy.source_dataspace != policy.destination_dataspace);
    }
    if let Some(SettlementInstructionBox::SettleFxCorridor(fx)) =
        any.downcast_ref::<SettlementInstructionBox>()
    {
        return fx_corridor_policy_with_world(world, &fx.policy_id)
            .map(|policy| policy.source_dataspace != policy.destination_dataspace);
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>()
        && let TransferBox::Asset(transfer) = transfer
    {
        let definition_target = asset_balance_definition_route_target_with_world(
            &transfer.source.definition,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?;
        return Ok(asset_id_explicit_dataspace_target(&transfer.source)
            == Some(DataSpaceId::UNIVERSAL)
            || definition_target.balance_scope_policy == Some(AssetBalancePolicy::Global));
    }
    if let Some(mint) = any.downcast_ref::<MintBox>()
        && let MintBox::Asset(mint) = mint
    {
        let definition_target = asset_balance_definition_route_target_with_world(
            &mint.destination.definition,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?;
        return Ok(asset_id_explicit_dataspace_target(&mint.destination)
            == Some(DataSpaceId::UNIVERSAL)
            || definition_target.balance_scope_policy == Some(AssetBalancePolicy::Global));
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>()
        && let BurnBox::Asset(burn) = burn
    {
        let definition_target = asset_balance_definition_route_target_with_world(
            &burn.destination.definition,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?;
        return Ok(asset_id_explicit_dataspace_target(&burn.destination)
            == Some(DataSpaceId::UNIVERSAL)
            || definition_target.balance_scope_policy == Some(AssetBalancePolicy::Global));
    }
    if let Some(register_zk_asset) = any.downcast_ref::<RegisterZkAsset>() {
        return asset_definition_requires_universal_coordinator_with_world(
            &register_zk_asset.asset,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    if let Some(schedule_transition) = any.downcast_ref::<ScheduleConfidentialPolicyTransition>() {
        return asset_definition_requires_universal_coordinator_with_world(
            &schedule_transition.asset,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    if let Some(cancel_transition) = any.downcast_ref::<CancelConfidentialPolicyTransition>() {
        return asset_definition_requires_universal_coordinator_with_world(
            &cancel_transition.asset,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    Ok(false)
}
fn trigger_executable_requires_universal_coordinator_with_world_and_fx_overlay<W: WorldReadOnly>(
    executable: &Executable,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &mut FxCorridorRoutingOverlay,
) -> Result<bool, RoutingResolveError> {
    let mut concrete_dataspaces = BTreeSet::new();
    let mut requires_universal_coordinator = false;
    match executable {
        Executable::ContractCall(call) => {
            return Ok(contract_address_dataspace_target(&call.contract_address)
                == Some(DataSpaceId::UNIVERSAL));
        }
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay(
                    &mut concrete_dataspaces,
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    fx_overlay,
                )?;
                requires_universal_coordinator |=
                    instruction_transaction_target_requires_universal_coordinator_with_world_and_fx_overlay(
                        &**instruction,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                        fx_overlay,
                    )?;
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay(
                            &mut concrete_dataspaces,
                            &**instruction,
                            dataspace_catalog,
                            world,
                            ledger_time_ms,
                            fx_overlay,
                        )?;
                        requires_universal_coordinator |=
                            instruction_transaction_target_requires_universal_coordinator_with_world_and_fx_overlay(
                                &**instruction,
                                dataspace_catalog,
                                world,
                                ledger_time_ms,
                                fx_overlay,
                            )?;
                        observe_top_level_instruction_fx_effects(
                            fx_overlay,
                            &**instruction,
                            usize::MAX,
                            &[],
                            world,
                        )?;
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        let target = contract_address_dataspace_target(&call.contract_address);
                        if let Some(target) = target {
                            concrete_dataspaces.insert(target);
                        }
                        requires_universal_coordinator |= target == Some(DataSpaceId::UNIVERSAL);
                    }
                }
            }
        }
        Executable::Ivm(_) => {}
        Executable::IvmProved(proved) => {
            for instruction in &proved.overlay {
                extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay(
                    &mut concrete_dataspaces,
                    &**instruction,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    fx_overlay,
                )?;
                requires_universal_coordinator |=
                    instruction_transaction_target_requires_universal_coordinator_with_world_and_fx_overlay(
                        &**instruction,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                        fx_overlay,
                    )?;
                observe_top_level_instruction_fx_effects(
                    fx_overlay,
                    &**instruction,
                    usize::MAX,
                    &[],
                    world,
                )?;
            }
        }
    }
    Ok(requires_universal_coordinator || concrete_dataspaces.len() > 1)
}
fn instruction_transaction_target_requires_universal_coordinator_with_world_and_fx_overlay<
    W: WorldReadOnly,
>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
    fx_overlay: &FxCorridorRoutingOverlay,
) -> Result<bool, RoutingResolveError> {
    if let Some(operation) = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1>(
    ) {
        let target = kagemusha_dataspace_with_world(world, operation)?;
        return Ok(target == DataSpaceId::UNIVERSAL);
    }
    let any = instruction.as_any();
    if instruction_routes_to_universal_dataspace(instruction) {
        return Ok(true);
    }
    if let Some(multisig) = multisig_instruction(instruction)? {
        // Concrete-target collection below is cycle-guarded and completes before the recursive
        // coordinator scan, preventing a cyclic payload from reaching that scan.
        let instructions = match multisig {
            MultisigInstructionBox::Propose(propose) => Some(propose.instructions),
            MultisigInstructionBox::Approve(approve) => fx_overlay
                .multisig_proposal_instructions_with_world(
                    world,
                    &approve.account,
                    &approve.instructions_hash,
                )?,
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => None,
        };
        let Some(instructions) = instructions else {
            return Ok(false);
        };
        let mut concrete_dataspaces = BTreeSet::new();
        let mut nested_fx_overlay = fx_overlay.clone();
        let mut requires_universal_coordinator = false;
        for nested in &instructions {
            extend_instruction_concrete_dataspace_targets_with_world_and_fx_overlay(
                &mut concrete_dataspaces,
                &**nested,
                dataspace_catalog,
                world,
                ledger_time_ms,
                &nested_fx_overlay,
            )?;
            requires_universal_coordinator |=
                instruction_transaction_target_requires_universal_coordinator_with_world_and_fx_overlay(
                    &**nested,
                    dataspace_catalog,
                    world,
                    ledger_time_ms,
                    &nested_fx_overlay,
                )?;
            observe_top_level_instruction_fx_effects(
                &mut nested_fx_overlay,
                &**nested,
                usize::MAX,
                &[],
                world,
            )?;
        }
        return Ok(requires_universal_coordinator || concrete_dataspaces.len() > 1);
    }
    if let Some(RegisterBox::Trigger(register)) = any.downcast_ref::<RegisterBox>() {
        let mut nested_fx_overlay = fx_overlay.clone();
        return trigger_executable_requires_universal_coordinator_with_world_and_fx_overlay(
            register.object.action().executable(),
            dataspace_catalog,
            world,
            ledger_time_ms,
            &mut nested_fx_overlay,
        );
    }
    if any.is::<SetFxCorridorPolicy>()
        || matches!(
            any.downcast_ref::<SettlementInstructionBox>(),
            Some(SettlementInstructionBox::SetFxCorridorPolicy(_))
        )
    {
        return Ok(true);
    }
    let settle = any.downcast_ref::<SettleFxCorridor>().or_else(|| {
        any.downcast_ref::<SettlementInstructionBox>()
            .and_then(|settlement| match settlement {
                SettlementInstructionBox::SettleFxCorridor(settle) => Some(settle),
                SettlementInstructionBox::Atomic(_)
                | SettlementInstructionBox::Dvp(_)
                | SettlementInstructionBox::Pvp(_)
                | SettlementInstructionBox::SetFxCorridorPolicy(_)
                | SettlementInstructionBox::FundFxCorridorEscrow(_)
                | SettlementInstructionBox::RefundFxCorridorEscrow(_) => None,
            })
    });
    if let Some(settle) = settle {
        let policy = fx_overlay.policy_with_world(world, &settle.policy_id)?;
        return Ok(policy.source_dataspace != policy.destination_dataspace);
    }
    instruction_transaction_target_requires_universal_coordinator_with_world(
        instruction,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )
}
fn account_dataspace_target<W: WorldReadOnly>(
    world: Option<&W>,
    account_id: &AccountId,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, ExecutionDeferred> {
    let Some(world) = world else {
        return Ok(None);
    };
    // A persisted directory remains authoritative; SNS fallback cannot narrow it.
    if world.account_scope_directory().get(account_id).is_some() {
        let Ok(hierarchy) = world.account_scope_hierarchy(account_id) else {
            return Ok(None);
        };
        let mut dataspaces = hierarchy.keys();
        let Some(&dataspace_id) = dataspaces.next() else {
            return Ok(None);
        };
        if dataspaces.next().is_some() {
            return Ok(Some(DataSpaceId::UNIVERSAL));
        }
        return Ok((dataspace_id != DataSpaceId::UNIVERSAL).then_some(dataspace_id));
    }
    let Some(account) = world.accounts().get(account_id) else {
        return Ok(None);
    };
    let mut dataspaces = BTreeSet::new();
    let mut primary_dataspace = None;
    if let Some(now_ms) = ledger_time_ms {
        if let Some(label) = account.as_ref().label()
            && original_account_alias_matches(
                world,
                world.dataspace_catalog(),
                label,
                account_id,
                now_ms,
            )?
        {
            primary_dataspace = Some(label.dataspace);
            dataspaces.insert(label.dataspace);
        }
        for alias in world.bound_account_aliases(account_id) {
            if original_account_alias_matches(
                world,
                world.dataspace_catalog(),
                &alias,
                account_id,
                now_ms,
            )? {
                dataspaces.insert(alias.dataspace);
            }
        }
    }
    if let Some(uaid) = account.as_ref().uaid().copied()
        && let Some(bindings) = world.uaid_dataspaces().get(&uaid)
    {
        dataspaces.extend(bindings.iter().filter_map(|(dataspace, accounts)| {
            accounts.contains(account_id).then_some(*dataspace)
        }));
    }
    if primary_dataspace.is_none_or(|dataspace| dataspace == DataSpaceId::UNIVERSAL) {
        dataspaces.insert(DataSpaceId::UNIVERSAL);
    }
    if dataspaces.len() > 1 {
        return Ok(Some(DataSpaceId::UNIVERSAL));
    }
    Ok(dataspaces
        .iter()
        .next()
        .copied()
        .filter(|dataspace| *dataspace != DataSpaceId::UNIVERSAL))
}
fn authority_dataspace_target_with_world<W: WorldReadOnly>(
    world: Option<&W>,
    tx: &dyn TransactionRoutingView,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, ExecutionDeferred> {
    match tx.authority_opt() {
        Some(authority) => account_dataspace_target(world, authority, ledger_time_ms),
        None => Ok(None),
    }
}
fn domain_dataspace_target_with_state(
    domain_id: &DomainId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    dataspace_alias_target_with_state(
        domain_id.dataspace().as_ref(),
        dataspace_catalog,
        state_view,
    )
}
fn domain_dataspace_target_with_world<W: WorldReadOnly>(
    domain_id: &DomainId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    dataspace_alias_target_with_world(
        domain_id.dataspace().as_ref(),
        dataspace_catalog,
        world,
        ledger_time_ms,
    )
}
fn contract_address_dataspace_target(contract_address: &ContractAddress) -> Option<DataSpaceId> {
    contract_address.dataspace_id().ok()
}
fn musubi_package_dataspace_target(package: &MusubiPackageIdV1) -> DataSpaceId {
    package.home_dataspace
}
fn musubi_instruction_dataspace_target(any: &dyn core::any::Any) -> Option<DataSpaceId> {
    if let Some(register) = any.downcast_ref::<RegisterMusubiNamespaceBindingV1>() {
        return Some(register.binding.home_dataspace);
    }
    if any.downcast_ref::<RegisterMusubiArchiveV1>().is_some()
        || any.downcast_ref::<AdvanceMusubiPinOutboxV1>().is_some()
        || any.downcast_ref::<CheckMusubiPinOutboxV1>().is_some()
        || any
            .downcast_ref::<RegisterMusubiProviderBundleAttestationV1>()
            .is_some()
        || any.downcast_ref::<AddMusubiArchiveLocationV1>().is_some()
        || any
            .downcast_ref::<RetireMusubiArchiveLocationV1>()
            .is_some()
        || any.downcast_ref::<SetMusubiRegistryPolicyV1>().is_some()
    {
        return Some(DataSpaceId::UNIVERSAL);
    }
    if let Some(publish) = any.downcast_ref::<PublishMusubiReleaseV1>() {
        return Some(musubi_package_dataspace_target(
            &publish.publication.manifest.release.package,
        ));
    }
    if let Some(yank) = any.downcast_ref::<SetMusubiReleaseYankV1>() {
        return Some(musubi_package_dataspace_target(&yank.release.package));
    }
    if let Some(metadata) = any.downcast_ref::<SetMusubiPackageMetadataV1>() {
        return Some(musubi_package_dataspace_target(&metadata.package));
    }
    if let Some(invite) = any.downcast_ref::<InviteMusubiPackageMaintainerV1>() {
        return Some(musubi_package_dataspace_target(&invite.package));
    }
    if let Some(accept) = any.downcast_ref::<AcceptMusubiPackageMaintainerV1>() {
        return Some(musubi_package_dataspace_target(&accept.package));
    }
    if let Some(revoke) = any.downcast_ref::<RevokeMusubiPackageMaintainerInvitationV1>() {
        return Some(musubi_package_dataspace_target(&revoke.package));
    }
    if let Some(set_role) = any.downcast_ref::<SetMusubiPackageMaintainerRoleV1>() {
        return Some(musubi_package_dataspace_target(&set_role.package));
    }
    if let Some(remove) = any.downcast_ref::<RemoveMusubiPackageMaintainerV1>() {
        return Some(musubi_package_dataspace_target(&remove.package));
    }
    if let Some(register) = any.downcast_ref::<RegisterMusubiAliasV1>() {
        return Some(musubi_package_dataspace_target(&register.target));
    }
    if let Some(recover) = any.downcast_ref::<RecoverMusubiPackageV1>() {
        return Some(musubi_package_dataspace_target(&recover.package));
    }
    if let Some(retarget) = any.downcast_ref::<RetargetMusubiAliasV1>() {
        return Some(musubi_package_dataspace_target(&retarget.target));
    }
    if let Some(takedown) = any.downcast_ref::<SetMusubiArtifactTakedownV1>() {
        return Some(musubi_package_dataspace_target(&takedown.release.package));
    }
    if let Some(assert) = any.downcast_ref::<AssertMusubiReleaseDigestV1>() {
        return Some(musubi_package_dataspace_target(&assert.release.package));
    }
    None
}
fn musubi_instruction_requires_universal_coordinator(any: &dyn core::any::Any) -> bool {
    any.downcast_ref::<RegisterMusubiNamespaceBindingV1>()
        .is_some()
        || any.downcast_ref::<PublishMusubiReleaseV1>().is_some()
        || any.downcast_ref::<SetMusubiReleaseYankV1>().is_some()
        || any.downcast_ref::<SetMusubiPackageMetadataV1>().is_some()
        || any.downcast_ref::<RegisterMusubiAliasV1>().is_some()
        || any.downcast_ref::<RecoverMusubiPackageV1>().is_some()
        || any.downcast_ref::<RetargetMusubiAliasV1>().is_some()
        || any.downcast_ref::<SetMusubiArtifactTakedownV1>().is_some()
}
fn dataspace_alias_target(
    dataspace_alias: &str,
    dataspace_catalog: Option<&DataSpaceCatalog>,
) -> Option<DataSpaceId> {
    if dataspace_alias.eq_ignore_ascii_case("universal") {
        return Some(DataSpaceId::UNIVERSAL);
    }
    dataspace_catalog?
        .by_alias(dataspace_alias)
        .map(|entry| entry.id)
}
fn dataspace_alias_target_with_state(
    dataspace_alias: &str,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let Some(view) = state_view else {
        return Ok(dataspace_alias_target(dataspace_alias, dataspace_catalog));
    };
    dataspace_alias_target_with_world(
        dataspace_alias,
        dataspace_catalog,
        view.world(),
        Some(state_view_ledger_time_ms(view)),
    )
}
fn dataspace_alias_target_with_world<W: WorldReadOnly>(
    dataspace_alias: &str,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let Some(catalog) = dataspace_catalog else {
        return Ok(None);
    };
    let Some(now_ms) = ledger_time_ms else {
        return Ok(dataspace_alias_target(dataspace_alias, Some(catalog)));
    };
    match crate::sns::resolve_active_dataspace_id_by_alias(world, catalog, dataspace_alias, now_ms)
    {
        Ok(dataspace_id) => Ok(Some(dataspace_id)),
        Err(crate::sns::SnsError::NotFound(_)) => Ok(None),
        Err(crate::sns::SnsError::Deferred(reason)) => {
            if cfg!(all(test, sumeragi_core_mutation = "HC38")) {
                return Err(RoutingResolveError::DataspaceAliasResolution {
                    alias: dataspace_alias.to_owned(),
                    reason: reason.to_string(),
                });
            }
            Err(reason.into())
        }
        Err(error) => Err(RoutingResolveError::DataspaceAliasResolution {
            alias: dataspace_alias.to_owned(),
            reason: error.to_string(),
        }),
    }
}
fn state_view_ledger_time_ms(state_view: &StateView<'_>) -> u64 {
    // The immutable view captured this committed ledger time with its original State cut.
    // Routing only needs that fixed metadata, so it does not acquire a block body.
    state_view.query_ledger_time_ms()
}
fn asset_definition_target_from_parts_with_state(
    asset_definition_id: &AssetDefinitionId,
    asset_definition_alias: Option<&AssetDefinitionAlias>,
    owning_domain: Option<&DomainId>,
    balance_scope_policy: Option<AssetBalancePolicy>,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    if let Some(view) = state_view
        && let Some(dataspace) = view
            .world
            .asset_definition_dataspace(asset_definition_id)
            .map_err(|error| RoutingResolveError::OrdinaryRouteUnavailable {
                reason: format!("invalid asset-definition home: {error}"),
            })?
    {
        return Ok(Some(dataspace));
    }
    let dataspace_alias = asset_definition_alias
        .map(|alias| alias.dataspace_segment().to_owned())
        .or_else(|| {
            state_view.and_then(|view| {
                view.world
                    .asset_definition_domains()
                    .get(asset_definition_id)
                    .map(|domain| domain.dataspace().as_ref().to_owned())
            })
        })
        .or_else(|| owning_domain.map(|domain| domain.dataspace().as_ref().to_owned()));
    let Some(dataspace_alias) = dataspace_alias else {
        return Ok(balance_scope_policy
            .is_some_and(|policy| policy == AssetBalancePolicy::Global)
            .then_some(DataSpaceId::UNIVERSAL));
    };
    dataspace_alias_target_with_state(&dataspace_alias, dataspace_catalog, state_view)
}
fn asset_definition_target_from_parts_with_world<W: WorldReadOnly>(
    asset_definition_id: &AssetDefinitionId,
    asset_definition_alias: Option<&AssetDefinitionAlias>,
    owning_domain: Option<&DomainId>,
    balance_scope_policy: Option<AssetBalancePolicy>,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    if let Some(dataspace) = world
        .asset_definition_dataspace(asset_definition_id)
        .map_err(|error| RoutingResolveError::OrdinaryRouteUnavailable {
            reason: format!("invalid asset-definition home: {error}"),
        })?
    {
        return Ok(Some(dataspace));
    }
    let dataspace_alias = asset_definition_alias
        .map(|alias| alias.dataspace_segment().to_owned())
        .or_else(|| {
            world
                .asset_definition_domains()
                .get(asset_definition_id)
                .map(|domain| domain.dataspace().as_ref().to_owned())
        })
        .or_else(|| owning_domain.map(|domain| domain.dataspace().as_ref().to_owned()));
    let Some(dataspace_alias) = dataspace_alias else {
        return Ok(balance_scope_policy
            .is_some_and(|policy| policy == AssetBalancePolicy::Global)
            .then_some(DataSpaceId::UNIVERSAL));
    };
    dataspace_alias_target_with_world(&dataspace_alias, dataspace_catalog, world, ledger_time_ms)
}
fn trigger_executable_transaction_target_needs_state(executable: &Executable) -> bool {
    match executable {
        Executable::Instructions(instructions) => instructions.iter().any(|instruction| {
            instruction_transaction_dataspace_target_needs_state(&**instruction)
        }),
        Executable::ContractCall(_) | Executable::Ivm(_) => false,
        Executable::Batch(items) => items.iter().any(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => {
                instruction_transaction_dataspace_target_needs_state(&**instruction)
            }
            ExecutableBatchItem::ContractCall(_) => false,
        }),
        Executable::IvmProved(proved) => proved.overlay.iter().any(|instruction| {
            instruction_transaction_dataspace_target_needs_state(&**instruction)
        }),
    }
}
fn instruction_transaction_dataspace_target_needs_state(instruction: &dyn Instruction) -> bool {
    let any = instruction.as_any();
    if any.is::<iroha_data_model::isi::retail_daily_limit::RetailMonetaryMovementV1>() {
        return true;
    }
    if any.is::<TransferAssetBatch>() {
        return true;
    }
    if settlement_atomic::instruction(instruction).is_some() {
        // Every movement binds an explicit scope; aliases cannot alter the signed routes.
        return false;
    }

    if instruction_routes_to_universal_dataspace(instruction) {
        return false;
    }
    if any.downcast_ref::<SettleFxCorridor>().is_some() {
        return true;
    }
    if let Some(settlement) = any.downcast_ref::<SettlementInstructionBox>()
        && matches!(settlement, SettlementInstructionBox::SettleFxCorridor(_))
    {
        return true;
    }
    if any.is::<CustomInstruction>() {
        // Classification needs the state-backed fallible route path. Never turn an unfinished
        // custom decode into a claim that no authoritative state is required.
        return true;
    }
    if let Ok(Some(multisig)) = multisig_instruction(instruction) {
        return match multisig {
            MultisigInstructionBox::Propose(_) | MultisigInstructionBox::Approve(_) => true,
            MultisigInstructionBox::Register(_)
            | MultisigInstructionBox::Cancel(_)
            | MultisigInstructionBox::InvalidateOutstanding(_) => false,
        };
    }
    if any.downcast_ref::<MultisigPropose>().is_some() {
        return true;
    }
    if any.downcast_ref::<MultisigApprove>().is_some() {
        return true;
    }
    if let Some(register) = any.downcast_ref::<RegisterBox>() {
        return match register {
            RegisterBox::Trigger(register) => trigger_executable_transaction_target_needs_state(
                register.object.action().executable(),
            ),
            RegisterBox::Domain(_) | RegisterBox::Nft(_) => true,
            RegisterBox::AssetDefinition(register) => {
                register.object.alias.is_some() || register.object.owning_domain.is_some()
            }
            RegisterBox::Account(_) | RegisterBox::Peer(_) | RegisterBox::Role(_) => false,
        };
    }
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant) => {
                dataspace_scoped_permission_target_needs_state(&grant.object)
            }
            GrantBox::RolePermission(grant) => {
                dataspace_scoped_permission_target_needs_state(&grant.object)
            }
            GrantBox::Role(_) => false,
        };
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return match revoke {
            RevokeBox::Permission(revoke) => {
                dataspace_scoped_permission_target_needs_state(&revoke.object)
            }
            RevokeBox::RolePermission(revoke) => {
                dataspace_scoped_permission_target_needs_state(&revoke.object)
            }
            RevokeBox::Role(_) => false,
        };
    }
    if any.downcast_ref::<DvpIsi>().is_some() {
        return true;
    }
    if any.downcast_ref::<PvpIsi>().is_some() {
        return true;
    }
    if any.downcast_ref::<SettleFxCorridor>().is_some()
        || any.downcast_ref::<FundFxCorridorEscrow>().is_some()
        || any.downcast_ref::<RefundFxCorridorEscrow>().is_some()
    {
        return true;
    }
    if let Some(settlement) = any.downcast_ref::<SettlementInstructionBox>() {
        return match settlement {
            SettlementInstructionBox::Atomic(_) => false,
            SettlementInstructionBox::Dvp(_) | SettlementInstructionBox::Pvp(_) => true,
            SettlementInstructionBox::SetFxCorridorPolicy(_) => false,
            SettlementInstructionBox::FundFxCorridorEscrow(_)
            | SettlementInstructionBox::RefundFxCorridorEscrow(_)
            | SettlementInstructionBox::SettleFxCorridor(_) => true,
        };
    }
    if let Some(unregister) = any.downcast_ref::<UnregisterBox>() {
        return matches!(
            unregister,
            UnregisterBox::Domain(_) | UnregisterBox::AssetDefinition(_) | UnregisterBox::Nft(_)
        );
    }
    if let Some(set_key_value) = any.downcast_ref::<SetKeyValueBox>() {
        return matches!(
            set_key_value,
            SetKeyValueBox::Domain(_)
                | SetKeyValueBox::Account(_)
                | SetKeyValueBox::AssetDefinition(_)
                | SetKeyValueBox::Nft(_)
        );
    }
    if let Some(remove_key_value) = any.downcast_ref::<RemoveKeyValueBox>() {
        return matches!(
            remove_key_value,
            RemoveKeyValueBox::Domain(_)
                | RemoveKeyValueBox::Account(_)
                | RemoveKeyValueBox::AssetDefinition(_)
                | RemoveKeyValueBox::Nft(_)
        );
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>() {
        return match transfer {
            TransferBox::Domain(_)
            | TransferBox::AssetDefinition(_)
            | TransferBox::Asset(_)
            | TransferBox::Nft(_) => true,
        };
    }
    if let Some(mint) = any.downcast_ref::<MintBox>() {
        return matches!(mint, MintBox::Asset(_));
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>() {
        return matches!(burn, BurnBox::Asset(_));
    }
    if any.downcast_ref::<RegisterZkAsset>().is_some()
        || any
            .downcast_ref::<ScheduleConfidentialPolicyTransition>()
            .is_some()
        || any
            .downcast_ref::<CancelConfidentialPolicyTransition>()
            .is_some()
    {
        return true;
    }
    false
}
fn instruction_dataspace_scoped_permission_target(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant) => {
                dataspace_scoped_permission_target(&grant.object, dataspace_catalog, state_view)
            }
            GrantBox::RolePermission(grant) => {
                dataspace_scoped_permission_target(&grant.object, dataspace_catalog, state_view)
            }
            GrantBox::Role(_) => Ok(None),
        };
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return match revoke {
            RevokeBox::Permission(revoke) => {
                dataspace_scoped_permission_target(&revoke.object, dataspace_catalog, state_view)
            }
            RevokeBox::RolePermission(revoke) => {
                dataspace_scoped_permission_target(&revoke.object, dataspace_catalog, state_view)
            }
            RevokeBox::Role(_) => Ok(None),
        };
    }
    Ok(None)
}
fn instruction_dataspace_scoped_permission_target_with_world<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let any = instruction.as_any();
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant) => dataspace_scoped_permission_target_with_world(
                &grant.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            GrantBox::RolePermission(grant) => dataspace_scoped_permission_target_with_world(
                &grant.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            GrantBox::Role(_) => Ok(None),
        };
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return match revoke {
            RevokeBox::Permission(revoke) => dataspace_scoped_permission_target_with_world(
                &revoke.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            RevokeBox::RolePermission(revoke) => dataspace_scoped_permission_target_with_world(
                &revoke.object,
                dataspace_catalog,
                world,
                ledger_time_ms,
            ),
            RevokeBox::Role(_) => Ok(None),
        };
    }
    Ok(None)
}
fn asset_definition_dataspace_target(
    asset_definition_id: &AssetDefinitionId,
    owning_domain: Option<&DomainId>,
    balance_scope_policy: Option<AssetBalancePolicy>,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let resolved = state_view
        .and_then(|view| {
            asset_definition_for_routing(
                &view.world,
                asset_definition_id,
                Some(state_view_ledger_time_ms(view)),
            )
        })
        .map(|definition| {
            let balance_scope_policy = definition.balance_scope_policy();
            (
                definition.id,
                balance_scope_policy,
                definition.owning_domain,
                definition.alias,
            )
        });
    let effective_id = resolved
        .as_ref()
        .map(|(resolved_id, _, _, _)| resolved_id)
        .unwrap_or(asset_definition_id);
    let effective_alias = resolved
        .as_ref()
        .and_then(|(_, _, _, resolved_alias)| resolved_alias.as_ref());
    let effective_owning_domain = resolved
        .as_ref()
        .and_then(|(_, _, resolved_domain, _)| resolved_domain.as_ref())
        .or(owning_domain);
    let effective_policy = resolved
        .as_ref()
        .map(|(_, policy, _, _)| *policy)
        .or(balance_scope_policy);
    asset_definition_target_from_parts_with_state(
        effective_id,
        effective_alias,
        effective_owning_domain,
        effective_policy,
        dataspace_catalog,
        state_view,
    )
}
fn asset_definition_dataspace_target_with_world<W: WorldReadOnly>(
    asset_definition_id: &AssetDefinitionId,
    owning_domain: Option<&DomainId>,
    balance_scope_policy: Option<AssetBalancePolicy>,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let resolved = asset_definition_for_routing(world, asset_definition_id, ledger_time_ms).map(
        |definition| {
            let balance_scope_policy = definition.balance_scope_policy();
            (
                definition.id,
                balance_scope_policy,
                definition.owning_domain,
                definition.alias,
            )
        },
    );
    let effective_id = resolved
        .as_ref()
        .map(|(resolved_id, _, _, _)| resolved_id)
        .unwrap_or(asset_definition_id);
    let effective_alias = resolved
        .as_ref()
        .and_then(|(_, _, _, resolved_alias)| resolved_alias.as_ref());
    let effective_owning_domain = resolved
        .as_ref()
        .and_then(|(_, _, resolved_domain, _)| resolved_domain.as_ref())
        .or(owning_domain);
    let effective_policy = resolved
        .as_ref()
        .map(|(_, policy, _, _)| *policy)
        .or(balance_scope_policy);
    asset_definition_target_from_parts_with_world(
        effective_id,
        effective_alias,
        effective_owning_domain,
        effective_policy,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )
}
fn asset_balance_definition_route_target(
    asset_definition_id: &AssetDefinitionId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<AssetBalanceDefinitionRouteTarget, RoutingResolveError> {
    let mut confined_home = None;
    let resolved = state_view
        .and_then(|view| {
            asset_definition_for_balance_routing(
                &view.world,
                asset_definition_id,
                Some(state_view_ledger_time_ms(view)),
            )
            .map(|definition| (view, definition))
        })
        .map(|(view, definition)| {
            confined_home = Some(asset_definition_confined_home(&view.world, &definition));
            definition
        })
        .map(|definition| {
            let balance_scope_policy = definition.balance_scope_policy();
            (
                definition.id,
                balance_scope_policy,
                definition.owning_domain,
                definition.alias,
            )
        });
    let effective_id = resolved
        .as_ref()
        .map(|(resolved_id, _, _, _)| resolved_id)
        .unwrap_or(asset_definition_id);
    let effective_alias = resolved
        .as_ref()
        .and_then(|(_, _, _, resolved_alias)| resolved_alias.as_ref());
    let effective_owning_domain = resolved
        .as_ref()
        .and_then(|(_, _, resolved_domain, _)| resolved_domain.as_ref());
    let effective_policy = resolved.as_ref().map(|(_, policy, _, _)| *policy);
    let dataspace_id = if effective_policy == Some(AssetBalancePolicy::Global) {
        Some(DataSpaceId::UNIVERSAL)
    } else {
        asset_definition_target_from_parts_with_state(
            effective_id,
            effective_alias,
            effective_owning_domain,
            effective_policy,
            dataspace_catalog,
            state_view,
        )?
    };
    Ok(AssetBalanceDefinitionRouteTarget {
        dataspace_id,
        balance_scope_policy: effective_policy,
        confined_home: confined_home.transpose()?.flatten(),
    })
}
fn asset_balance_definition_dataspace_target(
    asset_definition_id: &AssetDefinitionId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    asset_balance_definition_route_target(asset_definition_id, dataspace_catalog, state_view)
        .map(|target| target.dataspace_id)
}
fn asset_balance_definition_route_target_with_world<W: WorldReadOnly>(
    asset_definition_id: &AssetDefinitionId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<AssetBalanceDefinitionRouteTarget, RoutingResolveError> {
    let definition =
        asset_definition_for_balance_routing(world, asset_definition_id, ledger_time_ms);
    let confined_home = definition
        .as_ref()
        .map(|definition| asset_definition_confined_home(world, definition))
        .transpose()?
        .flatten();
    let resolved = definition.map(|definition| {
        let balance_scope_policy = definition.balance_scope_policy();
        (
            definition.id,
            balance_scope_policy,
            definition.owning_domain,
            definition.alias,
        )
    });
    let effective_id = resolved
        .as_ref()
        .map(|(resolved_id, _, _, _)| resolved_id)
        .unwrap_or(asset_definition_id);
    let effective_alias = resolved
        .as_ref()
        .and_then(|(_, _, _, resolved_alias)| resolved_alias.as_ref());
    let effective_owning_domain = resolved
        .as_ref()
        .and_then(|(_, _, resolved_domain, _)| resolved_domain.as_ref());
    let effective_policy = resolved.as_ref().map(|(_, policy, _, _)| *policy);
    let dataspace_id = if effective_policy == Some(AssetBalancePolicy::Global) {
        Some(DataSpaceId::UNIVERSAL)
    } else {
        asset_definition_target_from_parts_with_world(
            effective_id,
            effective_alias,
            effective_owning_domain,
            effective_policy,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?
    };
    Ok(AssetBalanceDefinitionRouteTarget {
        dataspace_id,
        balance_scope_policy: effective_policy,
        confined_home,
    })
}
fn asset_balance_definition_dataspace_target_with_world<W: WorldReadOnly>(
    asset_definition_id: &AssetDefinitionId,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    asset_balance_definition_route_target_with_world(
        asset_definition_id,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )
    .map(|target| target.dataspace_id)
}
fn asset_definition_for_routing<W: WorldReadOnly>(
    world: &W,
    asset_definition_id: &AssetDefinitionId,
    ledger_time_ms: Option<u64>,
) -> Option<AssetDefinition> {
    let mut definition = world.asset_definition(asset_definition_id).ok()?;
    if definition.alias.is_none() {
        definition.alias = world
            .asset_definition_alias_bindings()
            .get(&definition.id)
            .filter(|binding| {
                ledger_time_ms.is_none_or(|now_ms| !binding.is_grace_expired_at(now_ms))
            })
            .map(|binding| binding.alias.clone());
    }
    Some(definition)
}
/// Home that confines a definition's balances, from the shared home owner used by execution.
fn asset_definition_confined_home<W: WorldReadOnly + ?Sized>(
    world: &W,
    definition: &AssetDefinition,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    crate::read_scope::confined_home(world, definition).map_err(|error| {
        RoutingResolveError::OrdinaryRouteUnavailable {
            reason: format!("invalid asset-definition home: {error}"),
        }
    })
}
fn asset_definition_for_balance_routing<W: WorldReadOnly>(
    world: &W,
    asset_definition_id: &AssetDefinitionId,
    ledger_time_ms: Option<u64>,
) -> Option<AssetDefinition> {
    let mut definition = asset_definition_for_routing(world, asset_definition_id, ledger_time_ms)?;
    if definition.balance_scope_policy() == AssetBalancePolicy::Global {
        definition.alias = None;
    }
    Some(definition)
}
fn account_alias_permission_scope_dataspace_target_with_state(
    scope: &AccountAliasPermissionScope,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    match scope {
        AccountAliasPermissionScope::Domain(domain_id) => {
            domain_dataspace_target_with_state(domain_id, dataspace_catalog, state_view)
        }
        AccountAliasPermissionScope::Dataspace(dataspace_id) => Ok(Some(*dataspace_id)),
        AccountAliasPermissionScope::Alias(alias) => Ok(Some(alias.dataspace_id)),
    }
}
fn account_alias_permission_scope_dataspace_target_with_world<W: WorldReadOnly>(
    scope: &AccountAliasPermissionScope,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    match scope {
        AccountAliasPermissionScope::Domain(domain_id) => {
            domain_dataspace_target_with_world(domain_id, dataspace_catalog, world, ledger_time_ms)
        }
        AccountAliasPermissionScope::Dataspace(dataspace_id) => Ok(Some(*dataspace_id)),
        AccountAliasPermissionScope::Alias(alias) => Ok(Some(alias.dataspace_id)),
    }
}
fn asset_definition_alias_permission_scope_dataspace_target_with_state(
    scope: &AssetDefinitionAliasPermissionScope,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    match scope {
        AssetDefinitionAliasPermissionScope::Domain(domain_id) => {
            domain_dataspace_target_with_state(domain_id, dataspace_catalog, state_view)
        }
        AssetDefinitionAliasPermissionScope::Dataspace(dataspace_id) => Ok(Some(*dataspace_id)),
        AssetDefinitionAliasPermissionScope::Alias(alias) => Ok(Some(alias.dataspace_id)),
    }
}
fn asset_definition_alias_permission_scope_dataspace_target_with_world<W: WorldReadOnly>(
    scope: &AssetDefinitionAliasPermissionScope,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    match scope {
        AssetDefinitionAliasPermissionScope::Domain(domain_id) => {
            domain_dataspace_target_with_world(domain_id, dataspace_catalog, world, ledger_time_ms)
        }
        AssetDefinitionAliasPermissionScope::Dataspace(dataspace_id) => Ok(Some(*dataspace_id)),
        AssetDefinitionAliasPermissionScope::Alias(alias) => Ok(Some(alias.dataspace_id)),
    }
}
fn dataspace_scoped_permission_target_needs_state(permission: &Permission) -> bool {
    match permission.name() {
        "CanMintAssetToAccount" => permission
            .payload()
            .try_into_any_norito::<CanMintAssetToAccount>()
            .ok()
            .is_some(),
        "CanMintAssetWithDefinition" => permission
            .payload()
            .try_into_any_norito::<CanMintAssetWithDefinition>()
            .ok()
            .is_some(),
        "CanBurnAssetWithDefinition" => permission
            .payload()
            .try_into_any_norito::<CanBurnAssetWithDefinition>()
            .ok()
            .is_some(),
        "CanTransferAssetWithDefinition" => permission
            .payload()
            .try_into_any_norito::<CanTransferAssetWithDefinition>()
            .ok()
            .is_some(),
        "CanModifyAssetMetadataWithDefinition" => permission
            .payload()
            .try_into_any_norito::<CanModifyAssetMetadataWithDefinition>()
            .ok()
            .is_some(),
        "CanUnregisterAssetDefinition" => permission
            .payload()
            .try_into_any_norito::<CanUnregisterAssetDefinition>()
            .ok()
            .is_some(),
        "CanModifyAssetDefinitionMetadata" => permission
            .payload()
            .try_into_any_norito::<CanModifyAssetDefinitionMetadata>()
            .ok()
            .is_some(),
        "CanManageKagemushaWallet" => permission
            .payload()
            .try_into_any_norito::<CanManageKagemushaWallet>()
            .ok()
            .is_some(),
        "CanManageAssetDefinitionConfidentialPolicy" => permission
            .payload()
            .try_into_any_norito::<CanManageAssetDefinitionConfidentialPolicy>()
            .ok()
            .is_some(),
        "CanManageAccountAlias" => permission
            .payload()
            .try_into_any_norito::<CanManageAccountAlias>()
            .ok()
            .is_some_and(|token| matches!(token.scope, AccountAliasPermissionScope::Domain(_))),
        "CanResolveAccountAlias" => permission
            .payload()
            .try_into_any_norito::<CanResolveAccountAlias>()
            .ok()
            .is_some_and(|token| matches!(token.scope, AccountAliasPermissionScope::Domain(_))),
        "CanDelegateAccountAliasResolution" => permission
            .payload()
            .try_into_any_norito::<CanDelegateAccountAliasResolution>()
            .ok()
            .is_some_and(|token| matches!(token.scope, AccountAliasPermissionScope::Domain(_))),
        "CanManageAssetDefinitionAlias" => permission
            .payload()
            .try_into_any_norito::<CanManageAssetDefinitionAlias>()
            .ok()
            .is_some_and(|token| {
                matches!(token.scope, AssetDefinitionAliasPermissionScope::Domain(_))
            }),
        "CanManageFeeSponsorProgram" => permission
            .payload()
            .try_into_any_norito::<CanManageFeeSponsorProgram>()
            .ok()
            .is_some(),
        "CanEnrollFeeSponsorProgram" => permission
            .payload()
            .try_into_any_norito::<CanEnrollFeeSponsorProgram>()
            .ok()
            .is_some(),
        _ => false,
    }
}
fn resolve_optional_dataspace_target<T>(
    value: Option<T>,
    resolve: impl FnOnce(T) -> Result<Option<DataSpaceId>, RoutingResolveError>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    match value {
        Some(value) => resolve(value),
        None => Ok(None),
    }
}
fn dataspace_scoped_permission_target(
    permission: &Permission,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    state_view: Option<&StateView<'_>>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    if permission.name() != "CanPublishSpaceDirectoryManifest"
        && permission.name() != "CanPublishSpaceDirectoryManifestForUaid"
        && permission.name() != "CanPublishSpaceDirectoryManifestForAccountDomain"
    {
        return match permission.name() {
            "CanMintAssetToAccount" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanMintAssetToAccount>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanMintAssetWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanMintAssetWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanBurnAssetWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanBurnAssetWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanTransferAssetWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanTransferAssetWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanModifyAssetMetadataWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanModifyAssetMetadataWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanUnregisterAssetDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanUnregisterAssetDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanModifyAssetDefinitionMetadata" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanModifyAssetDefinitionMetadata>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanManageKagemushaWallet" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageKagemushaWallet>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanManageAssetDefinitionConfidentialPolicy" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageAssetDefinitionConfidentialPolicy>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanManageAccountAlias" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageAccountAlias>()
                    .ok(),
                |token| {
                    account_alias_permission_scope_dataspace_target_with_state(
                        &token.scope,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanManageAssetDefinitionAlias" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageAssetDefinitionAlias>()
                    .ok(),
                |token| {
                    asset_definition_alias_permission_scope_dataspace_target_with_state(
                        &token.scope,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanResolveAccountAlias" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanResolveAccountAlias>()
                    .ok(),
                |token| {
                    account_alias_permission_scope_dataspace_target_with_state(
                        &token.scope,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanDelegateAccountAliasResolution" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanDelegateAccountAliasResolution>()
                    .ok(),
                |token| {
                    account_alias_permission_scope_dataspace_target_with_state(
                        &token.scope,
                        dataspace_catalog,
                        state_view,
                    )
                },
            ),
            "CanManageFeeSponsorProgram" => Ok(permission
                .payload()
                .try_into_any_norito::<CanManageFeeSponsorProgram>()
                .ok()
                .map(|token| {
                    account_dataspace_target(
                        state_view.map(StateView::world),
                        &token.sponsor,
                        state_view.map(state_view_ledger_time_ms),
                    )
                })
                .transpose()?
                .flatten()),
            "CanEnrollFeeSponsorProgram" => Ok(permission
                .payload()
                .try_into_any_norito::<CanEnrollFeeSponsorProgram>()
                .ok()
                .map(|token| {
                    account_dataspace_target(
                        state_view.map(StateView::world),
                        &token.program_id.sponsor,
                        state_view.map(state_view_ledger_time_ms),
                    )
                })
                .transpose()?
                .flatten()),
            _ => Ok(None),
        };
    }
    Ok(match permission.name() {
        "CanPublishSpaceDirectoryManifest" => permission
            .payload()
            .try_into_any_norito::<CanPublishSpaceDirectoryManifest>()
            .ok()
            .map(|token| token.dataspace),
        "CanPublishSpaceDirectoryManifestForUaid" => permission
            .payload()
            .try_into_any_norito::<CanPublishSpaceDirectoryManifestForUaid>()
            .ok()
            .map(|token| token.dataspace),
        "CanPublishSpaceDirectoryManifestForAccountDomain" => permission
            .payload()
            .try_into_any_norito::<CanPublishSpaceDirectoryManifestForAccountDomain>()
            .ok()
            .map(|token| token.dataspace),
        _ => None,
    })
}
fn dataspace_scoped_permission_target_with_world<W: WorldReadOnly>(
    permission: &Permission,
    dataspace_catalog: Option<&DataSpaceCatalog>,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    if permission.name() != "CanPublishSpaceDirectoryManifest"
        && permission.name() != "CanPublishSpaceDirectoryManifestForUaid"
        && permission.name() != "CanPublishSpaceDirectoryManifestForAccountDomain"
    {
        return match permission.name() {
            "CanMintAssetToAccount" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanMintAssetToAccount>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanMintAssetWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanMintAssetWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanBurnAssetWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanBurnAssetWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanTransferAssetWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanTransferAssetWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanModifyAssetMetadataWithDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanModifyAssetMetadataWithDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanUnregisterAssetDefinition" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanUnregisterAssetDefinition>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanModifyAssetDefinitionMetadata" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanModifyAssetDefinitionMetadata>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanManageKagemushaWallet" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageKagemushaWallet>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanManageAssetDefinitionConfidentialPolicy" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageAssetDefinitionConfidentialPolicy>()
                    .ok(),
                |token| {
                    asset_definition_dataspace_target_with_world(
                        &token.asset_definition,
                        None,
                        None,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanManageAccountAlias" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageAccountAlias>()
                    .ok(),
                |token| {
                    account_alias_permission_scope_dataspace_target_with_world(
                        &token.scope,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanManageAssetDefinitionAlias" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanManageAssetDefinitionAlias>()
                    .ok(),
                |token| {
                    asset_definition_alias_permission_scope_dataspace_target_with_world(
                        &token.scope,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanResolveAccountAlias" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanResolveAccountAlias>()
                    .ok(),
                |token| {
                    account_alias_permission_scope_dataspace_target_with_world(
                        &token.scope,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanDelegateAccountAliasResolution" => resolve_optional_dataspace_target(
                permission
                    .payload()
                    .try_into_any_norito::<CanDelegateAccountAliasResolution>()
                    .ok(),
                |token| {
                    account_alias_permission_scope_dataspace_target_with_world(
                        &token.scope,
                        dataspace_catalog,
                        world,
                        ledger_time_ms,
                    )
                },
            ),
            "CanManageFeeSponsorProgram" => Ok(permission
                .payload()
                .try_into_any_norito::<CanManageFeeSponsorProgram>()
                .ok()
                .map(|token| account_dataspace_target(Some(world), &token.sponsor, ledger_time_ms))
                .transpose()?
                .flatten()),
            "CanEnrollFeeSponsorProgram" => Ok(permission
                .payload()
                .try_into_any_norito::<CanEnrollFeeSponsorProgram>()
                .ok()
                .map(|token| {
                    account_dataspace_target(Some(world), &token.program_id.sponsor, ledger_time_ms)
                })
                .transpose()?
                .flatten()),
            _ => Ok(None),
        };
    }
    Ok(match permission.name() {
        "CanPublishSpaceDirectoryManifest" => permission
            .payload()
            .try_into_any_norito::<CanPublishSpaceDirectoryManifest>()
            .ok()
            .map(|token| token.dataspace),
        "CanPublishSpaceDirectoryManifestForUaid" => permission
            .payload()
            .try_into_any_norito::<CanPublishSpaceDirectoryManifestForUaid>()
            .ok()
            .map(|token| token.dataspace),
        "CanPublishSpaceDirectoryManifestForAccountDomain" => permission
            .payload()
            .try_into_any_norito::<CanPublishSpaceDirectoryManifestForAccountDomain>()
            .ok()
            .map(|token| token.dataspace),
        _ => None,
    })
}
fn instruction_dataspace_scoped_permission_target_needs_state(
    instruction: &dyn Instruction,
) -> bool {
    let any = instruction.as_any();
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant) => {
                dataspace_scoped_permission_target_needs_state(&grant.object)
            }
            GrantBox::RolePermission(grant) => {
                dataspace_scoped_permission_target_needs_state(&grant.object)
            }
            GrantBox::Role(_) => false,
        };
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        return match revoke {
            RevokeBox::Permission(revoke) => {
                dataspace_scoped_permission_target_needs_state(&revoke.object)
            }
            RevokeBox::RolePermission(revoke) => {
                dataspace_scoped_permission_target_needs_state(&revoke.object)
            }
            RevokeBox::Role(_) => false,
        };
    }
    false
}
fn dataspace_scoped_permission_routing_requires_state(tx: &dyn TransactionRoutingView) -> bool {
    let Some(executable) = transaction_executable(tx) else {
        return false;
    };
    match executable {
        Executable::Instructions(instructions) => instructions.iter().any(|instruction| {
            instruction_dataspace_scoped_permission_target_needs_state(&**instruction)
        }),
        Executable::ContractCall(_) | Executable::Ivm(_) => false,
        Executable::Batch(items) => items.iter().any(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => {
                instruction_dataspace_scoped_permission_target_needs_state(&**instruction)
            }
            ExecutableBatchItem::ContractCall(_) => false,
        }),
        Executable::IvmProved(proved) => proved.overlay.iter().any(|instruction| {
            instruction_dataspace_scoped_permission_target_needs_state(&**instruction)
        }),
    }
}
fn canonical_dataspace_route(
    dataspace_id: DataSpaceId,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
) -> Result<RoutingDecision, RoutingResolveError> {
    // Classify an absent dataspace before looking for its lane. Lane absence
    // applies only to a dataspace admitted by the current catalog.
    if dataspace_catalog.by_id(dataspace_id).is_none() {
        return Err(RoutingResolveError::UnknownDataspace { dataspace_id });
    }
    let lane_id = lane_catalog
        .lanes()
        .iter()
        .filter(|lane| is_canonical_dataspace_lane(lane, dataspace_id))
        .map(|lane| lane.id)
        .min()
        .ok_or(RoutingResolveError::NoLaneForDataspace { dataspace_id })?;
    resolve_routing_decision(
        RoutingDecision::new(lane_id, dataspace_id),
        lane_catalog,
        dataspace_catalog,
    )
}
fn is_canonical_dataspace_lane(
    lane: &iroha_data_model::nexus::LaneConfig,
    dataspace_id: DataSpaceId,
) -> bool {
    lane.dataspace_id == dataspace_id && !lane_uses_reserved_autoscale_metadata(lane)
}
fn reject_autoscale_owned_rule_lane(
    rule: &LaneRoutingRule,
    lane_catalog: &LaneCatalog,
) -> Result<(), RoutingResolveError> {
    if lane_catalog
        .lanes()
        .iter()
        .any(|lane| lane.id == rule.lane && lane_uses_reserved_autoscale_metadata(lane))
    {
        return Err(RoutingResolveError::AutoscaleOwnedRuleLane { lane_id: rule.lane });
    }
    Ok(())
}
fn is_autoscale_managed_elastic_lane(lane: &iroha_data_model::nexus::LaneConfig) -> bool {
    lane.is_autoscale_managed_elastic()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AutoscaleElasticRange {
    min_lane_id: u32,
    max_lane_id_exclusive: u32,
    current_height: Option<u64>,
    required_active_height: Option<u64>,
}
impl AutoscaleElasticRange {
    fn from_nexus(nexus: &iroha_config::parameters::actual::Nexus) -> Self {
        let min_lane_id = nexus.autoscale.min_lane_id.get();
        let mut max_lane_id_exclusive = min_lane_id;
        if nexus.autoscale.enabled {
            let configured_max_lane_id_exclusive = nexus.autoscale.max_lane_id_exclusive.get();
            let default_lane = nexus.routing_policy.default_lane.as_u32();
            let cap = iroha_config::parameters::defaults::nexus::autoscale::MAX_LANE_ID_EXCLUSIVE;
            if min_lane_id < configured_max_lane_id_exclusive
                && configured_max_lane_id_exclusive <= cap
                && default_lane < min_lane_id
            {
                max_lane_id_exclusive = configured_max_lane_id_exclusive;
            }
        }
        Self {
            min_lane_id,
            max_lane_id_exclusive,
            current_height: None,
            required_active_height: None,
        }
    }
    fn from_nexus_at_height(
        nexus: &iroha_config::parameters::actual::Nexus,
        current_height: u64,
    ) -> Self {
        Self {
            current_height: Some(current_height),
            required_active_height: Some(current_height),
            ..Self::from_nexus(nexus)
        }
    }
    fn from_nexus_for_queue_admission(
        nexus: &iroha_config::parameters::actual::Nexus,
        committed_height: u64,
    ) -> Self {
        Self {
            current_height: Some(committed_height),
            required_active_height: Some(committed_height.saturating_add(1)),
            ..Self::from_nexus(nexus)
        }
    }
    const fn contains_lane(self, lane_id: LaneId) -> bool {
        let lane = lane_id.as_u32();
        lane >= self.min_lane_id && lane < self.max_lane_id_exclusive
    }
    fn lane_created_height_active(self, lane: &iroha_data_model::nexus::LaneConfig) -> bool {
        self.current_height.is_none_or(|current_height| {
            lane.autoscale_created_height()
                .is_some_and(|created_height| created_height <= current_height)
        })
    }
    fn contains_active_elastic_lane(self, lane: &iroha_data_model::nexus::LaneConfig) -> bool {
        self.contains_lane(lane.id)
            && is_autoscale_managed_elastic_lane(lane)
            && self.lane_created_height_active(lane)
            && crate::state::autoscale_lane_accepts_proposal_height(
                lane,
                self.required_active_height.unwrap_or(u64::MAX),
            )
    }
}
fn default_route_elastic_candidates(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    autoscale_range: Option<AutoscaleElasticRange>,
) -> Vec<LaneId> {
    let Some(default_lane) = lane_catalog
        .lanes()
        .iter()
        .find(|lane| lane.id == policy.default_lane)
    else {
        return Vec::new();
    };
    if default_lane.dataspace_id != policy.default_dataspace {
        return Vec::new();
    }
    let Some(autoscale_range) = autoscale_range else {
        return vec![policy.default_lane];
    };
    if lane_catalog.lanes().iter().any(|lane| {
        lane.id != policy.default_lane
            && autoscale_range.contains_lane(lane.id)
            && (lane.dataspace_id != policy.default_dataspace
                || !autoscale_range.contains_active_elastic_lane(lane))
    }) {
        return vec![policy.default_lane];
    }
    let mut candidates = vec![policy.default_lane];
    candidates.extend(
        lane_catalog
            .lanes()
            .iter()
            .filter(|lane| {
                lane.id != policy.default_lane
                    && lane.dataspace_id == policy.default_dataspace
                    && autoscale_range.contains_active_elastic_lane(lane)
            })
            .map(|lane| lane.id),
    );
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}
#[cfg(test)]
fn insert_height_active_routable_lane(
    lanes: &mut BTreeSet<LaneId>,
    route: RoutingDecision,
    nexus: &Nexus,
    block_height: u64,
) {
    if crate::state::nexus_active_lane_dataspace_at_height(route.lane_id, nexus, block_height)
        == Some(route.dataspace_id)
    {
        lanes.insert(route.lane_id);
    }
}
/// Resolve height-specific routable lanes for routing and scheduler regression fixtures.
#[cfg(test)]
pub(crate) fn routable_lane_ids_for_nexus_at_height(
    nexus: &Nexus,
    block_height: u64,
) -> BTreeSet<LaneId> {
    let mut lane_ids = BTreeSet::new();
    let policy = &nexus.routing_policy;
    let lane_catalog = &nexus.lane_catalog;
    let dataspace_catalog = &nexus.dataspace_catalog;
    let default_lane_can_anchor = lane_catalog
        .lanes()
        .iter()
        .find(|lane| lane.id == policy.default_lane)
        .is_some_and(|lane| !lane_uses_reserved_autoscale_metadata(lane));
    if default_lane_can_anchor {
        for lane_id in default_route_elastic_candidates(
            policy,
            lane_catalog,
            Some(AutoscaleElasticRange::from_nexus_at_height(
                nexus,
                block_height,
            )),
        ) {
            if let Ok(route) = resolve_routing_decision(
                RoutingDecision::new(lane_id, policy.default_dataspace),
                lane_catalog,
                dataspace_catalog,
            ) {
                insert_height_active_routable_lane(&mut lane_ids, route, nexus, block_height);
            }
        }
    }
    for dataspace in dataspace_catalog.entries() {
        if let Ok(route) = canonical_dataspace_route(dataspace.id, lane_catalog, dataspace_catalog)
        {
            insert_height_active_routable_lane(&mut lane_ids, route, nexus, block_height);
        }
    }
    for rule in &policy.rules {
        if reject_autoscale_owned_rule_lane(rule, lane_catalog).is_err() {
            continue;
        }
        let dataspace_id = rule.dataspace.unwrap_or(policy.default_dataspace);
        if let Ok(route) = resolve_routing_decision(
            RoutingDecision::new(rule.lane, dataspace_id),
            lane_catalog,
            dataspace_catalog,
        ) {
            insert_height_active_routable_lane(&mut lane_ids, route, nexus, block_height);
        }
    }
    lane_ids
}
fn default_route_shard_index(tx: &dyn TransactionRoutingView, lane_count: usize) -> usize {
    let hash = tx.routing_hash();
    let mut bytes = [0_u8; core::mem::size_of::<u64>()];
    bytes.copy_from_slice(&hash.as_ref()[..core::mem::size_of::<u64>()]);
    let shard = u64::from_le_bytes(bytes);
    (shard % lane_count as u64) as usize
}
fn resolve_default_routing_decision(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: Option<&dyn TransactionRoutingView>,
    autoscale_range: Option<AutoscaleElasticRange>,
) -> Result<RoutingDecision, RoutingResolveError> {
    if lane_catalog
        .lanes()
        .iter()
        .any(|lane| lane.id == policy.default_lane && lane_uses_reserved_autoscale_metadata(lane))
    {
        return Err(RoutingResolveError::AutoscaleOwnedDefaultLane {
            lane_id: policy.default_lane,
        });
    }
    if let Some(tx) = tx {
        let candidates = default_route_elastic_candidates(policy, lane_catalog, autoscale_range);
        if candidates.len() > 1 {
            let lane_id = candidates[default_route_shard_index(tx, candidates.len())];
            return resolve_routing_decision(
                RoutingDecision::new(lane_id, policy.default_dataspace),
                lane_catalog,
                dataspace_catalog,
            );
        }
    }
    resolve_routing_decision(
        RoutingDecision::new(policy.default_lane, policy.default_dataspace),
        lane_catalog,
        dataspace_catalog,
    )
}
fn resolve_policy_routing_plan(
    policy: &LaneRoutingPolicy,
    matched_rule: Option<&LaneRoutingRule>,
    mut target: TransactionDataspaceTarget,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: Option<&dyn TransactionRoutingView>,
    autoscale_range: Option<AutoscaleElasticRange>,
) -> Result<RoutingPlan, RoutingResolveError> {
    add_smart_contract_deploy_policy_participant(&mut target, matched_rule);
    reject_cross_dataspace_plan(
        tx.is_some_and(amx_policy_rejects_cross_dataspace),
        target.coordinator_route,
        target.participants.iter().copied(),
    )?;
    if !target.participants.is_empty()
        && (target.participants.len() > 1 || target.coordinator_route)
    {
        let coordinator_dataspace = if target.coordinator_route {
            DataSpaceId::UNIVERSAL
        } else {
            *target
                .participants
                .iter()
                .next()
                .expect("non-empty participants has first dataspace")
        };
        let coordinator_route =
            canonical_dataspace_route(coordinator_dataspace, lane_catalog, dataspace_catalog)?;
        let participants = target
            .participants
            .iter()
            .copied()
            .map(|dataspace_id| {
                canonical_dataspace_route(dataspace_id, lane_catalog, dataspace_catalog)
                    .map(|route| RouteLeg::new(route, RouteLegRole::Participant))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(RoutingPlan::native_amx(coordinator_route, participants));
    }
    let decision = resolve_policy_routing_decision(
        policy,
        matched_rule,
        target.dataspace_id,
        target.coordinator_route,
        lane_catalog,
        dataspace_catalog,
        tx,
        autoscale_range,
    )?;
    Ok(RoutingPlan::single(decision))
}
fn add_smart_contract_deploy_policy_participant(
    target: &mut TransactionDataspaceTarget,
    matched_rule: Option<&LaneRoutingRule>,
) {
    let Some(rule_dataspace) = smart_contract_deploy_policy_dataspace(matched_rule) else {
        return;
    };
    if target.participants.is_empty() && !target.coordinator_route && !target.has_universal_target {
        return;
    }
    if !target.participants.is_empty()
        && target
            .participants
            .iter()
            .all(|participant| *participant == rule_dataspace)
    {
        return;
    }
    target.participants.insert(rule_dataspace);
    target.dataspace_id = Some(DataSpaceId::UNIVERSAL);
    if target.has_universal_target {
        target.coordinator_route = true;
    }
}
fn smart_contract_deploy_policy_dataspace(
    matched_rule: Option<&LaneRoutingRule>,
) -> Option<DataSpaceId> {
    let rule = matched_rule?;
    let dataspace = rule.dataspace?;
    (dataspace != DataSpaceId::UNIVERSAL && rule_matches_smart_contract_deploy(rule))
        .then_some(dataspace)
}
fn rule_matches_smart_contract_deploy(rule: &LaneRoutingRule) -> bool {
    rule.matcher.instruction.as_deref().is_some_and(|matcher| {
        let matcher = matcher.trim();
        matches_label(matcher, "smartcontract::deploy")
    })
}
fn resolve_policy_routing_decision(
    policy: &LaneRoutingPolicy,
    matched_rule: Option<&LaneRoutingRule>,
    target_dataspace: Option<DataSpaceId>,
    target_is_coordinator_route: bool,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    tx: Option<&dyn TransactionRoutingView>,
    autoscale_range: Option<AutoscaleElasticRange>,
) -> Result<RoutingDecision, RoutingResolveError> {
    if target_is_coordinator_route && target_dataspace == Some(DataSpaceId::UNIVERSAL) {
        return canonical_dataspace_route(DataSpaceId::UNIVERSAL, lane_catalog, dataspace_catalog);
    }
    if let Some(dataspace_id) = target_dataspace {
        if let Some(rule) = matched_rule {
            reject_autoscale_owned_rule_lane(rule, lane_catalog)?;
            let decision = RoutingDecision::new(rule.lane, dataspace_id);
            if !lane_catalog.lanes().iter().any(|lane| lane.id == rule.lane) {
                return resolve_routing_decision(decision, lane_catalog, dataspace_catalog);
            }
            if let Some(rule_dataspace) = rule.dataspace
                && rule_dataspace != dataspace_id
            {
                return Err(RoutingResolveError::LaneDataspaceMismatch {
                    lane_id: rule.lane,
                    lane_dataspace_id: rule_dataspace,
                    dataspace_id,
                });
            }
            return resolve_routing_decision(decision, lane_catalog, dataspace_catalog);
        }
        return canonical_dataspace_route(dataspace_id, lane_catalog, dataspace_catalog);
    }
    if let Some(rule) = matched_rule {
        reject_autoscale_owned_rule_lane(rule, lane_catalog)?;
        let decision = RoutingDecision::new(
            rule.lane,
            rule.dataspace.unwrap_or(policy.default_dataspace),
        );
        return resolve_routing_decision(decision, lane_catalog, dataspace_catalog);
    }
    resolve_default_routing_decision(policy, lane_catalog, dataspace_catalog, tx, autoscale_range)
}
/// Resolve the configured routing policy for a signed query authority.
///
/// Query routing intentionally ignores transaction-instruction matchers because
/// queries do not carry ISI batches. Rules without an instruction matcher still
/// participate, including account-scoped rules and explicit catch-all rules.
pub fn resolve_query_routing_decision(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    authority: &AccountId,
    state_view: Option<&StateView<'_>>,
) -> Result<RoutingDecision, RoutingResolveError> {
    if let Some(state_view) = state_view {
        let matched_rule = first_matching_rule(&policy.rules, |rule| {
            query_rule_matches(rule, authority, Some(state_view))
        })?;
        let target_dataspace = account_dataspace_target(
            Some(state_view.world()),
            authority,
            Some(state_view_ledger_time_ms(state_view)),
        )?;
        return resolve_policy_routing_decision(
            policy,
            matched_rule,
            target_dataspace,
            target_dataspace == Some(DataSpaceId::UNIVERSAL),
            lane_catalog,
            dataspace_catalog,
            None,
            Some(AutoscaleElasticRange::from_nexus_at_height(
                state_view.nexus(),
                u64::try_from(state_view.height()).unwrap_or(u64::MAX),
            )),
        );
    }
    let matched_rule = first_matching_rule(&policy.rules, |rule| {
        query_rule_matches(rule, authority, None)
    })?;
    resolve_policy_routing_decision(
        policy,
        matched_rule,
        None,
        false,
        lane_catalog,
        dataspace_catalog,
        None,
        None,
    )
}
fn resolve_query_routing_decision_with_world<W: WorldReadOnly>(
    policy: &LaneRoutingPolicy,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
    authority: &AccountId,
    world: &W,
    ledger_time_ms: Option<u64>,
    autoscale_range: Option<AutoscaleElasticRange>,
) -> Result<RoutingDecision, RoutingResolveError> {
    let matched_rule = first_matching_rule(&policy.rules, |rule| {
        query_rule_matches_with_world(rule, authority, dataspace_catalog, world, ledger_time_ms)
    })?;
    let target_dataspace = account_dataspace_target(Some(world), authority, ledger_time_ms)?;
    resolve_policy_routing_decision(
        policy,
        matched_rule,
        target_dataspace,
        target_dataspace == Some(DataSpaceId::UNIVERSAL),
        lane_catalog,
        dataspace_catalog,
        None,
        autoscale_range,
    )
}
/// Resolve a policy decision against lane/dataspace catalogs without fallback.
///
/// This function intentionally rejects unresolved or ambiguous combinations
/// instead of silently rewriting them to defaults.
pub fn resolve_routing_decision(
    decision: RoutingDecision,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
) -> Result<RoutingDecision, RoutingResolveError> {
    let Some(lane) = lane_catalog
        .lanes()
        .iter()
        .find(|lane| lane.id == decision.lane_id)
    else {
        return Err(RoutingResolveError::UnknownLane {
            lane_id: decision.lane_id,
        });
    };
    let dataspace_known = dataspace_catalog
        .entries()
        .iter()
        .any(|entry| entry.id == decision.dataspace_id);
    if !dataspace_known {
        return Err(RoutingResolveError::UnknownDataspace {
            dataspace_id: decision.dataspace_id,
        });
    }
    if lane.dataspace_id != decision.dataspace_id {
        return Err(RoutingResolveError::LaneDataspaceMismatch {
            lane_id: lane.id,
            lane_dataspace_id: lane.dataspace_id,
            dataspace_id: decision.dataspace_id,
        });
    }
    Ok(decision)
}
fn first_matching_rule<'a>(
    rules: &'a [LaneRoutingRule],
    mut matches: impl FnMut(&LaneRoutingRule) -> Result<bool, ExecutionDeferred>,
) -> Result<Option<&'a LaneRoutingRule>, ExecutionDeferred> {
    for rule in rules {
        if matches(rule)? {
            return Ok(Some(rule));
        }
    }
    Ok(None)
}
fn rule_matches(
    rule: &LaneRoutingRule,
    tx: &dyn TransactionRoutingView,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, ExecutionDeferred> {
    if let Some(account) = rule.matcher.account.as_deref() {
        let Some(authority) = tx.authority_opt() else {
            return Ok(false);
        };
        if !account_matches(account, authority, state_view)? {
            return Ok(false);
        }
    }
    if let Some(instruction) = rule.matcher.instruction.as_deref()
        && !instructions_match(instruction, tx, state_view)?
    {
        return Ok(false);
    }
    Ok(true)
}
fn rule_matches_with_world<W: WorldReadOnly>(
    rule: &LaneRoutingRule,
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    matchers_match_with_world(
        rule.matcher.account.as_deref(),
        rule.matcher.instruction.as_deref(),
        tx,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )
}
/// Whether `tx` satisfies every present matcher: its authority matches `account` (an account
/// id, an encoded account id or an alias resolved in `world`) and one of its instructions
/// matches `instruction`.
///
/// Local refusal retains the original reader reason; it is not a completed mismatch.
pub(crate) fn matchers_match_with_world<W: WorldReadOnly>(
    account: Option<&str>,
    instruction: Option<&str>,
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    if let Some(account) = account {
        let Some(authority) = tx.authority_opt() else {
            return Ok(false);
        };
        if !account_matches_with_world(
            account,
            authority,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )? {
            return Ok(false);
        }
    }
    if let Some(instruction) = instruction
        && !instructions_match_with_world(
            instruction,
            tx,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?
    {
        return Ok(false);
    }
    Ok(true)
}
fn query_rule_matches(
    rule: &LaneRoutingRule,
    authority: &AccountId,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, ExecutionDeferred> {
    if rule.matcher.instruction.is_some() {
        return Ok(false);
    }
    match rule.matcher.account.as_deref() {
        Some(account) => account_matches(account, authority, state_view),
        None => Ok(true),
    }
}
fn query_rule_matches_with_world<W: WorldReadOnly>(
    rule: &LaneRoutingRule,
    authority: &AccountId,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    if rule.matcher.instruction.is_some() {
        return Ok(false);
    }
    match rule.matcher.account.as_deref() {
        Some(account) => {
            account_matches_with_world(account, authority, dataspace_catalog, world, ledger_time_ms)
        }
        None => Ok(true),
    }
}
fn account_matches_literal_or_encoded(
    pattern: &str,
    authority: &AccountId,
) -> Result<bool, ExecutionDeferred> {
    use iroha_data_model::account::address::AccountAddress;
    match AccountAddress::parse_encoded(pattern, None).and_then(|address| address.to_account_id()) {
        Ok(parsed) => Ok(parsed == *authority),
        Err(error) if error.is_decode_resource_limit() => {
            #[cfg(all(test, sumeragi_core_mutation = "HC40"))]
            return Ok(false);
            #[cfg(not(all(test, sumeragi_core_mutation = "HC40")))]
            Err(ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into())
        }
        Err(_) => Ok(false),
    }
}
fn account_matches(
    pattern: &str,
    authority: &AccountId,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, ExecutionDeferred> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Ok(false);
    }
    match state_view {
        Some(view) => account_matches_with_world(
            pattern,
            authority,
            &view.nexus().dataspace_catalog,
            view.world(),
            Some(state_view_ledger_time_ms(view)),
        ),
        None => account_matches_literal_or_encoded(pattern, authority),
    }
}
fn account_matches_with_world<W: WorldReadOnly>(
    pattern: &str,
    authority: &AccountId,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Ok(false);
    }
    if account_matches_literal_or_encoded(pattern, authority)? {
        return Ok(true);
    }
    if let Some(scope) = pattern.strip_prefix("*@") {
        return account_matches_alias_scope_with_world(
            scope,
            authority,
            dataspace_catalog,
            world,
            ledger_time_ms,
        );
    }
    let (Ok(alias), Some(now_ms)) = (
        AccountAlias::from_literal(pattern, dataspace_catalog),
        ledger_time_ms,
    ) else {
        return Ok(false);
    };
    original_account_alias_matches(world, dataspace_catalog, &alias, authority, now_ms)
}

fn original_account_alias_matches<W: WorldReadOnly>(
    world: &W,
    catalog: &DataSpaceCatalog,
    alias: &AccountAlias,
    account: &AccountId,
    now_ms: u64,
) -> Result<bool, ExecutionDeferred> {
    match crate::sns::resolve_active_account_alias(world, catalog, alias, now_ms) {
        Ok(resolved) => Ok(resolved.as_ref() == Some(account)),
        Err(crate::sns::SnsError::Deferred(reason)) => {
            #[cfg(all(test, sumeragi_core_mutation = "HC40"))]
            {
                drop(reason);
                Ok(false)
            }
            #[cfg(not(all(test, sumeragi_core_mutation = "HC40")))]
            Err(reason)
        }
        Err(_) => Ok(false),
    }
}
fn account_matches_alias_scope(
    scope: &str,
    account_id: &AccountId,
    state_view: &StateView<'_>,
) -> Result<bool, ExecutionDeferred> {
    account_matches_alias_scope_with_world(
        scope,
        account_id,
        &state_view.nexus().dataspace_catalog,
        state_view.world(),
        Some(state_view_ledger_time_ms(state_view)),
    )
}
fn account_matches_alias_scope_with_world<W: WorldReadOnly>(
    scope: &str,
    account_id: &AccountId,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    let scope = scope.trim().to_ascii_lowercase();
    if scope.is_empty() {
        return Ok(false);
    }
    // The maintained directory is authoritative, including malformed/missing scope material.
    if world.account_scope_directory().get(account_id).is_some() {
        return Ok(world
            .account_scope_hierarchy(account_id)
            .ok()
            .is_some_and(|hierarchy| {
                hierarchy.into_iter().any(|(dataspace_id, domains)| {
                    dataspace_catalog
                        .by_id(dataspace_id)
                        .is_some_and(|entry| entry.alias.eq_ignore_ascii_case(scope.as_str()))
                        || domains
                            .into_iter()
                            .any(|domain| domain.to_string().eq_ignore_ascii_case(scope.as_str()))
                })
            }));
    }
    let Some(now_ms) = ledger_time_ms else {
        return Ok(false);
    };
    for alias in world.bound_account_aliases(account_id) {
        if original_account_alias_matches(world, dataspace_catalog, &alias, account_id, now_ms)?
            && alias
                .to_literal(dataspace_catalog)
                .ok()
                .and_then(|literal| {
                    literal
                        .rsplit_once('@')
                        .map(|(_, alias_scope)| alias_scope == scope.as_str())
                })
                .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn instructions_match(
    matcher: &str,
    tx: &dyn TransactionRoutingView,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, ExecutionDeferred> {
    let matcher_norm = matcher.trim().to_ascii_lowercase();
    if matcher_norm.is_empty() {
        return Ok(false);
    }
    let (matcher_label, destination_scope) = split_instruction_matcher(&matcher_norm);
    if matcher_label.is_empty() {
        return Ok(false);
    }
    let Some(executable) = tx.executable() else {
        return Ok(false);
    };
    for instruction in executable.explicit_instructions() {
        if instruction_matches(matcher_label, destination_scope, &**instruction, state_view)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn instructions_match_with_world<W: WorldReadOnly>(
    matcher: &str,
    tx: &dyn TransactionRoutingView,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    let matcher_norm = matcher.trim().to_ascii_lowercase();
    if matcher_norm.is_empty() {
        return Ok(false);
    }
    let (matcher_label, destination_scope) = split_instruction_matcher(&matcher_norm);
    if matcher_label.is_empty() {
        return Ok(false);
    }
    let Some(executable) = tx.executable() else {
        return Ok(false);
    };
    for instruction in executable.explicit_instructions() {
        if instruction_matches_with_world(
            matcher_label,
            destination_scope,
            &**instruction,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn split_instruction_matcher(matcher: &str) -> (&str, Option<&str>) {
    if let Some((label, domain)) = matcher.rsplit_once('@')
        && label.starts_with("transfer")
    {
        let label = label.trim();
        let domain = domain.trim();
        if !label.is_empty() && !domain.is_empty() {
            return (label, Some(domain));
        }
    }
    (matcher, None)
}
fn instruction_matches(
    matcher: &str,
    destination_scope: Option<&str>,
    instruction: &dyn Instruction,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, ExecutionDeferred> {
    if let Some(scope) = destination_scope
        && !transfer_destination_matches_alias_scope(instruction, scope, state_view)?
    {
        return Ok(false);
    }
    if instruction_label_matches(matcher, instruction) {
        return Ok(true);
    }
    let id = Instruction::id(instruction).to_ascii_lowercase();
    if matches_label(matcher, &id) {
        return Ok(true);
    }
    Ok(id.split("::").any(|segment| {
        matches_label(matcher, segment)
            || segment
                .strip_suffix("box")
                .is_some_and(|trimmed| !trimmed.is_empty() && matches_label(matcher, trimmed))
    }))
}
fn instruction_matches_with_world<W: WorldReadOnly>(
    matcher: &str,
    destination_scope: Option<&str>,
    instruction: &dyn Instruction,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    if let Some(scope) = destination_scope
        && !transfer_destination_matches_alias_scope_with_world(
            instruction,
            scope,
            dataspace_catalog,
            world,
            ledger_time_ms,
        )?
    {
        return Ok(false);
    }
    if instruction_label_matches(matcher, instruction) {
        return Ok(true);
    }
    let id = Instruction::id(instruction).to_ascii_lowercase();
    if matches_label(matcher, &id) {
        return Ok(true);
    }
    Ok(id.split("::").any(|segment| {
        matches_label(matcher, segment)
            || segment
                .strip_suffix("box")
                .is_some_and(|trimmed| !trimmed.is_empty() && matches_label(matcher, trimmed))
    }))
}
fn transfer_destination_matches_alias_scope(
    instruction: &dyn Instruction,
    scope: &str,
    state_view: Option<&StateView<'_>>,
) -> Result<bool, ExecutionDeferred> {
    let scope = scope.trim();
    if scope.is_empty() {
        return Ok(false);
    }
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        let Some(view) = state_view else {
            return Ok(false);
        };
        for entry in batch.entries() {
            if account_matches_alias_scope(scope, entry.to(), view)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let Some(transfer) = any.downcast_ref::<TransferBox>() else {
        return Ok(false);
    };
    let destination = match transfer {
        TransferBox::Domain(transfer) => return Ok(domain_scope_matches(scope, &transfer.object)),
        TransferBox::AssetDefinition(transfer) => {
            return Ok(asset_definition_scope_matches(
                scope,
                &transfer.object,
                state_view,
            ));
        }
        TransferBox::Asset(transfer) => &transfer.destination,
        TransferBox::Nft(transfer) => &transfer.destination,
    };
    let Some(view) = state_view else {
        return Ok(false);
    };
    account_matches_alias_scope(scope, destination, view)
}
fn transfer_destination_matches_alias_scope_with_world<W: WorldReadOnly>(
    instruction: &dyn Instruction,
    scope: &str,
    dataspace_catalog: &DataSpaceCatalog,
    world: &W,
    ledger_time_ms: Option<u64>,
) -> Result<bool, ExecutionDeferred> {
    let scope = scope.trim();
    if scope.is_empty() {
        return Ok(false);
    }
    let any = instruction.as_any();
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        for entry in batch.entries() {
            if account_matches_alias_scope_with_world(
                scope,
                entry.to(),
                dataspace_catalog,
                world,
                ledger_time_ms,
            )? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let Some(transfer) = any.downcast_ref::<TransferBox>() else {
        return Ok(false);
    };
    let destination = match transfer {
        TransferBox::Domain(transfer) => {
            return Ok(domain_scope_matches(scope, &transfer.object));
        }
        TransferBox::AssetDefinition(transfer) => {
            return Ok(asset_definition_scope_matches_with_world(
                scope,
                &transfer.object,
                world,
            ));
        }
        TransferBox::Asset(transfer) => &transfer.destination,
        TransferBox::Nft(transfer) => &transfer.destination,
    };
    account_matches_alias_scope_with_world(
        scope,
        destination,
        dataspace_catalog,
        world,
        ledger_time_ms,
    )
}
fn domain_scope_matches(scope: &str, domain_id: &DomainId) -> bool {
    scope.eq_ignore_ascii_case(domain_id.to_string().as_str())
        || scope.eq_ignore_ascii_case(domain_id.dataspace().as_ref())
}
fn asset_definition_scope_matches(
    scope: &str,
    asset_definition_id: &AssetDefinitionId,
    state_view: Option<&StateView<'_>>,
) -> bool {
    state_view.is_some_and(|view| {
        asset_definition_scope_matches_with_world(scope, asset_definition_id, &view.world)
    })
}
fn asset_definition_scope_matches_with_world<W: WorldReadOnly>(
    scope: &str,
    asset_definition_id: &AssetDefinitionId,
    world: &W,
) -> bool {
    match world.asset_definition_dataspace(asset_definition_id) {
        Ok(Some(dataspace)) => {
            return world
                .dataspace_catalog()
                .by_id(dataspace)
                .is_some_and(|entry| scope.eq_ignore_ascii_case(&entry.alias));
        }
        Ok(None) => {}
        Err(_) => return false,
    }
    world
        .asset_definition_domains()
        .get(asset_definition_id)
        .cloned()
        .is_some_and(|domain_id| domain_scope_matches(scope, &domain_id))
}
fn instruction_label_matches(matcher: &str, instruction: &dyn Instruction) -> bool {
    let any = instruction.as_any();
    if any.is::<iroha_data_model::isi::RegisterDataspaceAssetDefinition>() {
        return matches_box_variant(matcher, "register", "register::asset_definition");
    }
    if any.is::<TransferAssetBatch>() {
        return matches_box_variant(matcher, "transfer", "transfer::asset");
    }
    if let Some(register) = any.downcast_ref::<RegisterBox>() {
        let variant = match register {
            RegisterBox::Peer(_) => "register::peer",
            RegisterBox::Domain(_) => "register::domain",
            RegisterBox::Account(_) => "register::account",
            RegisterBox::AssetDefinition(_) => "register::asset_definition",
            RegisterBox::Nft(_) => "register::nft",
            RegisterBox::Role(_) => "register::role",
            RegisterBox::Trigger(_) => "register::trigger",
        };
        return matches_box_variant(matcher, "register", variant);
    }
    if let Some(unregister) = any.downcast_ref::<UnregisterBox>() {
        let variant = match unregister {
            UnregisterBox::Peer(_) => "unregister::peer",
            UnregisterBox::Domain(_) => "unregister::domain",
            UnregisterBox::Account(_) => "unregister::account",
            UnregisterBox::AssetDefinition(_) => "unregister::asset_definition",
            UnregisterBox::Nft(_) => "unregister::nft",
            UnregisterBox::Role(_) => "unregister::role",
            UnregisterBox::Trigger(_) => "unregister::trigger",
        };
        return matches_box_variant(matcher, "unregister", variant);
    }
    if let Some(mint) = any.downcast_ref::<MintBox>() {
        let variant = match mint {
            MintBox::Asset(_) => "mint::asset",
            MintBox::TriggerRepetitions(_) => "mint::trigger_repetitions",
        };
        return matches_box_variant(matcher, "mint", variant);
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>() {
        let variant = match burn {
            BurnBox::Asset(_) => "burn::asset",
            BurnBox::TriggerRepetitions(_) => "burn::trigger_repetitions",
        };
        return matches_box_variant(matcher, "burn", variant);
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>() {
        let variant = match transfer {
            TransferBox::Domain(_) => "transfer::domain",
            TransferBox::AssetDefinition(_) => "transfer::asset_definition",
            TransferBox::Asset(_) => "transfer::asset",
            TransferBox::Nft(_) => "transfer::nft",
        };
        return matches_box_variant(matcher, "transfer", variant);
    }
    if let Some(set_key_value) = any.downcast_ref::<SetKeyValueBox>() {
        let variant = match set_key_value {
            SetKeyValueBox::Domain(_) => "set_key_value::domain",
            SetKeyValueBox::Account(_) => "set_key_value::account",
            SetKeyValueBox::AssetDefinition(_) => "set_key_value::asset_definition",
            SetKeyValueBox::Nft(_) => "set_key_value::nft",
            SetKeyValueBox::Trigger(_) => "set_key_value::trigger",
        };
        return matches_box_variant(matcher, "set_key_value", variant);
    }
    if let Some(remove_key_value) = any.downcast_ref::<RemoveKeyValueBox>() {
        let variant = match remove_key_value {
            RemoveKeyValueBox::Domain(_) => "remove_key_value::domain",
            RemoveKeyValueBox::Account(_) => "remove_key_value::account",
            RemoveKeyValueBox::AssetDefinition(_) => "remove_key_value::asset_definition",
            RemoveKeyValueBox::Nft(_) => "remove_key_value::nft",
            RemoveKeyValueBox::Trigger(_) => "remove_key_value::trigger",
        };
        return matches_box_variant(matcher, "remove_key_value", variant);
    }
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        let variant = match grant {
            GrantBox::Permission(_) => "grant::permission",
            GrantBox::Role(_) => "grant::role",
            GrantBox::RolePermission(_) => "grant::role_permission",
        };
        return matches_box_variant(matcher, "grant", variant);
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        let variant = match revoke {
            RevokeBox::Permission(_) => "revoke::permission",
            RevokeBox::Role(_) => "revoke::role",
            RevokeBox::RolePermission(_) => "revoke::role_permission",
        };
        return matches_box_variant(matcher, "revoke", variant);
    }
    if any.is::<RegisterSmartContractCode>()
        || any.is::<RegisterSmartContractBytes>()
        || any.is::<UploadSmartContractCodeChunk>()
        || any.is::<FinalizeSmartContractCodeUpload>()
        || any.is::<CommitContractDeployment>()
    {
        return matches_label(matcher, "smartcontract::deploy");
    }
    false
}
fn matches_box_variant(matcher: &str, base: &str, variant: &str) -> bool {
    matches_label(matcher, base) || matches_label(matcher, variant)
}
fn matches_label(matcher: &str, label: &str) -> bool {
    label == matcher
}
/// Strategy object that derives lane/dataspace assignments for queued transactions.
pub trait LaneRouter: Send + Sync + 'static {
    /// Route the given transaction and return deterministic route-resolution errors.
    fn try_route(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<RoutingDecision, RoutingResolveError>;
    /// Route with an existing state view and return deterministic route-resolution errors.
    fn try_route_with_view(
        &self,
        tx: &dyn TransactionRoutingView,
        _state_view: &StateView<'_>,
    ) -> Result<RoutingDecision, RoutingResolveError> {
        self.try_route(tx)
    }
    /// Route with narrow state access and return deterministic route-resolution errors.
    fn try_route_with_state(
        &self,
        tx: &dyn TransactionRoutingView,
        state: &State,
    ) -> Result<RoutingDecision, RoutingResolveError> {
        if let Some(decision) = self.try_route_without_state(tx)? {
            return Ok(decision);
        }
        let state_view = state.view();
        self.try_route_with_view(tx, &state_view)
    }
    /// Route without state snapshot when possible and return deterministic route errors.
    fn try_route_without_state(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
        self.try_route(tx).map(Some)
    }
    /// Build the full routing plan for a transaction and return deterministic errors.
    fn try_route_plan(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        self.try_route(tx)
            .map(|route| RoutingPlan::Single(RouteLeg::new(route, RouteLegRole::Coordinator)))
    }
    /// Build the full routing plan with an existing state view.
    fn try_route_plan_with_view(
        &self,
        tx: &dyn TransactionRoutingView,
        state_view: &StateView<'_>,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        self.try_route_with_view(tx, state_view)
            .map(|route| RoutingPlan::Single(RouteLeg::new(route, RouteLegRole::Coordinator)))
    }
    /// Build the full routing plan with narrow state access when possible.
    fn try_route_plan_with_state(
        &self,
        tx: &dyn TransactionRoutingView,
        state: &State,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        if let Some(plan) = self.try_route_plan_without_state(tx)? {
            return Ok(plan);
        }
        let state_view = state.view();
        self.try_route_plan_with_view(tx, &state_view)
    }
    /// Build the full routing plan without state when possible.
    fn try_route_plan_without_state(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<Option<RoutingPlan>, RoutingResolveError> {
        Ok(self
            .try_route_without_state(tx)?
            .map(|route| RoutingPlan::Single(RouteLeg::new(route, RouteLegRole::Coordinator))))
    }
}
/// Router that applies the declarative policy derived from configuration.
#[derive(Debug, Clone)]
pub struct ConfigLaneRouter {
    policy: Arc<LaneRoutingPolicy>,
    dataspace_catalog: Arc<DataSpaceCatalog>,
    lane_catalog: Arc<LaneCatalog>,
}
impl ConfigLaneRouter {
    /// Build a router from the validated runtime configuration.
    #[must_use]
    pub fn new(
        policy: LaneRoutingPolicy,
        dataspace_catalog: DataSpaceCatalog,
        lane_catalog: LaneCatalog,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            dataspace_catalog: Arc::new(dataspace_catalog),
            lane_catalog: Arc::new(lane_catalog),
        }
    }
    fn catalog_only_routing_decision(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
        if let Some(decision) = dataspace_scoped_permission_routing_decision(
            tx,
            Some(self.lane_catalog.as_ref()),
            Some(self.dataspace_catalog.as_ref()),
            None,
        )? {
            return Ok(Some(decision));
        }
        if let Some(decision) = settlement_routing_decision(
            tx,
            self.lane_catalog.as_ref(),
            self.dataspace_catalog.as_ref(),
            None,
        )? {
            return Ok(Some(decision));
        }
        Ok(None)
    }
}
impl LaneRouter for ConfigLaneRouter {
    fn try_route(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<RoutingDecision, RoutingResolveError> {
        self.try_route_plan(tx).map(|plan| plan.coordinator_route())
    }
    fn try_route_plan(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        let matched_rule =
            first_matching_rule(&self.policy.rules, |rule| rule_matches(rule, tx, None))?;
        if transaction_contains_fx_corridor_settlement(tx)?
            && let Some(decision) = settlement_routing_decision(
                tx,
                self.lane_catalog.as_ref(),
                self.dataspace_catalog.as_ref(),
                None,
            )?
        {
            return Ok(RoutingPlan::single(decision));
        }
        if let Some(plan) = dataspace_scoped_permission_routing_plan(
            tx,
            matched_rule,
            self.lane_catalog.as_ref(),
            self.dataspace_catalog.as_ref(),
            None,
        )? {
            return Ok(plan);
        }
        if let Some(decision) = settlement_routing_decision(
            tx,
            self.lane_catalog.as_ref(),
            self.dataspace_catalog.as_ref(),
            None,
        )? {
            let target = transaction_dataspace_routing_target_info(
                tx,
                Some(self.dataspace_catalog.as_ref()),
                None,
            )?;
            if target.participants.is_empty()
                || (target.participants.len() == 1 && !target.coordinator_route)
            {
                return Ok(RoutingPlan::Single(RouteLeg::new(
                    decision,
                    RouteLegRole::Coordinator,
                )));
            }
        }
        if let Some(account_id) = account_permission_holder_routing_target(tx) {
            return resolve_query_routing_decision(
                &self.policy,
                self.lane_catalog.as_ref(),
                self.dataspace_catalog.as_ref(),
                account_id,
                None,
            )
            .map(|decision| {
                RoutingPlan::Single(RouteLeg::new(decision, RouteLegRole::Coordinator))
            });
        }
        let target = transaction_dataspace_routing_target_info(
            tx,
            Some(self.dataspace_catalog.as_ref()),
            None,
        )?;
        resolve_policy_routing_plan(
            &self.policy,
            matched_rule,
            target,
            self.lane_catalog.as_ref(),
            self.dataspace_catalog.as_ref(),
            Some(tx),
            None,
        )
    }
    fn try_route_with_view(
        &self,
        tx: &dyn TransactionRoutingView,
        state_view: &StateView<'_>,
    ) -> Result<RoutingDecision, RoutingResolveError> {
        self.try_route_plan_with_view(tx, state_view)
            .map(|plan| plan.coordinator_route())
    }
    fn try_route_plan_with_view(
        &self,
        tx: &dyn TransactionRoutingView,
        state_view: &StateView<'_>,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        let nexus = state_view.nexus();
        let ledger_time_ms = state_view_ledger_time_ms(state_view);
        evaluate_policy_plan_with_catalog_and_world_at_opt(
            &nexus.routing_policy,
            &nexus.lane_catalog,
            &nexus.dataspace_catalog,
            tx,
            state_view.world(),
            Some(ledger_time_ms),
            Some(AutoscaleElasticRange::from_nexus_for_queue_admission(
                nexus,
                u64::try_from(state_view.height()).unwrap_or(u64::MAX),
            )),
        )
    }
    fn try_route_without_state(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
        self.try_route_plan_without_state(tx)
            .map(|plan| plan.map(|plan| plan.coordinator_route()))
    }
    fn try_route_plan_without_state(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<Option<RoutingPlan>, RoutingResolveError> {
        // Participant dataspaces come from the governed corridor registry.
        if transaction_contains_fx_corridor_settlement(tx)? {
            return Ok(None);
        }
        if dataspace_scoped_permission_routing_requires_state(tx)
            || transaction_target_routing_requires_state(tx)
        {
            return Ok(None);
        }
        let matched_rule =
            first_matching_rule(&self.policy.rules, |rule| rule_matches(rule, tx, None))?;
        if let Some(plan) = dataspace_scoped_permission_routing_plan(
            tx,
            matched_rule,
            self.lane_catalog.as_ref(),
            self.dataspace_catalog.as_ref(),
            None,
        )? {
            return Ok(Some(plan));
        }
        if let Some(decision) = self.catalog_only_routing_decision(tx)? {
            let target = transaction_dataspace_routing_target_info(
                tx,
                Some(self.dataspace_catalog.as_ref()),
                None,
            )?;
            if target.participants.is_empty()
                || (target.participants.len() == 1 && !target.coordinator_route)
            {
                return Ok(Some(RoutingPlan::single(decision)));
            }
        }
        if policy_needs_state(self.policy.as_ref()) {
            return Ok(None);
        }
        let target =
            transaction_dataspace_routing_target(tx, Some(self.dataspace_catalog.as_ref()), None)?;
        if target.is_none() && matched_rule.is_none() {
            return Ok(None);
        }
        if let Some(account_id) = account_permission_holder_routing_target(tx)
            && !first_matching_rule(&self.policy.rules, |rule| {
                query_rule_matches(rule, account_id, None)
            })?
            .is_some()
        {
            return Ok(None);
        }
        if self.authority_scope_routing_requires_state(tx)? {
            return Ok(None);
        }
        self.try_route_plan(tx).map(Some)
    }
}
impl ConfigLaneRouter {
    fn authority_scope_routing_requires_state(
        &self,
        tx: &dyn TransactionRoutingView,
    ) -> Result<bool, RoutingResolveError> {
        if tx.authority_opt().is_none() || account_permission_holder_routing_target(tx).is_some() {
            return Ok(false);
        }
        if dataspace_scoped_permission_routing_decision(
            tx,
            Some(self.lane_catalog.as_ref()),
            Some(self.dataspace_catalog.as_ref()),
            None,
        )?
        .is_some()
        {
            return Ok(false);
        }
        if settlement_routing_decision(
            tx,
            self.lane_catalog.as_ref(),
            self.dataspace_catalog.as_ref(),
            None,
        )?
        .is_some()
        {
            return Ok(false);
        }
        if transaction_dataspace_routing_target(tx, Some(self.dataspace_catalog.as_ref()), None)?
            .is_some()
        {
            return Ok(false);
        }
        let matched_rule =
            first_matching_rule(&self.policy.rules, |rule| rule_matches(rule, tx, None))?.is_some();
        Ok(!matched_rule)
    }
}
fn policy_needs_state(policy: &LaneRoutingPolicy) -> bool {
    policy
        .rules
        .iter()
        .any(|rule| matcher_needs_state(&rule.matcher))
}
fn matcher_needs_state(matcher: &LaneRoutingMatcher) -> bool {
    let account_needs_state = matcher.account.as_deref().is_some_and(|account| {
        let account = account.trim();
        account.contains('@')
    });
    let instruction_needs_state = matcher.instruction.as_deref().is_some_and(|instruction| {
        let instruction = instruction.trim().to_ascii_lowercase();
        instruction.starts_with("transfer") && instruction.rsplit_once('@').is_some()
    });
    account_needs_state || instruction_needs_state
}
fn transaction_target_routing_requires_state(tx: &dyn TransactionRoutingView) -> bool {
    let Some(executable) = transaction_executable(tx) else {
        return false;
    };
    match executable {
        Executable::Instructions(instructions) => instructions.iter().any(|instruction| {
            instruction_transaction_dataspace_target_needs_state(&**instruction)
        }),
        Executable::ContractCall(_) | Executable::Ivm(_) => false,
        Executable::Batch(items) => items.iter().any(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => {
                instruction_transaction_dataspace_target_needs_state(&**instruction)
            }
            ExecutableBatchItem::ContractCall(_) => false,
        }),
        Executable::IvmProved(proved) => proved.overlay.iter().any(|instruction| {
            instruction_transaction_dataspace_target_needs_state(&**instruction)
        }),
    }
}
#[cfg(test)]
#[path = "router/alias_registry_routing_tests.rs"]
mod alias_registry_routing_tests;

#[cfg(test)]
mod sccp_routing_tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::SampleInstructions;

    #[test]
    fn every_sccp_instruction_routes_to_the_universal_dataspace() {
        let samples = SampleInstructions::all();
        assert_eq!(samples.len(), 10);
        for (index, instruction) in samples.iter().enumerate() {
            let instruction: &dyn Instruction = &**instruction;
            assert!(instruction_routes_to_universal_dataspace(instruction));
            assert!(!instruction_uses_universal_alias_registry(instruction));
            assert_eq!(
                instruction_transaction_dataspace_target(instruction, None, None),
                Ok(Some(DataSpaceId::UNIVERSAL)),
                "SCCP sample {index}"
            );
            assert_eq!(
                instruction_transaction_target_requires_universal_coordinator(
                    instruction,
                    None,
                    None
                ),
                Ok(true),
                "SCCP sample {index}"
            );
            assert!(!instruction_transaction_dataspace_target_needs_state(
                instruction
            ));
        }
    }

    #[test]
    fn other_instructions_keep_their_routing() {
        let log = InstructionBox::from(iroha_data_model::isi::Log::new(
            iroha_data_model::Level::INFO,
            "not SCCP".to_owned(),
        ));
        assert!(!instruction_routes_to_universal_dataspace(&*log));
    }
}

#[cfg(test)]
mod tests {
    /// Canonical typed retail scope routing and native-policy refusal controls.
    mod retail_daily_limit_routing_tests {
        include!("router/retail_daily_limit_routing_tests.rs");
    }
    use super::*;
    use iroha_config::parameters::actual::{LaneRoutingMatcher, LaneRoutingRule};
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        Encode, IntoKeyValue,
        account::{AccountAddress, AccountAliasDomain},
        alias_setup::{AccountAliasName, ResolvedAccountAliasV1},
        asset::{AssetDefinitionAlias, Mintable, NewAssetDefinition},
        isi::{
            alias_setup::CompareAndSetPrimaryAccountAlias,
            prelude::{Mint, Register, Transfer},
            private_settlement::{
                AbortAtomicPrivateSettlementV1, ActivatePrivateSettlementPoolV1,
                FinalizeAtomicPrivateSettlementV1, RegisterAtomicPrivateSettlementPrepareV1,
            },
            settlement::{
                DvpIsi, FundFxCorridorEscrow, FxCorridorOracleEvidence, FxCorridorPolicy,
                FxCorridorPolicyRegistry, PvpIsi, RefundFxCorridorEscrow, SetFxCorridorPolicy,
                SettleFxCorridor, SettlementAtomicity, SettlementExecutionOrder,
                SettlementInstructionBox, SettlementLeg, SettlementPlan,
            },
            smart_contract_code::{
                FinalizeSmartContractCodeUpload, RegisterSmartContractBytes,
                UploadSmartContractCodeChunk,
            },
        },
        nexus::{
            AUTOSCALE_META_COMMITTEE, AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_DRAIN_STATE,
            AUTOSCALE_META_MANAGED, AssetPermissionManifest, AtomicPrivateSettlementV1, LaneConfig,
            LaneVisibility, ManifestVersion, PrivateSettlementAbortReasonV1,
            PrivateSettlementCommitBundleV1, PrivateSettlementPoolGovernanceLifecycleV1,
            PrivateSettlementPrepareBarrierV1, PrivateSettlementRouteV1, UniversalAccountId,
        },
        oracle::{FeedConfigVersion, FeedEvent, FeedEventOutcome, FeedSuccess, ObservationValue},
        permission::Permission,
        prelude::*,
        sns::{NameControllerV1, NameRecordV1},
        transaction::TransactionBuilder,
    };
    use iroha_executor_data_model::permission::{
        account::{
            AccountAliasPermissionScope, CanDelegateAccountAliasResolution, CanManageAccountAlias,
            CanResolveAccountAlias,
        },
        asset_definition::{AssetDefinitionAliasPermissionScope, CanManageAssetDefinitionAlias},
        nexus::{
            CanPublishSpaceDirectoryManifest, CanPublishSpaceDirectoryManifestForAccountDomain,
            CanPublishSpaceDirectoryManifestForUaid,
        },
        trigger::CanRegisterTrigger,
    };
    use iroha_model_base::metadata::Metadata;

    use iroha_model_base::topology::LaneId;
    use iroha_primitives::numeric::NumericSpec;
    use iroha_primitives::time::TimeSource;
    use iroha_test_samples::gen_account_in;
    use nonzero_ext::nonzero;
    use std::collections::{BTreeMap, BTreeSet};
    #[test]
    fn every_artifact_operation_routes_its_exact_full_width_dataspace() {
        use iroha_data_model::{
            isi::smart_contract_code::*,
            smart_contract::{ContractArtifactId, manifest::ContractManifest},
        };
        let own = DataSpaceId::new((1_u64 << 40) + 7);
        let artifact_id = ContractArtifactId::new(own, Hash::new(b"artifact"));
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(artifact_id.code_hash),
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        };
        let operations: Vec<InstructionBox> = vec![
            RegisterSmartContractCode {
                artifact_id,
                manifest,
            }
            .into(),
            RegisterSmartContractBytes {
                artifact_id,
                code: vec![1],
            }
            .into(),
            UploadSmartContractCodeChunk {
                artifact_id,
                total_size: 1,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![1],
            }
            .into(),
            FinalizeSmartContractCodeUpload {
                artifact_id,
                total_size: 1,
                chunk_count: 1,
            }
            .into(),
            CancelSmartContractCodeUpload { artifact_id }.into(),
            RemoveSmartContractBytes {
                artifact_id,
                reason: None,
            }
            .into(),
        ];
        let world = crate::state::World::new();
        let catalog = DataSpaceCatalog::default();
        for operation in operations {
            assert_eq!(
                instruction_transaction_dataspace_target(&*operation, Some(&catalog), None)
                    .unwrap(),
                Some(own)
            );
            assert_eq!(
                instruction_transaction_dataspace_target_with_world(
                    &*operation,
                    Some(&catalog),
                    &world.view(),
                    Some(0)
                )
                .unwrap(),
                Some(own)
            );
            let target =
                native_instruction_execution_target(&*operation, &catalog, &world.view(), 0)
                    .unwrap();
            assert_eq!(target.dataspace, Some(own));
            assert!(!target.global);
        }
    }
    #[test]
    fn routing_plan_frame_and_leg_payload_preserve_their_boundaries() {
        let leg = RouteLeg::new(RoutingDecision::default(), RouteLegRole::Coordinator);
        let plan = RoutingPlan::Single(leg);
        let leg_bytes = {
            let _layout =
                norito::core::DecodeFlagsGuard::enter(norito::core::header_flags::COMPACT_LEN);
            let mut bytes = Vec::new();
            norito::SerializePayload::serialize(&leg, &mut norito::core::Encoder::new(&mut bytes))
                .expect("encode route leg payload");
            assert_eq!(
                norito::core::decode_field_canonical::<RouteLeg>(&bytes)
                    .expect("decode route leg payload"),
                (leg, bytes.len())
            );
            bytes
        };
        assert!(!leg_bytes.is_empty());
        let plan_bytes = norito::encode_canonical(&plan).expect("encode routing plan");
        let unrelated_bytes = norito::encode_canonical(&42_u8).expect("encode unrelated owner");
        assert_eq!(
            norito::decode_from_bytes::<RoutingPlan>(&plan_bytes).expect("decode routing plan"),
            plan
        );
        assert!(matches!(
            norito::decode_from_bytes::<u8>(&plan_bytes),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(matches!(
            norito::decode_from_bytes::<RoutingPlan>(&unrelated_bytes),
            Err(norito::Error::SchemaMismatch)
        ));
    }
    fn sample_transaction(
        authority: &AccountId,
        signer: &iroha_crypto::PrivateKey,
        instructions: Vec<InstructionBox>,
    ) -> AcceptedTransaction<'static> {
        sample_transaction_with_metadata(authority, signer, instructions, Metadata::default())
    }

    #[test]
    fn alias_registry_routing_is_unconditional_for_queue_and_replay() {
        use iroha_data_model::{
            alias_setup::{
                AliasDataSpaceIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1, AliasQuoteGuardV1,
                AliasTargetV1, ResolvedDataSpaceV1,
            },
            isi::alias_setup::{EnsureAlias, RenewAliasLease},
        };

        let (owner, signer) = gen_account_in("alias-registry");
        let (dataspace, lane, _, _, router) = routed_dataspace_fixture("paynet");
        let resolved = ResolvedDataSpaceV1::new("paynet".parse().unwrap(), dataspace);
        let guard = AliasQuoteGuardV1 {
            expected_policy_version: 1,
            expected_payment_asset: iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .unwrap(),
            max_amount: 1_u32.into(),
            valid_until_ms: u64::MAX,
        };
        let instructions: Vec<InstructionBox> = vec![
            EnsureAlias::new(
                AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                    dataspace: resolved.clone(),
                    owner: owner.clone(),
                }),
                AliasLeaseAcquisitionV1::new(1, None),
                guard.clone(),
            )
            .into(),
            RenewAliasLease::new(AliasTargetV1::Dataspace(resolved), 1, 2, guard).into(),
        ];
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        let universal =
            RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL));
        let foreign = RoutingPlan::single(RoutingDecision::new(lane, dataspace));
        for instruction in instructions {
            assert!(!instruction_transaction_dataspace_target_needs_state(
                &*instruction
            ));
            let transaction = sample_transaction(&owner, signer.private_key(), vec![instruction]);
            assert_eq!(
                router.try_route_plan_without_state(&transaction).unwrap(),
                Some(universal.clone())
            );
            assert_eq!(
                router
                    .try_route_plan_with_state(&transaction, &state)
                    .unwrap(),
                universal
            );
            let view = state.view();
            assert_eq!(
                router
                    .try_route_plan_with_view(&transaction, &view)
                    .unwrap(),
                universal
            );
            assert_eq!(
                evaluate_policy_plan_with_nexus_and_world_at(
                    view.nexus(),
                    &transaction,
                    view.world(),
                    0
                )
                .unwrap(),
                universal
            );
            for height in [1, 2, 3] {
                let block_route = evaluate_policy_plan_with_nexus_and_world_at_block_height(
                    view.nexus(),
                    &transaction,
                    view.world(),
                    0,
                    height,
                )
                .unwrap();
                assert_eq!(block_route, universal);
                assert_ne!(block_route, foreign);
            }
        }
    }

    #[test]
    fn private_settlement_carrier_routes_to_universal_without_state_lookup() {
        let (sponsor, _) = gen_account_in("settlement");
        let instruction = InstructionBox::from(FinalizeAtomicPrivateSettlementV1::new(
            PrivateSettlementCommitBundleV1 {
                version: AtomicPrivateSettlementV1::VERSION,
                manifest: AtomicPrivateSettlementV1 {
                    version: AtomicPrivateSettlementV1::VERSION,
                    network_id: super::super::queue_test_network_id(),
                    bundle_id: Hash::new(b"router-private-settlement-bundle"),
                    authority_context_height: 10,
                    expiry_height: 20,
                    sponsor,
                    public_fee_intent: iroha_data_model::transaction::FeePaymentIntent::authority(
                        Vec::new(),
                        None,
                    ),
                    fee_intent_digest: Hash::new(b"router-private-settlement-fee"),
                    reimbursement_terms_commitment: Hash::new(
                        b"router-private-settlement-reimbursement",
                    ),
                    reimbursement_leg_ordinal: 0,
                    legs: Vec::new(),
                },
                authority_catalog: Default::default(),
                legs: Vec::new(),
            },
        ));

        assert_eq!(
            instruction_settlement_dataspace_target(&*instruction, None, None),
            Ok(Some(DataSpaceId::UNIVERSAL))
        );
        assert_eq!(
            instruction_transaction_target_requires_universal_coordinator(
                &*instruction,
                None,
                None,
            ),
            Ok(true)
        );
        assert!(!instruction_transaction_dataspace_target_needs_state(
            &*instruction
        ));
    }

    #[test]
    fn private_settlement_prepare_registration_routes_to_universal_without_state_lookup() {
        let (sponsor, _) = gen_account_in("settlement-prepare-registration");
        let instruction = InstructionBox::from(RegisterAtomicPrivateSettlementPrepareV1::new(
            PrivateSettlementPrepareBarrierV1 {
                version: AtomicPrivateSettlementV1::VERSION,
                manifest: AtomicPrivateSettlementV1 {
                    version: AtomicPrivateSettlementV1::VERSION,
                    network_id: super::super::queue_test_network_id(),
                    bundle_id: Hash::new(b"router-private-settlement-prepare-registration"),
                    authority_context_height: 10,
                    expiry_height: 20,
                    sponsor,
                    public_fee_intent: iroha_data_model::transaction::FeePaymentIntent::authority(
                        Vec::new(),
                        None,
                    ),
                    fee_intent_digest: Hash::new(
                        b"router-private-settlement-prepare-registration-fee",
                    ),
                    reimbursement_terms_commitment: Hash::new(
                        b"router-private-settlement-prepare-registration-reimbursement",
                    ),
                    reimbursement_leg_ordinal: 0,
                    legs: Vec::new(),
                },
                authority_catalog: Default::default(),
                deltas: Vec::new(),
                prepare_certificates: Vec::new(),
                prepared_bundle_digest: Hash::new(
                    b"router-private-settlement-prepare-registration-barrier",
                ),
            },
        ));

        assert_eq!(
            instruction_settlement_dataspace_target(&*instruction, None, None),
            Ok(Some(DataSpaceId::UNIVERSAL))
        );
        assert_eq!(
            instruction_transaction_target_requires_universal_coordinator(
                &*instruction,
                None,
                None,
            ),
            Ok(true)
        );
        assert!(!instruction_transaction_dataspace_target_needs_state(
            &*instruction
        ));
    }

    #[test]
    fn private_settlement_abort_routes_to_universal_without_state_lookup() {
        let (sponsor, _) = gen_account_in("settlement-abort");
        let instruction = InstructionBox::from(AbortAtomicPrivateSettlementV1::new(
            AtomicPrivateSettlementV1 {
                version: AtomicPrivateSettlementV1::VERSION,
                network_id: super::super::queue_test_network_id(),
                bundle_id: Hash::new(b"router-private-settlement-abort"),
                authority_context_height: 10,
                expiry_height: 20,
                sponsor,
                public_fee_intent: iroha_data_model::transaction::FeePaymentIntent::authority(
                    Vec::new(),
                    None,
                ),
                fee_intent_digest: Hash::new(b"router-private-settlement-abort-fee"),
                reimbursement_terms_commitment: Hash::new(
                    b"router-private-settlement-abort-reimbursement",
                ),
                reimbursement_leg_ordinal: 0,
                legs: Vec::new(),
            },
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        ));

        assert_eq!(
            instruction_settlement_dataspace_target(&*instruction, None, None),
            Ok(Some(DataSpaceId::UNIVERSAL))
        );
        assert_eq!(
            instruction_transaction_target_requires_universal_coordinator(
                &*instruction,
                None,
                None,
            ),
            Ok(true)
        );
        assert!(!instruction_transaction_dataspace_target_needs_state(
            &*instruction
        ));
    }

    #[test]
    fn private_settlement_pool_activation_routes_to_its_dataspace_without_state_lookup() {
        let dataspace_id = DataSpaceId::new(73);
        let instruction = InstructionBox::from(ActivatePrivateSettlementPoolV1 {
            version: AtomicPrivateSettlementV1::VERSION,
            route: PrivateSettlementRouteV1 {
                dataspace_id,
                lane_id: LaneId::new(11),
                lane_incarnation: Hash::new(b"router-private-settlement-incarnation"),
            },
            pool_id: iroha_data_model::privacy::PrivacyPoolIdV1::new([0x81; 32]),
            asset_binding_commitment: Hash::new(b"router-private-settlement-asset-binding"),
            audit_policy_digest: Hash::new(b"router-private-settlement-audit-policy"),
            audit_key_epoch: 1,
            lifecycle: PrivateSettlementPoolGovernanceLifecycleV1 {
                governance_revision: 1,
                activation_height: 10,
                retirement_height: None,
            },
            governance_digest: Hash::new(b"router-private-settlement-governance"),
            initial_commitments: vec![iroha_data_model::privacy::PrivacyCommitmentV1::new(
                [0x91; 32],
            )],
        });

        assert_eq!(
            instruction_settlement_dataspace_target(&*instruction, None, None),
            Ok(Some(dataspace_id))
        );
        assert_eq!(
            instruction_transaction_target_requires_universal_coordinator(
                &*instruction,
                None,
                None,
            ),
            Ok(false)
        );
        assert!(!instruction_transaction_dataspace_target_needs_state(
            &*instruction
        ));
    }
    fn resolved_account_alias(alias: &str, dataspace_id: DataSpaceId) -> ResolvedAccountAliasV1 {
        ResolvedAccountAliasV1::new(
            alias
                .parse::<AccountAliasName>()
                .expect("canonical account alias"),
            dataspace_id,
        )
    }
    fn sample_transaction_with_metadata(
        authority: &AccountId,
        signer: &iroha_crypto::PrivateKey,
        instructions: Vec<InstructionBox>,
        metadata: Metadata,
    ) -> AcceptedTransaction<'static> {
        let network_id = super::super::queue_test_network_id();
        let mut builder = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .with_metadata(metadata);
        builder.set_creation_time(core::time::Duration::from_millis(1));
        let tx = builder.sign(signer);
        let default_limits = TransactionParameters::default();
        let params = TransactionParameters::with_max_signatures(
            nonzero!(16_u64),
            nonzero!(4096_u64),
            nonzero!(4096_u64),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_, time_source) = TimeSource::new_mock(core::time::Duration::from_millis(2));
        AcceptedTransaction::accept_with_time_source(
            tx,
            &network_id,
            core::time::Duration::from_secs(30),
            params,
            &crypto_cfg,
            &time_source,
        )
        .expect("tx should be accepted")
    }
    fn sample_executable_transaction(
        authority: &AccountId,
        signer: &iroha_crypto::PrivateKey,
        executable: iroha_data_model::transaction::Executable,
    ) -> AcceptedTransaction<'static> {
        sample_executable_transaction_with_metadata(
            authority,
            signer,
            executable,
            Metadata::default(),
        )
    }
    fn sample_executable_transaction_with_metadata(
        authority: &AccountId,
        signer: &iroha_crypto::PrivateKey,
        executable: iroha_data_model::transaction::Executable,
        metadata: Metadata,
    ) -> AcceptedTransaction<'static> {
        let network_id = super::super::queue_test_network_id();
        let mut builder = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(10_000),
            ),
        )
        .with_executable(executable)
        .with_metadata(metadata);
        builder.set_creation_time(core::time::Duration::from_millis(1));
        let tx = builder.sign(signer);
        let default_limits = TransactionParameters::default();
        let params = TransactionParameters::with_max_signatures(
            nonzero!(16_u64),
            nonzero!(4096_u64),
            nonzero!(4096_u64),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_, time_source) = TimeSource::new_mock(core::time::Duration::from_millis(2));
        AcceptedTransaction::accept_with_time_source(
            tx,
            &network_id,
            core::time::Duration::from_secs(30),
            params,
            &crypto_cfg,
            &time_source,
        )
        .expect("tx should be accepted")
    }
    fn sample_proved_executable(
        overlay: Vec<InstructionBox>,
    ) -> iroha_data_model::transaction::Executable {
        let meta = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 1,
            abi_version: 1,
        };
        let mut bytecode = meta.encode();
        bytecode.extend_from_slice(b"LTLB");
        bytecode.extend_from_slice(&0u32.to_le_bytes());
        bytecode.extend_from_slice(&0u32.to_le_bytes());
        bytecode.extend_from_slice(&0u32.to_le_bytes());
        bytecode.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        iroha_data_model::transaction::Executable::IvmProved(
            iroha_data_model::transaction::IvmProved {
                bytecode: iroha_data_model::transaction::IvmBytecode::from_compiled(bytecode),
                overlay: overlay.into(),
                events_commitment: Hash::new(b"events"),
                gas_policy_commitment: Hash::new(b"gas-policy"),
            },
        )
    }
    fn sample_contract_invocation(
        authority: &AccountId,
        dataspace: DataSpaceId,
        nonce: u64,
    ) -> iroha_data_model::transaction::executable::ContractInvocation {
        iroha_data_model::transaction::executable::ContractInvocation {
            contract_address: ContractAddress::derive(
                &super::super::queue_test_network_id(),
                authority,
                nonce,
                dataspace,
            )
            .expect("contract address"),
            expected_code_hash: Hash::new(format!("router-contract-{nonce}").as_bytes()),
            entrypoint: "transfer".to_owned(),
            arguments: None,
        }
    }
    fn sample_trigger_registration(
        authority: &AccountId,
        name: &str,
        executable: Executable,
    ) -> InstructionBox {
        let trigger_id: iroha_data_model::trigger::TriggerId = name.parse().expect("trigger id");
        let action = iroha_data_model::trigger::action::Action::new(
            executable,
            iroha_data_model::trigger::action::Repeats::Exactly(1),
            authority.clone(),
            iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants");
        InstructionBox::from(Register::trigger(Trigger::new(trigger_id, action)))
    }
    fn sample_contract_trigger_registration(
        authority: &AccountId,
        name: &str,
        dataspace: DataSpaceId,
        nonce: u64,
    ) -> InstructionBox {
        sample_trigger_registration(
            authority,
            name,
            Executable::ContractCall(sample_contract_invocation(authority, dataspace, nonce)),
        )
    }
    fn three_dataspace_contract_router() -> (
        LaneRoutingPolicy,
        DataSpaceCatalog,
        LaneCatalog,
        ConfigLaneRouter,
    ) {
        let policy = default_routing_policy();
        let catalog = dataspace_catalog(&[
            (DataSpaceId::new(7), "signer"),
            (DataSpaceId::new(8), "multisig"),
            (DataSpaceId::new(9), "contract"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), DataSpaceId::new(7)),
            (LaneId::new(3), DataSpaceId::new(8)),
            (LaneId::new(4), DataSpaceId::new(9)),
        ]);
        let router = ConfigLaneRouter::new(policy.clone(), catalog.clone(), lane_catalog.clone());
        (policy, catalog, lane_catalog, router)
    }
    fn account_scope_entry(
        dataspace: DataSpaceId,
    ) -> crate::nexus::space_directory::AccountScopeDirectoryEntry {
        let mut entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
        entry.ensure_dataspace(dataspace);
        entry
    }
    fn catalog_with_lane_dataspaces(entries: &[(LaneId, DataSpaceId)]) -> LaneCatalog {
        let max_lane = entries
            .iter()
            .map(|(lane, _)| lane.as_u32())
            .max()
            .unwrap_or(0);
        let lane_count =
            std::num::NonZeroU32::new(max_lane + 1).expect("catalog requires nonzero lanes");
        let lanes = entries
            .iter()
            .map(|(lane_id, dataspace_id)| LaneConfig {
                id: *lane_id,
                dataspace_id: *dataspace_id,
                alias: format!("lane-{}", lane_id.as_u32()),
                ..LaneConfig::default()
            })
            .collect();
        LaneCatalog::new(lane_count, lanes).expect("valid lane catalog")
    }
    fn lane_catalog_from_configs(lanes: Vec<LaneConfig>) -> LaneCatalog {
        let max_lane = lanes.iter().map(|lane| lane.id.as_u32()).max().unwrap_or(0);
        let lane_count =
            std::num::NonZeroU32::new(max_lane + 1).expect("catalog requires nonzero lanes");
        LaneCatalog::new(lane_count, lanes).expect("valid lane catalog")
    }
    fn nexus_with_routing(
        routing_policy: LaneRoutingPolicy,
        lane_catalog: LaneCatalog,
        dataspace_catalog: DataSpaceCatalog,
    ) -> Nexus {
        let lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog);
        Nexus {
            routing_policy,
            lane_catalog,
            lane_config,
            dataspace_catalog,
            ..Nexus::default()
        }
    }
    fn default_lane_config() -> LaneConfig {
        LaneConfig::default()
    }
    fn autoscale_elastic_lane_config(
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        created_height: u64,
    ) -> LaneConfig {
        let mut metadata = BTreeMap::new();
        metadata.insert(AUTOSCALE_META_MANAGED.to_string(), "true".to_string());
        metadata.insert(
            AUTOSCALE_META_CREATED_HEIGHT.to_string(),
            created_height.to_string(),
        );
        let mut lane = LaneConfig {
            id: lane_id,
            dataspace_id,
            alias: format!("elastic-lane-{}", lane_id.as_u32()),
            metadata,
            ..LaneConfig::default()
        };
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut lane);
        lane
    }
    fn role_registration_instruction(authority: &AccountId, name: &str) -> InstructionBox {
        let role_id = iroha_data_model::role::RoleId {
            name: name.parse().expect("valid role name"),
        };
        InstructionBox::from(Register::role(iroha_data_model::role::Role::new(
            role_id,
            authority.clone(),
        )))
    }
    fn catalog_with_lanes(lanes: &[LaneId]) -> LaneCatalog {
        let entries: Vec<(LaneId, DataSpaceId)> = lanes
            .iter()
            .map(|lane_id| (*lane_id, DataSpaceId::UNIVERSAL))
            .collect();
        catalog_with_lane_dataspaces(&entries)
    }
    fn state_from_world(world: crate::state::World) -> crate::state::State {
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let telemetry = crate::telemetry::StateTelemetry::default();
        #[cfg(feature = "telemetry")]
        return crate::state::State::with_telemetry(world, kura, query, telemetry);
        #[cfg(not(feature = "telemetry"))]
        crate::state::State::new(world, kura, query)
    }
    fn blank_state() -> crate::state::State {
        state_from_world(crate::state::World::default())
    }
    fn default_routing_policy() -> LaneRoutingPolicy {
        LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: Vec::new(),
        }
    }
    fn encoded_multisig_proposal_state(proposal: &MultisigProposalState) -> Vec<u8> {
        norito::to_bytes(proposal).expect("multisig proposal fixture must use canonical storage")
    }
    fn default_router(
        dataspace_catalog: DataSpaceCatalog,
        lane_catalog: LaneCatalog,
    ) -> ConfigLaneRouter {
        ConfigLaneRouter::new(default_routing_policy(), dataspace_catalog, lane_catalog)
    }
    macro_rules! two_account_policy_router_fixture {
        () => {{
            let (alice_id, alice_keypair) = gen_account_in("wonderland");
            let (bob_id, _) = gen_account_in("wonderland");
            let policy = LaneRoutingPolicy {
                default_lane: LaneId::SINGLE,
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![
                    LaneRoutingRule {
                        lane: LaneId::new(1),
                        dataspace: Some(DataSpaceId::new(1)),
                        matcher: LaneRoutingMatcher {
                            account: Some(alice_id.to_string()),
                            instruction: None,
                            description: None,
                        },
                    },
                    LaneRoutingRule {
                        lane: LaneId::new(2),
                        dataspace: Some(DataSpaceId::new(2)),
                        matcher: LaneRoutingMatcher {
                            account: Some(bob_id.to_string()),
                            instruction: None,
                            description: None,
                        },
                    },
                ],
            };
            let lane_catalog = catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(1), DataSpaceId::new(1)),
                (LaneId::new(2), DataSpaceId::new(2)),
            ]);
            let dataspace_catalog = DataSpaceCatalog::new(vec![
                iroha_data_model::nexus::DataSpaceMetadata::default(),
                iroha_data_model::nexus::DataSpaceMetadata {
                    id: DataSpaceId::new(1),
                    alias: "alice".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
                iroha_data_model::nexus::DataSpaceMetadata {
                    id: DataSpaceId::new(2),
                    alias: "bob".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("dataspace catalog");
            let router = ConfigLaneRouter::new(policy, dataspace_catalog, lane_catalog);
            (alice_id, alice_keypair, bob_id, router)
        }};
    }
    macro_rules! multisig_routing_fixture {
        ($submitter_id:ident $submitter_keypair:ident $multisig_id:ident $dataspace_id:ident $lane_id:ident $catalog:ident $lane_catalog:ident $policy:ident $router:ident $proposed:ident) => {
            let ($submitter_id, $submitter_keypair) = gen_account_in("wonderland");
            let ($multisig_id, _) = gen_account_in("wonderland");
            let (target_id, _) = gen_account_in("wonderland");
            let $dataspace_id = DataSpaceId::new(10);
            let $lane_id = LaneId::new(2);
            let $catalog = dataspace_catalog(&[($dataspace_id, "restricted")]);
            let $lane_catalog = catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                ($lane_id, $dataspace_id),
            ]);
            let $policy = default_routing_policy();
            let $router =
                ConfigLaneRouter::new($policy.clone(), $catalog.clone(), $lane_catalog.clone());
            let $proposed = vec![InstructionBox::from(Register::account(
                Account::new(target_id)
                    .with_label(Some(account_alias("retail@restricted", &$catalog))),
            ))];
        };
    }
    fn routed_dataspace_fixture(
        alias: &str,
    ) -> (
        DataSpaceId,
        LaneId,
        DataSpaceCatalog,
        LaneCatalog,
        ConfigLaneRouter,
    ) {
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, alias)]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (lane_id, dataspace_id),
        ]);
        let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
        (
            dataspace_id,
            lane_id,
            dataspace_catalog,
            lane_catalog,
            router,
        )
    }
    fn seed_committed_height_for_router_test(state: &crate::state::State, height: u64) {
        let mut block_hashes = state.block_hashes.block();
        for idx in 0..height {
            block_hashes.push_for_tests(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(Hash::new(idx.to_le_bytes())));
        }
        block_hashes.commit_for_tests();
    }
    fn install_router_nexus(state: &mut crate::state::State, router: &ConfigLaneRouter) {
        let mut nexus = state.nexus_snapshot();
        nexus.routing_policy = router.policy.as_ref().clone();
        nexus.dataspace_catalog = router.dataspace_catalog.as_ref().clone();
        nexus.lane_catalog = router.lane_catalog.as_ref().clone();
        replace_router_fixture_nexus(state, nexus);
    }
    fn install_router_lane_catalog(state: &mut crate::state::State, catalog: LaneCatalog) {
        let mut nexus = state.nexus_snapshot();
        nexus.lane_catalog = catalog;
        replace_router_fixture_nexus(state, nexus);
    }
    fn install_synthetic_router_nexus(state: &crate::state::State, router: &ConfigLaneRouter) {
        let mut nexus = state.nexus_snapshot();
        nexus.routing_policy = router.policy.as_ref().clone();
        nexus.dataspace_catalog = router.dataspace_catalog.as_ref().clone();
        nexus.lane_catalog = router.lane_catalog.as_ref().clone();
        state.install_synthetic_routing_snapshot_for_testing(nexus);
    }
    fn replace_router_fixture_nexus(
        state: &mut crate::state::State,
        nexus: iroha_config::parameters::actual::Nexus,
    ) {
        assert_eq!(
            state.view().height(),
            0,
            "configure routing fixtures before history"
        );
        let world = std::mem::take(&mut state.world);
        *state = crate::state::State::new_with_nexus_for_testing(
            world,
            nexus,
            crate::query::store::LiveQueryStore::start_test(),
        );
    }
    fn set_nexus_autoscale_range(
        state: &crate::state::State,
        enabled: bool,
        min_lane_id: u32,
        max_lane_id_exclusive: u32,
    ) {
        let mut nexus = state.nexus_snapshot();
        nexus.autoscale.enabled = enabled;
        nexus.autoscale.min_lane_id = std::num::NonZeroU32::new(min_lane_id)
            .expect("autoscale test min_lane_id must be nonzero");
        nexus.autoscale.max_lane_id_exclusive = std::num::NonZeroU32::new(max_lane_id_exclusive)
            .expect("autoscale test max_lane_id_exclusive must be nonzero");
        state.install_synthetic_routing_snapshot_for_testing(nexus);
    }
    fn dataspace_catalog(entries: &[(DataSpaceId, &str)]) -> DataSpaceCatalog {
        let mut metadata = vec![iroha_data_model::nexus::DataSpaceMetadata::default()];
        metadata.extend(entries.iter().map(|(id, alias)| {
            iroha_data_model::nexus::DataSpaceMetadata {
                id: *id,
                alias: (*alias).to_string(),
                description: None,
                fault_tolerance: 1,
            }
        }));
        DataSpaceCatalog::new(metadata).expect("valid dataspace catalog")
    }
    fn world_with_dynamic_dataspace_until(
        alias: &str,
        owner: &AccountId,
        expires_at_ms: u64,
    ) -> crate::state::World {
        let selector = crate::sns::selector_for_dataspace_alias(alias).expect("selector");
        let address = AccountAddress::from_account_id(owner).expect("account address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            expires_at_ms,
            expires_at_ms.saturating_add(100),
            expires_at_ms.saturating_add(200),
            Metadata::default(),
        );
        let mut world = crate::state::World::default();
        world
            .smart_contract_state_mut_for_testing()
            .insert(crate::sns::record_storage_key(&selector), record.encode());
        world
    }
    fn world_with_dynamic_dataspace(alias: &str, owner: &AccountId) -> crate::state::World {
        world_with_dynamic_dataspace_until(alias, owner, u64::MAX)
    }
    fn account_alias(literal: &str, catalog: &DataSpaceCatalog) -> AccountAlias {
        AccountAlias::from_literal(literal, catalog).expect("valid account alias")
    }
    fn state_with_account_aliases(
        accounts: &[(AccountId, AccountAlias)],
        dataspace_catalog: DataSpaceCatalog,
    ) -> crate::state::State {
        let mut world = crate::state::World::default();
        for (account_id, alias) in accounts {
            let account = Account::new(account_id.clone())
                .with_label(Some(alias.clone()))
                .build(account_id);
            let (account_id, account_value) = account.into_key_value();
            world.accounts.insert(account_id.clone(), account_value);
            world
                .account_aliases
                .insert(alias.clone(), account_id.clone());
            world
                .account_aliases_by_account
                .insert(account_id.clone(), BTreeSet::from([alias.clone()]));
            world.replace_account_rekey_record_for_testing(
                iroha_data_model::account::rekey::AccountRekeyRecord::new(
                    alias.clone(),
                    account_id.clone(),
                ),
            );
            let selector = crate::sns::selector_for_account_alias(alias, &dataspace_catalog)
                .expect("fixture account alias selector");
            let address = AccountAddress::from_account_id(&account_id)
                .expect("fixture account address must be canonical");
            let record = NameRecordV1::new(
                selector.clone(),
                account_id.clone(),
                vec![NameControllerV1::account(&address)],
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                Metadata::default(),
            );
            world
                .smart_contract_state_mut_for_testing()
                .insert(crate::sns::record_storage_key(&selector), record.encode());
        }
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let telemetry = crate::telemetry::StateTelemetry::default();
        #[cfg(feature = "telemetry")]
        let mut state = crate::state::State::with_telemetry(world, kura, query, telemetry);
        #[cfg(not(feature = "telemetry"))]
        let mut state = crate::state::State::new(world, kura, query);
        state.set_dataspace_catalog_for_testing(dataspace_catalog);
        state
    }
    fn state_with_account_scope_entries(
        accounts: &[(
            AccountId,
            crate::nexus::space_directory::AccountScopeDirectoryEntry,
        )],
        dataspace_catalog: DataSpaceCatalog,
    ) -> crate::state::State {
        // Scope is a projection of primary labels and alias bindings. Seed those
        // authoritative records so rebuilding a configured State preserves it.
        let aliases = accounts
            .iter()
            .enumerate()
            .flat_map(|(index, (account_id, entry))| {
                entry.iter().flat_map(move |(dataspace, domains)| {
                    let domains = if domains.is_empty() {
                        vec![None]
                    } else {
                        domains.iter().cloned().map(Some).collect()
                    };
                    domains.into_iter().map(move |domain| {
                        (
                            account_id.clone(),
                            AccountAlias::new(
                                format!("scope_{index}").parse().expect("scope label"),
                                domain,
                                *dataspace,
                            ),
                        )
                    })
                })
            })
            .collect::<Vec<_>>();
        let mut state = state_with_account_aliases(&aliases, dataspace_catalog);
        for (account_id, entry) in accounts {
            if entry.is_empty() {
                let account = Account::new(account_id.clone()).build(account_id);
                let (id, value) = account.into_key_value();
                state.world.accounts.insert(id, value);
            }
        }
        state
    }
    fn state_with_asset_definitions(
        asset_definitions: Vec<AssetDefinition>,
        dataspace_catalog: DataSpaceCatalog,
        lane_catalog: LaneCatalog,
    ) -> crate::state::State {
        let mut state = crate::state::State::new_with_nexus_for_testing(
            crate::state::World::default(),
            iroha_config::parameters::actual::Nexus {
                dataspace_catalog,
                lane_catalog,
                ..Default::default()
            },
            crate::query::store::LiveQueryStore::start_test(),
        );
        for asset_definition in asset_definitions {
            state
                .world
                .asset_definitions
                .insert(asset_definition.id.clone(), asset_definition);
        }
        state
    }
    fn state_with_bound_numeric_asset_definition(
        asset_definition: &AssetDefinitionId,
        alias: &str,
        display_name: &str,
        owner: &AccountId,
        dataspace_catalog: DataSpaceCatalog,
        lane_catalog: LaneCatalog,
    ) -> crate::state::State {
        let alias: AssetDefinitionAlias = alias.parse().expect("asset alias");
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    display_name.to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(owner),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        state
            .world
            .asset_definition_aliases
            .insert(alias.clone(), asset_definition.clone());
        state.world.asset_definition_alias_bindings.insert(
            asset_definition.clone(),
            crate::state::AssetDefinitionAliasBindingRecord {
                alias,
                lease_expiry_ms: None,
                grace_until_ms: None,
                bound_at_ms: 0,
            },
        );
        state
    }
    fn bind_asset_definition_alias(
        state: &mut crate::state::State,
        asset_definition: &AssetDefinitionId,
        alias: &str,
    ) {
        let alias: AssetDefinitionAlias = alias.parse().expect("asset alias");
        state
            .world
            .asset_definition_aliases
            .insert(alias.clone(), asset_definition.clone());
        state.world.asset_definition_alias_bindings.insert(
            asset_definition.clone(),
            crate::state::AssetDefinitionAliasBindingRecord {
                alias,
                lease_expiry_ms: None,
                grace_until_ms: None,
                bound_at_ms: 0,
            },
        );
    }
    fn add_unlabeled_account_with_alias(
        state: &mut crate::state::State,
        account_id: &AccountId,
        alias: AccountAlias,
    ) {
        let account = Account::new(account_id.clone()).build(account_id);
        let (account_id, account_value) = account.into_key_value();
        state
            .world
            .accounts
            .insert(account_id.clone(), account_value);
        state
            .world
            .account_aliases
            .insert(alias.clone(), account_id.clone());
        state
            .world
            .account_aliases_by_account
            .insert(account_id, BTreeSet::from([alias]));
    }
    fn scope_account_to_dataspace(
        state: &mut crate::state::State,
        account_id: &AccountId,
        dataspace_id: DataSpaceId,
    ) {
        let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
        scope_entry.ensure_dataspace(dataspace_id);
        state
            .world
            .account_scope_directory
            .insert(account_id.clone(), scope_entry);
    }
    include!("router_initial_routing_tests.rs");
    #[test]
    fn canonical_dataspace_route_classifies_unknown_scope_before_lane_absence() {
        let unknown = DataSpaceId::new(8);
        for lanes in [
            LaneCatalog::default(),
            lane_catalog_from_configs(vec![LaneConfig {
                id: LaneId::SINGLE,
                dataspace_id: unknown,
                ..LaneConfig::default()
            }]),
        ] {
            assert_eq!(
                canonical_dataspace_route(unknown, &lanes, &DataSpaceCatalog::default()),
                Err(RoutingResolveError::UnknownDataspace {
                    dataspace_id: unknown
                })
            );
        }
    }
    #[test]
    fn canonical_dataspace_route_ignores_autoscale_owned_lanes() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(9),
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: Vec::new(),
        };
        let mut malformed_autoscale_claim =
            autoscale_elastic_lane_config(LaneId::new(2), DataSpaceId::UNIVERSAL, 7);
        malformed_autoscale_claim.alias = "lane-2".to_string();
        let lane_catalog = lane_catalog_from_configs(vec![
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
            malformed_autoscale_claim,
            LaneConfig {
                id: LaneId::new(9),
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "base-default".to_string(),
                ..LaneConfig::default()
            },
        ]);
        let dataspace_catalog = DataSpaceCatalog::default();
        let expected = RoutingDecision::new(LaneId::new(9), DataSpaceId::UNIVERSAL);
        assert_eq!(
            canonical_dataspace_route(DataSpaceId::UNIVERSAL, &lane_catalog, &dataspace_catalog)
                .expect("canonical universal route should use the non-autoscale base lane"),
            expected
        );
        let router = ConfigLaneRouter::new(policy.clone(), dataspace_catalog, lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("canonical", "universal").expect("domain"),
            )))],
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("catalog routing should ignore autoscale-owned canonical lanes"),
            expected
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("live routing should ignore autoscale-owned canonical lanes"),
            expected
        );
    }
    #[test]
    fn canonical_dataspace_route_fails_closed_with_only_autoscale_owned_lanes() {
        let mut malformed_autoscale_claim =
            autoscale_elastic_lane_config(LaneId::new(2), DataSpaceId::UNIVERSAL, 7);
        malformed_autoscale_claim
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_string(), "FALSE".to_string());
        malformed_autoscale_claim.alias = "lane-2".to_string();
        let lane_catalog = lane_catalog_from_configs(vec![
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
            malformed_autoscale_claim,
        ]);
        assert_eq!(
            canonical_dataspace_route(
                DataSpaceId::UNIVERSAL,
                &lane_catalog,
                &DataSpaceCatalog::default()
            ),
            Err(RoutingResolveError::NoLaneForDataspace {
                dataspace_id: DataSpaceId::UNIVERSAL,
            })
        );
    }
    #[test]
    fn canonical_dataspace_route_fails_closed_with_created_height_only_reserved_lane() {
        let mut marker_only = LaneConfig {
            id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "created-height-only".to_string(),
            ..LaneConfig::default()
        };
        marker_only
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "42".to_string());
        let lane_catalog = lane_catalog_from_configs(vec![marker_only]);
        assert_eq!(
            canonical_dataspace_route(
                DataSpaceId::UNIVERSAL,
                &lane_catalog,
                &DataSpaceCatalog::default()
            ),
            Err(RoutingResolveError::NoLaneForDataspace {
                dataspace_id: DataSpaceId::UNIVERSAL,
            })
        );
    }
    #[test]
    fn canonical_dataspace_route_fails_closed_for_every_consensus_autoscale_marker() {
        for marker in [AUTOSCALE_META_DRAIN_STATE, AUTOSCALE_META_COMMITTEE] {
            let mut marker_only = LaneConfig {
                id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: format!("reserved-{marker}"),
                ..LaneConfig::default()
            };
            marker_only
                .metadata
                .insert(marker.to_owned(), "malformed-but-reserved".to_owned());
            let lane_catalog = lane_catalog_from_configs(vec![marker_only]);
            assert_eq!(
                canonical_dataspace_route(
                    DataSpaceId::UNIVERSAL,
                    &lane_catalog,
                    &DataSpaceCatalog::default()
                ),
                Err(RoutingResolveError::NoLaneForDataspace {
                    dataspace_id: DataSpaceId::UNIVERSAL,
                }),
                "presence of reserved marker {marker} must never make a lane look operator-owned"
            );
        }
    }
    #[test]
    fn default_route_shards_no_target_traffic_across_autoscaled_lanes() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router =
            ConfigLaneRouter::new(policy.clone(), DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        seed_committed_height_for_router_test(&state, 7);
        let mut lanes_seen = BTreeSet::new();
        for idx in 0..256 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("elasticroute{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("default route should resolve with live catalog");
            assert_eq!(
                router
                    .try_route_with_state(&tx, &state)
                    .expect("default route should resolve with live state"),
                with_view
            );
            let with_catalog = evaluate_policy_with_catalog(
                &policy,
                router.lane_catalog.as_ref(),
                router.dataspace_catalog.as_ref(),
                &tx,
            )
            .expect("default route should resolve with configured catalog");
            assert_eq!(
                with_catalog,
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                "catalog-only default routing must not shard over autoscale lanes without live state"
            );
            assert_eq!(
                router
                    .try_route(&tx)
                    .expect("catalog-only route should resolve to base default lane"),
                with_catalog
            );
            assert_eq!(
                router
                    .try_route_plan(&tx)
                    .expect("catalog-only route plan should resolve to base default lane"),
                RoutingPlan::single(with_catalog)
            );
            assert_eq!(
                router
                    .try_route_without_state(&tx)
                    .expect("state-free default-route check should be deterministic"),
                None
            );
            assert_eq!(with_view.dataspace_id, DataSpaceId::UNIVERSAL);
            lanes_seen.insert(with_view.lane_id);
            if lanes_seen.len() == 2 {
                break;
            }
        }
        assert_eq!(lanes_seen, BTreeSet::from([LaneId::SINGLE, LaneId::new(1)]));
    }
    #[test]
    fn default_route_shards_no_target_ivm_traffic_with_state_not_state_free_hint() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        seed_committed_height_for_router_test(&state, 7);
        let mut lanes_seen = BTreeSet::new();
        for idx in 0..512_u64 {
            let mut metadata = Metadata::default();
            metadata.insert(
                "nonce".parse().expect("metadata key"),
                iroha_primitives::json::Json::new(idx),
            );
            let tx = sample_executable_transaction_with_metadata(
                &alice_id,
                alice_keypair.private_key(),
                sample_proved_executable(Vec::new()),
                metadata,
            );
            assert_eq!(
                router
                    .try_route_without_state(&tx)
                    .expect("state-free no-target IVM route should be deterministic"),
                None,
                "state-free no-target IVM routing must defer possible autoscale sharding"
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("live no-target IVM route should resolve");
            assert_eq!(
                router
                    .try_route_with_state(&tx, &state)
                    .expect("live no-target IVM route should resolve with state"),
                with_view
            );
            lanes_seen.insert(with_view.lane_id);
            if lanes_seen.len() == 2 {
                break;
            }
        }
        assert_eq!(lanes_seen, BTreeSet::from([LaneId::SINGLE, LaneId::new(1)]));
    }
    #[test]
    fn default_route_sharding_fails_closed_for_future_created_elastic_lane() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        seed_committed_height_for_router_test(&state, 6);
        for idx in 0..64 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("futureelasticroute{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("future-created elastic lane should fail closed to the default route");
            assert_eq!(
                with_view,
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                "future-created elastic lanes must not receive default-route traffic"
            );
            assert_eq!(
                router
                    .try_route_with_state(&tx, &state)
                    .expect("future-created elastic lane route should resolve"),
                with_view
            );
            assert_eq!(
                router
                    .try_route_plan_with_view(&tx, &state.view())
                    .expect("future-created elastic lane plan should resolve to the default route"),
                RoutingPlan::single(with_view),
                "future-created elastic lanes must not appear in default-route plans"
            );
        }
    }
    #[test]
    fn default_route_sharding_rejects_retired_drain_metadata() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let mut elastic = autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7);
        elastic
            .metadata
            .insert(AUTOSCALE_META_DRAIN_STATE.to_owned(), "{}".to_owned());
        let lane_catalog = lane_catalog_from_configs(vec![default_lane_config(), elastic]);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            DataSpaceCatalog::default(),
            lane_catalog,
        );
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        seed_committed_height_for_router_test(&state, 7);
        for index in 0..256 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("retireddrain{index}"),
                )],
            );
            let plan = router
                .try_route_plan_with_view(&tx, &state.view())
                .expect("base lane remains routable");
            assert_eq!(
                plan,
                RoutingPlan::single(RoutingDecision::default()),
                "retired metadata cannot authorize an elastic lane"
            );
        }
    }
    #[test]
    fn nexus_world_routing_at_block_height_excludes_future_created_elastic_lane() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let mut nexus = iroha_config::parameters::actual::Nexus {
            ..Default::default()
        };
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id = nonzero!(1_u32);
        nexus.autoscale.max_lane_id_exclusive = nonzero!(8_u32);
        nexus.lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        let state = blank_state();
        let mut saw_active_elastic = false;
        for idx in 0..256 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("heightawareelasticroute{idx}"),
                )],
            );
            assert_eq!(
                evaluate_policy_plan_with_nexus_and_world_at_block_height(
                    &nexus,
                    &tx,
                    state.view().world(),
                    0,
                    6,
                )
                .expect("future-created lane should resolve to the default plan"),
                RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)),
                "future-created elastic lanes must not be selected before their creation height"
            );
            assert_eq!(
                evaluate_policy_plan_with_nexus_and_world_at(&nexus, &tx, state.view().world(), 0,)
                    .expect("heightless Nexus/world route should resolve to the default plan"),
                RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)),
                "heightless Nexus/world routing must not shard over autoscale lanes"
            );
            let active_plan = evaluate_policy_plan_with_nexus_and_world_at_block_height(
                &nexus,
                &tx,
                state.view().world(),
                0,
                7,
            )
            .expect("active elastic lane should resolve at its creation height");
            if active_plan.coordinator_route().lane_id == LaneId::new(1) {
                saw_active_elastic = true;
                break;
            }
        }
        assert!(
            saw_active_elastic,
            "fixture should find a transaction assigned to the active elastic lane"
        );
    }
    #[test]
    fn default_route_sharding_fails_closed_with_default_anchor_above_elastic_range() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(9),
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: Vec::new(),
        };
        let lane_catalog = lane_catalog_from_configs(vec![
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
            LaneConfig {
                id: LaneId::new(9),
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "base-default".to_string(),
                ..LaneConfig::default()
            },
            LaneConfig {
                id: LaneId::new(10),
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "manual-sidecar".to_string(),
                ..LaneConfig::default()
            },
        ]);
        let router =
            ConfigLaneRouter::new(policy.clone(), DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 3);
        seed_committed_height_for_router_test(&state, 7);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![role_registration_instruction(
                &alice_id,
                "highdefaultelasticroute",
            )],
        );
        let expected = RoutingDecision::new(LaneId::new(9), DataSpaceId::UNIVERSAL);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("state-free routing should be deterministic"),
            None,
            "state-free no-target routing must defer possible autoscale sharding to live state"
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("catalog-only route should resolve to the high default anchor"),
            expected,
            "catalog-only default routing must stay pinned to the configured default anchor"
        );
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("default route should resolve with live Nexus state"),
            expected,
            "runtime high-side default route must fail closed instead of sharding onto elastic lanes"
        );
        assert_eq!(
            router
                .try_route_plan_with_state(&tx, &state)
                .expect("default route plan should resolve with live Nexus state"),
            RoutingPlan::single(expected)
        );
    }
    #[test]
    fn default_route_with_unmatched_rules_still_uses_live_autoscale_range() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(8),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("register::domain".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
            LaneConfig {
                id: LaneId::new(8),
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "manual-domain-lane".to_string(),
                ..LaneConfig::default()
            },
        ]);
        let router =
            ConfigLaneRouter::new(policy.clone(), DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        seed_committed_height_for_router_test(&state, 7);
        let mut lanes_seen = BTreeSet::new();
        for idx in 0..512 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("unmatchedruledefault{idx}"),
                )],
            );
            assert_eq!(
                router
                    .try_route_without_state(&tx)
                    .expect("state-free routing should be deterministic"),
                None,
                "unmatched rules must not make no-target default routing catalog-only"
            );
            assert_eq!(
                router
                    .try_route_plan_without_state(&tx)
                    .expect("state-free plan routing should be deterministic"),
                None,
                "unmatched rules must not make no-target default plans catalog-only"
            );
            assert_eq!(
                evaluate_policy_with_catalog(
                    &policy,
                    router.lane_catalog.as_ref(),
                    router.dataspace_catalog.as_ref(),
                    &tx,
                )
                .expect("catalog-only default route should resolve"),
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                "catalog-only routing remains pinned to the base default lane"
            );
            let with_state = router
                .try_route_with_state(&tx, &state)
                .expect("default route should resolve with live Nexus state");
            assert_eq!(with_state.dataspace_id, DataSpaceId::UNIVERSAL);
            assert_eq!(
                router
                    .try_route_plan_with_state(&tx, &state)
                    .expect("default route plan should resolve with live Nexus state"),
                RoutingPlan::single(with_state)
            );
            lanes_seen.insert(with_state.lane_id);
            if lanes_seen.len() == 2 {
                break;
            }
        }
        assert_eq!(
            lanes_seen,
            BTreeSet::from([LaneId::SINGLE, LaneId::new(1)]),
            "live default-route sharding must use the elastic lane even when unrelated rules exist"
        );
    }
    #[test]
    fn default_route_sharding_ignores_autoscale_lanes_outside_enabled_range() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
            autoscale_elastic_lane_config(LaneId::new(8), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        seed_committed_height_for_router_test(&state, 7);
        let mut lanes_seen = BTreeSet::new();
        for idx in 0..512 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("rangedefault{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("default route should resolve with live catalog");
            assert_eq!(
                router
                    .try_route_with_state(&tx, &state)
                    .expect("ranged default route should resolve"),
                with_view
            );
            assert_ne!(with_view.lane_id, LaneId::new(8));
            assert_eq!(
                router
                    .try_route_plan_with_view(&tx, &state.view())
                    .expect("default route plan should resolve with live catalog"),
                RoutingPlan::single(with_view)
            );
            lanes_seen.insert(with_view.lane_id);
            if lanes_seen.len() == 2 {
                break;
            }
        }
        assert_eq!(lanes_seen, BTreeSet::from([LaneId::SINGLE, LaneId::new(1)]));
    }
    #[test]
    fn default_route_sharding_fails_closed_when_elastic_range_contains_corruption() {
        struct CorruptionCase {
            name: &'static str,
            lane: LaneConfig,
        }
        let mut malformed_managed =
            autoscale_elastic_lane_config(LaneId::new(2), DataSpaceId::UNIVERSAL, 7);
        malformed_managed.alias = "malformed-elastic-lane".to_string();
        let cases = [
            CorruptionCase {
                name: "manual-in-range",
                lane: LaneConfig {
                    id: LaneId::new(2),
                    alias: "manual-elastic-range".to_string(),
                    ..LaneConfig::default()
                },
            },
            CorruptionCase {
                name: "malformed-managed-in-range",
                lane: malformed_managed,
            },
            CorruptionCase {
                name: "off-default-managed-in-range",
                lane: autoscale_elastic_lane_config(LaneId::new(2), DataSpaceId::new(9), 7),
            },
        ];
        for case in cases {
            let (alice_id, alice_keypair) = gen_account_in("wonderland");
            let policy = default_routing_policy();
            let lane_catalog = lane_catalog_from_configs(vec![
                default_lane_config(),
                autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
                case.lane,
            ]);
            let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
            let state = blank_state();
            install_synthetic_router_nexus(&state, &router);
            set_nexus_autoscale_range(&state, true, 1, 8);
            seed_committed_height_for_router_test(&state, 7);
            for idx in 0..64 {
                let tx = sample_transaction(
                    &alice_id,
                    alice_keypair.private_key(),
                    vec![role_registration_instruction(
                        &alice_id,
                        &format!("{}{}", case.name.replace('-', ""), idx),
                    )],
                );
                let with_view = router
                    .try_route_with_view(&tx, &state.view())
                    .unwrap_or_else(|err| {
                        panic!("{}: default route should resolve: {err}", case.name)
                    });
                assert_eq!(
                    with_view,
                    RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                    "{} corruption must keep default traffic on the base lane until repaired",
                    case.name
                );
                assert_eq!(
                    router
                        .try_route_with_state(&tx, &state)
                        .unwrap_or_else(|err| panic!("{}: state route failed: {err}", case.name)),
                    with_view
                );
                assert_eq!(
                    router
                        .try_route_plan_with_view(&tx, &state.view())
                        .unwrap_or_else(|err| panic!(
                            "{}: default route plan should resolve: {err}",
                            case.name
                        )),
                    RoutingPlan::single(with_view),
                    "{} corruption must not keep sharding route plans over elastic lanes",
                    case.name
                );
            }
        }
    }
    #[test]
    fn default_route_sharding_ignores_managed_lanes_when_autoscale_disabled() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, false, 1, 8);
        for idx in 0..64 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("disabledefault{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("default route should resolve with live catalog");
            assert_eq!(
                router
                    .try_route_with_state(&tx, &state)
                    .expect("disabled autoscale default route should resolve"),
                with_view
            );
            assert_eq!(
                with_view,
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
            );
            assert_eq!(
                router
                    .try_route_plan_with_view(&tx, &state.view())
                    .expect("default route plan should resolve with live catalog"),
                RoutingPlan::single(with_view)
            );
        }
    }
    #[test]
    fn default_route_sharding_fails_closed_when_default_lane_is_inside_autoscale_range() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(1),
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: Vec::new(),
        };
        let lane_catalog = lane_catalog_from_configs(vec![
            LaneConfig {
                id: LaneId::new(1),
                alias: "corrupt-default".to_string(),
                ..LaneConfig::default()
            },
            autoscale_elastic_lane_config(LaneId::new(2), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        for idx in 0..64 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("defaultinrange{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("corrupt default route should still resolve to the default lane");
            assert_eq!(
                with_view,
                RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL)
            );
            assert_eq!(
                router
                    .try_route_plan_with_view(&tx, &state.view())
                    .expect("corrupt default route plan should still resolve"),
                RoutingPlan::single(with_view)
            );
        }
    }
    #[test]
    fn default_route_sharding_fails_closed_when_autoscale_max_lane_id_exclusive_exceeds_cap() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(
            &state,
            true,
            1,
            iroha_config::parameters::defaults::nexus::autoscale::MAX_LANE_ID_EXCLUSIVE + 1,
        );
        for idx in 0..64 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("autoscalecap{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("default route should resolve when autoscale bounds are invalid");
            assert_eq!(
                with_view,
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
            );
            assert_eq!(
                router
                    .try_route_plan_with_view(&tx, &state.view())
                    .expect("default route plan should resolve when autoscale bounds are invalid"),
                RoutingPlan::single(with_view)
            );
        }
    }
    #[test]
    fn default_route_sharding_fails_closed_when_autoscale_min_exceeds_max() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 4, 2);
        for idx in 0..64 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("autoscaleinverted{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("default route should resolve when autoscale bounds are inverted");
            assert_eq!(
                with_view,
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
            );
            assert_eq!(
                router
                    .try_route_plan_with_state(&tx, &state)
                    .expect("default route plan should resolve when autoscale bounds are inverted"),
                RoutingPlan::single(with_view)
            );
        }
    }
    #[test]
    fn default_route_sharding_fails_closed_when_autoscale_min_equals_max() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = default_routing_policy();
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(4), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 4, 4);
        for idx in 0..64 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("autoscaleempty{idx}"),
                )],
            );
            let with_view = router
                .try_route_with_view(&tx, &state.view())
                .expect("default route should resolve when autoscale range is empty");
            assert_eq!(
                with_view,
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                "empty autoscale elastic ranges must fail closed to the default lane"
            );
            assert_eq!(
                router
                    .try_route_plan_with_state(&tx, &state)
                    .expect("default route plan should resolve when autoscale range is empty"),
                RoutingPlan::single(with_view)
            );
        }
    }
    #[test]
    fn default_route_rejects_autoscale_owned_default_lane() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(1),
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: Vec::new(),
        };
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![role_registration_instruction(&alice_id, "autoscaledefault")],
        );
        assert_eq!(
            router.try_route(&tx),
            Err(RoutingResolveError::AutoscaleOwnedDefaultLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_with_view(&tx, &state.view()),
            Err(RoutingResolveError::AutoscaleOwnedDefaultLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_plan(&tx),
            Err(RoutingResolveError::AutoscaleOwnedDefaultLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_with_state(&tx, &state),
            Err(RoutingResolveError::AutoscaleOwnedDefaultLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(router.try_route_without_state(&tx), Ok(None));
    }
    #[test]
    fn default_route_rejects_created_height_only_default_lane() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(1),
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: Vec::new(),
        };
        let mut marker_only = LaneConfig {
            id: LaneId::new(1),
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "created-height-only-default".to_string(),
            ..LaneConfig::default()
        };
        marker_only
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "42".to_string());
        let lane_catalog = lane_catalog_from_configs(vec![default_lane_config(), marker_only]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![role_registration_instruction(
                &alice_id,
                "createdheightdefault",
            )],
        );
        assert_eq!(
            router.try_route(&tx),
            Err(RoutingResolveError::AutoscaleOwnedDefaultLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_plan(&tx),
            Err(RoutingResolveError::AutoscaleOwnedDefaultLane {
                lane_id: LaneId::new(1),
            })
        );
    }
    #[test]
    fn explicit_rule_overrides_autoscaled_default_sharding() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(2),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("register::role".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
            LaneConfig {
                id: LaneId::new(2),
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "manual-role-lane".to_string(),
                ..LaneConfig::default()
            },
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        for idx in 0..32 {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![role_registration_instruction(
                    &alice_id,
                    &format!("manualroute{idx}"),
                )],
            );
            assert_eq!(
                router
                    .try_route_with_view(&tx, &state.view())
                    .expect("explicit rule route should resolve"),
                RoutingDecision::new(LaneId::new(2), DataSpaceId::UNIVERSAL)
            );
            assert_eq!(
                router
                    .try_route_without_state(&tx)
                    .expect("explicit rule state-free route should resolve")
                    .expect("explicit rule route should not need state"),
                RoutingDecision::new(LaneId::new(2), DataSpaceId::UNIVERSAL)
            );
        }
    }
    #[test]
    fn explicit_rule_rejects_autoscale_owned_rule_lane() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::UNIVERSAL),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("register::role".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = lane_catalog_from_configs(vec![
            default_lane_config(),
            autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        ]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        set_nexus_autoscale_range(&state, true, 1, 8);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![role_registration_instruction(&alice_id, "autoscalerule")],
        );
        assert_eq!(
            router.try_route(&tx),
            Err(RoutingResolveError::AutoscaleOwnedRuleLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_with_view(&tx, &state.view()),
            Err(RoutingResolveError::AutoscaleOwnedRuleLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_plan(&tx),
            Err(RoutingResolveError::AutoscaleOwnedRuleLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_with_state(&tx, &state),
            Err(RoutingResolveError::AutoscaleOwnedRuleLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_without_state(&tx),
            Err(RoutingResolveError::AutoscaleOwnedRuleLane {
                lane_id: LaneId::new(1),
            })
        );
    }
    #[test]
    fn explicit_rule_rejects_created_height_only_rule_lane() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::UNIVERSAL),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("register::role".to_string()),
                    description: None,
                },
            }],
        };
        let mut marker_only = LaneConfig {
            id: LaneId::new(1),
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "created-height-only-rule".to_string(),
            ..LaneConfig::default()
        };
        marker_only
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "42".to_string());
        let lane_catalog = lane_catalog_from_configs(vec![default_lane_config(), marker_only]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![role_registration_instruction(
                &alice_id,
                "createdheightrule",
            )],
        );
        assert_eq!(
            router.try_route(&tx),
            Err(RoutingResolveError::AutoscaleOwnedRuleLane {
                lane_id: LaneId::new(1),
            })
        );
        assert_eq!(
            router.try_route_without_state(&tx),
            Err(RoutingResolveError::AutoscaleOwnedRuleLane {
                lane_id: LaneId::new(1),
            })
        );
    }
    #[test]
    fn resolve_policy_rejects_rule_dataspace_override_for_target() {
        use iroha_data_model::nexus::DataSpaceMetadata;
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(5),
                dataspace: Some(DataSpaceId::new(7)),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("register".to_string()),
                    description: None,
                },
            }],
        };
        let dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: DataSpaceId::new(7),
                alias: "alpha".to_string(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("valid dataspace catalog");
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(5), DataSpaceId::new(7)),
        ]);
        assert_eq!(
            resolve_policy_routing_decision(
                &policy,
                Some(&policy.rules[0]),
                Some(DataSpaceId::UNIVERSAL),
                false,
                &lane_catalog,
                &dataspace_catalog,
                None,
                None,
            ),
            Err(RoutingResolveError::LaneDataspaceMismatch {
                lane_id: LaneId::new(5),
                lane_dataspace_id: DataSpaceId::new(7),
                dataspace_id: DataSpaceId::UNIVERSAL,
            })
        );
    }
    #[test]
    fn settlement_routes_to_common_leg_dataspace_before_account_policy() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::new(7)),
                matcher: LaneRoutingMatcher {
                    account: Some(alice_id.to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        };
        let router = ConfigLaneRouter::new(
            policy,
            dataspace_catalog(&[(DataSpaceId::new(7), "restricted")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(1), DataSpaceId::new(7)),
            ]),
        );
        let delivery_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("settlement", "universal").expect("domain id"),
            "bond".parse().expect("asset definition name"),
        );
        let payment_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("settlement", "universal").expect("domain id"),
            "cash".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(DvpIsi::new(
                "commonroute".parse().expect("settlement id"),
                SettlementLeg::new(
                    delivery_definition.clone(),
                    1_u32,
                    alice_id.clone(),
                    bob_id.clone(),
                ),
                SettlementLeg::new(payment_definition.clone(), 1_u32, bob_id, alice_id.clone()),
                SettlementPlan::new(
                    SettlementExecutionOrder::DeliveryThenPayment,
                    SettlementAtomicity::AllOrNothing,
                ),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    delivery_definition,
                    "bond".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    payment_definition,
                    "cash".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            router.dataspace_catalog.as_ref().clone(),
            router.lane_catalog.as_ref().clone(),
        );
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("settlement state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("settlement route should resolve from stored definitions"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn settlement_with_different_leg_dataspaces_routes_to_universal_coordinator() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(1),
            default_dataspace: DataSpaceId::new(7),
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::new(7)),
                matcher: LaneRoutingMatcher {
                    account: Some(alice_id.to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        };
        let router = ConfigLaneRouter::new(
            policy,
            dataspace_catalog(&[
                (DataSpaceId::new(7), "delivery"),
                (DataSpaceId::new(9), "payment"),
            ]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(1), DataSpaceId::new(7)),
                (LaneId::new(2), DataSpaceId::new(9)),
            ]),
        );
        let delivery_domain = DomainId::try_new("settlement", "delivery").expect("domain id");
        let payment_domain = DomainId::try_new("settlement", "payment").expect("domain id");
        let delivery_definition = AssetDefinitionId::derive_from_components(
            delivery_domain.clone(),
            "bond".parse().expect("asset definition name"),
        );
        let payment_definition = AssetDefinitionId::derive_from_components(
            payment_domain.clone(),
            "cash".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(DvpIsi::new(
                "crossroute".parse().expect("settlement id"),
                SettlementLeg::new(
                    delivery_definition.clone(),
                    1_u32,
                    alice_id.clone(),
                    bob_id.clone(),
                ),
                SettlementLeg::new(payment_definition.clone(), 1_u32, bob_id, alice_id.clone()),
                SettlementPlan::new(
                    SettlementExecutionOrder::DeliveryThenPayment,
                    SettlementAtomicity::AllOrNothing,
                ),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    delivery_definition,
                    "bond".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(delivery_domain),
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    payment_definition,
                    "cash".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(payment_domain),
                )
                .build(&alice_id),
            ],
            router.dataspace_catalog.as_ref().clone(),
            router.lane_catalog.as_ref().clone(),
        );
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("settlement state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("settlement route should resolve from stored definitions"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn settlement_pvp_with_different_leg_dataspaces_routes_to_universal_coordinator() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(1),
            default_dataspace: DataSpaceId::new(7),
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::new(7)),
                matcher: LaneRoutingMatcher {
                    account: Some(alice_id.to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        };
        let router = ConfigLaneRouter::new(
            policy,
            dataspace_catalog(&[
                (DataSpaceId::new(7), "primary"),
                (DataSpaceId::new(9), "counter"),
            ]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(1), DataSpaceId::new(7)),
                (LaneId::new(2), DataSpaceId::new(9)),
            ]),
        );
        let primary_domain = DomainId::try_new("settlement", "primary").expect("domain id");
        let counter_domain = DomainId::try_new("settlement", "counter").expect("domain id");
        let primary_definition = AssetDefinitionId::derive_from_components(
            primary_domain.clone(),
            "usd".parse().expect("asset definition name"),
        );
        let counter_definition = AssetDefinitionId::derive_from_components(
            counter_domain.clone(),
            "eur".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(PvpIsi::new(
                "pvpcrossroute".parse().expect("settlement id"),
                SettlementLeg::new(
                    primary_definition.clone(),
                    1_u32,
                    alice_id.clone(),
                    bob_id.clone(),
                ),
                SettlementLeg::new(counter_definition.clone(), 1_u32, bob_id, alice_id.clone()),
                SettlementPlan::new(
                    SettlementExecutionOrder::DeliveryThenPayment,
                    SettlementAtomicity::AllOrNothing,
                ),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    primary_definition,
                    "USD".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(primary_domain),
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    counter_definition,
                    "EUR".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(counter_domain),
                )
                .build(&alice_id),
            ],
            router.dataspace_catalog.as_ref().clone(),
            router.lane_catalog.as_ref().clone(),
        );
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("settlement state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("settlement route should resolve from stored definitions"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn bilateral_settlement_plans_retain_state_backed_participant_legs() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let delivery_dataspace = DataSpaceId::new(7);
        let payment_dataspace = DataSpaceId::new(9);
        let delivery_lane = LaneId::new(1);
        let payment_lane = LaneId::new(2);
        let dataspace_catalog = dataspace_catalog(&[
            (delivery_dataspace, "delivery"),
            (payment_dataspace, "payment"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (delivery_lane, delivery_dataspace),
            (payment_lane, payment_dataspace),
        ]);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        );
        let delivery_domain =
            DomainId::try_new("settlement", "delivery").expect("delivery domain id");
        let payment_domain = DomainId::try_new("settlement", "payment").expect("payment domain id");
        let delivery_definition = AssetDefinitionId::derive_from_components(
            delivery_domain.clone(),
            "bond".parse().expect("asset definition name"),
        );
        let payment_definition = AssetDefinitionId::derive_from_components(
            payment_domain.clone(),
            "cash".parse().expect("asset definition name"),
        );
        let global_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("settlement", "universal").expect("global domain id"),
            "global".parse().expect("asset definition name"),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    delivery_definition.clone(),
                    "bond".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(delivery_domain),
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    payment_definition.clone(),
                    "cash".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(payment_domain),
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    global_definition.clone(),
                    "global".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        );
        install_router_nexus(&mut state, &router);
        let expected = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![
                RouteLeg::new(
                    RoutingDecision::new(delivery_lane, delivery_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(payment_lane, payment_dataspace),
                    RouteLegRole::Participant,
                ),
            ],
        );
        let instructions = [
            (
                "DVP",
                InstructionBox::from(DvpIsi::new(
                    "dvp_plan".parse().expect("settlement id"),
                    SettlementLeg::new(
                        delivery_definition.clone(),
                        1_u32,
                        alice_id.clone(),
                        bob_id.clone(),
                    ),
                    SettlementLeg::new(
                        payment_definition.clone(),
                        1_u32,
                        bob_id.clone(),
                        alice_id.clone(),
                    ),
                    SettlementPlan::default(),
                )),
            ),
            (
                "boxed PVP",
                InstructionBox::from(SettlementInstructionBox::Pvp(PvpIsi::new(
                    "pvp_plan".parse().expect("settlement id"),
                    SettlementLeg::new(
                        delivery_definition.clone(),
                        1_u32,
                        alice_id.clone(),
                        bob_id.clone(),
                    ),
                    SettlementLeg::new(
                        payment_definition.clone(),
                        1_u32,
                        bob_id.clone(),
                        alice_id.clone(),
                    ),
                    SettlementPlan::default(),
                ))),
            ),
            (
                "multisig-wrapped DVP",
                InstructionBox::from(MultisigPropose::new(
                    alice_id.clone(),
                    vec![InstructionBox::from(DvpIsi::new(
                        "multisig_dvp_plan".parse().expect("settlement id"),
                        SettlementLeg::new(
                            delivery_definition.clone(),
                            1_u32,
                            alice_id.clone(),
                            bob_id.clone(),
                        ),
                        SettlementLeg::new(
                            payment_definition.clone(),
                            1_u32,
                            bob_id.clone(),
                            alice_id.clone(),
                        ),
                        SettlementPlan::default(),
                    ))],
                    None,
                )),
            ),
            (
                "multisig mixed private settlement and write",
                InstructionBox::from(MultisigPropose::new(
                    alice_id.clone(),
                    vec![
                        InstructionBox::from(DvpIsi::new(
                            "multisig_mixed_plan".parse().expect("settlement id"),
                            SettlementLeg::new(
                                delivery_definition.clone(),
                                1_u32,
                                alice_id.clone(),
                                bob_id.clone(),
                            ),
                            SettlementLeg::new(
                                delivery_definition.clone(),
                                1_u32,
                                bob_id.clone(),
                                alice_id.clone(),
                            ),
                            SettlementPlan::default(),
                        )),
                        InstructionBox::from(Register::domain(Domain::new(
                            DomainId::try_new("merchant", "payment").expect("domain id"),
                        ))),
                    ],
                    None,
                )),
            ),
        ];
        for (label, instruction) in instructions {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![instruction.clone()],
            );
            assert_eq!(
                router
                    .try_route_plan_without_state(&tx)
                    .expect("settlement state requirement should be deterministic"),
                None,
                "{label} must defer until definition ownership is loaded",
            );
            assert_eq!(
                router
                    .try_route_plan_with_state(&tx, &state)
                    .unwrap_or_else(|error| panic!("{label} state plan failed: {error}")),
                expected,
                "{label} state-backed plan must retain both settlement legs",
            );
            let view = state.view();
            assert_eq!(
                deferred_instruction_concrete_dataspace_targets(
                    &*instruction,
                    Some(&dataspace_catalog),
                    Some(&view),
                ),
                Ok(Some(BTreeSet::from([
                    delivery_dataspace,
                    payment_dataspace,
                ]))),
                "{label} must expose both concrete settlement targets",
            );
            assert_eq!(
                evaluate_policy_plan_with_catalog_and_world(
                    &default_routing_policy(),
                    &lane_catalog,
                    &dataspace_catalog,
                    &tx,
                    view.world(),
                )
                .unwrap_or_else(|error| panic!("{label} world plan failed: {error}")),
                expected,
                "{label} world-backed plan must retain both settlement legs",
            );
            let mut strict_metadata = Metadata::default();
            strict_metadata.insert(
                AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
                iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
            );
            let strict_tx = sample_transaction_with_metadata(
                &alice_id,
                alice_keypair.private_key(),
                vec![instruction],
                strict_metadata,
            );
            assert_eq!(
                router.try_route_plan_with_state(&strict_tx, &state),
                Err(
                    RoutingResolveError::ConflictingTransactionDataspaceTargets {
                        first_dataspace_id: delivery_dataspace,
                        second_dataspace_id: payment_dataspace,
                    }
                ),
                "strict metadata must reject cross-dataspace {label}",
            );
        }

        let global_private_instruction = InstructionBox::from(DvpIsi::new(
            "global_private_plan".parse().expect("settlement id"),
            SettlementLeg::new(global_definition, 1_u32, alice_id.clone(), bob_id.clone()),
            SettlementLeg::new(
                delivery_definition.clone(),
                1_u32,
                bob_id.clone(),
                alice_id.clone(),
            ),
            SettlementPlan::default(),
        ));
        let global_private_tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![global_private_instruction.clone()],
        );
        assert_eq!(
            router
                .try_route_plan_with_state(&global_private_tx, &state)
                .expect("global/private settlement plan should resolve"),
            RoutingPlan::native_amx(
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                vec![RouteLeg::new(
                    RoutingDecision::new(delivery_lane, delivery_dataspace),
                    RouteLegRole::Participant,
                )],
            ),
        );
        let mut strict_metadata = Metadata::default();
        strict_metadata.insert(
            AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
            iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
        );
        let strict_global_private_tx = sample_transaction_with_metadata(
            &alice_id,
            alice_keypair.private_key(),
            vec![global_private_instruction],
            strict_metadata,
        );
        assert_eq!(
            router.try_route_plan_with_state(&strict_global_private_tx, &state),
            Err(
                RoutingResolveError::ConflictingTransactionDataspaceTargets {
                    first_dataspace_id: DataSpaceId::UNIVERSAL,
                    second_dataspace_id: delivery_dataspace,
                }
            ),
            "strict policy must reject a universal coordinator plus private participant",
        );

        let same_dataspace_tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(DvpIsi::new(
                "same_dataspace_plan".parse().expect("settlement id"),
                SettlementLeg::new(
                    delivery_definition.clone(),
                    1_u32,
                    alice_id.clone(),
                    bob_id.clone(),
                ),
                SettlementLeg::new(delivery_definition, 1_u32, bob_id.clone(), alice_id.clone()),
                SettlementPlan::default(),
            ))],
        );
        assert_eq!(
            router
                .try_route_plan_with_state(&same_dataspace_tx, &state)
                .expect("same-dataspace DVP plan should resolve"),
            RoutingPlan::single(RoutingDecision::new(delivery_lane, delivery_dataspace,)),
        );
    }
    #[path = "router_account_refusal_tests.rs"]
    mod account_refusal_tests;
    #[path = "fx_scan_refusal_tests.rs"]
    mod fx_scan_refusal_tests;
    include!("router_transfer_batch_tests.rs");
    include!("router_route_resolution_tests.rs"); // Preserve stable route-resolution test paths.
    #[test]
    fn matches_register_domain_rule() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("register::domain".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1)]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("castle", "universal").expect("domain id"),
            )))],
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        let decision = router
            .try_route_with_view(&tx, &state.view())
            .expect("register-domain matcher route should resolve");
        assert_eq!(decision.lane_id, LaneId::new(1));
    }
    #[test]
    fn matches_smartcontract_deploy_rule() {
        assert!(matches_label(
            "smartcontract::deploy",
            "smartcontract::deploy"
        ));
        assert!(!matches_label(
            "smart_contract::deploy",
            "smartcontract::deploy"
        ));
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("smartcontract::deploy".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1)]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        let code_hash = Hash::new(&code);
        let cases = [
            InstructionBox::from(RegisterSmartContractBytes {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    DataSpaceId::UNIVERSAL,
                    code_hash,
                ),
                code: code.clone(),
            }),
            InstructionBox::from(UploadSmartContractCodeChunk {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    DataSpaceId::UNIVERSAL,
                    code_hash,
                ),
                total_size: u64::try_from(code.len()).unwrap(),
                chunk_index: 0,
                chunk_count: 1,
                chunk: code,
            }),
            InstructionBox::from(FinalizeSmartContractCodeUpload {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    DataSpaceId::UNIVERSAL,
                    code_hash,
                ),
                total_size: 4,
                chunk_count: 1,
            }),
        ];
        for instruction in cases {
            let tx = sample_transaction(&alice_id, alice_keypair.private_key(), vec![instruction]);
            let decision = router
                .try_route_with_view(&tx, &state.view())
                .expect("smart-contract deployment matcher route should resolve");
            assert_eq!(decision.lane_id, LaneId::new(1));
        }
    }
    #[test]
    fn contract_call_routes_to_contract_address_dataspace_without_explicit_rule() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &super::super::queue_test_network_id(),
            &alice_id,
            0,
            dataspace_id,
        )
        .expect("contract address");
        let invocation = iroha_data_model::transaction::executable::ContractInvocation {
            contract_address,
            expected_code_hash: iroha_crypto::Hash::new(b"router-contract-code"),
            entrypoint: "transfer".to_owned(),
            arguments: None,
        };
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            iroha_data_model::transaction::Executable::ContractCall(invocation),
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("contract call route must resolve"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn asset_home_proved_coverage_overlay_domain_routes_to_dataspace() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("merchant", "paynet").expect("domain id"),
            )))]),
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("proved overlay domain route must resolve"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn asset_home_proved_coverage_overlay_conflicting_domains_route_to_participant_coordinator() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let first_dataspace = DataSpaceId::new(10);
        let second_dataspace = DataSpaceId::new(11);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(first_dataspace, "paynet"), (second_dataspace, "cbuae")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), first_dataspace),
                (LaneId::new(3), second_dataspace),
            ]),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![
                InstructionBox::from(Register::domain(Domain::new(
                    DomainId::try_new("merchant", "paynet").expect("domain id"),
                ))),
                InstructionBox::from(Register::domain(Domain::new(
                    DomainId::try_new("issuer", "cbuae").expect("domain id"),
                ))),
            ]),
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("mixed proved overlay domain targets should route to AMX coordinator"),
            RoutingDecision::new(LaneId::new(2), first_dataspace)
        );
    }
    #[test]
    fn asset_home_proved_coverage_overlay_permission_routes_to_dataspace() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let permission: Permission = CanPublishSpaceDirectoryManifest {
            dataspace: dataspace_id,
        }
        .into();
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(Grant::account_permission(
                permission, bob_id,
            ))]),
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("proved overlay dataspace permission route must resolve"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn asset_home_proved_coverage_overlay_conflicting_permissions_route_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let first_dataspace = DataSpaceId::new(10);
        let second_dataspace = DataSpaceId::new(11);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(first_dataspace, "paynet"), (second_dataspace, "cbuae")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), first_dataspace),
                (LaneId::new(3), second_dataspace),
            ]),
        );
        let first_permission: Permission = CanPublishSpaceDirectoryManifest {
            dataspace: first_dataspace,
        }
        .into();
        let second_permission: Permission = CanPublishSpaceDirectoryManifest {
            dataspace: second_dataspace,
        }
        .into();
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![
                InstructionBox::from(Grant::account_permission(
                    first_permission,
                    alice_id.clone(),
                )),
                InstructionBox::from(Revoke::account_permission(
                    second_permission,
                    alice_id.clone(),
                )),
            ]),
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("mixed proved overlay permissions should route to AMX coordinator"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn asset_home_proved_state_coverage_overlay_mint_global_binding_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (_dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::of(asset_definition.clone(), alice_id.clone()),
            ))]),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &asset_definition, "pkr#paynet");
        let state_view = state.view();
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("proved overlay mint needs state for stored alias"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state_view)
                .expect("proved overlay mint route must resolve with state"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            evaluate_policy_with_catalog_and_world(
                router.policy.as_ref(),
                router.lane_catalog.as_ref(),
                router.dataspace_catalog.as_ref(),
                &tx,
                state_view.world(),
            )
            .expect("proved overlay mint route must resolve with world"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn asset_home_proved_state_coverage_overlay_permission_uses_stored_alias_dataspace() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let (dataspace_id, lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(Grant::account_permission(
                iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition {
                    asset_definition: asset_definition.clone(),
                },
                bob_id,
            ))]),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &asset_definition, "pkr#paynet");
        let state_view = state.view();
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("proved overlay permission needs state for stored alias"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state_view)
                .expect("proved overlay permission route must resolve with state"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
        assert_eq!(
            evaluate_policy_with_catalog_and_world(
                router.policy.as_ref(),
                router.lane_catalog.as_ref(),
                router.dataspace_catalog.as_ref(),
                &tx,
                state_view.world(),
            )
            .expect("proved overlay permission route must resolve with world"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn asset_home_proved_state_coverage_overlay_state_resolved_conflict_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let paynet = DataSpaceId::new(10);
        let cbuae = DataSpaceId::new(11);
        let dataspace_catalog = dataspace_catalog(&[(paynet, "paynet"), (cbuae, "cbuae")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), paynet),
            (LaneId::new(3), cbuae),
        ]);
        let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![
                InstructionBox::from(Mint::asset_quantity(
                    1_u32,
                    AssetId::of(asset_definition.clone(), alice_id.clone()),
                )),
                InstructionBox::from(Register::domain(Domain::new(
                    DomainId::try_new("issuer", "cbuae").expect("domain id"),
                ))),
            ]),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &asset_definition, "pkr#paynet");
        let state_view = state.view();
        assert_eq!(
            router
                .try_route_with_view(&tx, &state_view)
                .expect("state-resolved proved overlay targets should route to AMX coordinator"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            evaluate_policy_with_catalog_and_world(
                router.policy.as_ref(),
                router.lane_catalog.as_ref(),
                router.dataspace_catalog.as_ref(),
                &tx,
                state_view.world(),
            )
            .expect("state-resolved world overlay targets should route to AMX coordinator"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn asset_home_proved_settlement_coverage_overlay_dvp_routes_to_common_dataspace() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let settlement_domain = DomainId::try_new("settlement", "paynet").expect("domain id");
        let delivery_definition = AssetDefinitionId::derive_from_components(
            settlement_domain.clone(),
            "bond".parse().expect("asset definition name"),
        );
        let payment_definition = AssetDefinitionId::derive_from_components(
            settlement_domain.clone(),
            "cash".parse().expect("asset definition name"),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(DvpIsi::new(
                "proved-dvp-common".parse().expect("settlement id"),
                SettlementLeg::new(
                    delivery_definition.clone(),
                    1_u32,
                    alice_id.clone(),
                    bob_id.clone(),
                ),
                SettlementLeg::new(payment_definition.clone(), 1_u32, bob_id, alice_id.clone()),
                SettlementPlan::new(
                    SettlementExecutionOrder::DeliveryThenPayment,
                    SettlementAtomicity::AllOrNothing,
                ),
            ))]),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    delivery_definition,
                    "bond".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(settlement_domain.clone()),
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    payment_definition,
                    "cash".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(settlement_domain),
                )
                .build(&alice_id),
            ],
            router.dataspace_catalog.as_ref().clone(),
            router.lane_catalog.as_ref().clone(),
        );
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("proved DVP state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("proved DVP route must resolve with stored definitions"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn asset_home_proved_settlement_coverage_overlay_pvp_cross_dataspace_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let paynet = DataSpaceId::new(10);
        let cbuae = DataSpaceId::new(11);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane: LaneId::new(2),
                default_dataspace: paynet,
                rules: vec![],
            },
            dataspace_catalog(&[(paynet, "paynet"), (cbuae, "cbuae")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), paynet),
                (LaneId::new(3), cbuae),
            ]),
        );
        let primary_domain = DomainId::try_new("settlement", "paynet").expect("domain id");
        let counter_domain = DomainId::try_new("settlement", "cbuae").expect("domain id");
        let primary_definition = AssetDefinitionId::derive_from_components(
            primary_domain.clone(),
            "usd".parse().expect("asset definition name"),
        );
        let counter_definition = AssetDefinitionId::derive_from_components(
            counter_domain.clone(),
            "aed".parse().expect("asset definition name"),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(PvpIsi::new(
                "proved-pvp-cross".parse().expect("settlement id"),
                SettlementLeg::new(
                    primary_definition.clone(),
                    1_u32,
                    alice_id.clone(),
                    bob_id.clone(),
                ),
                SettlementLeg::new(counter_definition.clone(), 1_u32, bob_id, alice_id.clone()),
                SettlementPlan::new(
                    SettlementExecutionOrder::DeliveryThenPayment,
                    SettlementAtomicity::AllOrNothing,
                ),
            ))]),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    primary_definition,
                    "USD".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(primary_domain),
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    counter_definition,
                    "AED".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(counter_domain),
                )
                .build(&alice_id),
            ],
            router.dataspace_catalog.as_ref().clone(),
            router.lane_catalog.as_ref().clone(),
        );
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("proved cross-dataspace PVP state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("proved cross-dataspace PVP route must resolve with stored definitions"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn asset_home_proved_settlement_overlay_dvp_global_bindings_route_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let (_dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let delivery_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("settlement", "universal").expect("domain id"),
            "bond".parse().expect("asset definition name"),
        );
        let payment_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("settlement", "universal").expect("domain id"),
            "cash".parse().expect("asset definition name"),
        );
        let opaque_delivery =
            AssetDefinitionId::parse_address_literal(&delivery_definition.canonical_address())
                .expect("opaque delivery definition id");
        let opaque_payment =
            AssetDefinitionId::parse_address_literal(&payment_definition.canonical_address())
                .expect("opaque payment definition id");
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(DvpIsi::new(
                "proved-dvp-alias".parse().expect("settlement id"),
                SettlementLeg::new(opaque_delivery, 1_u32, alice_id.clone(), bob_id.clone()),
                SettlementLeg::new(opaque_payment, 1_u32, bob_id, alice_id.clone()),
                SettlementPlan::new(
                    SettlementExecutionOrder::DeliveryThenPayment,
                    SettlementAtomicity::AllOrNothing,
                ),
            ))]),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    delivery_definition.clone(),
                    "bond".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
                AssetDefinition::numeric(
                    payment_definition.clone(),
                    "cash".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &delivery_definition, "bond#paynet");
        bind_asset_definition_alias(&mut state, &payment_definition, "cash#paynet");
        let state_view = state.view();
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("proved opaque DVP needs state for stored aliases"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state_view)
                .expect("proved opaque DVP route must resolve with state"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            evaluate_policy_with_catalog_and_world(
                router.policy.as_ref(),
                router.lane_catalog.as_ref(),
                router.dataspace_catalog.as_ref(),
                &tx,
                state_view.world(),
            )
            .expect("proved opaque DVP route must resolve with world"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn asset_home_proved_account_coverage_overlay_permission_routes_by_destination_account() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![
                LaneRoutingRule {
                    lane: LaneId::new(1),
                    dataspace: Some(DataSpaceId::new(1)),
                    matcher: LaneRoutingMatcher {
                        account: Some(alice_id.to_string()),
                        instruction: None,
                        description: None,
                    },
                },
                LaneRoutingRule {
                    lane: LaneId::new(2),
                    dataspace: Some(DataSpaceId::new(2)),
                    matcher: LaneRoutingMatcher {
                        account: Some(bob_id.to_string()),
                        instruction: None,
                        description: None,
                    },
                },
            ],
        };
        let router = ConfigLaneRouter::new(
            policy,
            dataspace_catalog(&[(DataSpaceId::new(1), "alice"), (DataSpaceId::new(2), "bob")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(1), DataSpaceId::new(1)),
                (LaneId::new(2), DataSpaceId::new(2)),
            ]),
        );
        let tx = sample_executable_transaction(
            &alice_id,
            alice_keypair.private_key(),
            sample_proved_executable(vec![InstructionBox::from(Grant::account_permission(
                iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                    account: alice_id.clone(),
                },
                bob_id,
            ))]),
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("proved account permission route should be state-free"),
            Some(RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)))
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("proved account permission route must resolve"),
            RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2))
        );
    }
    #[test]
    fn contract_instance_activation_routes_to_contract_address_dataspace() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &super::super::queue_test_network_id(),
            &alice_id,
            0,
            dataspace_id,
        )
        .expect("contract address");
        let instruction = iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
            contract_address,
            expected_revision: 1,
            code_hash: Hash::new(b"contract-code"),
        };
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(instruction)],
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("contract activation route must resolve"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn atomic_contract_deployment_routes_to_new_address_dataspace() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &super::super::queue_test_network_id(),
            &alice_id,
            0,
            dataspace_id,
        )
        .expect("contract address");
        let instruction = CommitContractDeployment {
            expected_deploy_nonce: 0,
            contract_address,
            code_hash: Hash::new(b"contract-code"),
            contract_alias: "payments::paynet".parse().expect("contract alias"),
            lease_expiry_ms: None,
            expected_previous_contract_address: None,
        };
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(instruction)],
        );
        assert_eq!(
            router
                .try_route(&tx)
                .expect("atomic contract deployment route must resolve"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn smart_contract_deploy_rule_with_target_dataspace_builds_native_amx_plan() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let zk_dataspace = DataSpaceId::new(2);
        let contract_dataspace = DataSpaceId::new(10);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane: LaneId::SINGLE,
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![LaneRoutingRule {
                    lane: LaneId::new(2),
                    dataspace: Some(zk_dataspace),
                    matcher: LaneRoutingMatcher {
                        account: None,
                        instruction: Some("smartcontract::deploy".to_owned()),
                        description: None,
                    },
                }],
            },
            dataspace_catalog(&[(zk_dataspace, "zk"), (contract_dataspace, "sbp")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), zk_dataspace),
                (LaneId::new(3), contract_dataspace),
            ]),
        );
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &super::super::queue_test_network_id(),
            &alice_id,
            0,
            contract_dataspace,
        )
        .expect("contract address");
        let instructions = vec![
            InstructionBox::from(RegisterSmartContractBytes {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    contract_dataspace,
                    Hash::new(&code),
                ),
                code,
            }),
            InstructionBox::from(
                iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
                    contract_address,
                    expected_revision: 1,
                    code_hash: Hash::new(b"contract-code"),
                },
            ),
        ];
        let tx = sample_transaction(&alice_id, alice_keypair.private_key(), instructions.clone());
        let plan = router
            .try_route_plan(&tx)
            .expect("contract deploy rule and target dataspace should build a native AMX plan");
        let RoutingPlan::NativeAmx(plan) = plan else {
            panic!("contract deploy should not collapse to a single mismatched route");
        };
        assert_eq!(
            plan.coordinator.route,
            RoutingDecision::new(LaneId::new(2), zk_dataspace)
        );
        assert_eq!(
            plan.participants,
            vec![
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(2), zk_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(3), contract_dataspace),
                    RouteLegRole::Participant,
                ),
            ]
        );
        let mut strict_metadata = Metadata::default();
        strict_metadata.insert(
            AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
            iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
        );
        let strict_tx = sample_transaction_with_metadata(
            &alice_id,
            alice_keypair.private_key(),
            instructions,
            strict_metadata,
        );
        assert_eq!(
            router.try_route_plan(&strict_tx),
            Err(
                RoutingResolveError::ConflictingTransactionDataspaceTargets {
                    first_dataspace_id: zk_dataspace,
                    second_dataspace_id: contract_dataspace,
                }
            ),
            "strict policy must include the deploy-rule participant",
        );
    }
    #[test]
    fn smart_contract_deploy_rule_with_universal_target_builds_native_amx_plan() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let is_dataspace = DataSpaceId::new(6647857470246403404);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane: LaneId::SINGLE,
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![LaneRoutingRule {
                    lane: LaneId::new(3),
                    dataspace: Some(is_dataspace),
                    matcher: LaneRoutingMatcher {
                        account: None,
                        instruction: Some("smartcontract::deploy".to_owned()),
                        description: None,
                    },
                }],
            },
            dataspace_catalog(&[(is_dataspace, "is")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(3), is_dataspace),
            ]),
        );
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &super::super::queue_test_network_id(),
            &alice_id,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let instructions = vec![
            InstructionBox::from(RegisterSmartContractBytes {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    DataSpaceId::UNIVERSAL,
                    Hash::new(&code),
                ),
                code,
            }),
            InstructionBox::from(
                iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
                    contract_address,
                    expected_revision: 1,
                    code_hash: Hash::new(b"contract-code"),
                },
            ),
        ];
        let tx = sample_transaction(&alice_id, alice_keypair.private_key(), instructions.clone());
        let plan = router
            .try_route_plan(&tx)
            .expect("universal contract deploy rule should build a native AMX plan");
        let RoutingPlan::NativeAmx(plan) = plan else {
            panic!("universal contract deploy should not collapse to a mismatched single route");
        };
        assert_eq!(
            plan.coordinator.route,
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            plan.participants,
            vec![RouteLeg::new(
                RoutingDecision::new(LaneId::new(3), is_dataspace),
                RouteLegRole::Participant,
            )]
        );
        let mut strict_metadata = Metadata::default();
        strict_metadata.insert(
            AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
            iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
        );
        let strict_tx = sample_transaction_with_metadata(
            &alice_id,
            alice_keypair.private_key(),
            instructions,
            strict_metadata,
        );
        assert_eq!(
            router.try_route_plan(&strict_tx),
            Err(
                RoutingResolveError::ConflictingTransactionDataspaceTargets {
                    first_dataspace_id: DataSpaceId::UNIVERSAL,
                    second_dataspace_id: is_dataspace,
                }
            ),
            "strict policy must reject a universal coordinator with a private participant",
        );
    }
    #[test]
    fn musubi_alias_registration_uses_universal_amx_with_home_dataspace_participant() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let target = iroha_data_model::musubi::MusubiPackageIdV1::new(
            dataspace_id,
            iroha_data_model::musubi::MusubiPackageScopeV1::Domain(
                "mibank".parse().expect("domain scope"),
            ),
            "fx".parse().expect("package name"),
        );
        let instruction = iroha_data_model::isi::musubi::RegisterMusubiAliasV1::new(
            "fx".parse().expect("alias"),
            target,
            1,
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(instruction)],
        );
        let plan = router
            .try_route_plan(&tx)
            .expect("Musubi alias route must resolve");
        let RoutingPlan::NativeAmx(plan) = plan else {
            panic!("Musubi alias registration must use Native AMX");
        };
        assert_eq!(
            plan.coordinator.route,
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            plan.participants,
            vec![RouteLeg::new(
                RoutingDecision::new(lane_id, dataspace_id),
                RouteLegRole::Participant,
            )]
        );
    }
    #[test]
    fn musubi_release_publication_uses_universal_amx_with_home_dataspace_participant() {
        use iroha_data_model::{
            isi::musubi::PublishMusubiReleaseV1,
            musubi::{
                ArchiveId, MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiContentDigestV1,
                MusubiKotodamaEditionV1, MusubiPackageIdV1, MusubiPackageScopeV1,
                MusubiPublicationV1, MusubiRegistrySnapshotV1, MusubiReleaseIdV1,
                MusubiReleaseManifestV1, MusubiReleaseMetadataV1, MusubiResolutionProofV1,
                MusubiVerificationLockV1,
            },
        };
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (lane_id, dataspace_id),
            ]),
        );
        let package = MusubiPackageIdV1::new(
            dataspace_id,
            MusubiPackageScopeV1::Domain("mibank".parse().expect("domain scope")),
            "fx".parse().expect("package name"),
        );
        let release =
            MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("publication version"));
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let publication = MusubiPublicationV1 {
            manifest: MusubiReleaseManifestV1 {
                release,
                edition: MusubiKotodamaEditionV1::V1,
                abi: MusubiAbiBindingV1::new([0x41; 32]).expect("ABI binding"),
                dependencies: Vec::new(),
                exports: Vec::new(),
                interface_digest: MusubiContentDigestV1::new([0x42; 32]),
                metadata: MusubiReleaseMetadataV1::default(),
                archive_id: ArchiveId::new([0x43; 32]),
                verification_lock_digest: lock.digest(),
            },
            resolution: MusubiResolutionProofV1 {
                snapshot: MusubiRegistrySnapshotV1 {
                    finalized_height: 7,
                    finalized_block_hash: [0x44; 32],
                    index_revision: 3,
                },
                lock,
            },
        };
        let instruction = PublishMusubiReleaseV1::new(
            "mibank.paynet".parse().expect("publication namespace"),
            publication,
            None,
            1,
            None,
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(instruction)],
        );
        let plan = router
            .try_route_plan(&tx)
            .expect("Musubi publication route must resolve");
        let RoutingPlan::NativeAmx(plan) = plan else {
            panic!("Musubi publication must use Native AMX");
        };
        assert_eq!(
            plan.coordinator.route,
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            plan.participants,
            vec![RouteLeg::new(
                RoutingDecision::new(lane_id, dataspace_id),
                RouteLegRole::Participant,
            )]
        );
    }
    #[test]
    fn untargeted_authority_transaction_routes_to_single_scope_dataspace_with_state() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (lane_id, dataspace_id),
        ]);
        let router = ConfigLaneRouter::new(default_routing_policy(), catalog.clone(), lane_catalog);
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                "untargeted authority".into(),
            ))],
        );
        let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
        scope_entry.ensure_dataspace(dataspace_id);
        let mut state = state_with_account_scope_entries(&[(alice_id, scope_entry)], catalog);
        install_router_lane_catalog(&mut state, router.lane_catalog.as_ref().clone());
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("untargeted authority transaction should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("authority single-scope route must resolve"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn untargeted_universal_authority_transaction_uses_default_lane_with_state() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let default_lane = LaneId::new(1);
        let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, default_lane]);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane,
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![],
            },
            DataSpaceCatalog::default(),
            lane_catalog,
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                "untargeted authority".into(),
            ))],
        );
        let mut state = blank_state();
        let account = Account::new(alice_id.clone()).build(&alice_id);
        let (account_id, account) = account.into_key_value();
        state.world.accounts.insert(account_id, account);
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("universal-only account should use configured default lane"),
            RoutingDecision::new(default_lane, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn rejects_noncanonical_instruction_matcher_without_underscores() {
        assert!(matches_label(
            "set_key_value::account",
            "set_key_value::account"
        ));
        assert!(!matches_label(
            "setkeyvalue::account",
            "set_key_value::account"
        ));
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("setkeyvalue::account".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1)]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let instruction = SetKeyValue::account(
            alice_id.clone(),
            "flag".parse().expect("metadata key"),
            Json::new("on"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(instruction)],
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        let decision = router
            .try_route_with_view(&tx, &state.view())
            .expect("noncanonical matcher must leave the canonical default route valid");
        assert_eq!(decision.lane_id, LaneId::SINGLE);
    }
    #[test]
    fn original_dataspace_alias_read_refusal_keeps_routing_retryable() {
        let (owner, owner_key) = gen_account_in("original_route_owner");
        let world = world_with_dynamic_dataspace("alpha", &owner);
        let catalog = DataSpaceCatalog::default();
        let selector = crate::sns::selector_for_dataspace_alias("alpha").unwrap();
        let key = crate::sns::record_storage_key(&selector);
        let original = world.smart_contract_state.view().get(&key).unwrap().clone();
        let target = crate::sns::dataspace_id_for_sns_alias("alpha").unwrap();
        let route =
            || dataspace_alias_target_with_world("alpha", Some(&catalog), &world.view(), Some(0));
        assert_eq!(route().unwrap(), Some(target));
        let refused = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || route().unwrap_err(),
        );
        assert_eq!(
            refused.as_label(),
            "routing_deferred",
            "an unfinished original SNS read became a permanent route error: {refused:?}"
        );
        assert_eq!(world.smart_contract_state.view().get(&key), Some(&original));
        assert_eq!(route().unwrap(), Some(target));

        let tx = sample_transaction(
            &owner,
            owner_key.private_key(),
            vec![Register::domain(Domain::new(DomainId::try_new("bank", "alpha").unwrap())).into()],
        );
        let lanes = iroha_data_model::sumeragi_lanes::SumeragiLaneState::default();
        let view = world.view();
        let inputs = crate::sumeragi::lanes::routing::RoutingInputs {
            root_scope: Some(iroha_data_model::block::consensus::SumeragiRootScope::Global),
            policy: None,
            lanes: &lanes,
            dataspaces: &catalog,
            world: &view,
            ledger_time_ms: 0,
        };
        let completed = inputs.execution_route(&tx, 2).unwrap();
        let original = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || inputs.execution_route(&tx, 2).unwrap_err(),
        );
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert_eq!(inputs.execution_route(&tx, 2).unwrap(), completed);
    }
    #[test]
    fn original_physical_policy_read_refusal_never_enters_captured_row() {
        use crate::execution_attempt::ExecutionAttemptError;
        use crate::state::network_policy_routes::CapturedNetworkPolicyRoute;
        let (owner, signer) = gen_account_in("original_physical_route_owner");
        let mut world = world_with_dynamic_dataspace("alpha", &owner);
        let (id, account) = Account::new(owner.clone()).build(&owner).into_key_value();
        world.accounts.insert(id, account);
        let selector = crate::sns::selector_for_dataspace_alias("alpha").unwrap();
        let key = crate::sns::record_storage_key(&selector);
        let original = world.smart_contract_state.view().get(&key).unwrap().clone();
        let state = crate::state::State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let tx = sample_transaction(
            &owner,
            signer.private_key(),
            vec![Register::domain(Domain::new(DomainId::try_new("bank", "alpha").unwrap())).into()],
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            nonzero!(2_u64),
            None,
            None,
            0,
            0,
        ));
        let resolve = || {
            crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
                &block.nexus,
                &block.world,
                &tx,
                1,
                0,
            )
        };
        assert!(
            matches!(resolve(), Err(ExecutionAttemptError::Rejected(_))),
            "dynamic SNS scope has no admitted physical lane"
        );
        let refused = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || resolve().unwrap_err(),
        );
        assert!(
            matches!(refused, ExecutionAttemptError::Deferred(ref reason) if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        );
        let overlay = block.transaction();
        assert!(
            CapturedNetworkPolicyRoute::for_component(&tx, &overlay, RoutingDecision::default())
                .is_ok()
        );
        let captured = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || CapturedNetworkPolicyRoute::for_component(&tx, &overlay, RoutingDecision::default()),
        );
        assert_eq!(
            captured.err().unwrap().reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert_eq!(
            overlay.world.smart_contract_state().get(&key),
            Some(&original)
        );
        assert!(
            CapturedNetworkPolicyRoute::for_component(&tx, &overlay, RoutingDecision::default())
                .is_ok()
        );
    }

    #[test]
    fn matches_account_alias_scope_rule() {
        let (uae_id, uae_keypair) = gen_account_in("uae");
        let (bank_id, bank_keypair) = gen_account_in("banka");
        let catalog = DataSpaceCatalog::default();
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: Some("*@uae.universal".to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        };
        let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1)]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let uae_tx = sample_transaction(
            &uae_id,
            uae_keypair.private_key(),
            vec![InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("uae-match", "universal").expect("domain id"),
            )))],
        );
        let bank_tx = sample_transaction(
            &bank_id,
            bank_keypair.private_key(),
            vec![InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("bank-no-match", "universal").expect("domain id"),
            )))],
        );
        let mut state = state_with_account_aliases(
            &[
                (
                    uae_id.clone(),
                    account_alias("central@uae.universal", &catalog),
                ),
                (
                    bank_id.clone(),
                    account_alias("settler@banka.universal", &catalog),
                ),
            ],
            catalog,
        );
        install_router_nexus(&mut state, &router);
        let uae_decision = router
            .try_route_with_view(&uae_tx, &state.view())
            .expect("UAE alias route should resolve");
        let bank_decision = router
            .try_route_with_view(&bank_tx, &state.view())
            .expect("bank alias route should resolve");
        assert_eq!(uae_decision.lane_id, LaneId::new(1));
        assert_eq!(bank_decision.lane_id, LaneId::SINGLE);
    }
    #[test]
    fn matches_transfer_destination_alias_scope_rule() {
        let (sender_id, sender_keypair) = gen_account_in("banka");
        let (receiver_id, _) = gen_account_in("acme");
        let catalog = DataSpaceCatalog::default();
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("transfer::asset@acme.universal".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1)]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let asset_definition: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("uae", "universal").unwrap(),
                "aed".parse().unwrap(),
            );
        let asset_id = AssetId::of(asset_definition, sender_id.clone());
        let transfer = Transfer::asset_quantity(asset_id, 1_u32, receiver_id.clone());
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(transfer)],
        );
        let mut state = state_with_account_aliases(
            &[
                (
                    sender_id.clone(),
                    account_alias("settler@banka.universal", &catalog),
                ),
                (
                    receiver_id.clone(),
                    account_alias("merchant@acme.universal", &catalog),
                ),
            ],
            catalog,
        );
        install_router_nexus(&mut state, &router);
        let decision = router
            .try_route_with_view(&tx, &state.view())
            .expect("transfer destination alias route should resolve");
        assert_eq!(decision.lane_id, LaneId::new(1));
    }
    #[test]
    fn matches_transferred_domain_scope_rule() {
        let (sender_id, sender_keypair) = gen_account_in("banka");
        let (receiver_id, _) = gen_account_in("acme");
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("transfer::domain@merchant.acme".to_string()),
                    description: None,
                },
            }],
        };
        let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1)]);
        let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
        let transfer = Transfer::domain(
            sender_id.clone(),
            DomainId::try_new("merchant", "acme").expect("domain id"),
            receiver_id,
        );
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(transfer)],
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        let decision = router
            .try_route_with_view(&tx, &state.view())
            .expect("transferred domain route should resolve");
        assert_eq!(decision.lane_id, LaneId::new(1));
    }
    #[test]
    fn routes_domain_write_to_target_dataspace_without_explicit_rule() {
        let (authority_id, authority_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(7);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "acme")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), dataspace_id),
            ]),
        );
        let tx = sample_transaction(
            &authority_id,
            authority_keypair.private_key(),
            vec![InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("merchant", "acme").expect("domain id"),
            )))],
        );
        assert_eq!(
            router.try_route(&tx).expect("domain route must resolve"),
            RoutingDecision::new(LaneId::new(2), dataspace_id)
        );
    }
    #[test]
    fn routes_asset_transfer_to_asset_definition_dataspace_without_explicit_rule() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let (receiver_id, _) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace_id),
        ]);
        let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
        let id_seed_domain = DomainId::try_new("cash", "sbp").expect("asset definition id seed");
        let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            id_seed_domain,
            "pkr".parse().expect("asset definition name"),
        );
        let transfer = Transfer::asset_quantity(
            AssetId::of(asset_definition.clone(), sender_id.clone()),
            1_u32,
            receiver_id,
        );
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(transfer)],
        );
        let owning_domain = DomainId::try_new("cash", "paynet").expect("owning domain");
        let state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&sender_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("opaque asset transfer should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("asset transfer route must resolve from stored ownership"),
            RoutingDecision::new(LaneId::new(2), dataspace_id)
        );
    }
    #[test]
    fn opaque_asset_transfer_defers_to_state_for_asset_definition_dataspace() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let (receiver_id, _) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace_id),
        ]);
        let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
        let owning_domain = DomainId::try_new("cash", "paynet").expect("asset definition domain");
        let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let opaque_asset_definition =
            AssetDefinitionId::parse_address_literal(&asset_definition.canonical_address())
                .expect("opaque canonical asset definition id");
        let transfer = Transfer::asset_quantity(
            AssetId::of(opaque_asset_definition, sender_id.clone()),
            1_u32,
            receiver_id,
        );
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(transfer)],
        );
        let state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&sender_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("opaque asset transfer should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("opaque asset transfer route must resolve with state"),
            RoutingDecision::new(LaneId::new(2), dataspace_id)
        );
    }
    #[test]
    fn canonical_asset_transfer_uses_stored_owning_domain_dataspace() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let (receiver_id, _) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace_id),
        ]);
        let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
        let transparent_asset_definition =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("cash", "universal").expect("asset definition domain"),
                "pkr".parse().expect("asset definition name"),
            );
        let opaque_asset_definition = AssetDefinitionId::parse_address_literal(
            &transparent_asset_definition.canonical_address(),
        )
        .expect("opaque canonical asset definition id");
        let transfer = Transfer::asset_quantity(
            AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
            1_u32,
            receiver_id,
        );
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(transfer)],
        );
        let alias: iroha_data_model::asset::AssetDefinitionAlias =
            "pkr#paynet".parse().expect("asset alias");
        let owning_domain = DomainId::try_new("cash", "paynet").expect("owning domain");
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    opaque_asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&sender_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        state
            .world
            .asset_definition_aliases
            .insert(alias.clone(), opaque_asset_definition.clone());
        state.world.asset_definition_alias_bindings.insert(
            opaque_asset_definition.clone(),
            crate::state::AssetDefinitionAliasBindingRecord {
                alias,
                lease_expiry_ms: None,
                grace_until_ms: None,
                bound_at_ms: 0,
            },
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("opaque asset transfer route must resolve with alias"),
            RoutingDecision::new(LaneId::new(2), dataspace_id)
        );
    }
    #[test]
    fn dataspace_restricted_asset_transfer_ignores_universal_account_fallback_scope() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let (receiver_id, _) = gen_account_in("wonderland");
        let (dataspace_id, lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("sbp");
        let transparent_asset_definition =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("cash", "universal").expect("asset definition domain"),
                "pkr".parse().expect("asset definition name"),
            );
        let opaque_asset_definition = AssetDefinitionId::parse_address_literal(
            &transparent_asset_definition.canonical_address(),
        )
        .expect("opaque canonical asset definition id");
        let transfer = Transfer::asset_quantity(
            AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
            1_u32,
            receiver_id.clone(),
        );
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(transfer)],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    opaque_asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(DomainId::try_new("cash", "sbp").expect("owning domain")),
                )
                .build(&sender_id),
            ],
            dataspace_catalog.clone(),
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &opaque_asset_definition, "pkr#sbp");
        add_unlabeled_account_with_alias(
            &mut state,
            &sender_id,
            account_alias("sender@ubl.sbp", &dataspace_catalog),
        );
        add_unlabeled_account_with_alias(
            &mut state,
            &receiver_id,
            account_alias("receiver@hbl.sbp", &dataspace_catalog),
        );
        let state_view = state.view();
        for account_id in [&sender_id, &receiver_id] {
            assert_eq!(
                state_view
                    .world()
                    .account_scope_hierarchy(account_id)
                    .expect("account hierarchy")
                    .into_keys()
                    .collect::<Vec<_>>(),
                vec![DataSpaceId::UNIVERSAL, dataspace_id]
            );
        }
        assert_eq!(
            router
                .try_route_with_view(&tx, &state_view)
                .expect("dataspace-restricted transfer must route to the asset dataspace"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn direct_dataspace_registration_uses_explicit_home_without_alias_resolution() {
        let dataspace = DataSpaceId::new(8_648_377_547_929_788_715);
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("unrelated", "universal").expect("id seed"),
            "kina".parse().expect("name"),
        );
        let register = iroha_data_model::isi::RegisterDataspaceAssetDefinition::new(
            dataspace,
            AssetDefinition::numeric(id, "Kina", AssetBalancePolicy::DataspaceRestricted, None),
        )
        .expect("valid direct registration");
        let world = crate::state::World::default();
        let state = state_from_world(world);
        assert_eq!(
            instruction_transaction_dataspace_target(&register, None, None).unwrap(),
            Some(dataspace)
        );
        assert_eq!(
            instruction_transaction_dataspace_target_with_world(
                &register,
                None,
                state.view().world(),
                None,
            )
            .unwrap(),
            Some(dataspace)
        );
        assert!(instruction_label_matches(
            "register::asset_definition",
            &register
        ));
    }

    #[test]
    fn direct_dataspace_home_survives_alias_changes_and_preserves_global_balance_routing() {
        let (owner, _) = gen_account_in("wonderland");
        let dataspace = DataSpaceId::new(10);
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("unrelated", "universal").expect("id seed"),
            "kina".parse().expect("name"),
        );
        let catalog = dataspace_catalog(&[(dataspace, "bpng"), (DataSpaceId::new(12), "other")]);
        let lanes = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace),
        ]);
        for policy in [
            AssetBalancePolicy::Global,
            AssetBalancePolicy::DataspaceRestricted,
        ] {
            let mut definition =
                AssetDefinition::numeric(id.clone(), "Kina", policy, None).build(&owner);
            definition.alias = Some("kina#other".parse().expect("mutable alias"));
            let mut state =
                state_with_asset_definitions(vec![definition], catalog.clone(), lanes.clone());
            state
                .world
                .set_asset_definition_dataspace_for_testing(id.clone(), dataspace)
                .expect("direct home fixture");
            let view = state.view();
            assert_eq!(
                asset_definition_dataspace_target(&id, None, None, Some(&catalog), Some(&view))
                    .unwrap(),
                Some(dataspace)
            );
            assert_eq!(
                asset_definition_dataspace_target_with_world(
                    &id,
                    None,
                    None,
                    Some(&catalog),
                    view.world(),
                    None
                )
                .unwrap(),
                Some(dataspace)
            );
            let expected_balance = if policy == AssetBalancePolicy::Global {
                DataSpaceId::UNIVERSAL
            } else {
                dataspace
            };
            assert_eq!(
                asset_balance_definition_route_target(&id, Some(&catalog), Some(&view))
                    .unwrap()
                    .dataspace_id,
                Some(expected_balance)
            );
            assert_eq!(
                asset_balance_definition_route_target_with_world(
                    &id,
                    Some(&catalog),
                    view.world(),
                    None
                )
                .unwrap()
                .dataspace_id,
                Some(expected_balance)
            );
            assert!(asset_definition_scope_matches("bpng", &id, Some(&view)));
            assert!(!asset_definition_scope_matches("other", &id, Some(&view)));
        }
    }

    #[test]
    fn asset_definition_registration_routes_by_declared_alias_dataspace() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let lane_id = LaneId::new(2);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (lane_id, dataspace_id),
        ]);
        let router =
            ConfigLaneRouter::new(default_routing_policy(), dataspace_catalog, lane_catalog);
        let transparent_asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let opaque_asset_definition = AssetDefinitionId::parse_address_literal(
            &transparent_asset_definition.canonical_address(),
        )
        .expect("opaque canonical asset definition id");
        let alias: AssetDefinitionAlias = "pkr#paynet".parse().expect("asset alias");
        let definition = NewAssetDefinition {
            id: opaque_asset_definition,
            name: "pkr".to_owned(),
            description: None,
            alias: Some(alias),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: Some(
                DomainId::try_new("cash", "universal").expect("asset definition domain"),
            ),
        };
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(Register::asset_definition(definition))],
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("declared alias state requirement should be deterministic"),
            None
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("declared alias should resolve against live SNS/static state"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn asset_definition_registration_opaque_global_without_alias_routes_to_universal() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), dataspace_id),
            ]),
        );
        let transparent_asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let opaque_asset_definition = AssetDefinitionId::parse_address_literal(
            &transparent_asset_definition.canonical_address(),
        )
        .expect("opaque canonical asset definition id");
        let definition = NewAssetDefinition {
            id: opaque_asset_definition,
            name: "pkr".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(Register::asset_definition(definition))],
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("opaque global definition without alias should route from policy"),
            Some(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL))
        );
    }
    #[test]
    fn asset_home_extra_coverage_registration_universal_alias_routes_to_universal() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), dataspace_id),
            ]),
        );
        let transparent_asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let opaque_asset_definition = AssetDefinitionId::parse_address_literal(
            &transparent_asset_definition.canonical_address(),
        )
        .expect("opaque canonical asset definition id");
        let definition = NewAssetDefinition {
            id: opaque_asset_definition,
            name: "pkr".to_owned(),
            description: None,
            alias: Some("pkr#universal".parse().expect("asset alias")),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(Register::asset_definition(definition))],
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("universal alias state requirement should be deterministic"),
            None
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("universal alias should resolve with live state"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn asset_home_extra_coverage_opaque_restricted_uses_declared_owning_domain() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace_id),
        ]);
        let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
        let transparent_asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let opaque_asset_definition = AssetDefinitionId::parse_address_literal(
            &transparent_asset_definition.canonical_address(),
        )
        .expect("opaque canonical asset definition id");
        let definition = NewAssetDefinition {
            id: opaque_asset_definition,
            name: "pkr".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::DataspaceRestricted,
            owning_domain: Some(
                DomainId::try_new("cash", "universal").expect("asset definition domain"),
            ),
        };
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(Register::asset_definition(definition))],
        );
        let state = state_with_asset_definitions(Vec::new(), dataspace_catalog, lane_catalog);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("declared owning-domain state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("opaque restricted definition without home should fall back to default"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn asset_home_more_coverage_alias_home_without_lane_returns_no_lane_error() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane: LaneId::new(4),
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![],
            },
            dataspace_catalog(&[(dataspace_id, "paynet")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(4), DataSpaceId::UNIVERSAL),
            ]),
        );
        let definition = NewAssetDefinition {
            id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("cash", "universal").expect("asset definition domain"),
                "pkr".parse().expect("asset definition name"),
            ),
            name: "pkr".to_owned(),
            description: None,
            alias: Some("pkr#paynet".parse().expect("asset alias")),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(Register::asset_definition(definition))],
        );
        assert_eq!(router.try_route_without_state(&tx), Ok(None));
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        let err = router
            .try_route_with_state(&tx, &state)
            .expect_err("state-backed alias home without lane should fail");
        assert_eq!(
            err,
            RoutingResolveError::NoLaneForDataspace { dataspace_id }
        );
    }
    #[test]
    fn mixed_declared_asset_aliases_use_participant_coordinator() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let paynet = DataSpaceId::new(10);
        let cbuae = DataSpaceId::new(11);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(paynet, "paynet"), (cbuae, "cbuae")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(2), paynet),
                (LaneId::new(3), cbuae),
            ]),
        );
        let pkr_id = AssetDefinitionId::parse_address_literal(
            &AssetDefinitionId::derive_from_components(
                DomainId::try_new("cash", "universal").expect("asset definition domain"),
                "pkr".parse().expect("asset definition name"),
            )
            .canonical_address(),
        )
        .expect("opaque pkr definition id");
        let aed_id = AssetDefinitionId::parse_address_literal(
            &AssetDefinitionId::derive_from_components(
                DomainId::try_new("cash", "universal").expect("asset definition domain"),
                "aed".parse().expect("asset definition name"),
            )
            .canonical_address(),
        )
        .expect("opaque aed definition id");
        let pkr = NewAssetDefinition {
            id: pkr_id,
            name: "pkr".to_owned(),
            description: None,
            alias: Some("pkr#paynet".parse().expect("asset alias")),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let aed = NewAssetDefinition {
            id: aed_id,
            name: "aed".to_owned(),
            description: None,
            alias: Some("aed#cbuae".parse().expect("asset alias")),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![
                InstructionBox::from(Register::asset_definition(pkr)),
                InstructionBox::from(Register::asset_definition(aed)),
            ],
        );
        let route = router
            .try_route(&tx)
            .expect("mixed declared aliases should route to AMX coordinator");
        assert_eq!(route, RoutingDecision::new(LaneId::new(2), paynet));
    }
    #[test]
    fn global_asset_transfer_alias_binding_routes_to_universal() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let (receiver_id, _) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let owning_domain = DomainId::try_new("cash", "sbp").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let transfer = Transfer::asset_quantity(
            AssetId::of(asset_definition.clone(), sender_id.clone()),
            1_u32,
            receiver_id,
        );
        let tx = sample_transaction(
            &sender_id,
            sender_keypair.private_key(),
            vec![InstructionBox::from(transfer)],
        );
        let mut state = state_with_bound_numeric_asset_definition(
            &asset_definition,
            "pkr#paynet",
            "pkr",
            &sender_id,
            dataspace_catalog,
            lane_catalog,
        );
        scope_account_to_dataspace(&mut state, &sender_id, dataspace_id);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("stored alias lookup should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("stored alias route must resolve with state"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    macro_rules! stored_alias_permission_route_test {
        (
            $name:ident,
            $operation:ident,
            $permission:path,
            $without_state_message:literal,
            $with_state_message:literal $(,)?
        ) => {
            #[test]
            fn $name() {
                let (alice_id, alice_keypair) = gen_account_in("wonderland");
                let (bob_id, _) = gen_account_in("wonderland");
                let (dataspace_id, lane_id, dataspace_catalog, lane_catalog, router) =
                    routed_dataspace_fixture("paynet");
                let asset_definition = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("cash", "universal").expect("asset definition domain"),
                    "pkr".parse().expect("asset definition name"),
                );
                type Permission = $permission;
                let permission = Permission {
                    asset_definition: asset_definition.clone(),
                };
                let tx = sample_transaction(
                    &alice_id,
                    alice_keypair.private_key(),
                    vec![InstructionBox::from($operation::account_permission(
                        permission, bob_id,
                    ))],
                );
                let state = state_with_bound_numeric_asset_definition(
                    &asset_definition,
                    "pkr#paynet",
                    "pkr",
                    &alice_id,
                    dataspace_catalog,
                    lane_catalog,
                );
                assert_eq!(
                    router
                        .try_route_without_state(&tx)
                        .expect($without_state_message),
                    None
                );
                assert_eq!(
                    router
                        .try_route_with_view(&tx, &state.view())
                        .expect($with_state_message),
                    RoutingDecision::new(lane_id, dataspace_id)
                );
            }
        };
    }
    stored_alias_permission_route_test!(
        asset_definition_permission_grant_uses_stored_alias_dataspace,
        Grant,
        iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition,
        "asset-definition permission alias lookup should defer to state",
        "stored alias permission route must resolve with state",
    );
    stored_alias_permission_route_test!(
        asset_definition_permission_revoke_uses_stored_alias_dataspace,
        Revoke,
        iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition,
        "asset-definition permission alias lookup should defer to state",
        "stored alias permission revoke route must resolve with state",
    );
    #[test]
    fn asset_home_coverage_mint_global_binding_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (_dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::of(asset_definition.clone(), alice_id.clone()),
            ))],
        );
        let state = state_with_bound_numeric_asset_definition(
            &asset_definition,
            "pkr#paynet",
            "pkr",
            &alice_id,
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("mint alias lookup should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("stored alias mint route must resolve with state"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_mint_to_private_scoped_account_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::of(asset_definition.clone(), alice_id.clone()),
            ))],
        );
        let mut state = state_with_bound_numeric_asset_definition(
            &asset_definition,
            "pkr#paynet",
            "pkr",
            &alice_id,
            dataspace_catalog,
            lane_catalog,
        );
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("mint alias lookup should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("global asset mint route must ignore destination account scope"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_burn_from_private_scoped_account_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Burn::asset_quantity(
                1_u32,
                AssetId::of(asset_definition.clone(), alice_id.clone()),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &asset_definition, "pkr#paynet");
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("burn alias lookup should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("global asset burn route must ignore holder account scope"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_mint_with_projected_private_home_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let owning_domain = DomainId::try_new("cash", "paynet").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::of(asset_definition.clone(), alice_id.clone()),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("projected private home must not override a global asset mint route"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_burn_with_projected_private_home_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let owning_domain = DomainId::try_new("cash", "paynet").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Burn::asset_quantity(
                1_u32,
                AssetId::of(asset_definition.clone(), alice_id.clone()),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("projected private home must not override a global asset burn route"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_transfer_with_projected_private_home_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let owning_domain = DomainId::try_new("cash", "paynet").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Transfer::asset_quantity(
                AssetId::of(asset_definition.clone(), alice_id.clone()),
                1_u32,
                bob_id,
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("projected private home must not override a global asset transfer route"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn explicit_dataspace_scoped_mint_routes_to_private_bucket() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("sbp");
        let owning_domain = DomainId::try_new("cash", "sbp").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let scoped_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            alice_id.clone(),
            AssetBalanceScope::Dataspace(dataspace_id),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                scoped_asset_id,
            ))],
        );
        let state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("explicit scoped mint without state should defer for definition policy"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("explicit scoped mint must route to the asset balance bucket"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn explicit_dataspace_scoped_transfer_routes_to_private_bucket() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let (dataspace_id, lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("sbp");
        let owning_domain = DomainId::try_new("cash", "sbp").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let scoped_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            alice_id.clone(),
            AssetBalanceScope::Dataspace(dataspace_id),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Transfer::asset_quantity(
                scoped_asset_id,
                1_u32,
                bob_id,
            ))],
        );
        let state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router.try_route_without_state(&tx).expect(
                "explicit scoped transfer without state should defer for definition policy"
            ),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("explicit transfer source scope must route to the asset balance bucket"),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn global_asset_explicit_dataspace_scoped_mint_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("sbp");
        let owning_domain = DomainId::try_new("cash", "paynet").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let scoped_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            alice_id.clone(),
            AssetBalanceScope::Dataspace(dataspace_id),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                scoped_asset_id,
            ))],
        );
        let state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router.try_route_without_state(&tx).expect(
                "explicit global asset mint without state should defer for definition policy"
            ),
            None
        );
        assert_eq!(
            router.try_route_with_view(&tx, &state.view()).expect(
                "explicit scope must not override a global definition's authoritative route"
            ),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_explicit_dataspace_scoped_burn_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("sbp");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let scoped_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            alice_id.clone(),
            AssetBalanceScope::Dataspace(dataspace_id),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Burn::asset_quantity(
                1_u32,
                scoped_asset_id,
            ))],
        );
        let state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("explicit burn scope must not override global asset route"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_explicit_dataspace_scoped_transfer_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("sbp");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let scoped_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            alice_id.clone(),
            AssetBalanceScope::Dataspace(dataspace_id),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Transfer::asset_quantity(
                scoped_asset_id,
                1_u32,
                bob_id,
            ))],
        );
        let state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition,
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("explicit transfer source scope must not override global asset route"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    #[test]
    fn global_asset_zk_registration_from_private_authority_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let owning_domain = DomainId::try_new("cash", "paynet").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        let instruction = InstructionBox::from(RegisterZkAsset::new(asset_definition, None));
        let tx = sample_transaction(&alice_id, alice_keypair.private_key(), vec![instruction]);
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("ZK asset route should defer to state"),
            None,
            "registration should not route without the asset policy"
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("global ZK asset route must resolve"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            "registration should route to universal"
        );
    }
    #[test]
    fn native_amx_participants_ignore_private_scopes_for_global_asset_write() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace_id),
        ]);
        let owning_domain =
            DomainId::try_new("cash", "universal").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::with_scope(
                    asset_definition.clone(),
                    alice_id.clone(),
                    AssetBalanceScope::Dataspace(dataspace_id),
                ),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::Global,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &asset_definition, "pkr#paynet");
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        let view = state.view();
        assert_eq!(
            native_amx_participant_dataspaces_with_world(
                &tx,
                &view.nexus().dataspace_catalog,
                view.world()
            ),
            Vec::<DataSpaceId>::new()
        );
    }
    #[test]
    fn native_amx_participants_preserve_restricted_asset_private_scope() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let dataspace_id = DataSpaceId::new(10);
        let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace_id),
        ]);
        let owning_domain = DomainId::try_new("cash", "paynet").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::with_scope(
                    asset_definition.clone(),
                    alice_id.clone(),
                    AssetBalanceScope::Dataspace(dataspace_id),
                ),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        bind_asset_definition_alias(&mut state, &asset_definition, "pkr#paynet");
        scope_account_to_dataspace(&mut state, &alice_id, dataspace_id);
        let view = state.view();
        assert_eq!(
            native_amx_participant_dataspaces_with_world(
                &tx,
                &view.nexus().dataspace_catalog,
                view.world()
            ),
            vec![dataspace_id]
        );
    }
    #[test]
    fn confined_asset_refuses_an_explicit_universal_or_foreign_balance_scope() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let definition_dataspace = DataSpaceId::new(7);
        let account_dataspace = DataSpaceId::new(8);
        let dataspace_catalog = dataspace_catalog(&[
            (definition_dataspace, "definition"),
            (account_dataspace, "account"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), definition_dataspace),
            (LaneId::new(3), account_dataspace),
        ]);
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(3),
                dataspace: Some(account_dataspace),
                matcher: LaneRoutingMatcher {
                    account: Some(alice_id.to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        };
        let router = ConfigLaneRouter::new(policy, dataspace_catalog.clone(), lane_catalog.clone());
        let owning_domain =
            DomainId::try_new("cash", "definition").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "coin".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::with_scope(
                    asset_definition.clone(),
                    alice_id.clone(),
                    AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL),
                ),
            ))],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "coin".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&alice_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        scope_account_to_dataspace(&mut state, &alice_id, account_dataspace);
        let view = state.view();
        // A restricted definition homed in a non-universal dataspace is confined there: an
        // explicit universal (or any foreign) bucket would create a public balance elsewhere.
        assert!(matches!(
            router.try_route_plan_with_view(&tx, &view),
            Err(RoutingResolveError::OrdinaryRouteUnavailable { .. })
        ));
        let foreign = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::with_scope(
                    asset_definition.clone(),
                    alice_id.clone(),
                    AssetBalanceScope::Dataspace(account_dataspace),
                ),
            ))],
        );
        assert!(matches!(
            router.try_route_plan_with_view(&foreign, &view),
            Err(RoutingResolveError::OrdinaryRouteUnavailable { .. })
        ));
        let home = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::with_scope(
                    asset_definition,
                    alice_id.clone(),
                    AssetBalanceScope::Dataspace(definition_dataspace),
                ),
            ))],
        );
        // The home bucket itself is never refused by confinement; the holder's other binding
        // still makes it a cross-dataspace plan, exactly as before.
        assert!(router.try_route_plan_with_view(&home, &view).is_ok());
    }
    #[test]
    fn restricted_asset_plan_is_invariant_to_duplicate_cross_dataspace_transfer() {
        let (sender_id, sender_keypair) = gen_account_in("wonderland");
        let (receiver_id, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(7);
        let destination_dataspace = DataSpaceId::new(8);
        let source_lane = LaneId::new(2);
        let destination_lane = LaneId::new(3);
        let dataspace_catalog = dataspace_catalog(&[
            (source_dataspace, "source"),
            (destination_dataspace, "destination"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (source_lane, source_dataspace),
            (destination_lane, destination_dataspace),
        ]);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        );
        let owning_domain = DomainId::try_new("cash", "source").expect("asset definition domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            owning_domain.clone(),
            "coin".parse().expect("asset definition name"),
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    asset_definition.clone(),
                    "coin".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(owning_domain),
                )
                .build(&sender_id),
            ],
            dataspace_catalog,
            lane_catalog,
        );
        install_router_nexus(&mut state, &router);
        scope_account_to_dataspace(&mut state, &sender_id, source_dataspace);
        scope_account_to_dataspace(&mut state, &receiver_id, destination_dataspace);
        let transfer = InstructionBox::from(Transfer::asset_quantity(
            AssetId::of(asset_definition, sender_id.clone()),
            1_u32,
            receiver_id,
        ));
        let expected = RoutingPlan::native_amx(
            RoutingDecision::new(source_lane, source_dataspace),
            vec![
                RouteLeg::new(
                    RoutingDecision::new(source_lane, source_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(destination_lane, destination_dataspace),
                    RouteLegRole::Participant,
                ),
            ],
        );
        for instructions in [
            vec![transfer.clone()],
            vec![transfer.clone(), transfer.clone()],
        ] {
            let tx = sample_transaction(&sender_id, sender_keypair.private_key(), instructions);
            assert_eq!(
                router
                    .try_route_plan_with_view(&tx, &state.view())
                    .expect("restricted transfer plan should resolve with account scopes"),
                expected,
                "duplicating the collapsed transfer must not change its coordinator",
            );
        }

        let mut strict_metadata = Metadata::default();
        strict_metadata.insert(
            AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
            iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
        );
        let strict_tx = sample_transaction_with_metadata(
            &sender_id,
            sender_keypair.private_key(),
            vec![transfer],
            strict_metadata,
        );
        assert_eq!(
            router.try_route_plan_with_view(&strict_tx, &state.view()),
            Err(
                RoutingResolveError::ConflictingTransactionDataspaceTargets {
                    first_dataspace_id: source_dataspace,
                    second_dataspace_id: destination_dataspace,
                }
            ),
        );
    }
    fn fx_corridor_fixture(
        source_dataspace: DataSpaceId,
        destination_dataspace: DataSpaceId,
        owner: AccountId,
        _former_destination_reserve: AccountId,
        recipient: AccountId,
        settlement_id: &str,
    ) -> (FxCorridorPolicy, InstructionBox) {
        let source_asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cbuae", "universal").expect("source asset domain"),
            "aed".parse().expect("source asset name"),
        );
        let destination_asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("sbp", "universal").expect("destination asset domain"),
            "pkr".parse().expect("destination asset name"),
        );
        let corridor = FxCorridorPolicy {
            policy_id: "mobile_aed_pkr".parse().expect("FX corridor policy id"),
            revision: 1,
            owner,
            source_dataspace,
            source_asset_definition_id: source_asset_definition_id.clone(),
            destination_dataspace,
            destination_asset_definition_id: destination_asset_definition_id.clone(),
            allowed_destination_alias_domains: BTreeSet::from([
                DomainId::try_new("hbl", "sbp").expect("HBL alias domain"),
                DomainId::try_new("ubl", "sbp").expect("UBL alias domain"),
            ]),
            oracle_feed_id: "mobile_aed_pkr_rate".parse().expect("FX corridor feed id"),
            max_oracle_age_ms: 60_000,
            max_source_amount_per_settlement: 1_000_u32.into(),
            max_destination_amount_per_settlement: 100_000_u32.into(),
            velocity_window_ms: 60_000,
            max_settlements_per_window: 100,
            max_source_amount_per_window: 10_000_u32.into(),
            max_destination_amount_per_window: 1_000_000_u32.into(),
            enabled: true,
        };
        let request_hash = Hash::new(b"router-fx-oracle-request");
        let oracle_event = FeedEvent {
            feed_id: corridor.oracle_feed_id.clone(),
            feed_config_version: FeedConfigVersion(1),
            slot: 1,
            request_hash,
            outcome: FeedEventOutcome::Success(FeedSuccess {
                value: ObservationValue::new(76, 0),
                entries: Vec::new(),
            }),
        };
        let settlement = SettleFxCorridor {
            policy_id: corridor.policy_id.clone(),
            expected_policy_revision: corridor.revision,
            source_asset_definition_id,
            destination_asset_definition_id,
            settlement_id: settlement_id.parse().expect("FX settlement id"),
            recipient,
            source_amount: iroha_primitives::numeric::Quantity::from(10_u32),
            expected_destination_amount: 760_u32.into(),
            oracle_evidence: FxCorridorOracleEvidence {
                feed_id: oracle_event.feed_id.clone(),
                feed_config_version: oracle_event.feed_config_version,
                slot: oracle_event.slot,
                request_hash: oracle_event.request_hash,
                event_hash: HashOf::new(&oracle_event),
            },
        };
        (
            corridor,
            InstructionBox::from(SettlementInstructionBox::SettleFxCorridor(settlement)),
        )
    }
    fn install_fx_corridor_policy(state: &crate::state::State, corridor: FxCorridorPolicy) {
        let mut registry = FxCorridorPolicyRegistry::default();
        registry.upsert(corridor);
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                registry.into_custom_parameter(),
            ));
        world.commit();
    }
    fn fx_route_plan_results(
        router: &ConfigLaneRouter,
        tx: &dyn TransactionRoutingView,
        corridor: FxCorridorPolicy,
        world: crate::state::World,
    ) -> (
        Result<RoutingPlan, RoutingResolveError>,
        Result<RoutingPlan, RoutingResolveError>,
    ) {
        let mut state = state_from_world(world);
        install_router_nexus(&mut state, router);
        install_fx_corridor_policy(&state, corridor);
        let view = state.view();
        let queued_plan = router.try_route_plan_with_view(tx, &view);
        let block_plan = evaluate_policy_plan_with_nexus_and_world_at(
            view.nexus(),
            tx,
            view.world(),
            state_view_ledger_time_ms(&view),
        );
        (queued_plan, block_plan)
    }
    fn expected_fx_plan(
        source_lane: LaneId,
        source_dataspace: DataSpaceId,
        destination_lane: LaneId,
        destination_dataspace: DataSpaceId,
    ) -> RoutingPlan {
        RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![
                RouteLeg::new(
                    RoutingDecision::new(source_lane, source_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(destination_lane, destination_dataspace),
                    RouteLegRole::Participant,
                ),
            ],
        )
    }
    #[test]
    fn fx_policy_update_mixed_with_private_target_retains_amx_plan_with_state() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let private_dataspace = DataSpaceId::new(7);
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let private_lane = LaneId::new(2);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[
                (private_dataspace, "private"),
                (source_dataspace, "cbuae"),
                (destination_dataspace, "sbp"),
            ]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (private_lane, private_dataspace),
                (LaneId::new(3), source_dataspace),
                (LaneId::new(4), destination_dataspace),
            ]),
        );
        let (corridor, _) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "policy_update_route",
        );
        let updates = [
            InstructionBox::from(SetFxCorridorPolicy {
                policy: corridor.clone(),
            }),
            InstructionBox::from(SettlementInstructionBox::SetFxCorridorPolicy(
                SetFxCorridorPolicy { policy: corridor },
            )),
        ];
        let private_write = InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("merchant", "private").expect("private domain id"),
        )));
        let expected = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![RouteLeg::new(
                RoutingDecision::new(private_lane, private_dataspace),
                RouteLegRole::Participant,
            )],
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        for (index, update) in updates.into_iter().enumerate() {
            let tx = sample_transaction(
                &authority,
                authority_keypair.private_key(),
                vec![update.clone(), private_write.clone()],
            );
            assert_eq!(
                router
                    .try_route_plan_without_state(&tx)
                    .unwrap_or_else(|error| panic!("policy update {index} failed: {error}")),
                None,
                "textual domain routing must wait for SNS state",
            );
            assert_eq!(
                router
                    .try_route_plan(&tx)
                    .unwrap_or_else(|error| panic!("policy update plan {index} failed: {error}")),
                expected,
            );
            assert_eq!(
                router
                    .try_route_plan_with_state(&tx, &state)
                    .unwrap_or_else(|error| panic!("state plan {index} failed: {error}")),
                expected,
            );

            let mut strict_metadata = Metadata::default();
            strict_metadata.insert(
                AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
                iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
            );
            let strict_tx = sample_transaction_with_metadata(
                &authority,
                authority_keypair.private_key(),
                vec![update, private_write.clone()],
                strict_metadata,
            );
            assert_eq!(router.try_route_plan_without_state(&strict_tx), Ok(None),);
            assert_eq!(
                router.try_route_plan_with_state(&strict_tx, &state),
                Err(
                    RoutingResolveError::ConflictingTransactionDataspaceTargets {
                        first_dataspace_id: DataSpaceId::UNIVERSAL,
                        second_dataspace_id: private_dataspace,
                    }
                ),
            );
        }
    }
    #[test]
    fn same_transaction_fx_policy_overlay_is_ordered_across_executables() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let dataspace_catalog =
            dataspace_catalog(&[(source_dataspace, "cbuae"), (destination_dataspace, "sbp")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (source_lane, source_dataspace),
            (destination_lane, destination_dataspace),
        ]);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog.clone(),
            lane_catalog,
        );
        let (corridor, settlement) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "same_transaction_policy",
        );
        let fund = FundFxCorridorEscrow {
            policy_id: corridor.policy_id.clone(),
            expected_policy_revision: corridor.revision,
            destination_asset_definition_id: corridor.destination_asset_definition_id.clone(),
            amount: 10_u32.into(),
        };
        let refund = RefundFxCorridorEscrow {
            policy_id: corridor.policy_id.clone(),
            expected_policy_revision: corridor.revision,
            destination_asset_definition_id: corridor.destination_asset_definition_id.clone(),
            amount: 10_u32.into(),
        };
        let destination_plan = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![RouteLeg::new(
                RoutingDecision::new(destination_lane, destination_dataspace),
                RouteLegRole::Participant,
            )],
        );
        let operations = [
            (
                "direct fund",
                InstructionBox::from(fund),
                destination_plan.clone(),
            ),
            (
                "boxed refund",
                InstructionBox::from(SettlementInstructionBox::RefundFxCorridorEscrow(refund)),
                destination_plan,
            ),
            (
                "boxed settlement",
                settlement,
                expected_fx_plan(
                    source_lane,
                    source_dataspace,
                    destination_lane,
                    destination_dataspace,
                ),
            ),
        ];
        let updates = [
            (
                "direct policy",
                InstructionBox::from(SetFxCorridorPolicy {
                    policy: corridor.clone(),
                }),
            ),
            (
                "boxed policy",
                InstructionBox::from(SettlementInstructionBox::SetFxCorridorPolicy(
                    SetFxCorridorPolicy {
                        policy: corridor.clone(),
                    },
                )),
            ),
        ];
        let executable_variants = |instructions: Vec<InstructionBox>| {
            vec![
                (
                    "instructions",
                    Executable::Instructions(instructions.clone().into()),
                ),
                (
                    "batch",
                    Executable::Batch(
                        instructions
                            .iter()
                            .cloned()
                            .map(ExecutableBatchItem::Instruction)
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                ),
                ("proved overlay", sample_proved_executable(instructions)),
            ]
        };
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        for (update_label, update) in updates {
            for (operation_label, operation, expected) in &operations {
                for (executable_label, executable) in
                    executable_variants(vec![update.clone(), operation.clone()])
                {
                    let tx = sample_executable_transaction(
                        &authority,
                        authority_keypair.private_key(),
                        executable,
                    );
                    assert_eq!(
                        router.try_route_plan_with_view(&tx, &state.view()),
                        Ok(expected.clone()),
                        "{update_label} before {operation_label} in {executable_label}",
                    );
                    assert_eq!(
                        router.try_route_plan_with_state(&tx, &state),
                        Ok(expected.clone()),
                        "state-backed {update_label} before {operation_label} in {executable_label}",
                    );
                }
                for (executable_label, executable) in
                    executable_variants(vec![operation.clone(), update.clone()])
                {
                    let tx = sample_executable_transaction(
                        &authority,
                        authority_keypair.private_key(),
                        executable,
                    );
                    assert_eq!(
                        router.try_route_plan_with_view(&tx, &state.view()),
                        Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
                        "{operation_label} before {update_label} in {executable_label}",
                    );
                    assert_eq!(
                        router.try_route_plan_with_state(&tx, &state),
                        Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
                        "state-backed {operation_label} before {update_label} in {executable_label}",
                    );
                }
            }
        }
    }
    #[test]
    fn nested_fx_policy_overlay_is_ordered_and_does_not_leak() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let destination_lane = LaneId::new(4);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(source_dataspace, "cbuae"), (destination_dataspace, "sbp")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (LaneId::new(3), source_dataspace),
                (destination_lane, destination_dataspace),
            ]),
        );
        let (corridor, _) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "nested_policy_overlay",
        );
        let update = InstructionBox::from(SetFxCorridorPolicy {
            policy: corridor.clone(),
        });
        let fund = InstructionBox::from(SettlementInstructionBox::FundFxCorridorEscrow(
            FundFxCorridorEscrow {
                policy_id: corridor.policy_id,
                expected_policy_revision: corridor.revision,
                destination_asset_definition_id: corridor.destination_asset_definition_id,
                amount: 10_u32.into(),
            },
        ));
        let expected = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![RouteLeg::new(
                RoutingDecision::new(destination_lane, destination_dataspace),
                RouteLegRole::Participant,
            )],
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        let nested_cases = [
            (
                "trigger",
                sample_trigger_registration(
                    &authority,
                    "ordered_nested_fx_policy",
                    Executable::Instructions(vec![update.clone(), fund.clone()].into()),
                ),
                sample_trigger_registration(
                    &authority,
                    "reversed_nested_fx_policy",
                    Executable::Instructions(vec![fund.clone(), update.clone()].into()),
                ),
                sample_trigger_registration(
                    &authority,
                    "isolated_nested_fx_policy",
                    Executable::Instructions(vec![update.clone()].into()),
                ),
            ),
            (
                "multisig proposal",
                InstructionBox::from(MultisigPropose::new(
                    authority.clone(),
                    vec![update.clone(), fund.clone()],
                    None,
                )),
                InstructionBox::from(MultisigPropose::new(
                    authority.clone(),
                    vec![fund.clone(), update.clone()],
                    None,
                )),
                InstructionBox::from(MultisigPropose::new(
                    authority.clone(),
                    vec![update.clone()],
                    None,
                )),
            ),
        ];
        for (label, ordered, reversed, isolated_update) in nested_cases {
            let ordered_tx =
                sample_transaction(&authority, authority_keypair.private_key(), vec![ordered]);
            assert_eq!(
                router.try_route_plan_with_state(&ordered_tx, &state),
                Ok(expected.clone()),
                "ordered {label} overlay",
            );
            let reversed_tx =
                sample_transaction(&authority, authority_keypair.private_key(), vec![reversed]);
            assert_eq!(
                router.try_route_plan_with_state(&reversed_tx, &state),
                Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
                "reversed {label} overlay",
            );
            let leak_tx = sample_transaction(
                &authority,
                authority_keypair.private_key(),
                vec![isolated_update, fund.clone()],
            );
            assert_eq!(
                router.try_route_plan_with_state(&leak_tx, &state),
                Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
                "{label} overlay must not escape to a later outer instruction",
            );
        }
    }
    #[test]
    fn multisig_approve_fx_policy_overlay_flows_to_later_outer_instruction() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (multisig_id, _) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let dataspace_catalog =
            dataspace_catalog(&[(source_dataspace, "cbuae"), (destination_dataspace, "sbp")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (source_lane, source_dataspace),
            (destination_lane, destination_dataspace),
        ]);
        let policy = default_routing_policy();
        let router = ConfigLaneRouter::new(
            policy.clone(),
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        );
        let (corridor, _) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "approved_policy_overlay",
        );
        let update = InstructionBox::from(SetFxCorridorPolicy {
            policy: corridor.clone(),
        });
        let fund = InstructionBox::from(SettlementInstructionBox::FundFxCorridorEscrow(
            FundFxCorridorEscrow {
                policy_id: corridor.policy_id.clone(),
                expected_policy_revision: corridor.revision,
                destination_asset_definition_id: corridor.destination_asset_definition_id.clone(),
                amount: 10_u32.into(),
            },
        ));
        let proposed = vec![update.clone()];
        let proposal_hash = HashOf::new(&proposed);
        let proposal = InstructionBox::from(MultisigPropose::new(
            multisig_id.clone(),
            proposed.clone(),
            None,
        ));
        let approval =
            InstructionBox::from(MultisigApprove::new(multisig_id.clone(), proposal_hash));
        let expected = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![RouteLeg::new(
                RoutingDecision::new(destination_lane, destination_dataspace),
                RouteLegRole::Participant,
            )],
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);

        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![proposal.clone(), approval.clone(), fund.clone()],
        );
        assert_eq!(
            router.try_route_plan_with_view(&tx, &state.view()),
            Ok(expected.clone()),
            "an authenticated preceding proposal may execute its FX policy update",
        );
        assert_eq!(
            evaluate_policy_plan_with_catalog_and_world(
                &policy,
                &lane_catalog,
                &dataspace_catalog,
                &tx,
                state.view().world(),
            ),
            Ok(expected.clone()),
            "queue and validation routing must agree on approval effects",
        );

        let reversed_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![approval.clone(), proposal.clone(), fund.clone()],
        );
        assert_eq!(
            router.try_route_plan_with_view(&reversed_tx, &state.view()),
            Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
            "an approval must not authenticate a later sibling proposal",
        );

        let nested_cases = [
            sample_trigger_registration(
                &authority,
                "nested_multisig_fx_approval",
                Executable::Instructions(vec![approval.clone()].into()),
            ),
            InstructionBox::from(MultisigPropose::new(
                multisig_id.clone(),
                vec![approval.clone()],
                None,
            )),
        ];
        for (index, nested_approval) in nested_cases.into_iter().enumerate() {
            let leak_tx = sample_transaction(
                &authority,
                authority_keypair.private_key(),
                vec![proposal.clone(), nested_approval, fund.clone()],
            );
            assert_eq!(
                router.try_route_plan_with_view(&leak_tx, &state.view()),
                Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
                "nested approval case {index} must not leak payload effects",
            );
        }

        let mut persisted_state = blank_state();
        install_router_nexus(&mut persisted_state, &router);
        let persisted_proposal = MultisigProposalState::new(
            multisig_id.clone(),
            proposal_hash,
            proposed,
            1,
            10_000,
            BTreeSet::new(),
            None,
        );
        persisted_state
            .world
            .smart_contract_state_mut_for_testing()
            .insert(
                multisig_proposal_state_key(&multisig_id, &proposal_hash),
                encoded_multisig_proposal_state(&persisted_proposal),
            );
        let persisted_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![approval.clone(), fund.clone()],
        );
        assert_eq!(
            router.try_route_plan_with_view(&persisted_tx, &persisted_state.view()),
            Ok(expected.clone()),
            "persisted proposal fallback must propagate the same ordered effect",
        );

        let (outer_multisig_id, _) = gen_account_in("wonderland");
        let outer_proposed = vec![approval.clone()];
        let outer_proposal_hash = HashOf::new(&outer_proposed);
        let outer_proposal = MultisigProposalState::new(
            outer_multisig_id.clone(),
            outer_proposal_hash,
            outer_proposed,
            1,
            10_000,
            BTreeSet::new(),
            None,
        );
        persisted_state
            .world
            .smart_contract_state_mut_for_testing()
            .insert(
                multisig_proposal_state_key(&outer_multisig_id, &outer_proposal_hash),
                encoded_multisig_proposal_state(&outer_proposal),
            );
        let nested_approval_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(MultisigApprove::new(outer_multisig_id, outer_proposal_hash)),
                fund.clone(),
            ],
        );
        assert_eq!(
            router.try_route_plan_with_view(&nested_approval_tx, &persisted_state.view()),
            Ok(expected.clone()),
            "a persisted approval chain must propagate authenticated FX policy effects",
        );
        assert_eq!(
            evaluate_policy_plan_with_catalog_and_world(
                &policy,
                &lane_catalog,
                &dataspace_catalog,
                &nested_approval_tx,
                persisted_state.view().world(),
            ),
            Ok(expected.clone()),
            "queue and validation routing must agree on nested approval effects",
        );

        let (payload_multisig_id, _) = gen_account_in("wonderland");
        let payload_proposed = vec![approval.clone(), fund.clone()];
        let payload_proposal_hash = HashOf::new(&payload_proposed);
        let payload_proposal = MultisigProposalState::new(
            payload_multisig_id.clone(),
            payload_proposal_hash,
            payload_proposed,
            1,
            10_000,
            BTreeSet::new(),
            None,
        );
        persisted_state
            .world
            .smart_contract_state_mut_for_testing()
            .insert(
                multisig_proposal_state_key(&payload_multisig_id, &payload_proposal_hash),
                encoded_multisig_proposal_state(&payload_proposal),
            );
        let nested_payload_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![InstructionBox::from(MultisigApprove::new(
                payload_multisig_id,
                payload_proposal_hash,
            ))],
        );
        assert_eq!(
            router.try_route_plan_with_view(&nested_payload_tx, &persisted_state.view()),
            Ok(expected.clone()),
            "an approval chain must expose FX policy effects to later authenticated payload instructions",
        );

        let (local_multisig_id, _) = gen_account_in("wonderland");
        let local_proposed = vec![update.clone()];
        let local_proposal_hash = HashOf::new(&local_proposed);
        let local_proposal = InstructionBox::from(MultisigPropose::new(
            local_multisig_id.clone(),
            local_proposed,
            None,
        ));
        let local_approval =
            InstructionBox::from(MultisigApprove::new(local_multisig_id, local_proposal_hash));
        let (ordered_outer_id, _) = gen_account_in("wonderland");
        let ordered_outer_instructions =
            vec![local_proposal.clone(), local_approval.clone(), fund.clone()];
        let ordered_outer_hash = HashOf::new(&ordered_outer_instructions);
        persisted_state
            .world
            .smart_contract_state_mut_for_testing()
            .insert(
                multisig_proposal_state_key(&ordered_outer_id, &ordered_outer_hash),
                encoded_multisig_proposal_state(&MultisigProposalState::new(
                    ordered_outer_id.clone(),
                    ordered_outer_hash,
                    ordered_outer_instructions,
                    1,
                    10_000,
                    BTreeSet::new(),
                    None,
                )),
            );
        let ordered_local_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![InstructionBox::from(MultisigApprove::new(
                ordered_outer_id,
                ordered_outer_hash,
            ))],
        );
        assert_eq!(
            router.try_route_plan_with_view(&ordered_local_tx, &persisted_state.view()),
            Ok(expected.clone()),
            "a persisted payload must observe a locally executed proposal before its approval",
        );
        assert_eq!(
            evaluate_policy_plan_with_catalog_and_world(
                &policy,
                &lane_catalog,
                &dataspace_catalog,
                &ordered_local_tx,
                persisted_state.view().world(),
            ),
            Ok(expected.clone()),
            "queue and validation routing must agree on local proposal effects",
        );

        let (reversed_outer_id, _) = gen_account_in("wonderland");
        let reversed_outer_instructions =
            vec![local_approval.clone(), local_proposal.clone(), fund.clone()];
        let reversed_outer_hash = HashOf::new(&reversed_outer_instructions);
        persisted_state
            .world
            .smart_contract_state_mut_for_testing()
            .insert(
                multisig_proposal_state_key(&reversed_outer_id, &reversed_outer_hash),
                encoded_multisig_proposal_state(&MultisigProposalState::new(
                    reversed_outer_id.clone(),
                    reversed_outer_hash,
                    reversed_outer_instructions,
                    1,
                    10_000,
                    BTreeSet::new(),
                    None,
                )),
            );
        let reversed_local_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![InstructionBox::from(MultisigApprove::new(
                reversed_outer_id,
                reversed_outer_hash,
            ))],
        );
        assert_eq!(
            router.try_route_plan_with_view(&reversed_local_tx, &persisted_state.view()),
            Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
            "an approval must not see a local proposal that executes later in its payload",
        );
        assert_eq!(
            evaluate_policy_plan_with_catalog_and_world(
                &policy,
                &lane_catalog,
                &dataspace_catalog,
                &reversed_local_tx,
                persisted_state.view().world(),
            ),
            Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
        );

        let (inert_outer_id, _) = gen_account_in("wonderland");
        let inert_proposal = InstructionBox::from(MultisigPropose::new(
            inert_outer_id,
            vec![local_proposal, local_approval],
            None,
        ));
        let inert_leak_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![inert_proposal, fund],
        );
        assert_eq!(
            router.try_route_plan_with_view(&inert_leak_tx, &persisted_state.view()),
            Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
            "an unapproved proposal payload must not leak its local approval effects",
        );
        assert_eq!(
            evaluate_policy_plan_with_catalog_and_world(
                &policy,
                &lane_catalog,
                &dataspace_catalog,
                &inert_leak_tx,
                persisted_state.view().world(),
            ),
            Err(RoutingResolveError::FxCorridorPolicyRegistryMissing),
        );
    }
    #[test]
    fn persisted_multisig_body_binding_and_local_refusal_reach_signed_queue_admission() {
        let (authority, keypair) = gen_account_in("wonderland");
        let (account, _) = gen_account_in("wonderland");
        let instructions = vec![InstructionBox::from(iroha_data_model::isi::Log::new(
            iroha_data_model::prelude::Level::INFO,
            "reviewed queue proposal".into(),
        ))];
        let hash = HashOf::new(&instructions);
        let approval = InstructionBox::from(MultisigApprove::new(account.clone(), hash));
        let signed = sample_transaction(&authority, keypair.private_key(), vec![approval.clone()]);
        let original = MultisigProposalState::new(
            account.clone(),
            hash,
            instructions,
            1,
            10_000,
            BTreeSet::new(),
            None,
        );
        let key = multisig_proposal_state_key(&account, &hash);
        let bytes = encoded_multisig_proposal_state(&original);
        let mut state = blank_state();
        let route = |state: &State| {
            evaluate_policy_plan_with_catalog_and_world(
                &default_routing_policy(),
                &catalog_with_lanes(&[LaneId::SINGLE]),
                &DataSpaceCatalog::default(),
                &signed,
                state.view().world(),
            )
        };
        state
            .world
            .smart_contract_state_mut_for_testing()
            .insert(key.clone(), bytes.clone());
        let expected_route = route(&state).expect("the exact signed approval routes successfully");
        let expected_deferral = crate::execution_attempt::ExecutionDeferred::from(
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
        );
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                assert_eq!(
                    multisig_proposal_state_raw(state.view().world(), &account, &hash),
                    Err(RoutingResolveError::Deferred(expected_deferral.clone()))
                );
                assert_eq!(
                    route(&state),
                    Err(RoutingResolveError::Deferred(expected_deferral))
                );
            },
        );
        assert_eq!(
            route(&state),
            Ok(expected_route.clone()),
            "same signed operation retries after the original local limit ends"
        );
        for malformed in [false, true] {
            let mut altered = original.clone();
            altered.instructions = Vec::new();
            state.world.smart_contract_state_mut_for_testing().insert(
                key.clone(),
                if malformed {
                    vec![1, 2, 3]
                } else {
                    encoded_multisig_proposal_state(&altered)
                },
            );
            assert!(matches!(
                route(&state),
                Err(RoutingResolveError::InvalidMultisigProposal { .. })
            ));
            let view = state.view();
            assert!(matches!(
                instruction_transaction_target_requires_universal_coordinator_with_world(
                    &*approval,
                    None,
                    view.world(),
                    None,
                ),
                Err(RoutingResolveError::InvalidMultisigProposal { .. })
            ));
            let mut overlay = FxCorridorRoutingOverlay::default();
            assert!(matches!(
                observe_top_level_instruction_fx_effects(
                    &mut overlay,
                    &*approval,
                    0,
                    &[],
                    view.world()
                ),
                Err(RoutingResolveError::InvalidMultisigProposal { .. })
            ));
            assert!(overlay.policies.is_empty());
            assert!(overlay.executed_multisig_proposals.is_empty());
        }
        state
            .world
            .smart_contract_state_mut_for_testing()
            .insert(key.clone(), bytes.clone());
        assert_eq!(route(&state), Ok(expected_route));
        assert_eq!(
            state.view().world().smart_contract_state().get(&key),
            Some(&bytes)
        );
    }
    #[test]
    fn authenticated_multisig_approval_fx_effect_projection_breaks_cycles() {
        let (multisig_id, _) = gen_account_in("wonderland");
        let instructions_hash = HashOf::new(&Vec::<InstructionBox>::new());
        let approval =
            InstructionBox::from(MultisigApprove::new(multisig_id.clone(), instructions_hash));
        let proposal = MultisigProposalState::new(
            multisig_id.clone(),
            instructions_hash,
            vec![approval.clone()],
            1,
            10_000,
            BTreeSet::new(),
            None,
        );
        let mut state = blank_state();
        state.world.smart_contract_state_mut_for_testing().insert(
            multisig_proposal_state_key(&multisig_id, &instructions_hash),
            encoded_multisig_proposal_state(&proposal),
        );
        let view = state.view();
        let mut fx_overlay = FxCorridorRoutingOverlay::default();
        assert!(matches!(
            observe_top_level_instruction_fx_effects(
                &mut fx_overlay,
                &*approval,
                0,
                &[],
                view.world()
            ),
            Err(RoutingResolveError::InvalidMultisigProposal { .. })
        ));
        assert!(fx_overlay.policies.is_empty());
    }
    #[test]
    fn persisted_multisig_proposal_cycle_fails_closed_without_rejecting_repeated_siblings() {
        let (cyclic_account, _) = gen_account_in("wonderland");
        let cyclic_hash = HashOf::new(&Vec::<InstructionBox>::new());
        let cyclic_approval =
            InstructionBox::from(MultisigApprove::new(cyclic_account.clone(), cyclic_hash));
        let cyclic_proposal = MultisigProposalState::new(
            cyclic_account.clone(),
            cyclic_hash,
            vec![cyclic_approval.clone()],
            1,
            10_000,
            BTreeSet::new(),
            None,
        );
        let mut state = blank_state();
        state.world.smart_contract_state_mut_for_testing().insert(
            multisig_proposal_state_key(&cyclic_account, &cyclic_hash),
            encoded_multisig_proposal_state(&cyclic_proposal),
        );
        let expected = RoutingResolveError::InvalidMultisigProposal {
            account: cyclic_account.clone(),
            instructions_hash: cyclic_hash,
            reason: crate::smartcontracts::isi::multisig::read_proposal_state(
                state.view().world(),
                &cyclic_account,
                &cyclic_hash,
            )
            .unwrap_err()
            .to_string(),
        };
        assert_eq!(expected.as_label(), "invalid_multisig_proposal");
        let mut cycle_stack = MultisigProposalRoutingStack::default();
        assert!(matches!(
            cycle_stack.with_proposal(&cyclic_account, &cyclic_hash, |stack| {
                stack.with_proposal(&cyclic_account, &cyclic_hash, |_| Ok(()))
            }),
            Err(RoutingResolveError::MultisigProposalCycle { .. })
        ));
        assert!(cycle_stack.active.is_empty());
        {
            let view = state.view();
            assert_eq!(
                instruction_settlement_dataspace_target(&*cyclic_approval, None, Some(&view),),
                Err(expected.clone()),
            );
            assert_eq!(
                deferred_instruction_concrete_dataspace_targets(
                    &*cyclic_approval,
                    None,
                    Some(&view),
                ),
                Err(expected.clone()),
            );
            assert_eq!(
                instruction_transaction_dataspace_target(&*cyclic_approval, None, Some(&view)),
                Err(expected.clone()),
            );
            assert_eq!(
                instruction_transaction_target_requires_universal_coordinator(
                    &*cyclic_approval,
                    None,
                    Some(&view),
                ),
                Err(expected.clone()),
            );
            let (authority, authority_keypair) = gen_account_in("wonderland");
            let transaction = sample_transaction(
                &authority,
                authority_keypair.private_key(),
                vec![cyclic_approval.clone()],
            );
            assert_eq!(
                evaluate_policy_plan_with_catalog_and_world(
                    &default_routing_policy(),
                    &catalog_with_lanes(&[LaneId::SINGLE]),
                    &DataSpaceCatalog::default(),
                    &transaction,
                    view.world(),
                ),
                Err(expected.clone()),
            );
            let mut participants = BTreeSet::new();
            let mut participant_stack = MultisigProposalRoutingStack::default();
            assert_eq!(
                collect_instruction_native_amx_participants(
                    &*cyclic_approval,
                    &DataSpaceCatalog::default(),
                    view.world(),
                    None,
                    &mut participants,
                    &FxCorridorRoutingOverlay::default(),
                    &mut participant_stack,
                ),
                Err(expected.clone()),
            );
        }

        let (leaf_account, _) = gen_account_in("wonderland");
        let leaf_hash = HashOf::new(&Vec::<InstructionBox>::new());
        state.world.smart_contract_state_mut_for_testing().insert(
            multisig_proposal_state_key(&leaf_account, &leaf_hash),
            encoded_multisig_proposal_state(&MultisigProposalState::new(
                leaf_account.clone(),
                leaf_hash,
                Vec::new(),
                1,
                10_000,
                BTreeSet::new(),
                None,
            )),
        );
        let (parent_account, _) = gen_account_in("wonderland");
        let repeated_approval = InstructionBox::from(MultisigApprove::new(leaf_account, leaf_hash));
        let parent_instructions = vec![repeated_approval.clone(), repeated_approval];
        let parent_hash = HashOf::new(&parent_instructions);
        state.world.smart_contract_state_mut_for_testing().insert(
            multisig_proposal_state_key(&parent_account, &parent_hash),
            encoded_multisig_proposal_state(&MultisigProposalState::new(
                parent_account.clone(),
                parent_hash,
                parent_instructions,
                1,
                10_000,
                BTreeSet::new(),
                None,
            )),
        );
        let parent_approval =
            InstructionBox::from(MultisigApprove::new(parent_account, parent_hash));
        let view = state.view();
        let mut stack = MultisigProposalRoutingStack::default();
        assert_eq!(
            instruction_settlement_dataspace_target_with_stack(
                &*parent_approval,
                None,
                Some(&view),
                &mut stack,
            ),
            Ok(None),
            "repeated sibling approvals must not be mistaken for a cycle",
        );
        assert_eq!(
            stack.expansions, 3,
            "the parent and two actual leaf edges must each expand exactly once",
        );
    }
    #[test]
    fn persisted_multisig_chain_is_checked_in_linear_expansions() {
        const NODE_COUNT: usize = 64;
        let mut state = blank_state();
        let mut child = None;
        for _ in (0..NODE_COUNT).rev() {
            let (account, _) = gen_account_in("wonderland");
            let instructions = child.map_or_else(Vec::new, |(next_account, next_hash)| {
                vec![InstructionBox::from(MultisigApprove::new(
                    next_account,
                    next_hash,
                ))]
            });
            let hash = HashOf::new(&instructions);
            state.world.smart_contract_state_mut_for_testing().insert(
                multisig_proposal_state_key(&account, &hash),
                encoded_multisig_proposal_state(&MultisigProposalState::new(
                    account.clone(),
                    hash,
                    instructions,
                    1,
                    10_000,
                    BTreeSet::new(),
                    None,
                )),
            );
            child = Some((account, hash));
        }
        let (root_account, root_hash) = child.unwrap();
        let root_approval =
            InstructionBox::from(MultisigApprove::new(root_account.clone(), root_hash));
        let view = state.view();
        let mut stack = MultisigProposalRoutingStack::default();
        assert_eq!(
            instruction_settlement_dataspace_target_with_stack(
                &*root_approval,
                None,
                Some(&view),
                &mut stack,
            ),
            Ok(None),
        );
        assert_eq!(stack.expansions, NODE_COUNT);
        drop(view);
        let (outer_account, _) = gen_account_in("wonderland");
        let instructions = vec![root_approval];
        let hash = HashOf::new(&instructions);
        state.world.smart_contract_state_mut_for_testing().insert(
            multisig_proposal_state_key(&outer_account, &hash),
            encoded_multisig_proposal_state(&MultisigProposalState::new(
                outer_account.clone(),
                hash,
                instructions,
                1,
                10_000,
                BTreeSet::new(),
                None,
            )),
        );
        let approval = InstructionBox::from(MultisigApprove::new(outer_account, hash));
        let view = state.view();
        assert!(matches!(
            instruction_settlement_dataspace_target_with_stack(
                &*approval,
                None,
                Some(&view),
                &mut stack,
            ),
            Err(RoutingResolveError::OrdinaryRouteUnavailable { .. })
        ));
        assert!(stack.active.is_empty());
    }
    #[test]
    fn fx_escrow_operations_preserve_the_policy_destination_route() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let private_dataspace = DataSpaceId::new(7);
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let private_lane = LaneId::new(2);
        let destination_lane = LaneId::new(4);
        let dataspace_catalog = dataspace_catalog(&[
            (private_dataspace, "private"),
            (source_dataspace, "cbuae"),
            (destination_dataspace, "sbp"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (private_lane, private_dataspace),
            (LaneId::new(3), source_dataspace),
            (destination_lane, destination_dataspace),
        ]);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        );
        let (corridor, _) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "escrow_route",
        );
        let fund = FundFxCorridorEscrow {
            policy_id: corridor.policy_id.clone(),
            expected_policy_revision: corridor.revision,
            destination_asset_definition_id: corridor.destination_asset_definition_id.clone(),
            amount: 10_u32.into(),
        };
        let refund = RefundFxCorridorEscrow {
            policy_id: corridor.policy_id.clone(),
            expected_policy_revision: corridor.revision,
            destination_asset_definition_id: corridor.destination_asset_definition_id.clone(),
            amount: 10_u32.into(),
        };
        let operations = [
            InstructionBox::from(fund.clone()),
            InstructionBox::from(SettlementInstructionBox::FundFxCorridorEscrow(fund.clone())),
            InstructionBox::from(refund.clone()),
            InstructionBox::from(SettlementInstructionBox::RefundFxCorridorEscrow(refund)),
        ];
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        install_fx_corridor_policy(&state, corridor);
        let expected_single = RoutingPlan::single(RoutingDecision::new(
            destination_lane,
            destination_dataspace,
        ));
        for (index, operation) in operations.into_iter().enumerate() {
            let tx =
                sample_transaction(&authority, authority_keypair.private_key(), vec![operation]);
            assert_eq!(
                router
                    .try_route_plan_with_view(&tx, &state.view())
                    .unwrap_or_else(|error| panic!("escrow operation {index} failed: {error}")),
                expected_single,
            );
            assert_eq!(
                evaluate_policy_plan_with_catalog_and_world(
                    &default_routing_policy(),
                    &lane_catalog,
                    &dataspace_catalog,
                    &tx,
                    state.view().world(),
                )
                .unwrap_or_else(|error| {
                    panic!("world-backed escrow operation {index} failed: {error}")
                }),
                expected_single,
            );
        }

        let private_write = InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("merchant", "private").expect("private domain id"),
        )));
        let mixed_tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![private_write.clone(), InstructionBox::from(fund.clone())],
        );
        assert_eq!(
            router
                .try_route_plan_with_view(&mixed_tx, &state.view())
                .expect("mixed escrow plan should resolve"),
            RoutingPlan::native_amx(
                RoutingDecision::new(private_lane, private_dataspace),
                vec![
                    RouteLeg::new(
                        RoutingDecision::new(private_lane, private_dataspace),
                        RouteLegRole::Participant,
                    ),
                    RouteLeg::new(
                        RoutingDecision::new(destination_lane, destination_dataspace),
                        RouteLegRole::Participant,
                    ),
                ],
            ),
        );
        let mut strict_metadata = Metadata::default();
        strict_metadata.insert(
            AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
            iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
        );
        let strict_tx = sample_transaction_with_metadata(
            &authority,
            authority_keypair.private_key(),
            vec![private_write, InstructionBox::from(fund)],
            strict_metadata,
        );
        assert_eq!(
            router.try_route_plan_with_state(&strict_tx, &state),
            Err(
                RoutingResolveError::ConflictingTransactionDataspaceTargets {
                    first_dataspace_id: private_dataspace,
                    second_dataspace_id: destination_dataspace,
                }
            ),
        );
    }
    #[test]
    fn fx_corridor_non_deploy_first_match_does_not_add_rule_dataspaces() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let non_deploy_dataspace = DataSpaceId::new(14);
        let deploy_dataspace = DataSpaceId::new(16);
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let non_deploy_lane = LaneId::new(5);
        let deploy_lane = LaneId::new(6);
        let dataspace_catalog = dataspace_catalog(&[
            (source_dataspace, "cbuae"),
            (destination_dataspace, "sbp"),
            (non_deploy_dataspace, "domain_policy"),
            (deploy_dataspace, "deploy_policy"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (source_lane, source_dataspace),
            (destination_lane, destination_dataspace),
            (non_deploy_lane, non_deploy_dataspace),
            (deploy_lane, deploy_dataspace),
        ]);
        let routing_policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![
                LaneRoutingRule {
                    lane: non_deploy_lane,
                    dataspace: Some(non_deploy_dataspace),
                    matcher: LaneRoutingMatcher {
                        account: None,
                        instruction: Some("register::domain".to_owned()),
                        description: None,
                    },
                },
                LaneRoutingRule {
                    lane: deploy_lane,
                    dataspace: Some(deploy_dataspace),
                    matcher: LaneRoutingMatcher {
                        account: None,
                        instruction: Some("smartcontract::deploy".to_owned()),
                        description: None,
                    },
                },
            ],
        };
        let router = ConfigLaneRouter::new(routing_policy, dataspace_catalog, lane_catalog);
        let (corridor, settlement_instruction) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "fx_non_deploy_first_match",
        );
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(Register::domain(Domain::new(
                    DomainId::try_new("merchant", "universal").expect("universal domain"),
                ))),
                InstructionBox::from(RegisterSmartContractBytes {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        DataSpaceId::UNIVERSAL,
                        Hash::new(&code),
                    ),
                    code,
                }),
                settlement_instruction,
            ],
        );
        let world = crate::state::World::default();
        {
            let view = world.view();
            assert!(
                rule_matches_with_world(
                    &router.policy.rules[0],
                    &tx,
                    &router.dataspace_catalog,
                    &view,
                    Some(0),
                )
                .expect("completed fixture account routing")
            );
            assert!(
                rule_matches_with_world(
                    &router.policy.rules[1],
                    &tx,
                    &router.dataspace_catalog,
                    &view,
                    Some(0),
                )
                .expect("completed fixture account routing")
            );
        }
        let expected = expected_fx_plan(
            source_lane,
            source_dataspace,
            destination_lane,
            destination_dataspace,
        );
        let (queued_plan, block_plan) = fx_route_plan_results(&router, &tx, corridor, world);
        assert_eq!(queued_plan, Ok(expected.clone()));
        assert_eq!(block_plan, Ok(expected));
    }
    #[test]
    fn fx_corridor_universal_deploy_rule_does_not_add_policy_participant() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane: LaneId::SINGLE,
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![LaneRoutingRule {
                    lane: LaneId::SINGLE,
                    dataspace: Some(DataSpaceId::UNIVERSAL),
                    matcher: LaneRoutingMatcher {
                        account: None,
                        instruction: Some("smartcontract::deploy".to_owned()),
                        description: None,
                    },
                }],
            },
            dataspace_catalog(&[(source_dataspace, "cbuae"), (destination_dataspace, "sbp")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (source_lane, source_dataspace),
                (destination_lane, destination_dataspace),
            ]),
        );
        let (corridor, settlement_instruction) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "fx_universal_deploy_policy",
        );
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(RegisterSmartContractBytes {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        DataSpaceId::UNIVERSAL,
                        Hash::new(&code),
                    ),
                    code,
                }),
                settlement_instruction,
            ],
        );
        let expected = expected_fx_plan(
            source_lane,
            source_dataspace,
            destination_lane,
            destination_dataspace,
        );
        let (queued_plan, block_plan) =
            fx_route_plan_results(&router, &tx, corridor, crate::state::World::default());
        assert_eq!(queued_plan, Ok(expected.clone()));
        assert_eq!(block_plan, Ok(expected));
    }
    #[test]
    fn fx_corridor_deploy_policy_participant_is_deduplicated_from_intrinsic_participants() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane: LaneId::SINGLE,
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![LaneRoutingRule {
                    lane: source_lane,
                    dataspace: Some(source_dataspace),
                    matcher: LaneRoutingMatcher {
                        account: None,
                        instruction: Some("smartcontract::deploy".to_owned()),
                        description: None,
                    },
                }],
            },
            dataspace_catalog(&[(source_dataspace, "cbuae"), (destination_dataspace, "sbp")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (source_lane, source_dataspace),
                (destination_lane, destination_dataspace),
            ]),
        );
        let (corridor, settlement_instruction) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "fx_duplicate_deploy_policy",
        );
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(RegisterSmartContractBytes {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        source_dataspace,
                        Hash::new(&code),
                    ),
                    code,
                }),
                settlement_instruction,
            ],
        );
        let expected = expected_fx_plan(
            source_lane,
            source_dataspace,
            destination_lane,
            destination_dataspace,
        );
        let (queued_plan, block_plan) =
            fx_route_plan_results(&router, &tx, corridor, crate::state::World::default());
        assert_eq!(queued_plan, Ok(expected.clone()));
        assert_eq!(block_plan, Ok(expected));
    }
    #[test]
    fn fx_corridor_expired_sns_only_alias_is_excluded_with_queue_block_parity() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let expired_dataspace =
            crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic dataspace id");
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let router = ConfigLaneRouter::new(
            default_routing_policy(),
            dataspace_catalog(&[(source_dataspace, "cbuae"), (destination_dataspace, "sbp")]),
            catalog_with_lane_dataspaces(&[
                (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                (source_lane, source_dataspace),
                (destination_lane, destination_dataspace),
            ]),
        );
        let (corridor, settlement_instruction) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "fx_expired_sns",
        );
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(Register::domain(Domain::new(
                    DomainId::try_new("merchant", "alpha").expect("SNS-only domain"),
                ))),
                settlement_instruction,
            ],
        );
        let expected = expected_fx_plan(
            source_lane,
            source_dataspace,
            destination_lane,
            destination_dataspace,
        );
        let (queued_plan, block_plan) = fx_route_plan_results(
            &router,
            &tx,
            corridor,
            world_with_dynamic_dataspace_until("alpha", &authority, 0),
        );
        assert_eq!(queued_plan, Ok(expected.clone()));
        assert_eq!(block_plan, Ok(expected));
        assert!(
            !queued_plan
                .expect("queued plan should resolve")
                .legs()
                .iter()
                .any(|leg| leg.route.dataspace_id == expired_dataspace)
        );
    }
    #[test]
    fn fx_corridor_deploy_policy_without_canonical_lane_fails_closed_with_parity() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let deploy_dataspace = DataSpaceId::new(14);
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let deploy_lane = LaneId::new(5);
        let lane_catalog = lane_catalog_from_configs(vec![
            LaneConfig {
                id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "universal".to_owned(),
                ..LaneConfig::default()
            },
            LaneConfig {
                id: source_lane,
                dataspace_id: source_dataspace,
                alias: "source".to_owned(),
                ..LaneConfig::default()
            },
            LaneConfig {
                id: destination_lane,
                dataspace_id: destination_dataspace,
                alias: "destination".to_owned(),
                ..LaneConfig::default()
            },
            autoscale_elastic_lane_config(deploy_lane, deploy_dataspace, 0),
        ]);
        let router = ConfigLaneRouter::new(
            LaneRoutingPolicy {
                default_lane: LaneId::SINGLE,
                default_dataspace: DataSpaceId::UNIVERSAL,
                rules: vec![LaneRoutingRule {
                    lane: deploy_lane,
                    dataspace: Some(deploy_dataspace),
                    matcher: LaneRoutingMatcher {
                        account: None,
                        instruction: Some("smartcontract::deploy".to_owned()),
                        description: None,
                    },
                }],
            },
            dataspace_catalog(&[
                (source_dataspace, "cbuae"),
                (destination_dataspace, "sbp"),
                (deploy_dataspace, "deploy_policy"),
            ]),
            lane_catalog,
        );
        let (corridor, settlement_instruction) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "fx_missing_deploy_lane",
        );
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(RegisterSmartContractBytes {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        deploy_dataspace,
                        Hash::new(&code),
                    ),
                    code,
                }),
                settlement_instruction,
            ],
        );
        let state = blank_state();
        install_synthetic_router_nexus(&state, &router);
        install_fx_corridor_policy(&state, corridor);
        let view = state.view();
        let queued_plan = router.try_route_plan_with_view(&tx, &view);
        let block_plan = evaluate_policy_plan_with_nexus_and_world_at(
            view.nexus(),
            &tx,
            view.world(),
            state_view_ledger_time_ms(&view),
        );
        let expected_error = RoutingResolveError::NoLaneForDataspace {
            dataspace_id: deploy_dataspace,
        };
        assert_eq!(queued_plan, Err(expected_error.clone()));
        assert_eq!(block_plan, Err(expected_error));
    }
    #[test]
    fn fx_corridor_plan_includes_smart_contract_deploy_policy_participant() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let contract_dataspace = DataSpaceId::new(14);
        let deploy_policy_dataspace = DataSpaceId::new(16);
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let contract_lane = LaneId::new(5);
        let deploy_policy_lane = LaneId::new(6);
        let dataspace_catalog = dataspace_catalog(&[
            (source_dataspace, "cbuae"),
            (destination_dataspace, "sbp"),
            (contract_dataspace, "contracts"),
            (deploy_policy_dataspace, "private_deploy"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (source_lane, source_dataspace),
            (destination_lane, destination_dataspace),
            (contract_lane, contract_dataspace),
            (deploy_policy_lane, deploy_policy_dataspace),
        ]);
        let routing_policy = LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: deploy_policy_lane,
                dataspace: Some(deploy_policy_dataspace),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("smartcontract::deploy".to_owned()),
                    description: None,
                },
            }],
        };
        let router = ConfigLaneRouter::new(routing_policy, dataspace_catalog, lane_catalog);
        let (corridor, settlement_instruction) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "fx_deploy_policy",
        );
        let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &super::super::queue_test_network_id(),
            &authority,
            0,
            contract_dataspace,
        )
        .expect("contract address");
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(RegisterSmartContractBytes {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        contract_dataspace,
                        Hash::new(&code),
                    ),
                    code,
                }),
                InstructionBox::from(
                    iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
                        contract_address,
                        expected_revision: 1,
                        code_hash: Hash::new(b"contract-code"),
                    },
                ),
                settlement_instruction,
            ],
        );
        let mut state = blank_state();
        install_router_nexus(&mut state, &router);
        install_fx_corridor_policy(&state, corridor);
        let view = state.view();
        let expected = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![
                RouteLeg::new(
                    RoutingDecision::new(source_lane, source_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(destination_lane, destination_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(contract_lane, contract_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(deploy_policy_lane, deploy_policy_dataspace),
                    RouteLegRole::Participant,
                ),
            ],
        );
        assert_eq!(
            router
                .try_route_plan_with_view(&tx, &view)
                .expect("state-view FX deployment plan should resolve"),
            expected
        );
        assert_eq!(
            evaluate_policy_plan_with_nexus_and_world_at(
                view.nexus(),
                &tx,
                view.world(),
                state_view_ledger_time_ms(&view),
            )
            .expect("block-time FX deployment plan should resolve"),
            expected
        );
    }
    #[test]
    fn fx_corridor_state_view_plan_rejects_sns_dataspace_outside_catalog() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let dynamic_dataspace =
            crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic dataspace id");
        let source_lane = LaneId::new(3);
        let destination_lane = LaneId::new(4);
        let dataspace_catalog =
            dataspace_catalog(&[(source_dataspace, "cbuae"), (destination_dataspace, "sbp")]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (source_lane, source_dataspace),
            (destination_lane, destination_dataspace),
        ]);
        let routing_policy = default_routing_policy();
        let router = ConfigLaneRouter::new(routing_policy, dataspace_catalog, lane_catalog);
        let (corridor, settlement_instruction) = fx_corridor_fixture(
            source_dataspace,
            destination_dataspace,
            source_sink,
            destination_reserve,
            recipient,
            "fx_dynamic_sns",
        );
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(Register::domain(Domain::new(
                    DomainId::try_new("merchant", "alpha").expect("SNS-only domain"),
                ))),
                settlement_instruction,
            ],
        );
        let mut state = state_from_world(world_with_dynamic_dataspace("alpha", &authority));
        install_router_nexus(&mut state, &router);
        install_fx_corridor_policy(&state, corridor);
        let view = state.view();
        let queued_plan = router.try_route_plan_with_view(&tx, &view);
        let block_plan = evaluate_policy_plan_with_nexus_and_world_at(
            view.nexus(),
            &tx,
            view.world(),
            state_view_ledger_time_ms(&view),
        );
        // SNS identity alone cannot admit a physical participant absent from the catalog.
        let expected = RoutingResolveError::UnknownDataspace {
            dataspace_id: dynamic_dataspace,
        };
        assert_eq!(queued_plan, Err(expected.clone()));
        assert_eq!(block_plan, Err(expected));
    }
    #[test]
    fn fx_corridor_full_plan_routes_native_amx_from_governed_policy() {
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (source_sink, _) = gen_account_in("wonderland");
        let (_former_destination_reserve, _) = gen_account_in("wonderland");
        let (recipient, _) = gen_account_in("wonderland");
        let source_dataspace = DataSpaceId::new(10);
        let auxiliary_dataspace = DataSpaceId::new(11);
        let destination_dataspace = DataSpaceId::new(12);
        let source_lane = LaneId::new(3);
        let auxiliary_lane = LaneId::new(5);
        let destination_lane = LaneId::new(4);
        let dataspace_catalog = dataspace_catalog(&[
            (source_dataspace, "cbuae"),
            (auxiliary_dataspace, "sepa"),
            (destination_dataspace, "sbp"),
        ]);
        let lane_catalog = catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (source_lane, source_dataspace),
            (auxiliary_lane, auxiliary_dataspace),
            (destination_lane, destination_dataspace),
        ]);
        let routing_policy = default_routing_policy();
        let router = ConfigLaneRouter::new(
            routing_policy.clone(),
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        );
        let source_asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cbuae", "universal").expect("source asset domain"),
            "aed".parse().expect("source asset name"),
        );
        let destination_asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("sbp", "universal").expect("destination asset domain"),
            "pkr".parse().expect("destination asset name"),
        );
        let corridor = FxCorridorPolicy {
            policy_id: "mobile_aed_pkr".parse().expect("FX corridor policy id"),
            revision: 1,
            owner: source_sink.clone(),
            source_dataspace,
            source_asset_definition_id: source_asset_definition_id.clone(),
            destination_dataspace,
            destination_asset_definition_id: destination_asset_definition_id.clone(),
            allowed_destination_alias_domains: BTreeSet::from([
                DomainId::try_new("hbl", "sbp").expect("HBL alias domain"),
                DomainId::try_new("ubl", "sbp").expect("UBL alias domain"),
            ]),
            oracle_feed_id: "mobile_aed_pkr_rate".parse().expect("FX corridor feed id"),
            max_oracle_age_ms: 60_000,
            max_source_amount_per_settlement: 1_000_u32.into(),
            max_destination_amount_per_settlement: 100_000_u32.into(),
            velocity_window_ms: 60_000,
            max_settlements_per_window: 100,
            max_source_amount_per_window: 10_000_u32.into(),
            max_destination_amount_per_window: 1_000_000_u32.into(),
            enabled: true,
        };
        let request_hash = Hash::new(b"router-fx-full-plan-oracle-request");
        let oracle_event = FeedEvent {
            feed_id: corridor.oracle_feed_id.clone(),
            feed_config_version: FeedConfigVersion(1),
            slot: 1,
            request_hash,
            outcome: FeedEventOutcome::Success(FeedSuccess {
                value: ObservationValue::new(76, 0),
                entries: Vec::new(),
            }),
        };
        let settlement = SettleFxCorridor {
            policy_id: corridor.policy_id.clone(),
            expected_policy_revision: corridor.revision,
            source_asset_definition_id,
            destination_asset_definition_id,
            settlement_id: "mobile_fx_1".parse().expect("FX settlement id"),
            recipient,
            source_amount: iroha_primitives::numeric::Quantity::from(10_u32),
            expected_destination_amount: 760_u32.into(),
            oracle_evidence: FxCorridorOracleEvidence {
                feed_id: oracle_event.feed_id.clone(),
                feed_config_version: oracle_event.feed_config_version,
                slot: oracle_event.slot,
                request_hash: oracle_event.request_hash,
                event_hash: HashOf::new(&oracle_event),
            },
        };
        let settlement_instruction =
            InstructionBox::from(SettlementInstructionBox::SettleFxCorridor(settlement));
        let dvp_source_domain =
            DomainId::try_new("cash", "cbuae").expect("source DVP asset domain");
        let dvp_auxiliary_domain =
            DomainId::try_new("securities", "sepa").expect("auxiliary DVP asset domain");
        let dvp_source_definition = AssetDefinitionId::derive_from_components(
            dvp_source_domain.clone(),
            "aed".parse().expect("source DVP asset name"),
        );
        let dvp_auxiliary_definition = AssetDefinitionId::derive_from_components(
            dvp_auxiliary_domain.clone(),
            "bond".parse().expect("auxiliary DVP asset name"),
        );
        let bilateral_settlement = InstructionBox::from(DvpIsi::new(
            "mobile_dvp_1".parse().expect("DVP settlement id"),
            SettlementLeg::new(
                dvp_source_definition.clone(),
                1_u32,
                authority.clone(),
                source_sink.clone(),
            ),
            SettlementLeg::new(
                dvp_auxiliary_definition.clone(),
                1_u32,
                source_sink,
                authority.clone(),
            ),
            SettlementPlan::default(),
        ));
        let scoped_permission: Permission = CanPublishSpaceDirectoryManifest {
            dataspace: source_dataspace,
        }
        .into();
        let tx = sample_transaction(
            &authority,
            authority_keypair.private_key(),
            vec![
                InstructionBox::from(Grant::account_permission(
                    scoped_permission,
                    authority.clone(),
                )),
                bilateral_settlement,
                settlement_instruction.clone(),
            ],
        );
        let mut state = state_with_asset_definitions(
            vec![
                AssetDefinition::numeric(
                    dvp_source_definition,
                    "AED".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(dvp_source_domain),
                )
                .build(&authority),
                AssetDefinition::numeric(
                    dvp_auxiliary_definition,
                    "bond".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(dvp_auxiliary_domain),
                )
                .build(&authority),
            ],
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        );
        install_router_nexus(&mut state, &router);
        let mut registry = FxCorridorPolicyRegistry::default();
        registry.upsert(corridor);
        {
            let mut world = state.world.block();
            world.parameters.get_mut().set_parameter(
                iroha_data_model::parameter::Parameter::Custom(registry.into_custom_parameter()),
            );
            world.commit();
        }
        let expected = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![
                RouteLeg::new(
                    RoutingDecision::new(source_lane, source_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(auxiliary_lane, auxiliary_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(destination_lane, destination_dataspace),
                    RouteLegRole::Participant,
                ),
            ],
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("FX route state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_with_state(&tx, &state)
                .expect("universal FX coordinator route should resolve with state"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            router
                .try_route_plan_without_state(&tx)
                .expect("FX route state requirement should be deterministic"),
            None
        );
        assert_eq!(
            router
                .try_route_plan_with_state(&tx, &state)
                .expect("state-backed FX plan should resolve"),
            expected
        );
        let view = state.view();
        assert_eq!(
            router
                .try_route_plan_with_view(&tx, &view)
                .expect("state-view FX plan should resolve"),
            expected
        );
        assert_eq!(
            evaluate_policy_plan_with_catalog_and_world(
                &routing_policy,
                &lane_catalog,
                &dataspace_catalog,
                &tx,
                view.world(),
            )
            .expect("world-backed FX plan should resolve"),
            expected
        );
        let mut strict_metadata = Metadata::default();
        strict_metadata.insert(
            AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
            iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
        );
        let strict_tx = sample_transaction_with_metadata(
            &authority,
            authority_keypair.private_key(),
            vec![settlement_instruction],
            strict_metadata,
        );
        assert_eq!(
            router.try_route_plan_with_state(&strict_tx, &state),
            Err(
                RoutingResolveError::ConflictingTransactionDataspaceTargets {
                    first_dataspace_id: source_dataspace,
                    second_dataspace_id: destination_dataspace,
                }
            )
        );
    }
    #[test]
    fn asset_home_coverage_burn_global_binding_routes_to_universal() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (_dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let tx = sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Burn::asset_quantity(
                1_u32,
                AssetId::of(asset_definition.clone(), alice_id.clone()),
            ))],
        );
        let state = state_with_bound_numeric_asset_definition(
            &asset_definition,
            "pkr#paynet",
            "pkr",
            &alice_id,
            dataspace_catalog,
            lane_catalog,
        );
        assert_eq!(
            router
                .try_route_without_state(&tx)
                .expect("burn alias lookup should defer to state"),
            None
        );
        assert_eq!(
            router
                .try_route_with_view(&tx, &state.view())
                .expect("stored alias burn route must resolve with state"),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
        );
    }
    stored_alias_permission_route_test!(
        asset_home_coverage_modify_asset_metadata_permission_uses_stored_alias_dataspace,
        Grant,
        iroha_executor_data_model::permission::asset::CanModifyAssetMetadataWithDefinition,
        "asset metadata permission alias lookup should defer to state",
        "stored alias metadata permission route must resolve with state",
    );
    #[test]
    fn asset_home_extra_coverage_mint_permissions_use_stored_alias_dataspace() {
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, _) = gen_account_in("wonderland");
        let (dataspace_id, lane_id, dataspace_catalog, lane_catalog, router) =
            routed_dataspace_fixture("paynet");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
        let state = state_with_bound_numeric_asset_definition(
            &asset_definition,
            "pkr#paynet",
            "pkr",
            &alice_id,
            dataspace_catalog,
            lane_catalog,
        );
        let permissions = [
            Permission::from(CanMintAssetWithDefinition {
                asset_definition: asset_definition.clone(),
            }),
            Permission::from(CanMintAssetToAccount {
                asset_definition,
                account: bob_id.clone(),
            }),
        ];
        for permission in permissions {
            let tx = sample_transaction(
                &alice_id,
                alice_keypair.private_key(),
                vec![InstructionBox::from(Grant::account_permission(
                    permission,
                    bob_id.clone(),
                ))],
            );
            assert_eq!(
                router
                    .try_route_without_state(&tx)
                    .expect("mint permission alias lookup should defer to state"),
                None
            );
            assert_eq!(
                router
                    .try_route_with_view(&tx, &state.view())
                    .expect("stored alias mint permission route must resolve with state"),
                RoutingDecision::new(lane_id, dataspace_id)
            );
        }
    }
    stored_alias_permission_route_test!(
        asset_home_extra_coverage_burn_permission_uses_stored_alias_dataspace,
        Grant,
        iroha_executor_data_model::permission::asset::CanBurnAssetWithDefinition,
        "burn permission alias lookup should defer to state",
        "stored alias burn permission route must resolve with state",
    );
    stored_alias_permission_route_test!(
        asset_home_more_coverage_modify_definition_metadata_permission_uses_stored_alias_dataspace,
        Grant,
        iroha_executor_data_model::permission::asset_definition::CanModifyAssetDefinitionMetadata,
        "definition metadata permission alias lookup should defer to state",
        "stored alias definition metadata permission route must resolve",
    );
    stored_alias_permission_route_test!(
        asset_home_more_coverage_revoke_modify_definition_metadata_permission_uses_stored_alias,
        Revoke,
        iroha_executor_data_model::permission::asset_definition::CanModifyAssetDefinitionMetadata,
        "definition metadata revoke alias lookup should defer to state",
        "stored alias definition metadata revoke route must resolve",
    );
    include!("router_opaque_asset_scope_tests.rs");
    include!("router_cross_dataspace_plan_tests.rs"); // Preserve stable `queue::router::tests` paths.
    include!("router_multisig_scope_tests.rs");
    include!("router_resolved_asset_scope_tests.rs");
    include!("router_private_pool_routing_tests.rs");
    include!("router_confined_home_tests.rs");
}
