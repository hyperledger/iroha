//! Parliament-authorized retail fees and exact native conversion execution.
pub(crate) mod policy_history;
use crate::execution_attempt::ExecutionAttemptError;
use crate::{
    smartcontracts::isi::triggers::{
        set::{ExecutableRef, SetReadOnly as _},
        specialized::LoadedActionTrait as _,
        trigger_is_enabled,
    },
    state::{StateReadOnly, StateTransaction, WorldReadOnly, validate_network_xor_asset},
    tx::TransactionRejectionReason,
};
use iroha_data_model::{
    ValidationFail,
    governance::types::ProposalKind,
    isi::{InstructionBox, TransferBox},
    prelude::*,
    transaction::SignedTransaction,
    validation_fee::{
        ValidationFeeParliamentAuthorizationV1, ValidationFeePolicyRegistryEntryV1,
        ValidationFeePolicyRegistryV1, ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1,
    },
};
use iroha_model_base::{name::Name, state_path::StatePath};
use iroha_primitives::numeric::{Numeric, Quantity};
use ivm::state_value::{
    StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1, StateValueSchemaV1,
    state_value_schema_hash_v1,
};
use mv::storage::StorageReadOnly;
pub(crate) const VALIDATION_FEE_POOL_SWAP_ENTRYPOINT: &str = "swap_exact_in_quote_public";
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
/// Deterministic protected fee-policy rejection retained until the caller boundary.
pub(crate) enum ValidationFeeAdmissionError {
    #[error("malformed protected policy registry")]
    MalformedPolicyRegistryParameter,
    #[error("invalid protected policy registry: {0}")]
    InvalidPolicyRegistry(String),
    #[error("invalid fee policy: {0}")]
    InvalidPolicyInvariant(&'static str),
    #[error("fee policy network mismatch: expected {expected}, found {found}")]
    WrongPolicyNetwork { expected: String, found: String },
    #[error("fee treasury {treasury_account_id} must be the active contract subject")]
    TreasuryPayoutRequiresActiveContractSubject { treasury_account_id: String },
    #[error("invalid conversion lifecycle seal")]
    InvalidPayoutLifecycleSeal,
    #[error("conversion runtime binding differs: {reason}")]
    TreasuryPayoutRuntimeBindingMismatch { reason: &'static str },
    #[error("conversion effect plan differs: {reason}")]
    TreasuryPayoutEffectPlanMismatch { reason: &'static str },
    #[error("conversion arithmetic is outside exact asset units")]
    TreasuryPayoutArithmeticFailure,
    #[error("unrepresented proof-carrying AXT effects ({completed_envelopes}) cannot bypass fees")]
    OpaqueIvmProvedAxtEffects { completed_envelopes: usize },
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationFeePayoutTerms {
    debit_ds: Quantity,
    min_xor_out: Quantity,
    xor_scale: u32,
}

pub(crate) struct OpaqueDeferredRuntimeOrigin<'a> {
    runtime_context: &'a crate::executor::ContractRuntimeExecutionContext,
    code_bytes: &'a [u8],
    trigger_id: Option<&'a iroha_data_model::trigger::TriggerId>,
    scheduled_time_trigger: bool,
}
/// Whether validated opaque effects should be atomically applied or discarded
/// as the bound payout's legitimate empty/insufficient-credit no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpaqueDeferredValidationOutcome {
    Apply,
    NoOp,
}
impl<'a> OpaqueDeferredRuntimeOrigin<'a> {
    pub(crate) fn new(
        runtime_context: &'a crate::executor::ContractRuntimeExecutionContext,
        code_bytes: &'a [u8],
    ) -> Self {
        Self {
            runtime_context,
            code_bytes,
            trigger_id: None,
            scheduled_time_trigger: false,
        }
    }
    /// Bind opaque execution to a trigger event, admitting the payout exemption
    /// only when consensus invoked the contract from a scheduled Time trigger.
    pub(crate) fn from_trigger_event(
        runtime_context: &'a crate::executor::ContractRuntimeExecutionContext,
        code_bytes: &'a [u8],
        event: &iroha_data_model::events::EventBox,
        trigger_id: &'a iroha_data_model::trigger::TriggerId,
    ) -> Self {
        Self {
            runtime_context,
            code_bytes,
            trigger_id: Some(trigger_id),
            scheduled_time_trigger: matches!(event, iroha_data_model::events::EventBox::Time(_)),
        }
    }
}

struct ResolvedPayoutLifecycle {
    binding: ValidationFeeTreasuryPayoutBindingV1,
    ds_scale: u8,
}

fn retained_enacted_validation_fee_proposals<'a>(
    state_transaction: &'a StateTransaction<'_, '_>,
) -> impl Iterator<Item = ([u8; 32], &'a ProposalKind)> + 'a {
    let world = &state_transaction.world;
    world
        .validation_fee_proposal_index
        .iter()
        .filter_map(move |((_, proposal_id), ())| {
            let proposal = world.governance_proposals.get(proposal_id)?;
            (proposal.status == crate::state::GovernanceProposalStatus::Enacted)
                .then_some((*proposal_id, &proposal.kind))
        })
}

pub(crate) fn retained_enacted_validation_fee_account_reference(
    state_transaction: &StateTransaction<'_, '_>,
    account_id: &AccountId,
) -> Option<([u8; 32], &'static str)> {
    retained_enacted_validation_fee_proposals(state_transaction).find_map(
        |(proposal_id, proposal_kind)| {
            let payout_reference = |binding: &iroha_data_model::validation_fee::ValidationFeeTreasuryPayoutBindingV1| {
                if &binding.treasury_account_id == account_id {
                    Some("payout treasury")
                } else if &binding.pool_vault_account_id == account_id {
                    Some("payout pool vault")
                } else if &binding.reward_pool_account_id == account_id {
                    Some("validator reward custody")
                } else if binding.reference_provider_accounts.contains(account_id) {
                    Some("reference provider")
                } else {
                    None
                }
            };
            let reference_kind = match proposal_kind {
                ProposalKind::ValidationFeePolicy(payload) => {
                    if &payload.policy.treasury_account_id == account_id {
                        Some("policy treasury")
                    } else {
                        (&payload.policy.reward_custody.reward_pool_account_id == account_id)
                            .then_some("validator reward custody")
                    }
                }
                ProposalKind::ValidationFeePayoutLifecycle(payload) => {
                    payout_reference(&payload.payout_binding)
                }
                _ => None,
            }?;
            Some((proposal_id, reference_kind))
        },
    )
}

fn retained_enacted_validation_fee_asset_reference_matching(
    state_transaction: &StateTransaction<'_, '_>,
    mut matches: impl FnMut(&AssetDefinitionId) -> bool,
) -> Option<([u8; 32], &'static str, AssetDefinitionId)> {
    retained_enacted_validation_fee_proposals(state_transaction).find_map(
        |(proposal_id, proposal_kind)| {
            let matched = match proposal_kind {
                ProposalKind::ValidationFeePolicy(payload) => {
                    if matches(&payload.policy.ds_asset_id) {
                        Some((
                            "policy DS asset definition",
                            payload.policy.ds_asset_id.clone(),
                        ))
                    } else if matches(&payload.policy.reward_custody.xor_asset_id) {
                        Some((
                            "payout XOR asset definition",
                            payload.policy.reward_custody.xor_asset_id.clone(),
                        ))
                    } else {
                        None
                    }
                }
                ProposalKind::ValidationFeePayoutLifecycle(payload) => {
                    let binding = &payload.payout_binding;
                    if matches(&binding.ds_asset_id) {
                        Some(("payout DS asset definition", binding.ds_asset_id.clone()))
                    } else if matches(&binding.xor_asset_id) {
                        Some(("payout XOR asset definition", binding.xor_asset_id.clone()))
                    } else {
                        None
                    }
                }
                _ => None,
            }?;
            Some((proposal_id, matched.0, matched.1))
        },
    )
}

pub(crate) fn retained_enacted_validation_fee_asset_reference(
    state_transaction: &StateTransaction<'_, '_>,
    asset_definition_id: &AssetDefinitionId,
) -> Option<([u8; 32], &'static str)> {
    retained_enacted_validation_fee_asset_reference_matching(state_transaction, |candidate| {
        candidate == asset_definition_id
    })
    .map(|(proposal_id, reference_kind, _)| (proposal_id, reference_kind))
}

pub(crate) fn retained_enacted_validation_fee_asset_reference_in(
    state_transaction: &StateTransaction<'_, '_>,
    candidates: &std::collections::BTreeSet<AssetDefinitionId>,
) -> Option<([u8; 32], &'static str, AssetDefinitionId)> {
    retained_enacted_validation_fee_asset_reference_matching(state_transaction, |candidate| {
        candidates.contains(candidate)
    })
}

fn enacted_payout_binding_for_contract<'a>(
    state_transaction: &'a StateTransaction<'_, '_>,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
) -> Option<&'a ValidationFeeTreasuryPayoutBindingV1> {
    state_transaction
        .world
        .governance_proposals
        .iter()
        .filter(|(_, proposal)| proposal.status == crate::state::GovernanceProposalStatus::Enacted)
        .find_map(|(_, proposal)| {
            let iroha_data_model::governance::types::ProposalKind::ValidationFeePayoutLifecycle(
                lifecycle,
            ) = &proposal.kind
            else {
                return None;
            };
            (&lifecycle.payout_binding.contract_address == contract_address
                || &lifecycle.payout_binding.pool_contract_address == contract_address)
                .then_some(&lifecycle.payout_binding)
        })
}

pub(crate) fn is_enacted_validation_fee_payout_contract(
    state_transaction: &StateTransaction<'_, '_>,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
) -> bool {
    enacted_payout_binding_for_contract(state_transaction, contract_address).is_some()
}

pub(crate) fn is_enacted_validation_fee_payout_trigger(
    state_transaction: &StateTransaction<'_, '_>,
    trigger_id: &iroha_data_model::trigger::TriggerId,
) -> bool {
    let Some(action) = state_transaction
        .world
        .triggers
        .time_triggers()
        .get(trigger_id)
    else {
        return false;
    };
    let ExecutableRef::ContractCall(invocation) = action.executable() else {
        return false;
    };
    let Some(binding) =
        enacted_payout_binding_for_contract(state_transaction, &invocation.contract_address)
    else {
        return false;
    };
    action.authority() == &binding.treasury_account_id
        && invocation.entrypoint == binding.entrypoint.as_ref()
        && trigger_is_enabled(action.metadata())
}

pub(crate) fn is_enacted_validation_fee_payout_invocation(
    state_transaction: &StateTransaction<'_, '_>,
    invocation: &iroha_data_model::transaction::executable::ContractInvocation,
) -> bool {
    let Some(binding) =
        enacted_payout_binding_for_contract(state_transaction, &invocation.contract_address)
    else {
        return false;
    };
    let Some(active_code_hash) = state_transaction
        .world
        .contract_instances
        .get(&invocation.contract_address)
        .copied()
    else {
        return false;
    };
    invocation.expected_code_hash == active_code_hash
        && invocation.entrypoint == binding.entrypoint.as_ref()
        && invocation.arguments.is_none()
}

fn trigger_id_from_permission(
    state_transaction: &StateTransaction<'_, '_>,
    permission: &iroha_data_model::permission::Permission,
) -> Result<
    Option<iroha_data_model::trigger::TriggerId>,
    iroha_data_model::isi::error::InstructionExecutionError,
> {
    use iroha_executor_data_model::permission::{
        Permission as _,
        trigger::{
            CanExecuteTrigger, CanModifyTrigger, CanModifyTriggerMetadata, CanUnregisterTrigger,
        },
    };
    if permission.name() == CanUnregisterTrigger::name() {
        return decode_payout_runtime_permission(state_transaction, permission)
            .map(|token: CanUnregisterTrigger| Some(token.trigger));
    }
    if permission.name() == CanModifyTrigger::name() {
        return decode_payout_runtime_permission(state_transaction, permission)
            .map(|token: CanModifyTrigger| Some(token.trigger));
    }
    if permission.name() == CanExecuteTrigger::name() {
        return decode_payout_runtime_permission(state_transaction, permission)
            .map(|token: CanExecuteTrigger| Some(token.trigger));
    }
    if permission.name() == CanModifyTriggerMetadata::name() {
        return decode_payout_runtime_permission(state_transaction, permission)
            .map(|token: CanModifyTriggerMetadata| Some(token.trigger));
    }
    Ok(None)
}

pub(crate) fn permission_targets_enacted_validation_fee_payout_trigger(
    state_transaction: &StateTransaction<'_, '_>,
    permission: &iroha_data_model::permission::Permission,
) -> Result<bool, iroha_data_model::isi::error::InstructionExecutionError> {
    let trigger_id = match trigger_id_from_permission(state_transaction, permission) {
        Ok(trigger_id) => trigger_id,
        Err(_) if cfg!(all(test, sumeragi_core_mutation = "HC97")) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(trigger_id.is_some_and(|trigger_id| {
        is_enacted_validation_fee_payout_trigger(state_transaction, &trigger_id)
    }))
}

/// Resolve a dedicated instance permission without broadening a payout selector grant.
/// A grouped role, shared chain marker, open policy or lifecycle policy cannot protect a payout.
pub(crate) fn dedicated_payout_permission(
    manifest: &iroha_data_model::smart_contract::manifest::ContractManifest,
    selector: &str,
) -> Option<Name> {
    use iroha_data_model::smart_contract::manifest::{
        ContractPermissionScopeV1, EntryPointKind, EntrypointAuthorizationV1,
    };
    let entries = manifest.entrypoints.as_ref()?;
    let mut selected = entries.iter().filter(|entry| entry.name == selector);
    let entry = selected.next()?;
    if selected.next().is_some() || entry.kind != EntryPointKind::Kotoage {
        return None;
    }
    let EntrypointAuthorizationV1::Permission(name) = &entry.authorization else {
        return None;
    };
    let mut declarations = manifest
        .permissions
        .iter()
        .filter(|role| role.name == *name);
    let declaration = declarations.next()?;
    if declarations.next().is_some()
        || !matches!(declaration.scope, ContractPermissionScopeV1::Instance)
        || entries
            .iter()
            .filter(|candidate| candidate.authorization == entry.authorization)
            .count()
            != 1
    {
        return None;
    }
    Some(name.clone())
}

/// Recover the exact role from the immutable artifact named by a payout policy.
/// Historical policies use their original manifest when their derived grants are revoked.
pub(crate) fn payout_contract_permission(
    state_transaction: &StateTransaction<'_, '_>,
    address: &iroha_data_model::smart_contract::ContractAddress,
    code_hash: &[u8; 32],
    selector: &str,
) -> Result<
    iroha_data_model::permission::Permission,
    iroha_data_model::isi::error::InstructionExecutionError,
> {
    use iroha_data_model::isi::error::InstructionExecutionError;
    let invalid = || {
        InstructionExecutionError::InvariantViolation(
        "validation-fee payout requires a declared instance permission dedicated to its selector".into(),
    )
    };
    let artifact = iroha_data_model::smart_contract::ContractArtifactId::for_address(
        address,
        iroha_crypto::Hash::prehashed(*code_hash),
    )
    .map_err(|_| invalid())?;
    let manifest = crate::smartcontracts::code::fetch_manifest(state_transaction, &artifact)
        .map_err(|error| {
            state_transaction
                .world
                .attempt_error_to_instruction_error(error.map_rejection(|error| {
                    InstructionExecutionError::InvariantViolation(error.to_string().into())
                }))
        })?
        .ok_or_else(invalid)?;
    let permission = dedicated_payout_permission(&manifest, selector).ok_or_else(invalid)?;
    Ok(
        iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
            contract: address.clone(),
            permission,
        }
        .into(),
    )
}

pub(crate) fn enacted_validation_fee_payout_runtime_permission_owner(
    state_transaction: &StateTransaction<'_, '_>,
    permission: &iroha_data_model::permission::Permission,
) -> Result<Option<AccountId>, iroha_data_model::isi::error::InstructionExecutionError> {
    use iroha_executor_data_model::permission::{
        Permission as _, asset::CanTransferAsset, smart_contract::CanUseContractPermission,
    };
    if permission.name() == CanUseContractPermission::name() {
        let scoped: CanUseContractPermission =
            decode_payout_runtime_permission(state_transaction, permission)?;
        // Enacted payout artifacts remain immutable historical authorities. Their dedicated
        // role identities stay reserved after policy replacement, even after the old grants
        // are revoked; a later ordinary grant must not revive a retired autonomous payout.
        for (_, proposal) in state_transaction.world.governance_proposals.iter() {
            if proposal.status != crate::state::GovernanceProposalStatus::Enacted {
                continue;
            }
            let ProposalKind::ValidationFeePayoutLifecycle(lifecycle) = &proposal.kind else {
                continue;
            };
            let binding = &lifecycle.payout_binding;
            let selected = if scoped.contract == binding.contract_address {
                Some((
                    &binding.contract_address,
                    &binding.code_hash,
                    binding.entrypoint.as_ref(),
                ))
            } else if scoped.contract == binding.pool_contract_address {
                Some((
                    &binding.pool_contract_address,
                    &binding.pool_code_hash,
                    VALIDATION_FEE_POOL_SWAP_ENTRYPOINT,
                ))
            } else {
                None
            };
            if let Some((address, code_hash, selector)) = selected {
                let expected =
                    payout_contract_permission(state_transaction, address, code_hash, selector)?;
                if expected == *permission {
                    return Ok(Some(binding.treasury_account_id.clone()));
                }
            }
        }
        return Ok(None);
    }
    if permission.name() != CanTransferAsset::name() {
        return Ok(None);
    }
    let transfer: CanTransferAsset =
        decode_payout_runtime_permission(state_transaction, permission)?;
    // Enactment atomically replaces derived permissions. Its new head owns this
    // permission immediately, even though conversion eligibility begins next block.
    // Historical proposal iteration cannot select a retired pool as the holder.
    let registry = match validated_policy_registry_in_world(&state_transaction.world) {
        Ok(Some(registry)) => registry,
        Ok(None) => return Ok(None),
        Err(error) => {
            if cfg!(all(test, sumeragi_core_mutation = "HC96")) {
                return Ok(None);
            }
            return Err(state_transaction.world.attempt_error_to_instruction_error(
                error.map_rejection(|error| {
                    iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                        format!("validation-fee permission guard rejected registry: {error}")
                            .into(),
                    )
                }),
            ));
        }
    };
    let Some(head) = registry.payout_policies.head() else {
        return Ok(None);
    };
    let binding = &head.payout_binding;
    let wrapper_ds_asset = AssetId::new(
        binding.ds_asset_id.clone(),
        binding.treasury_account_id.clone(),
    );
    Ok((transfer.asset == wrapper_ds_asset).then(|| binding.pool_vault_account_id.clone()))
}

/// Decode only a recognized runtime permission, retaining its original local refusal.
fn decode_payout_runtime_permission<P: norito::json::JsonDeserialize>(
    state_transaction: &StateTransaction<'_, '_>,
    permission: &iroha_data_model::permission::Permission,
) -> Result<P, iroha_data_model::isi::error::InstructionExecutionError> {
    norito::json::from_str(permission.payload().get()).map_err(|error| {
        state_transaction.world.attempt_error_to_instruction_error(
            crate::execution_attempt::json_decode_attempt_error(error, |error| {
                iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                    format!(
                        "validation-fee payout runtime permission {} is malformed: {error}",
                        permission.name()
                    )
                    .into(),
                )
            }),
        )
    })
}

pub(crate) fn enforce_validation_fee_admission(
    tx: &SignedTransaction,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), ExecutionAttemptError<TransactionRejectionReason>> {
    // Always validate the protected Parliament registry; the single release model collects
    // the reviewed native charge after actual successful payment execution.
    let _ = active_policy(state_transaction)?;
    crate::retail_fee::admit(tx, state_transaction)?;
    Ok(())
}

pub(crate) fn enforce_ivm_proved_completed_axt_admission(
    completed_envelopes: usize,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), ValidationFail> {
    if completed_envelopes == 0 {
        return Ok(());
    }
    let policy = active_policy(state_transaction).map_err(|error| match error {
        ExecutionAttemptError::Rejected(TransactionRejectionReason::Validation(fail)) => fail,
        ExecutionAttemptError::Rejected(other) => ValidationFail::NotPermitted(format!(
            "validation-fee policy resolution failed during IvmProved AXT admission: {other:?}"
        )),
        ExecutionAttemptError::Deferred(reason) => state_transaction.world.defer_execution(reason),
    })?;
    if policy.is_none() {
        return Ok(());
    }
    let error = reject_ivm_proved_completed_axt_effects(completed_envelopes)
        .expect_err("non-zero completed AXT count must fail closed under active policy");
    let rejection = admission_rejection(error);
    match rejection {
        TransactionRejectionReason::Validation(fail) => Err(fail),
        _ => unreachable!("validation-fee admission rejection must be a validation failure"),
    }
}

fn reject_ivm_proved_completed_axt_effects(
    completed_envelopes: usize,
) -> Result<(), ValidationFeeAdmissionError> {
    if completed_envelopes == 0 {
        return Ok(());
    }
    Err(ValidationFeeAdmissionError::OpaqueIvmProvedAxtEffects {
        completed_envelopes,
    })
}

pub(crate) fn enforce_deferred_instruction_list(
    _authority: &AccountId,
    instructions: &[InstructionBox],
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), TransactionRejectionReason> {
    let _ = active_policy(state_transaction)
        .map_err(|error| transaction_attempt_rejection(state_transaction, error))?;
    crate::retail_fee::admit_deferred(instructions, state_transaction)
}

fn validation_fee_payout_xor_scale(
    state_transaction: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<u32, ExecutionAttemptError<ValidationFeeAdmissionError>> {
    validate_network_xor_asset(&state_transaction.world, &binding.xor_asset_id).map_err(
        |error| {
            error.map_rejection(|error| {
                ValidationFeeAdmissionError::InvalidPolicyRegistry(error.to_string())
            })
        },
    )?;
    Ok(9)
}

fn quantity_to_minor_units_u128(
    amount: &Quantity,
    asset_scale: u32,
) -> Result<u128, ValidationFeeAdmissionError> {
    let amount_scale = amount.scale();
    if amount_scale > asset_scale {
        return Err(ValidationFeeAdmissionError::TreasuryPayoutArithmeticFailure);
    }
    let mantissa = amount
        .as_numeric()
        .try_mantissa_u128()
        .ok_or(ValidationFeeAdmissionError::TreasuryPayoutArithmeticFailure)?;
    mantissa
        .checked_mul(
            10_u128
                .checked_pow(asset_scale - amount_scale)
                .ok_or(ValidationFeeAdmissionError::TreasuryPayoutArithmeticFailure)?,
        )
        .ok_or(ValidationFeeAdmissionError::TreasuryPayoutArithmeticFailure)
}

fn quantity_from_minor_units_u128(
    minor_units: u128,
    asset_scale: u32,
) -> Result<Quantity, ValidationFeeAdmissionError> {
    let numeric = Numeric::try_new(minor_units, asset_scale)
        .map_err(|_| ValidationFeeAdmissionError::TreasuryPayoutArithmeticFailure)?;
    Quantity::from_canonical_numeric(numeric)
        .map_err(|_| ValidationFeeAdmissionError::TreasuryPayoutArithmeticFailure)
}

fn transaction_attempt_rejection(
    state: &mut StateTransaction<'_, '_>,
    error: ExecutionAttemptError<TransactionRejectionReason>,
) -> TransactionRejectionReason {
    match error {
        ExecutionAttemptError::Rejected(error) => error,
        ExecutionAttemptError::Deferred(reason) => {
            TransactionRejectionReason::Validation(state.defer_execution(reason))
        }
    }
}

fn fee_attempt_rejection(
    state: &mut StateTransaction<'_, '_>,
    error: ExecutionAttemptError<ValidationFeeAdmissionError>,
) -> TransactionRejectionReason {
    transaction_attempt_rejection(state, error.map_rejection(admission_rejection))
}

pub(crate) fn active_policy(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<Option<ValidationFeePolicyV1>, ExecutionAttemptError<TransactionRejectionReason>> {
    let registry = validated_policy_registry(state_transaction)?;
    active_policy_from_validated_registry(registry.as_ref(), state_transaction)
}

/// Select the independently finalized conversion policy at an exact ledger height.
/// Customer pricing calendars do not delay conversion-policy enactments.
pub(crate) fn active_payout_binding_at_height(
    state_transaction: &StateTransaction<'_, '_>,
    height: u64,
) -> Result<
    Option<ValidationFeeTreasuryPayoutBindingV1>,
    ExecutionAttemptError<ValidationFeeAdmissionError>,
> {
    active_payout_binding_in_world_at_height(&state_transaction.world, height)
}

/// Read the same authenticated payout lifecycle for execution and signing preparation.
pub(crate) fn active_payout_binding_in_world_at_height(
    world: &impl WorldReadOnly,
    height: u64,
) -> Result<
    Option<ValidationFeeTreasuryPayoutBindingV1>,
    ExecutionAttemptError<ValidationFeeAdmissionError>,
> {
    Ok(
        validated_policy_registry_in_world(world)?.and_then(|registry| {
            registry
                .payout_policies
                .effective_entry_at_height(height)
                .map(|entry| entry.payout_binding.clone())
        }),
    )
}

/// Return the authenticated immutable custody coordinates retained by every lifecycle revision.
pub(crate) fn retained_payout_custody_binding(
    world: &impl WorldReadOnly,
) -> Result<Option<ValidationFeeTreasuryPayoutBindingV1>, ExecutionAttemptError<String>> {
    Ok(validated_policy_registry_in_world(world)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?
        .and_then(|registry| {
            registry
                .payout_policies
                .head()
                .map(|entry| entry.payout_binding.clone())
        }))
}

fn validated_policy_registry(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<Option<ValidationFeePolicyRegistryV1>, ExecutionAttemptError<TransactionRejectionReason>>
{
    validated_policy_registry_in_world(&state_transaction.world)
        .map_err(|error| error.map_rejection(admission_rejection))
}

fn validated_policy_registry_in_world<W: WorldReadOnly + ?Sized>(
    world: &W,
) -> Result<Option<ValidationFeePolicyRegistryV1>, ExecutionAttemptError<ValidationFeeAdmissionError>>
{
    let parameter_id = ValidationFeePolicyRegistryV1::parameter_id();
    let Some(custom) = world.parameters().custom().get(&parameter_id) else {
        return Ok(None);
    };
    if custom.id() != &parameter_id {
        return Err(ValidationFeeAdmissionError::MalformedPolicyRegistryParameter.into());
    }
    let registry: ValidationFeePolicyRegistryV1 = norito::core::classify_decode_attempt(|| {
        norito::json::from_str(custom.payload().get()).map_err(norito::json::Error::into_core_error)
    })
    .map_err(|error| {
        #[cfg(all(test, sumeragi_core_mutation = "HC30"))]
        {
            let _ = error;
            ExecutionAttemptError::Rejected(
                ValidationFeeAdmissionError::MalformedPolicyRegistryParameter,
            )
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC30")))]
        crate::execution_attempt::canonical_decode_attempt_error(error, |_| {
            ValidationFeeAdmissionError::MalformedPolicyRegistryParameter
        })
    })?;
    registry
        .validate()
        .map_err(|err| ValidationFeeAdmissionError::InvalidPolicyRegistry(err.to_string()))?;
    for entry in &registry.registered_policies {
        validate_registry_entry_governance(entry, world)?;
    }
    for entry in &registry.payout_policies.entries {
        validate_network_xor_asset(world, &entry.payout_binding.xor_asset_id).map_err(|error| {
            error.map_rejection(|error| {
                ValidationFeeAdmissionError::InvalidPolicyRegistry(error.to_string())
            })
        })?;
        let exact_kind = ProposalKind::ValidationFeePayoutLifecycle(
            iroha_data_model::governance::types::ValidationFeePayoutLifecycleProposal {
                proposal_operator: entry.parliament_authorization.proposal_operator.clone(),
                payout_binding: entry.payout_binding.clone(),
            },
        );
        validate_parliament_authorization(&entry.parliament_authorization, &exact_kind, world)?;
    }
    Ok(Some(registry))
}
pub(crate) fn validate_persisted_policy_registry_governance_v1<W: WorldReadOnly + ?Sized>(
    world: &W,
) -> Result<(), ExecutionAttemptError<String>> {
    validated_policy_registry_in_world(world)
        .map(drop)
        .map_err(|error| error.map_rejection(|error| error.to_string()))
}

pub(crate) fn validate_persisted_policy_registry_runtime_v1(
    state: &impl StateReadOnly,
    restored_height: u64,
) -> Result<(), ExecutionAttemptError<String>> {
    let Some(registry) = validated_policy_registry_in_world(state.world())
        .map_err(|error| error.map_rejection(|error| error.to_string()))?
    else {
        return Ok(());
    };
    policy_history::validate_retained_history(state, &registry, restored_height)?;
    for entry in &registry.registered_policies {
        validate_policy_network_id(&entry.policy, state.network_id())
            .map_err(|error| error.to_string())?;
    }
    if registry
        .scheduled_entry_at_height(restored_height)
        .is_none()
    {
        return Ok(());
    }
    let restored_timestamp_ms = state
        .latest_block()
        .map_err(|error| error.map_rejection(|error| error.to_string()))?
        .ok_or_else(|| {
            "active fee policy restoration requires its retained block timestamp".to_owned()
        })?
        .header()
        .creation_time()
        .as_millis();
    let restored_timestamp_ms = u64::try_from(restored_timestamp_ms)
        .map_err(|_| "restored block timestamp overflow".to_owned())?;
    let Some(entry) = registry.effective_entry_at(restored_height, restored_timestamp_ms) else {
        return Ok(());
    };
    validate_treasury_payout_contract_subject(&entry.policy, state)
        .map_err(|error| error.map_rejection(|error| error.to_string()))
}

fn active_policy_from_validated_registry(
    registry: Option<&ValidationFeePolicyRegistryV1>,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<Option<ValidationFeePolicyV1>, ExecutionAttemptError<TransactionRejectionReason>> {
    let Some(registry) = registry else {
        return Ok(None);
    };
    let current_height = state_transaction.block_height();
    let Some(entry) =
        registry.effective_entry_at(current_height, state_transaction.block_unix_timestamp_ms())
    else {
        // The initial Parliament policy is deliberately enacted well before
        // activation so downstreams can pin its finalized proof. Until that
        // calendar activation boundary arrives there is no active validation fee.
        return Ok(None);
    };
    let policy = entry.policy.clone();
    if let Some(reason) = policy.policy_invariant_error() {
        return Err(
            (admission_rejection(ValidationFeeAdmissionError::InvalidPolicyInvariant(reason)))
                .into(),
        );
    }
    validate_policy_network_id(&policy, &state_transaction.network_id)
        .map_err(admission_rejection)?;
    validate_treasury_payout_contract_subject(&policy, state_transaction)
        .map_err(|error| error.map_rejection(admission_rejection))?;
    Ok(Some(policy))
}

fn validate_registry_entry_governance<W: WorldReadOnly + ?Sized>(
    entry: &ValidationFeePolicyRegistryEntryV1,
    world: &W,
) -> Result<(), ValidationFeeAdmissionError> {
    let policy_kind = ProposalKind::ValidationFeePolicy(
        iroha_data_model::governance::types::ValidationFeePolicyProposal {
            proposal_operator: entry.parliament_authorization.proposal_operator.clone(),
            policy: entry.policy.clone(),
        },
    );
    validate_parliament_authorization(&entry.parliament_authorization, &policy_kind, world)
}
fn validate_parliament_authorization<W: WorldReadOnly + ?Sized>(
    authorization: &ValidationFeeParliamentAuthorizationV1,
    exact_kind: &iroha_data_model::governance::types::ProposalKind,
    world: &W,
) -> Result<(), ValidationFeeAdmissionError> {
    if let Some(reason) = authorization.invariant_error() {
        return Err(ValidationFeeAdmissionError::InvalidPolicyRegistry(
            reason.to_owned(),
        ));
    }
    let fingerprint = exact_kind.fingerprint();
    if fingerprint != authorization.proposal_fingerprint {
        return Err(ValidationFeeAdmissionError::InvalidPolicyRegistry(
            "stored proposal fingerprint does not match the exact typed proposal preimage"
                .to_owned(),
        ));
    }
    let exact_operator = match exact_kind {
        iroha_data_model::governance::types::ProposalKind::ValidationFeePolicy(payload) => {
            &payload.proposal_operator
        }
        iroha_data_model::governance::types::ProposalKind::ValidationFeePayoutLifecycle(
            payload,
        ) => &payload.proposal_operator,
        _ => {
            return Err(ValidationFeeAdmissionError::InvalidPolicyRegistry(
                "validation-fee authorization received a non-validation-fee proposal".to_owned(),
            ));
        }
    };
    if exact_operator != &authorization.proposal_operator {
        return Err(ValidationFeeAdmissionError::InvalidPolicyRegistry(
            "stored proposal operator does not match the exact typed proposal preimage".to_owned(),
        ));
    }
    let certificate = &authorization.governance_certificate;
    let governed_subject = exact_kind.governed_subject_id_v1().map_err(|_| {
        ValidationFeeAdmissionError::InvalidPolicyRegistry(
            "failed to derive the exact validation-fee governed subject".to_owned(),
        )
    })?;
    let certificate_subject = match certificate.expected_head {
        iroha_data_model::governance::types::GovernanceExpectedHeadV1::Absent(head) => {
            head.subject_id
        }
        iroha_data_model::governance::types::GovernanceExpectedHeadV1::Present(head) => {
            head.subject_id
        }
    };
    if certificate.effect_preimage_hash != exact_kind.effect_preimage_hash_v1()
        || certificate_subject != governed_subject
    {
        return Err(ValidationFeeAdmissionError::InvalidPolicyRegistry(
            "stored Parliament certificate is not bound to the exact governed effect and subject"
                .to_owned(),
        ));
    }
    let proposal = world
        .governance_proposals()
        .get(&authorization.proposal_fingerprint)
        .ok_or_else(|| {
            ValidationFeeAdmissionError::InvalidPolicyRegistry(
                "authorized governance proposal is missing".to_owned(),
            )
        })?;
    if &proposal.kind != exact_kind
        || proposal.proposer != authorization.proposal_operator
        || proposal.status != crate::state::GovernanceProposalStatus::Enacted
    {
        return Err(ValidationFeeAdmissionError::InvalidPolicyRegistry(
            "authorized governance proposal payload or status differs from the registry".to_owned(),
        ));
    }
    let attempt = world
        .parliament_attempts()
        .get(&certificate.governance_attempt_id)
        .ok_or_else(|| {
            ValidationFeeAdmissionError::InvalidPolicyRegistry(
                "authorized Parliament attempt is missing".to_owned(),
            )
        })?;
    attempt.validate().map_err(|error| {
        ValidationFeeAdmissionError::InvalidPolicyRegistry(format!(
            "authorized Parliament attempt is invalid: {error}"
        ))
    })?;
    attempt
        .validate_proposal_bindings_v1(exact_kind)
        .map_err(|error| {
            ValidationFeeAdmissionError::InvalidPolicyRegistry(format!(
                "authorized Parliament attempt proposal bindings are invalid: {error}"
            ))
        })?;
    if attempt.proposal_content_id() != certificate.proposal_content_id
        || attempt.attempt().status
            != iroha_data_model::governance::types::GovernanceAttemptStatusV1::Enacted
        || attempt.terminal_height() != Some(authorization.enacted_at_height)
        || attempt.certificate() != Some(certificate)
    {
        return Err(ValidationFeeAdmissionError::InvalidPolicyRegistry(
            "authorized Parliament attempt does not retain the exact enacted certificate"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_treasury_payout_contract_subject(
    policy: &ValidationFeePolicyV1,
    state: &impl StateReadOnly,
) -> Result<(), ExecutionAttemptError<ValidationFeeAdmissionError>> {
    let custody = &policy.reward_custody;
    validate_network_xor_asset(state.world(), &custody.xor_asset_id).map_err(|error| {
        error.map_rejection(|error| {
            ValidationFeeAdmissionError::InvalidPolicyRegistry(error.to_string())
        })
    })?;
    let record =
        crate::smartcontracts::code::fetch_bound_contract_record(state, &custody.contract_address)
            .map_err(|error| {
                error.map_rejection(|_| {
                    ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                        reason: "immutable governed contract scope could not be resolved",
                    }
                })
            })?
            .ok_or_else(|| {
                ValidationFeeAdmissionError::TreasuryPayoutRequiresActiveContractSubject {
                    treasury_account_id: custody.treasury_account_id.to_string(),
                }
            })?;
    if record.contract_subject != custody.treasury_account_id
        || record.contract_address != custody.contract_address
        || custody.treasury_account_id != policy.treasury_account_id
        || custody.ds_asset_id != policy.ds_asset_id
    {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "retail reward custody differs from its immutable contract subject",
            }
            .into(),
        );
    }
    let definition = state
        .world()
        .asset_definition(&custody.ds_asset_id)
        .map_err(
            |_| ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the governed SBD definition is missing",
            },
        )?;
    if definition.spec().scale() != Some(u32::from(policy.ds_scale)) {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "retail fee asset scale differs from its ledger definition",
            }
            .into(),
        );
    }
    Ok(())
}

fn payout_ds_scale(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    state: &impl StateReadOnly,
) -> Result<u8, ValidationFeeAdmissionError> {
    state
        .world()
        .asset_definition(&binding.ds_asset_id)
        .ok()
        .and_then(|definition| definition.spec().scale())
        .and_then(|scale| u8::try_from(scale).ok())
        .filter(|scale| *scale == 2)
        .ok_or(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the governed SBD asset must have two decimal places",
            },
        )
}

fn validate_treasury_payout_binding_contract_subject(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    ds_scale: u8,
    state: &impl StateReadOnly,
) -> Result<(), ExecutionAttemptError<ValidationFeeAdmissionError>> {
    validate_network_xor_asset(state.world(), &binding.xor_asset_id).map_err(|error| {
        error.map_rejection(|error| {
            ValidationFeeAdmissionError::InvalidPolicyRegistry(error.to_string())
        })
    })?;
    let Some(record) =
        crate::smartcontracts::code::fetch_bound_contract_record(state, &binding.contract_address)
            .map_err(|error| {
                error.map_rejection(|_| {
                    ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                        reason: "immutable governed contract scope could not be resolved",
                    }
                })
            })?
    else {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRequiresActiveContractSubject {
                treasury_account_id: binding.treasury_account_id.to_string(),
            }
            .into(),
        );
    };
    if record.contract_address != binding.contract_address
        || record.contract_subject != binding.treasury_account_id
    {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "contract address or immutable subject differs from the enacted binding",
            }
            .into(),
        );
    }
    if <[u8; 32]>::from(ivm::contract_code_hash(&record.code_bytes)) != binding.code_hash {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "deployed code hash differs from the enacted binding",
            }
            .into(),
        );
    }
    let entrypoint = binding.entrypoint.as_ref();
    if !record
        .manifest
        .entrypoints
        .as_ref()
        .is_some_and(|entrypoints| entrypoints.iter().any(|item| item.name == entrypoint))
    {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the enacted entrypoint is absent from the deployed manifest",
            }
            .into(),
        );
    }
    let lifecycle_seal = binding
        .lifecycle_seal()
        .map_err(|_| ValidationFeeAdmissionError::InvalidPayoutLifecycleSeal)?;
    if lifecycle_seal == [0; 32] {
        return Err((ValidationFeeAdmissionError::InvalidPayoutLifecycleSeal).into());
    }
    let ds_definition = state
        .world()
        .asset_definition(&binding.ds_asset_id)
        .map_err(
            |_| ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the governed SBD definition is missing",
            },
        )?;
    if ds_definition.spec().scale() != Some(u32::from(ds_scale)) {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the governed SBD scale differs",
            }
            .into(),
        );
    }
    let pool = crate::smartcontracts::code::fetch_bound_contract_record_by_subject(
        state,
        &binding.pool_vault_account_id,
    )
    .map_err(|error| {
        error.map_rejection(
            |_| ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "immutable governed pool scope could not be resolved",
            },
        )
    })?
    .ok_or(
        ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
            reason: "the governed pool is not an active contract",
        },
    )?;
    if pool.contract_address != binding.pool_contract_address
        || <[u8; 32]>::from(ivm::contract_code_hash(&pool.code_bytes)) != binding.pool_code_hash
    {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the governed pool address or artifact hash differs",
            }
            .into(),
        );
    }
    let feed = state
        .world()
        .oracle_feeds()
        .get(&binding.reference_feed_id)
        .ok_or(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the governed reference feed is missing",
            },
        )?;
    let expected: std::collections::BTreeSet<_> =
        binding.reference_provider_accounts.iter().collect();
    let observed: std::collections::BTreeSet<_> = feed.providers.iter().collect();
    if feed.feed_config_version.0 != binding.reference_feed_config_version
        || expected != observed
        || feed.min_signers < 3
        || feed.committee_size != 5
    {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "the governed native reference feed configuration differs",
            }
            .into(),
        );
    }
    Ok(())
}

fn scheduled_trigger_claims_payout_binding(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    state_transaction: &StateTransaction<'_, '_>,
    origin: &OpaqueDeferredRuntimeOrigin<'_>,
) -> bool {
    let Some(trigger_id) = origin.trigger_id else {
        return false;
    };
    let Some(action) = state_transaction
        .world
        .triggers
        .time_triggers()
        .get(trigger_id)
    else {
        return false;
    };
    let ExecutableRef::ContractCall(invocation) = action.executable() else {
        return false;
    };
    let Some(active_code_hash) = state_transaction
        .world
        .contract_instances
        .get(&binding.contract_address)
    else {
        return false;
    };
    origin.scheduled_time_trigger
        && trigger_is_enabled(action.metadata())
        && action.authority() == &binding.treasury_account_id
        && invocation.contract_address == binding.contract_address
        && invocation.expected_code_hash == *active_code_hash
        && invocation.entrypoint == binding.entrypoint.as_ref()
        && invocation.arguments.is_none()
}

fn runtime_origin_matches_payout_binding(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    state_transaction: &StateTransaction<'_, '_>,
    origin: &OpaqueDeferredRuntimeOrigin<'_>,
) -> Result<bool, ExecutionAttemptError<ValidationFeeAdmissionError>> {
    if !runtime_origin_claims_payout_binding(binding, origin) {
        return Ok(false);
    }
    let record = match crate::smartcontracts::code::fetch_bound_contract_record(
        state_transaction,
        &binding.contract_address,
    ) {
        Ok(record) => record,
        // A completed inaccessible/invalid subject is not the enacted runtime, as before.
        Err(ExecutionAttemptError::Rejected(_)) => return Ok(false),
        Err(ExecutionAttemptError::Deferred(reason)) => {
            return Err(ExecutionAttemptError::Deferred(reason));
        }
    };
    Ok(record.is_some_and(|record| {
        record.contract_address == binding.contract_address
            && record.contract_subject == binding.treasury_account_id
            && <[u8; 32]>::from(ivm::contract_code_hash(&record.code_bytes)) == binding.code_hash
            && record.code_bytes.as_slice() == origin.code_bytes
    }))
}

fn runtime_origin_claims_payout_binding(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    origin: &OpaqueDeferredRuntimeOrigin<'_>,
) -> bool {
    !(origin.runtime_context.contract_address != binding.contract_address
        || origin.runtime_context.contract_subject != binding.treasury_account_id
        || origin.runtime_context.entrypoint != binding.entrypoint.as_ref()
        || <[u8; 32]>::from(ivm::contract_code_hash(origin.code_bytes)) != binding.code_hash)
}

fn resolve_retained_payout_lifecycle(
    registry: Option<&ValidationFeePolicyRegistryV1>,
    state_transaction: &StateTransaction<'_, '_>,
    runtime_origin: Option<&OpaqueDeferredRuntimeOrigin<'_>>,
) -> Result<Option<ResolvedPayoutLifecycle>, ExecutionAttemptError<ValidationFeeAdmissionError>> {
    let (Some(registry), Some(origin)) = (registry, runtime_origin) else {
        return Ok(None);
    };
    let Some(entry) = registry
        .payout_policies
        .effective_entry_at_height(state_transaction.block_height())
    else {
        return Ok(None);
    };
    let binding = &entry.payout_binding;
    let ds_scale = payout_ds_scale(binding, state_transaction)?;
    let trigger_matches =
        scheduled_trigger_claims_payout_binding(binding, state_transaction, origin);
    let runtime_claims = runtime_origin_claims_payout_binding(binding, origin);
    if !trigger_matches && !runtime_claims {
        return Ok(None);
    }
    if !trigger_matches
        || !runtime_origin_matches_payout_binding(binding, state_transaction, origin)?
    {
        return Err(
            ValidationFeeAdmissionError::TreasuryPayoutRuntimeBindingMismatch {
                reason: "conversion must match the independently finalized Parliament policy and exact scheduled trigger",
            }
            .into(),
        );
    }
    validate_treasury_payout_binding_contract_subject(binding, ds_scale, state_transaction)?;
    Ok(Some(ResolvedPayoutLifecycle {
        binding: binding.clone(),
        ds_scale,
    }))
}

fn validate_policy_network_id(
    policy: &ValidationFeePolicyV1,
    expected_network_id: &iroha_data_model::NetworkId,
) -> Result<(), ValidationFeeAdmissionError> {
    if &policy.network_id != expected_network_id {
        return Err(ValidationFeeAdmissionError::WrongPolicyNetwork {
            expected: expected_network_id.to_string(),
            found: policy.network_id.to_string(),
        });
    }
    Ok(())
}

/// Wrap a retained policy rejection only at the transaction admission boundary.
pub(crate) fn admission_rejection(
    error: ValidationFeeAdmissionError,
) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
        "validation-fee admission rejected transaction: {error}"
    )))
}

fn conversion_quantity_state_schema() -> StateValueSchemaV1 {
    StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Quantity)],
    }
}

pub(crate) fn encode_conversion_quantity_state_value(
    value: &Quantity,
) -> Result<Vec<u8>, ivm::VMError> {
    let schema_payload = norito::to_bytes(&conversion_quantity_state_schema())
        .map_err(|_| ivm::VMError::NoritoInvalid)?;
    let envelope = ivm_abi::numeric_tlv::encode_quantity(value)?;
    norito::to_bytes(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&schema_payload),
        atoms: vec![StateValueAtomV1::Pointer(envelope)],
    })
    .map_err(|_| ivm::VMError::NoritoInvalid)
}

fn direct_conversion_transfer(
    instruction: &InstructionBox,
) -> Result<&Transfer<Asset, Quantity, Account>, ValidationFeeAdmissionError> {
    instruction
        .as_any()
        .downcast_ref::<Transfer<Asset, Quantity, Account>>()
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<TransferBox>()
                .and_then(|transfer| match transfer {
                    TransferBox::Asset(transfer) => Some(transfer),
                    _ => None,
                })
        })
        .ok_or(
            ValidationFeeAdmissionError::TreasuryPayoutEffectPlanMismatch {
                reason: "conversion must use three direct asset transfers",
            },
        )
}
fn validate_treasury_payout_effect_plan(
    groups: &std::collections::BTreeMap<AccountId, Vec<InstructionBox>>,
    ordered: &[(AccountId, InstructionBox)],
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    terms: &ValidationFeePayoutTerms,
) -> Result<bool, ValidationFeeAdmissionError> {
    let mismatch =
        |reason| ValidationFeeAdmissionError::TreasuryPayoutEffectPlanMismatch { reason };
    if binding.invariant_error().is_some() {
        return Err(mismatch("invalid enacted conversion policy"));
    }
    let (Some(pool_effects), Some(wrapper_effects)) = (
        groups.get(&binding.pool_vault_account_id),
        groups.get(&binding.treasury_account_id),
    ) else {
        return Err(mismatch(
            "conversion effects must retain the governed pool and wrapper subjects",
        ));
    };
    if groups.len() != 2
        || pool_effects.len() != 2
        || wrapper_effects.len() != 1
        || ordered.len() != 3
        || ordered[0].0 != binding.pool_vault_account_id
        || ordered[1].0 != binding.pool_vault_account_id
        || ordered[2].0 != binding.treasury_account_id
        || pool_effects[0] != ordered[0].1
        || pool_effects[1] != ordered[1].1
        || wrapper_effects[0] != ordered[2].1
    {
        return Err(mismatch(
            "conversion must preserve two nested pool effects followed by the wrapper reservation",
        ));
    }
    let sbd = direct_conversion_transfer(&ordered[0].1)?;
    let output = direct_conversion_transfer(&ordered[1].1)?;
    let reserve = direct_conversion_transfer(&ordered[2].1)?;
    if sbd.source.definition != binding.ds_asset_id
        || sbd.source.account != binding.treasury_account_id
        || sbd.destination != binding.pool_vault_account_id
        || sbd.object != terms.debit_ds
    {
        return Err(mismatch(
            "SBD input must match the governed treasury, pool and native offer",
        ));
    }
    if output.source.definition != binding.xor_asset_id
        || output.source.account != binding.pool_vault_account_id
        || output.destination != binding.treasury_account_id
    {
        return Err(mismatch(
            "XOR output must come from the exact governed pool",
        ));
    }
    if output.object.is_zero()
        || output.object < terms.min_xor_out
        || quantity_to_minor_units_u128(&output.object, terms.xor_scale).is_err()
    {
        return Ok(false);
    }
    if reserve.source.definition != binding.xor_asset_id
        || reserve.source.account != binding.treasury_account_id
        || reserve.destination != binding.reward_pool_account_id
        || reserve.object != output.object
    {
        return Err(mismatch(
            "all actual XOR output must enter reserved reward custody",
        ));
    }
    Ok(true)
}
pub(crate) fn enforce_opaque_deferred_instruction_groups(
    groups: &std::collections::BTreeMap<AccountId, Vec<InstructionBox>>,
    ordered: &[(AccountId, InstructionBox)],
    stx: &mut StateTransaction<'_, '_>,
    origin: Option<OpaqueDeferredRuntimeOrigin<'_>>,
) -> Result<OpaqueDeferredValidationOutcome, TransactionRejectionReason> {
    // Committee and monetary staking authority are independent of native fee
    // accounting. Resolve deferred approvals against this execution overlay first.
    crate::deferred_authority::reject_opaque_deferred_authority(groups, stx)
        .map_err(|error| transaction_attempt_rejection(stx, error))?;
    let registry = validated_policy_registry(stx)
        .map_err(|error| transaction_attempt_rejection(stx, error))?;
    let _ = active_policy_from_validated_registry(registry.as_ref(), stx)
        .map_err(|error| transaction_attempt_rejection(stx, error))?;
    let Some(lifecycle) =
        resolve_retained_payout_lifecycle(registry.as_ref(), stx, origin.as_ref())
            .map_err(|error| fee_attempt_rejection(stx, error))?
    else {
        // Every actual user payment is checked by the native account assessment
        // at the common asset mutation boundary, including contract-driven legs.
        return Ok(OpaqueDeferredValidationOutcome::Apply);
    };
    if ordered.is_empty() && groups.is_empty() {
        return Ok(OpaqueDeferredValidationOutcome::NoOp);
    }
    let binding = &lifecycle.binding;
    let scale = validation_fee_payout_xor_scale(stx, binding)
        .map_err(|error| fee_attempt_rejection(stx, error))?;
    let rewards_error = |error: iroha_data_model::isi::error::InstructionExecutionError| {
        admission_rejection(ValidationFeeAdmissionError::InvalidPolicyRegistry(
            error.to_string(),
        ))
    };
    let Some(offer) =
        crate::validation_fee_rewards::conversion_offer(stx, binding).map_err(rewards_error)?
    else {
        return Ok(OpaqueDeferredValidationOutcome::NoOp);
    };
    let terms = ValidationFeePayoutTerms {
        debit_ds: quantity_from_minor_units_u128(
            u128::from(offer.sbd_minor),
            u32::from(lifecycle.ds_scale),
        )
        .map_err(admission_rejection)?,
        min_xor_out: quantity_from_minor_units_u128(offer.min_xor_minor, scale)
            .map_err(admission_rejection)?,
        xor_scale: scale,
    };
    if !validate_treasury_payout_effect_plan(groups, ordered, binding, &terms)
        .map_err(admission_rejection)?
    {
        return Ok(OpaqueDeferredValidationOutcome::NoOp);
    }
    let output = direct_conversion_transfer(&ordered[1].1).map_err(admission_rejection)?;
    let output_minor =
        quantity_to_minor_units_u128(&output.object, scale).map_err(admission_rejection)?;
    crate::validation_fee_rewards::reserve_conversion(stx, binding, &offer, output_minor)
        .map_err(rewards_error)?;
    stx.world.retail_fee_exempt_payments.push((
        AssetId::new(
            binding.ds_asset_id.clone(),
            binding.treasury_account_id.clone(),
        ),
        binding.pool_vault_account_id.clone(),
        terms.debit_ds,
    ));
    Ok(OpaqueDeferredValidationOutcome::Apply)
}
/// Whether a state path is owned exclusively by native fee consensus.
pub(crate) fn is_consensus_fee_state_key(key: &StatePath) -> bool {
    crate::validation_fee_rewards::is_reserved_state_key(key)
        || crate::retail_fee::is_reserved_state_key(key)
}

#[cfg(test)]
#[path = "validation_fee/tests.rs"]
pub(crate) mod tests;
