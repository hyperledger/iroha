//! Consensus-owned Bokolo monthly accounting, native collection and fee assessments.
mod reward_history;
use crate::execution_attempt::{
    ExecutionAttemptError, json_decode_attempt_error, norito_decode_attempt_error,
};
use crate::state::{StateTransaction, WorldReadOnly, WorldTransaction};
use crate::tx::TransactionRejectionReason;
use iroha_crypto::Hash;
use iroha_data_model::{
    account::AccountId, asset::AssetId, isi::error::InstructionExecutionError, prelude::*,
    transaction::SignedTransaction, validation_fee::*,
};
use iroha_model_base::state_path::StatePath;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
pub(crate) use reward_history::{
    ensure_reward_history_open, reward_history_closed_through, reward_history_is_closed,
    validate_reward_history_frontier,
};

const STATE_PREFIX: &str = "retail_fee_v1/";
/// Canonical marker preserves the complete reviewed assessment inside deferred instructions.
pub const ASSESSMENT_MARKER_PREFIX: &str = "iroha:retail_fee:assessment:v1:";
type FeeReadError = ExecutionAttemptError<String>;

fn world_read_error(
    world: &WorldTransaction<'_, '_>,
    error: FeeReadError,
) -> InstructionExecutionError {
    world.attempt_error_to_instruction_error(error.map_rejection(invalid))
}
fn transaction_read_error(
    stx: &mut StateTransaction<'_, '_>,
    error: FeeReadError,
) -> TransactionRejectionReason {
    match error {
        ExecutionAttemptError::Rejected(error) => rejection(error),
        ExecutionAttemptError::Deferred(reason) => {
            TransactionRejectionReason::Validation(stx.defer_execution(reason))
        }
    }
}
fn transaction_marker_error(
    stx: &mut StateTransaction<'_, '_>,
    error: ExecutionAttemptError<TransactionRejectionReason>,
) -> TransactionRejectionReason {
    match error {
        ExecutionAttemptError::Rejected(error) => error,
        ExecutionAttemptError::Deferred(reason) => {
            TransactionRejectionReason::Validation(stx.defer_execution(reason))
        }
    }
}

fn invalid(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(message.into().into())
}
fn rejection(message: impl Into<String>) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message.into()))
}
/// Protect the complete consensus retail namespace against contract state writes.
pub(crate) fn is_reserved_state_key(key: &StatePath) -> bool {
    key.as_ref().starts_with(STATE_PREFIX)
        || key.as_ref().starts_with("retail_fee_control_v1/")
        || key.as_ref().starts_with("retail_fee_receipts_v1/")
        || key.as_ref().starts_with("retail_fee_heads_v1/")
        || key.as_ref().starts_with("retail_fee_sequence_v1/")
        || key.as_ref().starts_with("retail_fee_head_tree_v1/")
}
fn key(account: &AccountId) -> StatePath {
    format!(
        "{STATE_PREFIX}{}",
        hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
    )
    .parse()
    .expect("canonical retail fee state key")
}
fn rekey_path(account: &AccountId, purpose: &str) -> StatePath {
    format!(
        "retail_fee_control_v1/{purpose}/{}",
        hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
    )
    .parse()
    .expect("canonical retail rekey key")
}
/// Reject reusing a retired recovery identity to acquire another retail allowance.
pub(crate) fn ensure_not_rekeyed(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if world
        .smart_contract_state()
        .get(&rekey_path(account, "retired"))
        .is_some()
    {
        return Err(invalid(
            "retired retail wallet identity must use its recovered account",
        ));
    }
    Ok(())
}
fn predecessors(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Result<Vec<AccountId>, FeeReadError> {
    world
        .smart_contract_state()
        .get(&rekey_path(account, "lineage"))
        .map(|bytes| {
            norito::decode_from_bytes(bytes)
                .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))
        })
        .transpose()
        .map(|value| value.unwrap_or_default())
}
/// Settle the old identity before its balances move during native controller recovery.
pub(crate) fn prepare_rekey(
    stx: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) -> Result<(), InstructionExecutionError> {
    ensure_not_rekeyed(&stx.world, new)?;
    if account_state(&stx.world, new)
        .map_err(|error| world_read_error(&mut stx.world, error))?
        .is_some()
        || receipt_head(&stx.world, new)
            .map_err(|error| world_read_error(&mut stx.world, error))?
            .is_some()
    {
        return Err(invalid(
            "recovery cannot merge independent retail wallet histories",
        ));
    }
    if account_state(&stx.world, old)
        .map_err(|error| world_read_error(&mut stx.world, error))?
        .is_some()
    {
        let policy = registry(&stx.world)
            .map_err(|error| world_read_error(&mut stx.world, error))?
            .and_then(|r| r.head().map(|e| e.policy.clone()))
            .ok_or_else(|| invalid("retail recovery requires its protected policy"))?;
        settle_balance(
            &mut stx.world,
            &AssetId::new(policy.ds_asset_id, old.clone()),
        )?;
    }
    Ok(())
}
/// Preserve the same wallet allowance, accrued balance-time, and receipts across account rekey.
pub(crate) fn finish_rekey(
    stx: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) -> Result<(), InstructionExecutionError> {
    let record =
        account_state(&stx.world, old).map_err(|error| world_read_error(&mut stx.world, error))?;
    let head =
        receipt_head(&stx.world, old).map_err(|error| world_read_error(&mut stx.world, error))?;
    if record.is_none() && head.is_none() {
        return Ok(());
    }
    let wallet = receipt_wallet_id(&stx.world, old)
        .map_err(|error| world_read_error(&mut stx.world, error))?;
    let mut lineage =
        predecessors(&stx.world, old).map_err(|error| world_read_error(&mut stx.world, error))?;
    lineage.push(old.clone());
    if let Some(mut record) = record {
        reward_history::update(&mut stx.world, Some(&record), None)?;
        record.account_id = new.clone();
        stx.world.smart_contract_state.remove(key(old));
        write_account(&mut stx.world, &record)?;
    }
    stx.world.smart_contract_state.insert(
        rekey_path(old, "retired"),
        norito::to_bytes(new)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
            .map_err(|error| world_read_error(&stx.world, error))?,
    );
    stx.world.smart_contract_state.insert(
        rekey_path(new, "lineage"),
        norito::to_bytes(&lineage)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
            .map_err(|error| world_read_error(&stx.world, error))?,
    );
    stx.world.smart_contract_state.insert(
        rekey_path(new, "wallet"),
        norito::to_bytes(&wallet)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
            .map_err(|error| world_read_error(&stx.world, error))?,
    );
    if let Some(mut head) = head {
        head.current_account_id = new.clone();
        head.updated_at_height = stx.block_height();
        write_receipt_head(&mut stx.world, &head)?;
    }
    Ok(())
}

/// Read authoritative retail enrollment; no metadata-supplied counters are consulted.
pub fn account_state(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Result<Option<RetailFeeAccountStateV1>, FeeReadError> {
    world
        .smart_contract_state()
        .get(&key(account))
        .map(|bytes| {
            norito::decode_from_bytes(bytes).map_err(|e| {
                norito_decode_attempt_error(e, |e| format!("invalid protected retail state: {e}"))
            })
        })
        .transpose()
}
/// Write authoritative wallet state and its exact unsettled-month frontier together.
pub(crate) fn write_account(
    world: &mut WorldTransaction<'_, '_>,
    record: &RetailFeeAccountStateV1,
) -> Result<(), InstructionExecutionError> {
    let previous =
        account_state(world, &record.account_id).map_err(|error| world_read_error(world, error))?;
    reward_history::update(world, previous.as_ref(), Some(record))?;
    world.smart_contract_state.insert(
        key(&record.account_id),
        norito::to_bytes(record)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
            .map_err(|error| world_read_error(world, error))?,
    );
    Ok(())
}
fn registry(
    world: &impl WorldReadOnly,
) -> Result<Option<ValidationFeePolicyRegistryV1>, FeeReadError> {
    let id = ValidationFeePolicyRegistryV1::parameter_id();
    let Some(parameter) = world.parameters().custom().get(&id) else {
        return Ok(None);
    };
    if parameter.id() != &id {
        return Err(ExecutionAttemptError::Rejected(
            "malformed protected fee registry identity".into(),
        ));
    }
    let registry = norito::json::from_str(parameter.payload().get()).map_err(|error| {
        json_decode_attempt_error(error, |error| {
            format!("malformed protected fee registry: {error}")
        })
    })?;
    Ok(Some(registry))
}
/// Get the authenticated first-release policy at a ledger time and height.
pub fn policy_at(
    world: &impl WorldReadOnly,
    height: u64,
    now_ms: u64,
) -> Result<Option<ValidationFeePolicyV1>, FeeReadError> {
    let Some(registry) = registry(world)? else {
        return Ok(None);
    };
    registry.validate().map_err(|e| e.to_string())?;
    Ok(registry
        .effective_entry_at(height, now_ms)
        .map(|entry| entry.policy.clone()))
}

/// Decide whether the narrow native AMX transfer host can escrow this leg without inventing
/// a customer assessment or treating its custody account as a retail merchant.
///
/// Enrolled wallet legs and every registered retail monetary asset return a business `No`.
/// TODO(S6): admit the original signed assessment and frozen payment/fee obligations into the
/// funded escrow before supporting these legs. A permissionless relayer supplies no assessment.
pub(crate) fn native_amx_leg_supported(
    world: &impl WorldReadOnly,
    source: &AssetId,
    destination: &AccountId,
) -> Result<bool, FeeReadError> {
    if account_state(world, source.account())?.is_some()
        || account_state(world, destination)?.is_some()
    {
        return Ok(false);
    }
    let Some(registry) = registry(world)? else {
        return Ok(true);
    };
    registry.validate().map_err(|error| error.to_string())?;
    Ok(!registry
        .registered_policies
        .iter()
        .any(|entry| &entry.policy.ds_asset_id == source.definition()))
}

#[cfg(test)]
#[test]
fn native_amx_enrolled_leg_is_no_without_effects_and_original_decoder_refusal_stays_local() {
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        1_793_451_600_000,
        0,
    ));
    let mut transaction = block.transaction();
    let source = AssetId::new(
        AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("amx", "retail").unwrap(),
            "currency".parse().unwrap(),
        ),
        iroha_test_samples::ALICE_ID.clone(),
    );
    let destination = iroha_test_samples::BOB_ID.clone();
    let record =
        RetailFeeAccountStateV1::enroll(destination.clone(), 1_793_451_600_000, 10_000).unwrap();
    let original = norito::to_bytes(&record).unwrap();
    write_account(&mut transaction.world, &record).unwrap();
    assert!(!native_amx_leg_supported(&transaction.world, &source, &destination).unwrap());
    assert_eq!(
        transaction
            .world
            .smart_contract_state
            .get(&key(&destination)),
        Some(&original)
    );
    let refusal = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX),
        || native_amx_leg_supported(&transaction.world, &source, &destination),
    )
    .unwrap_err();
    assert!(
        matches!(refusal, ExecutionAttemptError::Deferred(_)),
        "original account decoder refusal is never a business No: {refusal:?}"
    );
    assert_eq!(
        transaction
            .world
            .smart_contract_state
            .get(&key(&destination)),
        Some(&original)
    );
    assert!(transaction.world.retail_fee_observed_payments.is_empty());
    assert!(transaction.world.retail_fee_pending_credits.is_empty());
}
fn minor(value: &Quantity) -> Result<u64, InstructionExecutionError> {
    iroha_data_model::fastpq::normalized_numeric_to_u64(value.as_numeric(), 2)
        .ok_or_else(|| invalid("SBD balance must fit exact unsigned minor units"))
}
fn quantity(value: u64) -> Quantity {
    format!("{}.{:02}", value / 100, value % 100)
        .parse()
        .expect("u64 minor units are valid Quantity")
}
fn stored_balance(
    world: &impl WorldReadOnly,
    id: &AssetId,
) -> Result<u64, InstructionExecutionError> {
    world
        .assets()
        .get(id)
        .map(|v| minor(v.as_ref()))
        .unwrap_or(Ok(0))
}
fn set_balance(
    world: &mut WorldTransaction<'_, '_>,
    id: &AssetId,
    value: u64,
) -> Result<(), InstructionExecutionError> {
    if value == 0 {
        world.remove_asset_and_metadata(id);
        return Ok(());
    }
    let target = quantity(value);
    world.precheck_quantity_balance_assignment(id, &target)?;
    world.quantity_mutation_observation.changed();
    world.assign_prechecked_quantity_balance(id, target);
    world.track_nonzero_asset_holder(id);
    Ok(())
}
fn funds_available(world: &impl WorldReadOnly, id: &AssetId, balance: u64) -> bool {
    if balance == 0 {
        return false;
    }
    world
        .account(id.account())
        .ok()
        .and_then(|account| {
            crate::smartcontracts::isi::asset::isi::load_asset_transfer_control_store_from_account(
                account.id(),
                account.metadata(),
            )
            .ok()
        })
        .is_some_and(|store| {
            store.find(id.definition()).is_none_or(|record| {
                !record.blacklisted && record.outgoing_availability.is_enabled()
            })
        })
}
fn project(
    world: &impl WorldReadOnly,
    mut record: RetailFeeAccountStateV1,
    now_ms: u64,
    available: bool,
) -> Result<(RetailFeeAccountStateV1, Vec<RetailMaintenanceReceiptV1>), FeeReadError> {
    let registry =
        registry(world)?.ok_or_else(|| "retail state without a protected fee policy".to_owned())?;
    let receipts = record.settle_until(now_ms, available, |period| {
        let entry = registry
            .registered_policies
            .iter()
            .rev()
            .find(|entry| entry.policy.effective_from_ms <= period)
            .ok_or_else(|| "missing earning-period policy".to_owned())?;
        Ok((
            entry.policy.policy_version,
            entry.policy.retail_schedule.clone(),
        ))
    })?;
    Ok((record, receipts))
}
/// Logical retail balance used by reads and transfer prechecks before materialization.
pub fn projected_balance(
    world: &impl WorldReadOnly,
    id: &AssetId,
    now_ms: u64,
) -> Result<Option<Quantity>, FeeReadError> {
    let Some(record) = account_state(world, id.account())? else {
        return Ok(None);
    };
    let Some(registry) = registry(world)? else {
        return Err(ExecutionAttemptError::Rejected(
            "enrolled wallet has no policy".into(),
        ));
    };
    if registry
        .head()
        .is_none_or(|entry| entry.policy.ds_asset_id != *id.definition())
    {
        return Ok(None);
    }
    let available = funds_available(world, id, record.balance_minor);
    let (record, _) = project(world, record, now_ms, available)?;
    Ok(Some(quantity(record.balance_minor)))
}
/// Queue a conserved native movement after all arithmetic has been checked.
fn queue_collection_transcript(
    world: &mut WorldTransaction<'_, '_>,
    source: &AssetId,
    treasury: &AccountId,
    receipt_id: [u8; 32],
    amount_minor: u64,
    source_before: u64,
    treasury_before: u64,
) -> Result<(), InstructionExecutionError> {
    use iroha_data_model::fastpq::{TransferDeltaTranscript, TransferSmtWitness};
    if amount_minor == 0 {
        return Ok(());
    }
    let source_after = source_before
        .checked_sub(amount_minor)
        .ok_or_else(|| invalid("fee transcript source underflow"))?;
    let treasury_after = treasury_before
        .checked_add(amount_minor)
        .ok_or_else(|| invalid("fee transcript treasury overflow"))?;
    world.retail_fee_pending_transcripts.push((
        treasury.clone(),
        Hash::prehashed(receipt_id),
        TransferDeltaTranscript {
            from_account: source.account().clone(),
            to_account: treasury.clone(),
            asset_definition: source.definition().clone(),
            amount: quantity(amount_minor),
            from_balance_before: quantity(source_before),
            from_balance_after: quantity(source_after),
            to_balance_before: quantity(treasury_before),
            to_balance_after: quantity(treasury_after),
            from_smt_witness: TransferSmtWitness::default(),
            to_smt_witness: TransferSmtWitness::default(),
        },
    ));
    Ok(())
}
/// Materialize every elapsed boundary before a source or destination changes balance.
pub(crate) fn settle_balance(
    world: &mut WorldTransaction<'_, '_>,
    id: &AssetId,
) -> Result<(), InstructionExecutionError> {
    settle_balance_until(world, id, world.retail_fee_now_ms)
}
fn settle_balance_until(
    world: &mut WorldTransaction<'_, '_>,
    id: &AssetId,
    now_ms: u64,
) -> Result<(), InstructionExecutionError> {
    let Some(record) =
        account_state(world, id.account()).map_err(|error| world_read_error(world, error))?
    else {
        return Ok(());
    };
    let Some(registry) = registry(world).map_err(|error| world_read_error(world, error))? else {
        return Err(invalid("enrolled wallet has no fee registry"));
    };
    if registry
        .head()
        .is_none_or(|entry| entry.policy.ds_asset_id != *id.definition())
    {
        return Ok(());
    }
    let available = funds_available(world, id, record.balance_minor);
    let mut source_balance = record.balance_minor;
    let (record, receipts) = project(world, record, now_ms, available)
        .map_err(|error| world_read_error(world, error))?;
    for receipt in &receipts {
        let policy = registry
            .registered_policies
            .iter()
            .find(|entry| entry.policy.policy_version == receipt.policy_revision)
            .ok_or_else(|| invalid("missing maintenance earning policy"))?
            .policy
            .clone();
        if receipt.collected_minor > 0 {
            let treasury = AssetId::new(
                policy.ds_asset_id.clone(),
                policy.treasury_account_id.clone(),
            );
            let before = stored_balance(world, &treasury)?;
            let receipt_id = retail_fee_receipt_id_v1(
                id.account(),
                RetailFeeReceiptKindV1::Maintenance,
                receipt.billing_month_start_ms,
                None,
                Some(receipt.effective_at_ms),
            )
            .map_err(invalid)?;
            queue_collection_transcript(
                world,
                id,
                &policy.treasury_account_id,
                receipt_id,
                receipt.collected_minor,
                source_balance,
                before,
            )?;
            source_balance -= receipt.collected_minor;
            set_balance(
                world,
                &treasury,
                before
                    .checked_add(receipt.collected_minor)
                    .ok_or_else(|| invalid("maintenance treasury overflow"))?,
            )?;
            world.retail_fee_pending_credits.push((
                policy,
                receipt.billing_month_start_ms,
                receipt.collected_minor,
            ));
        }
        let earning_policy = registry
            .registered_policies
            .iter()
            .find(|entry| entry.policy.policy_version == receipt.policy_revision)
            .ok_or_else(|| invalid("missing receipt policy"))?;
        let mut native_receipt = RetailFeeReceiptV1 {
            receipt_id: retail_fee_receipt_id_v1(
                id.account(),
                RetailFeeReceiptKindV1::Maintenance,
                receipt.billing_month_start_ms,
                None,
                Some(receipt.effective_at_ms),
            )
            .map_err(invalid)?,
            account_id: id.account().clone(),
            wallet_id: id.account().clone(),
            sequence: 0,
            previous_receipt_hash: None,
            kind: RetailFeeReceiptKindV1::Maintenance,
            billing_month_start_ms: receipt.billing_month_start_ms,
            policy_revision: receipt.policy_revision,
            policy_hash: earning_policy.policy_hash,
            scheduled_minor: receipt.scheduled_minor,
            collected_minor: receipt.collected_minor,
            waived_minor: receipt.waived_minor,
            payment_count: 0,
            source_transaction_hash: None,
            effective_at_ms: Some(receipt.effective_at_ms),
            recorded_at_height: world.retail_fee_height,
            assessment: None,
        };
        store_receipt(world, &mut native_receipt)?;
    }
    if receipts.iter().any(|receipt| receipt.collected_minor > 0) {
        set_balance(world, id, record.balance_minor)?;
    }
    write_account(world, &record)
}
/// Update the balance held constant until the next ledger-clock integration.
pub(crate) fn observe_balance(
    world: &mut WorldTransaction<'_, '_>,
    id: &AssetId,
) -> Result<(), InstructionExecutionError> {
    let Some(mut record) =
        account_state(world, id.account()).map_err(|error| world_read_error(world, error))?
    else {
        return Ok(());
    };
    if registry(world)
        .map_err(|error| world_read_error(world, error))?
        .and_then(|registry| {
            registry
                .head()
                .map(|entry| entry.policy.ds_asset_id.clone())
        })
        .as_ref()
        != Some(id.definition())
    {
        return Ok(());
    }
    record.balance_minor = stored_balance(world, id)?;
    write_account(world, &record)
}
/// Check the issuer capability against the wallet's registered primary-alias domain.
/// This authorizes issuer-scoped fee disclosures without granting fee overrides.
///
/// # Errors
/// Returns an error when a referenced ledger account or alias is invalid.
pub fn is_account_issuer_for_primary_alias(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    account: &AccountId,
) -> Result<bool, FeeReadError> {
    if authority == account {
        return Ok(false);
    }
    let wallet = world.account(account).map_err(|e| e.to_string())?;
    let label = wallet.label();
    let Some(alias) = label.as_ref() else {
        return Ok(false);
    };
    let Some(domain) = alias
        .domain_id(world.dataspace_catalog())
        .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    let permission_is_issuer = |p: &Permission| {
        iroha_executor_data_model::permission::account::CanRegisterAccount::try_from(p)
            .is_ok_and(|permission| permission.domain == domain)
    };
    Ok(world
        .account_permissions_iter(authority)
        .map_err(|e| e.to_string())?
        .any(permission_is_issuer)
        || world.account_roles_iter(authority).any(|role_id| {
            world
                .roles()
                .get(role_id)
                .is_some_and(|role| role.permissions.iter().any(permission_is_issuer))
        }))
}
/// Enroll through a native protected account-metadata action authorized for account issuers.
pub(crate) fn enroll(
    stx: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    account: &AccountId,
) -> Result<(), InstructionExecutionError> {
    ensure_not_rekeyed(&stx.world, account)?;
    let permitted = is_account_issuer_for_primary_alias(&stx.world, authority, account)
        .map_err(|error| world_read_error(&mut stx.world, error))?;
    if authority == account || !permitted {
        return Err(invalid(
            "retail enrollment requires an authorized account issuer",
        ));
    }
    stx.world.account(account)?;
    if account_state(&stx.world, account)
        .map_err(|error| world_read_error(&mut stx.world, error))?
        .is_some()
    {
        return Ok(());
    }
    let policy = policy_at(
        &stx.world,
        stx.block_height(),
        stx.block_unix_timestamp_ms(),
    )
    .map_err(|error| world_read_error(&mut stx.world, error))?
    .ok_or_else(|| invalid("retail enrollment requires active Parliament fee policy"))?;
    if account == &policy.treasury_account_id {
        return Err(invalid("fee treasury cannot be retail enrolled"));
    }
    let id = AssetId::new(policy.ds_asset_id, account.clone());
    let record = RetailFeeAccountStateV1::enroll(
        account.clone(),
        stx.block_unix_timestamp_ms(),
        stored_balance(&stx.world, &id)?,
    )
    .map_err(invalid)?;
    write_account(&mut stx.world, &record)?;
    initialize_receipt_head(&mut stx.world, account)
}
/// Return authoritative status, including logical deductions of all expired periods.
pub fn status(
    world: &impl WorldReadOnly,
    account: &AccountId,
    now_ms: u64,
) -> Result<Option<RetailFeeAccountStateV1>, FeeReadError> {
    let Some(record) = account_state(world, account)? else {
        return Ok(None);
    };
    let registry =
        registry(world)?.ok_or_else(|| "retail state without fee registry".to_owned())?;
    let asset = registry
        .head()
        .ok_or_else(|| "empty fee registry".to_owned())?
        .policy
        .ds_asset_id
        .clone();
    let available = funds_available(
        world,
        &AssetId::new(asset, account.clone()),
        record.balance_minor,
    );
    project(world, record, now_ms, available).map(|(record, _)| Some(record))
}
/// Produce an exact quote from finalized ledger facts, including institutional sending accounts.
pub fn quote(
    world: &impl WorldReadOnly,
    height: u64,
    now_ms: u64,
    request: &RetailFeeQuoteRequestV1,
) -> Result<RetailFeeAssessmentV1, FeeReadError> {
    world
        .account(&request.account_id)
        .map_err(|e| e.to_string())?;
    let policy = policy_at(world, height, now_ms)?
        .ok_or_else(|| "no active Parliament fee policy".to_owned())?;
    if policy.ds_asset_id != request.asset_definition_id {
        return Err(ExecutionAttemptError::Rejected(
            "quote asset differs from governed SBD asset".into(),
        ));
    }
    if request.transfers.is_empty()
        || request.transfers.len() > 1000
        || request
            .transfers
            .iter()
            .any(|leg| leg.amount_minor_units == 0)
    {
        return Err(ExecutionAttemptError::Rejected(
            "quote needs 1 to 1000 positive payment legs".into(),
        ));
    }
    let account = status(world, &request.account_id, now_ms)?;
    let (start, end) = honiara_month_bounds(now_ms)?;
    let used = account.as_ref().map_or(0, |state| state.payments_used);
    let count = request.qualifying_payments();
    let fee = if account.is_some() {
        policy.retail_schedule.payment_fee(used, count)?
    } else {
        minor(&policy.fee)
            .map_err(|e| e.to_string())?
            .checked_mul(count)
            .ok_or_else(|| "institutional fee overflow".to_owned())?
    };
    let policy_hash = policy.policy_hash().map_err(|e| e.to_string())?;
    let transient = RetailFeeAccountStateV1::enroll(request.account_id.clone(), now_ms, 0)?;
    let commitment = account
        .as_ref()
        .unwrap_or(&transient)
        .state_commitment(policy_hash, account.is_some())?;
    Ok(RetailFeeAssessmentV1 {
        account_id: request.account_id.clone(),
        retail_enrolled: account.is_some(),
        billing_month_start_ms: start,
        policy_revision: policy.policy_version,
        payments_used_before: used,
        qualifying_payments: count,
        fee_minor: fee,
        state_commitment: commitment,
        intent_hash: request.intent_hash()?,
        expires_at_ms: now_ms
            .checked_add(RETAIL_FEE_QUOTE_TTL_MS)
            .ok_or_else(|| "quote expiry overflow".to_owned())?
            .min(end),
    })
}
/// Bind the customer's signed assessment before any executable can move value.
pub(crate) fn admit(
    tx: &SignedTransaction,
    stx: &mut StateTransaction<'_, '_>,
) -> Result<(), TransactionRejectionReason> {
    if tx
        .instructions()
        .explicit_instructions()
        .any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<Log>()
                .is_some_and(|log| log.msg.starts_with(ASSESSMENT_MARKER_PREFIX))
        })
    {
        return Err(rejection(
            "direct payments require assessment metadata, not deferred assessment markers",
        ));
    }
    stx.world.retail_fee_source_transaction_hash = Some(*tx.hash().as_ref());
    if let Some(value) = tx.metadata().get(RETAIL_FEE_ASSESSMENT_METADATA_KEY) {
        let assessment = norito::json::from_str::<RetailFeeAssessmentV1>(value.get())
            .map_err(|error| {
                json_decode_attempt_error(error, |error| {
                    format!("invalid retail fee assessment: {error}")
                })
            })
            .map_err(|error| transaction_read_error(stx, error))?;
        bind_assessment(stx, assessment)?;
    }
    Ok(())
}
fn bind_assessment(
    stx: &mut StateTransaction<'_, '_>,
    assessment: RetailFeeAssessmentV1,
) -> Result<(), TransactionRejectionReason> {
    let now = stx.block_unix_timestamp_ms();
    if now >= assessment.expires_at_ms
        || assessment.expires_at_ms > now.saturating_add(RETAIL_FEE_QUOTE_TTL_MS)
    {
        return Err(rejection(
            "retail fee assessment expired or has invalid lifetime",
        ));
    }
    if stx.world.retail_fee_assessment.is_some() {
        return Err(rejection(
            "duplicate retail fee assessments in one execution",
        ));
    }
    stx.world.retail_fee_assessment = Some(assessment);
    Ok(())
}
/// Preserve a reviewed assessment in a multisig proposal's signed instruction list.
pub(crate) fn admit_deferred(
    instructions: &[InstructionBox],
    stx: &mut StateTransaction<'_, '_>,
) -> Result<(), TransactionRejectionReason> {
    let mut reviewed = None;
    for instruction in instructions {
        if let Some(log) = instruction.as_any().downcast_ref::<Log>() {
            if let Some(assessment) = decode_assessment_marker(log)
                .map_err(|error| transaction_marker_error(stx, error))?
            {
                if reviewed.replace(assessment).is_some() {
                    return Err(rejection("duplicate retail assessment markers"));
                }
            }
        }
    }
    if let Some(assessment) = reviewed {
        bind_assessment(stx, assessment)?;
        stx.world.retail_fee_assessment_marker_pending = true;
    }
    Ok(())
}

fn decode_assessment_marker(
    log: &Log,
) -> Result<Option<RetailFeeAssessmentV1>, ExecutionAttemptError<TransactionRejectionReason>> {
    let Some(encoded) = log.msg.strip_prefix(ASSESSMENT_MARKER_PREFIX) else {
        return Ok(None);
    };
    if log.level != Level::TRACE {
        return Err((rejection("retail assessment marker must use TRACE")).into());
    }
    if encoded.is_empty()
        || log.msg.len() > 4096
        || encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err((rejection(
            "retail assessment marker requires bounded canonical lowercase hex",
        ))
        .into());
    }
    let bytes =
        hex::decode(encoded).map_err(|_| rejection("invalid retail assessment marker hex"))?;
    let assessment = norito::decode_canonical(&bytes).map_err(|error| {
        norito_decode_attempt_error(error, |_| {
            rejection("retail assessment marker is not canonical")
        })
    })?;
    Ok(Some(assessment))
}

/// Consume the one marker preauthorized by an authenticated multisig instruction list.
/// Direct and contract-emitted logs cannot establish or duplicate a reviewed assessment.
pub(crate) fn execute_assessment_marker(
    log: &Log,
    stx: &mut StateTransaction<'_, '_>,
) -> Result<(), InstructionExecutionError> {
    let Some(assessment) = decode_assessment_marker(log).map_err(|error| {
        stx.world.attempt_error_to_instruction_error(
            error.map_rejection(|error| invalid(error.to_string())),
        )
    })?
    else {
        return Ok(());
    };
    if stx.multisig_deferred_execution_stack.is_empty()
        || !stx.world.retail_fee_assessment_marker_pending
        || stx.world.retail_fee_assessment.as_ref() != Some(&assessment)
    {
        return Err(invalid(
            "retail assessment marker requires its single authenticated deferred instruction",
        ));
    }
    stx.world.retail_fee_assessment_marker_pending = false;
    Ok(())
}
/// Record executed user-authorized payment legs; typed custody paths never invoke this hook.
pub(crate) fn record_payment(
    stx: &mut StateTransaction<'_, '_>,
    source: &AssetId,
    destination: &AccountId,
    amount: &Quantity,
) -> Result<(), InstructionExecutionError> {
    // Independently enacted native conversion may precede customer pricing.
    // Consume only its exact verified leg before the optional retail policy;
    // otherwise a real exempt transfer leaves an unconsumed authorization and
    // finalization rejects the entire conversion.
    if let Some(index) = stx.world.retail_fee_exempt_payments.iter().position(
        |(approved_source, approved_destination, approved_amount)| {
            approved_source == source
                && approved_destination == destination
                && approved_amount == amount
        },
    ) {
        stx.world.retail_fee_exempt_payments.remove(index);
        return Ok(());
    }
    let Some(policy) = policy_at(
        &stx.world,
        stx.block_height(),
        stx.block_unix_timestamp_ms(),
    )
    .map_err(|error| world_read_error(&stx.world, error))?
    else {
        return Ok(());
    };
    if source.definition() != &policy.ds_asset_id || amount.is_zero() {
        return Ok(());
    }
    if source.account() == destination && stx.world.retail_fee_assessment.is_none() {
        return Ok(());
    }
    if stx.world.retail_fee_assessment.is_none() {
        return Err(invalid(
            "outgoing SBD payment requires a signed current validation_fee_assessment",
        ));
    }
    stx.world.retail_fee_observed_payments.push((
        source.clone(),
        RetailFeePaymentLegV1 {
            destination_account_id: destination.clone(),
            amount_minor_units: minor(amount)?,
        },
    ));
    Ok(())
}
/// Finish inside the same disposable overlay as principal transfers and trigger execution.
/// Any missing/stale quote, insufficient fee funds or replay rolls back the complete transaction.
pub(crate) fn finalize(
    stx: &mut StateTransaction<'_, '_>,
) -> Result<(), TransactionRejectionReason> {
    if stx.world.retail_fee_assessment_marker_pending {
        return Err(rejection(
            "authenticated retail assessment marker was not executed",
        ));
    }
    if !stx.world.retail_fee_exempt_payments.is_empty() {
        return Err(rejection(
            "verified protocol fee exemption was not consumed by its exact transfer",
        ));
    }
    let observed = std::mem::take(&mut stx.world.retail_fee_observed_payments);
    if !observed.is_empty() {
        let assessment = stx
            .world
            .retail_fee_assessment
            .clone()
            .ok_or_else(|| rejection("missing retail assessment"))?;
        let source = &observed[0].0;
        if observed.iter().any(|(id, _)| id != source) {
            return Err(rejection(
                "one assessment cannot charge multiple source wallets",
            ));
        }
        let request = RetailFeeQuoteRequestV1 {
            account_id: source.account().clone(),
            asset_definition_id: source.definition().clone(),
            transfers: observed.iter().map(|(_, leg)| leg.clone()).collect(),
        };
        let expected = quote(
            &stx.world,
            stx.block_height(),
            stx.block_unix_timestamp_ms(),
            &request,
        )
        .map_err(|error| transaction_read_error(stx, error))?;
        if assessment.retail_enrolled != expected.retail_enrolled
            || assessment.account_id != expected.account_id
            || assessment.billing_month_start_ms != expected.billing_month_start_ms
            || assessment.policy_revision != expected.policy_revision
            || assessment.payments_used_before != expected.payments_used_before
            || assessment.qualifying_payments != expected.qualifying_payments
            || assessment.fee_minor != expected.fee_minor
            || assessment.state_commitment != expected.state_commitment
            || assessment.intent_hash != expected.intent_hash
        {
            return Err(rejection(
                "fee assessment is stale or differs from executed payments; review a fresh quote",
            ));
        }
        let policy = policy_at(
            &stx.world,
            stx.block_height(),
            stx.block_unix_timestamp_ms(),
        )
        .map_err(|error| transaction_read_error(stx, error))?
        .ok_or_else(|| rejection("fee policy vanished"))?;
        let source_transaction_hash = stx
            .world
            .retail_fee_source_transaction_hash
            .ok_or_else(|| rejection("payment receipt requires signed execution context"))?;
        let receipt_id = retail_fee_receipt_id_v1(
            source.account(),
            RetailFeeReceiptKindV1::Payment,
            assessment.billing_month_start_ms,
            Some(source_transaction_hash),
            None,
        )
        .map_err(rejection)?;
        if assessment.fee_minor > 0 {
            crate::validation_fee_rewards::ensure_reward_custody_debit(
                stx,
                source,
                &quantity(assessment.fee_minor),
            )
            .map_err(|e| rejection(e.to_string()))?;
            let from = stored_balance(&stx.world, source).map_err(|e| rejection(e.to_string()))?;
            let remaining = from.checked_sub(assessment.fee_minor).ok_or_else(|| {
                rejection("insufficient available funds for principal and assessed fee")
            })?;
            let treasury = AssetId::new(
                policy.ds_asset_id.clone(),
                policy.treasury_account_id.clone(),
            );
            let to = stored_balance(&stx.world, &treasury).map_err(|e| rejection(e.to_string()))?;
            queue_collection_transcript(
                &mut stx.world,
                source,
                &policy.treasury_account_id,
                receipt_id,
                assessment.fee_minor,
                from,
                to,
            )
            .map_err(|e| rejection(e.to_string()))?;
            set_balance(&mut stx.world, source, remaining).map_err(|e| rejection(e.to_string()))?;
            set_balance(
                &mut stx.world,
                &treasury,
                to.checked_add(assessment.fee_minor)
                    .ok_or_else(|| rejection("fee treasury overflow"))?,
            )
            .map_err(|e| rejection(e.to_string()))?;
            observe_balance(&mut stx.world, source).map_err(|e| rejection(e.to_string()))?;
            stx.world.retail_fee_pending_credits.push((
                policy.clone(),
                assessment.billing_month_start_ms,
                assessment.fee_minor,
            ));
        }
        let mut native_receipt = RetailFeeReceiptV1 {
            receipt_id,
            account_id: source.account().clone(),
            wallet_id: source.account().clone(),
            sequence: 0,
            previous_receipt_hash: None,
            kind: RetailFeeReceiptKindV1::Payment,
            billing_month_start_ms: assessment.billing_month_start_ms,
            policy_revision: assessment.policy_revision,
            policy_hash: policy.policy_hash().map_err(|e| rejection(e.to_string()))?,
            scheduled_minor: assessment.fee_minor,
            collected_minor: assessment.fee_minor,
            waived_minor: 0,
            payment_count: assessment.qualifying_payments,
            source_transaction_hash: Some(source_transaction_hash),
            effective_at_ms: None,
            recorded_at_height: stx.world.retail_fee_height,
            assessment: Some(assessment.clone()),
        };
        store_receipt(&mut stx.world, &mut native_receipt).map_err(|e| rejection(e.to_string()))?;
        if let Some(mut record) = account_state(&stx.world, source.account())
            .map_err(|error| transaction_read_error(stx, error))?
        {
            record.payments_used = record
                .payments_used
                .checked_add(assessment.qualifying_payments)
                .ok_or_else(|| rejection("payment counter overflow"))?;
            write_account(&mut stx.world, &record).map_err(|e| rejection(e.to_string()))?;
        }
    }
    stx.flush_retail_fee_transfer_transcripts()
        .map_err(|e| rejection(e.to_string()))?;
    for (policy, period, collected) in std::mem::take(&mut stx.world.retail_fee_pending_credits) {
        crate::validation_fee_rewards::credit_collected_fee(stx, &policy, period, collected)?;
    }
    crate::validation_fee_rewards::validate_pending_fee_evidence_budget(stx)
        .map_err(|error| transaction_read_error(stx, error))?;
    Ok(())
}

/// Settle one bounded idle-wallet batch before any later customer mutation.
pub(crate) fn settle_idle_account(
    stx: &mut StateTransaction<'_, '_>,
    policy: &ValidationFeePolicyV1,
    record: RetailFeeAccountStateV1,
) -> Result<(), FeeReadError> {
    let mut through = stx.block_unix_timestamp_ms();
    if record.closed_at_ms.is_none() {
        let mut boundary = record.billing_month_start_ms;
        for _ in 0..RETAIL_FEE_MAX_CATCH_UP_MONTHS {
            if boundary >= through {
                break;
            }
            boundary = honiara_month_bounds(boundary)?.1;
        }
        through = through.min(boundary);
    }
    settle_balance_until(
        &mut stx.world,
        &AssetId::new(policy.ds_asset_id.clone(), record.account_id),
        through,
    )
    .map_err(|error| match stx.execution_deferral() {
        Some(reason) => ExecutionAttemptError::Deferred(reason),
        None => ExecutionAttemptError::Rejected(error.to_string()),
    })
}
/// Materialize at most 128 idle wallets and twelve months each per finalized block.
/// The durable cursor guarantees progress without scanning the complete account table.
///
/// # Errors
/// Local State storage admission refuses the sweep transaction. Fee-policy failures are
/// logged and defer the whole batch without partial collection.
pub(crate) fn process_idle_accounts(
    block: &mut crate::state::StateBlock<'_>,
) -> Result<(), crate::state::StateStorageAdmissionError> {
    let mut stx = block.consensus_effects_transaction()?;
    let cursor_key: StatePath = "retail_fee_control_v1/sweep_cursor"
        .parse()
        .expect("retail cursor key");
    let cursor = stx
        .world
        .smart_contract_state
        .get(&cursor_key)
        .map(|bytes| {
            norito::decode_from_bytes::<StatePath>(bytes)
                .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
        })
        .transpose();
    let cursor = match cursor {
        Ok(cursor) => cursor,
        Err(error) => {
            if let ExecutionAttemptError::Deferred(reason) = error {
                let _ = stx.defer_execution(reason);
            }
            return Ok(());
        }
    };
    let lower = cursor
        .map(std::ops::Bound::Excluded)
        .unwrap_or_else(|| std::ops::Bound::Included(STATE_PREFIX.parse().expect("retail prefix")));
    let keys: Vec<_> = stx
        .world
        .smart_contract_state
        .range((lower, std::ops::Bound::Unbounded))
        .take_while(|(key, _)| key.as_ref().starts_with(STATE_PREFIX))
        .filter(|(key, _)| key.as_ref().len() == STATE_PREFIX.len() + 64)
        .take(128)
        .map(|(key, _)| key.clone())
        .collect();
    let result = (|| -> Result<(), FeeReadError> {
        let Some(registry) = registry(&stx.world)? else {
            return Ok(());
        };
        let Some(policy) = registry.head().map(|entry| entry.policy.clone()) else {
            return Ok(());
        };
        for key in &keys {
            let bytes = stx
                .world
                .smart_contract_state
                .get(key)
                .ok_or("missing retail sweep record")?;
            let record: RetailFeeAccountStateV1 = norito::decode_from_bytes(bytes)
                .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?;
            if stx.world.account(&record.account_id).is_ok() || record.closed_at_ms.is_some() {
                settle_idle_account(&mut stx, &policy, record)?;
            }
        }
        finalize(&mut stx).map_err(|e| e.to_string())?;
        if let Some(last) = keys.last() {
            stx.world.smart_contract_state.insert(
                cursor_key.clone(),
                norito::to_bytes(last).map_err(|error| {
                    norito_decode_attempt_error(error, |error| error.to_string())
                })?,
            );
        } else {
            stx.world.smart_contract_state.remove(cursor_key.clone());
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            // Idle settlements always write protected account/receipt state or
            // their cursor. This child journal excludes earlier applied siblings;
            // an empty sweep must not manufacture a committed fragment.
            if stx.world.smart_contract_state.touched_entries().len() != 0 {
                stx.apply();
            }
        }
        Err(error) => {
            iroha_logger::warn!(%error,"retail fee idle settlement refused without partial collection");
            if let ExecutionAttemptError::Deferred(reason) = error {
                let _ = stx.defer_execution(reason);
            }
        }
    }
    Ok(())
}

fn receipt_prefix(account: &AccountId) -> String {
    format!(
        "retail_fee_receipts_v1/{}/",
        hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
    )
}
/// Resolve the original canonical wallet identity through protected native recovery state.
pub fn receipt_wallet_id(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Result<AccountId, FeeReadError> {
    world
        .smart_contract_state()
        .get(&rekey_path(account, "wallet"))
        .map(|bytes| {
            norito::decode_from_bytes(bytes)
                .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))
        })
        .transpose()
        .map(|id| id.unwrap_or_else(|| account.clone()))
}
/// Read a wallet receipt head; absence means no head has yet been committed.
pub fn receipt_head(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Result<Option<RetailFeeReceiptHeadV1>, FeeReadError> {
    let wallet = receipt_wallet_id(world, account)?;
    let path = retail_fee_receipt_head_state_key_v1(&wallet)?;
    world
        .smart_contract_state()
        .get(&path)
        .map(|bytes| {
            norito::decode_from_bytes(bytes)
                .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))
        })
        .transpose()
}
fn write_receipt_head(
    world: &mut WorldTransaction<'_, '_>,
    head: &RetailFeeReceiptHeadV1,
) -> Result<(), InstructionExecutionError> {
    world.smart_contract_state.insert(
        retail_fee_receipt_head_state_key_v1(&head.wallet_id).map_err(invalid)?,
        norito::to_bytes(head)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
            .map_err(|error| world_read_error(world, error))?,
    );
    crate::validation_fee_rewards::update_receipt_head_tree(world, head)
        .map_err(|error| world_read_error(world, error))
}
pub(crate) fn receipt_sequence_key(wallet: &AccountId, sequence: u64) -> StatePath {
    format!(
        "retail_fee_sequence_v1/{}/{sequence:020}",
        hex::encode(Hash::new(wallet.to_string().as_bytes()).as_ref())
    )
    .parse()
    .expect("canonical native receipt sequence key")
}
fn initialize_receipt_head(
    world: &mut WorldTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if receipt_head(world, account)
        .map_err(|error| world_read_error(world, error))?
        .is_some()
    {
        return Ok(());
    }
    let wallet_id =
        receipt_wallet_id(world, account).map_err(|error| world_read_error(world, error))?;
    let updated_at_height = world.retail_fee_height;
    write_receipt_head(
        world,
        &RetailFeeReceiptHeadV1 {
            wallet_id,
            current_account_id: account.clone(),
            sequence: 0,
            last_receipt_hash: None,
            updated_at_height,
        },
    )
}
pub(crate) fn store_receipt(
    world: &mut WorldTransaction<'_, '_>,
    receipt: &mut RetailFeeReceiptV1,
) -> Result<(), InstructionExecutionError> {
    let path = retail_fee_receipt_state_key_v1(receipt).map_err(invalid)?;
    if world.smart_contract_state.get(&path).is_some() {
        return Err(invalid("native fee receipt replay"));
    }
    initialize_receipt_head(world, &receipt.account_id)?;
    let mut head = receipt_head(world, &receipt.account_id)
        .map_err(|error| world_read_error(world, error))?
        .ok_or_else(|| invalid("native receipt head unavailable"))?;
    if head.current_account_id != receipt.account_id {
        return Err(invalid(
            "native receipt account is not the current wallet controller",
        ));
    }
    receipt.wallet_id = head.wallet_id.clone();
    receipt.sequence = head
        .sequence
        .checked_add(1)
        .ok_or_else(|| invalid("native receipt sequence overflow"))?;
    receipt.previous_receipt_hash = head.last_receipt_hash;
    let sequence_key = receipt_sequence_key(&head.wallet_id, receipt.sequence);
    if world.smart_contract_state.get(&sequence_key).is_some() {
        return Err(invalid("native receipt sequence replay"));
    }
    world.smart_contract_state.insert(
        sequence_key,
        norito::to_bytes(&path)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
            .map_err(|error| world_read_error(world, error))?,
    );
    world.smart_contract_state.insert(
        path,
        norito::to_bytes(receipt)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
            .map_err(|error| world_read_error(world, error))?,
    );
    head.sequence = receipt.sequence;
    head.last_receipt_hash = Some(retail_fee_receipt_chain_hash_v1(receipt).map_err(invalid)?);
    head.updated_at_height = world.retail_fee_height;
    write_receipt_head(world, &head)
}
/// Read a contiguous bounded receipt sequence for one stable canonical wallet.
pub fn receipt_sequence(
    world: &impl WorldReadOnly,
    wallet: &AccountId,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<RetailFeeReceiptV1>, FeeReadError> {
    if limit == 0 || limit > 100 {
        return Err(ExecutionAttemptError::Rejected(
            "receipt sequence limit must be 1..100".into(),
        ));
    }
    let mut rows = Vec::new();
    for offset in 1..=limit as u64 {
        let sequence = after_sequence
            .checked_add(offset)
            .ok_or("receipt sequence overflow")?;
        let Some(bytes) = world
            .smart_contract_state()
            .get(&receipt_sequence_key(wallet, sequence))
        else {
            break;
        };
        let path: StatePath = norito::decode_from_bytes(bytes)
            .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))?;
        let receipt: RetailFeeReceiptV1 = norito::decode_from_bytes(
            world
                .smart_contract_state()
                .get(&path)
                .ok_or("receipt sequence points to missing record")?,
        )
        .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))?;
        if receipt.wallet_id != *wallet || receipt.sequence != sequence {
            return Err(ExecutionAttemptError::Rejected(
                "receipt sequence identity mismatch".into(),
            ));
        }
        rows.push(receipt);
    }
    Ok(rows)
}
/// Read a bounded, canonical page of immutable native receipts for an authenticated account.
pub fn receipts(
    world: &impl WorldReadOnly,
    account: &AccountId,
    after: Option<[u8; 32]>,
    limit: usize,
) -> Result<Vec<RetailFeeReceiptV1>, FeeReadError> {
    if limit == 0 || limit > 100 {
        return Err(ExecutionAttemptError::Rejected(
            "receipt page limit must be between 1 and 100".into(),
        ));
    }
    let mut identities = predecessors(world, account)?;
    identities.push(account.clone());
    let mut result = Vec::new();
    for identity in identities {
        let prefix = receipt_prefix(&identity);
        let lower = if let Some(after) = after {
            std::ops::Bound::Excluded(
                format!("{prefix}{}", hex::encode(after))
                    .parse::<StatePath>()
                    .map_err(|e| e.to_string())?,
            )
        } else {
            std::ops::Bound::Included(prefix.parse::<StatePath>().map_err(|e| e.to_string())?)
        };
        for (_, bytes) in world
            .smart_contract_state()
            .range((lower, std::ops::Bound::Unbounded))
            .take_while(|(key, _)| key.as_ref().starts_with(&prefix))
            .take(limit)
        {
            result.push(
                norito::decode_from_bytes::<RetailFeeReceiptV1>(bytes)
                    .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))?,
            );
        }
    }
    result.sort_by_key(|receipt| receipt.receipt_id);
    result.truncate(limit);
    Ok(result)
}

/// Close the active interval without billing an incomplete calendar month.
pub(crate) fn close_account(
    stx: &mut StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), InstructionExecutionError> {
    let Some(policy) = policy_at(
        &stx.world,
        stx.block_height(),
        stx.block_unix_timestamp_ms(),
    )
    .map_err(|error| world_read_error(&mut stx.world, error))?
    else {
        return Ok(());
    };
    settle_balance(
        &mut stx.world,
        &AssetId::new(policy.ds_asset_id, account.clone()),
    )?;
    let Some(mut record) = account_state(&stx.world, account)
        .map_err(|error| world_read_error(&mut stx.world, error))?
    else {
        return Ok(());
    };
    if record.closed_at_ms.is_none() {
        record.closed_at_ms = Some(stx.block_unix_timestamp_ms());
        // Successful account unregistration removes its assets in the same atomic overlay.
        // The completed closing month can only collect funds present at its later boundary.
        record.balance_minor = 0;
        write_account(&mut stx.world, &record)?;
    }
    Ok(())
}
/// Preserve retained counters when a previously closed canonical account is registered again.
pub(crate) fn reopen_account(
    stx: &mut StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if account_state(&stx.world, account)
        .map_err(|error| world_read_error(&mut stx.world, error))?
        .is_none()
    {
        return Ok(());
    }
    let Some(policy) = policy_at(
        &stx.world,
        stx.block_height(),
        stx.block_unix_timestamp_ms(),
    )
    .map_err(|error| world_read_error(&mut stx.world, error))?
    else {
        return Err(invalid("retail reopening requires active policy"));
    };
    let asset = AssetId::new(policy.ds_asset_id, account.clone());
    settle_balance(&mut stx.world, &asset)?;
    let mut record = account_state(&stx.world, account)
        .map_err(|error| world_read_error(&mut stx.world, error))?
        .ok_or_else(|| invalid("retained retail state disappeared"))?;
    let balance = stored_balance(&stx.world, &asset)?;
    record
        .reopen(stx.block_unix_timestamp_ms(), balance)
        .map_err(invalid)?;
    write_account(&mut stx.world, &record)
}

/// Read immutable receipts backwards from a previously authenticated wallet frontier.
pub fn receipt_page(
    world: &impl WorldReadOnly,
    cursor: &iroha_data_model::fee_evidence::RetailFeeReceiptCursorV1,
    limit: usize,
) -> Result<iroha_data_model::fee_evidence::RetailFeeReceiptPageV1, FeeReadError> {
    use iroha_data_model::fee_evidence::RetailFeeReceiptPageV1;
    if limit == 0 || limit > 100 {
        return Err(ExecutionAttemptError::Rejected(
            "receipt page limit must be 1..100".into(),
        ));
    }
    let mut receipts = Vec::new();
    for offset in 0..u64::try_from(limit)
        .map_err(|_| "receipt limit overflow".to_owned())?
        .min(cursor.next_sequence)
    {
        let sequence = cursor.next_sequence - offset;
        let bytes = world
            .smart_contract_state()
            .get(&receipt_sequence_key(&cursor.wallet_id, sequence))
            .ok_or_else(|| {
                "authenticated receipt frontier is missing from the native sequence index"
                    .to_owned()
            })?;
        let path: StatePath = norito::decode_from_bytes(bytes)
            .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))?;
        let receipt: RetailFeeReceiptV1 =
            norito::decode_from_bytes(world.smart_contract_state().get(&path).ok_or_else(
                || "native receipt sequence index points to a missing record".to_owned(),
            )?)
            .map_err(|e| norito_decode_attempt_error(e, |e| e.to_string()))?;
        receipts.push(receipt);
    }
    let page = RetailFeeReceiptPageV1 { receipts };
    page.verify(cursor)?;
    Ok(page)
}

#[cfg(test)]
#[path = "retail_fee_resource_tests.rs"]
mod resource_tests;
