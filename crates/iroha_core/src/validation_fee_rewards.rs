//! Native fee-credit provenance, reference-price guards and funded SORA Nexus rewards.
//!
//! Only consensus fee collection, authenticated native oracle admission and the
//! exact Parliament-enacted conversion effect plan can write this state.
mod beneficiary;
mod exposure;
mod head_tree;
mod history;
mod pending;
mod reconciliation;
pub use pending::pending_fee_reward;
mod settlement;
use crate::execution_attempt::{
    ExecutionAttemptError, json_decode_attempt_error, norito_decode_attempt_error,
};
use crate::smartcontracts::Execute;
use crate::{
    state::{StateBlock, StateTransaction, WorldReadOnly},
    tx::TransactionRejectionReason,
};
pub(crate) use beneficiary::rekey_beneficiary;
#[cfg(test)]
pub(crate) use exposure::before_block as reward_exposure_before_block_for_testing;
pub(crate) use exposure::ensure_validator_capacity as ensure_reward_validator_capacity;
pub(crate) use exposure::{ensure_existing_reward_identities, ensure_reward_identity};
pub use head_tree::receipt_head_membership;
pub(crate) use head_tree::update_receipt_head_tree;
use iroha_crypto::Hash;
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    asset::{Asset, AssetId},
    isi::{Transfer, error::InstructionExecutionError as Error},
    nexus::PublicLaneFeeRewardClaimV1,
    oracle::Observation,
    validation_fee::{ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1},
    validation_fee_rewards::{
        ValidationFeeConversionAttempt, ValidationFeeReferenceObservation,
        ValidationFeeRewardAllocation, ValidationFeeRewardClaim, ValidationFeeRewardsState,
        ValidationFeeServiceSnapshot,
    },
};
use iroha_model_base::{state_path::StatePath, topology::LaneId};
use iroha_primitives::numeric::{Numeric, Quantity};
use mv::storage::StorageReadOnly;
use norito::{NoritoDeserialize, NoritoSerialize};
pub(crate) use settlement::process_reward_entitlements;
use std::collections::{BTreeMap, BTreeSet};

const PREFIX: &str = "ValidationFeeRewards";
const HONIARA_OFFSET_MS: u64 = 11 * 60 * 60 * 1000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
fn conversion_projection_map_key(index: i128) -> Result<Vec<u8>, Error> {
    use ivm_abi::state_value::{
        StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
        StateValueSchemaV1, state_value_schema_hash_v1,
    };
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Int)],
    };
    let encoded_schema = norito::to_bytes(&schema).map_err(|error| fail(error.to_string()))?;
    let envelope =
        ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from_i128(index))
            .map_err(|error| fail(error.to_string()))?;
    norito::to_bytes(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&encoded_schema),
        atoms: vec![StateValueAtomV1::Pointer(envelope)],
    })
    .map_err(|error| fail(error.to_string()))
}
fn fail(message: impl Into<String>) -> Error {
    Error::InvariantViolation(message.into().into())
}
fn rejection(error: Error) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
        "validation fee rewards: {error}"
    )))
}
fn state_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    leaf: &str,
) -> Result<StatePath, Error> {
    iroha_data_model::validation_fee_rewards::validation_fee_reward_state_key(binding, leaf)
        .map_err(fail)
}
/// Whether this key belongs to consensus-owned rewards; callers cannot forge these records.
pub(crate) fn is_reserved_state_key(key: &StatePath) -> bool {
    let mut fields = key.as_ref().split('/');
    fields.next() == Some("sc")
        && fields
            .next()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        && fields
            .next()
            .is_some_and(|leaf| leaf == PREFIX || leaf == "ValidationFeeConversion")
}
fn read_attempt<T: NoritoSerialize + for<'de> NoritoDeserialize<'de>>(
    stx: &StateTransaction<'_, '_>,
    key: &StatePath,
) -> Result<Option<T>, ExecutionAttemptError<Error>> {
    read_from_world(&stx.world, key)
}
fn read_from_world<T: NoritoSerialize + for<'de> NoritoDeserialize<'de>>(
    world: &impl WorldReadOnly,
    key: &StatePath,
) -> Result<Option<T>, ExecutionAttemptError<Error>> {
    world
        .smart_contract_state()
        .get(key)
        .map(|bytes| {
            norito::decode_from_bytes(bytes).map_err(|error| {
                norito_decode_attempt_error(error, |error| {
                    fail(format!("malformed protected rewards state: {error}"))
                })
            })
        })
        .transpose()
}
fn read<T: NoritoSerialize + for<'de> NoritoDeserialize<'de>>(
    stx: &StateTransaction<'_, '_>,
    key: &StatePath,
) -> Result<Option<T>, Error> {
    read_attempt(stx, key).map_err(|error| stx.world.attempt_error_to_instruction_error(error))
}
fn string_attempt_instruction_error(
    stx: &StateTransaction<'_, '_>,
    error: ExecutionAttemptError<String>,
) -> Error {
    stx.world
        .attempt_error_to_instruction_error(error.map_rejection(fail))
}
fn error_attempt_transaction_error(
    stx: &StateTransaction<'_, '_>,
    error: ExecutionAttemptError<TransactionRejectionReason>,
) -> TransactionRejectionReason {
    match error {
        ExecutionAttemptError::Rejected(error) => error,
        ExecutionAttemptError::Deferred(reason) => {
            TransactionRejectionReason::Validation(stx.world.defer_execution(reason))
        }
    }
}
fn write<T: NoritoSerialize>(
    stx: &mut StateTransaction<'_, '_>,
    key: StatePath,
    value: &T,
) -> Result<(), Error> {
    let bytes = norito::to_bytes(value)
        .map_err(|error| norito_decode_attempt_error(error, |error| fail(error.to_string())))
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    history::journal_write(stx, &key, &bytes)?;
    stx.world.smart_contract_state.insert(key, bytes);
    Ok(())
}
fn read_state(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<ValidationFeeRewardsState, Error> {
    Ok(read(stx, &state_key(binding, "State")?)?.unwrap_or_default())
}
fn save_state(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    state: &ValidationFeeRewardsState,
) -> Result<(), Error> {
    write(stx, state_key(binding, "State")?, state)
}
fn pending_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
) -> Result<StatePath, Error> {
    state_key(binding, &format!("Pending/{period:020}"))
}
fn service_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
) -> Result<StatePath, Error> {
    state_key(binding, &format!("Service/{period:020}"))
}
fn claimable_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    account: &AccountId,
) -> Result<StatePath, Error> {
    state_key(
        binding,
        &format!(
            "Claimable/{}",
            hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
        ),
    )
}
fn service_snapshot(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
) -> Result<ValidationFeeServiceSnapshot, Error> {
    let snapshot: ValidationFeeServiceSnapshot = read(stx, &service_key(binding, period)?)?
        .unwrap_or_else(|| ValidationFeeServiceSnapshot {
            earning_period_start_ms: period,
            service_blocks: BTreeMap::new(),
        });
    if snapshot.earning_period_start_ms != period {
        return Err(fail("reward exposure source has mismatched earning period"));
    }
    Ok(snapshot)
}
fn service_weights(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
) -> Result<BTreeMap<AccountId, u64>, Error> {
    Ok(service_snapshot(stx, binding, period)?.service_blocks)
}
/// Only the first pending month is examined. Native positive-credit records are
/// ordered by their fixed-width original ID; no lifetime map or account scan.
fn first_pending(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<Option<(u64, u64)>, Error> {
    let start = state_key(binding, "Pending/00000000000000000000")?;
    let end = state_key(binding, "Pending/99999999999999999999")?;
    let Some((key, bytes)) = stx.world.smart_contract_state.range(start..=end).next() else {
        return Ok(None);
    };
    let period = key
        .as_ref()
        .rsplit('/')
        .next()
        .ok_or_else(|| fail("malformed pending key"))?
        .parse::<u64>()
        .map_err(|_| fail("malformed pending period"))?;
    let amount: u64 = norito::decode_canonical(bytes)
        .map_err(|error| norito_decode_attempt_error(error, |error| fail(error.to_string())))
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    if amount == 0 {
        return Err(fail("zero pending credit must be pruned"));
    }
    Ok(Some((period, amount)))
}
fn active_bindings_at_height(
    stx: &StateTransaction<'_, '_>,
    height: u64,
) -> Result<Vec<ValidationFeeTreasuryPayoutBindingV1>, Error> {
    Ok(
        crate::validation_fee::active_payout_binding_at_height(stx, height)
            .map_err(|error| error.map_rejection(|error| fail(error.to_string())))
            .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?
            .into_iter()
            .collect(),
    )
}
fn active_bindings(
    stx: &StateTransaction<'_, '_>,
) -> Result<Vec<ValidationFeeTreasuryPayoutBindingV1>, Error> {
    active_bindings_at_height(stx, stx.block_height())
}
/// Derive the exact pending block corpus from applied and still-open native state.
fn collect_pending_fee_evidence_records(
    stx: &StateTransaction<'_, '_>,
) -> Result<Vec<iroha_data_model::fee_evidence::FeeEvidenceRecordV1>, ExecutionAttemptError<String>>
{
    use iroha_data_model::fee_evidence::{
        FeeEvidencePayloadV1, FeeEvidenceRecordV1, FeeRewardCustodySnapshotV1,
    };
    let height = stx.block_height();
    let custody_binding = match crate::validation_fee::active_payout_binding_at_height(stx, height)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?
    {
        Some(binding) => Some(binding),
        None => crate::validation_fee::retained_payout_custody_binding(&stx.world)?,
    };
    let mut custody = custody_binding
        .into_iter()
        .map(|binding| {
            let key = state_key(&binding, "State").map_err(|e| e.to_string())?;
            let state: ValidationFeeRewardsState = read_attempt(
                stx,
                &state_key(&binding, "State").map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.map_rejection(|error| error.to_string()))?
            .unwrap_or_default();
            let balance = |definition: &iroha_data_model::asset::AssetDefinitionId,
                           account: &AccountId|
             -> Result<u128, ExecutionAttemptError<String>> {
                let scale = stx
                    .world
                    .asset_definition(definition)
                    .map_err(|e| e.to_string())?
                    .spec()
                    .scale()
                    .ok_or_else(|| "custody asset has no fixed scale".to_owned())?;
                stx.world
                    .assets
                    .get(&AssetId::new(definition.clone(), account.clone()))
                    .map(|a| minor_units(a.as_ref(), scale).map_err(|e| e.to_string()))
                    .transpose()
                    .map(|v| v.unwrap_or(0))
                    .map_err(Into::into)
            };
            let treasury_sbd_minor = balance(&binding.ds_asset_id, &binding.treasury_account_id)?;
            let reward_pool_xor_minor =
                balance(&binding.xor_asset_id, &binding.reward_pool_account_id)?;
            let xor_scale = stx
                .world
                .asset_definition(&binding.xor_asset_id)
                .map_err(|e| e.to_string())?
                .spec()
                .scale()
                .ok_or_else(|| "XOR custody asset has no fixed scale".to_owned())?;
            Ok(FeeEvidenceRecordV1 {
                key,
                recorded_at_height: height,
                payload: FeeEvidencePayloadV1::RewardCustody(FeeRewardCustodySnapshotV1 {
                    binding,
                    state,
                    treasury_sbd_minor,
                    reward_pool_xor_minor,
                    xor_scale,
                }),
            })
        })
        .collect::<Result<Vec<_>, ExecutionAttemptError<String>>>()?;
    let registry_id =
        iroha_data_model::validation_fee::ValidationFeePolicyRegistryV1::parameter_id();
    if let Some(custom) = stx.world.parameters().custom().get(&registry_id) {
        if custom.id() != &registry_id {
            return Err(ExecutionAttemptError::Rejected(
                "protected fee registry parameter identity differs".into(),
            ));
        }
        let registry = norito::json::from_str::<
            iroha_data_model::validation_fee::ValidationFeePolicyRegistryV1,
        >(custom.payload().get())
        .map_err(|error| {
            json_decode_attempt_error(error, |error| {
                format!("protected fee registry preimage is malformed: {error}")
            })
        })?;
        custody.push(FeeEvidenceRecordV1 {
            key: "native_fee_registry_v1"
                .parse()
                .map_err(|e| format!("native registry key: {e}"))?,
            recorded_at_height: height,
            payload: FeeEvidencePayloadV1::PolicyRegistry(registry),
        });
    }
    let mut records = custody;
    for key in stx
        .world
        .smart_contract_state
        .changed_keys_in_block()
        .collect::<BTreeSet<_>>()
    {
        let text = key.as_ref();
        let receipt = text.starts_with("retail_fee_receipts_v1/");
        let head = text.starts_with("retail_fee_heads_v1/");
        let allocation = is_reserved_state_key(key) && text.contains("/Allocation/");
        let claim = is_reserved_state_key(key) && text.contains("/Claim/");
        let entitlement = is_reserved_state_key(key) && text.contains("/Entitlement/");
        let attempt = is_reserved_state_key(key) && text.contains("/Attempt/");
        let beneficiary_alias = is_reserved_state_key(key) && text.contains("/BeneficiaryAlias/");
        let beneficiary_revision =
            is_reserved_state_key(key) && text.contains("/BeneficiaryHistory/");
        if !receipt
            && !head
            && !allocation
            && !claim
            && !entitlement
            && !attempt
            && !beneficiary_alias
            && !beneficiary_revision
        {
            continue;
        }
        if stx.world.smart_contract_state.get(key).is_none()
            && history::permits_retirement(stx, key)?
        {
            continue;
        }
        if !head
            && stx
                .world
                .smart_contract_state
                .get_before_block(key)
                .is_some()
        {
            return Err(ExecutionAttemptError::Rejected(
                "immutable native fee record was rewritten".into(),
            ));
        }
        let bytes = stx
            .world
            .smart_contract_state
            .get(key)
            .ok_or_else(|| "immutable native fee record was removed".to_owned())?;
        let payload =
            if head {
                FeeEvidencePayloadV1::RetailReceiptHead(norito::decode_canonical(bytes).map_err(
                    |error| norito_decode_attempt_error(error, |error| error.to_string()),
                )?)
            } else if receipt {
                FeeEvidencePayloadV1::RetailReceipt(norito::decode_canonical(bytes).map_err(
                    |error| norito_decode_attempt_error(error, |error| error.to_string()),
                )?)
            } else if allocation {
                FeeEvidencePayloadV1::RewardAllocation(norito::decode_canonical(bytes).map_err(
                    |error| norito_decode_attempt_error(error, |error| error.to_string()),
                )?)
            } else if entitlement {
                FeeEvidencePayloadV1::RewardEntitlement(norito::decode_canonical(bytes).map_err(
                    |error| norito_decode_attempt_error(error, |error| error.to_string()),
                )?)
            } else if beneficiary_alias {
                FeeEvidencePayloadV1::RewardBeneficiaryAlias(
                    norito::decode_canonical(bytes).map_err(|error| {
                        norito_decode_attempt_error(error, |error| error.to_string())
                    })?,
                )
            } else if beneficiary_revision {
                FeeEvidencePayloadV1::RewardBeneficiaryRevision(
                    norito::decode_canonical(bytes).map_err(|error| {
                        norito_decode_attempt_error(error, |error| error.to_string())
                    })?,
                )
            } else if attempt {
                FeeEvidencePayloadV1::RewardAttempt(norito::decode_canonical(bytes).map_err(
                    |error| norito_decode_attempt_error(error, |error| error.to_string()),
                )?)
            } else {
                FeeEvidencePayloadV1::RewardClaim(norito::decode_canonical(bytes).map_err(
                    |error| norito_decode_attempt_error(error, |error| error.to_string()),
                )?)
            };
        records.push(FeeEvidenceRecordV1 {
            key: key.clone(),
            recorded_at_height: height,
            payload,
        });
    }
    // Authenticate the historical source key separately from each allocation's
    // declared weights. Only periods actually allocated in this block are copied.
    let allocated_periods = records
        .iter()
        .filter_map(|r| match &r.payload {
            FeeEvidencePayloadV1::RewardAllocation(a) => Some(a.earning_period_start_ms),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let entitlement_binding =
        match crate::validation_fee::active_payout_binding_at_height(stx, stx.block_height())
            .map_err(|error| error.map_rejection(|error| error.to_string()))?
        {
            Some(binding) => Some(binding),
            None => crate::validation_fee::retained_payout_custody_binding(&stx.world)?,
        };
    if let Some(binding) = entitlement_binding {
        let entitlements = records
            .iter()
            .filter_map(|record| match &record.payload {
                FeeEvidencePayloadV1::RewardEntitlement(value) => Some(value.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut included = records
            .iter()
            .map(|record| record.key.clone())
            .collect::<BTreeSet<_>>();
        for entitlement in entitlements {
            let allocation_key = state_key(
                &binding,
                &format!("Allocation/{}", entitlement.allocation_sequence),
            )
            .map_err(|error| error.to_string())?;
            let allocation = read_attempt::<ValidationFeeRewardAllocation>(stx, &allocation_key)
                .map_err(|error| error.map_rejection(|error| error.to_string()))?
                .ok_or_else(|| {
                    ExecutionAttemptError::Rejected(
                        "entitlement allocation source is absent".to_owned(),
                    )
                })?;
            let page_key = exposure::page_key(
                &binding,
                allocation.earning_period_start_ms,
                &entitlement.validator,
                entitlement.page_index,
            )
            .map_err(|error| error.to_string())?;
            if included.insert(page_key.clone()) {
                let source_key = exposure::source_key(
                    &binding,
                    height,
                    &entitlement.validator,
                    entitlement.page_index,
                )
                .map_err(|error| error.to_string())?;
                let page = read_attempt(stx, &source_key)
                    .map_err(|error| error.map_rejection(|error| error.to_string()))?
                    .ok_or_else(|| {
                        ExecutionAttemptError::Rejected(
                            "entitlement exposure source is absent".to_owned(),
                        )
                    })?;
                records.push(FeeEvidenceRecordV1 {
                    key: page_key,
                    recorded_at_height: height,
                    payload: FeeEvidencePayloadV1::RewardExposure(page),
                });
            }
            if included.insert(allocation_key.clone()) {
                records.push(FeeEvidenceRecordV1 {
                    key: allocation_key,
                    recorded_at_height: height,
                    payload: FeeEvidencePayloadV1::RewardAllocationSource(allocation),
                });
            }
        }
        for period in &allocated_periods {
            records.push(FeeEvidenceRecordV1 {
                key: service_key(&binding, *period).map_err(|e| e.to_string())?,
                recorded_at_height: height,
                payload: FeeEvidencePayloadV1::RewardService(
                    read_attempt::<ValidationFeeServiceSnapshot>(
                        stx,
                        &service_key(&binding, *period).map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.map_rejection(|error| error.to_string()))?
                    .ok_or_else(|| {
                        ExecutionAttemptError::Rejected(
                            "allocated historical reward exposure is absent".to_owned(),
                        )
                    })?,
                ),
            });
        }
    }
    beneficiary::append_evidence_sources(stx, &mut records)?;
    records.sort_by(|a, b| a.key.cmp(&b.key));
    if records
        .iter()
        .any(|r| r.recorded_at_height != height || !r.is_valid())
        || records.windows(2).any(|w| w[0].key >= w[1].key)
    {
        return Err(ExecutionAttemptError::Rejected(
            "invalid or oversized pending native fee corpus".into(),
        ));
    }
    Ok(records)
}

fn pending_fee_evidence_records(
    stx: &StateTransaction<'_, '_>,
) -> Result<Vec<iroha_data_model::fee_evidence::FeeEvidenceRecordV1>, ExecutionAttemptError<String>>
{
    let records = collect_pending_fee_evidence_records(stx)?;
    if records.len() > iroha_data_model::fee_evidence::MAX_FEE_EVIDENCE_RECORDS_V1 as usize {
        return Err(
            "candidate fee accounting exceeds the durable per-block record budget"
                .to_owned()
                .into(),
        );
    }
    Ok(records)
}
/// Reject oversized candidate accounting effects before accepting their transaction.
/// Size includes the actual current registry/custody snapshots and the fixed SMT path.
pub(crate) fn validate_pending_fee_evidence_budget(
    stx: &StateTransaction<'_, '_>,
) -> Result<(), ExecutionAttemptError<String>> {
    if !pending_fee_evidence_fits(stx)? {
        return Err(
            "candidate fee accounting exceeds the durable per-block evidence budget"
                .to_owned()
                .into(),
        );
    }
    Ok(())
}

/// Separate deterministic capacity backpressure from malformed state and original
/// local read refusals. Only optional conversion offers may wait for more room.
fn pending_fee_evidence_fits(
    stx: &StateTransaction<'_, '_>,
) -> Result<bool, ExecutionAttemptError<String>> {
    use iroha_data_model::fee_evidence::{
        FEE_EVIDENCE_WITNESS_KEY_V1, FeeEvidenceBlockProofV1, FeeEvidenceSnapshotV1,
        FeeEvidenceWitnessProofV1, MAX_FEE_EVIDENCE_BLOCK_BYTES_V1,
    };
    let records = collect_pending_fee_evidence_records(stx)?;
    if records.len() > iroha_data_model::fee_evidence::MAX_FEE_EVIDENCE_RECORDS_V1 as usize {
        return Ok(false);
    }
    // The commitment hash has fixed wire length. Budgeting must not rebuild a
    // Merkle tree for every candidate; the real root is computed once at capture.
    let snapshot = FeeEvidenceSnapshotV1 {
        version: 1,
        evaluated_height: stx.block_height(),
        root: Hash::new([]),
        account_heads_root: head_tree::receipt_head_root(&stx.world)?,
        count: u32::try_from(records.len()).map_err(|_| "fee corpus count overflow".to_owned())?,
    };
    let proof = FeeEvidenceBlockProofV1 {
        snapshot_witness: FeeEvidenceWitnessProofV1 {
            key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
            value: norito::to_bytes(&snapshot)
                .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?,
            siblings: vec![Hash::new([]); 256],
        },
        records,
    };
    if norito::to_bytes(&proof)
        .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?
        .len()
        > MAX_FEE_EVIDENCE_BLOCK_BYTES_V1
    {
        return Ok(false);
    }
    Ok(true)
}
/// Capture complete block-owned native fee records after successful application.
pub(crate) fn capture_fee_evidence(
    block: &mut StateBlock<'_>,
    witness: &mut iroha_data_model::block::consensus::ExecWitness,
) -> Result<(), crate::state::WitnessCaptureError> {
    use iroha_data_model::{
        block::consensus::ExecKv,
        execution_witness::{FEE_EVIDENCE_RECORD_TAG_V1, FEE_EVIDENCE_WITNESS_KEY_V1},
        fee_evidence::FeeEvidenceSnapshotV1,
    };
    let (height, records) = {
        let stx = block
            .consensus_effects_transaction()
            .map_err(crate::state::WitnessCaptureError::StorageAdmission)?;
        validate_pending_fee_evidence_budget(&stx)?;
        (stx.block_height(), pending_fee_evidence_records(&stx)?)
    };
    exposure::capture_archive(block, witness)?;
    let mut snapshot = FeeEvidenceSnapshotV1::from_records(height, &records)?;
    snapshot.account_heads_root = head_tree::receipt_head_root(&block.world)?;
    // Reserved synthetic writes are always derived here from native post-block state.
    // Never accept a contract recorder's preexisting value for either family.
    witness.writes.retain(|entry| {
        entry.key.as_slice() != FEE_EVIDENCE_WITNESS_KEY_V1
            && entry.key.first() != Some(&FEE_EVIDENCE_RECORD_TAG_V1)
    });
    for record in records {
        let mut key = vec![FEE_EVIDENCE_RECORD_TAG_V1];
        key.extend_from_slice(Hash::new(record.key.as_ref().as_bytes()).as_ref());
        witness.writes.push(ExecKv {
            key,
            value: norito::to_bytes(&record)
                .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?,
        });
    }
    witness.writes.push(ExecKv {
        key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
        value: norito::to_bytes(&snapshot)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?,
    });
    Ok(())
}

/// UTC instant at the start of the containing Honiara calendar month.
pub(crate) fn earning_month(timestamp_ms: u64) -> Result<u64, Error> {
    let utc = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp_ms) * 1_000_000)
        .map_err(|_| fail("block timestamp is outside calendar range"))?;
    let local = utc.to_offset(
        time::UtcOffset::from_hms(11, 0, 0).map_err(|_| fail("invalid Honiara offset"))?,
    );
    let start = time::Date::from_calendar_date(local.year(), local.month(), 1)
        .map_err(|_| fail("invalid billing month"))?
        .midnight()
        .assume_offset(local.offset());
    u64::try_from(start.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| fail("billing month before epoch"))
}
/// Record collected maintenance or overage with its original earning month.
/// Waived fees and arbitrary treasury deposits must never call this hook.
pub(crate) fn credit_collected_fee(
    stx: &mut StateTransaction<'_, '_>,
    policy: &ValidationFeePolicyV1,
    earning_period_start_ms: u64,
    collected_minor: u64,
) -> Result<(), TransactionRejectionReason> {
    if collected_minor == 0 {
        return Ok(());
    }
    crate::retail_fee::ensure_reward_history_open(&stx.world, earning_period_start_ms)
        .map_err(|error| string_attempt_instruction_error(stx, error))
        .map_err(rejection)?;
    let binding = crate::validation_fee::active_payout_binding_at_height(stx, stx.block_height())
        .map_err(|error| {
            error_attempt_transaction_error(
                stx,
                error.map_rejection(crate::validation_fee::admission_rejection),
            )
        })?
        .ok_or_else(|| {
            rejection(fail(
                "collected fee has no finalized Parliament conversion policy",
            ))
        })?;
    if binding.custody() != policy.reward_custody {
        return Err(rejection(fail(
            "collected fee custody differs from the conversion policy",
        )));
    }
    let binding = &binding;
    let result = (|| {
        let mut state = read_state(stx, binding)?;
        let key = pending_key(binding, earning_period_start_ms)?;
        let credit = read::<u64>(stx, &key)?
            .unwrap_or(0)
            .checked_add(collected_minor)
            .ok_or_else(|| fail("SBD fee credit overflow"))?;
        state.pending_sbd_total = state
            .pending_sbd_total
            .checked_add(u128::from(collected_minor))
            .ok_or_else(|| fail("total SBD fee credit overflow"))?;
        write(stx, key, &credit)?;
        save_state(stx, binding, &state)
    })();
    result.map_err(rejection)
}
/// Retain native observations only after the ordinary oracle handler verified
/// provider authorization, signature, feed version, slot and replay constraints.
pub(crate) fn retain_authenticated_observation(
    stx: &mut StateTransaction<'_, '_>,
    observation: &Observation,
) -> Result<(), Error> {
    for binding in active_bindings(stx)? {
        if observation.body.feed_id != binding.reference_feed_id
            || observation.body.feed_config_version.0 != binding.reference_feed_config_version
            || !binding
                .reference_provider_accounts
                .contains(&observation.body.provider_id)
        {
            continue;
        }
        let Some(timestamp) = observation.body.timestamp_ms else {
            continue;
        };
        let now = stx.block_unix_timestamp_ms();
        if timestamp > now || now - timestamp > binding.max_source_age_ms {
            continue;
        }
        let record = ValidationFeeReferenceObservation {
            observation: observation.clone(),
            admitted_height: stx.block_height(),
            admitted_at_ms: now,
        };
        iroha_data_model::validation_fee_rewards::validate_reference_observation_bytes(&record)
            .map_err(fail)?;
        let leaf = format!(
            "Oracle/{}",
            hex::encode(Hash::new(observation.body.provider_id.to_string().as_bytes()).as_ref())
        );
        write(stx, state_key(&binding, &leaf)?, &record)?;
    }
    Ok(())
}
/// A reference-price-guarded, unconsumed conversion offer from one earning month.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConversionOffer {
    pub(crate) earning_period_start_ms: u64,
    pub(crate) sbd_minor: u64,
    pub(crate) min_xor_minor: u128,
    pub(crate) sequence: u64,
}
fn reference_minimum(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    records: &[ValidationFeeReferenceObservation],
    now: u64,
    height: u64,
    sbd_minor: u64,
    xor_scale: u32,
) -> Result<Option<u128>, Error> {
    iroha_data_model::validation_fee_rewards::reference_minimum(
        binding, records, now, height, sbd_minor, xor_scale,
    )
    .map_err(fail)
}
/// Quote only mature fee credits, a complete historical service roster and a
/// fresh quorum of prior-block signed source observations. Missing evidence is a no-op.
pub(crate) fn conversion_offer(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<Option<ConversionOffer>, Error> {
    crate::state::validate_network_xor_asset(&stx.world, &binding.xor_asset_id)
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    if let Some(reason) = binding.invariant_error() {
        return Err(fail(reason));
    }
    let state = read_state(stx, binding)?;
    if read::<settlement::RewardAllocationCursor>(stx, &state_key(binding, "AllocationCursor")?)?
        .is_some()
    {
        return Ok(None);
    }
    let now = stx.block_unix_timestamp_ms();
    if state.service_height != stx.block_height().saturating_sub(1) {
        return Ok(None);
    }
    if state
        .last_conversion_ms
        .is_some_and(|last| now < last || now - last < binding.min_interval_ms)
    {
        return Ok(None);
    }
    if state.last_attempt_height != stx.block_height()
        && state
            .last_attempt_ms
            .is_some_and(|last| now < last || now - last < binding.min_interval_ms)
    {
        return Ok(None);
    }
    let day = now.saturating_add(HONIARA_OFFSET_MS) / DAY_MS;
    let used = if day == state.conversion_day {
        state.converted_today_sbd
    } else {
        0
    };
    let remaining = binding.max_sbd_per_day_minor.saturating_sub(used);
    let current_month = earning_month(now)?;
    let Some((period, pending)) = first_pending(stx, binding)? else {
        return Ok(None);
    };
    if period >= current_month
        || !service_weights(stx, binding, period)?
            .values()
            .any(|w| *w > 0)
    {
        return Ok(None);
    }
    let amount = pending
        .min(binding.max_sbd_per_attempt_minor)
        .min(remaining);
    if amount == 0 {
        return Ok(None);
    }
    let mut records = Vec::new();
    for account in &binding.reference_provider_accounts {
        let leaf = format!(
            "Oracle/{}",
            hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
        );
        if let Some(record) = read(stx, &state_key(binding, &leaf)?)? {
            records.push(record);
        }
    }
    let Some(min_xor_minor) =
        reference_minimum(binding, &records, now, stx.block_height(), amount, 9)?
    else {
        return Ok(None);
    };
    Ok(Some(ConversionOffer {
        earning_period_start_ms: period,
        sbd_minor: amount,
        min_xor_minor,
        sequence: state.next_allocation,
    }))
}
/// Divide every XOR minor unit using historical service counts. Largest
/// fractional remainders win, with canonical account order breaking ties.
#[cfg(test)]
fn allocate(
    amount: u128,
    weights: &BTreeMap<AccountId, u64>,
) -> Result<BTreeMap<AccountId, u128>, Error> {
    iroha_data_model::validation_fee_rewards::allocate(amount, weights).map_err(fail)
}
/// Consume authenticated SBD credit and reserve the exact actual XOR output in
/// the same overlay as the verified three-transfer conversion effect plan.
pub(crate) fn reserve_conversion(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    offer: &ConversionOffer,
    xor_minor: u128,
) -> Result<(), Error> {
    crate::state::validate_network_xor_asset(&stx.world, &binding.xor_asset_id)
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    let reward_asset = AssetId::new(
        binding.xor_asset_id.clone(),
        binding.reward_pool_account_id.clone(),
    );
    let before = stx
        .world
        .assets
        .get(&reward_asset)
        .map_or_else(Quantity::zero, |value| value.as_ref().clone());
    crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
        &stx.world,
        &reward_asset,
        &before,
    )
    .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    let mut state = read_state(stx, binding)?;
    if state.next_allocation != offer.sequence || xor_minor < offer.min_xor_minor {
        return Err(fail(
            "stale conversion allocation or insufficient XOR output",
        ));
    }
    if read::<settlement::RewardAllocationCursor>(stx, &state_key(binding, "AllocationCursor")?)?
        .is_some()
    {
        return Err(fail("previous funded reward allocation is still accruing"));
    }
    let source = service_snapshot(stx, binding, offer.earning_period_start_ms)?;
    let gross_shares =
        iroha_data_model::validation_fee_rewards::allocate(xor_minor, &source.service_blocks)
            .map_err(fail)?;
    let now = stx.block_unix_timestamp_ms();
    let receipt = ValidationFeeRewardAllocation {
        sequence: offer.sequence,
        lifecycle_seal: binding.lifecycle_seal().map_err(|e| fail(e.to_string()))?,
        earning_period_start_ms: offer.earning_period_start_ms,
        sbd_minor: offer.sbd_minor,
        xor_minor,
        converted_at_height: stx.block_height(),
        converted_at_ms: now,
        min_xor_minor: offer.min_xor_minor,
        reference_observations: reference_observations(stx, binding)?,
        service_blocks: source.service_blocks,
        gross_shares,
    };
    // A funded source is copied into every mandatory page proof. Refuse an
    // oversized optional conversion before changing credits, reserves or cursors.
    iroha_data_model::validation_fee_rewards::validate_allocation_bytes(&receipt).map_err(fail)?;
    let key = pending_key(binding, offer.earning_period_start_ms)?;
    let pending = read::<u64>(stx, &key)?
        .ok_or_else(|| fail("missing conversion credit"))?
        .checked_sub(offer.sbd_minor)
        .ok_or_else(|| fail("insufficient authenticated conversion credit"))?;
    if pending == 0 {
        stx.world.smart_contract_state.remove(key);
    } else {
        write(stx, key, &pending)?;
    }
    state.pending_sbd_total = state
        .pending_sbd_total
        .checked_sub(u128::from(offer.sbd_minor))
        .ok_or_else(|| fail("total conversion credit underflow"))?;
    state.reserved_xor = state
        .reserved_xor
        .checked_add(xor_minor)
        .ok_or_else(|| fail("reserved balance overflow"))?;
    state.next_allocation = state
        .next_allocation
        .checked_add(1)
        .ok_or_else(|| fail("allocation sequence exhausted"))?;
    let day = now.saturating_add(HONIARA_OFFSET_MS) / DAY_MS;
    if state.conversion_day != day {
        state.conversion_day = day;
        state.converted_today_sbd = 0;
    }
    state.converted_today_sbd = state
        .converted_today_sbd
        .checked_add(offer.sbd_minor)
        .ok_or_else(|| fail("daily conversion counter overflow"))?;
    state.last_conversion_ms = Some(now);
    let key = state_key(binding, &format!("Allocation/{}", offer.sequence))?;
    if stx.world.smart_contract_state.get(&key).is_some() {
        return Err(fail("duplicate allocation identity"));
    }
    write(stx, key, &receipt)?;
    write(
        stx,
        state_key(binding, "AllocationCursor")?,
        &settlement::RewardAllocationCursor {
            allocation_sequence: offer.sequence,
            validator_index: 0,
            page_index: 0,
            service_offset: 0,
            credited_xor: 0,
            next_archive: None,
        },
    )?;
    save_state(stx, binding, &state)
}
/// Convert exact asset minor units without rounding.
pub(crate) fn minor_units(amount: &Quantity, scale: u32) -> Result<u128, Error> {
    if amount.scale() > scale || scale > 18 {
        return Err(fail("asset quantity is not exact minor units"));
    }
    amount
        .as_numeric()
        .try_mantissa_u128()
        .and_then(|v| v.checked_mul(10u128.pow(scale - amount.scale())))
        .ok_or_else(|| fail("asset quantity overflow"))
}
/// Construct an exact nonnegative asset quantity.
pub(crate) fn quantity(amount: u128, scale: u32) -> Result<Quantity, Error> {
    Quantity::from_canonical_numeric(
        Numeric::try_new(amount, scale).map_err(|e| fail(e.to_string()))?,
    )
    .map_err(|e| fail(e.to_string()))
}
/// Read one exact global custody obligation from the immutable authenticated registry.
/// Every lifecycle retains the same state key, so this counts the ledger once.
pub(crate) fn reserved_fee_custody(
    world: &impl WorldReadOnly,
    asset: &AssetId,
) -> Result<Quantity, ExecutionAttemptError<Error>> {
    let Some(binding) = crate::validation_fee::retained_payout_custody_binding(world)
        .map_err(|error| error.map_rejection(fail))?
    else {
        return Ok(Quantity::zero());
    };
    let reward = asset
        == &AssetId::new(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
        );
    let treasury = asset
        == &AssetId::new(
            binding.ds_asset_id.clone(),
            binding.treasury_account_id.clone(),
        );
    if !reward && !treasury {
        return Ok(Quantity::zero());
    }
    let state =
        read_from_world::<ValidationFeeRewardsState>(world, &state_key(&binding, "State")?)?
            .unwrap_or_default();
    let reserved = if reward {
        state.reserved_xor
    } else {
        state.pending_sbd_total
    };
    if reserved == 0 {
        return Ok(Quantity::zero());
    }
    let scale = world
        .asset_definition(asset.definition())
        .map_err(Error::from)?
        .spec()
        .scale()
        .ok_or_else(|| fail("fee custody asset has no fixed scale"))?;
    quantity(reserved, scale).map_err(Into::into)
}

/// Reconcile historical reward and retail frontier sources only during restoration.
pub(crate) fn validate_fee_reward_history(
    world: &impl WorldReadOnly,
) -> Result<(), ExecutionAttemptError<Error>> {
    crate::retail_fee::validate_reward_history_frontier(world)
        .map_err(|error| error.map_rejection(fail))?;
    if let Some(binding) = crate::validation_fee::retained_payout_custody_binding(world)
        .map_err(|error| error.map_rejection(fail))?
    {
        reconciliation::validate(world, &binding)?;
    }
    Ok(())
}

/// Check the two current custody balances against their additive indexed reserves.
/// Election uses this bounded check without rescanning historical reward receipts.
pub(crate) fn validate_fee_custody_backing(
    world: &impl WorldReadOnly,
) -> Result<(), ExecutionAttemptError<Error>> {
    let Some(binding) = crate::validation_fee::retained_payout_custody_binding(world)
        .map_err(|error| error.map_rejection(fail))?
    else {
        return Ok(());
    };
    for asset in [
        AssetId::new(binding.xor_asset_id, binding.reward_pool_account_id),
        AssetId::new(binding.ds_asset_id, binding.treasury_account_id),
    ] {
        let balance = world
            .assets()
            .get(&asset)
            .map_or_else(Quantity::zero, |value| value.as_ref().clone());
        crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
            world, &asset, &balance,
        )?;
    }
    Ok(())
}

/// Keep a reward lane available while funded claims or historical earnings remain.
pub(crate) fn unsettled_reward_lane(
    world: &impl WorldReadOnly,
    lanes: &BTreeSet<LaneId>,
) -> Result<Option<LaneId>, ExecutionAttemptError<String>> {
    let Some(binding) = crate::validation_fee::retained_payout_custody_binding(world)? else {
        return Ok(None);
    };
    if !lanes.contains(&binding.validator_lane_id) {
        return Ok(None);
    }
    let key = state_key(&binding, "State").map_err(|error| error.to_string())?;
    let state = read_from_world::<ValidationFeeRewardsState>(world, &key)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?
        .unwrap_or_default();
    let exposure = state_key(&binding, "Exposure/").map_err(|error| error.to_string())?;
    let has_history = world
        .smart_contract_state()
        .range(exposure.clone()..)
        .next()
        .is_some_and(|(key, _)| key.as_ref().starts_with(exposure.as_ref()));
    Ok(
        (state.pending_sbd_total != 0 || state.reserved_xor != 0 || has_history)
            .then_some(binding.validator_lane_id),
    )
}

/// Preserve the sum of fee proceeds, funded rewards and stake before any debit.
pub(crate) fn ensure_reward_custody_debit(
    stx: &StateTransaction<'_, '_>,
    asset: &AssetId,
    amount: &Quantity,
) -> Result<(), Error> {
    let balance = stx
        .world
        .assets
        .get(asset)
        .map_or_else(Quantity::zero, |value| value.as_ref().clone());
    let after = balance
        .checked_sub(amount)
        .map_err(|_| fail("insufficient fee custody balance"))?;
    crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
        &stx.world, asset, &after,
    )
    .map_err(|error| stx.world.attempt_error_to_instruction_error(error))
}
/// One exact fee payment preflighted before any reward claim mutation.
pub(crate) struct PreparedFeeRewardClaim {
    binding: ValidationFeeTreasuryPayoutBindingV1,
    plan: PublicLaneFeeRewardClaimV1,
    credit_key: StatePath,
    receipt_key: StatePath,
    state_after: ValidationFeeRewardsState,
    amount_minor: u128,
}

/// Resolve a single eligible fee credit from the same committed view as other claim inputs.
pub(crate) fn fee_reward_claim_plan(
    world: &impl WorldReadOnly,
    height: u64,
    account: &AccountId,
    lane: LaneId,
) -> Result<Option<PublicLaneFeeRewardClaimV1>, ExecutionAttemptError<Error>> {
    observed_fee_reward_claim(world, height, account, lane)
        .map(|claim| claim.map(|claim| claim.plan))
}

fn observed_fee_reward_claim(
    world: &impl WorldReadOnly,
    height: u64,
    account: &AccountId,
    lane: LaneId,
) -> Result<Option<PreparedFeeRewardClaim>, ExecutionAttemptError<Error>> {
    let Some(binding) =
        crate::validation_fee::active_payout_binding_in_world_at_height(world, height)
            .map_err(|error| error.map_rejection(|error| fail(error.to_string())))?
            .filter(|binding| binding.validator_lane_id == lane)
    else {
        return Ok(None);
    };
    let original = beneficiary::root_in_world(world, &binding, account)?;
    let credit_key = claimable_key(&binding, &original)?;
    let amount_minor = read_from_world::<u128>(world, &credit_key)?.unwrap_or(0);
    if amount_minor == 0 || amount_minor < u128::from(binding.min_reward_claim_xor_minor) {
        return Ok(None);
    }
    crate::state::validate_network_xor_asset(world, &binding.xor_asset_id)?;
    let owner = beneficiary::owner_in_world(world, &binding, &original)?
        .ok_or_else(|| fail("reserved claim has no authenticated beneficiary owner"))?;
    if owner.account_id != *account {
        return Err(fail("claimant is not the current recovered reward beneficiary").into());
    }
    let source_asset = AssetId::new(
        binding.xor_asset_id.clone(),
        binding.reward_pool_account_id.clone(),
    );
    let rewards_state_key = state_key(&binding, "State")?;
    let mut state_after = read_from_world::<ValidationFeeRewardsState>(world, &rewards_state_key)?
        .unwrap_or_default();
    let balance = world
        .assets()
        .get(&source_asset)
        .map(|value| minor_units(value.as_ref(), 9))
        .transpose()?
        .unwrap_or(0);
    if balance < state_after.reserved_xor {
        return Err(fail("validator rewards custody is underfunded").into());
    }
    crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
        world,
        &source_asset,
        &quantity(balance, 9)?,
    )?;
    let plan = PublicLaneFeeRewardClaimV1 {
        lifecycle_seal: binding
            .lifecycle_seal()
            .map_err(|error| fail(error.to_string()))?,
        beneficiary_id: original,
        beneficiary_revision: owner.revision,
        source_asset,
        destination_asset: AssetId::new(binding.xor_asset_id.clone(), account.clone()),
        amount: quantity(amount_minor, 9)?,
        expected_claim_sequence: state_after.next_claim,
    };
    if !plan.has_canonical_shape(account) {
        return Err(fail("fee reward claim does not name canonical custody assets").into());
    }
    let receipt_key = state_key(&binding, &format!("Claim/{}", state_after.next_claim))?;
    if world.smart_contract_state().get(&receipt_key).is_some() {
        return Err(fail("duplicate reward claim receipt").into());
    }
    state_after.reserved_xor = state_after
        .reserved_xor
        .checked_sub(amount_minor)
        .ok_or_else(|| fail("reward claim exceeds reservation"))?;
    state_after.next_claim = state_after
        .next_claim
        .checked_add(1)
        .ok_or_else(|| fail("claim sequence exhausted"))?;
    Ok(Some(PreparedFeeRewardClaim {
        binding,
        plan,
        credit_key,
        receipt_key,
        state_after,
        amount_minor,
    }))
}

/// Authenticate every signed claim field before changing any reward or reserve state.
pub(crate) fn prepare_fee_reward_claim(
    stx: &StateTransaction<'_, '_>,
    account: &AccountId,
    lane: LaneId,
    signed: &PublicLaneFeeRewardClaimV1,
) -> Result<PreparedFeeRewardClaim, Error> {
    let claim = observed_fee_reward_claim(&stx.world, stx.block_height(), account, lane)
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?
        .ok_or_else(|| fail("signed fee reward claim has no eligible reserved credit"))?;
    if !cfg!(all(test, sumeragi_core_mutation = "HC55")) && signed != &claim.plan {
        return Err(fail(
            "fee reward claim differs from its exact current signed monetary plan",
        ));
    }
    Ok(claim)
}

/// Apply only the independently verified exact fee reward claim in the caller's transaction.
pub(crate) fn claim_fee_rewards(
    stx: &mut StateTransaction<'_, '_>,
    claim: PreparedFeeRewardClaim,
) -> Result<(), Error> {
    let PreparedFeeRewardClaim {
        binding,
        plan,
        credit_key,
        receipt_key,
        state_after,
        amount_minor,
    } = claim;
    let receipt = ValidationFeeRewardClaim {
        beneficiary_id: plan.beneficiary_id,
        beneficiary_revision: plan.beneficiary_revision,
        sequence: plan.expected_claim_sequence,
        account_id: plan.destination_asset.account().clone(),
        xor_minor: amount_minor,
        claimed_at_height: stx.block_height(),
        claimed_at_ms: stx.block_unix_timestamp_ms(),
        lifecycle_seal: plan.lifecycle_seal,
    };
    // All credit, sequence, custody and owner checks completed before the public
    // claim's first mutation. Failure here rejects the whole enclosing transaction.
    write(stx, receipt_key, &receipt)?;
    stx.world.smart_contract_state.remove(credit_key);
    save_state(stx, &binding, &state_after)?;
    Transfer::<Asset, Quantity, iroha_data_model::account::Account>::asset_quantity(
        plan.source_asset,
        plan.amount,
        plan.destination_asset.account().clone(),
    )
    .execute(&binding.reward_pool_account_id, stx)?;
    validate_pending_fee_evidence_budget(stx)
        .map_err(|error| string_attempt_instruction_error(stx, error))?;
    Ok(())
}
/// Fold only the current proposal's authenticated parent participation once.
/// Local certificates are not read by this consensus mutation owner.
pub(crate) fn process_finalized_service(
    block: &mut StateBlock<'_>,
    proposal: &iroha_data_model::block::SignedBlock,
    parent: Option<&crate::sumeragi::certified_chain::VerifiedParentService>,
) -> Result<(), crate::state::ExecutionOutputAttemptError> {
    // The current block may remove or rebind validators before time triggers.
    // Resolve previous-block service using the exact pre-block staking records.
    let keys: BTreeSet<_> = block
        .world
        .public_lane_validators
        .iter()
        .map(|(key, _)| key.clone())
        .chain(
            block
                .world
                .public_lane_validators
                .revert_map()
                .keys()
                .cloned(),
        )
        .collect();
    let prior_validators: Vec<_> = keys
        .into_iter()
        .filter_map(|key| {
            block
                .world
                .public_lane_validators
                .get_before_block(&key)
                .filter(|record| {
                    parent.is_some_and(|service| {
                        record.validator == key.1
                            && record.lane_id == key.0
                            && service.signers().contains(&record.peer_id)
                            && record.activation_height <= service.height()
                            && record
                                .deactivation_height
                                .is_none_or(|end| service.height() < end)
                    })
                })
                .cloned()
                .map(|record| (key, record))
        })
        .collect();
    let mut serviced_validators = BTreeMap::<LaneId, BTreeSet<AccountId>>::new();
    for ((lane, account), _) in &prior_validators {
        serviced_validators
            .entry(*lane)
            .or_default()
            .insert(account.clone());
    }
    let prior_stakes = exposure::before_block(block, &serviced_validators).map_err(|error| {
        crate::state::ExecutionOutputAttemptError::Owner(format!(
            "validation fee reward exposure capture failed: {error}"
        ))
    })?;
    let mut stx = block.try_transaction()?;
    let result = (|| -> Result<(), Error> {
        let height = stx.block_height().saturating_sub(1);
        let active = active_bindings_at_height(&stx, height)?;
        if active.is_empty() || height <= 1 {
            return Ok(());
        }
        let parent =
            parent.ok_or_else(|| fail("authenticated proposal parent service is absent"))?;
        parent
            .require_proposal(proposal)
            .map_err(|error| fail(error.to_string()))?;
        if parent.height() != height {
            return Err(fail(
                "service height differs from authenticated proposal parent",
            ));
        }
        let period = earning_month(parent.timestamp_ms())?;
        for binding in active {
            let mut state = read_state(&stx, &binding)?;
            if state.service_height != 0
                && state.service_height != height.saturating_sub(1)
                && state.service_height != height
            {
                return Err(fail("fee reward service history is not contiguous"));
            }
            if state.service_height == height {
                continue;
            }
            if state.service_height != 0 && state.service_height.checked_add(1) != Some(height) {
                return Err(fail(
                    "validator service history has a gap; conversion remains pending",
                ));
            }
            let owner_lane = stx
                .staking_authority_lane(binding.validator_lane_id)
                .ok_or_else(|| fail("reward lane lacks staking authority"))?;
            let mut accounts = BTreeSet::new();
            for peer in parent.signers() {
                for ((lane, account), validator) in &prior_validators {
                    if *lane == owner_lane
                        && validator.validator == *account
                        && validator.lane_id == *lane
                        && validator.peer_id == *peer
                        && validator.activation_height <= height
                        && validator.deactivation_height.is_none_or(|end| height < end)
                    {
                        accounts.insert(account.clone());
                    }
                }
            }
            let mut snapshot = service_snapshot(&stx, &binding, period)?;
            for account in accounts {
                let stakes = prior_stakes
                    .get(&(owner_lane, account.clone()))
                    .cloned()
                    .unwrap_or_default();
                let original = beneficiary::root(&stx, &binding, &account)?;
                exposure::record_service(&mut stx, &binding, period, &original, stakes)?;
                let count = snapshot.service_blocks.entry(original).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| fail("validator service counter overflow"))?;
            }
            write(&mut stx, service_key(&binding, period)?, &snapshot)?;
            state.service_height = height;
            save_state(&mut stx, &binding, &state)?;
        }
        validate_pending_fee_evidence_budget(&stx)
            .map_err(|error| string_attempt_instruction_error(&stx, error))?;
        Ok(())
    })();
    finish_reward_maintenance(stx, result)
}

fn reference_observations(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<Vec<ValidationFeeReferenceObservation>, Error> {
    binding
        .reference_provider_accounts
        .iter()
        .map(|account| {
            let leaf = format!(
                "Oracle/{}",
                hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
            );
            read(stx, &state_key(binding, &leaf)?)
        })
        .collect::<Result<Vec<Option<ValidationFeeReferenceObservation>>, Error>>()
        .map(|v| v.into_iter().flatten().collect())
}
/// Refresh read-only conversion quantities before any scheduled contract execution.
///
/// # Errors
/// Original local execution or State storage refusal remains typed through the Time owner.
/// Completed preparation failures stop Time matching before stale projections can be used.
pub(crate) fn publish_conversion_offers(
    block: &mut StateBlock<'_>,
) -> Result<(), crate::state::ExecutionOutputAttemptError> {
    let mut stx = block.try_transaction()?;
    let result = prepare_conversion_projections(&mut stx, true);
    if result.is_err() {
        return finish_reward_maintenance(stx, result);
    }
    let fits = pending_fee_evidence_fits(&stx);
    stx.require_storage_admission()?;
    if let Some(reason) = stx.execution_deferral() {
        return Err(crate::state::ExecutionOutputAttemptError::Deferred(reason));
    }
    match fits {
        Ok(true) => finish_reward_maintenance(stx, Ok(())),
        Err(error) => {
            let error = string_attempt_instruction_error(&stx, error);
            finish_reward_maintenance(stx, Err(error))
        }
        Ok(false) => {
            // A full valid block postpones this optional attempt. Discard its
            // receipt and rate-limit mutations, then clear any stale projection
            // atomically. Malformed state or original local refusals never use
            // this capacity-only path.
            drop(stx);
            let mut stx = block.try_transaction()?;
            let result = prepare_conversion_projections(&mut stx, false).and_then(|()| {
                validate_pending_fee_evidence_budget(&stx)
                    .map_err(|error| string_attempt_instruction_error(&stx, error))
            });
            finish_reward_maintenance(stx, result)
        }
    }
}

fn prepare_conversion_projections(
    stx: &mut StateTransaction<'_, '_>,
    allow_offers: bool,
) -> Result<(), Error> {
    for binding in active_bindings(stx)? {
        let scale = 9;
        let offer = if allow_offers {
            conversion_offer(stx, &binding)?
        } else {
            None
        };
        if let Some(offer) = &offer {
            let key = state_key(&binding, &format!("Attempt/{}", stx.block_height()))?;
            if stx.world.smart_contract_state.get(&key).is_some() {
                return Err(fail("duplicate native conversion attempt"));
            }
            let attempt = ValidationFeeConversionAttempt {
                attempted_at_height: stx.block_height(),
                attempted_at_ms: stx.block_unix_timestamp_ms(),
                earning_period_start_ms: offer.earning_period_start_ms,
                sbd_minor: offer.sbd_minor,
                min_xor_minor: offer.min_xor_minor,
                lifecycle_seal: binding.lifecycle_seal().map_err(|e| fail(e.to_string()))?,
                reference_observations: reference_observations(stx, &binding)?,
            };
            write(stx, key, &attempt)?;
            let mut state = read_state(stx, &binding)?;
            state.last_attempt_ms = Some(stx.block_unix_timestamp_ms());
            state.last_attempt_height = stx.block_height();
            save_state(stx, &binding, &state)?;
        }
        let sbd = quantity(offer.as_ref().map_or(0, |o| u128::from(o.sbd_minor)), 2)?;
        let xor = quantity(offer.as_ref().map_or(0, |o| o.min_xor_minor), scale)?;
        let digest =
            hex::encode(Hash::new(binding.contract_address.to_string().as_bytes()).as_ref());
        for (index, amount) in [(0_i128, sbd), (1_i128, xor)] {
            let base = "ValidationFeeConversion"
                .parse()
                .map_err(|e| fail(format!("invalid conversion base: {e}")))?;
            let encoded_key = conversion_projection_map_key(index)?;
            let path = ivm::host::canonical_state_map_path(&base, &encoded_key)
                .map_err(|e| fail(e.to_string()))?;
            let key = format!("sc/{digest}/{path}")
                .parse()
                .map_err(|e| fail(format!("invalid conversion projection key: {e}")))?;
            let bytes = crate::validation_fee::encode_conversion_quantity_state_value(&amount)
                .map_err(|e| fail(e.to_string()))?;
            stx.world.smart_contract_state.insert(key, bytes);
        }
    }
    Ok(())
}

/// Observe the actual disposable journal before its sole successful apply.
/// Return original local owners before projecting a completed preparation failure.
fn finish_reward_maintenance(
    stx: StateTransaction<'_, '_>,
    result: Result<(), Error>,
) -> Result<(), crate::state::ExecutionOutputAttemptError> {
    stx.require_storage_admission()?;
    if let Some(reason) = stx.execution_deferral() {
        return Err(crate::state::ExecutionOutputAttemptError::Deferred(reason));
    }
    result.map_err(|error| {
        crate::state::ExecutionOutputAttemptError::Owner(format!(
            "validation fee reward maintenance failed: {error}"
        ))
    })?;
    // Both maintenance callers write only protected smart-contract state. The
    // original local touch journal excludes writes from earlier applied siblings;
    // an empty maintenance attempt must not invent an execution fragment.
    if stx.world.smart_contract_state.touched_entries().len() != 0 {
        stx.apply();
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn seed_automatic_claim_for_testing(
    stx: &mut StateTransaction<'_, '_>,
    claimant: &AccountId,
    amount: u128,
    custody_balance: u128,
) -> PublicLaneFeeRewardClaimV1 {
    let binding = active_bindings(stx).unwrap().remove(0);
    tests::seed_claim_credit(stx, &binding, claimant, amount, custody_balance);
    fee_reward_claim_plan(
        &stx.world,
        stx.block_height(),
        claimant,
        binding.validator_lane_id,
    )
    .unwrap()
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("validation_fee_rewards/signed_claim_tests.rs");
    include!("validation_fee_rewards/credit_refusal_tests.rs");
    include!("validation_fee_rewards/automatic_tests.rs");
    include!("validation_fee_rewards/offers_capacity_tests.rs");
    use iroha_crypto::{Algorithm, HashOf, KeyPair, SignatureOf};
    use iroha_data_model::{
        asset::AssetDefinitionId,
        block::BlockHeader,
        oracle::{FeedConfigVersion, ObservationBody, ObservationOutcome, ObservationValue},
        smart_contract::ContractAddress,
    };
    use iroha_model_base::{domain::DomainId, name::Name, topology::DataSpaceId};
    #[test]
    fn conversion_projection_keys_match_compiler_declared_map_storage() {
        let artifact = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku ConversionKeys { state StateMap<int, quantity> ValidationFeeConversion; view fn amount(int index) authorize(anyone) -> quantity { ValidationFeeConversion.get(key: index).unwrap_or(default: 0) } }",
        ).expect("compile conversion map schema");
        let mut vm = ivm::IVM::new(1_000_000);
        vm.load_program(&artifact).expect("load conversion schema");
        let base = "ValidationFeeConversion".parse().unwrap();
        let mut paths = BTreeSet::new();
        for index in [0, 1] {
            let encoded = conversion_projection_map_key(index).expect("canonical key");
            let path = ivm::host::canonical_state_map_path(&base, &encoded).unwrap();
            ivm::host::validate_declared_state_path(&vm, &path)
                .expect("native projection matches the contract's complete key schema");
            assert!(paths.insert(path));
            let retired = ivm_abi::numeric_tlv::encode_int(
                &iroha_primitives::bigint::BigInt::from_i128(index),
            )
            .unwrap();
            let retired_path = ivm::host::canonical_state_map_path(&base, &retired).unwrap();
            assert!(ivm::host::validate_declared_state_path(&vm, &retired_path).is_err());
        }
    }
    pub(super) fn accrue_all(
        stx: &mut StateTransaction<'_, '_>,
        binding: &ValidationFeeTreasuryPayoutBindingV1,
    ) {
        while settlement::accrue_next_page(stx, binding).unwrap() {}
    }
    /// Seed a complete validator-only historical source for existing custody tests.
    pub(super) fn seed_service(
        stx: &mut StateTransaction<'_, '_>,
        binding: &ValidationFeeTreasuryPayoutBindingV1,
        period: u64,
        weights: &BTreeMap<AccountId, u64>,
    ) {
        for (account, count) in weights {
            exposure::seed_page_for_testing(
                stx,
                binding,
                period,
                account,
                *count,
                BTreeMap::from([(account.clone(), Quantity::from(1u32))]),
            );
        }
        write(
            stx,
            service_key(binding, period).unwrap(),
            &ValidationFeeServiceSnapshot {
                earning_period_start_ms: period,
                service_blocks: weights.clone(),
            },
        )
        .unwrap();
    }
    fn key(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key")
    }
    pub(super) fn account(seed: u8) -> AccountId {
        AccountId::new(key(seed).public_key().clone())
    }
    fn binding() -> ValidationFeeTreasuryPayoutBindingV1 {
        let network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([7; 32])),
        );
        let address = |nonce| {
            ContractAddress::derive(&network, &account(1), nonce, DataSpaceId::UNIVERSAL)
                .expect("address")
        };
        let asset = |name: &str| {
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("fees", "paynet").expect("domain"),
                name.parse::<Name>().expect("name"),
            )
        };
        ValidationFeeTreasuryPayoutBindingV1 {
            contract_address: address(1),
            code_hash: [1; 32],
            entrypoint: "autonomous_validation_fee_tick"
                .parse()
                .expect("entrypoint"),
            treasury_account_id: address(1).subject_id(),
            ds_asset_id: asset("sbd"),
            xor_asset_id: iroha_data_model::parameter::system::SumeragiNposParameters::default()
                .xor_asset_definition_id,
            pool_contract_address: address(2),
            pool_code_hash: [2; 32],
            pool_vault_account_id: address(2).subject_id(),
            reward_pool_account_id: address(3).subject_id(),
            reference_feed_id: "xor_per_sbd".parse().expect("feed"),
            reference_feed_config_version: 1,
            reference_provider_accounts: (10..15).map(account).collect(),
            max_sbd_per_attempt_minor: 1000,
            max_sbd_per_day_minor: 100_000,
            min_interval_ms: 60000,
            max_source_age_ms: 300_000,
            max_slippage_bps: 100,
            validator_lane_id: LaneId::new(0),
            min_reward_claim_xor_minor: 1,
        }
    }
    fn observation(
        seed: u8,
        source: u64,
        admitted: u64,
        height: u64,
    ) -> ValidationFeeReferenceObservation {
        let binding = binding();
        let body = ObservationBody {
            feed_id: binding.reference_feed_id,
            feed_config_version: FeedConfigVersion(1),
            slot: 50,
            provider_id: account(seed),
            connector_id: "signed_xor_per_sbd".to_owned(),
            connector_version: 1,
            request_hash: Hash::prehashed([3; 32]),
            outcome: ObservationOutcome::Value(ObservationValue::new(2, 0)),
            timestamp_ms: Some(source),
        };
        let signature = SignatureOf::new(key(seed).private_key(), &body);
        ValidationFeeReferenceObservation {
            observation: Observation { body, signature },
            admitted_height: height,
            admitted_at_ms: admitted,
        }
    }
    #[test]
    fn price_requires_three_unique_prior_block_fresh_original_sources() {
        let b = binding();
        let now = 1_000_000;
        let records: Vec<_> = (10..13)
            .map(|seed| observation(seed, now - 300_000, now - 1, 8))
            .collect();
        assert_eq!(
            reference_minimum(&b, &records, now, 9, 1000, 2).expect("quote"),
            Some(1980)
        );
        assert_eq!(
            reference_minimum(&b, &records[..2], now, 9, 1000, 2).expect("quote"),
            None
        );
        assert_eq!(
            reference_minimum(&b, &records, now, 8, 1000, 2).expect("quote"),
            None
        );
        assert_eq!(
            reference_minimum(&b, &records, now + 1, 9, 1000, 2).expect("quote"),
            None
        );
        let duplicate = vec![records[0].clone(); 3];
        assert_eq!(
            reference_minimum(&b, &duplicate, now, 9, 1000, 2).expect("quote"),
            None
        );
    }
    #[test]
    fn reference_cannot_mix_requests_or_use_future_source_timestamps() {
        let mut records: Vec<_> = (10..13)
            .map(|seed| observation(seed, 999, 1000, 8))
            .collect();
        records[2].observation.body.request_hash = Hash::prehashed([4; 32]);
        assert_eq!(
            reference_minimum(&binding(), &records, 1001, 9, 1000, 2).expect("quote"),
            None
        );
        records[2] = observation(12, 1001, 1000, 8);
        assert_eq!(
            reference_minimum(&binding(), &records, 1001, 9, 1000, 2).expect("quote"),
            None
        );
    }
    #[test]
    fn historical_weights_conserve_every_minor_unit_with_deterministic_dust() {
        let weights = BTreeMap::from([(account(1), 1), (account(2), 3), (account(3), 0)]);
        let shares = allocate(101, &weights).expect("allocate");
        assert_eq!(shares[&account(1)], 25);
        assert_eq!(shares[&account(2)], 76);
        assert_eq!(shares.values().sum::<u128>(), 101);
        assert!(!shares.contains_key(&account(3)));
        let equal = BTreeMap::from([(account(1), 1), (account(2), 1)]);
        let shares = allocate(1, &equal).expect("dust");
        assert_eq!(shares[equal.keys().next().expect("first")], 1);
        assert!(allocate(1, &BTreeMap::new()).is_err());
    }
    #[test]
    fn exact_quantity_and_honiara_calendar_boundaries() {
        assert_eq!(
            minor_units(&quantity(101, 2).expect("quantity"), 2).expect("minor"),
            101
        );
        assert!(minor_units(&"0.001".parse().expect("quantity"), 2).is_err());
        // 2026-09-30T13:00:00Z = 2026-10-01T00:00:00+11.
        let october = 1_790_773_200_000;
        assert_eq!(earning_month(october).expect("month"), october);
        assert!(earning_month(october - 1).expect("previous") < october);
    }
    #[test]
    fn conversion_reserves_once_preserves_earning_month_and_obeys_caps() {
        let b = binding();
        let now = 1_790_773_200_000_u64;
        let period = earning_month(now - 1).expect("earning month");
        let state = crate::state::State::new_for_testing(
            crate::validation_fee::tests::validation_fee_payout_world(&account(1)),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let header = BlockHeader::new(
            std::num::NonZeroU64::new(10).expect("height"),
            None,
            None,
            now,
            0,
        );
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let initial = ValidationFeeRewardsState {
            pending_sbd_total: 2000,
            service_height: 9,
            ..Default::default()
        };
        save_state(&mut stx, &b, &initial).expect("credit fixture");
        write(&mut stx, pending_key(&b, period).unwrap(), &2000u64).unwrap();
        seed_service(
            &mut stx,
            &b,
            period,
            &BTreeMap::from([(account(1), 1u64), (account(2), 3u64)]),
        );
        for seed in 10..13 {
            let record = observation(seed, now - 1, now - 1, 9);
            let leaf = format!(
                "Oracle/{}",
                hex::encode(
                    Hash::new(record.observation.body.provider_id.to_string().as_bytes()).as_ref()
                )
            );
            write(&mut stx, state_key(&b, &leaf).expect("key"), &record)
                .expect("native observation fixture");
        }
        let offer = conversion_offer(&stx, &b)
            .expect("offer")
            .expect("eligible");
        assert_eq!(offer.earning_period_start_ms, period);
        assert_eq!(offer.sbd_minor, 1000);
        assert_eq!(offer.min_xor_minor, 19_800_000_000);
        reserve_conversion(&mut stx, &b, &offer, 20_010_000_000).expect("reserve actual output");
        accrue_all(&mut stx, &b);
        let after = read_state(&stx, &b).expect("state");
        assert_eq!(after.pending_sbd_total, 1000);
        assert_eq!(
            read::<u64>(&stx, &pending_key(&b, period).unwrap()).unwrap(),
            Some(1000)
        );
        assert_eq!(after.reserved_xor, 20_010_000_000);
        assert_eq!(
            [account(1), account(2)]
                .iter()
                .map(
                    |account| read::<u128>(&stx, &claimable_key(&b, account).unwrap())
                        .unwrap()
                        .unwrap_or(0)
                )
                .sum::<u128>(),
            20_010_000_000
        );
        assert_eq!(after.next_allocation, 1);
        assert!(
            reserve_conversion(&mut stx, &b, &offer, 20_010_000_000).is_err(),
            "allocation cannot replay"
        );
        assert!(conversion_offer(&stx, &b).expect("rate limited").is_none());
        let mut daily = initial;
        daily.conversion_day = (now + HONIARA_OFFSET_MS) / DAY_MS;
        daily.converted_today_sbd = b.max_sbd_per_day_minor - 7;
        save_state(&mut stx, &b, &daily).expect("daily limit fixture");
        let tail = conversion_offer(&stx, &b)
            .expect("tail")
            .expect("seven cents remain");
        assert_eq!(tail.sbd_minor, 7);
        daily.converted_today_sbd = b.max_sbd_per_day_minor;
        save_state(&mut stx, &b, &daily).expect("full daily limit");
        assert!(conversion_offer(&stx, &b).expect("limit").is_none());
    }
    #[test]
    fn policy_revisions_preserve_credit_scope_but_change_allocation_authority() {
        let b = binding();
        let mut next = b.clone();
        next.max_sbd_per_attempt_minor = 2000;
        next.reference_feed_config_version = 2;
        assert_eq!(
            state_key(&b, "State").expect("key"),
            state_key(&next, "State").expect("key")
        );
        assert_ne!(
            b.lifecycle_seal().expect("seal"),
            next.lifecycle_seal().expect("seal")
        );
        next.reward_pool_account_id = account(99);
        assert_ne!(
            state_key(&b, "State").expect("key"),
            state_key(&next, "State").expect("key")
        );
    }
    #[test]
    fn provider_control_and_positive_policy_limits_are_enforced() {
        let mut b = binding();
        assert_eq!(b.invariant_error(), None);
        b.reference_provider_accounts[4] = b.reference_provider_accounts[0].clone();
        assert!(b.invariant_error().is_some());
        let mut b = binding();
        b.max_sbd_per_day_minor = 999;
        assert!(b.invariant_error().is_some());
    }
    #[test]
    fn fractional_reference_rounds_after_execution_loss_limit() {
        let mut records: Vec<_> = (10..13)
            .map(|seed| observation(seed, 999, 1000, 8))
            .collect();
        for record in &mut records {
            record.observation.body.outcome = ObservationOutcome::Value(ObservationValue {
                mantissa: 1001,
                scale: 3,
            });
        }
        // SBD 1 -> XOR 1.001 reference -> 0.99099 minimum -> XOR 1.00 at scale 2.
        assert_eq!(
            reference_minimum(&binding(), &records, 1001, 9, 100, 2).expect("quote"),
            Some(100)
        );
    }
    #[test]
    fn pending_sbd_and_reserved_xor_are_protected_but_unrelated_funds_are_spendable() {
        use iroha_data_model::IntoKeyValue;
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _policy| {
            let b = active_bindings(stx).unwrap().remove(0);
            let reserve = ValidationFeeRewardsState {
                pending_sbd_total: 1000,
                reserved_xor: 15_000_000_000,
                ..Default::default()
            };
            save_state(stx, &b, &reserve).expect("native reserve fixture");
            for (id, balance, permitted, forbidden) in [
                (
                    AssetId::new(b.ds_asset_id.clone(), b.treasury_account_id.clone()),
                    "15",
                    "5",
                    "5.01",
                ),
                (
                    AssetId::new(b.xor_asset_id.clone(), b.reward_pool_account_id.clone()),
                    "20",
                    "5",
                    "5.01",
                ),
            ] {
                let (_, value) =
                    Asset::new(id.clone(), balance.parse::<Quantity>().expect("balance"))
                        .into_key_value();
                stx.world.assets.insert(id.clone(), value);
                ensure_reward_custody_debit(stx, &id, &permitted.parse().expect("permitted"))
                    .expect("unrelated funds may move");
                assert!(
                    ensure_reward_custody_debit(stx, &id, &forbidden.parse().expect("forbidden"))
                        .is_err()
                );
            }
        });
    }
    #[test]
    fn fee_capture_preserves_original_sccp_and_amx_writes_and_replaces_only_fee_families() {
        use iroha_data_model::{
            block::consensus::{ExecKv, ExecWitness},
            execution_witness::{FEE_EVIDENCE_RECORD_TAG_V1, FEE_EVIDENCE_WITNESS_KEY_V1},
            sumeragi_amx::{AmxRecordKind, amx_record_witness_key},
        };
        let state = crate::state::State::new_for_testing(
            crate::state::World::with([], [], []),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(BlockHeader::new(
            std::num::NonZeroU64::new(10).unwrap(),
            None,
            None,
            1_793_451_600_000,
            0,
        ));
        let sccp = crate::smartcontracts::isi::sccp::witness::state_delta_witness_write(
            10,
            b"retained original SCCP delta TESTDATA",
        )
        .unwrap();
        let amx = ExecKv {
            key: amx_record_witness_key(AmxRecordKind::Begin, [0x31; 32]).to_vec(),
            value: norito::to_bytes(&String::from("opaque original AMX DATA; no proof claim"))
                .unwrap(),
        };
        assert_eq!(sccp.key[0], 0xD8);
        assert_eq!(amx.key[0], 0xD9);
        assert_eq!(FEE_EVIDENCE_WITNESS_KEY_V1[0], 0xDA);
        assert_eq!(FEE_EVIDENCE_RECORD_TAG_V1, 0xDB);
        let stale_snapshot = ExecKv {
            key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
            value: vec![0x71],
        };
        let stale_record = ExecKv {
            key: [vec![FEE_EVIDENCE_RECORD_TAG_V1], vec![0x41; 32]].concat(),
            value: vec![0x72],
        };
        let mut witness = ExecWitness::default();
        witness.writes = vec![
            sccp.clone(),
            amx.clone(),
            stale_snapshot.clone(),
            stale_record.clone(),
        ];
        capture_fee_evidence(&mut block, &mut witness).unwrap();
        assert!(witness.writes.contains(&sccp));
        assert!(witness.writes.contains(&amx));
        assert!(!witness.writes.contains(&stale_snapshot));
        assert!(!witness.writes.contains(&stale_record));
        assert_eq!(
            witness
                .writes
                .iter()
                .filter(|entry| entry.key == FEE_EVIDENCE_WITNESS_KEY_V1)
                .count(),
            1
        );
        assert!(
            witness
                .writes
                .iter()
                .filter(|entry| entry.key.first() == Some(&FEE_EVIDENCE_RECORD_TAG_V1))
                .all(|entry| entry.key.len() == 33)
        );
    }

    #[test]
    fn pending_fee_evidence_budget_counts_applied_and_candidate_receipts_before_apply() {
        use iroha_data_model::fee_evidence::MAX_FEE_EVIDENCE_RECORDS_V1;
        use iroha_data_model::validation_fee::{
            RetailFeeReceiptKindV1, RetailFeeReceiptV1, retail_fee_receipt_state_key_v1,
        };
        let state = crate::state::State::new_for_testing(
            crate::state::World::with([], [], []),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let header = BlockHeader::new(
            std::num::NonZeroU64::new(10).unwrap(),
            None,
            None,
            1_793_451_600_000,
            0,
        );
        let mut block = state.block(header);
        let receipt = |index: u32| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&index.to_le_bytes());
            RetailFeeReceiptV1 {
                wallet_id: account(1),
                sequence: 1,
                previous_receipt_hash: None,
                receipt_id: id,
                account_id: account(1),
                kind: RetailFeeReceiptKindV1::Maintenance,
                billing_month_start_ms: 1_790_773_200_000,
                policy_revision: 1,
                policy_hash: [7; 32],
                scheduled_minor: 100,
                collected_minor: 0,
                waived_minor: 100,
                payment_count: 0,
                source_transaction_hash: None,
                effective_at_ms: Some(1_793_451_600_000),
                recorded_at_height: 10,
                assessment: None,
            }
        };
        {
            let mut applied = block.transaction();
            let r = receipt(0);
            write(
                &mut applied,
                retail_fee_receipt_state_key_v1(&r).unwrap(),
                &r,
            )
            .unwrap();
            validate_pending_fee_evidence_budget(&applied).unwrap();
            applied.apply();
        }
        {
            let mut aborted = block.transaction();
            let r = receipt(1);
            write(
                &mut aborted,
                retail_fee_receipt_state_key_v1(&r).unwrap(),
                &r,
            )
            .unwrap();
        }
        let mut candidate = block.transaction();
        for index in 2..=MAX_FEE_EVIDENCE_RECORDS_V1 {
            let r = receipt(index);
            write(
                &mut candidate,
                retail_fee_receipt_state_key_v1(&r).unwrap(),
                &r,
            )
            .unwrap();
        }
        validate_pending_fee_evidence_budget(&candidate)
            .expect("exactly maximum applied and pending records");
        assert!(pending_fee_evidence_fits(&candidate).unwrap());
        let r = receipt(MAX_FEE_EVIDENCE_RECORDS_V1 + 1);
        write(
            &mut candidate,
            retail_fee_receipt_state_key_v1(&r).unwrap(),
            &r,
        )
        .unwrap();
        assert!(
            validate_pending_fee_evidence_budget(&candidate).is_err(),
            "oversized candidate is rejected before apply"
        );
        assert!(!pending_fee_evidence_fits(&candidate).unwrap());
        drop(candidate);
        let check = block.transaction();
        assert_eq!(
            pending_fee_evidence_records(&check).unwrap().len(),
            1,
            "aborted candidate never enters durable corpus"
        );
    }
    #[test]
    fn retained_periods_and_claims_do_not_expand_mandatory_custody_checkpoint() {
        let b = binding();
        let state = crate::state::State::new_for_testing(
            crate::state::World::with([], [], []),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let now = 1_790_773_200_000;
        let mut block = state.block(BlockHeader::new(
            std::num::NonZeroU64::new(10).unwrap(),
            None,
            None,
            now,
            0,
        ));
        let mut stx = block.transaction();
        let original = earning_month(now - 1).unwrap();
        let checkpoint = ValidationFeeRewardsState {
            pending_sbd_total: 7,
            reserved_xor: 1,
            service_height: 9,
            ..Default::default()
        };
        save_state(&mut stx, &b, &checkpoint).unwrap();
        let state_key = state_key(&b, "State").unwrap();
        let original_checkpoint = stx
            .world
            .smart_contract_state
            .get(&state_key)
            .unwrap()
            .clone();
        write(&mut stx, pending_key(&b, original).unwrap(), &7u64).unwrap();
        let historical = BTreeMap::from([(account(2), 17u64)]);
        seed_service(&mut stx, &b, original, &historical);
        write(&mut stx, claimable_key(&b, &account(2)).unwrap(), &1u128).unwrap();
        // Cold history and unrelated future pending keys never become fields of
        // the required custody snapshot or force a claim-time account scan.
        for period in 1..=1000 {
            seed_service(
                &mut stx,
                &b,
                period,
                &BTreeMap::from([(account(1), period)]),
            );
        }
        assert_eq!(
            stx.world.smart_contract_state.get(&state_key),
            Some(&original_checkpoint)
        );
        assert!(original_checkpoint.len() < 1024);
        assert_eq!(first_pending(&stx, &b).unwrap(), Some((original, 7)));
        assert_eq!(service_weights(&stx, &b, original).unwrap(), historical);
        assert_eq!(
            read::<u128>(&stx, &claimable_key(&b, &account(2)).unwrap()).unwrap(),
            Some(1)
        );
        assert!(
            pending_fee_evidence_records(&stx).unwrap().is_empty(),
            "cold service/credit/claim keys are not copied into the block corpus"
        );
    }
    #[test]
    fn independent_conversion_revision_preserves_retail_quotes_and_historical_custody() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
            let original = active_bindings(stx).unwrap().remove(0);
            let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
            credit_collected_fee(stx, &policy, period, 70).unwrap();
            let owner = account(2);
            let services = BTreeMap::from([(owner.clone(), 7u64)]);
            seed_service(stx, &original, period, &services);
            write(stx, claimable_key(&original, &owner).unwrap(), &3u128).unwrap();
            let mut funded = read_state(stx, &original).unwrap();
            funded.reserved_xor = 3;
            save_state(stx, &original, &funded).unwrap();
            let pricing_hash = crate::validation_fee::active_policy(stx)
                .unwrap()
                .unwrap()
                .policy_hash()
                .unwrap();
            let mut revised = original.clone();
            revised.max_sbd_per_attempt_minor = 500;
            revised.reference_feed_config_version += 1;
            revised.min_reward_claim_xor_minor = 20;
            revised.pool_contract_address =
                iroha_data_model::smart_contract::ContractAddress::derive(
                    &stx.network_id,
                    &account(55),
                    991,
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                )
                .unwrap();
            revised.pool_vault_account_id = revised.pool_contract_address.subject_id();
            let mut registry = crate::validation_fee::tests::policy_registry(
                &[policy.clone()],
                &[original.clone()],
            );
            let enactment = stx.block_height();
            registry.payout_policies.entries.push(
                crate::validation_fee::tests::payout_registry_entry(&revised, 2, enactment),
            );
            registry.validate().unwrap();
            crate::validation_fee::tests::install_policy_registry_fixture(&registry, stx);
            assert_eq!(
                active_bindings(stx).unwrap(),
                vec![original.clone()],
                "unfinalized enactment cannot change this block"
            );
            assert!(
                crate::smartcontracts::code::fetch_bound_contract_record_by_subject(
                    stx,
                    &revised.pool_vault_account_id,
                )
                .expect("resolve the original authenticated contract scope")
                .is_none(),
                "an address alone cannot supply an activated payout pool"
            );
            let artifact = iroha_data_model::smart_contract::ContractArtifactId::for_address(
                &original.pool_contract_address,
                Hash::prehashed(original.pool_code_hash),
            )
            .unwrap();
            let code = stx.world.contract_code.get(&artifact).unwrap();
            assert_eq!(
                <[u8; 32]>::from(ivm::contract_code_hash(code)),
                revised.pool_code_hash
            );
            let replacement_deployer = account(55);
            stx.world.bind_inactive_contract_subject_for_testing(
                revised.pool_contract_address.clone(),
                replacement_deployer.clone(),
            );
            // A pool replacement does not create a second autonomous payout
            // trigger; the enacted lifecycle retains its original sole trigger.
            crate::smartcontracts::code::activate_instance(
                &replacement_deployer,
                revised.pool_contract_address.clone(),
                1,
                Hash::prehashed(original.pool_code_hash),
                stx,
            )
            .expect("activate the exact replacement pool artifact");
            let pool = crate::smartcontracts::code::fetch_bound_contract_record_by_subject(
                stx,
                &revised.pool_vault_account_id,
            )
            .expect("resolve the activated authenticated pool")
            .expect("the deployed replacement is active");
            assert_eq!(pool.contract_address, revised.pool_contract_address);
            assert_eq!(pool.contract_subject, revised.pool_vault_account_id);
            assert_eq!(
                <[u8; 32]>::from(ivm::contract_code_hash(&pool.code_bytes)),
                revised.pool_code_hash
            );
            assert_eq!(
                active_bindings_at_height(stx, enactment + 1).unwrap(),
                vec![revised.clone()],
                "conversion activates next block without a retail month boundary"
            );
            assert_eq!(
                crate::validation_fee::active_policy(stx)
                    .unwrap()
                    .unwrap()
                    .policy_hash()
                    .unwrap(),
                pricing_hash
            );
            assert_eq!(read_state(stx, &revised).unwrap(), funded);
            assert_eq!(first_pending(stx, &revised).unwrap(), Some((period, 70)));
            assert_eq!(service_weights(stx, &revised, period).unwrap(), services);
            assert_eq!(
                read::<u128>(stx, &claimable_key(&revised, &owner).unwrap()).unwrap(),
                Some(3)
            );
            let permission: iroha_data_model::permission::Permission =
                iroha_executor_data_model::permission::asset::CanTransferAsset {
                    asset: AssetId::new(
                        original.ds_asset_id.clone(),
                        original.treasury_account_id.clone(),
                    ),
                }
                .into();
            assert_eq!(
                crate::validation_fee::enacted_validation_fee_payout_runtime_permission_owner(
                    stx,
                    &permission
                )
                .unwrap(),
                Some(revised.pool_vault_account_id.clone()),
                "permission ownership switches atomically at enactment; historical order cannot restore an old pool",
            );
            let denied = iroha_data_model::isi::Grant::account_permission(
                permission.clone(),
                original.pool_vault_account_id.clone(),
            )
            .execute(&owner, stx)
            .unwrap_err();
            assert!(
                denied
                    .to_string()
                    .contains("forbids delegating its exact runtime permissions")
            );
            let denied = iroha_data_model::isi::Revoke::account_permission(
                permission,
                revised.pool_vault_account_id.clone(),
            )
            .execute(&owner, stx)
            .unwrap_err();
            assert!(
                denied
                    .to_string()
                    .contains("pins its exact runtime permissions")
            );
            assert_eq!(original.custody(), revised.custody());
            assert_ne!(
                original.lifecycle_seal().unwrap(),
                revised.lifecycle_seal().unwrap()
            );
        });
    }
    #[test]
    fn enacted_reward_corpus_binds_source_history_and_claims_only_reserved_funds_once() {
        use iroha_data_model::IntoKeyValue;
        use iroha_data_model::fee_evidence::FeeEvidencePayloadV1;
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
            let (policy, mut binding) = network_xor_claim_fixture(stx, policy);
            binding.min_reward_claim_xor_minor = 10;
            let registry =
                crate::validation_fee::tests::policy_registry(&[policy], &[binding.clone()]);
            crate::validation_fee::tests::install_policy_registry_fixture(&registry, stx);
            let b = &binding;
            let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
            let claimant = account(2);
            let dust_owner = account(3);
            let weights = BTreeMap::from([(claimant.clone(), 100u64), (dust_owner.clone(), 1u64)]);
            seed_service(stx, b, period, &weights);
            write(stx, pending_key(b, period).unwrap(), &100u64).unwrap();
            save_state(
                stx,
                b,
                &ValidationFeeRewardsState {
                    pending_sbd_total: 100,
                    service_height: stx.block_height() - 1,
                    ..Default::default()
                },
            )
            .unwrap();
            let offer = ConversionOffer {
                earning_period_start_ms: period,
                sbd_minor: 100,
                min_xor_minor: 100,
                sequence: 0,
            };
            reserve_conversion(stx, b, &offer, 101).unwrap();
            accrue_all(stx, b);
            // Seed the exact received XOR as the integration fixture's pool effect.
            // Native wrapper tests independently enforce all three atomic transfers.
            let pool_id = AssetId::new(b.xor_asset_id.clone(), b.reward_pool_account_id.clone());
            let (_, balance) =
                Asset::new(pool_id.clone(), quantity(101, 9).unwrap()).into_key_value();
            stx.world.assets.insert(pool_id.clone(), balance);
            let corpus = pending_fee_evidence_records(stx).unwrap();
            let source = corpus
                .iter()
                .find_map(|r| match &r.payload {
                    FeeEvidencePayloadV1::RewardService(service) => Some((r, service)),
                    _ => None,
                })
                .expect("independent native historical source snapshot");
            assert_eq!(source.0.key, service_key(b, period).unwrap());
            assert_eq!(source.1.service_blocks, weights);
            let component_claim_hash = stx
                .tx_call_hash
                .expect("retained component execution identity");
            let transcript_count = stx.retail_fee_transcripts_for_test().len();
            claim_current_fee_credit(stx, &claimant, b.validator_lane_id).unwrap();
            let claim_transcripts = &stx.retail_fee_transcripts_for_test()[transcript_count..];
            assert_eq!(claim_transcripts.len(), 1);
            let transcript = &claim_transcripts[0];
            assert_eq!(transcript.batch_hash, component_claim_hash);
            assert_eq!(
                transcript.authority_digest,
                crate::fastpq::authority_digest(&b.reward_pool_account_id),
                "native claim authorization retains the debited custody owner in the execution proof",
            );
            assert_ne!(
                transcript.authority_digest,
                crate::fastpq::authority_digest(&claimant)
            );
            assert!(
                !stx.retail_fee_source_kind_for_test(&component_claim_hash),
                "a retained component claim has ExecutionCall provenance, not an invented protocol-purpose source"
            );
            assert_eq!(transcript.deltas.len(), 1);
            let delta = &transcript.deltas[0];
            assert_eq!(delta.from_account, b.reward_pool_account_id);
            assert_eq!(delta.to_account, claimant);
            assert_eq!(delta.asset_definition, b.xor_asset_id);
            assert_eq!(delta.amount, quantity(100, 9).unwrap());
            assert_eq!(delta.from_balance_before, quantity(101, 9).unwrap());
            assert_eq!(delta.from_balance_after, quantity(1, 9).unwrap());
            assert_eq!(delta.to_balance_before, Quantity::zero());
            assert_eq!(delta.to_balance_after, quantity(100, 9).unwrap());
            assert_eq!(read_state(stx, b).unwrap().reserved_xor, 1);
            assert_eq!(
                read::<u128>(stx, &claimable_key(b, &dust_owner).unwrap()).unwrap(),
                Some(1)
            );
            assert_eq!(
                read::<u128>(stx, &claimable_key(b, &claimant).unwrap()).unwrap(),
                None
            );
            let paid_id = AssetId::new(b.xor_asset_id.clone(), claimant.clone());
            assert_eq!(
                minor_units(stx.world.assets.get(&paid_id).unwrap().as_ref(), 9).unwrap(),
                100
            );
            claim_current_fee_credit(stx, &claimant, b.validator_lane_id).unwrap();
            claim_current_fee_credit(stx, &dust_owner, b.validator_lane_id).unwrap();
            assert_eq!(
                stx.retail_fee_transcripts_for_test().len(),
                transcript_count + 1,
                "replayed claims and retained dust cannot add a transfer or proof occurrence"
            );
            assert_eq!(read_state(stx, b).unwrap().next_claim, 1);
            assert_eq!(read_state(stx, b).unwrap().reserved_xor, 1);
            assert_eq!(
                minor_units(stx.world.assets.get(&pool_id).unwrap().as_ref(), 9).unwrap(),
                1
            );
            assert_eq!(
                pending_fee_evidence_records(stx)
                    .unwrap()
                    .iter()
                    .filter(|r| matches!(r.payload, FeeEvidencePayloadV1::RewardClaim(_)))
                    .count(),
                1
            );
        });
    }
}

#[cfg(test)]
mod protected_original_retry_controls {
    use super::*;

    #[test]
    fn empty_conversion_maintenance_cannot_publish_an_inherited_dirty_sibling() {
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let fragments = block.committed_fragment_count();
        publish_conversion_offers(&mut block).unwrap();
        assert_eq!(block.committed_fragment_count(), fragments);
        let key: StatePath = "protected_maintenance_original_TESTDATA".parse().unwrap();
        {
            let mut stx = block.transaction();
            stx.world.smart_contract_state.insert(key.clone(), vec![23]);
            finish_reward_maintenance(stx, Ok(())).unwrap();
        }
        assert_eq!(block.committed_fragment_count(), fragments + 1);
        assert_eq!(block.world.smart_contract_state.touched_entries().len(), 1);
        {
            let stx = block.transaction();
            assert_eq!(stx.world.smart_contract_state.touched_entries().len(), 0);
            finish_reward_maintenance(stx, Ok(())).unwrap();
        }
        publish_conversion_offers(&mut block).unwrap();
        assert_eq!(block.committed_fragment_count(), fragments + 1);
        assert_eq!(block.world.smart_contract_state.get(&key), Some(&vec![23]));
    }

    #[test]
    fn empty_conversion_journal_still_returns_original_decoder_refusal() {
        use crate::state::ExecutionOutputAttemptError;
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let key: StatePath = "empty_maintenance_original_TESTDATA".parse().unwrap();
        let original = norito::to_bytes(&vec![7_u64, 11, 13]).unwrap();
        block
            .world
            .smart_contract_state
            .insert(key.clone(), original.clone());
        let fragments = block.committed_fragment_count();
        let stx = block.transaction();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, 0, usize::MAX, usize::MAX);
        let result =
            norito::with_decode_limits_scope(limits, || read::<Vec<u64>>(&stx, &key).map(|_| ()));
        let original_refusal = stx.execution_deferral().expect("genuine decoder refusal");
        assert_eq!(stx.world.smart_contract_state.touched_entries().len(), 0);
        assert_eq!(
            finish_reward_maintenance(stx, result),
            Err(ExecutionOutputAttemptError::Deferred(original_refusal))
        );
        assert_eq!(block.committed_fragment_count(), fragments);
        assert_eq!(block.world.smart_contract_state.get(&key), Some(&original));
    }

    #[test]
    fn incomplete_conversion_preparation_returns_original_owner_and_keeps_prior_projection() {
        use crate::state::{ExecutionOutputAttemptError, ExecutionOutputSealError};
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let original: StatePath = "conversion_original_TESTDATA".parse().unwrap();
        let projection: StatePath = "conversion_projection_TESTDATA".parse().unwrap();
        let original_bytes = norito::to_bytes(&vec![7_u64, 11, 13]).unwrap();
        let prior_projection = vec![19];
        block
            .world
            .smart_contract_state
            .insert(original.clone(), original_bytes.clone());
        block
            .world
            .smart_contract_state
            .insert(projection.clone(), prior_projection.clone());
        let returned = {
            let mut stx = block.transaction();
            stx.world
                .smart_contract_state
                .insert(projection.clone(), vec![23]);
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, 0, usize::MAX, usize::MAX);
            let result = norito::with_decode_limits_scope(limits, || {
                read::<Vec<u64>>(&stx, &original).map(|_| ())
            });
            assert!(result.is_err());
            let owner = stx.execution_deferral().expect("genuine decoder refusal");
            let error = finish_reward_maintenance(stx, result).unwrap_err();
            assert_eq!(error, ExecutionOutputAttemptError::Deferred(owner.clone()));
            let sealed: ExecutionOutputSealError<()> = error.into();
            let ExecutionOutputSealError::Deferred(observed) = sealed else {
                panic!("discarding the maintenance journal must not erase its original owner");
            };
            assert_eq!(observed, owner);
            observed
        };
        assert!(returned.allocation_refusal().is_none());
        assert_eq!(
            block.world.smart_contract_state.get(&projection),
            Some(&prior_projection)
        );
        assert_eq!(
            block.world.smart_contract_state.get(&original),
            Some(&original_bytes)
        );
    }

    #[test]
    fn completed_conversion_preparation_refusal_stops_without_retry_or_partial_apply() {
        use crate::state::ExecutionOutputAttemptError;
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let projection: StatePath = "completed_conversion_projection_TESTDATA".parse().unwrap();
        let error = {
            let mut stx = block.transaction();
            stx.world
                .smart_contract_state
                .insert(projection.clone(), vec![23]);
            finish_reward_maintenance(stx, Err(fail("completed TESTDATA refusal"))).unwrap_err()
        };
        assert!(matches!(error, ExecutionOutputAttemptError::Owner(reason)
            if reason.contains("completed TESTDATA refusal")));
        assert!(block.world.smart_contract_state.get(&projection).is_none());
    }

    #[test]
    fn protected_reward_read_retains_first_refusal_and_cannot_publish_the_partial_overlay() {
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let original_key: StatePath = "retained_reward_original_TESTDATA".parse().unwrap();
        let unpublished_key: StatePath = "retained_reward_unpublished_TESTDATA".parse().unwrap();
        let bytes = norito::to_bytes(&vec![7_u64, 11, 13]).unwrap();
        block
            .world
            .smart_contract_state
            .insert(original_key.clone(), bytes.clone());
        {
            let mut stx = block.transaction();
            stx.world
                .smart_contract_state
                .insert(unpublished_key.clone(), vec![1]);
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, 0, usize::MAX, usize::MAX);
            let error =
                norito::with_decode_limits_scope(limits, || read::<Vec<u64>>(&stx, &original_key))
                    .unwrap_err();
            assert!(matches!(error, Error::InvariantViolation(_)));
            assert!(stx.execution_deferral().is_some());
            assert_eq!(
                read_attempt::<Vec<u64>>(&stx, &original_key).unwrap(),
                Some(vec![7, 11, 13])
            );
            stx.apply();
        }
        assert!(
            block
                .world
                .smart_contract_state
                .get(&unpublished_key)
                .is_none()
        );
        assert_eq!(
            block.world.smart_contract_state.get(&original_key),
            Some(&bytes)
        );
    }
}
