//! Consensus-owned SBD conversion accounting and reserved SORA Nexus staking rewards.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, oracle::Observation};
use crate::{oracle::ObservationOutcome, validation_fee::ValidationFeeTreasuryPayoutBindingV1};
use iroha_crypto::Hash;
use iroha_model_base::state_path::StatePath;
use iroha_primitives::{bigint::BigInt, numeric::Quantity};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::collections::{BTreeMap, BTreeSet};

/// Durable per-custody balances; ordinary treasury deposits never enter this ledger.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeRewardsState")]
pub struct ValidationFeeRewardsState {
    /// Total unconverted authenticated SBD cents. Per-month credits, historical
    /// service, and individual claims live in separate protected records so this
    /// mandatory per-block custody checkpoint has constant size.
    pub pending_sbd_total: u128,
    /// Total XOR minor units reserved exclusively for these claims.
    pub reserved_xor: u128,
    /// Next allocation sequence; never reused after conversion or claims.
    pub next_allocation: u64,
    /// Next immutable claim receipt sequence.
    pub next_claim: u64,
    /// Last successfully converted block time.
    pub last_conversion_ms: Option<u64>,
    /// Last scheduled conversion attempt, including failed pool execution.
    pub last_attempt_ms: Option<u64>,
    /// Block that owns the current attempt; retries in later blocks are rate limited.
    pub last_attempt_height: u64,
    /// Honiara day containing the current conversion limit counter.
    pub conversion_day: u64,
    /// Converted SBD cents in that day.
    pub converted_today_sbd: u64,
    /// Last finalized block incorporated into the service record.
    pub service_height: u64,
}

/// Canonical protected custody key shared by execution and independent evidence.
///
/// # Errors
///
/// Returns an error if custody coordinates cannot be canonically encoded or their
/// state path cannot be represented.
pub fn validation_fee_reward_state_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    leaf: &str,
) -> Result<StatePath, String> {
    let digest = hex::encode(Hash::new(binding.contract_address.to_string().as_bytes()).as_ref());
    let custody = (
        binding.treasury_account_id.clone(),
        binding.ds_asset_id.clone(),
        binding.xor_asset_id.clone(),
        binding.reward_pool_account_id.clone(),
    );
    let bytes = norito::to_bytes(&custody).map_err(|e| e.to_string())?;
    let scope = hex::encode(Hash::new(bytes).as_ref());
    format!("sc/{digest}/ValidationFeeRewards/{scope}/{leaf}")
        .parse()
        .map_err(|e| format!("invalid rewards state key: {e}"))
}

/// Historical service read from its protected original-month key. The fee
/// commitment authenticates this source snapshot independently of an allocation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeServiceSnapshot")]
pub struct ValidationFeeServiceSnapshot {
    /// Original Honiara earning-month start.
    pub earning_period_start_ms: u64,
    /// Native finalized service weights, retained after the period closes.
    pub service_blocks: BTreeMap<AccountId, u64>,
}

/// Maximum distinct beneficiary accounts in one exposure page.
pub const MAX_REWARD_RECIPIENTS: usize = 256;
/// Maximum distinct historical validator identities in one monthly service summary.
pub const MAX_REWARD_VALIDATORS: usize = 4_096;
/// Maximum exposure cohorts in one exposure page.
pub const MAX_REWARD_EXPOSURE_COHORTS: usize = 1_024;
/// Maximum stake entries across all cohorts in one exposure page.
pub const MAX_REWARD_EXPOSURE_ENTRIES: usize = 4_096;
/// Maximum canonical encoded account identity admitted to staking reward history.
/// This applies to staking participants and reward recovery, not general accounts.
pub const MAX_REWARD_IDENTITY_BYTES: usize = 256;
/// Maximum canonical encoded historical exposure page, including all identities.
pub const MAX_REWARD_EXPOSURE_BYTES: usize = 128 * 1024;
/// Maximum archived page and its fixed-size authenticated predecessor reference.
pub const MAX_REWARD_EXPOSURE_ARCHIVE_BYTES: usize = MAX_REWARD_EXPOSURE_BYTES + 1024;
/// Maximum retained funded allocation copied into each automatic page proof.
pub const MAX_REWARD_ALLOCATION_BYTES: usize = 3 * 1024 * 1024;
/// Maximum retained authenticated oracle report, including signed connector metadata.
pub const MAX_REWARD_REFERENCE_BYTES: usize = 16 * 1024;

/// Reject reward identities whose variable-length controller would defeat page bounds.
///
/// # Errors
/// Rejects serialization failure or an identity exceeding the canonical byte limit.
pub fn validate_reward_identity(account: &AccountId) -> Result<(), String> {
    if norito::to_bytes(account)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_REWARD_IDENTITY_BYTES
    {
        return Err("staking reward account identity exceeds encoded byte bound".into());
    }
    Ok(())
}

/// Equal-service cohort with the same historical eligible stake distribution.
///
/// Cohorts are retained in earning order and adjacent identical maps may be
/// coalesced. Commission is zero. Monetary quantities retain
/// their full canonical precision; they are never narrowed into service counts.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeRewardExposure")]
pub struct ValidationFeeRewardExposure {
    /// Number of authenticated validator service units with these eligible stakes.
    pub service_blocks: u64,
    /// Exact eligible self-stake and nominations, keyed by their earning account.
    /// A retained signer with zero eligible stake uses one validator unit solely
    /// as an allocation weight; that unit creates no staking principal.
    pub stakes: BTreeMap<AccountId, Quantity>,
}

/// Bounded chronological exposure source retained until its funded work is consumed.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeExposurePage")]
pub struct ValidationFeeExposurePage {
    /// Original Honiara earning-month start.
    pub earning_period_start_ms: u64,
    /// Validator whose authenticated service generated these cohorts.
    pub validator: AccountId,
    /// Consecutive page index, starting at zero for this validator and month.
    pub page_index: u64,
    /// Exact eligible stakes in earning order, with adjacent identical maps coalesced.
    pub exposure: Vec<ValidationFeeRewardExposure>,
}

/// Exact original certified execution record containing a historical exposure page.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeExposureArchiveRef")]
pub struct ValidationFeeExposureArchiveRef {
    /// Original finalized block whose ordinary execution witness retains the archive.
    pub recorded_at_height: u64,
    /// Consecutive chronological page index within this validator's earning month.
    pub page_index: u64,
    /// Number of validator service units preceding the page in earning order.
    pub service_start: u64,
    /// Hash of the complete canonical archive wrapper, including its predecessor.
    pub archive_hash: Hash,
}

/// Bounded page and authenticated predecessor retained in original block custody.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeExposureArchive")]
pub struct ValidationFeeExposureArchive {
    /// Exact chronological exposure page at its original write height.
    pub page: ValidationFeeExposurePage,
    /// Prior sealed page; absent only for chronological page zero.
    pub previous: Option<ValidationFeeExposureArchiveRef>,
}

/// Constant-size authenticated head for one validator's earning-month exposure.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeExposureHead")]
pub struct ValidationFeeExposureHead {
    /// Number of chronological pages, including the current mutable tail.
    pub page_count: u64,
    /// Total authenticated validator service across every linked page.
    pub service_total: u64,
    /// Current tail's original certified archive record.
    pub latest: ValidationFeeExposureArchiveRef,
    /// Whether the matching tail page and archive wrapper remain in World state.
    /// False only after their original certified archive has been authenticated.
    pub tail_resident: bool,
}

/// Immutable claimable distribution of one funded allocation over an exposure page.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeRewardEntitlement")]
pub struct ValidationFeeRewardEntitlement {
    /// Immutable funded conversion whose gross reward is being distributed.
    pub allocation_sequence: u64,
    /// Validator earning the gross reward.
    pub validator: AccountId,
    /// Consumed exposure page index.
    pub page_index: u64,
    /// Validator service units preceding this page in chronological earning order.
    pub service_start: u64,
    /// Validator service units through this page in chronological earning order.
    pub service_end: u64,
    /// Native block that created the enforceable claim balances.
    pub recorded_at_height: u64,
    /// Exact account entitlements, including deterministic retained dust.
    pub shares: BTreeMap<AccountId, u128>,
    /// Stable beneficiary identity for every historical earning account.
    pub beneficiaries: BTreeMap<AccountId, AccountId>,
}

/// Canonical retained historical exposure page key.
///
/// # Errors
/// Returns an error if the protected custody key cannot be represented.
pub fn validation_fee_exposure_page_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    page_index: u64,
) -> Result<StatePath, String> {
    validation_fee_reward_state_key(
        binding,
        &format!(
            "Exposure/{period:020}/{}/{page_index:020}",
            hex::encode(Hash::new(validator.to_string().as_bytes()).as_ref()),
        ),
    )
}

/// Canonical protected archive key for one chronological exposure page.
///
/// # Errors
/// Returns an error if the protected custody key cannot be represented.
pub fn validation_fee_exposure_archive_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    page_index: u64,
) -> Result<StatePath, String> {
    validation_fee_reward_state_key(
        binding,
        &format!(
            "ExposureArchive/{period:020}/{}/{page_index:020}",
            hex::encode(Hash::new(validator.to_string().as_bytes()).as_ref()),
        ),
    )
}

/// Original ordinary-witness key for the canonical protected exposure archive path.
pub fn validation_fee_exposure_archive_witness_key(key: &StatePath) -> [u8; 33] {
    let mut witness = [0; 33];
    witness[0] = crate::execution_witness::REWARD_EXPOSURE_ARCHIVE_TAG_V1;
    witness[1..].copy_from_slice(Hash::new(key.as_ref().as_bytes()).as_ref());
    witness
}

/// Canonical immutable automatic reward entitlement key.
///
/// # Errors
/// Returns an error if the protected custody key cannot be represented.
pub fn validation_fee_entitlement_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    allocation_sequence: u64,
    validator: &AccountId,
    page_index: u64,
) -> Result<StatePath, String> {
    validation_fee_reward_state_key(
        binding,
        &format!(
            "Entitlement/{allocation_sequence:020}/{}/{page_index:020}",
            hex::encode(Hash::new(validator.to_string().as_bytes()).as_ref()),
        ),
    )
}

/// Original provider-signed observation and its consensus admission coordinates.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::validation_fee_rewards::ValidationFeeReferenceObservation"
)]
pub struct ValidationFeeReferenceObservation {
    /// Canonical signed native oracle report, including original source timestamp.
    pub observation: Observation,
    /// Block height that admitted and authenticated the signature.
    pub admitted_height: u64,
    /// Consensus timestamp of admission.
    pub admitted_at_ms: u64,
}

/// Keep an original signed reference report bounded before retaining it for rewards.
///
/// # Errors
/// Rejects serialization failure or a report exceeding its canonical byte limit.
pub fn validate_reference_observation_bytes(
    record: &ValidationFeeReferenceObservation,
) -> Result<(), String> {
    if norito::to_bytes(record)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_REWARD_REFERENCE_BYTES
    {
        return Err("reward reference observation exceeds encoded byte bound".into());
    }
    Ok(())
}

/// Immutable funded gross allocation, distributed through bounded exposure pages.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeRewardAllocation")]
pub struct ValidationFeeRewardAllocation {
    /// Monotonic allocation identity scoped to the immutable custody identity.
    pub sequence: u64,
    /// Exact Parliament-enacted conversion policy used by this allocation.
    pub lifecycle_seal: [u8; 32],
    /// Original earning month, preserved when conversion is delayed.
    pub earning_period_start_ms: u64,
    /// Authenticated SBD cents consumed.
    pub sbd_minor: u64,
    /// Actual XOR minor units atomically received from the pool.
    pub xor_minor: u128,
    /// Consensus block height at conversion.
    pub converted_at_height: u64,
    /// Exact consensus conversion time.
    pub converted_at_ms: u64,
    /// Reference-derived minimum output, with execution loss applied before rounding.
    pub min_xor_minor: u128,
    /// Original signed reference reports retained with this conversion forever.
    pub reference_observations: Vec<ValidationFeeReferenceObservation>,
    /// Actual historical service counts used for this allocation.
    pub service_blocks: BTreeMap<AccountId, u64>,
    /// Funded gross validator rewards before automatic historical stake sharing.
    pub gross_shares: BTreeMap<AccountId, u128>,
}

/// Bound the immutable allocation source required by every later entitlement page.
///
/// # Errors
/// Rejects too many or oversized references, serialization failure, or an oversized source.
pub fn validate_allocation_bytes(allocation: &ValidationFeeRewardAllocation) -> Result<(), String> {
    if allocation.reference_observations.len() > 5 {
        return Err("reward allocation has too many reference observations".into());
    }
    for reference in &allocation.reference_observations {
        validate_reference_observation_bytes(reference)?;
    }
    if norito::to_bytes(allocation)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_REWARD_ALLOCATION_BYTES
    {
        return Err("reward allocation exceeds encoded byte bound".into());
    }
    Ok(())
}

/// Immutable funded claim receipt; repeated claims cannot reuse this sequence.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeRewardClaim")]
pub struct ValidationFeeRewardClaim {
    /// Stable original beneficiary whose reserved credit is claimed.
    pub beneficiary_id: AccountId,
    /// Immutable authorized owner revision used at claim execution.
    pub beneficiary_revision: u64,
    /// Monotonic identity in the protected custody ledger.
    pub sequence: u64,
    /// Exact claimant authenticated by the native claim instruction.
    pub account_id: AccountId,
    /// Actually transferred XOR minor units.
    pub xor_minor: u128,
    /// Native finalization height.
    pub claimed_at_height: u64,
    /// Native finalization time.
    pub claimed_at_ms: u64,
    /// Parliament lifecycle governing the claim.
    pub lifecycle_seal: [u8; 32],
}

/// Immutable scheduled conversion attempt. Absence of a same-height allocation
/// proves that the attempted conversion retained its SBD credit.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::validation_fee_rewards::ValidationFeeConversionAttempt")]
pub struct ValidationFeeConversionAttempt {
    /// Exact block that published this native attempt.
    pub attempted_at_height: u64,
    /// Consensus timestamp used by source freshness and rate limits.
    pub attempted_at_ms: u64,
    /// Original completed earning month.
    pub earning_period_start_ms: u64,
    /// Authenticated SBD cents offered for conversion.
    pub sbd_minor: u64,
    /// Exact reference-based minimum XOR output.
    pub min_xor_minor: u128,
    /// Exact independently governed conversion policy identity.
    pub lifecycle_seal: [u8; 32],
    /// Original native signed provider reports retained at scheduling time.
    pub reference_observations: Vec<ValidationFeeReferenceObservation>,
}

/// Canonical exact reference-price minimum used by consensus and offline proof verification.
///
/// # Errors
///
/// Returns an error for an invalid payout binding, unsupported scale, zero input,
/// or overflowing conversion arithmetic.
pub fn reference_minimum(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    records: &[ValidationFeeReferenceObservation],
    now: u64,
    height: u64,
    sbd_minor: u64,
    xor_scale: u32,
) -> Result<Option<u128>, String> {
    if let Some(reason) = binding.invariant_error() {
        return Err(reason.to_owned());
    }
    if xor_scale > 18 || sbd_minor == 0 {
        return Err("reference minimum requires positive exact supported-scale input".into());
    }
    let mut groups: BTreeMap<(u64, Hash), Vec<u128>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for record in records {
        let body = &record.observation.body;
        if body.feed_id != binding.reference_feed_id
            || body.feed_config_version.0 != binding.reference_feed_config_version
            || !binding
                .reference_provider_accounts
                .contains(&body.provider_id)
            || !seen.insert(body.provider_id.clone())
            || record.admitted_height >= height
        {
            continue;
        }
        let Some(source) = body.timestamp_ms else {
            continue;
        };
        if source > record.admitted_at_ms
            || record.admitted_at_ms > now
            || source > now
            || now - source > binding.max_source_age_ms
        {
            continue;
        }
        let ObservationOutcome::Value(value) = &body.outcome else {
            continue;
        };
        if value.mantissa <= 0 || value.scale > 18 || xor_scale > 18 {
            continue;
        }
        let numerator = u128::try_from(value.mantissa)
            .map_err(|_| String::from("negative reference price"))?
            .checked_mul(u128::from(sbd_minor))
            .and_then(|v| v.checked_mul(10u128.pow(xor_scale)))
            .ok_or_else(|| String::from("reference price overflow"))?;
        let denominator = 100u128
            .checked_mul(10u128.pow(value.scale))
            .ok_or_else(|| String::from("reference scale overflow"))?;
        let loss_adjusted = numerator
            .checked_mul(u128::from(10_000 - binding.max_slippage_bps))
            .ok_or_else(|| String::from("minimum conversion overflow"))?;
        let denominator = denominator
            .checked_mul(10_000)
            .ok_or_else(|| String::from("minimum denominator overflow"))?;
        // Apply the execution-loss limit to the exact reference output before
        // rounding upward. Flooring the reference first could permit >1% loss.
        let minimum = loss_adjusted / denominator + u128::from(loss_adjusted % denominator != 0);
        groups
            .entry((body.slot, body.request_hash))
            .or_default()
            .push(minimum);
    }
    let Some((_, mut values)) = groups.into_iter().rev().find(|(_, v)| v.len() >= 3) else {
        return Ok(None);
    };
    values.sort_unstable();
    let minimum = values[values.len() / 2];
    Ok((minimum > 0).then_some(minimum))
}

/// Validate one bounded historical exposure page.
///
/// # Errors
///
/// Rejects empty pages, nonpositive stakes or service, adjacent duplicate
/// cohorts, checked service-count overflow, and exceeded per-page bounds.
pub fn validate_exposure_page(page: &ValidationFeeExposurePage) -> Result<(), String> {
    validate_reward_identity(&page.validator)?;
    if page.exposure.is_empty() || page.exposure.len() > MAX_REWARD_EXPOSURE_COHORTS {
        return Err("reward exposure page cohort bound exceeded".into());
    }
    let mut recipients = BTreeSet::new();
    let mut entry_count = 0usize;
    let mut service_total = 0u64;
    for cohort in &page.exposure {
        entry_count = entry_count
            .checked_add(cohort.stakes.len())
            .ok_or("reward exposure stake count overflow")?;
        if entry_count > MAX_REWARD_EXPOSURE_ENTRIES || cohort.stakes.len() > MAX_REWARD_RECIPIENTS
        {
            return Err("reward exposure page stake entry bound exceeded".into());
        }
        if cohort.service_blocks == 0
            || cohort.stakes.is_empty()
            || cohort.stakes.values().any(Quantity::is_zero)
        {
            return Err("reward exposure requires positive service and eligible stakes".into());
        }
        service_total = service_total
            .checked_add(cohort.service_blocks)
            .ok_or("reward exposure service count overflow")?;
        recipients.extend(cohort.stakes.keys());
        if recipients.len() > MAX_REWARD_RECIPIENTS {
            return Err("reward exposure page beneficiary bound exceeded".into());
        }
    }
    for recipient in recipients {
        validate_reward_identity(recipient)?;
    }
    if page
        .exposure
        .windows(2)
        .any(|pair| pair[0].stakes == pair[1].stakes)
    {
        return Err("adjacent reward exposure cohorts must be coalesced".into());
    }
    if norito::to_bytes(page)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_REWARD_EXPOSURE_BYTES
    {
        return Err("reward exposure page encoded byte bound exceeded".into());
    }
    Ok(())
}

/// Validate the bounded canonical archive envelope and its immediate predecessor identity.
///
/// Original certified witness inclusion and the full archive hash are checked by
/// the archive reader; following a predecessor also verifies its exact service range.
///
/// # Errors
/// Rejects an invalid page, missing or nonconsecutive predecessor, zero original
/// write height, or encoded archive exceeding its retained-byte bound.
pub fn validate_exposure_archive(archive: &ValidationFeeExposureArchive) -> Result<(), String> {
    validate_exposure_page(&archive.page)?;
    match &archive.previous {
        None if archive.page.page_index == 0 => (),
        Some(previous)
            if previous.recorded_at_height > 0
                && previous.page_index.checked_add(1) == Some(archive.page.page_index) => {}
        _ => return Err("exposure archive predecessor is missing or nonconsecutive".into()),
    }
    if norito::to_bytes(archive)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_REWARD_EXPOSURE_ARCHIVE_BYTES
    {
        return Err("reward exposure archive encoded byte bound exceeded".into());
    }
    Ok(())
}

/// Exact largest-remainder allocation over bounded nonnegative integer weights.
/// The weight domain is independent of the funded minor-unit output domain.
fn allocate_exact<K: Clone + Ord>(
    amount: u128,
    weights: &BTreeMap<K, BigInt>,
) -> Result<BTreeMap<K, u128>, String> {
    let mut total = BigInt::zero();
    for weight in weights.values() {
        if weight.is_negative() {
            return Err("negative reward allocation weight".into());
        }
        total = total
            .checked_add(weight)
            .map_err(|error| error.to_string())?;
    }
    if total.is_zero() {
        return Err("no authenticated reward allocation weight".into());
    }
    let amount_wide = BigInt::from(amount);
    let mut shares = BTreeMap::new();
    let mut remainders = Vec::new();
    let mut allocated = 0u128;
    for (account, weight) in weights.iter().filter(|(_, weight)| !weight.is_zero()) {
        let numerator = amount_wide
            .checked_mul(weight)
            .map_err(|error| error.to_string())?;
        let (share, remainder) = numerator
            .checked_div_rem(&total)
            .map_err(|error| error.to_string())?;
        let share = share
            .try_to_u128()
            .ok_or("reward allocation output overflow")?;
        allocated = allocated.checked_add(share).ok_or("reward sum overflow")?;
        shares.insert(account.clone(), share);
        remainders.push((remainder, account.clone()));
    }
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let remaining = amount
        .checked_sub(allocated)
        .ok_or("reward rounding underflow")?;
    let remaining = usize::try_from(remaining).map_err(|_| "reward rounding overflow")?;
    if remaining > remainders.len() {
        return Err("reward remainder exceeds recipient count".into());
    }
    for (_, account) in remainders.into_iter().take(remaining) {
        let share = shares
            .get_mut(&account)
            .ok_or("reward remainder account absent")?;
        *share = share.checked_add(1).ok_or("reward remainder overflow")?;
    }
    Ok(shares)
}

/// Canonical funded largest-remainder gross validator allocation.
///
/// # Errors
///
/// Returns an error for zero total service weight or overflowing checked
/// arithmetic. Intermediate products retain more than 128 bits.
pub fn allocate(
    amount: u128,
    weights: &BTreeMap<AccountId, u64>,
) -> Result<BTreeMap<AccountId, u128>, String> {
    if weights.len() > MAX_REWARD_VALIDATORS {
        return Err("monthly reward validator bound exceeded".into());
    }
    for validator in weights.keys() {
        validate_reward_identity(validator)?;
    }
    allocate_exact(
        amount,
        &weights
            .iter()
            .map(|(key, weight)| (key.clone(), BigInt::from(*weight)))
            .collect(),
    )
}

/// Allocate one historical exposure page from an already funded validator reward.
///
/// At cumulative service count `c`, exactly `floor(gross * c / total_service)`
/// minor units have been assigned. Each chronological cohort receives the
/// difference between its ending and starting cumulative quotients, then divides
/// that amount proportionally by exact stake using largest remainder with
/// canonical account order breaking ties. Commission is zero. Across contiguous
/// pages every funded minor unit is allocated exactly once, independently of when
/// funding arrives or pages are materialized. Stake quantities are never narrowed.
///
/// # Errors
///
/// Rejects invalid or oversized pages, out-of-range service coordinates,
/// arithmetic overflow, or loss of any funded minor unit.
pub fn allocate_page(
    gross: u128,
    total_service: u64,
    service_start: u64,
    page: &ValidationFeeExposurePage,
) -> Result<BTreeMap<AccountId, u128>, String> {
    validate_exposure_page(page)?;
    if total_service == 0 || service_start >= total_service {
        return Err("reward exposure page starts outside authenticated service".into());
    }
    let cumulative = |count: u64| -> Result<u128, String> {
        BigInt::from(gross)
            .checked_mul(&BigInt::from(count))
            .and_then(|value| value.checked_div_rem(&BigInt::from(total_service)))
            .map_err(|error| error.to_string())?
            .0
            .try_to_u128()
            .ok_or_else(|| "reward cumulative amount overflow".to_owned())
    };
    let initial = cumulative(service_start)?;
    let mut previous = initial;
    let mut service = service_start;
    let mut shares = BTreeMap::<AccountId, u128>::new();
    for cohort in &page.exposure {
        service = service
            .checked_add(cohort.service_blocks)
            .ok_or("reward exposure service count overflow")?;
        if service > total_service {
            return Err("reward exposure exceeds authenticated validator service".into());
        }
        let current = cumulative(service)?;
        let amount = current
            .checked_sub(previous)
            .ok_or("reward cumulative amount underflow")?;
        let scale = cohort
            .stakes
            .values()
            .map(Quantity::scale)
            .max()
            .ok_or("empty reward exposure cohort")?;
        let weights = cohort
            .stakes
            .iter()
            .map(|(account, stake)| {
                let multiplier =
                    BigInt::pow10(scale - stake.scale()).ok_or("reward stake scale overflow")?;
                let weight = stake
                    .mantissa()
                    .checked_mul(&multiplier)
                    .map_err(|error| error.to_string())?;
                Ok((account.clone(), weight))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        for (account, credit) in allocate_exact(amount, &weights)? {
            let accrued = shares.entry(account).or_default();
            *accrued = accrued
                .checked_add(credit)
                .ok_or("reward entitlement overflow")?;
        }
        previous = current;
    }
    if shares
        .values()
        .try_fold(0u128, |sum, share| sum.checked_add(*share))
        != previous.checked_sub(initial)
    {
        return Err("reward entitlement conservation failed".into());
    }
    Ok(shares)
}

/// Immutable alias from an account identity to its original reward beneficiary.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::validation_fee_rewards::ValidationFeeRewardBeneficiaryAlias"
)]
pub struct ValidationFeeRewardBeneficiaryAlias {
    /// Account whose historical earnings or claims use this beneficiary.
    pub account_id: AccountId,
    /// Original identity; never changes during recovery.
    pub beneficiary_id: AccountId,
}
/// Immutable authenticated owner revision, retained for claims before later recovery.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::validation_fee_rewards::ValidationFeeRewardBeneficiaryRevision"
)]
pub struct ValidationFeeRewardBeneficiaryRevision {
    /// Original reward beneficiary.
    pub beneficiary_id: AccountId,
    /// Monotonic owner revision; zero initializes the original owner.
    pub revision: u64,
    /// Account entitled to claim at this revision.
    pub account_id: AccountId,
    /// Previous authorized owner, absent only for initial revision zero.
    pub previous_account_id: Option<AccountId>,
    /// Block that authorized this owner revision.
    pub authorized_at_height: u64,
}
/// Canonical immutable account alias source key.
///
/// # Errors
///
/// Returns an error if the custody key cannot be derived or the beneficiary state
/// path cannot be represented.
pub fn validation_fee_beneficiary_alias_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    account: &AccountId,
) -> Result<StatePath, String> {
    validation_fee_reward_state_key(
        binding,
        &format!(
            "BeneficiaryAlias/{}",
            hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
        ),
    )
}
/// Canonical immutable owner revision source key.
///
/// # Errors
///
/// Returns an error if the custody key cannot be derived or the revision state path
/// cannot be represented.
pub fn validation_fee_beneficiary_revision_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    beneficiary: &AccountId,
    revision: u64,
) -> Result<StatePath, String> {
    validation_fee_reward_state_key(
        binding,
        &format!(
            "BeneficiaryHistory/{}/{revision:020}",
            hex::encode(Hash::new(beneficiary.to_string().as_bytes()).as_ref())
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(seed: u32) -> AccountId {
        AccountId::new(
            iroha_crypto::KeyPair::from_seed(
                seed.to_le_bytes().to_vec(),
                iroha_crypto::Algorithm::Ed25519,
            )
            .public_key()
            .clone(),
        )
    }
    fn cohort(
        service_blocks: u64,
        stakes: impl IntoIterator<Item = (AccountId, Quantity)>,
    ) -> ValidationFeeRewardExposure {
        ValidationFeeRewardExposure {
            service_blocks,
            stakes: stakes.into_iter().collect(),
        }
    }
    fn page(
        validator: &AccountId,
        page_index: u64,
        exposure: Vec<ValidationFeeRewardExposure>,
    ) -> ValidationFeeExposurePage {
        ValidationFeeExposurePage {
            earning_period_start_ms: 0,
            validator: validator.clone(),
            page_index,
            exposure,
        }
    }

    #[test]
    fn automatic_reward_shares_preserve_twenty_thirty_fifty() {
        let validator = account(1);
        let a = account(2);
        let b = account(3);
        let source = page(
            &validator,
            0,
            vec![cohort(
                7,
                [
                    (validator.clone(), Quantity::from(20u32)),
                    (a.clone(), Quantity::from(30u32)),
                    (b.clone(), Quantity::from(50u32)),
                ],
            )],
        );
        assert_eq!(
            allocate_page(100, 7, 0, &source).unwrap(),
            BTreeMap::from([(validator, 20), (a, 30), (b, 50)])
        );
    }

    #[test]
    fn reward_page_allocation_and_entitlement_norito_json_roundtrip() {
        let validator = account(1);
        let source = page(
            &validator,
            0,
            vec![cohort(1, [(validator.clone(), Quantity::one())])],
        );
        let bytes = norito::to_bytes(&source).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<ValidationFeeExposurePage>(&bytes).unwrap(),
            source
        );
        assert_eq!(
            norito::json::from_str::<ValidationFeeExposurePage>(
                &norito::json::to_json(&source).unwrap()
            )
            .unwrap(),
            source
        );
        let allocation = ValidationFeeRewardAllocation {
            sequence: 0,
            lifecycle_seal: [1; 32],
            earning_period_start_ms: 0,
            sbd_minor: 1,
            xor_minor: 100,
            converted_at_height: 2,
            converted_at_ms: 1,
            min_xor_minor: 100,
            reference_observations: vec![],
            service_blocks: BTreeMap::from([(validator.clone(), 1)]),
            gross_shares: BTreeMap::from([(validator.clone(), 100)]),
        };
        assert_eq!(
            norito::decode_from_bytes::<ValidationFeeRewardAllocation>(
                &norito::to_bytes(&allocation).unwrap()
            )
            .unwrap(),
            allocation
        );
        assert_eq!(
            norito::json::from_str::<ValidationFeeRewardAllocation>(
                &norito::json::to_json(&allocation).unwrap()
            )
            .unwrap(),
            allocation
        );
        let entitlement = ValidationFeeRewardEntitlement {
            allocation_sequence: 0,
            validator: validator.clone(),
            page_index: 0,
            service_start: 0,
            service_end: 1,
            recorded_at_height: 3,
            shares: BTreeMap::from([(validator.clone(), 100)]),
            beneficiaries: BTreeMap::from([(validator.clone(), validator.clone())]),
        };
        assert_eq!(
            norito::decode_from_bytes::<ValidationFeeRewardEntitlement>(
                &norito::to_bytes(&entitlement).unwrap()
            )
            .unwrap(),
            entitlement
        );
        assert_eq!(
            norito::json::from_str::<ValidationFeeRewardEntitlement>(
                &norito::json::to_json(&entitlement).unwrap()
            )
            .unwrap(),
            entitlement
        );
        let snapshot = ValidationFeeServiceSnapshot {
            earning_period_start_ms: 0,
            service_blocks: allocation.service_blocks,
        };
        assert_eq!(
            norito::decode_from_bytes::<ValidationFeeServiceSnapshot>(
                &norito::to_bytes(&snapshot).unwrap()
            )
            .unwrap(),
            snapshot
        );
        let state = ValidationFeeRewardsState {
            pending_sbd_total: 100,
            reserved_xor: 43,
            ..Default::default()
        };
        assert_eq!(
            norito::decode_from_bytes::<ValidationFeeRewardsState>(
                &norito::to_bytes(&state).unwrap()
            )
            .unwrap(),
            state
        );
    }

    #[test]
    fn changed_stake_and_multiple_validators_preserve_historical_cohorts() {
        let first = account(1);
        let second = account(2);
        let nominator = account(3);
        let late = account(4);
        let gross = allocate(
            80,
            &BTreeMap::from([(first.clone(), 2), (second.clone(), 6)]),
        )
        .unwrap();
        let first_page = page(
            &first,
            0,
            vec![
                cohort(1, [(nominator.clone(), Quantity::one())]),
                cohort(1, [(late.clone(), Quantity::one())]),
            ],
        );
        let second_page = page(
            &second,
            0,
            vec![cohort(
                6,
                [
                    (second.clone(), Quantity::one()),
                    (nominator.clone(), Quantity::from(2u32)),
                ],
            )],
        );
        let mut credited = allocate_page(gross[&first], 2, 0, &first_page).unwrap();
        for (account, amount) in allocate_page(gross[&second], 6, 0, &second_page).unwrap() {
            *credited.entry(account).or_default() += amount;
        }
        assert_eq!(
            credited,
            BTreeMap::from([(nominator, 50), (late, 10), (second, 20)])
        );
    }

    #[test]
    fn contiguous_pages_conserve_prefix_rounding_and_cannot_reassign_previous_service() {
        let validator = account(1);
        let a = account(2);
        let b = account(3);
        let c = account(4);
        let cohorts = vec![
            cohort(1, [(a.clone(), Quantity::one())]),
            cohort(1, [(b.clone(), Quantity::one())]),
            cohort(2, [(c.clone(), Quantity::one())]),
        ];
        let complete = allocate_page(3, 4, 0, &page(&validator, 0, cohorts.clone())).unwrap();
        let mut split =
            allocate_page(3, 4, 0, &page(&validator, 0, cohorts[..1].to_vec())).unwrap();
        split.extend(allocate_page(3, 4, 1, &page(&validator, 1, cohorts[1..].to_vec())).unwrap());
        assert_eq!(split, complete);
        assert_eq!(split, BTreeMap::from([(a, 0), (b, 1), (c, 2)]));
        assert!(allocate_page(3, 4, 3, &page(&validator, 1, cohorts.clone())).is_err());
        assert!(allocate_page(3, 0, 0, &page(&validator, 0, cohorts)).is_err());
    }

    #[test]
    fn exact_wide_stakes_and_reward_products_do_not_narrow() {
        let validator = account(1);
        let nominator = account(2);
        let huge: Quantity = format!("1{}", "0".repeat(100)).parse().unwrap();
        let double: Quantity = format!("2{}", "0".repeat(100)).parse().unwrap();
        assert!(huge.mantissa().try_to_u128().is_none());
        let source = page(
            &validator,
            0,
            vec![cohort(
                u64::MAX,
                [(validator.clone(), huge), (nominator.clone(), double)],
            )],
        );
        assert_eq!(
            allocate_page(u128::MAX, u64::MAX, 0, &source).unwrap(),
            BTreeMap::from([
                (validator.clone(), u128::MAX / 3),
                (nominator.clone(), (u128::MAX / 3) * 2)
            ])
        );
        let gross = allocate(
            u128::MAX,
            &BTreeMap::from([(validator, u64::MAX), (nominator, u64::MAX)]),
        )
        .unwrap();
        assert_eq!(gross.values().copied().sum::<u128>(), u128::MAX);
    }

    #[test]
    fn mixed_scale_stakes_and_remainders_preserve_every_minor_unit() {
        let validator = account(1);
        let accounts = [account(2), account(3), account(4)];
        let source = page(
            &validator,
            0,
            vec![cohort(
                1,
                [
                    (accounts[0].clone(), "0.1".parse().unwrap()),
                    (accounts[1].clone(), "0.3".parse().unwrap()),
                    (accounts[2].clone(), Quantity::one()),
                ],
            )],
        );
        assert_eq!(
            allocate_page(14, 1, 0, &source).unwrap(),
            BTreeMap::from([
                (accounts[0].clone(), 1),
                (accounts[1].clone(), 3),
                (accounts[2].clone(), 10)
            ])
        );
        let equal = BTreeMap::from([
            (accounts[0].clone(), BigInt::one()),
            (accounts[1].clone(), BigInt::one()),
            (accounts[2].clone(), BigInt::one()),
        ]);
        assert_eq!(
            allocate_exact(2, &equal)
                .unwrap()
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![1, 1, 0]
        );
        assert!(allocate_exact(1, &BTreeMap::from([(0usize, BigInt::from(-1i32))])).is_err());
        assert!(allocate(1, &BTreeMap::new()).is_err());
    }

    #[test]
    fn page_validation_bounds_work_without_bounding_monthly_stake_churn() {
        let validator = account(1);
        let valid = cohort(1, [(validator.clone(), Quantity::one())]);
        for exposure in [
            vec![],
            vec![cohort(0, [(validator.clone(), Quantity::one())])],
            vec![cohort(1, [(validator.clone(), Quantity::zero())])],
            vec![valid.clone(), valid],
        ] {
            assert!(validate_exposure_page(&page(&validator, 0, exposure)).is_err());
        }
        let excessive_cohorts = (1..=MAX_REWARD_EXPOSURE_COHORTS + 1)
            .map(|value| cohort(1, [(validator.clone(), Quantity::from(value as u64))]))
            .collect();
        assert!(validate_exposure_page(&page(&validator, 0, excessive_cohorts)).is_err());
        let excessive_recipients = (0..=MAX_REWARD_RECIPIENTS).map(|index| {
            (
                account(u32::try_from(index).expect("bounded reward account seed fits u32")),
                Quantity::one(),
            )
        });
        assert!(
            validate_exposure_page(&page(&validator, 0, vec![cohort(1, excessive_recipients)]))
                .is_err()
        );
        let recipients = (0..MAX_REWARD_RECIPIENTS)
            .map(|index| {
                account(u32::try_from(index).expect("bounded reward account seed fits u32"))
            })
            .collect::<Vec<_>>();
        let excessive_entries = (1..=MAX_REWARD_EXPOSURE_ENTRIES / MAX_REWARD_RECIPIENTS + 1)
            .map(|value| {
                cohort(
                    1,
                    recipients.iter().cloned().map(|account| {
                        (
                            account,
                            Quantity::from(
                                u32::try_from(value)
                                    .expect("bounded reward exposure value fits u32"),
                            ),
                        )
                    }),
                )
            })
            .collect();
        assert!(validate_exposure_page(&page(&validator, 0, excessive_entries)).is_err());
        let mut sum = 0u128;
        for index in 0..=MAX_REWARD_EXPOSURE_COHORTS {
            let source = page(
                &validator,
                index as u64,
                vec![cohort(
                    1,
                    [(
                        account(
                            u32::try_from(index).expect("bounded reward account seed fits u32"),
                        ),
                        Quantity::one(),
                    )],
                )],
            );
            validate_exposure_page(&source).unwrap();
            sum += allocate_page(
                100,
                (MAX_REWARD_EXPOSURE_COHORTS + 1) as u64,
                index as u64,
                &source,
            )
            .unwrap()
            .values()
            .sum::<u128>();
        }
        assert_eq!(
            sum, 100,
            "total monthly exposure may exceed every single-page bound"
        );
    }
}
