//! On-chain oracle instruction handlers.
use super::prelude::*;
use crate::state::{
    oracle_stage_deadline as stage_deadline, seed_oracle_change_stages as seed_change_stages,
};
use crate::{
    oracle::{FeedEventRecord, ObservationWindow, ObservationWindowKey},
    state::{StateTransaction, WorldTransaction},
};
use blake3::Hasher;
use iroha_crypto::{Algorithm, Hash, PublicKey, SignatureOf, ed25519_parse_signature};
use iroha_data_model::{
    events::data::oracle::{
        DefiOracleAttestationRecorded, OracleChangeProposed, OracleChangeStageUpdated, OracleEvent,
        TwitterBindingRecorded, TwitterBindingRevoked,
    },
    isi::{
        error::{InstructionExecutionError as Error, InvalidParameterError},
        oracle::{
            AggregateOracleFeed, OpenOracleDispute, ProposeOracleChange, RecordTwitterBinding,
            RegisterOracleFeed, ResolveOracleDispute, RevokeTwitterBinding, RollbackOracleChange,
            SubmitDefiOracleAttestation, SubmitOracleObservation, VoteOracleChangeStage,
        },
    },
    oracle::{
        DEFI_ORACLE_DOMAIN_COVER_POLICY, DEFI_ORACLE_DOMAIN_OPTIONS_SERIES,
        DEFI_ORACLE_DOMAIN_OPTIONS_SHOUT, DEFI_ORACLE_DOMAIN_PERPS_MARKET, DefiOracleAttestation,
        DefiOracleAttestationSource, FeedConfigVersion, FeedEventOutcome, FeedId, FeedSlot,
        Observation, ObservationOutcome, OracleChangeEvidence, OracleChangeFailure,
        OracleChangeProposal, OracleChangeStage, OracleChangeStageFailure, OracleChangeStatus,
        OracleDispute, OracleDisputeId, OracleDisputeOutcome, OracleDisputeStatus, OraclePenalty,
        OraclePenaltyKind, OracleProviderKey, OracleProviderStats, OracleReward,
        TwitterBindingAttestation, TwitterBindingRecord,
    },
    permission::{Permission as DataPermission, Permissions},
    prelude::*,
};
use iroha_executor_data_model::permission::oracle as oracle_permission;
use iroha_primitives::numeric::Quantity;
#[cfg(feature = "telemetry")]
use std::time::Instant;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
};
/// Exact retained Oracle purpose carried by a one-shot numeric movement capability.
pub(in crate::smartcontracts::isi) enum VerifiedOracleNumericPurpose {
    Reward {
        feed_id: FeedId,
        feed_config_version: FeedConfigVersion,
        slot: FeedSlot,
        request_hash: Hash,
        provider: AccountId,
    },
    Penalty {
        feed_id: FeedId,
        feed_config_version: FeedConfigVersion,
        slot: FeedSlot,
        request_hash: Hash,
        provider: AccountId,
        kind: OraclePenaltyKind,
    },
    DisputeEscrow {
        dispute_id: OracleDisputeId,
    },
}
/// Non-reusable proof that Oracle admission selected one exact retained movement.
pub(in crate::smartcontracts::isi) struct VerifiedOracleNumericMovement {
    purpose: VerifiedOracleNumericPurpose,
    source_id: AssetId,
    destination_id: AssetId,
    amount: Quantity,
}
impl VerifiedOracleNumericMovement {
    fn new(
        purpose: VerifiedOracleNumericPurpose,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            purpose,
            source_id,
            destination_id,
            amount,
        }
    }
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (VerifiedOracleNumericPurpose, AssetId, AssetId, Quantity) {
        (
            self.purpose,
            self.source_id,
            self.destination_id,
            self.amount,
        )
    }
}
fn aggregation_err(err: &iroha_data_model::oracle::OracleAggregationError) -> Error {
    Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
}
fn signature_err(message: impl Into<String>) -> Error {
    Error::InvalidParameter(InvalidParameterError::SmartContract(message.into()))
}
fn verify_typed_signature_for_signer<T: norito::codec::Encode>(
    signature: &SignatureOf<T>,
    signer: &PublicKey,
    value: &T,
) -> Result<(), iroha_crypto::Error> {
    match signer.try_algorithm() {
        Ok(Algorithm::Ed25519) => {
            ed25519_parse_signature(signature.payload())?;
        }
        Ok(Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_parse_signature(signature.payload())?;
        }
        _ => {}
    }
    signature.verify(signer, value)
}
fn has_permission_in_set(permissions: Option<&Permissions>, required: &DataPermission) -> bool {
    permissions.is_some_and(|permissions| permissions.contains(required))
}
fn has_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    required: &DataPermission,
) -> bool {
    if has_permission_in_set(
        state_transaction.world.account_permissions.get(authority),
        required,
    ) {
        return true;
    }
    let role_ids: Vec<_> = state_transaction
        .world
        .account_roles_iter(authority)
        .cloned()
        .collect();
    for role_id in role_ids {
        if let Some(role) = state_transaction.world.roles.get(&role_id)
            && role.permissions().any(|permission| permission == required)
        {
            return true;
        }
    }
    false
}
fn require_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    required: impl Into<DataPermission>,
    permission_name: &'static str,
) -> Result<(), Error> {
    let required = required.into();
    if has_permission(state_transaction, authority, &required) {
        Ok(())
    } else {
        Err(signature_err(format!(
            "authority `{authority}` does not have `{permission_name}`"
        )))
    }
}
fn ensure_provider_allowed(
    config: &iroha_data_model::oracle::FeedConfig,
    provider: &AccountId,
) -> Result<(), Error> {
    if config.providers.contains(provider) {
        Ok(())
    } else {
        Err(signature_err(format!(
            "oracle provider `{provider}` is not part of feed `{}`",
            config.feed_id.as_str()
        )))
    }
}
fn expected_twitter_feed_id(
    cfg: &iroha_config::parameters::actual::OracleTwitterBinding,
) -> FeedId {
    FeedId(cfg.feed_id.clone())
}
fn validate_binding_ttl(
    attestation: &TwitterBindingAttestation,
    cfg: &iroha_config::parameters::actual::OracleTwitterBinding,
) -> Result<(), Error> {
    if attestation.expires_at_ms <= attestation.observed_at_ms {
        return Err(signature_err(
            "twitter binding expiry must be greater than observed_at_ms",
        ));
    }
    let ttl = attestation
        .expires_at_ms
        .saturating_sub(attestation.observed_at_ms);
    if ttl > cfg.max_ttl_ms {
        return Err(signature_err(format!(
            "twitter binding TTL {}ms exceeds max {}ms",
            ttl, cfg.max_ttl_ms
        )));
    }
    if ttl < cfg.min_ttl_ms {
        return Err(signature_err(format!(
            "twitter binding TTL {}ms is below min {}ms",
            ttl, cfg.min_ttl_ms
        )));
    }
    Ok(())
}
fn ensure_binding_matches_history(
    state_transaction: &StateTransaction<'_, '_>,
    feed_id: &FeedId,
    attestation: &TwitterBindingAttestation,
) -> Result<(), Error> {
    let history = state_transaction
        .world
        .oracle_history
        .get(feed_id)
        .cloned()
        .unwrap_or_default();
    let expected_value = attestation.observation_value();
    let found = history.into_iter().rev().any(|record| {
        record.event.feed_config_version == attestation.feed_config_version
            && record.event.slot == attestation.slot
            && record.event.request_hash == attestation.request_hash
            && matches!(
                record.event.outcome,
                FeedEventOutcome::Success(ref success) if success.value == expected_value
            )
    });
    if found {
        Ok(())
    } else {
        Err(signature_err(format!(
            "no oracle feed event found for slot {} and binding hash in feed `{}`",
            attestation.slot,
            feed_id.as_str()
        )))
    }
}
fn retained_history_event<'world>(
    world: &'world WorldTransaction<'_, '_>,
    feed_id: &FeedId,
    feed_config_version: FeedConfigVersion,
    slot: FeedSlot,
    request_hash: Hash,
) -> Option<&'world FeedEventRecord> {
    world.oracle_history.get(feed_id)?.iter().find(|record| {
        record.event.feed_config_version == feed_config_version
            && record.event.slot == slot
            && record.event.request_hash == request_hash
    })
}
fn latest_retained_slot(world: &WorldTransaction<'_, '_>, feed_id: &FeedId) -> Option<FeedSlot> {
    world
        .oracle_history
        .get(feed_id)
        .and_then(|history| history.iter().map(|record| record.event.slot).max())
}
fn ensure_window_fresh_and_unprocessed(
    world: &WorldTransaction<'_, '_>,
    config: &iroha_data_model::oracle::FeedConfig,
    slot: FeedSlot,
    request_hash: Hash,
) -> Result<(), Error> {
    if retained_history_event(
        world,
        &config.feed_id,
        config.feed_config_version,
        slot,
        request_hash,
    )
    .is_some()
    {
        return Err(aggregation_err(
            &iroha_data_model::oracle::OracleAggregationError::ProcessedWindow {
                feed_id: config.feed_id.clone(),
                feed_config_version: config.feed_config_version,
                slot,
                request_hash,
            },
        ));
    }
    if let Some(latest_slot) = latest_retained_slot(world, &config.feed_id)
        && latest_slot > slot
        && latest_slot.saturating_sub(slot) > config.replay_window_slots.get()
    {
        return Err(aggregation_err(
            &iroha_data_model::oracle::OracleAggregationError::StaleWindow {
                feed_id: config.feed_id.clone(),
                feed_config_version: config.feed_config_version,
                slot,
                request_hash,
                latest_slot,
                replay_window_slots: config.replay_window_slots.get(),
            },
        ));
    }
    Ok(())
}
fn validate_feed_registration(
    feed: &iroha_data_model::oracle::FeedConfig,
    world: &WorldTransaction<'_, '_>,
    history_depth: NonZeroUsize,
) -> Result<(), Error> {
    // Enforce provider uniqueness and reasonable caps.
    let mut providers = BTreeSet::new();
    for provider in &feed.providers {
        if !providers.insert(provider.clone()) {
            return Err(signature_err(format!(
                "duplicate oracle provider `{provider}` in feed `{}`",
                feed.feed_id.as_str()
            )));
        }
    }
    if providers.is_empty() {
        return Err(signature_err(format!(
            "feed `{}` must list at least one provider",
            feed.feed_id.as_str()
        )));
    }
    if feed.min_signers == 0 {
        return Err(signature_err(format!(
            "feed `{}` must require at least one signer",
            feed.feed_id.as_str()
        )));
    }
    if feed.committee_size == 0 {
        return Err(signature_err(format!(
            "feed `{}` must have a non-zero committee size",
            feed.feed_id.as_str()
        )));
    }
    if providers.len() > usize::from(feed.max_observers) {
        return Err(signature_err(format!(
            "feed `{}` allows {}/{} observers",
            feed.feed_id.as_str(),
            providers.len(),
            feed.max_observers
        )));
    }
    if feed.committee_size > feed.max_observers {
        return Err(signature_err(format!(
            "feed `{}` committee_size {} exceeds max_observers {}",
            feed.feed_id.as_str(),
            feed.committee_size,
            feed.max_observers
        )));
    }
    if usize::from(feed.committee_size) > providers.len() {
        return Err(signature_err(format!(
            "feed `{}` committee_size {} exceeds providers {}",
            feed.feed_id.as_str(),
            feed.committee_size,
            providers.len()
        )));
    }
    if feed.min_signers > feed.committee_size {
        return Err(signature_err(format!(
            "feed `{}` min_signers {} exceeds committee_size {}",
            feed.feed_id.as_str(),
            feed.min_signers,
            feed.committee_size
        )));
    }
    if feed.max_error_rate_bps > 10_000 {
        return Err(signature_err(format!(
            "feed `{}` max_error_rate_bps {} exceeds 10000",
            feed.feed_id.as_str(),
            feed.max_error_rate_bps
        )));
    }
    let replay_window = usize::try_from(feed.replay_window_slots.get()).unwrap_or(usize::MAX);
    if replay_window > history_depth.get() {
        return Err(signature_err(format!(
            "feed `{}` replay_window_slots {} exceeds retained history depth {}",
            feed.feed_id.as_str(),
            feed.replay_window_slots.get(),
            history_depth.get()
        )));
    }
    if let Some(existing) = world.oracle_feeds.get(&feed.feed_id) {
        if existing.feed_config_version >= feed.feed_config_version {
            return Err(signature_err(format!(
                "feed `{}` already registered with version {} (incoming {})",
                feed.feed_id.as_str(),
                existing.feed_config_version.0,
                feed.feed_config_version.0
            )));
        }
    }
    Ok(())
}
fn required_votes(
    stage: iroha_data_model::oracle::OracleChangeStage,
    class: iroha_data_model::oracle::OracleChangeClass,
    cfg: &iroha_config::parameters::actual::OracleGovernance,
) -> NonZeroUsize {
    use iroha_data_model::oracle::OracleChangeStage as Stage;
    match stage {
        Stage::Intake => cfg.intake_min_votes,
        Stage::RulesCommittee => cfg.rules_min_votes,
        Stage::CopReview => class.required_votes(
            cfg.cop_min_votes.low,
            cfg.cop_min_votes.medium,
            cfg.cop_min_votes.high,
        ),
        Stage::TechnicalAudit => cfg.technical_min_votes,
        Stage::PolicyJury => class.required_votes(
            cfg.policy_jury_min_votes.low,
            cfg.policy_jury_min_votes.medium,
            cfg.policy_jury_min_votes.high,
        ),
        Stage::Enactment => NonZeroUsize::new(1).expect("non-zero"),
    }
}
fn append_stage_evidence(
    proposal: &mut iroha_data_model::oracle::OracleChangeProposal,
    stage: iroha_data_model::oracle::OracleChangeStage,
    evidence_hashes: &[Hash],
) {
    if evidence_hashes.is_empty() {
        return;
    }
    if let Some(record) = proposal
        .stages
        .iter_mut()
        .find(|record| record.stage == stage)
    {
        for hash in evidence_hashes {
            if !record.evidence.contains(hash) {
                record.evidence.push(*hash);
            }
            proposal.evidence.push(OracleChangeEvidence {
                stage,
                evidence_hash: *hash,
                note: None,
            });
        }
    }
}
#[derive(Clone, Copy)]
enum ProviderOutcome {
    Inlier,
    Outlier,
    Error,
    NoShow,
}
fn classify_providers(
    config: &iroha_data_model::oracle::FeedConfig,
    observations: &[Observation],
    outcome: &iroha_data_model::oracle::FeedEventOutcome,
) -> BTreeMap<AccountId, ProviderOutcome> {
    let mut map = BTreeMap::new();
    for obs in observations {
        match obs.body.outcome {
            ObservationOutcome::Value(_) => {
                map.insert(obs.body.provider_id.clone(), ProviderOutcome::Inlier);
            }
            ObservationOutcome::Error(_) => {
                map.insert(obs.body.provider_id.clone(), ProviderOutcome::Error);
            }
        }
    }
    if let iroha_data_model::oracle::FeedEventOutcome::Success(success) = outcome {
        for entry in &success.entries {
            map.insert(
                entry.oracle_id.clone(),
                if entry.outlier {
                    ProviderOutcome::Outlier
                } else {
                    ProviderOutcome::Inlier
                },
            );
        }
    }
    for provider in &config.providers {
        map.entry(provider.clone())
            .or_insert(ProviderOutcome::NoShow);
    }
    map
}
fn with_provider_stats_mut<F>(
    world: &mut WorldTransaction<'_, '_>,
    feed_id: &FeedId,
    provider: &AccountId,
    mut f: F,
) where
    F: FnMut(&mut OracleProviderStats),
{
    let key = OracleProviderKey::new(feed_id.clone(), provider.clone());
    let mut stats = world
        .oracle_provider_stats
        .get(&key)
        .copied()
        .unwrap_or_default();
    f(&mut stats);
    world.oracle_provider_stats.insert(key, stats);
}
fn reward_provider(
    state_transaction: &mut StateTransaction<'_, '_>,
    feed_id: &FeedId,
    feed_config_version: FeedConfigVersion,
    slot: FeedSlot,
    request_hash: Hash,
    provider: &AccountId,
) -> Result<(), Error> {
    let economics = &state_transaction.oracle.economics;
    let amount = economics.reward_amount.clone();
    let pool_asset = AssetId::new(
        economics.reward_asset.clone(),
        economics.reward_pool.clone(),
    );
    let provider_asset = AssetId::new(economics.reward_asset.clone(), provider.clone());
    if amount.is_zero() {
        return Ok(());
    }
    let movement = VerifiedOracleNumericMovement::new(
        VerifiedOracleNumericPurpose::Reward {
            feed_id: feed_id.clone(),
            feed_config_version,
            slot,
            request_hash,
            provider: provider.clone(),
        },
        pool_asset,
        provider_asset,
        amount.clone(),
    );
    crate::smartcontracts::isi::asset::isi::execute_verified_oracle_numeric_movement(
        state_transaction,
        movement,
    )?;
    with_provider_stats_mut(&mut state_transaction.world, feed_id, provider, |stats| {
        stats.inliers = stats.inliers.saturating_add(1);
        stats.record_reward();
    });
    state_transaction
        .world
        .emit_events(Some(OracleEvent::RewardApplied(OracleReward {
            feed_id: feed_id.clone(),
            feed_config_version,
            slot,
            request_hash,
            oracle_id: provider.clone(),
            amount: amount.clone(),
        })));
    #[cfg(feature = "telemetry")]
    {
        state_transaction
            .telemetry
            .observe_oracle_reward(feed_id, &amount);
    }
    Ok(())
}
fn slash_provider(
    state_transaction: &mut StateTransaction<'_, '_>,
    feed_id: &FeedId,
    ctx: (FeedConfigVersion, FeedSlot, Hash),
    provider: &AccountId,
    kind: OraclePenaltyKind,
    amount: &Quantity,
) -> Result<(), Error> {
    let (feed_config_version, slot, request_hash) = ctx;
    let economics = &state_transaction.oracle.economics;
    let provider_asset = AssetId::new(economics.slash_asset.clone(), provider.clone());
    let receiver_asset = AssetId::new(
        economics.slash_asset.clone(),
        economics.slash_receiver.clone(),
    );
    if amount.is_zero() {
        return Ok(());
    }
    let movement = VerifiedOracleNumericMovement::new(
        VerifiedOracleNumericPurpose::Penalty {
            feed_id: feed_id.clone(),
            feed_config_version,
            slot,
            request_hash,
            provider: provider.clone(),
            kind,
        },
        provider_asset,
        receiver_asset,
        amount.clone(),
    );
    crate::smartcontracts::isi::asset::isi::execute_verified_oracle_numeric_movement(
        state_transaction,
        movement,
    )?;
    with_provider_stats_mut(&mut state_transaction.world, feed_id, provider, |stats| {
        match kind {
            OraclePenaltyKind::Outlier => {
                stats.outliers = stats.outliers.saturating_add(1);
            }
            OraclePenaltyKind::Error => {
                stats.errors = stats.errors.saturating_add(1);
            }
            OraclePenaltyKind::NoShow => {
                stats.no_shows = stats.no_shows.saturating_add(1);
            }
            OraclePenaltyKind::BadSignature | OraclePenaltyKind::Dispute => {}
        }
        stats.record_slash();
    });
    state_transaction
        .world
        .emit_events(Some(OracleEvent::PenaltyApplied(OraclePenalty {
            feed_id: feed_id.clone(),
            feed_config_version,
            slot,
            request_hash,
            oracle_id: provider.clone(),
            kind,
            amount: amount.clone(),
        })));
    #[cfg(feature = "telemetry")]
    {
        state_transaction
            .telemetry
            .observe_oracle_penalty(feed_id, amount, kind);
    }
    Ok(())
}
fn apply_economics_for_slot(
    state_transaction: &mut StateTransaction<'_, '_>,
    config: &iroha_data_model::oracle::FeedConfig,
    observations: &[Observation],
    outcome: &iroha_data_model::oracle::FeedEventOutcome,
    slot: FeedSlot,
    request_hash: Hash,
) -> Result<(), Error> {
    let feed_version = config.feed_config_version;
    let classifications = classify_providers(config, observations, outcome);
    let economics = state_transaction.oracle.economics.clone();
    for (provider, class) in classifications {
        match class {
            ProviderOutcome::Inlier => reward_provider(
                state_transaction,
                &config.feed_id,
                feed_version,
                slot,
                request_hash,
                &provider,
            )?,
            ProviderOutcome::Outlier => slash_provider(
                state_transaction,
                &config.feed_id,
                (feed_version, slot, request_hash),
                &provider,
                OraclePenaltyKind::Outlier,
                &economics.slash_outlier_amount,
            )?,
            ProviderOutcome::Error => slash_provider(
                state_transaction,
                &config.feed_id,
                (feed_version, slot, request_hash),
                &provider,
                OraclePenaltyKind::Error,
                &economics.slash_error_amount,
            )?,
            ProviderOutcome::NoShow => slash_provider(
                state_transaction,
                &config.feed_id,
                (feed_version, slot, request_hash),
                &provider,
                OraclePenaltyKind::NoShow,
                &economics.slash_no_show_amount,
            )?,
        }
    }
    Ok(())
}
fn ensure_dispute_anchors_to_history(
    world: &WorldTransaction<'_, '_>,
    config: &iroha_data_model::oracle::FeedConfig,
    slot: FeedSlot,
    request_hash: Hash,
    target: &AccountId,
    evidence_hashes: &[Hash],
) -> Result<(), Error> {
    if evidence_hashes.is_empty() {
        return Err(signature_err("oracle dispute evidence must not be empty"));
    }
    let record = retained_history_event(
        world,
        &config.feed_id,
        config.feed_config_version,
        slot,
        request_hash,
    )
    .ok_or_else(|| {
        signature_err(format!(
            "no retained oracle feed event for feed `{}` version {} slot {} request {}",
            config.feed_id.as_str(),
            config.feed_config_version.0,
            slot,
            request_hash
        ))
    })?;
    if let Some(latest_slot) = latest_retained_slot(world, &config.feed_id)
        && latest_slot > slot
        && latest_slot.saturating_sub(slot) > config.dispute_window_slots.get()
    {
        return Err(signature_err(format!(
            "dispute for feed `{}` slot {} is outside dispute window {} from latest retained slot {}",
            config.feed_id.as_str(),
            slot,
            config.dispute_window_slots.get(),
            latest_slot
        )));
    }
    if let FeedEventOutcome::Success(success) = &record.event.outcome
        && !success
            .entries
            .iter()
            .any(|entry| &entry.oracle_id == target)
    {
        return Err(signature_err(format!(
            "target provider `{target}` did not contribute to the disputed successful event"
        )));
    }
    Ok(())
}
fn derive_dispute_id(
    feed_id: &FeedId,
    slot: FeedSlot,
    request_hash: Hash,
    challenger: &AccountId,
    target: &AccountId,
) -> OracleDisputeId {
    let mut hasher = Hasher::new();
    hasher.update(feed_id.as_str().as_bytes());
    hasher.update(&slot.to_le_bytes());
    hasher.update(request_hash.as_ref());
    hasher.update(challenger.to_string().as_bytes());
    hasher.update(target.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&digest.as_bytes()[..8]);
    OracleDisputeId(u64::from_le_bytes(buf))
}
fn payload_u64(payload: &norito::json::Map, field: &str) -> Result<u64, Error> {
    let value = payload
        .get(field)
        .ok_or_else(|| signature_err(format!("DeFi oracle payload missing `{field}`")))?;
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    if let Some(value) = value.as_i64()
        && let Ok(value) = u64::try_from(value)
    {
        return Ok(value);
    }
    Err(signature_err(format!(
        "DeFi oracle payload field `{field}` must be a non-negative integer"
    )))
}
fn checked_observation_integer(
    value: iroha_data_model::oracle::ObservationValue,
) -> Result<u64, Error> {
    if value.mantissa < 0 {
        return Err(signature_err("DeFi source feed value must be non-negative"));
    }
    let mut divisor = 1_i128;
    for _ in 0..value.scale {
        divisor = divisor
            .checked_mul(10)
            .ok_or_else(|| signature_err("DeFi source feed scale overflow"))?;
    }
    if divisor > 1 && value.mantissa % divisor != 0 {
        return Err(signature_err(
            "DeFi source feed value must resolve to an integer payload field",
        ));
    }
    let normalized = value.mantissa / divisor;
    u64::try_from(normalized).map_err(|_| signature_err("DeFi source feed value exceeds u64 range"))
}
fn find_retained_source_event<'a>(
    world: &'a WorldTransaction<'_, '_>,
    source: &DefiOracleAttestationSource,
) -> Option<&'a FeedEventRecord> {
    world
        .oracle_history
        .get(&source.feed_id)?
        .iter()
        .find(|record| {
            record.event.slot == source.slot && record.event.request_hash == source.request_hash
        })
}
fn derive_defi_attestation_hash(attestation: &DefiOracleAttestation) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"defi-oracle-attestation-v1");
    hasher.update(&attestation.key.domain.to_le_bytes());
    hasher.update(&attestation.key.subject_id.to_le_bytes());
    hasher.update(&attestation.oracle_slot.to_le_bytes());
    hasher.update(&attestation.status_flags.to_le_bytes());
    for source in &attestation.source_events {
        hasher.update(source.feed_id.as_str().as_bytes());
        hasher.update(&source.slot.to_le_bytes());
        hasher.update(source.request_hash.as_ref());
        hasher.update(source.field.as_bytes());
    }
    let digest = hasher.finalize();
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&digest.as_bytes()[..8]);
    let value = u64::from_le_bytes(buf) & i64::MAX as u64;
    value.max(1)
}
fn verify_defi_oracle_signature(
    public_key: &PublicKey,
    attestation: &DefiOracleAttestation,
) -> Result<(), Error> {
    let signature = ed25519_parse_signature(&attestation.oracle_signature)
        .map_err(|err| signature_err(format!("invalid DeFi oracle signature material: {err}")))?;
    signature
        .verify(public_key, &attestation.oracle_payload)
        .map_err(|err| signature_err(format!("invalid DeFi oracle signature: {err}")))
}
fn parse_defi_oracle_signer_public_key(signer_public_key: &[u8]) -> Result<PublicKey, Error> {
    PublicKey::from_bytes(Algorithm::Ed25519, signer_public_key)
        .map_err(|err| signature_err(format!("invalid DeFi signer public key: {err}")))
}
fn validate_defi_payload_shape(
    attestation: &DefiOracleAttestation,
) -> Result<norito::json::Map, Error> {
    if !attestation.key.has_supported_domain() {
        return Err(signature_err(format!(
            "unsupported DeFi oracle domain {}",
            attestation.key.domain
        )));
    }
    if attestation.oracle_payload.is_empty() {
        return Err(signature_err("DeFi oracle payload must not be empty"));
    }
    if attestation.oracle_signature.is_empty() {
        return Err(signature_err("DeFi oracle signature must not be empty"));
    }
    let value: norito::json::Value = norito::json::from_slice(&attestation.oracle_payload)
        .map_err(|err| signature_err(format!("invalid DeFi oracle JSON payload: {err}")))?;
    let object = value
        .as_object()
        .cloned()
        .ok_or_else(|| signature_err("DeFi oracle payload must be a JSON object"))?;
    let domain = payload_u64(&object, "domain")?;
    if domain != u64::from(attestation.key.domain) {
        return Err(signature_err("DeFi oracle payload domain mismatch"));
    }
    let subject_field = attestation
        .key
        .subject_field()
        .ok_or_else(|| signature_err("unsupported DeFi oracle domain"))?;
    let subject_id = payload_u64(&object, subject_field)?;
    if subject_id != attestation.key.subject_id {
        return Err(signature_err("DeFi oracle payload subject mismatch"));
    }
    if payload_u64(&object, "oracle_slot")? != attestation.oracle_slot {
        return Err(signature_err("DeFi oracle payload slot mismatch"));
    }
    if payload_u64(&object, "status_flags")? != u64::from(attestation.status_flags) {
        return Err(signature_err("DeFi oracle payload status_flags mismatch"));
    }
    if payload_u64(&object, "attestation_hash")? != attestation.attestation_hash {
        return Err(signature_err(
            "DeFi oracle payload attestation_hash mismatch",
        ));
    }
    if attestation.attestation_hash == 0 {
        return Err(signature_err(
            "DeFi oracle attestation_hash must be non-zero",
        ));
    }
    if !attestation.source_events.is_empty()
        && attestation.attestation_hash != derive_defi_attestation_hash(attestation)
    {
        return Err(signature_err(
            "DeFi oracle attestation_hash is not deterministic",
        ));
    }
    match attestation.key.domain {
        DEFI_ORACLE_DOMAIN_PERPS_MARKET => {
            for field in ["mark_price_bps", "index_price_bps", "confidence_bps"] {
                let _ = payload_u64(&object, field)?;
            }
        }
        DEFI_ORACLE_DOMAIN_OPTIONS_SERIES => {
            for field in ["final_mark", "final_quote_mark"] {
                let _ = payload_u64(&object, field)?;
            }
        }
        DEFI_ORACLE_DOMAIN_OPTIONS_SHOUT => {
            let _ = payload_u64(&object, "mark_price_bps")?;
        }
        DEFI_ORACLE_DOMAIN_COVER_POLICY => {
            let _ = payload_u64(&object, "observed_price")?;
        }
        _ => {}
    }
    Ok(object)
}
fn validate_defi_sources(
    world: &WorldTransaction<'_, '_>,
    attestation: &DefiOracleAttestation,
    payload: &norito::json::Map,
    provider: &AccountId,
) -> Result<(), Error> {
    for source in &attestation.source_events {
        if source.field.is_empty() {
            return Err(signature_err("DeFi oracle source field must not be empty"));
        }
        let config = world.oracle_feeds.get(&source.feed_id).ok_or_else(|| {
            Error::Find(iroha_data_model::query::error::FindError::OracleFeed(
                source.feed_id.clone(),
            ))
        })?;
        ensure_provider_allowed(config, provider)?;
        let record = find_retained_source_event(world, source).ok_or_else(|| {
            signature_err(format!(
                "no retained oracle feed event for feed `{}` slot {} request {}",
                source.feed_id.as_str(),
                source.slot,
                source.request_hash
            ))
        })?;
        let FeedEventOutcome::Success(success) = &record.event.outcome else {
            return Err(signature_err(format!(
                "DeFi oracle source feed `{}` did not produce a successful value",
                source.feed_id.as_str()
            )));
        };
        if !success
            .entries
            .iter()
            .any(|entry| &entry.oracle_id == provider)
        {
            return Err(signature_err(format!(
                "DeFi oracle provider `{provider}` did not contribute to feed `{}`",
                source.feed_id.as_str()
            )));
        }
        let expected = payload_u64(payload, &source.field)?;
        let actual = checked_observation_integer(success.value)?;
        if actual != expected {
            return Err(signature_err(format!(
                "DeFi oracle source field `{}` value {} does not match payload value {}",
                source.field, actual, expected
            )));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{KeyPair, Signature, SignatureOf};
    use iroha_data_model::oracle::{DefiOracleAttestationKey, kits};
    fn checked_ed25519_keypair() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("DeFi oracle fixture key generation should succeed")
    }
    fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
            panic!("{algorithm:?} oracle fixture key generation should succeed: {err}")
        })
    }
    fn provider() -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![0xA7; 32], Algorithm::Ed25519)
            .expect("DeFi oracle provider fixture key generation should succeed");
        AccountId::new(keypair.public_key().clone())
    }
    fn direct_defi_attestation(attestation_hash: u64) -> DefiOracleAttestation {
        DefiOracleAttestation {
            key: DefiOracleAttestationKey::new(DEFI_ORACLE_DOMAIN_PERPS_MARKET, 42),
            provider: provider(),
            oracle_slot: 11,
            status_flags: 0,
            attestation_hash,
            oracle_payload: format!(
                "{{\"domain\":1,\"market_id\":42,\"mark_price_bps\":10000,\"index_price_bps\":10000,\"confidence_bps\":5,\"oracle_slot\":11,\"status_flags\":0,\"attestation_hash\":{attestation_hash}}}"
            )
            .into_bytes(),
            oracle_signature: vec![7; 64],
            signer_public_key: vec![9; 32],
            oracle_scheme: 1,
            source_events: Vec::new(),
        }
    }
    fn observation_body(provider: AccountId) -> iroha_data_model::oracle::ObservationBody {
        iroha_data_model::oracle::ObservationBody {
            feed_id: FeedId("price_xor_usd".parse().expect("oracle feed id")),
            feed_config_version: FeedConfigVersion(1),
            slot: 11,
            provider_id: provider,
            connector_id: "test-connector".to_owned(),
            connector_version: 1,
            request_hash: Hash::new(b"oracle-observation-request"),
            outcome: ObservationOutcome::Value(iroha_data_model::oracle::ObservationValue::new(
                12_345, 2,
            )),
            timestamp_ms: Some(1_700_000_000_123),
        }
    }
    const SMALL_ORDER_ED25519_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn signature_of_with_malformed_ed25519_r<T>(
        signature: &SignatureOf<T>,
        replacement_r: &[u8; 32],
    ) -> SignatureOf<T> {
        let mut payload = signature.payload().to_vec();
        payload[..replacement_r.len()].copy_from_slice(replacement_r);
        SignatureOf::from_signature(Signature::from_bytes(&payload))
    }
    #[test]
    fn direct_defi_attestation_shape_accepts_empty_sources() {
        validate_defi_payload_shape(&direct_defi_attestation(17))
            .expect("direct provider-signed attestation should not require source events");
    }
    #[test]
    fn direct_defi_attestation_shape_rejects_zero_hash() {
        let err = validate_defi_payload_shape(&direct_defi_attestation(0))
            .expect_err("zero compatibility hash must reject");
        assert!(format!("{err:?}").contains("attestation_hash must be non-zero"));
    }
    #[test]
    fn defi_oracle_signature_rejects_all_zero_signature_material() {
        let keypair = checked_ed25519_keypair();
        let mut attestation = direct_defi_attestation(17);
        attestation.oracle_signature = vec![0; 64];
        let err = verify_defi_oracle_signature(keypair.public_key(), &attestation)
            .expect_err("all-zero signature material must reject before verification");
        let Error::InvalidParameter(InvalidParameterError::SmartContract(message)) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(
            message.contains("signature payload must not be empty or all zero"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn defi_oracle_signer_public_key_rejects_inert_or_malformed_ed25519_material() {
        for (label, signer_public_key) in [
            ("all-zero", [0_u8; 32]),
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let err = parse_defi_oracle_signer_public_key(&signer_public_key)
                .expect_err("malformed DeFi oracle signer public key must fail admission");
            let Error::InvalidParameter(InvalidParameterError::SmartContract(message)) = err else {
                panic!("unexpected error for {label} signer public key: {err:?}");
            };
            assert!(
                message.contains("invalid DeFi signer public key"),
                "{label} signer public key produced unexpected error message: {message}"
            );
        }
    }
    #[test]
    fn defi_oracle_signature_rejects_malformed_ed25519_signature_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let keypair = checked_ed25519_keypair();
        let mut attestation = direct_defi_attestation(17);
        let valid_signature =
            Signature::try_new(keypair.private_key(), &attestation.oracle_payload)
                .expect("DeFi oracle fixture signing should succeed")
                .payload()
                .to_vec();
        attestation.oracle_signature = valid_signature.clone();
        verify_defi_oracle_signature(keypair.public_key(), &attestation)
            .expect("valid DeFi oracle signature should verify");
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut malformed_signature = valid_signature.clone();
            malformed_signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            attestation.oracle_signature = malformed_signature;
            let err = verify_defi_oracle_signature(keypair.public_key(), &attestation)
                .expect_err("malformed DeFi oracle signature R must fail admission");
            let Error::InvalidParameter(InvalidParameterError::SmartContract(message)) = err else {
                panic!("unexpected error: {err:?}");
            };
            assert!(
                message.contains("invalid DeFi oracle signature material"),
                "{label} R should fail as invalid material before verification: {message}"
            );
        }
    }
    #[test]
    fn oracle_observation_signature_rejects_malformed_ed25519_signature_r() {
        let keypair = checked_ed25519_keypair();
        let body = observation_body(AccountId::new(keypair.public_key().clone()));
        let signature = SignatureOf::try_new(keypair.private_key(), &body)
            .expect("oracle observation fixture signing should succeed");
        verify_typed_signature_for_signer(&signature, keypair.public_key(), &body)
            .expect("valid oracle observation signature should verify");
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let malformed_signature =
                signature_of_with_malformed_ed25519_r(&signature, &replacement_r);
            let err = verify_typed_signature_for_signer(
                &malformed_signature,
                keypair.public_key(),
                &body,
            )
            .expect_err("malformed oracle observation signature R must fail admission");
            assert!(
                matches!(err, iroha_crypto::Error::BadSignature),
                "{label} observation signature R should fail before typed verification: {err:?}"
            );
        }
    }
    #[test]
    fn oracle_observation_signature_rejects_malformed_mldsa_signature_lengths() {
        let keypair = checked_keypair_with_algorithm(Algorithm::MlDsa);
        let body = observation_body(AccountId::new(keypair.public_key().clone()));
        let signature = SignatureOf::try_new(keypair.private_key(), &body)
            .expect("oracle ML-DSA observation fixture signing should succeed");
        verify_typed_signature_for_signer(&signature, keypair.public_key(), &body)
            .expect("valid oracle ML-DSA observation signature should verify");
        let valid_signature = signature.payload().to_vec();
        for (label, replacement_signature) in [
            (
                "short",
                valid_signature[..valid_signature.len() - 1].to_vec(),
            ),
            ("overlong", {
                let mut payload = valid_signature.clone();
                payload.push(0x65);
                payload
            }),
        ] {
            let malformed_signature =
                SignatureOf::from_signature(Signature::from_bytes(&replacement_signature));
            let err = verify_typed_signature_for_signer(
                &malformed_signature,
                keypair.public_key(),
                &body,
            )
            .expect_err("malformed oracle ML-DSA signature length must fail admission");
            assert!(
                matches!(err, iroha_crypto::Error::BadSignature),
                "{label} observation ML-DSA signature length should fail before typed verification: {err:?}"
            );
        }
    }
    #[test]
    fn source_linked_defi_attestation_keeps_deterministic_hash_check() {
        let mut attestation = direct_defi_attestation(17);
        let kit = kits::price_xor_usd();
        attestation.source_events.push(DefiOracleAttestationSource {
            feed_id: kit.feed_config.feed_id,
            slot: 11,
            request_hash: kit.connector_request.request_hash(),
            field: "mark_price_bps".to_owned(),
        });
        let err = validate_defi_payload_shape(&attestation)
            .expect_err("source-linked attestation must keep deterministic hash validation");
        assert!(format!("{err:?}").contains("attestation_hash is not deterministic"));
        let deterministic_hash = derive_defi_attestation_hash(&attestation);
        attestation.attestation_hash = deterministic_hash;
        attestation.oracle_payload = format!(
            "{{\"domain\":1,\"market_id\":42,\"mark_price_bps\":10000,\"index_price_bps\":10000,\"confidence_bps\":5,\"oracle_slot\":11,\"status_flags\":0,\"attestation_hash\":{deterministic_hash}}}"
        )
        .into_bytes();
        validate_defi_payload_shape(&attestation)
            .expect("source-linked attestation with deterministic hash should validate");
    }
}
impl Execute for RegisterOracleFeed {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let feed = self.feed;
        require_permission(
            state_transaction,
            authority,
            oracle_permission::CanRegisterOracleFeed,
            "CanRegisterOracleFeed",
        )?;
        validate_feed_registration(
            &feed,
            &state_transaction.world,
            state_transaction.oracle.history_depth,
        )?;
        // Persist the new configuration.
        state_transaction
            .world
            .oracle_feeds
            .insert(feed.feed_id.clone(), feed);
        Ok(())
    }
}
impl Execute for SubmitOracleObservation {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let observation = self.observation;
        let provider = &observation.body.provider_id;
        if provider != authority {
            return Err(signature_err(format!(
                "authority `{authority}` is not the observation provider `{provider}`"
            )));
        }
        let config = state_transaction
            .world
            .oracle_feeds
            .get(&observation.body.feed_id)
            .cloned()
            .ok_or_else(|| {
                signature_err(format!(
                    "oracle feed `{}` is not registered",
                    observation.body.feed_id.as_str()
                ))
            })?;
        ensure_provider_allowed(&config, provider)?;
        ensure_window_fresh_and_unprocessed(
            &state_transaction.world,
            &config,
            observation.body.slot,
            observation.body.request_hash,
        )?;
        // Verify the provider signature over the observation payload.
        let signatory = provider.controller().single_signatory().ok_or_else(|| {
            signature_err("oracle providers must use single-signature controllers")
        })?;
        if let Err(err) =
            verify_typed_signature_for_signer(&observation.signature, signatory, &observation.body)
        {
            let slash_amount = state_transaction
                .oracle
                .economics
                .slash_error_amount
                .clone();
            let _ = slash_provider(
                state_transaction,
                &observation.body.feed_id,
                (
                    config.feed_config_version,
                    observation.body.slot,
                    observation.body.request_hash,
                ),
                provider,
                OraclePenaltyKind::BadSignature,
                &slash_amount,
            );
            return Err(signature_err(format!(
                "invalid observation signature: {err}"
            )));
        }
        // Buffer the observation for its `(feed, slot, request_hash)` window.
        let key = ObservationWindowKey::new(
            observation.body.feed_id.clone(),
            observation.body.feed_config_version,
            observation.body.slot,
            observation.body.request_hash,
        );
        let mut window = state_transaction
            .world
            .oracle_observations
            .get(&key)
            .cloned()
            .unwrap_or_else(|| ObservationWindow::new(&key));
        window
            .push(&config, observation.clone())
            .map_err(|err| aggregation_err(&err))?;
        crate::validation_fee_rewards::retain_authenticated_observation(
            state_transaction,
            &observation,
        )?;
        state_transaction
            .world
            .oracle_observations
            .insert(key, window);
        Ok(())
    }
}
impl Execute for SubmitDefiOracleAttestation {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let attestation = self.attestation;
        let provider = &attestation.provider;
        if provider != authority {
            return Err(signature_err(format!(
                "authority `{authority}` is not the DeFi oracle provider `{provider}`"
            )));
        }
        if attestation.oracle_scheme != 1 {
            return Err(signature_err(
                "DeFi oracle attestation currently requires Ed25519 scheme 1",
            ));
        }
        let provider_signatory = provider.controller().single_signatory().ok_or_else(|| {
            signature_err("DeFi oracle providers must use single-signature controllers")
        })?;
        let public_key = parse_defi_oracle_signer_public_key(&attestation.signer_public_key)?;
        if &public_key != provider_signatory {
            return Err(signature_err(
                "DeFi oracle signer must match provider account controller",
            ));
        }
        verify_defi_oracle_signature(&public_key, &attestation)?;
        let payload = validate_defi_payload_shape(&attestation)?;
        validate_defi_sources(&state_transaction.world, &attestation, &payload, provider)?;
        let key = attestation.key;
        let mut retained = state_transaction
            .world
            .defi_oracle_attestations
            .get(&key)
            .cloned()
            .unwrap_or_default();
        if let Some(last) = retained.last()
            && attestation.oracle_slot <= last.oracle_slot
        {
            return Err(signature_err(
                "DeFi oracle attestation slot must increase for the subject",
            ));
        }
        retained.push(attestation.clone());
        let depth = state_transaction.oracle.history_depth.get();
        if retained.len() > depth {
            let drop_count = retained.len() - depth;
            retained.drain(0..drop_count);
        }
        state_transaction
            .world
            .defi_oracle_attestations
            .insert(key, retained);
        state_transaction
            .world
            .emit_events(Some(OracleEvent::DefiAttestationRecorded(
                DefiOracleAttestationRecorded { attestation },
            )));
        Ok(())
    }
}
impl Execute for AggregateOracleFeed {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let config = state_transaction
            .world
            .oracle_feeds
            .get(&self.feed_id)
            .cloned()
            .ok_or_else(|| {
                signature_err(format!(
                    "oracle feed `{}` is not registered",
                    self.feed_id.as_str()
                ))
            })?;
        ensure_provider_allowed(&config, authority)?;
        ensure_window_fresh_and_unprocessed(
            &state_transaction.world,
            &config,
            self.slot,
            self.request_hash,
        )?;
        let key = ObservationWindowKey::new(
            self.feed_id.clone(),
            config.feed_config_version,
            self.slot,
            self.request_hash,
        );
        let window = state_transaction
            .world
            .oracle_observations
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                aggregation_err(
                    &iroha_data_model::oracle::OracleAggregationError::InsufficientQuorum {
                        required: config.min_signers,
                        provided: 0,
                    },
                )
            })?;
        let observations = window.into_sorted();
        #[cfg(feature = "telemetry")]
        let started = Instant::now();
        let output = crate::oracle::aggregate(
            &config,
            self.slot,
            self.request_hash,
            authority.clone(),
            &observations,
        )
        .map_err(|err| aggregation_err(&err))?;
        state_transaction.world.oracle_observations.remove(key);
        let record = FeedEventRecord {
            event: output.into_feed_event(),
            recorded_at_ms: state_transaction.block_unix_timestamp_ms(),
            evidence_hashes: self.evidence_hashes,
        };
        apply_economics_for_slot(
            state_transaction,
            &config,
            &observations,
            &record.event.outcome,
            self.slot,
            self.request_hash,
        )?;
        // Persist bounded history (per feed).
        let mut history = state_transaction
            .world
            .oracle_history
            .get(&self.feed_id)
            .cloned()
            .unwrap_or_default();
        history.push(record.clone());
        let max_history = state_transaction.oracle.history_depth.get();
        if history.len() > max_history {
            let excess = history.len() - max_history;
            history.drain(0..excess);
        }
        state_transaction
            .world
            .oracle_history
            .insert(self.feed_id.clone(), history);
        // Emit data event for subscribers.
        state_transaction
            .world
            .emit_events(Some(OracleEvent::FeedProcessed(record.clone())));
        #[cfg(feature = "telemetry")]
        {
            state_transaction.telemetry.observe_oracle_aggregation(
                &self.feed_id,
                observations.len() as u64,
                &record.evidence_hashes,
                started.elapsed(),
            );
        }
        Ok(())
    }
}
impl Execute for OpenOracleDispute {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let config = state_transaction
            .world
            .oracle_feeds
            .get(&self.feed_id)
            .ok_or_else(|| {
                signature_err(format!(
                    "oracle feed `{}` is not registered",
                    self.feed_id.as_str()
                ))
            })?;
        ensure_provider_allowed(config, &self.target)?;
        ensure_dispute_anchors_to_history(
            &state_transaction.world,
            config,
            self.slot,
            self.request_hash,
            &self.target,
            &self.evidence_hashes,
        )?;
        let economics = state_transaction.oracle.economics.clone();
        let bond_amount = self
            .bond
            .unwrap_or_else(|| economics.dispute_bond_amount.clone());
        let challenger_asset =
            AssetId::new(economics.dispute_bond_asset.clone(), authority.clone());
        let escrow_asset = AssetId::new(
            economics.dispute_bond_asset.clone(),
            economics.slash_receiver.clone(),
        );
        let dispute_id = derive_dispute_id(
            &self.feed_id,
            self.slot,
            self.request_hash,
            authority,
            &self.target,
        );
        if state_transaction
            .world
            .oracle_disputes
            .get(&dispute_id)
            .is_some()
        {
            return Err(signature_err(format!(
                "dispute `{}` already exists",
                dispute_id.0
            )));
        }
        crate::smartcontracts::isi::asset::isi::execute_oracle_dispute_bond_transfer(
            state_transaction,
            authority,
            dispute_id,
            challenger_asset,
            escrow_asset,
            bond_amount.clone(),
        )?;
        let dispute = OracleDispute {
            id: dispute_id,
            feed_id: self.feed_id,
            slot: self.slot,
            request_hash: self.request_hash,
            challenger: authority.clone(),
            target: self.target,
            bond: bond_amount,
            evidence: self.evidence_hashes,
            reason: self.reason,
            status: OracleDisputeStatus::Open,
        };
        state_transaction
            .world
            .oracle_disputes
            .insert(dispute_id, dispute.clone());
        state_transaction
            .world
            .emit_events(Some(OracleEvent::DisputeOpened(dispute)));
        Ok(())
    }
}
struct DisputeAssets {
    escrow: AssetId,
    challenger: AssetId,
    target: AssetId,
}
impl DisputeAssets {
    fn new(
        economics: &iroha_config::parameters::actual::OracleEconomics,
        challenger: &AccountId,
        target: &AccountId,
    ) -> Self {
        let escrow = AssetId::new(
            economics.dispute_bond_asset.clone(),
            economics.slash_receiver.clone(),
        );
        let challenger = AssetId::new(economics.dispute_bond_asset.clone(), challenger.clone());
        let target = AssetId::new(economics.dispute_bond_asset.clone(), target.clone());
        Self {
            escrow,
            challenger,
            target,
        }
    }
}
struct DisputeEconomics {
    outlier_slash: Quantity,
    error_slash: Quantity,
    reward: Quantity,
    frivolous_slash: Quantity,
}
impl DisputeEconomics {
    fn from_config(economics: &iroha_config::parameters::actual::OracleEconomics) -> Self {
        Self {
            outlier_slash: economics.slash_outlier_amount.clone(),
            error_slash: economics.slash_error_amount.clone(),
            reward: economics.dispute_reward_amount.clone(),
            frivolous_slash: economics.frivolous_slash_amount.clone(),
        }
    }
}
fn resolve_upheld_dispute(
    state_transaction: &mut StateTransaction<'_, '_>,
    dispute: &OracleDispute,
    ctx: (FeedConfigVersion, FeedSlot, Hash),
    economics: &DisputeEconomics,
    assets: &DisputeAssets,
) -> Result<(), Error> {
    slash_provider(
        state_transaction,
        &dispute.feed_id,
        ctx,
        &dispute.target,
        OraclePenaltyKind::Dispute,
        &economics.outlier_slash,
    )?;
    move_from_escrow(
        state_transaction,
        dispute,
        assets,
        &dispute.bond,
        &assets.challenger,
    )?;
    move_from_escrow(
        state_transaction,
        dispute,
        assets,
        &economics.reward,
        &assets.challenger,
    )
}
fn resolve_reduced_dispute(
    state_transaction: &mut StateTransaction<'_, '_>,
    dispute: &OracleDispute,
    ctx: (FeedConfigVersion, FeedSlot, Hash),
    economics: &DisputeEconomics,
    assets: &DisputeAssets,
) -> Result<(), Error> {
    slash_provider(
        state_transaction,
        &dispute.feed_id,
        ctx,
        &dispute.target,
        OraclePenaltyKind::Dispute,
        &economics.error_slash,
    )?;
    move_from_escrow(
        state_transaction,
        dispute,
        assets,
        &dispute.bond,
        &assets.challenger,
    )
}
fn resolve_frivolous_dispute(
    state_transaction: &mut StateTransaction<'_, '_>,
    dispute: &OracleDispute,
    economics: &DisputeEconomics,
    assets: &DisputeAssets,
) -> Result<(), Error> {
    move_from_escrow(
        state_transaction,
        dispute,
        assets,
        &economics.frivolous_slash,
        &assets.target,
    )
}
fn move_from_escrow(
    state_transaction: &mut StateTransaction<'_, '_>,
    dispute: &OracleDispute,
    assets: &DisputeAssets,
    amount: &Quantity,
    destination: &AssetId,
) -> Result<(), Error> {
    let movement = VerifiedOracleNumericMovement::new(
        VerifiedOracleNumericPurpose::DisputeEscrow {
            dispute_id: dispute.id,
        },
        assets.escrow.clone(),
        destination.clone(),
        amount.clone(),
    );
    crate::smartcontracts::isi::asset::isi::execute_verified_oracle_numeric_movement(
        state_transaction,
        movement,
    )
}
impl Execute for ResolveOracleDispute {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            oracle_permission::CanResolveOracleDispute,
            "CanResolveOracleDispute",
        )?;
        let Some(mut dispute) = state_transaction
            .world
            .oracle_disputes
            .get(&self.dispute_id)
            .cloned()
        else {
            return Err(signature_err(format!(
                "dispute `{}` does not exist",
                self.dispute_id.0
            )));
        };
        if !matches!(dispute.status, OracleDisputeStatus::Open) {
            return Err(signature_err(format!(
                "dispute `{}` already resolved",
                dispute.id.0
            )));
        }
        let economics_cfg = state_transaction.oracle.economics.clone();
        let config = state_transaction
            .world
            .oracle_feeds
            .get(&dispute.feed_id)
            .cloned()
            .ok_or_else(|| {
                signature_err(format!(
                    "oracle feed `{}` is not registered",
                    dispute.feed_id.as_str()
                ))
            })?;
        let assets = DisputeAssets::new(&economics_cfg, &dispute.challenger, &dispute.target);
        let economics = DisputeEconomics::from_config(&economics_cfg);
        let ctx = (
            config.feed_config_version,
            dispute.slot,
            dispute.request_hash,
        );
        match self.outcome {
            OracleDisputeOutcome::Upheld => {
                resolve_upheld_dispute(state_transaction, &dispute, ctx, &economics, &assets)?
            }
            OracleDisputeOutcome::Reduced => {
                resolve_reduced_dispute(state_transaction, &dispute, ctx, &economics, &assets)?
            }
            OracleDisputeOutcome::Frivolous => {
                resolve_frivolous_dispute(state_transaction, &dispute, &economics, &assets)?
            }
        }
        dispute.status = OracleDisputeStatus::Resolved(self.outcome);
        state_transaction
            .world
            .oracle_disputes
            .insert(dispute.id, dispute.clone());
        state_transaction
            .world
            .emit_events(Some(OracleEvent::DisputeResolved(dispute)));
        Ok(())
    }
}
impl Execute for ProposeOracleChange {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if state_transaction
            .world
            .oracle_changes
            .get(&self.change_id)
            .is_some()
        {
            return Err(signature_err(format!(
                "oracle change `{}` already exists",
                self.change_id.as_hash()
            )));
        }
        require_permission(
            state_transaction,
            authority,
            oracle_permission::CanProposeOracleChange,
            "CanProposeOracleChange",
        )?;
        validate_feed_registration(
            &self.feed,
            &state_transaction.world,
            state_transaction.oracle.history_depth,
        )?;
        let created_at = state_transaction.block_height();
        let mut proposal = OracleChangeProposal {
            id: self.change_id,
            feed: self.feed,
            class: self.class,
            payload_hash: self.payload_hash,
            proposer: authority.clone(),
            created_at,
            evidence: Vec::new(),
            stages: seed_change_stages(created_at, &state_transaction.oracle.governance),
            status: OracleChangeStatus::Pending,
        };
        append_stage_evidence(
            &mut proposal,
            OracleChangeStage::Intake,
            &self.evidence_hashes,
        );
        state_transaction
            .world
            .oracle_changes
            .insert(self.change_id, proposal.clone());
        state_transaction
            .world
            .emit_events(Some(OracleEvent::ChangeProposed(OracleChangeProposed {
                change_id: self.change_id,
                feed_id: proposal.feed.feed_id.clone(),
                class: proposal.class,
                payload_hash: proposal.payload_hash,
                proposer: authority.clone(),
            })));
        if let Some(intake) = proposal
            .stages
            .iter()
            .find(|stage| stage.stage == OracleChangeStage::Intake)
        {
            state_transaction
                .world
                .emit_events(Some(OracleEvent::ChangeStageUpdated(
                    OracleChangeStageUpdated {
                        change_id: proposal.id,
                        stage: OracleChangeStage::Intake,
                        status: proposal.status.clone(),
                        approvals: u32::try_from(intake.approvals.len()).unwrap_or(u32::MAX),
                        rejections: u32::try_from(intake.rejections.len()).unwrap_or(u32::MAX),
                        evidence_hashes: intake.evidence.clone(),
                    },
                )));
        }
        Ok(())
    }
}
fn start_stage_if_needed(
    proposal: &mut OracleChangeProposal,
    stage: OracleChangeStage,
    now: u64,
    cfg: &iroha_config::parameters::actual::OracleGovernance,
) {
    if let Some(record) = proposal
        .stages
        .iter_mut()
        .find(|record| record.stage == stage)
    {
        if record.started_at.is_none() {
            record.started_at = Some(now);
            record.deadline = stage_deadline(stage, cfg, now);
        }
    }
}
fn enact_change(
    state_transaction: &mut StateTransaction<'_, '_>,
    proposal: &OracleChangeProposal,
) -> Result<(), Error> {
    validate_feed_registration(
        &proposal.feed,
        &state_transaction.world,
        state_transaction.oracle.history_depth,
    )?;
    state_transaction
        .world
        .oracle_feeds
        .insert(proposal.feed.feed_id.clone(), proposal.feed.clone());
    Ok(())
}
impl Execute for VoteOracleChangeStage {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            oracle_permission::CanVoteOracleChangeStage { stage: self.stage },
            "CanVoteOracleChangeStage",
        )?;
        let Some(mut proposal) = state_transaction
            .world
            .oracle_changes
            .get(&self.change_id)
            .cloned()
        else {
            return Err(signature_err(format!(
                "oracle change `{}` is not registered",
                self.change_id.as_hash()
            )));
        };
        if proposal.status.is_terminal() {
            return Err(signature_err(format!(
                "oracle change `{}` is already finalized",
                proposal.id.as_hash()
            )));
        }
        let now = state_transaction.block_height();
        if proposal.stages.is_empty() {
            proposal.stages = seed_change_stages(now, &state_transaction.oracle.governance);
        }
        let active_stage = proposal
            .current_stage()
            .map(|stage| stage.stage)
            .ok_or_else(|| signature_err("oracle change has no active stage"))?;
        if self.stage != active_stage {
            let direction = if self.stage.order() < active_stage.order() {
                "past"
            } else {
                "future"
            };
            return Err(signature_err(format!(
                "cannot vote {direction} oracle change stage {:?}; active stage is {:?}",
                self.stage, active_stage
            )));
        }
        start_stage_if_needed(
            &mut proposal,
            active_stage,
            now,
            &state_transaction.oracle.governance,
        );
        append_stage_evidence(&mut proposal, self.stage, &self.evidence_hashes);
        let stage_idx = proposal
            .stages
            .iter()
            .position(|record| record.stage == self.stage)
            .ok_or_else(|| {
                signature_err(format!(
                    "stage {:?} is not part of the oracle change pipeline",
                    self.stage
                ))
            })?;
        let mut next_stage = None;
        let mut should_enact = false;
        let mut status_update: Option<OracleChangeStatus> = None;
        let approvals;
        let rejections;
        let evidence_hashes;
        {
            let stage_rec = proposal
                .stages
                .get_mut(stage_idx)
                .expect("stage exists by index");
            if !stage_rec.is_pending() {
                return Err(signature_err("stage already completed or failed"));
            }
            if self.approve {
                stage_rec.approvals.insert(authority.clone());
                let needed = required_votes(
                    stage_rec.stage,
                    proposal.class,
                    &state_transaction.oracle.governance,
                );
                if stage_rec.approvals.len() >= needed.get() {
                    stage_rec.completed_at = Some(now);
                    if let Some(next) = stage_rec.stage.next() {
                        next_stage = Some(next);
                    } else {
                        should_enact = true;
                    }
                }
            } else {
                stage_rec.rejections.insert(authority.clone());
                stage_rec.failure = Some(OracleChangeStageFailure::Rejected);
                stage_rec.completed_at.get_or_insert(now);
                status_update = Some(OracleChangeStatus::Failed(OracleChangeFailure {
                    stage: stage_rec.stage,
                    reason: OracleChangeStageFailure::Rejected,
                    at: now,
                }));
            }
            approvals = u32::try_from(stage_rec.approvals.len()).unwrap_or(u32::MAX);
            rejections = u32::try_from(stage_rec.rejections.len()).unwrap_or(u32::MAX);
            evidence_hashes = stage_rec.evidence.clone();
        }
        if let Some(next) = next_stage {
            start_stage_if_needed(
                &mut proposal,
                next,
                now,
                &state_transaction.oracle.governance,
            );
        }
        if self.approve && should_enact {
            enact_change(state_transaction, &proposal)?;
            if let Some(enact) = proposal
                .stages
                .iter_mut()
                .find(|record| record.stage == OracleChangeStage::Enactment)
            {
                enact.started_at.get_or_insert(now);
                if let Some(deadline) = stage_deadline(
                    OracleChangeStage::Enactment,
                    &state_transaction.oracle.governance,
                    now,
                ) {
                    enact.deadline.get_or_insert(deadline);
                }
                enact.completed_at.get_or_insert(now);
            }
            status_update = Some(OracleChangeStatus::Enacted(now));
        }
        if let Some(status) = status_update {
            proposal.status = status;
        }
        state_transaction
            .world
            .oracle_changes
            .insert(self.change_id, proposal.clone());
        state_transaction
            .world
            .emit_events(Some(OracleEvent::ChangeStageUpdated(
                OracleChangeStageUpdated {
                    change_id: self.change_id,
                    stage: self.stage,
                    status: proposal.status.clone(),
                    approvals,
                    rejections,
                    evidence_hashes,
                },
            )));
        Ok(())
    }
}
/// Oracle-specific query handlers.
pub mod query {
    use crate::{
        smartcontracts::{ValidQuery, ValidSingularQuery},
        state::{StateReadOnly, WorldReadOnly},
    };
    use eyre::Result;
    use iroha_data_model::{
        events::data::oracle::FeedEventRecord,
        oracle::{
            DefiOracleAttestation, FeedConfig, OracleChangeProposal, OracleDispute,
            OracleProviderStats, OracleProviderStatsRecord, TwitterBindingRecord,
        },
        query::{
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::{FindError, QueryExecutionFail as Error},
            oracle::prelude::{
                FindDefiOracleAttestationsByKey, FindLatestDefiOracleAttestation,
                FindOracleChangeById, FindOracleChanges, FindOracleDisputeById, FindOracleDisputes,
                FindOracleDisputesByFeedId, FindOracleFeedById, FindOracleFeeds,
                FindOracleHistoryByFeedId, FindOracleProviderStatsByFeedId,
                FindOracleProviderStatsByKey, FindTwitterBindingByHash, FindTwitterBindingsByUaid,
            },
        },
    };
    use iroha_telemetry::metrics;
    use mv::storage::StorageReadOnly;
    impl ValidSingularQuery for FindOracleFeedById {
        #[metrics(+"find_oracle_feed_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<FeedConfig, Error> {
            state_ro
                .world()
                .oracle_feeds()
                .get(&self.feed_id)
                .ok_or_else(|| Error::Find(FindError::OracleFeed(self.feed_id.clone())))
                .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
        }
    }
    impl ValidSingularQuery for FindOracleDisputeById {
        #[metrics(+"find_oracle_dispute_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<OracleDispute, Error> {
            state_ro
                .world()
                .oracle_disputes()
                .get(&self.dispute_id)
                .ok_or_else(|| Error::Find(FindError::OracleDispute(self.dispute_id)))
                .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
        }
    }
    impl ValidSingularQuery for FindOracleChangeById {
        #[metrics(+"find_oracle_change_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<OracleChangeProposal, Error> {
            state_ro
                .world()
                .oracle_changes()
                .get(&self.change_id)
                .ok_or_else(|| Error::Find(FindError::OracleChange(self.change_id)))
                .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
        }
    }
    impl ValidSingularQuery for FindOracleProviderStatsByKey {
        #[metrics(+"find_oracle_provider_stats_by_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<OracleProviderStats, Error> {
            state_ro
                .world()
                .oracle_provider_stats()
                .get(&self.key)
                .copied()
                .ok_or_else(|| Error::Find(FindError::OracleProviderStats(self.key.clone())))
        }
    }
    impl ValidSingularQuery for FindTwitterBindingByHash {
        #[metrics(+"find_twitter_binding_by_hash")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<TwitterBindingRecord, Error> {
            state_ro
                .world()
                .twitter_bindings()
                .get(&self.binding_hash.digest)
                .ok_or_else(|| Error::Find(FindError::TwitterBinding(self.binding_hash.clone())))
                .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
        }
    }
    impl ValidSingularQuery for FindLatestDefiOracleAttestation {
        #[metrics(+"find_latest_defi_oracle_attestation")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<DefiOracleAttestation, Error> {
            state_ro
                .world()
                .defi_oracle_attestations()
                .get(&self.key)
                .and_then(|items| items.last())
                .ok_or_else(|| Error::Find(FindError::DefiOracleAttestation(self.key)))
                .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
        }
    }
    impl ValidQuery for FindOracleFeeds {
        #[metrics(+"find_oracle_feeds")]
        fn execute(
            self,
            filter: CompoundPredicate<FeedConfig>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = FeedConfig>, Error> {
            let items = state_ro
                .world()
                .oracle_feeds()
                .iter()
                .map(|(_, feed)| feed.clone())
                .filter(move |feed| filter.applies(feed))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
    impl ValidQuery for FindOracleHistoryByFeedId {
        #[metrics(+"find_oracle_history_by_feed_id")]
        fn execute(
            self,
            filter: CompoundPredicate<FeedEventRecord>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = FeedEventRecord>, Error> {
            let items = state_ro
                .world()
                .oracle_history()
                .get(&self.feed_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(move |record| filter.applies(record))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
    impl ValidQuery for FindOracleProviderStatsByFeedId {
        #[metrics(+"find_oracle_provider_stats_by_feed_id")]
        fn execute(
            self,
            filter: CompoundPredicate<OracleProviderStatsRecord>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = OracleProviderStatsRecord>, Error> {
            let feed_id = self.feed_id;
            let items = state_ro
                .world()
                .oracle_provider_stats()
                .iter()
                .filter(|&(key, _stats)| key.feed_id == feed_id)
                .map(|(key, stats)| OracleProviderStatsRecord {
                    key: key.clone(),
                    stats: *stats,
                })
                .filter(move |record| filter.applies(record))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
    impl ValidQuery for FindDefiOracleAttestationsByKey {
        #[metrics(+"find_defi_oracle_attestations_by_key")]
        fn execute(
            self,
            filter: CompoundPredicate<DefiOracleAttestation>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = DefiOracleAttestation>, Error> {
            let items = state_ro
                .world()
                .defi_oracle_attestations()
                .get(&self.key)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(move |attestation| filter.applies(attestation))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
    impl ValidQuery for FindOracleDisputes {
        #[metrics(+"find_oracle_disputes")]
        fn execute(
            self,
            filter: CompoundPredicate<OracleDispute>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = OracleDispute>, Error> {
            let items = state_ro
                .world()
                .oracle_disputes()
                .iter()
                .map(|(_, dispute)| dispute.clone())
                .filter(move |dispute| filter.applies(dispute))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
    impl ValidQuery for FindOracleDisputesByFeedId {
        #[metrics(+"find_oracle_disputes_by_feed_id")]
        fn execute(
            self,
            filter: CompoundPredicate<OracleDispute>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = OracleDispute>, Error> {
            let feed_id = self.feed_id;
            let items = state_ro
                .world()
                .oracle_disputes()
                .iter()
                .filter(|&(_, dispute)| dispute.feed_id == feed_id)
                .map(|(_, dispute)| dispute.clone())
                .filter(move |dispute| filter.applies(dispute))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
    impl ValidQuery for FindOracleChanges {
        #[metrics(+"find_oracle_changes")]
        fn execute(
            self,
            filter: CompoundPredicate<OracleChangeProposal>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = OracleChangeProposal>, Error> {
            let items = state_ro
                .world()
                .oracle_changes()
                .iter()
                .map(|(_, change)| change.clone())
                .filter(move |change| filter.applies(change))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
    impl ValidQuery for FindTwitterBindingsByUaid {
        #[metrics(+"find_twitter_bindings_by_uaid")]
        fn execute(
            self,
            filter: CompoundPredicate<TwitterBindingRecord>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = TwitterBindingRecord>, Error> {
            let digests = state_ro
                .world()
                .twitter_bindings_by_uaid()
                .get(&self.uaid)
                .cloned()
                .unwrap_or_default();
            let items = digests
                .into_iter()
                .filter_map(|digest| state_ro.world().twitter_bindings().get(&digest).cloned())
                .filter(move |record| filter.applies(record))
                .collect::<Vec<_>>();
            Ok(items.into_iter())
        }
    }
}
impl Execute for RecordTwitterBinding {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            oracle_permission::CanManageTwitterBindings,
            "CanManageTwitterBindings",
        )?;
        let RecordTwitterBinding {
            attestation,
            feed_id,
        } = self;
        let cfg = &state_transaction.oracle.twitter_binding;
        let expected_feed_id = expected_twitter_feed_id(cfg);
        if feed_id != expected_feed_id {
            return Err(signature_err(format!(
                "twitter binding feed `{}` does not match configured feed `{}`",
                feed_id.as_str(),
                expected_feed_id.as_str()
            )));
        }
        let feed_config = state_transaction
            .world
            .oracle_feeds
            .get(&feed_id)
            .cloned()
            .ok_or_else(|| {
                signature_err(format!(
                    "oracle feed `{}` is not registered",
                    feed_id.as_str()
                ))
            })?;
        ensure_provider_allowed(&feed_config, authority)?;
        if attestation.feed_config_version != feed_config.feed_config_version {
            return Err(signature_err(format!(
                "attestation feed_config_version {} does not match registered version {}",
                attestation.feed_config_version.0, feed_config.feed_config_version.0
            )));
        }
        if attestation.binding_hash.pepper_id != cfg.pepper_id {
            return Err(signature_err(format!(
                "twitter binding pepper `{}` does not match expected `{}`",
                attestation.binding_hash.pepper_id, cfg.pepper_id
            )));
        }
        validate_binding_ttl(&attestation, cfg)?;
        let now_ms = state_transaction.block_unix_timestamp_ms();
        if attestation.is_expired(now_ms) {
            return Err(signature_err(
                "twitter binding attestation is already expired",
            ));
        }
        ensure_binding_matches_history(state_transaction, &feed_id, &attestation)?;
        let digest = attestation.binding_hash.digest;
        if let Some(existing) = state_transaction.world.twitter_bindings.get(&digest) {
            let spacing = attestation
                .observed_at_ms
                .saturating_sub(existing.attestation.observed_at_ms);
            if spacing < cfg.min_update_spacing_ms && !existing.attestation.is_expired(now_ms) {
                return Err(signature_err(format!(
                    "twitter binding update too frequent: {}ms < {}ms",
                    spacing, cfg.min_update_spacing_ms
                )));
            }
        }
        let record = TwitterBindingRecord {
            feed_id,
            provider: authority.clone(),
            attestation,
            recorded_at_ms: now_ms,
        };
        let binding_digest = record.binding_digest();
        state_transaction
            .world
            .twitter_bindings
            .insert(binding_digest, record.clone());
        let mut uaid_index = state_transaction
            .world
            .twitter_bindings_by_uaid
            .get(&record.attestation.uaid)
            .cloned()
            .unwrap_or_default();
        if !uaid_index.contains(&binding_digest) {
            uaid_index.push(binding_digest);
        }
        state_transaction
            .world
            .twitter_bindings_by_uaid
            .insert(record.attestation.uaid, uaid_index);
        state_transaction
            .world
            .emit_events(Some(OracleEvent::TwitterBindingRecorded(
                TwitterBindingRecorded {
                    record: record.clone(),
                },
            )));
        #[cfg(feature = "telemetry")]
        {
            state_transaction.telemetry.observe_twitter_binding(
                record.feed_id.as_str(),
                record.attestation.status,
                record.attestation.is_expired(now_ms),
            );
        }
        Ok(())
    }
}
impl Execute for RevokeTwitterBinding {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            oracle_permission::CanManageTwitterBindings,
            "CanManageTwitterBindings",
        )?;
        let cfg = &state_transaction.oracle.twitter_binding;
        let feed_id = expected_twitter_feed_id(cfg);
        let feed_config = state_transaction
            .world
            .oracle_feeds
            .get(&feed_id)
            .cloned()
            .ok_or_else(|| {
                signature_err(format!(
                    "oracle feed `{}` is not registered",
                    feed_id.as_str()
                ))
            })?;
        ensure_provider_allowed(&feed_config, authority)?;
        let digest = self.binding_hash.digest;
        let Some(record) = state_transaction.world.twitter_bindings.remove(digest) else {
            return Err(signature_err("twitter binding not found"));
        };
        if let Some(mut uaids) = state_transaction
            .world
            .twitter_bindings_by_uaid
            .get(&record.attestation.uaid)
            .cloned()
        {
            uaids.retain(|existing| existing != &digest);
            if uaids.is_empty() {
                state_transaction
                    .world
                    .twitter_bindings_by_uaid
                    .remove(record.attestation.uaid);
            } else {
                state_transaction
                    .world
                    .twitter_bindings_by_uaid
                    .insert(record.attestation.uaid, uaids);
            }
        }
        let now_ms = state_transaction.block_unix_timestamp_ms();
        state_transaction
            .world
            .emit_events(Some(OracleEvent::TwitterBindingRevoked(
                TwitterBindingRevoked {
                    binding_hash: self.binding_hash,
                    revoked_by: authority.clone(),
                    reason: self.reason,
                    recorded_at_ms: now_ms,
                },
            )));
        Ok(())
    }
}
impl Execute for RollbackOracleChange {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        require_permission(
            state_transaction,
            authority,
            oracle_permission::CanRollbackOracleChange,
            "CanRollbackOracleChange",
        )?;
        let Some(mut proposal) = state_transaction
            .world
            .oracle_changes
            .get(&self.change_id)
            .cloned()
        else {
            return Err(signature_err(format!(
                "oracle change `{}` is not registered",
                self.change_id.as_hash()
            )));
        };
        if proposal.status.is_terminal() {
            return Err(signature_err(format!(
                "oracle change `{}` is already finalized",
                self.change_id.as_hash()
            )));
        }
        let now = state_transaction.block_height();
        let target_stage = self
            .stage
            .or_else(|| proposal.current_stage().map(|stage| stage.stage))
            .unwrap_or(OracleChangeStage::Enactment);
        if let Some(active_stage) = proposal.current_stage().map(|stage| stage.stage)
            && target_stage != active_stage
        {
            let direction = if target_stage.order() < active_stage.order() {
                "past"
            } else {
                "future"
            };
            return Err(signature_err(format!(
                "cannot roll back {direction} oracle change stage {target_stage:?}; active stage is {active_stage:?}"
            )));
        }
        if let Some(record) = proposal
            .stages
            .iter_mut()
            .find(|record| record.stage == target_stage)
        {
            record.failure = Some(OracleChangeStageFailure::Rollback(self.reason.clone()));
            record.completed_at.get_or_insert(now);
        }
        proposal.status = OracleChangeStatus::Failed(OracleChangeFailure {
            stage: target_stage,
            reason: OracleChangeStageFailure::Rollback(self.reason.clone()),
            at: now,
        });
        state_transaction
            .world
            .oracle_changes
            .insert(self.change_id, proposal.clone());
        state_transaction
            .world
            .emit_events(Some(OracleEvent::ChangeStageUpdated(
                OracleChangeStageUpdated {
                    change_id: self.change_id,
                    stage: target_stage,
                    status: proposal.status.clone(),
                    approvals: proposal.current_stage().map_or(0, |stage| {
                        u32::try_from(stage.approvals.len()).unwrap_or(u32::MAX)
                    }),
                    rejections: proposal.current_stage().map_or(0, |stage| {
                        u32::try_from(stage.rejections.len()).unwrap_or(u32::MAX)
                    }),
                    evidence_hashes: proposal
                        .current_stage()
                        .map(|stage| stage.evidence.clone())
                        .unwrap_or_default(),
                },
            )));
        Ok(())
    }
}
