//! Relay incentive engine wiring treasury payouts to the XOR ledger.
//!
//! This module bridges the SoraNet relay metrics emitted by the runtime with the core reward
//! calculator implemented in `soranet_incentives`. The orchestrator feeds epoch metrics,
//! bond state, and optional metadata into the calculator and converts the resulting reward decision
//! into deterministic `RelayRewardInstructionV1` payloads that the treasury daemon can execute.
use hex::encode as hex_encode;
use iroha_data_model::{
    account::AccountId,
    soranet::{
        RelayId,
        incentives::RelayRewardInstructionV1,
        prelude::{Digest32, RelayBondLedgerEntryV1, RelayBondPolicyV1, RelayEpochMetricsV1},
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use soranet_incentives::{
    RelayIncentiveError, RelayRewardCalculator, RewardConfig as CoreRewardConfig, RewardDecision,
    RewardSkipReason, RewardWeights,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tracing::warn;
/// Declarative configuration for the relay reward engine.
#[derive(Debug, Clone)]
pub struct RewardConfig {
    /// Bonding policy enforced for relay payouts.
    pub policy: RelayBondPolicyV1,
    /// Base reward (in XOR) allocated per relay per epoch before applying weights.
    pub base_reward: Quantity,
    /// Weight applied to the uptime ratio (`0‒1000`, interpreted as per-mille).
    pub uptime_weight_per_mille: u16,
    /// Weight applied to the bandwidth ratio (`0‒1000`, interpreted as per-mille).
    pub bandwidth_weight_per_mille: u16,
    /// Penalty (basis points) applied when the relay enters the `Warning` compliance state
    /// (`0‒10_000`).
    pub compliance_penalty_basis_points: u16,
    /// Target bytes per epoch used to normalise bandwidth ratios.
    pub bandwidth_target_bytes: u128,
    /// Optional governance approval (Sora Parliament budget hash) attached to payouts.
    pub budget_approval_id: Option<Digest32>,
    /// Optional path where relay epoch metrics are persisted as a Norito log.
    pub metrics_log_path: Option<PathBuf>,
}
impl RewardConfig {
    /// Validate the reward configuration, ensuring weights fall within expected bounds.
    pub fn validate(&self) -> Result<(), RewardConfigError> {
        let total = self
            .uptime_weight_per_mille
            .saturating_add(self.bandwidth_weight_per_mille);
        if total > 1_000 {
            return Err(RewardConfigError::WeightOverflow {
                uptime: self.uptime_weight_per_mille,
                bandwidth: self.bandwidth_weight_per_mille,
            });
        }
        if self.bandwidth_target_bytes == 0 {
            return Err(RewardConfigError::BandwidthTargetZero);
        }
        if self.base_reward.scale() > 9 {
            return Err(RewardConfigError::BaseRewardScale {
                scale: self.base_reward.scale(),
            });
        }
        if self.compliance_penalty_basis_points > 10_000 {
            return Err(RewardConfigError::CompliancePenaltyOverflow {
                penalty: self.compliance_penalty_basis_points,
            });
        }
        if self.budget_approval_id.is_none() {
            return Err(RewardConfigError::MissingBudgetApprovalId);
        }
        Ok(())
    }
}
/// Errors raised while constructing the reward engine.
#[derive(Debug, Error)]
pub enum RewardConfigError {
    /// Combined per-mille weights exceed 100%.
    #[error("reward weights exceed 100% (uptime={uptime}, bandwidth={bandwidth})")]
    WeightOverflow {
        /// Uptime weight (per mille).
        uptime: u16,
        /// Bandwidth weight (per mille).
        bandwidth: u16,
    },
    /// Bandwidth target must be greater than zero.
    #[error("bandwidth target must be non-zero")]
    BandwidthTargetZero,
    /// Base rewards must fit the nano-XOR precision domain.
    #[error("base reward scale {scale} exceeds nano-XOR scale 9")]
    BaseRewardScale {
        /// Configured decimal scale.
        scale: u32,
    },
    /// Compliance penalties cannot exceed 100%.
    #[error("compliance penalty must not exceed 100% (got {penalty} bps)")]
    CompliancePenaltyOverflow {
        /// Requested penalty in basis points.
        penalty: u16,
    },
    /// Budget approvals are mandatory for relay payouts.
    #[error("budget_approval_id is required for relay payouts")]
    MissingBudgetApprovalId,
    /// Unexpected calculator invariant violation.
    #[error("invalid reward configuration: {0}")]
    Invariant(#[from] RelayIncentiveError),
    /// Failed to prepare the relay metrics log.
    #[error("failed to prepare relay metrics log at {path:?}: {source}")]
    MetricsLog {
        /// Location of the metrics log file.
        path: PathBuf,
        /// Underlying error.
        source: MetricsLogOpenError,
    },
}
/// Computes relay reward instructions given epoch metrics and bonding state.
#[derive(Debug, Clone)]
pub struct RelayRewardEngine {
    calculator: RelayRewardCalculator,
    budget_approval_id: Option<Digest32>,
    config: RewardConfig,
    metrics_log: Option<Arc<MetricsLog>>,
}
impl RelayRewardEngine {
    /// Construct a new reward engine using the supplied configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RewardConfigError`] if the configuration fails validation (e.g., weights exceed
    /// `1000` per mille or the bandwidth target is zero).
    pub fn new(config: RewardConfig) -> Result<Self, RewardConfigError> {
        config.validate()?;
        Self::build(config)
    }
    fn build(config: RewardConfig) -> Result<Self, RewardConfigError> {
        let availability_raw = config.uptime_weight_per_mille.saturating_mul(10);
        let bandwidth_raw = config.bandwidth_weight_per_mille.saturating_mul(10);
        let compliance_bps = config.compliance_penalty_basis_points.min(10_000);
        let remaining_total = 10_000u16.saturating_sub(compliance_bps);
        let total_raw = u32::from(availability_raw) + u32::from(bandwidth_raw);
        let (availability_bps, bandwidth_bps) = if total_raw == 0 {
            (0, remaining_total)
        } else {
            let avail = ((u32::from(availability_raw) * u32::from(remaining_total)) / total_raw)
                .min(u32::from(remaining_total)) as u16;
            let bandwidth = remaining_total.saturating_sub(avail);
            (avail, bandwidth)
        };
        let weights = RewardWeights {
            availability_bps,
            bandwidth_bps,
            compliance_bps,
        };
        let base_reward = config.base_reward.clone();
        let core_config = CoreRewardConfig {
            policy: config.policy.clone(),
            weights,
            bandwidth_target_bytes: config.bandwidth_target_bytes,
            epoch_base_payout: base_reward.clone(),
            warning_penalty_per_mille: (config.compliance_penalty_basis_points / 10).min(1_000),
            exit_bonus_per_mille: 0,
        };
        let calculator = RelayRewardCalculator::new(core_config).map_err(|err| match err {
            RelayIncentiveError::InvalidWeights { .. } => RewardConfigError::WeightOverflow {
                uptime: config.uptime_weight_per_mille,
                bandwidth: config.bandwidth_weight_per_mille,
            },
            RelayIncentiveError::ZeroBandwidthTarget => RewardConfigError::BandwidthTargetZero,
            RelayIncentiveError::InvalidBasePayoutScale { scale } => {
                RewardConfigError::BaseRewardScale { scale }
            }
            other => RewardConfigError::Invariant(other),
        })?;
        let metrics_log = if let Some(path) = config.metrics_log_path.clone() {
            Some(Arc::new(MetricsLog::open(path.clone()).map_err(
                |source| RewardConfigError::MetricsLog { path, source },
            )?))
        } else {
            None
        };
        if let Some(handle) = iroha_telemetry::metrics::global()
            && let Some(base_nanos) = quantity_to_nanos(&base_reward)
        {
            handle.set_soranet_reward_base_payout(base_nanos);
        }
        Ok(Self {
            calculator,
            budget_approval_id: config.budget_approval_id,
            config,
            metrics_log,
        })
    }
    /// Returns a reference to the orchestrator-level configuration.
    #[must_use]
    pub fn config(&self) -> &RewardConfig {
        &self.config
    }
    /// Produce a relay reward instruction for the provided metrics and bond ledger entry.
    ///
    /// Bond checks are delegated to the core calculator; relays that fail to maintain the minimum
    /// exit bond or enter a suspended compliance state receive zero payout with diagnostic metadata.
    #[must_use]
    pub fn compute_reward(
        &self,
        metrics: &RelayEpochMetricsV1,
        bond_entry: &RelayBondLedgerEntryV1,
        beneficiary: AccountId,
        metadata: Metadata,
    ) -> RelayRewardInstructionV1 {
        let issued_at_unix = u64::from(metrics.epoch);
        let beneficiary_clone = beneficiary.clone();
        match self.calculator.evaluate(
            metrics,
            bond_entry,
            &beneficiary_clone,
            issued_at_unix,
            self.budget_approval_id,
            Some(&metadata),
        ) {
            Ok(decision) => {
                self.log_metrics(
                    metrics,
                    &metadata,
                    MetricsLogOutcome::from_decision(&decision),
                );
                match decision {
                    RewardDecision::Rewarded { instruction, .. } => {
                        record_reward_telemetry(
                            metrics.relay_id,
                            &instruction.payout_amount,
                            "rewarded",
                            None,
                        );
                        instruction
                    }
                    RewardDecision::Skipped {
                        instruction,
                        reason,
                        ..
                    } => {
                        let skip_label = skip_reason_label(reason);
                        record_reward_telemetry(
                            metrics.relay_id,
                            &instruction.payout_amount,
                            "skipped",
                            Some(skip_label),
                        );
                        warn!(
                            relay_id = %hex_encode(metrics.relay_id),
                            ?reason,
                            "relay reward skipped"
                        );
                        instruction
                    }
                }
            }
            Err(err) => {
                self.log_metrics(metrics, &metadata, MetricsLogOutcome::Error { error: &err });
                warn!(
                    relay_id = %hex_encode(metrics.relay_id),
                    ?err,
                    "failed to compute relay reward"
                );
                let mut metadata = metadata;
                if let Ok(name) = Name::from_str("reward_error") {
                    let _ = metadata.insert(name, Json::new(format!("{err:?}")));
                }
                let instruction = self.zero_instruction(metrics, beneficiary, metadata);
                record_reward_telemetry(
                    metrics.relay_id,
                    &instruction.payout_amount,
                    "error",
                    None,
                );
                instruction
            }
        }
    }
    fn log_metrics(
        &self,
        metrics: &RelayEpochMetricsV1,
        extra_metadata: &Metadata,
        outcome: MetricsLogOutcome<'_>,
    ) {
        let Some(log) = &self.metrics_log else {
            return;
        };
        let mut record = metrics.clone();
        let mut metadata = record.metadata.clone();
        metadata_merge(&mut metadata, extra_metadata);
        match outcome {
            MetricsLogOutcome::Rewarded { score } => {
                record.reward_score = u64::from(score);
                metadata_insert(&mut metadata, "reward_decision", Json::new("rewarded"));
            }
            MetricsLogOutcome::Skipped { score, reason } => {
                record.reward_score = u64::from(score);
                metadata_insert(&mut metadata, "reward_decision", Json::new("skipped"));
                metadata_insert(
                    &mut metadata,
                    "reward_skip_reason",
                    Json::new(skip_reason_label(reason)),
                );
            }
            MetricsLogOutcome::Error { error } => {
                metadata_insert(&mut metadata, "reward_decision", Json::new("error"));
                metadata_insert(
                    &mut metadata,
                    "reward_error",
                    Json::new(format!("{error:?}")),
                );
            }
        }
        record.metadata = metadata;
        if let Err(err) = log.append(&record) {
            warn!(
                relay_id = %hex_encode(record.relay_id),
                ?err,
                "failed to append relay metrics log entry"
            );
        }
    }
    fn zero_instruction(
        &self,
        metrics: &RelayEpochMetricsV1,
        beneficiary: AccountId,
        metadata: Metadata,
    ) -> RelayRewardInstructionV1 {
        RelayRewardInstructionV1 {
            relay_id: metrics.relay_id,
            epoch: metrics.epoch,
            beneficiary,
            payout_asset_id: self.calculator.config().policy.bond_asset_id.clone(),
            payout_amount: Quantity::zero(),
            reward_score: 0,
            budget_approval_id: self.budget_approval_id,
            metadata,
        }
    }
}
fn metadata_insert(metadata: &mut Metadata, key: &str, value: impl Into<Json>) {
    if let Ok(name) = Name::from_str(key) {
        metadata.insert(name, value);
    }
}
fn metadata_merge(target: &mut Metadata, extra: &Metadata) {
    for (key, value) in extra.iter() {
        let _ = target.insert(key.clone(), value.clone());
    }
}
fn skip_reason_label(reason: RewardSkipReason) -> &'static str {
    match reason {
        RewardSkipReason::InsufficientBond => "insufficient_bond",
        RewardSkipReason::ComplianceSuspended => "compliance_suspended",
        RewardSkipReason::BondAssetMismatch => "bond_asset_mismatch",
        RewardSkipReason::ZeroScore => "zero_score",
    }
}
fn record_reward_telemetry(
    relay_id: RelayId,
    amount: &Quantity,
    result: &str,
    skip_reason: Option<&'static str>,
) {
    if let Some(handle) = iroha_telemetry::metrics::global() {
        let relay_label = hex_encode(relay_id);
        let Some(nanos) = quantity_to_nanos(amount) else {
            warn!(
                relay_id = %relay_label,
                amount = %amount,
                "relay reward amount cannot be represented as nanos for telemetry"
            );
            return;
        };
        handle.record_soranet_reward(&relay_label, nanos, result);
        if let Some(reason) = skip_reason {
            handle.record_soranet_reward_skip(&relay_label, reason);
        }
    }
}
pub(crate) fn quantity_to_nanos(amount: &Quantity) -> Option<u128> {
    let scale = amount.scale();
    let mantissa = amount.as_numeric().try_mantissa_u128()?;
    if scale >= 9 {
        let divisor = 10u128.checked_pow(scale.saturating_sub(9))?;
        mantissa.checked_div(divisor)
    } else {
        let multiplier = 10u128.checked_pow(9 - scale)?;
        mantissa.checked_mul(multiplier)
    }
}
#[derive(Debug)]
enum MetricsLogOutcome<'a> {
    Rewarded {
        score: u16,
    },
    Skipped {
        score: u16,
        reason: RewardSkipReason,
    },
    Error {
        error: &'a RelayIncentiveError,
    },
}
impl<'a> MetricsLogOutcome<'a> {
    fn from_decision(decision: &'a RewardDecision) -> Self {
        match decision {
            RewardDecision::Rewarded {
                score_per_mille, ..
            } => Self::Rewarded {
                score: *score_per_mille,
            },
            RewardDecision::Skipped {
                score_per_mille,
                reason,
                ..
            } => Self::Skipped {
                score: *score_per_mille,
                reason: *reason,
            },
        }
    }
}
include!("incentives/metrics_log.rs");
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        asset::AssetDefinitionId, soranet::incentives::RelayComplianceStatusV1,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use std::convert::TryFrom;
    use tempfile::tempdir;
    fn quantity(value: u32) -> Quantity {
        Quantity::from(value)
    }
    fn asset_id() -> AssetDefinitionId {
        let domain = DomainId::try_new("sora", "universal").expect("domain id");
        let name = Name::from_str("xor").expect("asset name");
        AssetDefinitionId::derive_from_components(domain, name)
    }
    fn policy() -> RelayBondPolicyV1 {
        RelayBondPolicyV1 {
            minimum_exit_bond: quantity(1_000),
            bond_asset_id: asset_id(),
            uptime_floor_per_mille: 900,
            slash_penalty_basis_points: 250,
            activation_grace_epochs: 0,
        }
    }
    fn budget_id() -> [u8; 32] {
        [0xAB; 32]
    }
    fn bond_entry(amount: u32, exit_capable: bool) -> RelayBondLedgerEntryV1 {
        RelayBondLedgerEntryV1 {
            relay_id: [0_u8; 32],
            bonded_amount: quantity(amount),
            bond_asset_id: asset_id(),
            bonded_since_unix: 1,
            exit_capable,
        }
    }
    fn sample_account() -> AccountId {
        let (public_key, _) = KeyPair::try_from_seed(vec![0x11; 32], Algorithm::Ed25519)
            .expect("derive relay reward account fixture key")
            .into_parts();
        AccountId::new(public_key)
    }
    fn metrics(uptime_ratio_per_mille: u16, bandwidth_bytes: u128) -> RelayEpochMetricsV1 {
        RelayEpochMetricsV1 {
            relay_id: [0_u8; 32],
            epoch: 1,
            uptime_seconds: 100,
            scheduled_uptime_seconds: if uptime_ratio_per_mille == 0 {
                200
            } else {
                100
            },
            verified_bandwidth_bytes: bandwidth_bytes,
            compliance: RelayComplianceStatusV1::Clean,
            reward_score: 50,
            confidence_floor_per_mille: 900,
            measurement_ids: Vec::new(),
            metadata: Metadata::default(),
        }
    }
    fn engine(uptime_weight: u16, bandwidth_weight: u16, penalty_bps: u16) -> RelayRewardEngine {
        let config = RewardConfig {
            policy: policy(),
            base_reward: quantity(100),
            uptime_weight_per_mille: uptime_weight,
            bandwidth_weight_per_mille: bandwidth_weight,
            compliance_penalty_basis_points: penalty_bps,
            bandwidth_target_bytes: 1_000,
            budget_approval_id: Some(budget_id()),
            metrics_log_path: None,
        };
        RelayRewardEngine::new(config).expect("config valid")
    }
    #[test]
    fn weight_validation_rejects_overflow() {
        let config = RewardConfig {
            policy: policy(),
            base_reward: quantity(100),
            uptime_weight_per_mille: 800,
            bandwidth_weight_per_mille: 300,
            compliance_penalty_basis_points: 0,
            bandwidth_target_bytes: 1_000,
            budget_approval_id: Some(budget_id()),
            metrics_log_path: None,
        };
        assert!(matches!(
            RelayRewardEngine::new(config),
            Err(RewardConfigError::WeightOverflow { .. })
        ));
    }
    #[test]
    fn compliance_penalty_rejects_overflow() {
        let config = RewardConfig {
            policy: policy(),
            base_reward: quantity(100),
            uptime_weight_per_mille: 500,
            bandwidth_weight_per_mille: 500,
            compliance_penalty_basis_points: 12_500,
            bandwidth_target_bytes: 1_000,
            budget_approval_id: Some(budget_id()),
            metrics_log_path: None,
        };
        assert!(matches!(
            RelayRewardEngine::new(config),
            Err(RewardConfigError::CompliancePenaltyOverflow { penalty: 12_500 })
        ));
    }
    #[test]
    fn missing_budget_approval_is_rejected() {
        let config = RewardConfig {
            policy: policy(),
            base_reward: quantity(100),
            uptime_weight_per_mille: 500,
            bandwidth_weight_per_mille: 500,
            compliance_penalty_basis_points: 0,
            bandwidth_target_bytes: 1_000,
            budget_approval_id: None,
            metrics_log_path: None,
        };
        assert!(matches!(
            RelayRewardEngine::new(config),
            Err(RewardConfigError::MissingBudgetApprovalId)
        ));
    }
    #[test]
    fn sub_nano_base_reward_is_rejected() {
        let mut config = engine(500, 500, 0).config().clone();
        config.base_reward = "0.0000000001"
            .parse::<Quantity>()
            .expect("scale-10 quantity");
        assert!(matches!(
            RelayRewardEngine::new(config),
            Err(RewardConfigError::BaseRewardScale { scale: 10 })
        ));
    }
    #[test]
    fn reward_engine_sets_base_payout_metric() {
        let metrics = iroha_telemetry::metrics::global_or_default();
        metrics.soranet_reward_base_payout_nanos.set(0);
        let expected_nanos = quantity_to_nanos(&quantity(100)).expect("base reward convertible");
        let _ = engine(500, 500, 0);
        let observed = metrics.soranet_reward_base_payout_nanos.get();
        let expected = u64::try_from(expected_nanos).expect("fits in gauge");
        assert_eq!(observed, expected);
        metrics.soranet_reward_base_payout_nanos.set(0);
    }
    #[test]
    fn quantity_to_nanos_accepts_zero_without_panic() {
        assert_eq!(quantity_to_nanos(&Quantity::zero()), Some(0));
    }
    #[test]
    fn clean_compliant_relay_receives_full_payout() {
        let engine = engine(500, 500, 0);
        let metrics = metrics(1_000, 1_000);
        let instruction = engine.compute_reward(
            &metrics,
            &bond_entry(5_000, true),
            sample_account(),
            Metadata::default(),
        );
        assert_eq!(instruction.payout_amount, quantity(100));
    }
    #[test]
    fn warning_penalty_reduces_payout() {
        let mut metrics = metrics(1_000, 1_000);
        metrics.compliance = RelayComplianceStatusV1::Warning;
        let engine = engine(500, 500, 200); // 2% penalty
        let instruction = engine.compute_reward(
            &metrics,
            &bond_entry(5_000, true),
            sample_account(),
            Metadata::default(),
        );
        assert!(instruction.payout_amount < quantity(100));
        assert!(instruction.payout_amount > Quantity::zero());
    }
    #[test]
    fn suspended_relay_receives_zero() {
        let mut metrics = metrics(1_000, 1_000);
        metrics.compliance = RelayComplianceStatusV1::Suspended;
        let engine = engine(500, 500, 0);
        let instruction = engine.compute_reward(
            &metrics,
            &bond_entry(5_000, true),
            sample_account(),
            Metadata::default(),
        );
        assert_eq!(instruction.payout_amount, Quantity::zero());
    }
    #[test]
    fn insufficient_bond_zeroes_payout() {
        let engine = engine(500, 500, 0);
        let instruction = engine.compute_reward(
            &metrics(1_000, 1_000),
            &bond_entry(100, true),
            sample_account(),
            Metadata::default(),
        );
        assert_eq!(instruction.payout_amount, Quantity::zero());
    }
    #[test]
    fn metrics_log_bounds_each_canonical_record_and_rejects_partial_tail() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("metrics.log");
        let log = MetricsLog::open(path.clone()).expect("open log");
        let entry = metrics(1_000, 1_000);
        let canonical = norito::encode_canonical(&entry).expect("canonical entry");
        let mut count = 0;
        for flags in (0..=norito::core::supported_header_flags())
            .filter(|flags| norito::core::validate_header_flags(*flags).is_ok())
        {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            log.append(&entry).expect("append under caller layout");
            count += 1;
        }
        drop(log);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, canonical.repeat(count));
        assert_eq!(
            read_metrics_log(&path, log_test_limits()).unwrap(),
            vec![entry; count]
        );
        for length in [
            1,
            norito::core::Header::SIZE - 1,
            canonical.len() - 1,
            bytes.len() - 1,
        ] {
            std::fs::write(&path, &bytes[..length]).unwrap();
            assert!(
                read_metrics_log(&path, log_test_limits()).is_err(),
                "partial log at {length} accepted"
            );
        }
        let mut header = canonical[..norito::core::Header::SIZE].to_vec();
        // Header layout: magic/version/owner/compression precede the u64 length.
        header[23..31].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            norito::core::Header::read(header.as_slice())
                .unwrap()
                .length,
            u64::MAX
        );
        std::fs::write(&path, header).unwrap();
        assert!(
            read_metrics_log(&path, log_test_limits()).is_err(),
            "unbacked declared size accepted"
        );
    }
    #[test]
    fn metrics_log_records_entries() {
        let dir = tempdir().expect("temp dir");
        let log_path = dir.path().join("relay_metrics.log");
        let config = RewardConfig {
            policy: policy(),
            base_reward: quantity(100),
            uptime_weight_per_mille: 500,
            bandwidth_weight_per_mille: 500,
            compliance_penalty_basis_points: 0,
            bandwidth_target_bytes: 1_000,
            budget_approval_id: Some(budget_id()),
            metrics_log_path: Some(log_path.clone()),
        };
        let engine = RelayRewardEngine::new(config).expect("config valid");
        let mut extra_metadata = Metadata::default();
        let epoch_key = Name::from_str("epoch_tag").expect("name");
        extra_metadata.insert(epoch_key.clone(), Json::new("epoch-1"));
        let _ = engine.compute_reward(
            &metrics(1_000, 1_000),
            &bond_entry(5_000, true),
            sample_account(),
            extra_metadata.clone(),
        );
        let _ = engine.compute_reward(
            &metrics(1_000, 1_000),
            &bond_entry(100, true),
            sample_account(),
            Metadata::default(),
        );
        let records = read_metrics_log(&log_path, log_test_limits()).expect("read metrics log");
        assert_eq!(records.len(), 2);
        let recorded_bytes = std::fs::read(&log_path).expect("read actual producer bytes");
        assert_eq!(
            recorded_bytes[6..22],
            norito::schema::identity::frame_hash::<RelayEpochMetricsV1>()
        );
        let mut wrong_owner = recorded_bytes;
        wrong_owner[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<
            iroha_data_model::soranet::incentives::RelayBandwidthProofPayloadV1,
        >());
        let corrupt_path = dir.path().join("wrong-owner.log");
        std::fs::write(&corrupt_path, wrong_owner).expect("write owner substitution");
        assert!(matches!(
            read_metrics_log(&corrupt_path, log_test_limits()),
            Err(MetricsLogError::Decode {
                source: norito::Error::SchemaMismatch,
                ..
            })
        ));
        let decision_key = Name::from_str("reward_decision").expect("name");
        assert_eq!(
            records[0].metadata.get(&decision_key),
            Some(&Json::new("rewarded"))
        );
        assert_eq!(
            records[1].metadata.get(&decision_key),
            Some(&Json::new("skipped"))
        );
        let reason_key = Name::from_str("reward_skip_reason").expect("name");
        assert_eq!(
            records[1].metadata.get(&reason_key),
            Some(&Json::new(skip_reason_label(
                RewardSkipReason::InsufficientBond
            )))
        );
        assert_eq!(
            records[0].metadata.get(&epoch_key),
            Some(&Json::new("epoch-1"))
        );
    }
    include!("incentives/metrics_log_tests.rs");
}
