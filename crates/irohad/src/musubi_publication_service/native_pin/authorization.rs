//! Immutable spending and lifetime limits for the native publication pin and its read rounds.
//!
//! These are explicit caller authorizations, not ledger facts. Every retained quoted payload
//! consumes its worst-case fee limits even if signing, Queue admission or finality later fails.

use eyre::{Result, ensure};
use iroha_data_model::{
    asset::AssetDefinitionId,
    transaction::{FeeChargeKind, FeePaymentIntent},
};
use iroha_primitives::numeric::Quantity;
use norito::json::{JsonDeserialize, JsonSerialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const MAX_CHECK_ROUNDS: u16 = 16;
const MAX_FEE_ASSETS: usize = 16;
const MAX_AUTHORIZATION_BYTES: usize = 32 * 1024;

/// Original finite authorization for one publication operation and all its native controls.
/// Construction/decoding grants no current-state, signing-credential or Queue authority.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct NativePinAuthorizationV1 {
    /// Original exclusive UTC deadline for all preparation and exposure.
    pub deadline_unix_ms: u64,
    /// Maximum number of distinct fresh challenges, including abandoned/exposed rounds.
    pub max_check_rounds: u16,
    /// Per-transaction authority-paid native fee ceilings; native ISIs have no gas allowance.
    pub per_transaction: FeePaymentIntent,
    /// Aggregate Nexus ceilings across the pin, two advances and every retained Check payload.
    /// Native public-pin pricing is separate and has no principal maximum in the signed ISI.
    pub max_total_fees: BTreeMap<AssetDefinitionId, Quantity>,
}
impl NativePinAuthorizationV1 {
    pub(in crate::musubi_publication_service) fn validate(&self) -> Result<()> {
        ensure!(
            self.deadline_unix_ms > 0 && self.deadline_unix_ms < u64::MAX,
            "native pin requires an original finite UTC deadline"
        );
        ensure!(
            (1..=MAX_CHECK_ROUNDS).contains(&self.max_check_rounds),
            "native pin Check round bound is invalid"
        );
        ensure!(
            self.per_transaction.charge_limits().len() <= MAX_FEE_ASSETS
                && self.max_total_fees.len() <= MAX_FEE_ASSETS,
            "native pin fee cardinality exceeds its bound"
        );
        self.per_transaction.validate()?;
        ensure!(
            matches!(self.per_transaction, FeePaymentIntent::Authority(_))
                && self.per_transaction.gas_limit().is_none()
                && self
                    .per_transaction
                    .charge_limits()
                    .iter()
                    .all(|limit| limit.kind == FeeChargeKind::Nexus),
            "native pin permits only authority-paid native fees"
        );
        ensure!(
            self.max_total_fees.values().all(|amount| !amount.is_zero()),
            "native pin aggregate fee caps must be positive"
        );
        for limit in self.per_transaction.charge_limits() {
            ensure!(
                self.max_total_fees
                    .get(&limit.asset_definition_id)
                    .is_some_and(|cap| cap >= &limit.max_amount),
                "native pin aggregate authorization does not cover a selected component"
            );
        }
        // Bound the complete original before an owner clones or persists it.
        norito::json::to_json_bounded_boxed(self, MAX_AUTHORIZATION_BYTES)?;
        Ok(())
    }

    pub(in crate::musubi_publication_service) fn ensure_live(&self, now_ms: u64) -> Result<()> {
        self.validate()?;
        ensure!(
            now_ms > 0 && now_ms < self.deadline_unix_ms,
            "original native pin authorization has expired"
        );
        Ok(())
    }

    /// Recheck originals at an effect boundary after preceding codec/native/custody work.
    /// The durable clock may itself block, so the same monotonic deadline is checked on both
    /// sides of that sample. This never derives a replacement deadline from the observed time.
    pub(in crate::musubi_publication_service) fn check_effect_boundary(
        &self,
        clock: &mut dyn iroha_musubi_service::MusubiPublicationServiceClockV1,
        deadline: Instant,
    ) -> Result<u64> {
        self.validate()?;
        ensure!(
            Instant::now() < deadline,
            "original native action deadline expired"
        );
        let now_ms = clock.current_time_ms()?;
        ensure!(
            Instant::now() < deadline,
            "original native action deadline expired"
        );
        ensure!(
            now_ms > 0 && now_ms < self.deadline_unix_ms,
            "original native pin authorization has expired"
        );
        Ok(now_ms)
    }

    /// Select a work deadline inside the original UTC and caller's monotonic deadline.
    /// A fresh round never renews either boundary and Core independently caps it at 60 seconds.
    pub(in crate::musubi_publication_service) fn round_deadline(
        &self,
        now_ms: u64,
        caller: Instant,
    ) -> Result<Instant> {
        self.ensure_live(now_ms)?;
        let now = Instant::now();
        ensure!(caller > now, "native pin caller deadline has expired");
        let remaining =
            Duration::from_millis(self.deadline_unix_ms - now_ms).min(Duration::from_secs(60));
        let end = now
            .checked_add(remaining)
            .ok_or_else(|| eyre::eyre!("native pin deadline overflow"))?;
        Ok(caller.min(end))
    }

    pub(in crate::musubi_publication_service) fn reserve_payload(
        &self,
        previous: &ReservedFeesV1,
        intent: &FeePaymentIntent,
        check: bool,
    ) -> Result<ReservedFeesV1> {
        self.validate()?;
        previous.validate(self)?;
        intent.validate()?;
        ensure!(
            matches!(intent, FeePaymentIntent::Authority(_))
                && intent.gas_limit().is_none()
                && intent.charge_limits().len() <= MAX_FEE_ASSETS,
            "native pin quoted payer or fee shape differs"
        );
        let checks = previous
            .check_rounds
            .checked_add(u16::from(check))
            .ok_or_else(|| eyre::eyre!("native pin Check count overflow"))?;
        let transactions = previous
            .transactions
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("native pin transaction count overflow"))?;
        ensure!(
            checks <= self.max_check_rounds && transactions <= self.max_check_rounds + 3,
            "original native pin transaction authorization is exhausted"
        );
        let mut total = previous.amounts.clone();
        for limit in intent.charge_limits() {
            let cap = self
                .per_transaction
                .charge_limits()
                .iter()
                .find(|cap| {
                    cap.kind == limit.kind && cap.asset_definition_id == limit.asset_definition_id
                })
                .ok_or_else(|| eyre::eyre!("native pin quoted component was not authorized"))?;
            ensure!(
                limit.max_amount <= cap.max_amount,
                "native pin quote exceeds the original component cap"
            );
            let amount = total
                .get(&limit.asset_definition_id)
                .cloned()
                .unwrap_or_else(Quantity::zero)
                .checked_add(&limit.max_amount)?;
            ensure!(
                self.max_total_fees
                    .get(&limit.asset_definition_id)
                    .is_some_and(|cap| &amount <= cap),
                "native pin quote exceeds the original aggregate cap"
            );
            total.insert(limit.asset_definition_id.clone(), amount);
        }
        Ok(ReservedFeesV1 {
            check_rounds: checks,
            transactions,
            amounts: total,
        })
    }
}

/// Recomputed from every exact retained payload; no mutable caller-supplied counter is authority.
#[derive(Debug, Clone, PartialEq, Eq, Default, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(in crate::musubi_publication_service) struct ReservedFeesV1 {
    pub(in crate::musubi_publication_service) check_rounds: u16,
    pub(in crate::musubi_publication_service) transactions: u16,
    pub(in crate::musubi_publication_service) amounts: BTreeMap<AssetDefinitionId, Quantity>,
}
impl ReservedFeesV1 {
    fn validate(&self, original: &NativePinAuthorizationV1) -> Result<()> {
        let check_rounds_within_limit = self.check_rounds <= original.max_check_rounds;
        ensure!(
            check_rounds_within_limit
                && self.check_rounds <= self.transactions
                && self.transactions <= original.max_check_rounds + 3
                && self.amounts.len() <= MAX_FEE_ASSETS,
            "retained native pin fee inventory exceeds its original bounds"
        );
        ensure!(
            self.amounts.iter().all(|(asset, amount)| original
                .max_total_fees
                .get(asset)
                .is_some_and(|cap| amount <= cap)),
            "retained native pin aggregate fee bound differs"
        );
        Ok(())
    }
}

#[cfg(test)]
pub(in crate::musubi_publication_service) fn test_asset(seed: u8) -> AssetDefinitionId {
    let mut uuid = [seed; 16];
    uuid[6] = (uuid[6] & 15) | 0x40;
    uuid[8] = (uuid[8] & 63) | 0x80;
    AssetDefinitionId::from_uuid_bytes(uuid).unwrap()
}

#[cfg(test)]
pub(super) struct FixedClock(pub(super) u64);
#[cfg(test)]
impl iroha_musubi_service::MusubiPublicationServiceClockV1 for FixedClock {
    fn current_time_ms(
        &mut self,
    ) -> std::result::Result<u64, iroha_musubi_service::MusubiPublicationServiceBackendErrorV1>
    {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::transaction::FeeChargeLimit;

    fn original() -> NativePinAuthorizationV1 {
        let asset: AssetDefinitionId =
            crate::musubi_publication_service::native_pin::authorization::test_asset(7);
        NativePinAuthorizationV1 {
            deadline_unix_ms: 90_000,
            max_check_rounds: 2,
            per_transaction: FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    asset.clone(),
                    Quantity::from(3u64),
                )],
                None,
            ),
            max_total_fees: BTreeMap::from([(asset, Quantity::from(6u64))]),
        }
    }

    #[test]
    fn every_retained_payload_reserves_worst_case_fees_without_refund_on_unknown_dispatch() {
        let original = original();
        let first = original
            .reserve_payload(&ReservedFeesV1::default(), &original.per_transaction, true)
            .unwrap();
        let after_crash: ReservedFeesV1 =
            norito::json::from_slice(&norito::json::to_vec(&first).unwrap()).unwrap();
        assert_eq!(first, after_crash);
        let second = original
            .reserve_payload(&after_crash, &original.per_transaction, true)
            .unwrap();
        assert_eq!(second.check_rounds, 2);
        assert!(
            original
                .reserve_payload(&second, &original.per_transaction, false)
                .is_err()
        );
        assert!(
            original
                .reserve_payload(&second, &FeePaymentIntent::authority(vec![], None), true)
                .is_err()
        );
        assert_eq!(first.transactions, 1);
    }

    #[test]
    fn substituted_fee_asset_component_cap_gas_and_original_expiry_refuse() {
        let original = original();
        for intent in [
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    crate::musubi_publication_service::native_pin::authorization::test_asset(8),
                    Quantity::from(1u64),
                )],
                None,
            ),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    crate::musubi_publication_service::native_pin::authorization::test_asset(7),
                    Quantity::from(1u64),
                )],
                None,
            ),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    crate::musubi_publication_service::native_pin::authorization::test_asset(7),
                    Quantity::from(4u64),
                )],
                None,
            ),
            FeePaymentIntent::authority(vec![], std::num::NonZeroU64::new(1)),
        ] {
            assert!(
                original
                    .reserve_payload(&ReservedFeesV1::default(), &intent, true)
                    .is_err()
            );
        }
        assert!(original.ensure_live(89_999).is_ok());
        assert!(original.ensure_live(90_000).is_err());
        assert!(original.ensure_live(0).is_err());
        let caller = Instant::now() + Duration::from_millis(50);
        assert_eq!(original.round_deadline(89_000, caller).unwrap(), caller);
        assert!(original.round_deadline(90_000, caller).is_err());
    }
}
