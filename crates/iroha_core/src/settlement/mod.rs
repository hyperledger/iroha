//! Deterministic settlement pricing helpers.
//!
//! The implementation here wraps the primitives provided by the
//! `settlement_router` crate so the rest of `iroha_core` interacts with a
//! single façade.  The façade keeps the logic deterministic and hides
//! decimal arithmetic from the rest of the code base. Pricing results are not
//! execution receipts and never authorize an XOR balance or reserve change.
use iroha_config::parameters::actual as config;
use iroha_primitives::numeric::{Numeric, Quantity};
pub use settlement_router::VolatilityBucket;
use settlement_router::{
    BufferPolicyError, SettlementReceiptError, ShadowPriceCalculator, ShadowPriceError,
    XorQuantity,
    config::SettlementConfig,
    haircut::{HaircutTier, LiquidityProfile},
    policy::{BufferPolicy, BufferStatus},
    receipt::SettlementReceipt,
};
use time::Duration as TimeDuration;
/// Error returned when quoting settlement amounts fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QuoteError {
    /// Shadow-price calculation failed.
    #[error(transparent)]
    Price(#[from] ShadowPriceError),
    /// Receipt construction failed.
    #[error(transparent)]
    Receipt(#[from] SettlementReceiptError),
}
/// Result of a settlement quote.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SettlementQuote {
    /// Shadow price output used for buffer debits.
    pub receipt: SettlementReceipt,
    /// Exact XOR due immediately after inclusion.
    pub xor_due: XorQuantity,
    /// Exact XOR expected after haircuts.
    pub xor_after_haircut: XorQuantity,
    /// Effective safety margin (base + volatility) in basis points.
    pub effective_epsilon_bps: u16,
}
/// Deterministic XOR settlement engine.
#[derive(Debug, Clone)]
pub struct SettlementEngine {
    calculator: ShadowPriceCalculator,
    buffer_policy: BufferPolicy,
}
fn duration_from_std(duration: std::time::Duration) -> TimeDuration {
    let secs = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
    let mut converted = TimeDuration::seconds(secs);
    if duration.subsec_nanos() != 0 {
        converted += TimeDuration::nanoseconds(i64::from(duration.subsec_nanos()));
    }
    converted
}
impl SettlementEngine {
    /// Create an engine using roadmap defaults (60s TWAP, 25 bps margin,
    /// 72 h buffer horizon).  Used primarily in tests.
    #[must_use]
    pub fn new_roadmap_default() -> Self {
        Self::from_router_config(&config::Router::default())
    }
    /// Create an engine from configuration provided via `iroha_config`.
    #[must_use]
    pub fn from_router_config(router: &config::Router) -> Self {
        let settlement_config = SettlementConfig {
            twap_window: duration_from_std(router.twap_window).into(),
            epsilon: settlement_router::config::EpsilonBps::new(router.epsilon_bps),
            buffer_horizon_hours: router.buffer_horizon_hours,
        };
        let buffer_policy = BufferPolicy {
            alert: router.buffer_alert_pct,
            throttle: router.buffer_throttle_pct,
            xor_only: router.buffer_xor_only_pct,
            halt: router.buffer_halt_pct,
        };
        Self {
            calculator: ShadowPriceCalculator::new(settlement_config),
            buffer_policy,
        }
    }
    /// Access the current buffer policy thresholds.
    #[must_use]
    pub const fn buffer_policy(&self) -> &BufferPolicy {
        &self.buffer_policy
    }
    /// Evaluate the remaining buffer against the configured guard rails.
    ///
    /// # Errors
    ///
    /// Returns an error if policy thresholds are invalid or computing a threshold
    /// exceeds the exact XOR quantity domain.
    pub fn evaluate_buffer(
        &self,
        remaining: &XorQuantity,
        capacity: &XorQuantity,
    ) -> Result<BufferStatus, BufferPolicyError> {
        self.buffer_policy.evaluate(remaining, capacity)
    }
    /// Access the current settlement configuration used by this engine.
    #[must_use]
    pub const fn config(&self) -> &SettlementConfig {
        self.calculator.config()
    }
    /// Check that this retained engine is exactly the deterministic derivative
    /// of the State-owned router configuration.
    ///
    /// The complete State commitment owner can use this check before omitting
    /// the engine's duplicate derived fields from its canonical row set.
    #[must_use]
    pub fn matches_router_config(&self, router: &config::Router) -> bool {
        let expected = Self::from_router_config(router);
        self.config() == expected.config() && self.buffer_policy() == expected.buffer_policy()
    }
    /// Quote a settlement from an exact local gas-token amount, a positive
    /// local-token-per-XOR TWAP, and the conversion path's liquidity profile.
    ///
    /// # Errors
    ///
    /// Returns a stable error when price arithmetic or timestamp validation fails. No implicit
    /// fixed-unit conversion, rounding, or saturation is performed at this consensus boundary.
    pub fn quote(
        &self,
        source_id: [u8; 32],
        local_amount: Quantity,
        twap_local_per_xor: Numeric,
        liquidity: LiquidityProfile,
        volatility: VolatilityBucket,
        timestamp_ms: u64,
    ) -> Result<SettlementQuote, QuoteError> {
        let shadow = self.calculator.compute(
            &local_amount,
            &twap_local_per_xor,
            HaircutTier::new(liquidity),
            volatility,
        )?;
        let effective_epsilon_bps = self.calculator.effective_epsilon_bps(volatility);
        let receipt = SettlementReceipt::new_with_timestamp_ms(
            source_id,
            local_amount,
            &shadow,
            timestamp_ms,
        )?;
        Ok(SettlementQuote {
            xor_due: shadow.xor_due,
            xor_after_haircut: shadow.xor_with_haircut,
            effective_epsilon_bps,
            receipt,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn xor(value: &str) -> XorQuantity {
        value.parse().expect("canonical XOR quantity")
    }
    #[test]
    fn quote_roadmap_defaults() {
        let engine = SettlementEngine::new_roadmap_default();
        let quote = engine
            .quote(
                [0x11; 32],
                Quantity::from(2_000_000_u64),
                Numeric::from(50_u32),
                LiquidityProfile::Tier2,
                VolatilityBucket::Stable,
                1,
            )
            .expect("quote must succeed");
        assert!(quote.xor_due > XorQuantity::zero());
        assert!(quote.xor_after_haircut <= quote.xor_due);
        assert_eq!(quote.receipt.local_amount, Quantity::from(2_000_000_u64));
        assert_eq!(quote.effective_epsilon_bps, 25);
    }
    #[test]
    fn non_positive_twap_errors() {
        let engine = SettlementEngine::new_roadmap_default();
        for twap in [Numeric::zero(), "-1".parse().expect("negative numeric")] {
            assert_eq!(
                engine.quote(
                    [0xFF; 32],
                    Quantity::from(1_000_u32),
                    twap,
                    LiquidityProfile::Tier1,
                    VolatilityBucket::Stable,
                    1,
                ),
                Err(QuoteError::Price(ShadowPriceError::NonPositiveTwap))
            );
        }
    }
    #[test]
    fn evaluate_buffer_matches_policy_thresholds() {
        let engine = SettlementEngine::new_roadmap_default();
        let capacity = xor("1000000");
        assert_eq!(
            engine.evaluate_buffer(&xor("2000000"), &capacity),
            Ok(BufferStatus::Normal)
        );
        assert_eq!(
            engine.evaluate_buffer(&xor("700000"), &capacity),
            Ok(BufferStatus::Alert)
        );
        assert_eq!(
            engine.evaluate_buffer(&xor("200000"), &capacity),
            Ok(BufferStatus::Throttle)
        );
        assert_eq!(
            engine.evaluate_buffer(&xor("50000"), &capacity),
            Ok(BufferStatus::XorOnly)
        );
        assert_eq!(
            engine.evaluate_buffer(&xor("10000"), &capacity),
            Ok(BufferStatus::Halt)
        );
    }
    #[test]
    fn engine_from_router_config_applies_knobs() {
        let router = config::Router {
            epsilon_bps: 75,
            buffer_alert_pct: 80,
            buffer_throttle_pct: 60,
            buffer_xor_only_pct: 40,
            buffer_halt_pct: 5,
            twap_window: std::time::Duration::from_secs(90),
            buffer_horizon_hours: 96,
        };
        let engine = SettlementEngine::from_router_config(&router);
        assert_eq!(engine.config().epsilon.as_u16(), 75);
        assert_eq!(
            engine.config().twap_window.whole_seconds(),
            i64::try_from(router.twap_window.as_secs()).expect("twap_window seconds fit in i64")
        );
        assert_eq!(engine.config().buffer_horizon_hours, 96);
        assert_eq!(engine.buffer_policy().alert, 80);
        assert_eq!(engine.buffer_policy().throttle, 60);
        assert_eq!(engine.buffer_policy().xor_only, 40);
        assert_eq!(engine.buffer_policy().halt, 5);
    }
    #[test]
    fn engine_derivation_check_covers_every_router_input() {
        let baseline = config::Router::default();
        let engine = SettlementEngine::from_router_config(&baseline);
        assert!(engine.matches_router_config(&baseline));
        let changes: [(&str, fn(&mut config::Router)); 7] = [
            ("twap_window", |config| {
                config.twap_window += std::time::Duration::from_secs(1)
            }),
            ("epsilon_bps", |config| config.epsilon_bps += 1),
            ("buffer_alert_pct", |config| config.buffer_alert_pct += 1),
            ("buffer_throttle_pct", |config| {
                config.buffer_throttle_pct += 1
            }),
            ("buffer_xor_only_pct", |config| {
                config.buffer_xor_only_pct += 1
            }),
            ("buffer_halt_pct", |config| config.buffer_halt_pct += 1),
            ("buffer_horizon_hours", |config| {
                config.buffer_horizon_hours += 1
            }),
        ];
        for (name, change) in changes {
            let mut altered = baseline;
            change(&mut altered);
            assert!(
                !engine.matches_router_config(&altered),
                "{name} must change the derived engine"
            );
        }
    }
}
