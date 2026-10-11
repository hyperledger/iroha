//! Deterministic settlement router authority.

use iroha_config::parameters::actual::Settlement;
use norito::{Decode, Encode, NoritoSchema};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:settlement-router:v1")]
struct SettlementRouterPolicyV1 {
    twap_window_secs: u64,
    twap_window_nanos: u32,
    epsilon_bps: u16,
    buffer_alert_pct: u8,
    buffer_throttle_pct: u8,
    buffer_xor_only_pct: u8,
    buffer_halt_pct: u8,
    buffer_horizon_hours: u16,
}

/// Exact first-release State-owned settlement policy projection.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:settlement:v1")]
pub(super) struct SettlementPolicyV1 {
    router: SettlementRouterPolicyV1,
}

impl SettlementPolicyV1 {
    /// Capture the router inputs from State.
    pub(super) fn from_actual(config: &Settlement) -> Self {
        let router = &config.router;
        Self {
            router: SettlementRouterPolicyV1 {
                twap_window_secs: router.twap_window.as_secs(),
                twap_window_nanos: router.twap_window.subsec_nanos(),
                epsilon_bps: router.epsilon_bps,
                buffer_alert_pct: router.buffer_alert_pct,
                buffer_throttle_pct: router.buffer_throttle_pct,
                buffer_xor_only_pct: router.buffer_xor_only_pct,
                buffer_halt_pct: router.buffer_halt_pct,
                buffer_horizon_hours: router.buffer_horizon_hours,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn frame(config: &Settlement) -> Vec<u8> {
        norito::encode_canonical(&SettlementPolicyV1::from_actual(config)).unwrap()
    }

    #[test]
    fn settlement_policy_has_canonical_v1_roundtrip() {
        let config = Settlement::default();
        let projected = SettlementPolicyV1::from_actual(&config);
        assert_eq!(
            SettlementPolicyV1::nominal_name(),
            "iroha:state:settlement:v1"
        );
        let bytes = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<SettlementPolicyV1>(&bytes).unwrap(),
            projected
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projected).unwrap(), bytes);
    }

    #[test]
    fn every_router_input_changes_policy() {
        let original = Settlement::default();
        let expected = frame(&original);
        let mut changed = original.clone();
        changed.router.twap_window += Duration::from_secs(1);
        assert_ne!(frame(&changed), expected, "TWAP seconds");
        let mut changed = original.clone();
        changed.router.twap_window += Duration::from_nanos(1);
        assert_ne!(frame(&changed), expected, "TWAP nanoseconds");
        let changes: [(&str, fn(&mut iroha_config::parameters::actual::Router)); 6] = [
            ("epsilon", |router| router.epsilon_bps += 1),
            ("alert", |router| router.buffer_alert_pct += 1),
            ("throttle", |router| router.buffer_throttle_pct += 1),
            ("XOR only", |router| router.buffer_xor_only_pct += 1),
            ("halt", |router| router.buffer_halt_pct += 1),
            ("horizon", |router| router.buffer_horizon_hours += 1),
        ];
        for (name, change) in changes {
            let mut changed = original.clone();
            change(&mut changed.router);
            assert_ne!(frame(&changed), expected, "{name}");
        }
    }
}
