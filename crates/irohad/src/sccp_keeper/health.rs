//! Bounded keeper observations exported through the node's existing telemetry registry.

use super::SccpNetworkV1;

/// Independent remote keeper duties; labels never contain endpoints or route revisions.
#[derive(Clone, Copy)]
pub(super) enum Duty {
    Advance,
    Watch,
}

/// Local health observations. They never authorize protocol execution or recovery.
#[derive(Clone, Copy)]
pub(super) enum Health {
    Unconfigured(bool),
    Recovery(SccpNetworkV1, bool),
    Poll(SccpNetworkV1, Duty, bool),
}

impl Health {
    pub(super) fn report(self) {
        #[cfg(feature = "telemetry")]
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            self.record(metrics);
        }
        #[cfg(not(feature = "telemetry"))]
        match self {
            Self::Unconfigured(value) => {
                let _ = value;
            }
            Self::Recovery(network, value) => {
                let _ = (network, value);
            }
            Self::Poll(network, duty, success) => {
                let _ = (network, duty, success);
            }
        }
    }

    #[cfg(feature = "telemetry")]
    fn record(self, metrics: &iroha_telemetry::metrics::Metrics) {
        match self {
            Self::Unconfigured(value) => metrics.sccp_keeper_unconfigured.set(i64::from(value)),
            Self::Recovery(network, value) => metrics
                .sccp_keeper_needs_recovery
                .with_label_values(&[network.profile_key()])
                .set(i64::from(value)),
            Self::Poll(network, duty, success) => metrics
                .sccp_keeper_poll_success
                .with_label_values(&[
                    network.profile_key(),
                    match duty {
                        Duty::Advance => "advance",
                        Duty::Watch => "watch",
                    },
                ])
                .set(i64::from(success)),
        }
    }
}

#[cfg(all(test, feature = "telemetry"))]
mod tests {
    use super::*;

    #[test]
    fn health_gauges_preserve_independent_duties_and_clear_recovered_states() {
        let metrics = iroha_telemetry::metrics::Metrics::default();
        Health::Unconfigured(true).record(&metrics);
        assert_eq!(metrics.sccp_keeper_unconfigured.get(), 1);
        Health::Unconfigured(false).record(&metrics);
        assert_eq!(metrics.sccp_keeper_unconfigured.get(), 0);
        for network in super::super::NETWORKS {
            Health::Recovery(network, true).record(&metrics);
            assert_eq!(
                metrics
                    .sccp_keeper_needs_recovery
                    .with_label_values(&[network.profile_key()])
                    .get(),
                1
            );
            Health::Poll(network, Duty::Advance, false).record(&metrics);
            Health::Poll(network, Duty::Watch, true).record(&metrics);
            assert_eq!(
                metrics
                    .sccp_keeper_poll_success
                    .with_label_values(&[network.profile_key(), "advance"])
                    .get(),
                0
            );
            assert_eq!(
                metrics
                    .sccp_keeper_poll_success
                    .with_label_values(&[network.profile_key(), "watch"])
                    .get(),
                1
            );
            Health::Recovery(network, false).record(&metrics);
            assert_eq!(
                metrics
                    .sccp_keeper_needs_recovery
                    .with_label_values(&[network.profile_key()])
                    .get(),
                0
            );
        }
        let text = metrics.try_to_string().unwrap();
        assert!(
            text.lines()
                .any(|line| line == "sccp_keeper_unconfigured 0")
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("sccp_keeper_needs_recovery{"))
                .count(),
            3
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("sccp_keeper_poll_success{"))
                .count(),
            6
        );
    }
}
