//! Native Parliament and fast-pause controls and wallet scheduling (§5.1.6, §7.1).
//!
//! Planning uses coherent destination time and the higher control nonce. It never treats a
//! Torii readiness label as certificate verification: applying a control requires the native
//! proof preflight below. Fast pause expiry remains distinct from Parliament pause.

use super::bundle::{BundleError, BundleSourceV1, VerifiedSourceV1};
use iroha_sccp::{
    api::SccpControlProofBundleV1,
    v1::destination::{
        CertificateSourceV1, ControlProofV1, DestinationObservationV1, PauseStateV1,
    },
};

/// Latest Taira control information used only to schedule a subsequent proof fetch.
/// The caller must bind it to its selected network/revision; it is not finality evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TairaControlV1 {
    /// Strictly increasing control nonce.
    pub control_nonce: u64,
    /// Parliament's persistent pause bit after the control.
    pub parliament_paused: bool,
    /// Fast-pause expiry after the control, or zero.
    pub fast_pause_until_ms: u64,
    /// Whether a native certificate is available to fetch, not whether it is trusted.
    pub provable: bool,
}
impl TairaControlV1 {
    /// Whether the control leaves minting paused at the coherent destination time.
    #[must_use]
    pub const fn effective(&self, now_ms: u64) -> bool {
        self.parliament_paused || now_ms < self.fast_pause_until_ms
    }
}
/// Where the higher control nonce was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlSourceV1 {
    /// Destination's current applied state.
    Destination,
    /// A newer recorded Taira control.
    Taira,
}
/// Newest control at the destination observation's time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewestControlV1 {
    /// Higher nonce (ties retain the destination's applied state).
    pub control_nonce: u64,
    /// Whether that control currently pauses minting.
    pub paused: bool,
    /// Source of the selected control.
    pub source: ControlSourceV1,
}
/// Select the higher nonce without collapsing Parliament and fast-pause expiry.
#[must_use]
pub fn newest_control(
    observation: &DestinationObservationV1,
    taira: Option<&TairaControlV1>,
) -> NewestControlV1 {
    let destination = observation.pause();
    match taira {
        Some(taira) if taira.control_nonce > destination.control_nonce => NewestControlV1 {
            control_nonce: taira.control_nonce,
            paused: taira.effective(observation.now_ms()),
            source: ControlSourceV1::Taira,
        },
        _ => NewestControlV1 {
            control_nonce: destination.control_nonce,
            paused: destination.effective,
            source: ControlSourceV1::Destination,
        },
    }
}
/// A newer control currently pauses minting, so recording must wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewestControlIsPause {
    /// The control that prevents recording.
    pub newest: NewestControlV1,
}
impl core::fmt::Display for NewestControlIsPause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the newest destination control (nonce {}) pauses minting",
            self.newest.control_nonce
        )
    }
}
impl std::error::Error for NewestControlIsPause {}
/// Refuse recording while the highest control nonce currently leaves minting paused.
///
/// # Errors
/// Returns the selected pausing control.
pub fn check_may_record(
    observation: &DestinationObservationV1,
    taira: Option<&TairaControlV1>,
) -> Result<(), NewestControlIsPause> {
    let newest = newest_control(observation, taira);
    if newest.paused {
        Err(NewestControlIsPause { newest })
    } else {
        Ok(())
    }
}
/// Required scheduling before any finalization; this is not certificate admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreFinalizeActionV1 {
    /// No newer control and the destination currently permits minting.
    Finalize,
    /// Fetch and verify a native proof, then apply the newer control before finalizing.
    ApplyControl {
        /// Control to prove and apply.
        control_nonce: u64,
        /// Whether it currently pauses minting.
        paused: bool,
    },
    /// A newer recorded control has no available native certificate yet.
    AwaitCertificate {
        /// Pending control nonce.
        control_nonce: u64,
        /// Whether it currently pauses minting.
        paused: bool,
    },
    /// Up-to-date destination remains paused.
    Paused,
}
/// Never skip a newer control; a pending resume must also be applied before minting.
#[must_use]
pub fn plan_before_finalize(
    observation: &DestinationObservationV1,
    taira: Option<&TairaControlV1>,
) -> PreFinalizeActionV1 {
    let newest = newest_control(observation, taira);
    if let Some(taira) = taira.filter(|_| newest.source == ControlSourceV1::Taira) {
        if taira.provable {
            PreFinalizeActionV1::ApplyControl {
                control_nonce: newest.control_nonce,
                paused: newest.paused,
            }
        } else {
            PreFinalizeActionV1::AwaitCertificate {
                control_nonce: newest.control_nonce,
                paused: newest.paused,
            }
        }
    } else if newest.paused {
        PreFinalizeActionV1::Paused
    } else {
        PreFinalizeActionV1::Finalize
    }
}

/// Immutable verified control call and its projected pause after the native expiry clamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedControlBundleV1 {
    network: iroha_data_model::bridge::SccpNetworkV1,
    source: VerifiedSourceV1,
    proof: ControlProofV1,
    after: PauseStateV1,
    historical: bool,
}
impl VerifiedControlBundleV1 {
    /// Destination profile actually authenticated by the proof preflight.
    #[must_use]
    pub const fn network(&self) -> iroha_data_model::bridge::SccpNetworkV1 {
        self.network
    }

    /// Exact native certificate or checkpoint reference.
    #[must_use]
    pub fn source(&self) -> CertificateSourceV1<'_> {
        self.source.borrow()
    }
    /// Exact complete native control proof.
    #[must_use]
    pub const fn proof(&self) -> &ControlProofV1 {
        &self.proof
    }
    /// Whether the control block precedes the certified header.
    #[must_use]
    pub const fn is_historical(&self) -> bool {
        self.historical
    }
    /// Projected pause at the observation's time, including the fast-pause clamp.
    #[must_use]
    pub const fn after(&self) -> PauseStateV1 {
        self.after
    }
    /// Whether the successfully applied control leaves minting enabled at that time.
    #[must_use]
    pub const fn finalize_allowed_after_apply(&self) -> bool {
        !self.after.effective
    }
}
/// Verify the route-bound complete control leaf through the shared native destination checks.
/// The observation supplies the nonce and both pause mechanisms; no second mutable state
/// argument can contradict it.
///
/// # Errors
/// Returns a label/shape error, missing observation or the exact native proof refusal.
pub fn verify_control_bundle(
    bundle: &SccpControlProofBundleV1,
    observation: &DestinationObservationV1,
    source: BundleSourceV1,
) -> Result<VerifiedControlBundleV1, BundleError> {
    let deployment = observation.deployment();
    let proof = bundle.control_proof(deployment.network, deployment.route_revision)?;
    let source = VerifiedSourceV1::from_bundle(&bundle.certificate, source)?;
    let after = observation.preflight_control(source.borrow(), &proof)?;
    Ok(VerifiedControlBundleV1 {
        network: observation.deployment().network,
        source,
        proof,
        after,
        historical: bundle.is_historical(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Fixture, NOW, reads};
    use super::*;
    use iroha_sccp::v1::destination::{DestinationError, DestinationFlavor, PreflightError};
    use std::collections::BTreeMap;
    fn control(nonce: u64, paused: bool, provable: bool) -> TairaControlV1 {
        TairaControlV1 {
            control_nonce: nonce,
            parliament_paused: paused,
            fast_pause_until_ms: 0,
            provable,
        }
    }
    fn observed(paused: bool) -> DestinationObservationV1 {
        let f = Fixture::new(DestinationFlavor::Evm);
        let initial = f.observation(NOW, BTreeMap::new());
        f.observation_with(
            NOW,
            *initial.committee(),
            BTreeMap::new(),
            PauseStateV1 {
                control_nonce: 3,
                parliament_paused: paused,
                fast_pause_until_ms: 0,
                effective: paused,
            },
        )
    }
    #[test]
    fn newest_control_prefers_higher_nonce_and_keeps_pause_expiry() {
        let view = observed(false);
        let newer = control(4, true, false);
        let equal = control(3, true, true);
        assert_eq!(
            newest_control(&view, Some(&newer)),
            NewestControlV1 {
                control_nonce: 4,
                paused: true,
                source: ControlSourceV1::Taira
            }
        );
        assert_eq!(
            newest_control(&view, Some(&equal)).source,
            ControlSourceV1::Destination
        );
        assert!(!newest_control(&view, None).paused);
        let fast = TairaControlV1 {
            parliament_paused: false,
            fast_pause_until_ms: NOW,
            ..newer
        };
        assert!(!newest_control(&view, Some(&fast)).paused);
        assert!(
            newest_control(
                &view,
                Some(&TairaControlV1 {
                    fast_pause_until_ms: NOW + 1,
                    ..fast
                })
            )
            .paused
        );
    }
    #[test]
    fn recording_is_refused_only_behind_newest_effective_pause() {
        assert!(check_may_record(&observed(true), None).is_err());
        assert!(check_may_record(&observed(false), None).is_ok());
        assert!(check_may_record(&observed(false), Some(&control(4, true, false))).is_err());
        assert!(check_may_record(&observed(true), Some(&control(4, false, false))).is_ok());
        assert!(check_may_record(&observed(true), Some(&control(3, false, true))).is_err());
        assert!(
            check_may_record(&observed(true), None)
                .unwrap_err()
                .to_string()
                .contains("nonce 3")
        );
    }
    #[test]
    fn finalization_applies_newer_controls_before_minting() {
        assert_eq!(
            plan_before_finalize(&observed(false), None),
            PreFinalizeActionV1::Finalize
        );
        assert_eq!(
            plan_before_finalize(&observed(true), None),
            PreFinalizeActionV1::Paused
        );
        for paused in [false, true] {
            assert_eq!(
                plan_before_finalize(&observed(!paused), Some(&control(4, paused, true))),
                PreFinalizeActionV1::ApplyControl {
                    control_nonce: 4,
                    paused
                }
            );
            assert_eq!(
                plan_before_finalize(&observed(!paused), Some(&control(4, paused, false))),
                PreFinalizeActionV1::AwaitCertificate {
                    control_nonce: 4,
                    paused
                }
            );
        }
    }
    #[test]
    fn control_bundles_verify_for_own_deployment_full_leaf_and_nonce() {
        let f = Fixture::new(DestinationFlavor::Evm);
        for history in [false, true] {
            let good = f.control(history, true, 0);
            let view = f.observation(NOW, reads(&good.certificate, false));
            let accepted = verify_control_bundle(&good, &view, BundleSourceV1::Inline).unwrap();
            assert_eq!(accepted.is_historical(), history);
            assert!(!accepted.finalize_allowed_after_apply());
            assert_eq!(accepted.proof().effect_hash, good.effect_hash);
            let mut bad = good.clone();
            bad.revision += 1;
            assert!(verify_control_bundle(&bad, &view, BundleSourceV1::Inline).is_err());
            let mut bad = good.clone();
            bad.network = iroha_data_model::bridge::SccpNetworkV1::BscMainnet;
            assert!(verify_control_bundle(&bad, &view, BundleSourceV1::Inline).is_err());
            let mut bad = good.clone();
            bad.effect_hash[0] ^= 1;
            assert_eq!(
                verify_control_bundle(&bad, &view, BundleSourceV1::Inline),
                Err(BundleError::Preflight(PreflightError::Destination(
                    DestinationError::BadProof
                )))
            );
            let stale = f.observation_with(
                NOW,
                *view.committee(),
                reads(&good.certificate, false),
                accepted.after(),
            );
            assert_eq!(
                verify_control_bundle(&good, &stale, BundleSourceV1::Inline),
                Err(BundleError::Preflight(PreflightError::Destination(
                    DestinationError::StaleControl
                )))
            );
        }
    }
}
