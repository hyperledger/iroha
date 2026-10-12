//! Native committee checkpoint plans, with the destination's actual latch/frozen semantics.
//!
//! Every handoff is authenticated by the independently observed current committee. Offered
//! successor keys are checked against the signed successor root and never become an initial
//! trust pin. Plans are preflight only: callers re-read state/time before each submitted call.

use iroha_sccp::{
    api::{ApiShapeError, SccpRotationV1},
    v1::{
        committee::CommitteeStateV1,
        destination::{
            DestinationFlavor, DestinationObservationV1, MAX_CERTIFICATES_PER_CALL, PreflightError,
            StopReasonV1, TairaCertificateV1,
        },
    },
};

/// Failure before a checkpoint plan can be returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationChainError {
    /// Malformed bounded certificate/successor at the indexed step.
    Shape {
        /// Zero-based offered step.
        index: usize,
        /// Failed shape check.
        error: ApiShapeError,
    },
    /// Native destination refusal or missing independently observed checkpoint.
    Step {
        /// Zero-based offered step.
        index: usize,
        /// Shared preflight refusal.
        error: PreflightError,
    },
    /// The available certified prefix cannot reach the requested generation.
    ChainTooShort {
        /// Reached generation.
        reached: u64,
        /// Required generation.
        target: u64,
        /// First known unavailable certified handoff, if reported.
        first_uncertified_handoff: Option<u64>,
    },
}
impl core::fmt::Display for RotationChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shape { index, error } => write!(f, "checkpoint step {index}: {error}"),
            Self::Step { index, error } => write!(f, "checkpoint step {index}: {error}"),
            Self::ChainTooShort {
                reached,
                target,
                first_uncertified_handoff,
            } => write!(
                f,
                "checkpoint chain reaches generation {reached}, not {target}; first uncertified handoff: {first_uncertified_handoff:?}"
            ),
        }
    }
}
impl std::error::Error for RotationChainError {}

/// One immutable, preflighted checkpoint message, including TON successor keys when needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpointV1 {
    flavor: DestinationFlavor,
    certificate: TairaCertificateV1,
    next_keys: Option<Vec<[u8; 48]>>,
}
impl VerifiedCheckpointV1 {
    /// Contract family whose state was actually preflighted.
    #[must_use]
    pub const fn flavor(&self) -> DestinationFlavor {
        self.flavor
    }

    /// Exact native certificate, unchanged by preflight.
    #[must_use]
    pub const fn certificate(&self) -> &TairaCertificateV1 {
        &self.certificate
    }
    /// Successor keys for a key-changing TON rotation; absent for EVM or a heartbeat.
    #[must_use]
    pub fn next_keys(&self) -> Option<&[[u8; 48]]> {
        self.next_keys.as_deref()
    }
}
/// A checkpoint prefix and the exact projected native state. A persisted stop is explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointPlanV1 {
    checkpoints: Vec<VerifiedCheckpointV1>,
    final_observation: DestinationObservationV1,
    stopped: Option<StopReasonV1>,
}
impl CheckpointPlanV1 {
    /// Whether the destination was already at or beyond the target generation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }
    /// Exact verified prefix; unprocessed certificates are never included.
    #[must_use]
    pub fn checkpoints(&self) -> &[VerifiedCheckpointV1] {
        &self.checkpoints
    }
    /// EVM groups at most sixteen certificates; TON sends one certificate per message.
    pub fn batches(&self) -> impl Iterator<Item = &[VerifiedCheckpointV1]> {
        self.checkpoints.chunks(
            if self.final_observation.deployment().flavor == DestinationFlavor::Evm {
                MAX_CERTIFICATES_PER_CALL
            } else {
                1
            },
        )
    }
    /// Projected state; callers refresh the real observation after submission.
    #[must_use]
    pub const fn final_observation(&self) -> &DestinationObservationV1 {
        &self.final_observation
    }
    /// A successfully persisted latch/frozen outcome, distinct from an atomic refusal.
    #[must_use]
    pub const fn stopped(&self) -> Option<StopReasonV1> {
        self.stopped
    }
}
/// Verify certified rotations until the target or an explicit persisted stop is reached.
/// Steps past that prefix are ignored. A new chain starts only from the independently
/// observed current committee. The shared transition enforces exact heights, time bounds,
/// successor identity and latch semantics; it never accepts a previous-roster grace path.
///
/// # Errors
/// Returns the indexed shape/native refusal, or the exact reached/target shortfall.
pub fn verify_rotation_steps(
    steps: &[SccpRotationV1],
    first_uncertified_handoff: Option<u64>,
    observation: &DestinationObservationV1,
    target_generation: u64,
) -> Result<CheckpointPlanV1, RotationChainError> {
    let mut current = observation.clone();
    let mut checkpoints = Vec::new();
    let mut stopped = None;
    for (index, step) in steps.iter().enumerate() {
        if current.committee().generation >= target_generation {
            break;
        }
        step.check_shape()
            .map_err(|error| RotationChainError::Shape { index, error })?;
        let certificate = step
            .certificate
            .to_destination_certificate()
            .map_err(|error| RotationChainError::Shape { index, error })?;
        let next_keys = (current.deployment().flavor == DestinationFlavor::Ton
            && iroha_sccp::v1::finality::SccpFinalityHeaderV1::parse(&step.certificate.header)
                .map_err(|_| RotationChainError::Shape {
                    index,
                    error: ApiShapeError::BadCertificate,
                })?
                .next_committee_root()
                != current.committee().root)
            .then(|| step.next_committee.clone());
        let result = current
            .preflight_checkpoints(
                std::slice::from_ref(&certificate),
                std::slice::from_ref(&next_keys),
            )
            .map_err(|error| RotationChainError::Step { index, error })?;
        current = result.observation().clone();
        stopped = result.stopped();
        checkpoints.push(VerifiedCheckpointV1 {
            flavor: current.deployment().flavor,
            certificate,
            next_keys,
        });
        if stopped.is_some() {
            break;
        }
    }
    if stopped.is_none() && current.committee().generation < target_generation {
        return Err(RotationChainError::ChainTooShort {
            reached: current.committee().generation,
            target: target_generation,
            first_uncertified_handoff,
        });
    }
    Ok(CheckpointPlanV1 {
        checkpoints,
        final_observation: current,
        stopped,
    })
}

/// A committee expires too early for the wallet's selected finalize horizon, or is not live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitteeHorizonError {
    /// Expired or irreversibly equivocated.
    NotLive,
    /// The observed trust deadline precedes the required completion horizon.
    ExpiresTooSoon {
        /// Actual destination trust deadline.
        until_ms: u64,
        /// Checked deadline plus clock/inclusion margin.
        required_until_ms: u64,
    },
}
impl core::fmt::Display for CommitteeHorizonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLive => f.write_str("destination committee is not live"),
            Self::ExpiresTooSoon {
                until_ms,
                required_until_ms,
            } => write!(
                f,
                "committee ends at {until_ms}, before required horizon {required_until_ms}"
            ),
        }
    }
}
impl std::error::Error for CommitteeHorizonError {}
/// Require this generation's lifetime to cover the full intended mint horizon (§7.1).
/// Apply the check to every projected generation as well; mere availability of a future
/// rotation does not waive the currently observed deadline.
///
/// # Errors
/// Returns non-live or an insufficient trust deadline; arithmetic saturates without wrapping.
pub fn check_committee_horizon(
    state: &CommitteeStateV1,
    now_ms: u64,
    outbound_ttl_ms: u64,
    clock_and_inclusion_margin_ms: u64,
) -> Result<(), CommitteeHorizonError> {
    if !state.is_live(now_ms) {
        return Err(CommitteeHorizonError::NotLive);
    }
    let required_until_ms = now_ms
        .saturating_add(outbound_ttl_ms)
        .saturating_add(clock_and_inclusion_margin_ms);
    if state.until_ms < required_until_ms {
        Err(CommitteeHorizonError::ExpiresTooSoon {
            until_ms: state.until_ms,
            required_until_ms,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{DAY, Fixture, NOW, T0};
    use super::*;
    use std::collections::BTreeMap;
    fn setup(count: u64) -> (Vec<SccpRotationV1>, DestinationObservationV1) {
        let f = Fixture::new(DestinationFlavor::Evm);
        let steps = f.rotations(count);
        let view = f.observation(
            NOW,
            steps
                .iter()
                .map(|step| (step.certificate.height, None))
                .collect(),
        );
        (steps, view)
    }
    #[test]
    fn a_long_native_chain_verifies_and_splits_into_sixteen() {
        let (steps, view) = setup(17);
        let plan = verify_rotation_steps(&steps, None, &view, 24).unwrap();
        assert_eq!(plan.checkpoints().len(), 17);
        assert_eq!(plan.final_observation().committee().generation, 24);
        assert_eq!(
            plan.batches()
                .map(<[VerifiedCheckpointV1]>::len)
                .collect::<Vec<_>>(),
            vec![16, 1]
        );
        assert!(!plan.is_empty());
        assert_eq!(plan.stopped(), None);
        assert!(
            plan.checkpoints()
                .iter()
                .all(|step| step.certificate().qc[112..] == 0b111_u32.to_be_bytes())
        );
    }
    #[test]
    fn native_chain_stops_at_target_and_reports_exact_shortfall() {
        let (steps, view) = setup(3);
        let plan = verify_rotation_steps(&steps, None, &view, 8).unwrap();
        assert_eq!(plan.checkpoints().len(), 1);
        let empty = verify_rotation_steps(&steps, None, &view, 7).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.final_observation(), &view);
        assert_eq!(
            verify_rotation_steps(&steps, Some(777), &view, 13),
            Err(RotationChainError::ChainTooShort {
                reached: 10,
                target: 13,
                first_uncertified_handoff: Some(777)
            })
        );
        assert_eq!(
            verify_rotation_steps(&steps[..1], None, &view, 9),
            Err(RotationChainError::ChainTooShort {
                reached: 8,
                target: 9,
                first_uncertified_handoff: None
            })
        );
    }
    #[test]
    fn native_rotation_bounds_and_signatures_are_enforced() {
        let (steps, view) = setup(2);
        assert!(matches!(
            verify_rotation_steps(&steps[1..], None, &view, 9),
            Err(RotationChainError::Step { index: 0, .. })
        ));
        let f = Fixture::new(DestinationFlavor::Evm);
        let expired = f.observation(
            T0 + 14 * DAY + 1,
            steps
                .iter()
                .map(|step| (step.certificate.height, None))
                .collect(),
        );
        assert!(verify_rotation_steps(&steps, None, &expired, 9).is_err());
        let mut bad = steps.clone();
        bad[0].certificate.qc[80] ^= 1;
        assert!(matches!(
            verify_rotation_steps(&bad, None, &view, 9),
            Err(RotationChainError::Step { index: 0, .. })
        ));
        let mut bad = steps.clone();
        bad[0].next_committee.swap(0, 1);
        assert!(matches!(
            verify_rotation_steps(&bad, None, &view, 9),
            Err(RotationChainError::Shape { index: 0, .. })
        ));
        let mut bad = steps.clone();
        bad[0].certificate.header[88] ^= 1;
        assert!(verify_rotation_steps(&bad, None, &view, 9).is_err());
    }
    #[test]
    fn committee_horizon_has_no_available_rotation_waiver() {
        let f = Fixture::new(DestinationFlavor::Evm);
        let view = f.observation(NOW, BTreeMap::new());
        let mut state = *view.committee();
        state.until_ms = 1000;
        assert_eq!(check_committee_horizon(&state, 100, 400, 500), Ok(()));
        assert_eq!(
            check_committee_horizon(&state, 101, 400, 500),
            Err(CommitteeHorizonError::ExpiresTooSoon {
                until_ms: 1000,
                required_until_ms: 1001
            })
        );
        assert_eq!(
            check_committee_horizon(&state, 1001, 0, 0),
            Err(CommitteeHorizonError::NotLive)
        );
        state.equivocated = true;
        assert_eq!(
            check_committee_horizon(&state, 100, 0, 0),
            Err(CommitteeHorizonError::NotLive)
        );
        assert!(
            CommitteeHorizonError::NotLive
                .to_string()
                .contains("not live")
        );
        assert!(
            RotationChainError::ChainTooShort {
                reached: 1,
                target: 2,
                first_uncertified_handoff: None
            }
            .to_string()
            .contains("generation 1")
        );
    }
}
