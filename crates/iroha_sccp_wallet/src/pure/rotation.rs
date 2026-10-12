//! Native committee catch-up through authenticated checkpoint certificates (§5.1.2, §7.1).
//!
//! Every step is verified against the current destination root before it may install the
//! announced successor. The scalar committee machine owns Live, V1–V3 and deadline rules;
//! TON successor keys remain bound to the signed next root. A plan never silently submits a
//! latch or a rotation that would leave the destination frozen.

use super::bundle::{BundleError, DestinationContextV1, certificate_wire, committee_error};
use core::fmt;
use iroha_sccp::{
    api::SccpRotationV1,
    v1::{
        committee::{CheckpointOutcomeV1, CommitteeStateV1, ViolationV1, successor_keys_match},
        destination::{
            CertificateAuthorityV1, DestinationFlavor, MAX_CERTIFICATES_PER_CALL,
            TairaCertificateV1,
        },
        destination_abi::DestinationError,
    },
};
use std::collections::BTreeMap;

/// Why a requested catch-up cannot safely be submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationChainError {
    /// A candidate certificate or successor failed verification.
    Step {
        /// Zero-based candidate index.
        index: usize,
        /// Concrete failed check.
        error: BundleError,
    },
    /// A certificate would latch the destination; ordinary wallet catch-up must stop.
    Latch {
        /// Zero-based candidate index.
        index: usize,
        /// The authenticated violation, suitable for explicit evidence handling.
        violation: ViolationV1,
    },
    /// A verified successor is already expired at destination time.
    Frozen {
        /// Zero-based candidate index.
        index: usize,
    },
    /// The ordered chain did not reach the requested generation.
    ChainTooShort {
        /// Last generation reached.
        reached: u64,
        /// Requested generation.
        target: u64,
    },
}
impl fmt::Display for RotationChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Step { index, error } => write!(f, "checkpoint step {index}: {error}"),
            Self::Latch { index, violation } => write!(
                f,
                "checkpoint step {index} requires a latch: {:?}",
                violation.reason
            ),
            Self::Frozen { index } => {
                write!(f, "checkpoint step {index} installs an expired successor")
            }
            Self::ChainTooShort { reached, target } => write!(
                f,
                "committee chain reaches generation {reached}, not {target}"
            ),
        }
    }
}
impl std::error::Error for RotationChainError {}

/// One verified current certificate and, when required, the original announced TON keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRotationV1 {
    certificate: TairaCertificateV1,
    next_keys: Option<Vec<[u8; 48]>>,
}
impl VerifiedRotationV1 {
    /// Certificate exactly as verified, borrowed for the current destination encoder.
    #[must_use]
    pub const fn certificate(&self) -> &TairaCertificateV1 {
        &self.certificate
    }
    /// TON keys only for a key-changing rotation; a heartbeat retains the stored keys.
    #[must_use]
    pub fn next_keys(&self) -> Option<&[[u8; 48]]> {
        self.next_keys.as_deref()
    }
}
/// An immutable ordered catch-up plan and its verified resulting scalar state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPlanV1 {
    steps: Vec<VerifiedRotationV1>,
    initial_state: CommitteeStateV1,
    final_state: CommitteeStateV1,
    minimum_until_ms: u64,
}
impl RotationPlanV1 {
    /// Whether the destination already meets the requested generation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
    /// Current certificates in verified application order.
    #[must_use]
    pub fn steps(&self) -> &[VerifiedRotationV1] {
        &self.steps
    }
    /// EVM batches of at most sixteen; TON submits each certificate as a checkpoint message.
    pub fn batches(&self) -> impl Iterator<Item = &[VerifiedRotationV1]> {
        self.steps.chunks(MAX_CERTIFICATES_PER_CALL)
    }
    /// Scalar committee state after every planned checkpoint.
    #[must_use]
    pub const fn final_state(&self) -> &CommitteeStateV1 {
        &self.final_state
    }
    /// Earliest trust deadline among the destination's original and every successor generation.
    #[must_use]
    pub const fn minimum_until_ms(&self) -> u64 {
        self.minimum_until_ms
    }
}

fn record_checkpoint(
    checkpoints: &mut BTreeMap<u64, [u8; 32]>,
    flavor: DestinationFlavor,
    height: u64,
    id: [u8; 32],
) {
    if checkpoints.contains_key(&height) {
        return;
    }
    if let Some(slots) = flavor.checkpoint_slots()
        && checkpoints.len() >= slots
    {
        if checkpoints
            .first_key_value()
            .is_none_or(|(lowest, _)| height <= *lowest)
        {
            return;
        }
        checkpoints.pop_first();
    }
    checkpoints.insert(height, id);
}

/// Verify ordered current rotation records up to the required generation.
/// Candidates beyond the requested target are not used. All checked steps use the actual
/// selected destination clock; callers re-observe and re-verify after each submitted batch.
///
/// # Errors
/// Returns a concrete certificate, committee, successor, latch, expiry or missing-step error.
pub fn verify_rotation_steps(
    steps: &[SccpRotationV1],
    context: &DestinationContextV1<'_>,
    target_generation: u64,
) -> Result<RotationPlanV1, RotationChainError> {
    let mut current = context.committee_state;
    let mut keys = context.ton_keys.map(<[[u8; 48]]>::to_vec);
    let mut checkpoints = context.checkpoints.clone();
    let mut verified_steps = Vec::new();
    let mut minimum_until_ms = current.until_ms;
    current
        .require_live(context.now_ms)
        .map_err(|e| RotationChainError::Step {
            index: 0,
            error: committee_error(e).into(),
        })?;
    for (index, step) in steps.iter().enumerate() {
        if current.generation >= target_generation {
            break;
        }
        let failed = |error: BundleError| RotationChainError::Step { index, error };
        step.certificate
            .check_shape()
            .map_err(|e| failed(e.into()))?;
        let wire = certificate_wire(&step.certificate).map_err(failed)?;
        let authority = CertificateAuthorityV1::new(
            context.flavor,
            &context.taira_network_id,
            &context.consensus_instance,
            &current,
            keys.as_deref(),
        )
        .map_err(|e| failed(e.into()))?;
        let checked = authority
            .verify(&wire, |height| checkpoints.get(&height).copied())
            .map_err(|e| failed(e.into()))?;
        let needs_keys = current.successor_needs_keys(&checked.header);
        let outcome = current
            .apply_checkpoint(
                &checked.header,
                checkpoints.get(&checked.header.height()),
                context.now_ms,
            )
            .map_err(|e| failed(committee_error(e).into()))?;
        match outcome {
            CheckpointOutcomeV1::Latched(violation) => {
                return Err(RotationChainError::Latch { index, violation });
            }
            CheckpointOutcomeV1::Applied { live: false, .. } => {
                return Err(RotationChainError::Frozen { index });
            }
            CheckpointOutcomeV1::Applied { .. } => {}
        }
        step.check_shape().map_err(|e| failed(e.into()))?;
        // V1–V3 run before TON's key-change check, as the destination specifies.
        let next_keys = if context.flavor == DestinationFlavor::Ton && needs_keys {
            if !successor_keys_match(&step.next_committee, &checked.header.next_committee_root()) {
                return Err(failed(DestinationError::BadCommittee.into()));
            }
            keys = Some(step.next_committee.clone());
            Some(step.next_committee.clone())
        } else {
            None
        };
        record_checkpoint(
            &mut checkpoints,
            context.flavor,
            checked.header.height(),
            checked.checkpoint_id,
        );
        minimum_until_ms = minimum_until_ms.min(current.until_ms);
        verified_steps.push(VerifiedRotationV1 {
            certificate: wire,
            next_keys,
        });
    }
    if current.generation < target_generation {
        return Err(RotationChainError::ChainTooShort {
            reached: current.generation,
            target: target_generation,
        });
    }
    Ok(RotationPlanV1 {
        steps: verified_steps,
        initial_state: context.committee_state,
        final_state: current,
        minimum_until_ms,
    })
}

/// A destination cannot safely accept a new transfer for the requested time horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitteeHorizonError {
    /// The plan was verified against a different destination committee observation.
    ContextChanged,
    /// The requested TTL and margin extend beyond the representable time range.
    HorizonOverflow,
    /// The actual destination is already expired or latched.
    Frozen,
    /// A required generation expires before the requested deadline plus margin.
    ExpiresTooSoon {
        /// Earliest deadline on the actual verified chain.
        until_ms: u64,
        /// Required destination deadline.
        required_until_ms: u64,
    },
}
impl fmt::Display for CommitteeHorizonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextChanged => {
                f.write_str("committee state changed since catch-up verification")
            }
            Self::HorizonOverflow => {
                f.write_str("requested committee trust horizon exceeds the timestamp range")
            }
            Self::Frozen => f.write_str("destination committee is frozen"),
            Self::ExpiresTooSoon {
                until_ms,
                required_until_ms,
            } => write!(
                f,
                "committee trust expires at {until_ms} ms before the required {required_until_ms} ms"
            ),
        }
    }
}
impl std::error::Error for CommitteeHorizonError {}
/// Check both the actual destination and all generations in a verified catch-up plan.
/// A mere claim that a rotation is available never bypasses the deadline requirement.
///
/// # Errors
/// Refuses a changed context, a frozen or short-lived committee, and an unrepresentable
/// requested interval. An overflowing TTL or margin is never silently shortened.
pub fn check_committee_horizon(
    state: &CommitteeStateV1,
    plan: &RotationPlanV1,
    now_ms: u64,
    outbound_ttl_ms: u64,
    margin_ms: u64,
) -> Result<(), CommitteeHorizonError> {
    if *state != plan.initial_state {
        return Err(CommitteeHorizonError::ContextChanged);
    }
    if !state.is_live(now_ms) {
        return Err(CommitteeHorizonError::Frozen);
    }
    let required_until_ms = now_ms
        .checked_add(outbound_ttl_ms)
        .and_then(|until| until.checked_add(margin_ms))
        .ok_or(CommitteeHorizonError::HorizonOverflow)?;
    let until_ms = state.until_ms.min(plan.minimum_until_ms);
    if until_ms < required_until_ms {
        return Err(CommitteeHorizonError::ExpiresTooSoon {
            until_ms,
            required_until_ms,
        });
    }
    Ok(())
}
#[cfg(test)]
mod tests;
