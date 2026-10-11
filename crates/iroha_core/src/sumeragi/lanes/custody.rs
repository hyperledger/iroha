//! Creation-time stake ownership and retained global lifetime of native lane obligations.
//!
//! Monetary identity is pinned once. Retirement removes routing/storage ownership, not the
//! obligation. Native lane heights never enter the global evidence or withdrawal clocks.

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedBufferError, PrepaidBufferError,
    PrepaidSharedError,
};
use iroha_config::parameters::actual::Nexus;
use iroha_data_model::{
    nexus::PublicLaneValidatorRecord,
    sumeragi_lanes::{
        CustodySignersAdmissionError, LaneSamplesAdmissionError, LaneStateAdmissionError,
        MAX_LANE_CUSTODY_OBLIGATIONS, MAX_LANE_CUSTODY_SIGNERS, SumeragiLaneCustody,
        SumeragiLaneCustodySigners, SumeragiLanePolicy, SumeragiLaneRecord,
        SumeragiLaneSignerCustody, SumeragiLaneStakeBinding, SumeragiLaneState,
    },
};
use iroha_model_base::topology::LaneId;
use mv::storage::StorageReadOnly;

use crate::execution_attempt::{ExecutionAttemptError as Attempt, ExecutionDeferred};
use crate::state::{WorldReadOnly, nexus_staking_authority_lane_at_height};
use ivm::error::ExecutionDeferral;

/// Deterministic defects in original lane custody; fixed-size errors need no allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
// Keep the public lane-step error payload inline with its lane-id-sized alternatives.
#[repr(u32)]
pub enum CustodyViolation {
    /// The committee exceeds native geometry.
    #[error("invalid lane custody committee")]
    Committee,
    /// One peer occupies more than one committee position.
    #[error("duplicate original lane committee member")]
    DuplicateMember,
    /// A native position cannot fit its canonical index.
    #[error("lane signer index overflow")]
    SignerIndex,
    /// More than one original stake registration claims a native signer.
    #[error("lane signer has ambiguous original stake custody")]
    AmbiguousStake,
    /// Original registration or escrow cannot produce a valid tenure identity.
    #[error("invalid original lane stake custody")]
    StakeBinding,
    /// Sparse signer bindings violate their canonical order or bounds.
    #[error("invalid original lane custody signer order or bound")]
    Signers,
    /// Retained fences or original incarnation identity are inconsistent.
    #[error("invalid original lane custody obligation")]
    Obligation,
    /// Monetary custody has lost its signed admission and penalty policy.
    #[error("lane custody lost signed evidence policy")]
    MissingPolicy,
    /// A live original incarnation disappeared before authenticated retirement.
    #[error("live lane custody lost its original incarnation")]
    MissingIncarnation,
    /// A later global merge regressed or rewrote the same native frontier.
    #[error("original lane custody frontier regressed or changed branch")]
    Frontier,
    /// A creation attempts to replace already pinned original custody.
    #[error("duplicate lane custody creation")]
    DuplicateCreation,
    /// Deterministic creation failed to respect the available ledger capacity.
    #[error("lane custody capacity exhausted")]
    Capacity,
}

/// Preserve the exact refused original pool and its pre-refund release observation.
fn allocation_deferred(original: AllocationRefusal) -> ExecutionDeferred {
    #[cfg(not(all(test, sumeragi_core_mutation = "HC136")))]
    {
        original.into()
    }
    #[cfg(all(test, sumeragi_core_mutation = "HC136"))]
    {
        let _ = original;
        ExecutionDeferral::AllocationUnavailable.into()
    }
}

fn backing_deferred(error: ChargedBufferError) -> ExecutionDeferred {
    match error {
        ChargedBufferError::Admission(original) => allocation_deferred(original),
        ChargedBufferError::Allocator { .. } => ExecutionDeferral::AllocationUnavailable.into(),
    }
}

fn control_deferred(error: PrepaidSharedError) -> ExecutionDeferred {
    match error {
        PrepaidSharedError::Reservation(_) => ExecutionDeferral::LocalInvariantViolation.into(),
        PrepaidSharedError::Allocator { .. } => ExecutionDeferral::AllocationUnavailable.into(),
    }
}

/// Resource admission cannot turn invalid sparse signer geometry into a retry or conceal a
/// foreign original pool. A refused exact pool retains its original local release owner.
pub(super) fn signers_admission_attempt_error(
    error: CustodySignersAdmissionError,
) -> Attempt<CustodyViolation> {
    match error {
        CustodySignersAdmissionError::Invalid => CustodyViolation::Signers.into(),
        CustodySignersAdmissionError::ForeignBudget => {
            Attempt::Deferred(ExecutionDeferral::LocalInvariantViolation.into())
        }
        CustodySignersAdmissionError::Backing(error) => Attempt::Deferred(backing_deferred(error)),
        CustodySignersAdmissionError::ControlAdmission(original) => {
            Attempt::Deferred(allocation_deferred(original))
        }
        CustodySignersAdmissionError::ControlAllocation(error) => {
            Attempt::Deferred(control_deferred(error))
        }
    }
}

/// Preserve the exact original sample admission; prepaid geometry and pool identity defects
/// require recovery, while only a physical allocation failure reports unavailable allocation.
pub(super) fn samples_admission_deferred(error: LaneSamplesAdmissionError) -> ExecutionDeferred {
    match error {
        LaneSamplesAdmissionError::ForeignBudget
        | LaneSamplesAdmissionError::Backing(PrepaidBufferError::Reservation(_)) => {
            ExecutionDeferral::LocalInvariantViolation.into()
        }
        LaneSamplesAdmissionError::Admission(original) => allocation_deferred(original),
        LaneSamplesAdmissionError::Backing(PrepaidBufferError::Allocation(error)) => {
            backing_deferred(error)
        }
        LaneSamplesAdmissionError::Control(error) => control_deferred(error),
    }
}

/// Project completed signer rejection only; retain the original nested pool refusal before
/// the native finalizer can return its sole original proposal to the validator caller.
pub(super) fn state_admission_attempt_error(
    error: LaneStateAdmissionError,
) -> Attempt<CustodyViolation> {
    match error {
        LaneStateAdmissionError::Signers(error) => signers_admission_attempt_error(error),
        LaneStateAdmissionError::Samples(error) => {
            Attempt::Deferred(samples_admission_deferred(error))
        }
    }
}

/// Pin only genuine positive custody belonging to the original selected peer and tenure.
/// Sparse fixed-size entries contain no nested heap owners; identity hashing streams bytes.
/// Immutable signer backing and its shared control retain the original State pool through
/// every World clone. TODO(S8): fund outer lane/custody vectors and their Cell owners.
fn pin_signers(
    world: &impl WorldReadOnly,
    nexus: &Nexus,
    record: &SumeragiLaneRecord,
    elastic: bool,
    budget: &AllocationBudget,
) -> Result<SumeragiLaneCustodySigners, Attempt<CustodyViolation>> {
    if !(1..=MAX_LANE_CUSTODY_SIGNERS).contains(&record.committee.len()) {
        return Err(CustodyViolation::Committee.into());
    }
    // Elastic committees are sampled from global validators. Fixed committees may bind only
    // the canonical staking owner of their physical dataspace; an unbound signer is forensic.
    let owner = if elastic {
        Some(LaneId::SINGLE)
    } else {
        nexus_staking_authority_lane_at_height(record.lane, nexus, record.created_at)
    };
    let Some(owner) = owner else {
        return Ok(SumeragiLaneCustodySigners::default());
    };
    // Count from this same immutable cursor before creating the exact fixed backing.
    // Actual binding/order validation below is unchanged; no stake or authority is inferred
    // from this allocation count, and a refusal leaves the original World untouched.
    let count = world
        .public_lane_validators()
        .iter()
        .filter(|(key, validator)| {
            let (lane, account) = key;
            *lane == owner
                && validator.lane_id == *lane
                && validator.validator == *account
                && validator.stake_account == *account
                && validator.activation_height <= record.created_at
                && validator
                    .deactivation_height
                    .is_none_or(|end| record.created_at < end)
                && record
                    .committee
                    .iter()
                    .any(|member| member.peer == validator.peer_id)
                && world
                    .public_lane_stake_custody()
                    .get(key)
                    .is_some_and(|(_, amount)| !amount.is_zero())
        })
        .count();
    if count > record.committee.len() {
        return Err(CustodyViolation::AmbiguousStake.into());
    }
    let mut signers = ChargedBuffer::<SumeragiLaneSignerCustody>::new(count, budget)
        .map_err(|error| Attempt::Deferred(backing_deferred(error)))?;
    for (key, validator) in world.public_lane_validators().iter() {
        let (lane, account) = key;
        if *lane != owner
            || validator.lane_id != *lane
            || validator.validator != *account
            || validator.stake_account != *account
            || validator.activation_height > record.created_at
            || validator
                .deactivation_height
                .is_some_and(|end| record.created_at >= end)
        {
            continue;
        }
        let matching = record
            .committee
            .iter()
            .filter(|member| member.peer == validator.peer_id)
            .count();
        if matching == 0 {
            continue;
        }
        if matching != 1 {
            return Err(CustodyViolation::DuplicateMember.into());
        }
        // The native core sorts consensus keys, while a fixed policy need not store its
        // members in that order. BLS-normal PeerIds use the same canonical key ordering.
        let index = record
            .committee
            .iter()
            .filter(|member| member.peer < validator.peer_id)
            .count();
        // Borrow the complete composite key from this original cursor; no account clone is
        // needed just to find the original retained asset and positive custody amount.
        let Some((asset, amount)) = world.public_lane_stake_custody().get(key) else {
            continue;
        };
        if amount.is_zero() {
            continue;
        }
        let signer = u32::try_from(index).map_err(|_| CustodyViolation::SignerIndex)?;
        if signers
            .as_slice()
            .iter()
            .any(|entry| entry.signer == signer)
        {
            return Err(CustodyViolation::AmbiguousStake.into());
        }
        signers.push_reserved(SumeragiLaneSignerCustody {
            signer,
            binding: SumeragiLaneStakeBinding::from_record(validator, asset)
                .map_err(|_| CustodyViolation::StakeBinding)?,
        });
    }
    if signers.as_slice().is_empty() {
        return Ok(SumeragiLaneCustodySigners::default());
    }
    signers
        .as_mut_slice()
        .sort_unstable_by_key(|entry| entry.signer);
    SumeragiLaneCustodySigners::from_charged(signers, budget)
        .map_err(|(_rows, error)| signers_admission_attempt_error(error))
}

/// Carry forward monotone signed policy and mark exact retirement before records are removed.
pub(super) fn prepare_retirement(
    state: &mut SumeragiLaneState,
    world: &impl WorldReadOnly,
    height: u64,
) -> Result<(), Attempt<CustodyViolation>> {
    let parameters = world
        .sumeragi_npos_parameters()
        .map_err(|error| error.map_rejection(|_| CustodyViolation::MissingPolicy))?;
    for obligation in &mut state.custody {
        obligation
            .validate()
            .map_err(|_| CustodyViolation::Obligation)?;
        let parameters = parameters.as_ref().ok_or(CustodyViolation::MissingPolicy)?;
        obligation.evidence_horizon = obligation
            .evidence_horizon
            .max(parameters.evidence_horizon_blocks());
        obligation.slashing_delay = obligation
            .slashing_delay
            .max(parameters.slashing_delay_blocks());
        if obligation.retired_at.is_none() {
            let record = state
                .lanes
                .iter()
                .find(|record| record.incarnation == obligation.incarnation)
                .ok_or(CustodyViolation::MissingIncarnation)?;
            if record.merged.height < obligation.merged.height
                || (record.merged.height == obligation.merged.height
                    && record.merged != obligation.merged)
            {
                return Err(CustodyViolation::Frontier.into());
            }
            // The lane step has already applied this carrier's merges. Retain its final exact
            // frontier before retirement removes the live routing record in the same step.
            obligation.merged = record.merged;
            if record
                .retirement_height()
                .is_some_and(|retirement| retirement <= height)
            {
                obligation.retired_at = record.retirement_height();
            }
        }
        obligation
            .validate()
            .map_err(|_| CustodyViolation::Obligation)?;
    }
    state.custody.retain(|obligation| {
        obligation.retains_at(height).unwrap_or(true) || has_retained_evidence(world, obligation)
    });
    Ok(())
}

/// Creation can wait for custody capacity; existing lane close/retirement remains executable.
pub(super) fn creation_capacity(
    state: &SumeragiLaneState,
    world: &impl WorldReadOnly,
) -> Result<usize, Attempt<CustodyViolation>> {
    Ok(
        if world
            .sumeragi_npos_parameters()
            .map_err(|error| error.map_rejection(|_| CustodyViolation::MissingPolicy))?
            .is_some()
        {
            MAX_LANE_CUSTODY_OBLIGATIONS.saturating_sub(state.custody.len())
        } else {
            usize::MAX
        },
    )
}

/// Install each creation's original binding exactly once after deterministic lane selection.
pub(super) fn pin_created(
    state: &mut SumeragiLaneState,
    world: &impl WorldReadOnly,
    nexus: &Nexus,
    network: &iroha_data_model::NetworkId,
    chain_id: &str,
    policy: Option<&SumeragiLanePolicy>,
    height: u64,
    budget: &AllocationBudget,
) -> Result<(), Attempt<CustodyViolation>> {
    let Some(parameters) = world
        .sumeragi_npos_parameters()
        .map_err(|error| error.map_rejection(|_| CustodyViolation::MissingPolicy))?
    else {
        // Permissioned chains have no signed monetary evidence horizon; existing native
        // forensic verification remains possible but creation cannot manufacture stake policy.
        return Ok(());
    };
    for record in state
        .lanes
        .iter()
        .filter(|record| record.created_at == height)
    {
        if state
            .custody
            .iter()
            .any(|row| row.incarnation == record.incarnation)
        {
            return Err(CustodyViolation::DuplicateCreation.into());
        }
        if state.custody.len() >= MAX_LANE_CUSTODY_OBLIGATIONS {
            return Err(CustodyViolation::Capacity.into());
        }
        let obligation = SumeragiLaneCustody {
            lane: record.lane,
            incarnation: record.incarnation,
            instance: super::lane_instance(
                &crate::sumeragi::crypto::BlsCrypto::new(),
                network,
                chain_id,
                record,
            )
            .0,
            created_at: record.created_at,
            merged: record.merged,
            signer_count: u32::try_from(record.committee.len())
                .map_err(|_| CustodyViolation::Committee)?,
            signers: pin_signers(
                world,
                nexus,
                record,
                policy.is_some_and(|policy| policy.is_elastic(record.lane)),
                budget,
            )?,
            evidence_horizon: parameters.evidence_horizon_blocks(),
            slashing_delay: parameters.slashing_delay_blocks(),
            retired_at: None,
        };
        obligation
            .validate()
            .map_err(|_| CustodyViolation::Obligation)?;
        state
            .custody
            .try_reserve_exact(1)
            .map_err(|_| Attempt::Deferred(ExecutionDeferral::AllocationUnavailable.into()))?;
        state.custody.push(obligation);
    }
    state.custody.sort_unstable_by_key(|row| row.incarnation);
    Ok(())
}

/// Retained obligations prohibit reuse of the exact registration, even after all stake is gone.
/// Malformed authenticated custody fails closed. Ordinary global committee rules remain separate.
pub(crate) fn retains_registration(
    world: &impl WorldReadOnly,
    record: &PublicLaneValidatorRecord,
    height: u64,
) -> Result<bool, Attempt<String>> {
    let parameters = world.sumeragi_npos_parameters()?;
    Ok(retains_registration_with_parameters(
        world,
        record,
        height,
        parameters.as_ref(),
    ))
}

/// Use one already decoded original policy for a complete retained-custody scan.
pub(crate) fn retains_registration_with_parameters(
    world: &impl WorldReadOnly,
    record: &PublicLaneValidatorRecord,
    height: u64,
    parameters: Option<&iroha_data_model::parameter::system::SumeragiNposParameters>,
) -> bool {
    world.sumeragi_lanes().custody.iter().any(|obligation| {
        (effective_retains_at(obligation, parameters, height)
            || has_pending_evidence(world, obligation))
            && obligation.signers.as_slice().iter().any(|entry| {
                let binding = &entry.binding;
                binding.activation_height == record.activation_height
                    && binding
                        .names_account(record.lane_id, &record.validator)
                        .unwrap_or(true)
            })
    })
}

// A same-block policy extension must apply before a transaction can release custody; the
// final lane step persists those monotone fences only after transaction execution finishes.
fn effective_retains_at(
    obligation: &SumeragiLaneCustody,
    parameters: Option<&iroha_data_model::parameter::system::SumeragiNposParameters>,
    height: u64,
) -> bool {
    if obligation.validate().is_err() {
        return true;
    }
    let Some(retired) = obligation.retired_at else {
        return true;
    };
    let horizon = parameters.map_or(obligation.evidence_horizon, |p| {
        obligation.evidence_horizon.max(p.evidence_horizon_blocks())
    });
    let delay = parameters.map_or(obligation.slashing_delay, |p| {
        obligation.slashing_delay.max(p.slashing_delay_blocks())
    });
    retired
        .checked_add(horizon)
        .and_then(|end| end.checked_add(delay))
        .is_none_or(|end| height < end)
}

// Terminal reports still need original custody provenance for restoration and replay fences.
// Pruning the record in the next mandatory phase releases this nonmonetary retention as well.
fn has_retained_evidence(world: &impl WorldReadOnly, obligation: &SumeragiLaneCustody) -> bool {
    world
        .consensus_evidence()
        .iter()
        .any(|(_, record)| record.attribution.instance == obligation.instance)
}

fn has_pending_evidence(world: &impl WorldReadOnly, obligation: &SumeragiLaneCustody) -> bool {
    world.consensus_evidence().iter().any(|(_, record)| {
        record.attribution.instance == obligation.instance && !record.penalty_status.is_terminal()
    })
}

/// Copy the lane DTO while retaining/admitting original immutable signer and sample owners.
/// The borrowed source survives every failure; partial copies refund on abandonment.
/// This accounts for signer and sample backing/control, not the remaining outer lane graph.
pub(crate) fn admit_state(
    source: &SumeragiLaneState,
    budget: &AllocationBudget,
) -> Result<SumeragiLaneState, LaneStateAdmissionError> {
    let mut admitted = source.clone();
    #[cfg(not(all(test, sumeragi_core_mutation = "HC16")))]
    for row in &mut admitted.custody {
        row.signers = row.signers.admit(budget)?;
    }
    #[cfg(all(test, sumeragi_core_mutation = "HC16"))]
    let _ = budget;
    admitted.samples = retain_samples(&source.samples, None, budget)?;
    Ok(admitted)
}

/// Retain or append the original sample owner through the same admission boundary.
/// The test mutation bypasses this one owner boundary for both connected callers.
pub(super) fn retain_samples(
    source: &iroha_data_model::sumeragi_lanes::SumeragiLaneSamples,
    append: Option<(iroha_data_model::sumeragi_lanes::SumeragiLaneSample, usize)>,
    budget: &AllocationBudget,
) -> Result<
    iroha_data_model::sumeragi_lanes::SumeragiLaneSamples,
    iroha_data_model::sumeragi_lanes::LaneSamplesAdmissionError,
> {
    #[cfg(not(all(test, sumeragi_core_mutation = "HC18")))]
    match append {
        Some((sample, keep)) => source.retain_and_append(sample, keep, budget),
        None => source.admit(budget),
    }
    #[cfg(all(test, sumeragi_core_mutation = "HC18"))]
    {
        let _ = budget;
        let mut rows = source.to_vec();
        if let Some((sample, keep)) = append {
            rows.push(sample);
            let excess = rows.len().saturating_sub(keep);
            rows.drain(..excess);
        }
        Ok(rows
            .try_into()
            .expect("mutation retains canonical sample content"))
    }
}

/// Admit both original World generations before replacing either field.
/// Fresh-State construction owns this World exclusively; admission grants no history authority.
pub(crate) fn admit_world_state(
    world: &mut crate::state::World,
    budget: &AllocationBudget,
) -> Result<(), LaneStateAdmissionError> {
    let prepared = {
        let current = world.sumeragi_lanes.view();
        let previous = world.sumeragi_lanes.predecessor_view();
        if current.samples.admitted_to(budget)
            && current
                .custody
                .iter()
                .all(|row| row.signers.admitted_to(budget))
            && previous.as_ref().is_none_or(|value| {
                value.samples.admitted_to(budget)
                    && value
                        .custody
                        .iter()
                        .all(|row| row.signers.admitted_to(budget))
            })
        {
            return Ok(());
        }
        let current = admit_state(&current, budget)?;
        let previous = previous
            .as_ref()
            .map(|value| admit_state(value, budget))
            .transpose()?;
        (current, previous)
    };
    // Existing outer EBR controls are a separate open accounting obligation.
    world.sumeragi_lanes = mv::cell::Cell::from_values_charged(
        prepared.0,
        prepared.1,
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests;
