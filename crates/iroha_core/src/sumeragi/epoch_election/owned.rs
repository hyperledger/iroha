//! Original-pool custody of the immutable boundary decision and every nested canonical field.
//!
//! Audited allocation transfers are limited to the constructors below: exact buffer/key backing
//! moves into private canonical fields without growth or export, and the same-pool ledger remains
//! alive until those fields are destroyed. Partial construction destroys payloads before credits;
//! an unwind conservatively retains credits when destruction cannot be established.

use super::BoundaryInputs;
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, ChargedBufferFromChargeError, PrepaidBufferError, RetainedPayload,
};
use iroha_crypto::{PublicKey, PublicKeyAllocationError};
use iroha_data_model::{
    NetworkId,
    nexus::{ValidatorCommitteePreparationV1, ValidatorElectionPolicyV1},
    sumeragi::epoch::{
        ValidatorCommitteeMemberV1, ValidatorEpochBoundaryV1, ValidatorEpochContextV1,
        ValidatorGenerationV1,
    },
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::{bigint::BigIntAdmissionCloneError, numeric::Quantity};
use std::alloc::Layout;

/// A local allocation refusal stays distinct from deterministic invalid boundary inputs.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BoundaryCaptureError {
    /// A complete source or canonical materialization invariant was invalid.
    #[error("invalid native boundary: {0}")]
    Invalid(String),
    /// The original finite pool did not admit all nested storage atomically.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The global allocator refused storage already prepaid by the same original pool.
    #[error("native boundary allocator refused {requested_bytes} prepaid bytes")]
    Allocator {
        /// Exact failed allocation size.
        requested_bytes: usize,
    },
}
impl From<String> for BoundaryCaptureError {
    fn from(error: String) -> Self {
        Self::Invalid(error)
    }
}

impl From<&str> for BoundaryCaptureError {
    fn from(error: &str) -> Self {
        Self::Invalid(error.into())
    }
}
impl From<ChargedBufferError> for BoundaryCaptureError {
    fn from(error: ChargedBufferError) -> Self {
        match error {
            ChargedBufferError::Admission(error) => Self::Admission(error),
            ChargedBufferError::Allocator { requested_bytes } => {
                Self::Allocator { requested_bytes }
            }
        }
    }
}

fn prepaid_error(error: PrepaidBufferError) -> BoundaryCaptureError {
    match error {
        PrepaidBufferError::Allocation(ChargedBufferError::Admission(error)) => error.into(),
        PrepaidBufferError::Allocation(ChargedBufferError::Allocator { requested_bytes }) => {
            BoundaryCaptureError::Allocator { requested_bytes }
        }
        PrepaidBufferError::Reservation(error) => BoundaryCaptureError::Invalid(error.to_string()),
    }
}
fn quantity_error(error: BigIntAdmissionCloneError) -> BoundaryCaptureError {
    match error {
        BigIntAdmissionCloneError::LayoutOverflow => AllocationRefusal::DemandOverflow.into(),
        BigIntAdmissionCloneError::Allocator { requested_bytes } => {
            BoundaryCaptureError::Allocator { requested_bytes }
        }
        BigIntAdmissionCloneError::SourceShapeChanged => {
            BoundaryCaptureError::Invalid(error.to_string())
        }
    }
}

/// Private payload sealed only by the checked prestate constructor below.
struct FrozenPayload {
    inputs: crate::sumeragi::schedule::NativeExecutionInputs,
}

/// Move-only pretransaction boundary capability; no caller can forge a raw Activate decision.
/// It retains all actual model buffers and compact public keys in the original execution pool.
pub(crate) struct FrozenEpochBoundary {
    payload: RetainedPayload<FrozenPayload>,
}
impl FrozenEpochBoundary {
    pub(crate) fn current(&self) -> &ValidatorEpochContextV1 {
        &self.payload.get().inputs.schedule.current
    }
    pub(crate) fn boundary(&self) -> &ValidatorEpochBoundaryV1 {
        self.payload
            .get()
            .inputs
            .schedule
            .boundary
            .as_ref()
            .expect("sealed boundary owns its exact decision")
    }
    /// Borrow the original funded canonical execution fields before publication.
    pub(crate) fn execution_inputs(&self) -> &crate::sumeragi::schedule::NativeExecutionInputs {
        &self.payload.get().inputs
    }
    /// Move the exact canonical fields and ledger into result custody after every fallible
    /// post-state check succeeds. This method allocates nothing and preserves all originals.
    #[allow(
        unsafe_code,
        reason = "audited exact canonical allocation transfer with retained original-pool custody"
    )]
    pub(crate) fn into_execution_inputs(
        self,
        after_next_params: crate::sumeragi::schedule::ChainParamsRecord,
        beacon: Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
    ) -> RetainedPayload<crate::sumeragi::schedule::NativeExecutionInputs> {
        // SAFETY: only fixed-size post-execution parameters/pulse change; every nested
        // allocation moves unchanged from the complete original capture into the result.
        unsafe {
            self.payload.map_payload(|mut payload| {
                match &mut payload.inputs.schedule.after_next {
                    crate::sumeragi::schedule::ScheduledSlot::Ready(config) => {
                        config.params = after_next_params
                    }
                    crate::sumeragi::schedule::ScheduledSlot::PendingBoundary {
                        params, ..
                    } => *params = after_next_params,
                }
                payload.inputs.beacon = beacon;
                payload.inputs
            })
        }
    }
    /// Current, activating and newly selected seats remain obligated throughout this overlay.
    pub(crate) fn retains_peer(&self, peer: &PeerId) -> bool {
        self.current()
            .committee
            .iter()
            .any(|seat| &seat.validator == peer)
            || self
                .boundary()
                .next
                .committee
                .iter()
                .any(|seat| &seat.validator == peer)
            || self
                .boundary()
                .preparation
                .as_ref()
                .is_some_and(|preparation| {
                    preparation
                        .committee
                        .iter()
                        .any(|seat| &seat.validator == peer)
                })
    }
}

#[derive(Default)]
struct Demand {
    bytes: usize,
    charges: usize,
}
impl Demand {
    fn add(&mut self, layout: Layout) -> Result<(), BoundaryCaptureError> {
        self.bytes = self
            .bytes
            .checked_add(layout.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        self.charges = self
            .charges
            .checked_add(1)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(())
    }
    fn array<T>(&mut self, count: usize) -> Result<(), BoundaryCaptureError> {
        self.add(Layout::array::<T>(count).map_err(|_| AllocationRefusal::DemandOverflow)?)
    }
    fn key(&mut self, key: &PublicKey) -> Result<(), BoundaryCaptureError> {
        self.add(key.retained_allocation_layout())
    }
    fn committee<'a>(
        &mut self,
        count: usize,
        members: impl Iterator<Item = (&'a PeerId, &'a [u8])>,
    ) -> Result<(), BoundaryCaptureError> {
        self.array::<ValidatorCommitteeMemberV1>(count)?;
        for (peer, proof) in members {
            self.key(peer.public_key())?;
            self.array::<u8>(proof.len())?;
        }
        Ok(())
    }
    fn generation(
        &mut self,
        committee: &[ValidatorCommitteeMemberV1],
    ) -> Result<(), BoundaryCaptureError> {
        self.array::<PeerId>(committee.len())?;
        for member in committee {
            self.key(member.validator.public_key())?;
        }
        Ok(())
    }
    fn context(&mut self, context: &ValidatorEpochContextV1) -> Result<(), BoundaryCaptureError> {
        self.committee(
            context.committee.len(),
            context
                .committee
                .iter()
                .map(|member| (&member.validator, member.proof_of_possession.as_slice())),
        )
    }
    fn quantity(&mut self, value: &Quantity) -> Result<(), BoundaryCaptureError> {
        self.add(
            value
                .admission_clone_layout()
                .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?,
        )
    }
}

/// Guard the partially constructed canonical fields across every early return and unwind.
/// It is declared before those fields, so Rust destroys their allocations first. An unwind
/// conservatively retains all credits rather than reporting unproven reclamation as available.
struct Construction<'a> {
    budget: &'a AllocationBudget,
    reservation: AllocationReservation,
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Construction<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Destruction of a partially built field may be incomplete during unwind.
            if let Some(charges) = self.charges.take() {
                std::mem::forget(charges);
            }
        }
        // On normal refusal, later-declared payload locals have already dropped; Option
        // destroys the original ledger. A successful finish takes it without leaking the
        // now-empty reservation or its budget handle.
    }
}
impl<'a> Construction<'a> {
    fn new(demand: Demand, budget: &'a AllocationBudget) -> Result<Self, BoundaryCaptureError> {
        Self::new_with_extra(demand, budget, 0)
    }
    fn new_with_extra(
        mut demand: Demand,
        budget: &'a AllocationBudget,
        extra_bytes: usize,
    ) -> Result<Self, BoundaryCaptureError> {
        demand.bytes = demand
            .bytes
            .checked_add(extra_bytes)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let ledger = Layout::array::<AllocationCharge>(demand.charges)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        demand.bytes = demand
            .bytes
            .checked_add(ledger.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_bytes(demand.bytes)?;
        let charges = ChargedBuffer::from_reservation(demand.charges, &mut reservation)
            .map_err(prepaid_error)?;
        Ok(Self {
            budget,
            reservation,
            charges: Some(charges),
        })
    }
    fn retain(&mut self, charge: AllocationCharge) -> Result<(), BoundaryCaptureError> {
        if let Err(charge) = self
            .charges
            .as_mut()
            .expect("construction owns its ledger")
            .try_push(charge)
        {
            // Refusing a planner mismatch must never refund a payload which still exists.
            std::mem::forget(charge);
            return Err(BoundaryCaptureError::Invalid(
                "boundary charge ledger capacity changed".into(),
            ));
        }
        Ok(())
    }
    #[allow(
        unsafe_code,
        reason = "audited exact canonical allocation transfer with retained original-pool custody"
    )]
    fn key(&mut self, key: &PublicKey) -> Result<PublicKey, BoundaryCaptureError> {
        let charge = self
            .reservation
            .try_split(key.retained_allocation_layout())
            .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
        let owned = match key.try_clone_from_charge(self.budget, charge) {
            Ok(owned) => owned,
            Err((charge, error)) => {
                drop(charge);
                return Err(match error {
                    PublicKeyAllocationError::Allocation(
                        ChargedBufferFromChargeError::Allocator { layout },
                    ) => BoundaryCaptureError::Allocator {
                        requested_bytes: layout.size(),
                    },
                    PublicKeyAllocationError::Allocation(
                        ChargedBufferFromChargeError::DemandOverflow,
                    ) => AllocationRefusal::DemandOverflow.into(),
                    other => BoundaryCaptureError::Invalid(other.to_string()),
                });
            }
        };
        // SAFETY: this exact compact key moves directly into a known model field, never grows,
        // and its charge enters the private ledger retained past destruction of that field.
        let (key, charge) = unsafe { owned.into_allocation_parts() };
        self.retain(charge)?;
        Ok(key)
    }
    #[allow(
        unsafe_code,
        reason = "audited exact canonical allocation transfer with retained original-pool custody"
    )]
    fn vector<T>(&mut self, buffer: ChargedBuffer<T>) -> Result<Vec<T>, BoundaryCaptureError> {
        // SAFETY: callers move this exact backing into the declared immutable model Vec field;
        // no replacement, growth or detached clone occurs before the final payload drops.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        self.retain(charge)?;
        Ok(values)
    }
    fn buffer<T>(&mut self, count: usize) -> Result<ChargedBuffer<T>, BoundaryCaptureError> {
        ChargedBuffer::from_reservation(count, &mut self.reservation).map_err(prepaid_error)
    }
    fn quantity(&mut self, value: &Quantity) -> Result<Quantity, BoundaryCaptureError> {
        let layout = value
            .admission_clone_layout()
            .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
        let charge = self
            .reservation
            .try_split(layout)
            .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
        self.retain(charge)?;
        value.try_clone_for_admission().map_err(quantity_error)
    }
    fn committee<'s>(
        &mut self,
        count: usize,
        members: impl Iterator<Item = (&'s PeerId, &'s [u8])>,
    ) -> Result<Vec<ValidatorCommitteeMemberV1>, BoundaryCaptureError> {
        let mut output = self.buffer(count)?;
        for (peer, proof) in members {
            let validator = PeerId::new(self.key(peer.public_key())?);
            let mut bytes = self.buffer(proof.len())?;
            bytes
                .append(proof)
                .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
            let proof_of_possession = self.vector(bytes)?;
            output
                .try_push(ValidatorCommitteeMemberV1 {
                    validator,
                    proof_of_possession,
                })
                .map_err(|_| {
                    BoundaryCaptureError::Invalid("boundary member count changed".into())
                })?;
        }
        self.vector(output)
    }
    fn generation(
        &mut self,
        network_id: NetworkId,
        generation: u64,
        committee: &[ValidatorCommitteeMemberV1],
    ) -> Result<ValidatorGenerationV1, BoundaryCaptureError> {
        let mut validators = self.buffer(committee.len())?;
        for member in committee {
            let validator = PeerId::new(self.key(member.validator.public_key())?);
            validators.try_push(validator).map_err(|_| {
                BoundaryCaptureError::Invalid("boundary generation count changed".into())
            })?;
        }
        Ok(ValidatorGenerationV1 {
            network_id,
            generation,
            validators: self.vector(validators)?,
        })
    }
    fn context(
        &mut self,
        source: &ValidatorEpochContextV1,
    ) -> Result<ValidatorEpochContextV1, BoundaryCaptureError> {
        Ok(ValidatorEpochContextV1 {
            da_layout: source.da_layout,
            version: source.version,
            network_id: source.network_id,
            mode: source.mode,
            authorization: source.authorization,
            committee: self.committee(
                source.committee.len(),
                source
                    .committee
                    .iter()
                    .map(|member| (&member.validator, member.proof_of_possession.as_slice())),
            )?,
            leader_seed: source.leader_seed,
        })
    }
    fn policy(
        &mut self,
        source: &ValidatorElectionPolicyV1,
    ) -> Result<ValidatorElectionPolicyV1, BoundaryCaptureError> {
        Ok(ValidatorElectionPolicyV1 {
            xor_asset_definition_id: source.xor_asset_definition_id.clone(),
            asset_scope: source.asset_scope,
            asset_scale: source.asset_scale,
            min_self_bond: self.quantity(&source.min_self_bond)?,
            min_nomination_bond: self.quantity(&source.min_nomination_bond)?,
            max_validators: source.max_validators,
            epoch_length_blocks: source.epoch_length_blocks,
        })
    }
}

/// Derive the canonical commitment of the exact borrowed target roster in its original pool.
/// The temporary model graph is destroyed before its construction ledger releases; only the
/// fixed-width identity escapes. No separate generation graph enters the frozen boundary.
pub(super) fn generation_id(
    network_id: NetworkId,
    generation: u64,
    committee: &[ValidatorCommitteeMemberV1],
    budget: &AllocationBudget,
) -> Result<[u8; 32], BoundaryCaptureError> {
    let mut demand = Demand::default();
    demand.generation(committee)?;
    // Declare this before the canonical value so its fields drop before their credits.
    let mut owner = Construction::new(demand, budget)?;
    let original = owner.generation(network_id, generation, committee)?;
    let charges = owner.charges.as_ref().expect("original ledger");
    if owner.reservation.remaining_bytes() != 0 || charges.as_slice().len() != charges.capacity() {
        return Err("boundary generation allocation demand changed".into());
    }
    original
        .generation_id()
        .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))
}

/// Materialize one already checked decision with original-pool custody for every retained byte.
/// This constructor is private to the native election module and admits all demand before
/// constructing any retained model value. It never consumes a caller-forged raw boundary.
#[allow(
    unsafe_code,
    reason = "audited exact canonical allocation transfer with retained original-pool custody"
)]
pub(super) fn materialize(
    inputs: &BoundaryInputs<'_>,
    budget: &AllocationBudget,
) -> Result<FrozenEpochBoundary, BoundaryCaptureError> {
    let mut demand = Demand::default();
    demand.context(inputs.current)?;
    demand.committee(
        inputs.committee.len(),
        inputs
            .committee
            .iter()
            .map(|member| (&member.validator, member.proof_of_possession.as_slice())),
    )?;
    for _ in 0..2 {
        demand.committee(
            inputs.committee.len(),
            inputs
                .committee
                .iter()
                .map(|member| (&member.validator, member.proof_of_possession.as_slice())),
        )?;
    }
    let future_count = inputs.future.seats().len();
    if future_count > 0 {
        demand.committee(
            future_count,
            inputs
                .future
                .seats()
                .map(|seat| (&seat.record.peer_id, seat.proof)),
        )?;
        demand.quantity(&inputs.policy.min_self_bond)?;
        demand.quantity(&inputs.policy.min_nomination_bond)?;
    }
    let mut owner = Construction::new(demand, budget)?;
    let current = owner.context(inputs.current)?;
    let next = ValidatorEpochContextV1 {
        da_layout: current.da_layout,
        version: 1,
        network_id: current.network_id,
        mode: current.mode,
        authorization: inputs.authorization,
        committee: owner.committee(
            inputs.committee.len(),
            inputs
                .committee
                .iter()
                .map(|member| (&member.validator, member.proof_of_possession.as_slice())),
        )?,
        leader_seed: inputs.entropy.leader_seed,
    };
    let preparation = if future_count == 0 {
        None
    } else {
        Some(ValidatorCommitteePreparationV1 {
            version: 1,
            network_id: current.network_id,
            selection_epoch: current.authorization.epoch,
            selection_height: current.authorization.last_height,
            selection_anchor: inputs.selection_anchor,
            target_epoch: next
                .authorization
                .epoch
                .checked_add(1)
                .ok_or_else(|| BoundaryCaptureError::Invalid("target epoch overflows".into()))?,
            first_height: inputs.future_first,
            last_height: inputs.future_last,
            authority_generation: next
                .authorization
                .authority_generation
                .checked_add(1)
                .ok_or_else(|| BoundaryCaptureError::Invalid("next generation overflows".into()))?,
            preparing_authorization_id: next
                .authorization
                .authorization_id()
                .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?,
            election_seed: inputs.entropy.election_seed,
            eligibility: owner.policy(inputs.policy)?,
            committee: owner.committee(
                future_count,
                inputs
                    .future
                    .seats()
                    .map(|seat| (&seat.record.peer_id, seat.proof)),
            )?,
        })
    };
    let boundary = ValidatorEpochBoundaryV1 {
        version: 1,
        height: current.authorization.last_height,
        predecessor_context_id: current.context_id()?,
        selection_anchor: inputs.selection_anchor,
        next,
        preparation,
    };
    boundary.validate_against(&current)?;
    let next = crate::sumeragi::schedule::ScheduledSlot::Ready(
        crate::sumeragi::schedule::ScheduledConfig {
            height: boundary
                .height
                .checked_add(1)
                .ok_or(AllocationRefusal::DemandOverflow)?,
            epoch: owner.context(&boundary.next)?,
            params: inputs.next_params,
        },
    );
    let after_next = crate::sumeragi::schedule::ScheduledSlot::Ready(
        crate::sumeragi::schedule::ScheduledConfig {
            height: boundary
                .height
                .checked_add(2)
                .ok_or(AllocationRefusal::DemandOverflow)?,
            epoch: owner.context(&boundary.next)?,
            params: inputs.after_next_params,
        },
    );
    let schedule = crate::sumeragi::schedule::ScheduleOutcome {
        height: boundary.height,
        current,
        boundary: Some(boundary),
        next,
        after_next,
    };
    schedule
        .validate()
        .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
    let payload = FrozenPayload {
        inputs: crate::sumeragi::schedule::NativeExecutionInputs {
            schedule,
            beacon: None,
        },
    };
    if owner.reservation.remaining_bytes() != 0 {
        return Err(BoundaryCaptureError::Invalid(
            "boundary allocation demand did not match materialization".into(),
        ));
    }
    // SAFETY: every known nested model allocation was moved unchanged from its exact charged
    // buffer/key owner; quantities used exact admission clones. Payload destruction precedes
    // charge release, including conservative credit retention during an unwinding destructor.
    let charges = owner
        .charges
        .take()
        .expect("construction owns its complete ledger");
    if charges.as_slice().len() != charges.capacity() {
        // Source planner mismatches must not refund any possibly live payload allocation.
        std::mem::forget(charges);
        return Err(BoundaryCaptureError::Invalid(
            "boundary charge count changed".into(),
        ));
    }
    let budget = owner.budget;
    drop(owner);
    let payload = match unsafe { RetainedPayload::try_new(payload, charges, budget) } {
        Ok(payload) => payload,
        Err((payload, charges, error)) => {
            std::mem::forget(charges);
            drop(payload);
            return Err(BoundaryCaptureError::Invalid(error.to_string()));
        }
    };
    Ok(FrozenEpochBoundary { payload })
}

#[derive(Clone, Copy)]
enum SlotSource<'a> {
    Ready {
        height: u64,
        epoch: &'a ValidatorEpochContextV1,
        params: crate::sumeragi::schedule::ChainParamsRecord,
    },
    Pending {
        height: u64,
        boundary_height: u64,
        predecessor_context_id: [u8; 32],
        params: crate::sumeragi::schedule::ChainParamsRecord,
    },
}
impl<'a> SlotSource<'a> {
    fn from_slot(slot: &'a crate::sumeragi::schedule::ScheduledSlot) -> Self {
        use crate::sumeragi::schedule::ScheduledSlot;
        match slot {
            ScheduledSlot::Ready(config) => Self::Ready {
                height: config.height,
                epoch: &config.epoch,
                params: config.params,
            },
            ScheduledSlot::PendingBoundary {
                height,
                boundary_height,
                predecessor_context_id,
                params,
            } => Self::Pending {
                height: *height,
                boundary_height: *boundary_height,
                predecessor_context_id: *predecessor_context_id,
                params: *params,
            },
        }
    }
    fn with_params(self, next: crate::sumeragi::schedule::ChainParamsRecord) -> Self {
        match self {
            Self::Ready { height, epoch, .. } => Self::Ready {
                height,
                epoch,
                params: next,
            },
            Self::Pending {
                height,
                boundary_height,
                predecessor_context_id,
                ..
            } => Self::Pending {
                height,
                boundary_height,
                predecessor_context_id,
                params: next,
            },
        }
    }
}

/// Build a separate immutable World graph with original-pool deep allocation custody.
/// Sharing this completed owner never clones its model vectors or compact public keys.
pub(crate) fn retain_schedule(
    source: &crate::sumeragi::schedule::ConsensusSchedule,
    budget: &AllocationBudget,
) -> Result<crate::sumeragi::schedule::RetainedConsensusSchedule, BoundaryCaptureError> {
    if !source.is_well_formed() {
        return Err("cannot retain malformed native schedule".into());
    }
    if source.entries().is_empty() {
        return Ok(crate::sumeragi::schedule::RetainedConsensusSchedule::default());
    }
    let entries = source.entries();
    retain_slots(
        &[
            SlotSource::from_slot(&entries[0]),
            SlotSource::from_slot(&entries[1]),
            SlotSource::from_slot(&entries[2]),
        ],
        budget,
    )
}

/// Prepare the separately owned World copy without first making an uncharged canonical clone.
/// All source contexts stay borrowed from the original capture across local refusal.
pub(crate) fn retain_outcome_schedule(
    source: &crate::sumeragi::schedule::ScheduleOutcome,
    current_params: crate::sumeragi::schedule::ChainParamsRecord,
    after_params: crate::sumeragi::schedule::ChainParamsRecord,
    budget: &AllocationBudget,
) -> Result<crate::sumeragi::schedule::RetainedConsensusSchedule, BoundaryCaptureError> {
    source
        .validate()
        .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
    let next = SlotSource::from_slot(&source.next);
    let next = if source.height == 1 {
        next.with_params(after_params)
    } else {
        next
    };
    retain_slots(
        &[
            SlotSource::Ready {
                height: source.height,
                epoch: &source.current,
                params: current_params,
            },
            next,
            SlotSource::from_slot(&source.after_next).with_params(after_params),
        ],
        budget,
    )
}
#[allow(
    unsafe_code,
    reason = "audited exact canonical allocation transfer with retained original-pool custody"
)]
fn retain_slots(
    slots: &[SlotSource<'_>; 3],
    budget: &AllocationBudget,
) -> Result<crate::sumeragi::schedule::RetainedConsensusSchedule, BoundaryCaptureError> {
    use crate::sumeragi::schedule::{
        ConsensusSchedule, RetainedConsensusSchedule, ScheduledConfig, ScheduledSlot,
    };
    let mut demand = Demand::default();
    demand.array::<ScheduledSlot>(slots.len())?;
    for slot in slots {
        if let SlotSource::Ready { epoch, .. } = slot {
            demand.context(epoch)?;
        }
    }
    let shell = RetainedConsensusSchedule::shared_layout();
    let mut owner = Construction::new_with_extra(demand, budget, shell.size())?;
    let mut entries = owner.buffer(slots.len())?;
    for slot in slots {
        let retained = match *slot {
            SlotSource::Ready {
                height,
                epoch,
                params,
            } => ScheduledSlot::Ready(ScheduledConfig {
                height,
                epoch: owner.context(epoch)?,
                params,
            }),
            SlotSource::Pending {
                height,
                boundary_height,
                predecessor_context_id,
                params,
            } => ScheduledSlot::PendingBoundary {
                height,
                boundary_height,
                predecessor_context_id,
                params,
            },
        };
        entries.try_push(retained).map_err(|_| {
            BoundaryCaptureError::Invalid("retained schedule slot count changed".into())
        })?;
    }
    let entries = owner.vector(entries)?;
    let canonical = ConsensusSchedule::from_owned_entries(entries)
        .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
    if owner.reservation.remaining_bytes() != shell.size() {
        return Err("schedule allocation planner differs from materialized graph".into());
    }
    let charges = owner
        .charges
        .take()
        .expect("canonical constructor owns ledger");
    if charges.as_slice().len() != charges.capacity() {
        std::mem::forget(charges);
        return Err("schedule charge count changed".into());
    }
    // SAFETY: all exact canonical slots/contexts/keys were moved from the original admitted
    // allocations above. The payload keeps exclusive ownership until its ledger releases.
    let retained = match unsafe { RetainedPayload::try_new(canonical, charges, budget) } {
        Ok(value) => value,
        Err((value, charges, error)) => {
            std::mem::forget(charges);
            drop(value);
            return Err(error.to_string().into());
        }
    };
    match RetainedConsensusSchedule::from_retained(retained, &mut owner.reservation) {
        Ok(result) => Ok(result),
        Err((original, iroha_allocation::PrepaidSharedError::Allocator { requested_bytes })) => {
            drop(original);
            Err(BoundaryCaptureError::Allocator { requested_bytes })
        }
        Err((original, error)) => {
            drop(original);
            Err(error.to_string().into())
        }
    }
}

/// Capture an ordinary/genesis execution's exact authority fields before transactions.
/// Genesis passes no already-scheduled next slot; its actual executed parameters replace
/// both fixed-size successor parameter records before sealing.
#[allow(
    unsafe_code,
    reason = "audited exact canonical allocation transfer with retained original-pool custody"
)]
pub(crate) fn capture_continuation(
    current: &ValidatorEpochContextV1,
    height: u64,
    next: Option<&crate::sumeragi::schedule::ScheduledSlot>,
    params: crate::sumeragi::schedule::ChainParamsRecord,
    budget: &AllocationBudget,
) -> Result<RetainedPayload<crate::sumeragi::schedule::NativeExecutionInputs>, BoundaryCaptureError>
{
    use crate::sumeragi::schedule::{
        NativeExecutionInputs, ScheduleOutcome, ScheduledConfig, ScheduledSlot,
    };
    current.validate()?;
    params
        .validate()
        .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
    if height < current.authorization.first_height
        || height > current.authorization.last_height
        || (current.mode == iroha_data_model::parameter::system::ConsensusMode::Npos
            && height == current.authorization.last_height)
        || (next.is_none() && height != 1)
    {
        return Err("ordinary capture cannot invent boundary or genesis authority".into());
    }
    let next_height = height.checked_add(1).ok_or("next height overflows")?;
    let after_height = height.checked_add(2).ok_or("after-next height overflows")?;
    if let Some(next) = next {
        if next.height() != next_height {
            return Err("retained next slot height differs".into());
        }
        next.to_core(current)
            .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
    }
    let mut demand = Demand::default();
    demand.context(current)?;
    if next.is_none_or(|slot| matches!(slot, ScheduledSlot::Ready(_))) {
        demand.context(current)?;
    }
    if after_height <= current.authorization.last_height {
        demand.context(current)?;
    }
    let mut owner = Construction::new(demand, budget)?;
    let retained_current = owner.context(current)?;
    let next = match next {
        Some(ScheduledSlot::PendingBoundary {
            height,
            boundary_height,
            predecessor_context_id,
            params,
        }) => ScheduledSlot::PendingBoundary {
            height: *height,
            boundary_height: *boundary_height,
            predecessor_context_id: *predecessor_context_id,
            params: *params,
        },
        other => ScheduledSlot::Ready(ScheduledConfig {
            height: next_height,
            epoch: owner.context(current)?,
            params: other.map_or(params, |slot| *slot.params()),
        }),
    };
    let after_next = if after_height <= current.authorization.last_height {
        ScheduledSlot::Ready(ScheduledConfig {
            height: after_height,
            epoch: owner.context(current)?,
            params,
        })
    } else {
        ScheduledSlot::PendingBoundary {
            height: after_height,
            boundary_height: current.authorization.last_height,
            predecessor_context_id: current.context_id()?,
            params,
        }
    };
    let schedule = ScheduleOutcome {
        height,
        current: retained_current,
        boundary: None,
        next,
        after_next,
    };
    schedule
        .validate()
        .map_err(|error| BoundaryCaptureError::Invalid(error.to_string()))?;
    let inputs = NativeExecutionInputs {
        schedule,
        beacon: None,
    };
    if owner.reservation.remaining_bytes() != 0 {
        return Err("ordinary capture allocation demand changed".into());
    }
    let charges = owner
        .charges
        .take()
        .expect("canonical constructor owns ledger");
    if charges.as_slice().len() != charges.capacity() {
        std::mem::forget(charges);
        return Err("ordinary capture charge count changed".into());
    }
    // SAFETY: every exact canonical field was materialized above from the unchanged original
    // prepaid buffers/keys, and the ledger stays with those fields until final destruction.
    match unsafe { RetainedPayload::try_new(inputs, charges, budget) } {
        Ok(value) => Ok(value),
        Err((value, charges, error)) => {
            std::mem::forget(charges);
            drop(value);
            Err(error.to_string().into())
        }
    }
}
