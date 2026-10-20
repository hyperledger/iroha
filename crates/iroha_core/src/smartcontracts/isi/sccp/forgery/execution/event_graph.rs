//! Original event vector, offender accounts and immutable publication-shell custody.

use std::alloc::Layout;

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedShared,
    RetainedPayload,
};
use iroha_data_model::{
    events::{SharedDataEvent, data::DataEvent},
    sccp::{
        events::{
            SccpEvent, SccpForgeryEvidenceRecordedV1, SccpForgeryOffenderUnslashableV1,
            SccpRevisionForgeryHeldV1,
        },
        native::{SccpForgeryOffenderV1, SccpForgeryRecordV1},
    },
};

use super::store;
use crate::state::{EvidencePreparationError as Error, WorldReadOnly};

type Graph = RetainedPayload<Vec<DataEvent>>;

/// Closed immutable batch: every published handle retains all of its original allocations.
pub(super) struct FundedForgeryEvents {
    graph: ChargedShared<Graph>,
    budget: AllocationBudget,
}
impl FundedForgeryEvents {
    pub(super) fn iter(&self) -> impl ExactSizeIterator<Item = SharedDataEvent> + '_ {
        (0..self.graph.get().len()).map(|index| {
            SharedDataEvent::from_funded_batch(&self.graph, index, &self.budget)
                .expect("closed original event graph and index")
        })
    }
    #[cfg(test)]
    pub(super) fn as_slice(&self) -> &[DataEvent] {
        self.graph.get()
    }
    #[cfg(test)]
    pub(super) fn allocation_bytes(&self) -> usize {
        self.graph.allocation_bytes().expect("exact event ledger")
            + ChargedShared::<Graph>::allocation_layout().size()
    }
}
fn overflow() -> Error {
    Error::Admission(AllocationRefusal::DemandOverflow)
}
fn prepaid(error: iroha_allocation::PrepaidBufferError) -> Error {
    match error {
        iroha_allocation::PrepaidBufferError::Reservation(_) => Error::Invariant,
        iroha_allocation::PrepaidBufferError::Allocation(error) => error.into(),
    }
}
fn shared(error: iroha_allocation::PrepaidSharedError) -> Error {
    match error {
        iroha_allocation::PrepaidSharedError::Reservation(_) => Error::Invariant,
        iroha_allocation::PrepaidSharedError::Allocator { requested_bytes } => {
            Error::Allocator { requested_bytes }
        }
    }
}
fn decode<T>(f: impl FnOnce() -> Result<T, norito::Error>) -> Result<T, Error> {
    norito::core::classify_decode_attempt(f).map_err(Error::from_decode_attempt)
}

/// Plan and prepay the complete graph before copying any source account or allocating backing.
#[allow(unsafe_code)]
pub(super) fn prepare_events(
    world: &impl WorldReadOnly,
    evidence_id: [u8; 32],
    height: u64,
    record: &SccpForgeryRecordV1,
    unslashable: u32,
    original_budget: &AllocationBudget,
) -> Result<FundedForgeryEvents, Error> {
    #[cfg(all(test, sumeragi_core_mutation = "HC905"))]
    let replacement = AllocationBudget::new(original_budget.limit_bytes());
    #[cfg(all(test, sumeragi_core_mutation = "HC905"))]
    let budget = &replacement;
    #[cfg(not(all(test, sumeragi_core_mutation = "HC905")))]
    let budget = original_budget;

    if record.offenders.len() > 31 || unslashable & (1 << 31) != 0 {
        return Err(Error::Invariant);
    }
    let previous = store::forgery_max_generation(world);
    let maximum = Some(previous.map_or(record.generation, |g| g.max(record.generation)));
    let held = |revision: &iroha_data_model::sccp::registry::SccpRouteRevisionV1| {
        !revision.forgery_held(previous) && revision.forgery_held(maximum)
    };
    let mut count = usize::try_from(unslashable.count_ones()).map_err(|_| overflow())? + 1;
    for (_, route) in store::routes::iter(world) {
        for revision in route.revisions.values() {
            if held(revision) {
                count = count.checked_add(1).ok_or_else(overflow)?;
            }
        }
    }
    let mut bytes = Layout::array::<DataEvent>(count)
        .map_err(|_| overflow())?
        .size()
        .checked_add(
            Layout::array::<SccpForgeryOffenderV1>(record.offenders.len())
                .map_err(|_| overflow())?
                .size(),
        )
        .ok_or_else(overflow)?;
    let (mut entries, mut overflowed) = (2usize, false);
    for offender in &record.offenders {
        decode(|| {
            offender
                .validator
                .for_each_admission_clone_layout(|layout| {
                    match (entries.checked_add(1), bytes.checked_add(layout.size())) {
                        (Some(n), Some(b)) => {
                            entries = n;
                            bytes = b;
                        }
                        _ => overflowed = true,
                    }
                })
        })?;
    }
    if overflowed {
        return Err(overflow());
    }
    bytes = bytes
        .checked_add(
            Layout::array::<AllocationCharge>(entries)
                .map_err(|_| overflow())?
                .size(),
        )
        .and_then(|b| b.checked_add(ChargedShared::<Graph>::allocation_layout().size()))
        .ok_or_else(overflow)?;
    let mut reservation = budget.try_reserve_bytes(bytes).map_err(Error::Admission)?;
    // The ledger is declared before every partial graph: values always die first.
    let mut ledger = ChargedBuffer::from_reservation(entries, &mut reservation).map_err(prepaid)?;
    #[cfg(test)]
    construction_checkpoint(0);
    let shell = ChargedShared::<Graph>::reserve_from(&mut reservation).map_err(shared)?;
    #[cfg(test)]
    construction_checkpoint(1);
    let mut events = ChargedBuffer::from_reservation(count, &mut reservation).map_err(prepaid)?;
    #[cfg(test)]
    construction_checkpoint(2);
    let mut offenders = ChargedBuffer::from_reservation(record.offenders.len(), &mut reservation)
        .map_err(prepaid)?;
    #[cfg(test)]
    construction_checkpoint(3);
    for offender in &record.offenders {
        let mut mismatch = false;
        decode(|| {
            offender
                .validator
                .for_each_admission_clone_layout(|layout| match reservation.try_split(layout) {
                    Ok(charge) => ledger.push_reserved(charge),
                    Err(_) => mismatch = true,
                })
        })?;
        if mismatch {
            return Err(Error::Invariant);
        }
        let validator = decode(|| offender.validator.try_clone_for_admission())?;
        offenders.push_reserved(SccpForgeryOffenderV1 {
            signer: offender.signer,
            lane_id: offender.lane_id,
            validator,
            activation_height: offender.activation_height,
        });
        #[cfg(test)]
        construction_checkpoint(4);
    }
    for signer in 0..31_u32 {
        if unslashable & (1 << signer) != 0 {
            events.push_reserved(DataEvent::Sccp(SccpEvent::ForgeryOffenderUnslashable(
                SccpForgeryOffenderUnslashableV1 {
                    generation: record.generation,
                    signer,
                },
            )));
        }
    }
    // SAFETY: exact vector backing and all copied account charges enter the same
    // immutable graph. No fallible operation or mutation can separate these owners.
    let (offenders, charge) = unsafe { offenders.into_allocation_parts() };
    ledger.push_reserved(charge);
    events.push_reserved(DataEvent::Sccp(SccpEvent::ForgeryEvidenceRecorded(
        SccpForgeryEvidenceRecordedV1 {
            evidence_id,
            generation: record.generation,
            height,
            rule: record.rule,
            offenders,
        },
    )));
    for (network, route) in store::routes::iter(world) {
        for (revision, value) in &route.revisions {
            if held(value) {
                events.push_reserved(DataEvent::Sccp(SccpEvent::RevisionForgeryHeld(
                    SccpRevisionForgeryHeldV1 {
                        network: *network,
                        revision: *revision,
                        forgery_floor: value.forgery_floor,
                        generation: previous
                            .map_or(record.generation, |g| g.max(record.generation)),
                    },
                )));
            }
        }
    }
    // SAFETY: moves preserve every exact vector/account allocation and its ledger.
    let (events, charge) = unsafe { events.into_allocation_parts() };
    ledger.push_reserved(charge);
    let graph = unsafe { RetainedPayload::try_new(events, ledger, budget) }.map_err(
        |(events, ledger, _)| {
            drop(events);
            drop(ledger);
            Error::Invariant
        },
    )?;
    #[cfg(test)]
    construction_checkpoint(5);
    Ok(FundedForgeryEvents {
        graph: shell.initialize(graph),
        budget: budget.clone(),
    })
}

#[cfg(test)]
thread_local! {
    static UNWIND_AT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn construction_checkpoint(point: usize) {
    if UNWIND_AT.with(|selected| selected.get() == Some(point)) {
        UNWIND_AT.with(|selected| selected.set(None));
        panic!("controlled event graph construction unwind at {point}");
    }
}

#[cfg(test)]
mod tests;
