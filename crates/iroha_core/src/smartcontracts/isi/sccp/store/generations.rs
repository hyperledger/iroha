//! One admitted write funnel for immutable native generation records.

use super::*;
use crate::state::sccp_generation_custody::{GenerationAdmissionError, RetainedGeneration};

/// The unchanged canonical key/record invariant.
#[must_use]
pub fn valid_entry(key: &u64, record: &SccpCommitteeGenerationV1) -> bool {
    *key == record.generation && record.is_well_formed()
}
/// Borrow canonical bytes' typed owner without copying its graph.
pub fn get<'a>(
    world: &'a (impl WorldReadOnly + ?Sized),
    key: &u64,
) -> Option<&'a SccpCommitteeGenerationV1> {
    get_retained(world, key).map(|value| &**value)
}
pub(crate) fn get_retained<'a>(
    world: &'a (impl WorldReadOnly + ?Sized),
    key: &u64,
) -> Option<&'a RetainedGeneration> {
    world.sccp_committee_generations().get(key)
}
/// Check membership in the exact current map.
#[must_use]
pub fn contains(world: &(impl WorldReadOnly + ?Sized), key: &u64) -> bool {
    get_retained(world, key).is_some()
}
/// Borrow records in unchanged ascending semantic key order.
pub fn iter<'a>(
    world: &'a (impl WorldReadOnly + ?Sized),
) -> impl DoubleEndedIterator<Item = (&'a u64, &'a SccpCommitteeGenerationV1)> + 'a {
    world
        .sccp_committee_generations()
        .iter()
        .map(|(key, value)| (key, &**value))
}
/// Borrow a bounded semantic key range without materializing records.
pub fn range<'a>(
    world: &'a (impl WorldReadOnly + ?Sized),
    bounds: impl RangeBounds<u64>,
) -> impl DoubleEndedIterator<Item = (&'a u64, &'a SccpCommitteeGenerationV1)> + 'a {
    world
        .sccp_committee_generations()
        .range::<u64>(bounds)
        .map(|(key, value)| (key, &**value))
}
/// Number of retained current records.
#[must_use]
pub fn len(world: &(impl WorldReadOnly + ?Sized)) -> usize {
    world.sccp_committee_generations().len()
}
/// Whether the current map is empty.
#[must_use]
pub fn is_empty(world: &(impl WorldReadOnly + ?Sized)) -> bool {
    len(world) == 0
}

pub(crate) fn insert_owned(
    stx: &mut StateTransaction<'_, '_>,
    key: u64,
    value: RetainedGeneration,
) -> Result<Option<RetainedGeneration>, GenerationAdmissionError> {
    let map = &mut stx.world.sccp_committee_generations;
    if !valid_entry(&key, &value) {
        return Err(GenerationAdmissionError::Invalid);
    }
    if !value.belongs_to(map.allocation_budget()) {
        return Err(mv::storage::AdmittedStorageError::PolicyIdentity.into());
    }
    map.try_insert_admitted(key, value)
        .map_err(|(_original, error)| error.into())
}

fn refused(stx: &mut StateTransaction<'_, '_>, error: GenerationAdmissionError) -> Error {
    if error == GenerationAdmissionError::Invalid {
        return Error::InvariantViolation(
            "SCCP: committee generation breaks its stored invariant".into(),
        );
    }
    stx.arm_local_storage_refusal(error.into());
    Error::InvariantViolation("SCCP: generation source or local storage admission refused".into())
}

/// Copy a caller-owned canonical record into this map's original pool.
/// Local refusal arms the existing transaction deferral, even if a caller catches
/// the instruction-level error. A successful old value retains its own charges.
///
/// # Errors
/// Refuses malformed sources and preserves exact original local admission failures.
pub fn insert(
    stx: &mut StateTransaction<'_, '_>,
    key: u64,
    value: SccpCommitteeGenerationV1,
) -> Result<Option<RetainedGeneration>, Error> {
    if !valid_entry(&key, &value) {
        return Err(refused(stx, GenerationAdmissionError::Invalid));
    }
    let owned = RetainedGeneration::try_copy(
        &value,
        stx.world.sccp_committee_generations.allocation_budget(),
    )
    .map_err(|error| refused(stx, error))?;
    insert_owned(stx, key, owned).map_err(|error| refused(stx, error))
}

/// Remove one original current record; map-copy refusal remains local deferral.
///
/// # Errors
/// Leaves the original maps unchanged if the original finite pool refuses copying.
pub fn remove(
    stx: &mut StateTransaction<'_, '_>,
    key: u64,
) -> Result<Option<RetainedGeneration>, Error> {
    stx.world
        .sccp_committee_generations
        .try_remove_admitted(key)
        .map_err(|(_key, error)| refused(stx, error.into()))
}
