//! Bounded retirement using original retained liability and exact permanent penalty records.

use super::{liability, store};
use crate::state::{
    StateReadOnly, StateStorageAdmissionError, StateTransaction,
    sccp_forgery_custody::ForgeryStorageError,
};

/// Independent protocol limits for generation records and completed anchor roots.
const MAX_RETIREMENTS: usize = 8;

/// Prune after G2/G7 and before destination clearance. The caller owns rollback on error.
/// No evidence-history scan or absent external-owner assumption is needed: the permanent
/// offence index provides at most 31 exact, funded member probes per retained generation.
pub(super) fn prune(stx: &mut StateTransaction<'_, '_>) -> Result<(), StateStorageAdmissionError> {
    let current = *store::committee_current::get(&*stx.world);
    // A degraded/uninitialized SCCP state grants no retirement authority.
    if current == 0 || !store::committee_generations::contains(&*stx.world, &current) {
        return Ok(());
    }
    let clock = *store::liability_clock::get(&*stx.world);
    let budget = stx.execution_budget();
    let mut generations = [0_u64; MAX_RETIREMENTS];
    let mut count = 0;
    for (id, record) in store::committee_generations::iter(&*stx.world) {
        if *id != record.generation || !record.is_well_formed() {
            return Err(ForgeryStorageError::Invalid.into());
        }
        if *id >= current || record.is_liable(current, clock) {
            continue;
        }
        if liability::generation_has_pending_penalty(&*stx.world, record, &budget)?
            && !cfg!(all(test, sumeragi_core_mutation = "HC292"))
        {
            continue;
        }
        generations[count] = *id;
        count += 1;
        if count == MAX_RETIREMENTS {
            break;
        }
    }
    // Generation numbers can have gaps. The anchor boundary is the minimum retained
    // start height, not a successor assumption or the first remaining generation key.
    let first_height = store::committee_generations::iter(&*stx.world)
        .filter(|(id, _)| !generations[..count].contains(id))
        .map(|(_, record)| record.start_height)
        .min()
        .ok_or(ForgeryStorageError::Invalid)?;
    let mut chunks = [0_u64; MAX_RETIREMENTS];
    let mut chunk_count = 0;
    for (chunk, _) in store::anchor_chunks::iter(&*stx.world) {
        let last_height = chunk
            .checked_add(1)
            .and_then(|n| n.checked_mul(4096))
            .ok_or(ForgeryStorageError::Invalid)?;
        if last_height >= first_height && !cfg!(all(test, sumeragi_core_mutation = "HC293")) {
            break;
        }
        chunks[chunk_count] = *chunk;
        chunk_count += 1;
        if chunk_count == MAX_RETIREMENTS {
            break;
        }
    }
    for id in generations.into_iter().take(count) {
        let removed = store::committee_generations::remove(stx, id);
        stx.require_storage_admission()?;
        if removed.is_none() {
            return Err(ForgeryStorageError::Invalid.into());
        }
    }
    for chunk in chunks.into_iter().take(chunk_count) {
        let removed = store::anchor_chunks::remove(stx, chunk);
        stx.require_storage_admission()?;
        if removed.is_none() {
            return Err(ForgeryStorageError::Invalid.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
