//! Bounded SCCP light-client pruning while native forgery-record retention is integrated.
//!
//! Permanent message, commitment and history stores are never pruned. Committee generations
//! and anchor roots remain retained until pruning can inspect typed pending forgery records;
//! a missing shared-model migration must not make slashable evidence disappear.

use super::light_clients;
use crate::state::StateTransaction;

/// Maximum light-client checkpoint deletions per block.
pub const MAX_PRUNE_DELETIONS_PER_BLOCK: usize = 1_024;

/// Prune expired light-client checkpoints within the caller's deletion allowance.
///
/// TODO: complete §4.11's eight-generation/eight-anchor-root pruning after the shared
/// `RecordedEvidenceV1::SccpForgery` record exists, including the Pending-record exclusion.
/// Until then generations and anchor roots are deliberately retained, never guessed safe.
pub fn prune(stx: &mut StateTransaction<'_, '_>, budget: usize) -> usize {
    light_clients::prune(stx, budget.min(MAX_PRUNE_DELETIONS_PER_BLOCK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::{
        store,
        test_support::{blank_state, header, sample_generation},
    };

    #[test]
    fn pruning_without_pending_forgery_classification_retains_native_evidence() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        store::committee_generations::insert(&mut stx, 1, sample_generation(1, 1)).unwrap();
        store::anchor_chunks::insert(&mut stx, 0, [0; 32]).unwrap();
        assert_eq!(prune(&mut stx, usize::MAX), 0);
        assert!(store::committee_generations::contains(&*stx.world, &1));
        assert_eq!(store::anchor_chunks::get(&*stx.world, &0), Some(&[0; 32]));
    }
}
