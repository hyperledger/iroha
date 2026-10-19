//! Exact proof-status relation over the original frozen State execution owner.
//!
//! Both images use the same bounded relation as committed capture. Stored map
//! keys and status membership are checked; proof contents, verifier admission,
//! proof tags and historical finality remain with their separate owners.
//! TODO: consume this scoped encoder with every canonical table/cell, original
//! relation and authenticated history in StatePublication. Original predecessor
//! publication checks, complete scratch admission and durable node custody remain
//! required before any complete State root or finalized anchor is exposed.

use super::{CanonicalTableLeafSet, CanonicalTablePairedSnapshot, LeafError, LeafLimits};
use crate::state::{
    StateBlock, authority_registry::grouped_ownership::validate_original_proofs,
    block_field::AggregatePublication,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::proof::{ProofId, ProofRecord, ProofStatus};
use mv::storage::FrozenStorageImages;

struct Original<'frozen> {
    rows: FrozenStorageImages<'frozen, ProofId, ProofRecord>,
    index: FrozenStorageImages<'frozen, (ProofStatus, ProofId), ()>,
    budget: &'frozen AllocationBudget,
}

impl<'frozen> Original<'frozen> {
    fn retain(block: &'frozen StateBlock<'_>) -> Option<Self> {
        let fields = block.fields.as_ref()?;
        if fields.world.publication != AggregatePublication::Frozen {
            return None;
        }
        let rows = fields.world.proofs.frozen_images()?;
        let index = fields.world.proofs_by_status.frozen_images()?;
        let rows_owned = rows.belongs_to(&fields.state_ref.world.proofs);
        let index_owned = index.belongs_to(&fields.state_ref.world.proofs_by_status);
        if !rows_owned || !index_owned || rows.mode() != index.mode() {
            return None;
        }
        Some(Self {
            rows,
            index,
            budget: &fields.state_ref.ivm_execution_budget,
        })
    }
}

/// Encode the same original proof rows whose complete status inverse was checked.
///
/// `None` refuses incomplete, foreign, differently acquired or released original
/// sources without opening a State view or consulting a replacement pool. Both
/// original borrows survive validation and encoding. Work, row, byte and pool
/// refusals are local operational results; the original StateBlock remains intact
/// for retry. No State root, currentness or finality authority follows from success.
pub(in crate::state) fn capture(
    block: &StateBlock<'_>,
    limits: LeafLimits,
    max_work: u64,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let Some(original) = Original::retain(block) else {
        return Ok(None);
    };
    validate_original_proofs(&original.rows, &original.index, max_work)?;
    CanonicalTableLeafSet::paired_table_from_rows(
        "world.proofs",
        limits,
        original.budget,
        original.rows.current_entries(),
    )
    .map(Some)
}

#[cfg(test)]
#[path = "frozen_proofs/tests.rs"]
mod tests;
