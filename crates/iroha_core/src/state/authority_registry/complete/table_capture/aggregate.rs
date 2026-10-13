//! Original-pool custody for the fixed array of captured canonical table owners.
//!
//! Child nodes retain their separate charges. This owner funds only the exact
//! outer backing and discards every completed child on failure or generation retry.
//! Catalog completeness, coherent finality and State/Kura publication remain gates.
//! TODO: separately fund descriptor/schema scratch and remaining codec work before
//! claiming complete capture admission; this reservation owns only the outer array.

use super::{
    CanonicalTablePairedSnapshot, CapturedMembershipCompanion, CompleteInventoryError, Field,
    LeafError, LeafLimits, MembershipCaptureError, MembershipWorkLimits, SourceValidationError,
    SourceWorkLimits, State, TableMaterializer, capture_membership_group_once,
    is_stable_state_view_generation, musubi_source_work, require_complete_inventory,
    require_exact_table_materializers,
};
use super::{MusubiSourceAcquisitionError, StateMusubiSourceCut};
use iroha_allocation::{AllocationRefusal, ChargedBuffer, ChargedBufferError};

/// Why the declared State table set cannot be captured as one retained owner.
#[derive(Debug, thiserror::Error)]
pub(super) enum TableCaptureError {
    /// A canonical table has no actual State reader.
    #[error("State canonical table has no capture owner: {0}")]
    MissingMaterializer(&'static str),
    /// More than one reader claims a canonical table.
    #[error("State canonical table has duplicate capture owners: {0}")]
    DuplicateMaterializer(&'static str),
    /// Reader order must match the complete nested declaration order.
    #[error("State canonical table capture owner is out of order at {0}")]
    DisplacedMaterializer(&'static str),
    /// A reader claims an absent, derived, local or non-table field.
    #[error("State capture owner names a noncanonical table: {0}")]
    UnexpectedMaterializer(&'static str),
    /// The number of capture owners exceeds the V1 operational cap.
    #[error("State canonical table capture catalog exceeds its bound")]
    MaterializerLimit,
    /// A reader returned nodes for a different table identity.
    #[error("State table capture owner {expected} returned nodes for {actual}")]
    IdentityMismatch {
        expected: &'static str,
        actual: &'static str,
    },
    /// Membership table slots require their exact original owner and frontier cell.
    #[error("State membership capture group is malformed")]
    MalformedMembershipGroup,
    /// The original grouped reader preserves local acquisition and row errors.
    #[error(transparent)]
    Membership(#[from] MembershipCaptureError),
    /// Original native source acquisition preserves its exact local release owner.
    #[error(transparent)]
    MusubiAcquisition(#[from] MusubiSourceAcquisitionError),
    /// Semantic source validation preserves its original work, memory or validity error.
    #[error(transparent)]
    Musubi(#[from] SourceValidationError),
    /// The aggregate retained row count exceeded the caller's admission.
    #[error("State canonical table capture exceeds the aggregate row bound")]
    AggregateRowLimit,
    /// Original local pool refused the exact outer backing before any reader ran.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Retained-node owner allocation failed before returning a capture.
    #[error("State canonical table capture allocation failed")]
    Allocation,
    /// One declared schema, derivation or history descriptor is incomplete.
    #[error(transparent)]
    Inventory(#[from] CompleteInventoryError),
    /// A real State table cannot be captured within the supplied bounds.
    #[error(transparent)]
    Leaf(#[from] LeafError),
}

/// Explicit independent policy dimensions for native and grouped readers.
#[derive(Clone, Copy)]
pub(super) struct TableCaptureLimits {
    pub(super) tables: LeafLimits,
    pub(super) membership: MembershipWorkLimits,
    /// Independent whole-source bounds, consumed once across the three semantic readers.
    pub(super) musubi: SourceWorkLimits,
}

/// Retains actual table nodes without exposing a root or publication handle.
pub(super) struct CapturedCanonicalTables {
    /// Diagnostic State publication generation, never a finality certificate.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: complete State/Kura publication must bind the generation"
        )
    )]
    pub(super) generation: u64,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: complete State/Kura publication must retain the nodes"
        )
    )]
    nodes: ChargedBuffer<CanonicalTablePairedSnapshot>,
    /// Same-writer typed frontier and original surface retained with both roots.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: complete State publication must consume the retained membership companion"
        )
    )]
    membership: Option<CapturedMembershipCompanion>,
}

impl CapturedCanonicalTables {
    /// Tests borrow the retained inventory; no API can move roots out of their companion.
    #[cfg(test)]
    pub(super) fn nodes(&self) -> &[CanonicalTablePairedSnapshot] {
        self.nodes.as_slice()
    }
}

/// Attempt one aggregate capture from fixed State readers and declared tables.
///
/// Schema metadata admission permits this bounded table-only observation. `None`
/// means a State publication overlapped capture and the caller must retry. Direct
/// MV writes can bypass this generation counter, so `Some` is not a coherent
/// finalized-State certificate. Frozen cells and authenticated history are absent.
pub(super) fn capture_tables_once(
    state: &State,
    fields: &'static [Field],
    materializers: &[TableMaterializer],
    limits: TableCaptureLimits,
) -> Result<Option<CapturedCanonicalTables>, TableCaptureError> {
    let output_count = require_exact_table_materializers(fields, materializers)?;
    require_complete_inventory(fields)?;
    if output_count > limits.tables.max_tables {
        return Err(TableCaptureError::MaterializerLimit);
    }
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    // Count admission precedes the exact backing allocation and every reader.
    // Reload/restore preserve this original pool, including outstanding owners.
    let budget = state.ivm_execution_budget();
    let mut nodes = ChargedBuffer::new(output_count, &budget)?;
    let mut total_rows = 0_u64;
    let mut membership = None;
    // One retained native observation serves all semantic readers, including
    // across the intervening checkpoint table. This is diagnostic generation
    // custody, not a finalized State publication capsule.
    let musubi_world = if materializers
        .iter()
        .any(|reader| matches!(reader, TableMaterializer::MusubiSemantic(_)))
    {
        let Some(cut) = StateMusubiSourceCut::try_capture(state)? else {
            return Ok(None);
        };
        Some(cut)
    } else {
        None
    };
    let musubi_source = musubi_world
        .as_ref()
        .map(|world| musubi_source_work::validate(world, &budget, limits.musubi))
        .transpose()?;
    for materializer in materializers {
        match *materializer {
            TableMaterializer::Single { id, capture }
            | TableMaterializer::Native { id, capture, .. } => {
                let Some(node) = capture(state, limits.tables)? else {
                    return Ok(None);
                };
                retain_node(
                    &mut nodes,
                    &mut total_rows,
                    limits.tables.max_rows,
                    id,
                    node,
                )?;
            }
            TableMaterializer::MusubiSemantic(table) => {
                let source = musubi_source
                    .as_ref()
                    .expect("semantic reader acquired its native source");
                let remaining_rows = limits
                    .tables
                    .max_rows
                    .checked_sub(total_rows)
                    .ok_or(TableCaptureError::AggregateRowLimit)?;
                source.admit_table_rows(*table, limits.tables, remaining_rows)?;
                let node = source.capture_table(*table, limits.tables)?;
                retain_node(
                    &mut nodes,
                    &mut total_rows,
                    limits.tables.max_rows,
                    table.id(),
                    node,
                )?;
            }
            TableMaterializer::TransactionMembership => {
                let remaining_rows = limits
                    .tables
                    .max_rows
                    .checked_sub(total_rows)
                    .ok_or(TableCaptureError::AggregateRowLimit)?;
                let Some(pair) = capture_membership_group_once(
                    state,
                    limits.tables,
                    limits.membership,
                    remaining_rows,
                )?
                else {
                    return Ok(None);
                };
                let (current, rollback, companion) = pair.into_group(nodes.as_slice().len());
                retain_node(
                    &mut nodes,
                    &mut total_rows,
                    limits.tables.max_rows,
                    "state.transactions.current",
                    current,
                )?;
                retain_node(
                    &mut nodes,
                    &mut total_rows,
                    limits.tables.max_rows,
                    "state.transactions.rollback",
                    rollback,
                )?;
                if !companion.matches_nodes(nodes.as_slice()) || membership.is_some() {
                    return Err(TableCaptureError::MalformedMembershipGroup);
                }
                membership = Some(companion);
            }
        }
    }
    if let Some(source) = musubi_world.as_ref() {
        if !source.try_matches_current()? {
            return Ok(None);
        }
    }
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    Ok(Some(CapturedCanonicalTables {
        generation,
        nodes,
        membership,
    }))
}

/// Move a verified identity into an already admitted slot, preserving prior errors.
fn retain_node(
    nodes: &mut ChargedBuffer<CanonicalTablePairedSnapshot>,
    total_rows: &mut u64,
    max_rows: u64,
    expected: &'static str,
    node: CanonicalTablePairedSnapshot,
) -> Result<(), TableCaptureError> {
    if node.table_id() != expected {
        return Err(TableCaptureError::IdentityMismatch {
            expected,
            actual: node.table_id(),
        });
    }
    *total_rows = total_rows
        .checked_add(
            u64::try_from(node.row_count()).map_err(|_| TableCaptureError::AggregateRowLimit)?,
        )
        .filter(|rows| *rows <= max_rows)
        .ok_or(TableCaptureError::AggregateRowLimit)?;
    nodes.push_reserved(node);
    Ok(())
}

impl From<ChargedBufferError> for TableCaptureError {
    fn from(error: ChargedBufferError) -> Self {
        match error {
            ChargedBufferError::Admission(refusal) => Self::Admission(refusal),
            ChargedBufferError::Allocator { .. } => Self::Allocation,
        }
    }
}

#[cfg(test)]
#[path = "aggregate/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "aggregate/group_tests.rs"]
mod group_tests;
