//! Atomic membership pair from one exact already prepared original transition.
//!
//! Both complete tables replace their prior table contents. Consumers must clear
//! all previous rows, including on an empty replacement. No unavailable older
//! rollback journal is synthesized. TODO: the selected keyed engine must bind
//! these replacements to its authenticated predecessor under this original
//! surface; an optimized incremental path belongs to the existing membership
//! node-store owner, not a new membership or finality authority.

use super::*;
use crate::state::storage_transactions::authority::{
    TransactionMembershipSide, TransactionMembershipVisitError,
};

fn visit_error(error: TransactionMembershipVisitError<CaptureError>) -> CaptureError {
    match error {
        TransactionMembershipVisitError::Consumer(error) => error,
        TransactionMembershipVisitError::Authority(error) => {
            CaptureError::Source(error.to_string())
        }
    }
}

pub(super) fn append(block: &StateBlock<'_>, output: &mut Collector) -> Result<(), CaptureError> {
    let fields = block.fields.as_ref().ok_or(CaptureError::NotFrozen)?;
    let writer = fields
        .transactions
        .prepared_membership_writer()
        .ok_or(CaptureError::NotFrozen)?;
    if !writer.belongs_to(&fields.state_ref.transactions)
        || writer.mode() != fields.world.parameters.mode()
    {
        return Err(CaptureError::Changed("state.transactions"));
    }
    // Bind original metadata without traversing rows. Each count/filter pass
    // separately admits the owner's physical visit count against the shared
    // traversal budget, including hidden predecessor entries and retry recounts.
    // No writer, view, history generation or row is copied.
    let source = writer
        .membership_publication_authority_cut(usize::MAX)
        .map_err(|error| CaptureError::Source(error.to_string()))?;
    let mut counts = [0usize; 2];
    output.admit_source_visits(source.row_visits())?;
    source
        .visit(|side, _, _| {
            let index = usize::from(side == TransactionMembershipSide::Rollback);
            counts[index] = counts[index]
                .checked_add(1)
                .ok_or(CaptureError::CountLimit)?;
            Ok(())
        })
        .map_err(visit_error)?;
    for (index, side, id) in [
        (
            0,
            TransactionMembershipSide::Current,
            "state.transactions.current",
        ),
        (
            1,
            TransactionMembershipSide::Rollback,
            "state.transactions.rollback",
        ),
    ] {
        if !output.begin(
            id,
            SourceIdentity::Membership(writer.publication_surface()),
            counts[index],
            0,
        )? {
            continue;
        }
        output
            .pending
            .as_mut()
            .expect("same original membership field")
            .replacement = true;
        let retained = output.retained(false);
        let mut seen = 0usize;
        output.admit_source_visits(source.row_visits())?;
        source
            .visit(|which, key, height| {
                if which == side {
                    if seen >= retained {
                        output.row(
                            false,
                            |writer| bare(key, writer),
                            Some(|writer: &mut dyn Write| bare(&height, writer)),
                        )?;
                    }
                    seen += 1;
                }
                Ok(())
            })
            .map_err(visit_error)?;
        output.finish_field()?;
    }
    let current = source.frontier_height();
    let before = source
        .predecessor_frontier_height()
        .map_err(|error| CaptureError::Source(error.to_string()))?;
    output.projected_cell(
        "state.transactions.frontier",
        SourceIdentity::Membership(writer.publication_surface()),
        // This is an admitted original frontier publication, including a
        // repeated equal-height touch. Preserve its exact predecessor value.
        true,
        |writer| bare(&current, writer),
        |writer| bare(&before, writer),
    )
}
