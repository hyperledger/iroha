//! Atomic membership pair from one exact already prepared original transition.
//!
//! Complete capture replaces both complete tables, including empty replacements.
//! Change capture borrows the existing owner's committed-pair delta, retaining
//! exact original preimages and its distinct committed/logical frontier metadata.
//! No unavailable older rollback journal is synthesized. TODO: the selected keyed
//! engine must authenticate that original publication base and both executor cuts;
//! this local binding grants no State-root, execution or finality authority.

use super::*;
use crate::state::storage_transactions::authority::{
    TransactionMembershipSide, TransactionMembershipVisitError,
};

pub(super) fn visit_error(error: TransactionMembershipVisitError<CaptureError>) -> CaptureError {
    match error {
        TransactionMembershipVisitError::Consumer(error) => error,
        TransactionMembershipVisitError::Authority(error) => {
            CaptureError::Membership(MembershipCaptureRefusal(error))
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
    if output.intent == CaptureIntent::Changes && !cfg!(all(test, sumeragi_core_mutation = "HC453"))
    {
        return append_changes(writer, output);
    }
    // Bind original metadata without traversing rows. Each count/filter pass
    // separately admits the owner's physical visit count against the shared
    // traversal budget, including hidden predecessor entries and retry recounts.
    // No writer, view, history generation or row is copied.
    let source = writer
        .membership_publication_authority_cut(usize::MAX)
        .map_err(|error| CaptureError::Membership(MembershipCaptureRefusal(error)))?;
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
        .map_err(|error| CaptureError::Membership(MembershipCaptureRefusal(error)))?;
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

/// Retain only exact paired changes, with no scan of accumulated membership.
fn append_changes(
    writer: &crate::state::storage_transactions::PreparedTransactionsBlock<'_>,
    output: &mut Collector,
) -> Result<(), CaptureError> {
    let expected = writer.publication_surface();
    let source = writer
        .membership_publication_delta(&expected, usize::MAX)
        .map_err(|error| CaptureError::Membership(MembershipCaptureRefusal(error)))?;
    output.bind_membership_delta(source.base())?;
    let fields = [
        (
            TransactionMembershipSide::Current,
            "state.transactions.current",
        ),
        (
            TransactionMembershipSide::Rollback,
            "state.transactions.rollback",
        ),
    ];
    let mut complete = [false; 2];
    for (index, (_, id)) in fields.iter().enumerate() {
        complete[index] =
            output.already_captured(id, &SourceIdentity::Membership(expected.clone()))?;
    }
    if complete != [true, true] {
        // Count only the actual delta key sets. All subsequent filtered passes
        // admit the same complete pair's physical visits, including skipped
        // prefixes; none traverses historical rows.
        let mut counts = [0usize; 2];
        output.admit_source_visits(source.row_visits())?;
        source
            .visit(|side, _, _, _| {
                let index = usize::from(side == TransactionMembershipSide::Rollback);
                counts[index] = counts[index]
                    .checked_add(1)
                    .ok_or(CaptureError::CountLimit)?;
                Ok(())
            })
            .map_err(visit_error)?;
        for (index, (side, id)) in fields.into_iter().enumerate() {
            if complete[index] {
                continue;
            }
            if !output.begin(
                id,
                SourceIdentity::Membership(expected.clone()),
                counts[index],
                counts[index],
            )? {
                continue;
            }
            #[cfg(all(test, sumeragi_core_mutation = "HC454"))]
            let _replaced_original_key = output.pending.as_mut().and_then(|field| field.key.take());
            for undo in [false, true] {
                let retained = output.retained(undo);
                let mut seen = 0usize;
                output.admit_source_visits(source.row_visits())?;
                source
                    .visit(|which, key, before, after| {
                        if which == side {
                            if seen >= retained {
                                let value = if undo { before } else { after };
                                output.row(
                                    undo,
                                    |writer| bare(key, writer),
                                    value.map(|value| {
                                        move |writer: &mut dyn Write| bare(&value, writer)
                                    }),
                                )?;
                            }
                            seen += 1;
                        }
                        Ok(())
                    })
                    .map_err(visit_error)?;
            }
            output.finish_field()?;
        }
    }
    output.projected_cell(
        "state.transactions.frontier",
        SourceIdentity::Membership(expected),
        true,
        |writer| bare(&source.base().successor_frontier(), writer),
        |writer| bare(&source.base().committed_frontier(), writer),
    )
}
