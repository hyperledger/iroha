//! Borrowed transaction membership at the committed frontier and rollback cut.
//!
//! The original membership writer freezes both cuts for the entire borrow. No
//! row inventory is cloned. Physical map order, write leases and node locations
//! are excluded from canonical authority. This borrower issues no commitment or
//! finalized anchor; the complete State publisher must retain authenticated nodes
//! and their original storage through publication and recovery.

use super::{
    Key, MembershipAdmissionError, PreparedTransactionsBlock, TransactionsBlock,
    TransactionsMembershipTransition, TransactionsPublicationSurface, TransactionsStorage, Value,
};

#[path = "authority/observation.rs"]
mod observation;
pub(in crate::state) use observation::CommittedMembershipObservation;

/// Which exact map of one inseparable membership pair emitted a borrowed row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) enum TransactionMembershipSide {
    /// Latest-set precedence over historical values, after the committed tip.
    Current,
    /// Historical values before the committed tip, including shadowed values.
    Rollback,
}

/// Local failure to capture a complete canonical membership cut.
///
/// Resource refusal never changes transaction validity and must not be published
/// as an empty or truncated table. This type deliberately has no wire codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(in crate::state) enum TransactionMembershipAuthorityError {
    /// The local platform height cannot be represented as canonical u64.
    #[error("transaction membership height exceeds canonical u64")]
    HeightOverflow,
    /// A row lies outside the exact committed or rollback frontier.
    #[error("transaction membership row lies outside its committed cut")]
    InvalidHeight,
    /// Complete physical-entry visitation does not fit the local work counter.
    #[error("transaction membership traversal demand overflows")]
    TraversalOverflow,
    /// The local attempt cannot visit both complete cuts within its allowance.
    #[error("transaction membership needs {required} row visits, allowance is {limit}")]
    TraversalRefused {
        /// Latest entries plus every historical entry inspected across both cuts.
        required: usize,
        /// Locally admitted physical-entry inspections for this capture.
        limit: usize,
    },
}

/// Failed complete emission; the consumer must discard any provisional output.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(in crate::state) enum TransactionMembershipVisitError<E> {
    /// The original cut contains a noncanonical height.
    #[error(transparent)]
    Authority(#[from] TransactionMembershipAuthorityError),
    /// The original consumer refused a row or could not retain it.
    #[error("transaction membership consumer failed: {0}")]
    Consumer(E),
}

/// One complete, locally bounded capture borrowed from the original writer.
///
/// Private fields prevent constructing a cut from caller-supplied rows or roots.
/// The borrow prevents replacing or publishing the owner while either map is
/// emitted. Emission consumes this capture, and no key, value or map is cloned.
/// This is a membership reader, not successful-execution or finality evidence.
pub(in crate::state) struct TransactionMembershipCut<'block, 'storage> {
    owner: &'block TransactionsBlock<'storage>,
    frontier_height: u64,
    row_visits: usize,
}

/// Complete successor pair borrowed from an already admitted original publisher.
/// The lifetime retains its exact prepared writer; this has no finalized/root capability.
pub(in crate::state) struct TransactionMembershipPublicationCut<'block> {
    transition: TransactionsMembershipTransition<'block>,
    frontier_height: u64,
    row_visits: usize,
}

impl PreparedTransactionsBlock<'_> {
    /// Bind the actual original storage family, including physically prepared detached slots.
    pub(in crate::state) fn belongs_to(&self, storage: &TransactionsStorage) -> bool {
        self.unpublished_membership_block().belongs_to(storage)
    }

    /// Return this admitted original's replacement mode.
    pub(in crate::state) fn mode(&self) -> mv::BlockMode {
        self.unpublished_membership_block().mode()
    }

    /// Retain predecessor and staged-row allocation identity without cloning row contents.
    pub(in crate::state) fn publication_surface(&self) -> TransactionsPublicationSurface {
        self.unpublished_membership_block().publication_surface()
    }

    /// Admit both successor streams once before encoding or constructing any nodes.
    pub(in crate::state) fn membership_publication_authority_cut(
        &self,
        max_row_visits: usize,
    ) -> Result<TransactionMembershipPublicationCut<'_>, TransactionMembershipAuthorityError> {
        let transition = self.membership_transition();
        let frontier_height = u64::try_from(transition.staged_height().get())
            .map_err(|_| TransactionMembershipAuthorityError::HeightOverflow)?;
        let row_visits = transition
            .successor_row_visits()
            .ok_or(TransactionMembershipAuthorityError::TraversalOverflow)?;
        if row_visits > max_row_visits {
            return Err(TransactionMembershipAuthorityError::TraversalRefused {
                required: row_visits,
                limit: max_row_visits,
            });
        }
        Ok(TransactionMembershipPublicationCut {
            transition,
            frontier_height,
            row_visits,
        })
    }
}

impl TransactionMembershipPublicationCut<'_> {
    /// Exact successor frontier shared by both maps.
    pub(in crate::state) fn frontier_height(&self) -> u64 {
        self.frontier_height
    }

    /// Physical source-entry inspections admitted before either stream starts.
    pub(in crate::state) fn row_visits(&self) -> usize {
        self.row_visits
    }

    /// Emit current then rollback from this same immutable original transition.
    /// Error discards all provisional consumer output and changes no publication source.
    pub(in crate::state) fn visit<E>(
        self,
        mut visit: impl FnMut(TransactionMembershipSide, &Key, u64) -> Result<(), E>,
    ) -> Result<(), TransactionMembershipVisitError<E>> {
        self.transition.visit_staged_membership(|key, height| {
            let height = canonical_height(height, self.frontier_height)?;
            visit(TransactionMembershipSide::Current, key, height)
                .map_err(TransactionMembershipVisitError::Consumer)
        })?;
        self.transition
            .visit_staged_predecessor_membership(|key, height| {
                let height = canonical_height(height, self.frontier_height.saturating_sub(1))?;
                visit(TransactionMembershipSide::Rollback, key, height)
                    .map_err(TransactionMembershipVisitError::Consumer)
            })
    }
}

fn canonical_height(
    height: Value,
    frontier: u64,
) -> Result<u64, TransactionMembershipAuthorityError> {
    let value = u64::try_from(height.get())
        .map_err(|_| TransactionMembershipAuthorityError::HeightOverflow)?;
    if value == 0 || value > frontier {
        return Err(TransactionMembershipAuthorityError::InvalidHeight);
    }
    Ok(value)
}

fn admit_row_visits(
    latest: usize,
    history: usize,
    limit: usize,
) -> Result<usize, TransactionMembershipAuthorityError> {
    let required = history
        .checked_mul(2)
        .and_then(|history| latest.checked_add(history))
        .ok_or(TransactionMembershipAuthorityError::TraversalOverflow)?;
    if required > limit {
        return Err(TransactionMembershipAuthorityError::TraversalRefused { required, limit });
    }
    Ok(required)
}

impl<'storage> TransactionsBlock<'storage> {
    /// Borrow both committed maps and their frontier under this original writer.
    ///
    /// `max_row_visits` bounds physical entries inspected, including history
    /// filtered out of either cut. The two existing visitors inspect the latest
    /// set once and history twice; admission precedes any row scan or callback.
    /// Map lengths use container metadata while the same writer is retained.
    /// This is not a bound on empty hash buckets or elapsed time: the containers
    /// do not expose a stable bucket-inspection contract. Consumer encoding and
    /// allocation work require their own original, funded owner.
    ///
    /// # Errors
    ///
    /// Returns a typed local refusal before emission when the complete visit
    /// exceeds its allowance, or the canonical frontier cannot be represented.
    pub(in crate::state) fn membership_authority_cut(
        &self,
        max_row_visits: usize,
    ) -> Result<TransactionMembershipCut<'_, 'storage>, TransactionMembershipAuthorityError> {
        self._guard.identity();
        let latest = self.latest_block_ref.load();
        let (frontier_height, row_visits) = match latest.as_ref() {
            Some(tip) => (
                u64::try_from(tip.height.get())
                    .map_err(|_| TransactionMembershipAuthorityError::HeightOverflow)?,
                admit_row_visits(tip.transactions.len(), self.baseline.len(), max_row_visits)?,
            ),
            None => (0, 0),
        };
        Ok(TransactionMembershipCut {
            owner: self,
            frontier_height,
            row_visits,
        })
    }
}

impl TransactionMembershipCut<'_, '_> {
    /// Canonical frontier of both captured maps; zero only before the first tip.
    pub(in crate::state) fn frontier_height(&self) -> u64 {
        self.frontier_height
    }

    /// Complete admitted physical-entry work, including filtered history rows.
    pub(in crate::state) fn row_visits(&self) -> usize {
        self.row_visits
    }

    /// Emit both complete maps once, with borrowed keys and stack-local heights.
    ///
    /// Current and rollback are independent of the owner's replacement mode and
    /// any staged next block. Current rows precede rollback rows; order within a
    /// map is unspecified. Consumers must use the existing canonical table codec
    /// and duplicate checking, never fold callback order into a commitment.
    /// Callbacks must not acquire this storage's writer. On any error, discard
    /// all provisional output; a successfully emitted prefix is not a table.
    ///
    /// # Errors
    ///
    /// Forwards the exact consumer error or rejects a noncanonical row height.
    pub(in crate::state) fn visit<E>(
        self,
        mut visit: impl FnMut(TransactionMembershipSide, &Key, u64) -> Result<(), E>,
    ) -> Result<(), TransactionMembershipVisitError<E>> {
        self.owner.visit_committed_membership(|key, height| {
            let height = canonical_height(height, self.frontier_height)?;
            visit(TransactionMembershipSide::Current, key, height)
                .map_err(TransactionMembershipVisitError::Consumer)
        })?;
        self.owner
            .visit_committed_predecessor_membership(|key, height| {
                let height = canonical_height(height, self.frontier_height.saturating_sub(1))?;
                visit(TransactionMembershipSide::Rollback, key, height)
                    .map_err(TransactionMembershipVisitError::Consumer)
            })
    }
}

#[cfg(test)]
#[path = "authority/tests.rs"]
mod tests;

impl TransactionsStorage {
    /// Observe both committed cuts without staging, allocating or waiting.
    ///
    /// Refusal preserves the actual membership or active-reader release source.
    /// The returned borrower cannot prepare or publish a successor.
    pub(in crate::state) fn try_membership_observation(
        &self,
    ) -> Result<CommittedMembershipObservation<'_>, MembershipAdmissionError> {
        CommittedMembershipObservation::try_new(self)
    }
}
