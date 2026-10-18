//! Stream-owned read authorization for long-lived Torii subscriptions.
//!
//! A long-lived stream re-evaluates its reader's dataspace visibility before it
//! emits items, so a revoked grant ends the stream. Resolving that visibility
//! reads one complete State view, so each stream keeps its last decision and
//! recomputes it when the committed height moves (grants and revocations are
//! committed state), when the stream's periodic authorization tick fires, or
//! once the decision is older than the authorization interval. A revoked reader
//! is therefore cut off no later than one authorization interval after the
//! revocation.
//!
//! Event visibility also needs the dataspace scope of every transaction event.
//! The scopes of all signed transactions in a block are resolved once, when the
//! stream meets the first event of that block, and reused for its remaining
//! events instead of re-reading and re-hashing the block for each event.

use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc};

use iroha_core::{execution_attempt::ExecutionAttemptError, kura::Kura, state::AllocationBudget};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::SignedBlock,
    events::{
        EventBox,
        pipeline::{PipelineEventBox, TransactionEvent},
    },
    transaction::SignedTransaction,
};
use iroha_model_base::topology::DataSpaceId;

use crate::{
    ToriiDataspaceReadContext,
    routing::{DataspaceReadVisibility, STREAM_AUTHORIZATION_CHECK_INTERVAL},
};

/// Result of a read that may need canonical event history.
pub(crate) type EventHistoryResult<T> =
    Result<T, ExecutionAttemptError<iroha_core::kura::Error>>;

/// Authorization owned by exactly one long-lived stream.
pub(crate) trait StreamAuthorization: Send + 'static {
    /// Whether the admitted reader may still receive the next item.
    ///
    /// Implementations may reuse a recent decision; see the module docs for
    /// the staleness bound.
    fn authorization_is_current(&mut self) -> bool;

    /// Recompute the decision from current state; called on the periodic
    /// authorization tick.
    fn revalidate(&mut self) -> bool;
}

/// Authorization and visibility owned by exactly one event subscription.
pub(crate) trait EventStreamScope: StreamAuthorization {
    /// Restrict one received event to the reader's current visibility.
    ///
    /// # Errors
    /// Returns the original canonical history refusal when the scope of a
    /// transaction event cannot be read; it never falls back to a guess.
    fn filter_event(&mut self, event: EventBox) -> EventHistoryResult<Option<EventBox>>;
}

/// One stream's current read decision and its source height.
struct StreamReadDecision {
    /// Committed height of the State view the decision was read from.
    height: usize,
    decided_at: tokio::time::Instant,
    authorized: bool,
    visibility: DataspaceReadVisibility,
}

impl StreamReadDecision {
    fn read(context: &ToriiDataspaceReadContext) -> Self {
        let (height, visibility, authorized) = context.current_read_scope();
        Self {
            height,
            decided_at: tokio::time::Instant::now(),
            authorized,
            visibility,
        }
    }

    /// A decision stays current while no block commits and it is younger
    /// than one authorization interval.
    fn is_current_at(&self, committed_height: usize, now: tokio::time::Instant) -> bool {
        self.height == committed_height
            && now.saturating_duration_since(self.decided_at) < STREAM_AUTHORIZATION_CHECK_INTERVAL
    }
}

/// A stream's reader with its cached authorization and visibility.
pub(crate) struct ToriiStreamReadAuthorization {
    context: ToriiDataspaceReadContext,
    decision: StreamReadDecision,
    transactions: Option<BlockTransactionScopes>,
}

impl ToriiStreamReadAuthorization {
    /// Capture the reader and read its first decision.
    pub(crate) fn new(context: ToriiDataspaceReadContext) -> Self {
        let decision = StreamReadDecision::read(&context);
        Self {
            context,
            decision,
            transactions: None,
        }
    }

    /// The reader's current visibility.
    pub(crate) fn visibility(&mut self) -> &DataspaceReadVisibility {
        self.refresh_if_stale();
        &self.decision.visibility
    }

    /// Restrict an event using the reader's own canonical block store.
    ///
    /// # Errors
    /// See [`EventStreamScope::filter_event`].
    pub(crate) fn filter_current_event(
        &mut self,
        event: EventBox,
    ) -> EventHistoryResult<Option<EventBox>> {
        let kura = Arc::clone(&self.context.app.kura);
        self.filter_event_in(&kura, event)
    }

    /// Restrict an event to the reader's current visibility, resolving
    /// transaction scopes from `kura`.
    ///
    /// # Errors
    /// See [`EventStreamScope::filter_event`].
    pub(crate) fn filter_event_in(
        &mut self,
        kura: &Kura,
        event: EventBox,
    ) -> EventHistoryResult<Option<EventBox>> {
        self.refresh_if_stale();
        let budget = self.context.app.state.ivm_execution_budget();
        let visibility = &self.decision.visibility;
        let transactions = &mut self.transactions;
        match event {
            EventBox::PipelineBatch(events) => {
                let mut visible = Vec::new();
                for event in events {
                    let scope = pipeline_event_scope(kura, &event, &budget, transactions)?;
                    if scope.allows(visibility) {
                        visible.push(event);
                    }
                }
                Ok((!visible.is_empty()).then_some(EventBox::PipelineBatch(visible)))
            }
            EventBox::Pipeline(event) => {
                let scope = pipeline_event_scope(kura, &event, &budget, transactions)?;
                Ok(scope
                    .allows(visibility)
                    .then_some(EventBox::Pipeline(event)))
            }
            // Data, trigger, and clock events do not yet carry committed route
            // provenance. The explicit scope fails them closed to a global
            // reader instead of guessing scope from payload data.
            other @ (EventBox::Data(_)
            | EventBox::Time(_)
            | EventBox::ExecuteTrigger(_)
            | EventBox::TriggerCompleted(_)) => Ok(ScopedEventScope::GlobalReaderOnly
                .allows(visibility)
                .then_some(other)),
        }
    }

    fn refresh_if_stale(&mut self) {
        let committed_height = self.context.app.state.committed_height();
        if !self
            .decision
            .is_current_at(committed_height, tokio::time::Instant::now())
        {
            self.decision = StreamReadDecision::read(&self.context);
        }
    }
}

impl StreamAuthorization for ToriiStreamReadAuthorization {
    fn authorization_is_current(&mut self) -> bool {
        self.refresh_if_stale();
        self.decision.authorized
    }

    fn revalidate(&mut self) -> bool {
        self.decision = StreamReadDecision::read(&self.context);
        self.decision.authorized
    }
}

/// Event subscription whose transaction scopes come from an explicit block store.
pub(crate) struct ScopedEventStream {
    authorization: ToriiStreamReadAuthorization,
    kura: Arc<Kura>,
}

impl ScopedEventStream {
    /// Bind a reader to the block store that holds its events' blocks.
    pub(crate) fn new(context: ToriiDataspaceReadContext, kura: Arc<Kura>) -> Self {
        Self {
            authorization: ToriiStreamReadAuthorization::new(context),
            kura,
        }
    }
}

impl StreamAuthorization for ScopedEventStream {
    fn authorization_is_current(&mut self) -> bool {
        self.authorization.authorization_is_current()
    }

    fn revalidate(&mut self) -> bool {
        self.authorization.revalidate()
    }
}

impl EventStreamScope for ScopedEventStream {
    fn filter_event(&mut self, event: EventBox) -> EventHistoryResult<Option<EventBox>> {
        let kura = Arc::clone(&self.kura);
        self.authorization.filter_event_in(&kura, event)
    }
}

/// Admission-free subscription for fixtures: every event is delivered.
#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) struct UnscopedEventStream;

#[cfg(any(test, feature = "test-fixtures"))]
impl StreamAuthorization for UnscopedEventStream {
    fn authorization_is_current(&mut self) -> bool {
        true
    }

    fn revalidate(&mut self) -> bool {
        true
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl EventStreamScope for UnscopedEventStream {
    fn filter_event(&mut self, event: EventBox) -> EventHistoryResult<Option<EventBox>> {
        Ok(Some(event))
    }
}

/// The complete authorization scope of one event, resolved before any
/// subscriber-controlled filtering or projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScopedEventScope {
    /// Block lifecycle notices are public and carry no transaction body.
    Public,
    /// Every named dataspace must be visible to the current reader.
    Dataspaces(BTreeSet<DataSpaceId>),
    /// Missing, malformed, or intrinsically global provenance is visible only
    /// to a caller that still holds `CanReadAllLedgerData`.
    GlobalReaderOnly,
}

impl ScopedEventScope {
    fn allows(&self, visibility: &DataspaceReadVisibility) -> bool {
        match self {
            Self::Public => true,
            Self::Dataspaces(dataspaces) => dataspaces
                .iter()
                .all(|dataspace| visibility.allows_dataspace(*dataspace)),
            Self::GlobalReaderOnly => visibility.can_read_all(),
        }
    }
}

fn pipeline_event_scope(
    kura: &Kura,
    event: &PipelineEventBox,
    budget: &AllocationBudget,
    transactions: &mut Option<BlockTransactionScopes>,
) -> EventHistoryResult<ScopedEventScope> {
    Ok(match event {
        PipelineEventBox::Block(_) => ScopedEventScope::Public,
        PipelineEventBox::Transaction(transaction) => {
            transaction_event_scope(kura, transaction, budget, transactions)?
        }
        PipelineEventBox::Warning(_) | PipelineEventBox::Witness(_) => {
            ScopedEventScope::GlobalReaderOnly
        }
    })
}

/// Resolve the committed dataspace scope of one transaction event.
///
/// `transactions` caches the scopes of the last block read, keyed by its
/// committed height; a committed height never changes its block. A block that
/// is not (yet) available is not cached.
///
/// # Errors
/// Returns the original Kura refusal; a capacity refusal is never reported as
/// an absent block or a global-reader-only scope.
pub(crate) fn transaction_event_scope(
    kura: &Kura,
    transaction: &TransactionEvent,
    budget: &AllocationBudget,
    transactions: &mut Option<BlockTransactionScopes>,
) -> EventHistoryResult<ScopedEventScope> {
    let Some(height) = transaction
        .block_height()
        .and_then(|height| usize::try_from(height.get()).ok())
        .and_then(NonZeroUsize::new)
    else {
        return Ok(ScopedEventScope::GlobalReaderOnly);
    };
    if let Some(scopes) = transactions
        .as_ref()
        .filter(|scopes| scopes.height == height)
    {
        return Ok(scopes.scope(transaction.hash()));
    }
    let Some(block) = kura.get_block(height, budget)? else {
        return Ok(ScopedEventScope::GlobalReaderOnly);
    };
    let scopes = BlockTransactionScopes::from_block(height, &block);
    drop(block);
    Ok(transactions.insert(scopes).scope(transaction.hash()))
}

/// Dataspace scopes of the signed transactions committed in one block.
pub(crate) struct BlockTransactionScopes {
    height: NonZeroUsize,
    /// Signed-transaction hashes with their entrypoint's complete committed
    /// route (`None` when the context is missing, stale or malformed), sorted
    /// by hash. `None` when an entrypoint is not a signed transaction: such a
    /// block attributes no transaction event to a dataspace.
    transactions: Option<Vec<(HashOf<SignedTransaction>, Option<BTreeSet<DataSpaceId>>)>>,
}

impl BlockTransactionScopes {
    fn from_block(height: NonZeroUsize, block: &SignedBlock) -> Self {
        let count = block.external_entrypoint_count();
        let mut transactions = Vec::with_capacity(count);
        for index in 0..count {
            let Some(transaction) = block.external_signed_transaction_ref_at(index) else {
                return Self {
                    height,
                    transactions: None,
                };
            };
            transactions.push((
                transaction.hash(),
                DataspaceReadVisibility::external_entrypoint_dataspaces(block, index),
            ));
        }
        // Stable: equal hashes keep entrypoint order for the union below.
        transactions.sort_by_key(|(hash, _)| *hash);
        Self {
            height,
            transactions: Some(transactions),
        }
    }

    /// The scope of a transaction event: the union of the routes of every
    /// entrypoint carrying its hash. Absent, unscoped or malformed provenance
    /// is visible only to a global reader.
    fn scope(&self, hash: &HashOf<SignedTransaction>) -> ScopedEventScope {
        let Some(transactions) = &self.transactions else {
            return ScopedEventScope::GlobalReaderOnly;
        };
        let start = transactions.partition_point(|(candidate, _)| candidate < hash);
        let mut dataspaces = BTreeSet::new();
        for (candidate, routes) in &transactions[start..] {
            if candidate != hash {
                break;
            }
            let Some(routes) = routes else {
                return ScopedEventScope::GlobalReaderOnly;
            };
            dataspaces.extend(routes.iter().copied());
        }
        if dataspaces.is_empty() {
            ScopedEventScope::GlobalReaderOnly
        } else {
            ScopedEventScope::Dataspaces(dataspaces)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::Hash;
    use iroha_data_model::events::pipeline::TransactionStatus;
    use iroha_model_base::topology::LaneId;

    fn hash(byte: u8) -> HashOf<SignedTransaction> {
        HashOf::from_untyped_unchecked(Hash::prehashed([byte; Hash::LENGTH]))
    }

    fn scopes(
        entries: Vec<(HashOf<SignedTransaction>, Option<BTreeSet<DataSpaceId>>)>,
    ) -> BlockTransactionScopes {
        let mut entries = entries;
        entries.sort_by_key(|(hash, _)| *hash);
        BlockTransactionScopes {
            height: NonZeroUsize::MIN,
            transactions: Some(entries),
        }
    }

    #[test]
    fn block_transaction_scope_requires_a_complete_signed_route() {
        let visible = DataSpaceId::new(7);
        let other = DataSpaceId::new(8);
        let block = scopes(vec![
            (hash(1), Some(BTreeSet::from([visible]))),
            (hash(2), None),
            (hash(3), Some(BTreeSet::from([visible, other]))),
        ]);
        assert_eq!(
            block.scope(&hash(1)),
            ScopedEventScope::Dataspaces(BTreeSet::from([visible]))
        );
        assert_eq!(block.scope(&hash(2)), ScopedEventScope::GlobalReaderOnly);
        assert_eq!(
            block.scope(&hash(3)),
            ScopedEventScope::Dataspaces(BTreeSet::from([visible, other]))
        );
        assert_eq!(block.scope(&hash(4)), ScopedEventScope::GlobalReaderOnly);
        let unsigned = BlockTransactionScopes {
            height: NonZeroUsize::MIN,
            transactions: None,
        };
        assert_eq!(unsigned.scope(&hash(1)), ScopedEventScope::GlobalReaderOnly);
    }

    #[test]
    fn block_transaction_scope_unions_every_entrypoint_with_the_hash() {
        let first = DataSpaceId::new(3);
        let second = DataSpaceId::new(4);
        let block = scopes(vec![
            (hash(5), Some(BTreeSet::from([first]))),
            (hash(5), Some(BTreeSet::from([second]))),
        ]);
        assert_eq!(
            block.scope(&hash(5)),
            ScopedEventScope::Dataspaces(BTreeSet::from([first, second]))
        );
        let poisoned = scopes(vec![
            (hash(5), Some(BTreeSet::from([first]))),
            (hash(5), None),
        ]);
        assert_eq!(poisoned.scope(&hash(5)), ScopedEventScope::GlobalReaderOnly);
    }

    #[test]
    fn scoped_event_scope_applies_current_visibility() {
        let visible = DataSpaceId::new(7);
        let hidden = DataSpaceId::new(8);
        let reader = DataspaceReadVisibility::new(BTreeSet::from([visible]), false);
        let global = DataspaceReadVisibility::all_for_tests();
        assert!(ScopedEventScope::Public.allows(&reader));
        assert!(ScopedEventScope::Dataspaces(BTreeSet::from([visible])).allows(&reader));
        assert!(!ScopedEventScope::Dataspaces(BTreeSet::from([visible, hidden])).allows(&reader));
        assert!(!ScopedEventScope::GlobalReaderOnly.allows(&reader));
        assert!(ScopedEventScope::GlobalReaderOnly.allows(&global));
    }

    #[test]
    fn transaction_event_scope_reuses_the_cached_block_of_its_height() {
        let kura = Kura::blank_kura_for_testing();
        let budget = AllocationBudget::new(1 << 20);
        let visible = DataSpaceId::new(9);
        let mut cache = Some(BlockTransactionScopes {
            height: NonZeroUsize::new(5).unwrap(),
            ..scopes(vec![(hash(6), Some(BTreeSet::from([visible])))])
        });
        let event = |height: u64| TransactionEvent {
            hash: hash(6),
            block_height: core::num::NonZeroU64::new(height),
            lane_id: LaneId::SINGLE,
            dataspace_id: visible,
            status: TransactionStatus::Approved,
        };
        // The blank store has no block at height 5: only the cache can scope it.
        assert_eq!(
            transaction_event_scope(&kura, &event(5), &budget, &mut cache).unwrap(),
            ScopedEventScope::Dataspaces(BTreeSet::from([visible]))
        );
        // Another height is read from the store; an absent block is not cached.
        assert_eq!(
            transaction_event_scope(&kura, &event(6), &budget, &mut cache).unwrap(),
            ScopedEventScope::GlobalReaderOnly
        );
        assert_eq!(cache.as_ref().map(|scopes| scopes.height.get()), Some(5));
        // Queued transactions have no committed block.
        let queued = TransactionEvent {
            block_height: None,
            ..event(5)
        };
        assert_eq!(
            transaction_event_scope(&kura, &queued, &budget, &mut cache).unwrap(),
            ScopedEventScope::GlobalReaderOnly
        );
    }

    #[test]
    fn stream_decision_expires_on_commit_or_after_one_interval() {
        let decided_at = tokio::time::Instant::now();
        let decision = StreamReadDecision {
            height: 4,
            decided_at,
            authorized: true,
            visibility: DataspaceReadVisibility::all_for_tests(),
        };
        assert!(decision.is_current_at(4, decided_at));
        assert!(!decision.is_current_at(5, decided_at), "a commit may revoke");
        assert!(
            !decision.is_current_at(4, decided_at + STREAM_AUTHORIZATION_CHECK_INTERVAL),
            "a decision never outlives one authorization interval"
        );
    }

    #[test]
    fn stream_authorization_reuses_its_decision_until_revalidated() {
        let hidden = DataspaceReadVisibility::default();
        let mut authorization =
            ToriiStreamReadAuthorization::new(ToriiDataspaceReadContext::all_for_tests());
        assert!(authorization.authorization_is_current());
        assert!(authorization.visibility().can_read_all());
        // Pin the cached decision inside its interval, then replace the
        // reader's current scope behind it.
        let pinned = tokio::time::Instant::now() + STREAM_AUTHORIZATION_CHECK_INTERVAL * 1_000;
        authorization.decision.decided_at = pinned;
        authorization.context.fixed_visibility = Some(hidden.clone());
        assert!(
            authorization.authorization_is_current(),
            "a current decision is reused without reading State again"
        );
        assert_eq!(authorization.decision.decided_at, pinned);
        assert!(
            !authorization.revalidate(),
            "the periodic tick observes the lost admitted scope"
        );
        assert_eq!(authorization.visibility(), &hidden);
        assert!(!authorization.authorization_is_current());
    }
}
