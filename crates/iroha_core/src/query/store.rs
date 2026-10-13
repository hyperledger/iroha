//! This module contains [`LiveQueryStore`] actor.
use super::cursor::ErasedQueryIterator;
use crate::smartcontracts::isi::query::{
    OrdinaryQueryCursorBinding, OrdinaryQueryCursorMemory, OrdinaryQueryMemoryAdmission,
};
use dashmap::{DashMap, mapref::entry::Entry};
use iroha_config::parameters::actual::LiveQueryStore as Config;
use iroha_data_model::{
    account::AccountId,
    query::{
        QueryOutput, QueryOutputBatchBoxTuple, QueryRequest,
        error::QueryExecutionFail,
        parameters::{ForwardCursor, QueryId},
    },
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_logger::{trace, warn};
use std::{
    fmt,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;
type DeferredMaterializer = Box<dyn FnOnce() -> ErasedQueryIterator + Send + Sync>;
const QUERY_ID_BYTES: usize = 32;
const QUERY_ID_ALLOCATION_ATTEMPTS: usize = 16;
type PagedBatcher =
    Box<dyn Fn(u64, Option<u64>) -> Result<PagedQueryPage, QueryExecutionFail> + Send + Sync>;
struct PagedQueryPage {
    batch: QueryOutputBatchBoxTuple,
    remaining_items: Option<u64>,
    next_cursor: Option<NonZeroU64>,
}
/// Prepared output for iterable query start.
///
/// This lets the caller precompute the first response batch and defer iterator
/// materialization until the first continuation call.
pub(crate) struct PreparedQueryStart {
    /// Precomputed first response batch.
    pub first_batch: QueryOutputBatchBoxTuple,
    /// Remaining item count after the first batch, when exact counts were computed.
    pub remaining_items: Option<u64>,
    /// Deferred continuation state. `None` means query is already drained.
    pub deferred_continuation: Option<DeferredQueryContinuation>,
}
/// Prepared output for a cursor that computes each continuation page on demand.
pub(crate) struct PreparedPagedQueryStart {
    /// Precomputed first response batch.
    pub first_batch: QueryOutputBatchBoxTuple,
    /// Deferred page continuation state. `None` means query is already drained.
    pub paged_continuation: Option<PagedQueryContinuation>,
}
/// Deferred continuation for stored iterable queries.
pub(crate) struct DeferredQueryContinuation {
    expected_cursor: NonZeroU64,
    remaining_items: Option<u64>,
    materialize: Option<DeferredMaterializer>,
}
impl DeferredQueryContinuation {
    /// Construct deferred continuation state.
    pub(crate) fn new<F>(
        expected_cursor: NonZeroU64,
        remaining_items: Option<u64>,
        materialize: F,
    ) -> Self
    where
        F: FnOnce() -> ErasedQueryIterator + Send + Sync + 'static,
    {
        Self {
            expected_cursor,
            remaining_items,
            materialize: Some(Box::new(materialize)),
        }
    }
    fn expected_cursor(&self) -> NonZeroU64 {
        self.expected_cursor
    }
    fn take_materializer(&mut self) -> DeferredMaterializer {
        self.materialize
            .take()
            .expect("deferred continuation must materialize at most once")
    }
}
impl fmt::Debug for DeferredQueryContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeferredQueryContinuation")
            .field("expected_cursor", &self.expected_cursor)
            .field("remaining_items", &self.remaining_items)
            .finish_non_exhaustive()
    }
}
/// Continuation that materializes one page per `Continue` request.
pub(crate) struct PagedQueryContinuation {
    expected_cursor: NonZeroU64,
    remaining_items: Option<u64>,
    next_page: PagedBatcher,
}
impl PagedQueryContinuation {
    /// Construct paged continuation state.
    #[cfg(test)]
    pub(crate) fn new<F>(expected_cursor: NonZeroU64, next_page: F) -> Self
    where
        F: Fn(u64) -> Result<(QueryOutputBatchBoxTuple, Option<NonZeroU64>), QueryExecutionFail>
            + Send
            + Sync
            + 'static,
    {
        Self {
            expected_cursor,
            remaining_items: None,
            next_page: Box::new(move |cursor, _gas_budget| {
                let (batch, next_cursor) = next_page(cursor)?;
                Ok(PagedQueryPage {
                    batch,
                    remaining_items: None,
                    next_cursor,
                })
            }),
        }
    }
    /// Construct a paged continuation whose page producer receives the gas
    /// budget supplied by the current `Continue` request.
    pub(crate) fn new_budgeted<F>(expected_cursor: NonZeroU64, next_page: F) -> Self
    where
        F: Fn(
                u64,
                Option<u64>,
            )
                -> Result<(QueryOutputBatchBoxTuple, Option<NonZeroU64>), QueryExecutionFail>
            + Send
            + Sync
            + 'static,
    {
        Self {
            expected_cursor,
            remaining_items: None,
            next_page: Box::new(move |cursor, gas_budget| {
                let (batch, next_cursor) = next_page(cursor, gas_budget)?;
                Ok(PagedQueryPage {
                    batch,
                    remaining_items: None,
                    next_cursor,
                })
            }),
        }
    }
    /// Construct a paged continuation that reports exact remaining-item counts.
    #[cfg(test)]
    pub(crate) fn new_counted<F>(
        expected_cursor: NonZeroU64,
        remaining_items: u64,
        next_page: F,
    ) -> Self
    where
        F: Fn(
                u64,
            )
                -> Result<(QueryOutputBatchBoxTuple, u64, Option<NonZeroU64>), QueryExecutionFail>
            + Send
            + Sync
            + 'static,
    {
        Self {
            expected_cursor,
            remaining_items: Some(remaining_items),
            next_page: Box::new(move |cursor, _gas_budget| {
                let (batch, remaining_items, next_cursor) = next_page(cursor)?;
                Ok(PagedQueryPage {
                    batch,
                    remaining_items: Some(remaining_items),
                    next_cursor,
                })
            }),
        }
    }
    /// Construct an exact-count paged continuation whose page producer
    /// receives the gas budget supplied by the current `Continue` request.
    pub(crate) fn new_counted_budgeted<F>(
        expected_cursor: NonZeroU64,
        remaining_items: u64,
        next_page: F,
    ) -> Self
    where
        F: Fn(
                u64,
                Option<u64>,
            )
                -> Result<(QueryOutputBatchBoxTuple, u64, Option<NonZeroU64>), QueryExecutionFail>
            + Send
            + Sync
            + 'static,
    {
        Self {
            expected_cursor,
            remaining_items: Some(remaining_items),
            next_page: Box::new(move |cursor, gas_budget| {
                let (batch, remaining_items, next_cursor) = next_page(cursor, gas_budget)?;
                Ok(PagedQueryPage {
                    batch,
                    remaining_items: Some(remaining_items),
                    next_cursor,
                })
            }),
        }
    }
    fn expected_cursor(&self) -> NonZeroU64 {
        self.expected_cursor
    }
    fn next_batch(
        &mut self,
        cursor: u64,
        gas_budget: Option<u64>,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<NonZeroU64>), QueryExecutionFail> {
        if self.expected_cursor.get() != cursor {
            return Err(QueryExecutionFail::CursorMismatch);
        }
        let PagedQueryPage {
            batch,
            remaining_items,
            next_cursor,
        } = (self.next_page)(cursor, gas_budget)?;
        if self.remaining_items.is_some() != remaining_items.is_some() {
            return Err(QueryExecutionFail::Conversion(
                "paged query changed its count mode".to_owned(),
            ));
        }
        if let (Some(previous), Some(remaining)) = (self.remaining_items, remaining_items) {
            if remaining > previous {
                return Err(QueryExecutionFail::Conversion(
                    "paged query remaining count increased".to_owned(),
                ));
            }
            let terminal = next_cursor.is_none();
            if (remaining == 0 && !terminal) || (remaining > 0 && terminal) {
                return Err(QueryExecutionFail::Conversion(
                    "paged query cursor disagrees with its remaining count".to_owned(),
                ));
            }
        }
        if let Some(next_cursor) = next_cursor {
            if next_cursor.get() <= cursor {
                return Err(QueryExecutionFail::CursorDone);
            }
            self.expected_cursor = next_cursor;
        }
        self.remaining_items = remaining_items;
        Ok((batch, next_cursor))
    }
    fn remaining(&self) -> Option<u64> {
        self.remaining_items
    }
}
impl fmt::Debug for PagedQueryContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PagedQueryContinuation")
            .field("expected_cursor", &self.expected_cursor)
            .field("remaining_items", &self.remaining_items)
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
enum LiveQuery {
    Ready(ErasedQueryIterator),
    Deferred(DeferredQueryContinuation),
    Paged(PagedQueryContinuation),
}
impl LiveQuery {
    fn ready(iter: ErasedQueryIterator) -> Self {
        Self::Ready(iter)
    }
    fn deferred(continuation: DeferredQueryContinuation) -> Self {
        Self::Deferred(continuation)
    }
    fn paged(continuation: PagedQueryContinuation) -> Self {
        Self::Paged(continuation)
    }
    fn next_batch(
        &mut self,
        cursor: u64,
        gas_budget: Option<u64>,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<NonZeroU64>), QueryExecutionFail> {
        match self {
            Self::Ready(live_query) => live_query.next_batch(cursor),
            Self::Deferred(continuation) => {
                if continuation.expected_cursor().get() != cursor {
                    return Err(QueryExecutionFail::CursorMismatch);
                }
                let mut live_query = continuation.take_materializer()();
                let next_batch = live_query.next_batch(cursor);
                *self = Self::Ready(live_query);
                next_batch
            }
            Self::Paged(continuation) => continuation.next_batch(cursor, gas_budget),
        }
    }
    fn remaining(&self) -> Option<u64> {
        match self {
            Self::Ready(live_query) => live_query.remaining(),
            Self::Deferred(continuation) => continuation.remaining_items,
            Self::Paged(continuation) => continuation.remaining(),
        }
    }
}
/// Service which stores queries which might be non fully consumed by a client.
///
/// Clients can handle their queries using [`LiveQueryStoreHandle`]
#[derive(Debug)]
pub struct LiveQueryStore {
    queries: DashMap<QueryId, QueryInfo>,
    queries_per_user: DashMap<AccountId, usize>,
    // Includes both inserted queries and insertion reservations. Keeping this
    // independent of `DashMap::len` makes the global capacity check atomic
    // across shards and authorities.
    query_slots: AtomicUsize,
    // The maximum number of queries in the store
    capacity: NonZeroUsize,
    // The maximum number of queries in the store per user
    capacity_per_user: NonZeroUsize,
    // Queries older then this time will be automatically removed from the store
    idle_time: Duration,
    shutdown_signal: ShutdownSignal,
}
#[derive(Debug)]
struct QueryInfo {
    live_query: LiveQuery,
    last_access_time: Instant,
    authority: AccountId,
    expected_cursor: NonZeroU64,
    revalidation_request: Option<Arc<[u8]>>,
    ordinary_cursor_memory: Option<OrdinaryQueryCursorMemory>,
}
impl LiveQueryStore {
    /// Construct [`LiveQueryStore`] from configuration.
    pub fn from_config(cfg: Config, shutdown_signal: ShutdownSignal) -> Self {
        Self {
            queries: DashMap::new(),
            queries_per_user: DashMap::new(),
            query_slots: AtomicUsize::new(0),
            idle_time: cfg.idle_time,
            capacity: cfg.capacity,
            capacity_per_user: cfg.capacity_per_user,
            shutdown_signal,
        }
    }
    /// Construct [`LiveQueryStore`] for tests. Default configuration will be used.
    ///
    /// Not marked as `#[cfg(test)]` because it is used in benches as well.
    pub fn start_test() -> LiveQueryStoreHandle {
        // For tests, avoid spawning the pruning task to remove the dependency
        // on a running Tokio runtime. Tests typically exercise iterator paths
        // directly and do not rely on background pruning.
        Self::from_config(Config::default(), ShutdownSignal::new()).into_inert_handle()
    }
    /// Convert this store into a handle without starting its pruning worker.
    ///
    /// Use this only when every query and cursor route is unavailable, such as
    /// emergency Fast startup. A normal query-serving runtime must use
    /// [`Self::start`] so abandoned cursors are reclaimed.
    pub fn into_inert_handle(self) -> LiveQueryStoreHandle {
        LiveQueryStoreHandle::new(Arc::new(self))
    }
    /// Start [`LiveQueryStore`]. Requires a [`tokio::runtime::Runtime`] being run
    /// as it will create new [`tokio::task`] and detach it.
    ///
    /// Returns a handle to interact with the service.
    pub fn start(self) -> (LiveQueryStoreHandle, Child) {
        let store = Arc::new(self);
        let handle = Arc::clone(&store).spawn_pruning_task();
        (
            LiveQueryStoreHandle {
                store,
                ordinary_memory_admission: None,
            },
            Child::new(
                handle,
                // should shutdown immediately anyway
                OnShutdown::Wait(Duration::from_millis(5000)),
            ),
        )
    }
    fn spawn_pruning_task(self: Arc<Self>) -> JoinHandle<()> {
        let mut idle_interval = tokio::time::interval(self.idle_time);
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    _ = idle_interval.tick() => {
                        self.prune_expired_queries();
                    }
                    () = self.shutdown_signal.receive() => {
                        iroha_logger::debug!("LiveQueryStore is being shut down.");
                        break;
                    }
                    else => break,
                }
            }
        })
    }
    fn prune_expired_queries(&self) -> Vec<QueryId> {
        let mut expired = Vec::new();
        self.queries.retain(|key, query| {
            if query.last_access_time.elapsed() <= self.idle_time {
                true
            } else {
                expired.push((key.clone(), query.authority.clone()));
                false
            }
        });
        for (_, authority) in &expired {
            self.decrease_queries_per_user(authority.clone());
        }
        self.release_query_slots(expired.len());
        expired.into_iter().map(|(query_id, _)| query_id).collect()
    }
    fn remove(&self, query_id: &str) -> Option<QueryInfo> {
        let (_, query_info) = self.queries.remove(query_id)?;
        self.decrease_queries_per_user(query_info.authority.clone());
        self.release_query_slots(1);
        Some(query_info)
    }
    fn try_reserve_query_slot(&self) -> bool {
        self.query_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.capacity.get()).then_some(current + 1)
            })
            .is_ok()
    }
    fn release_query_slots(&self, count: usize) {
        if count == 0 {
            return;
        }
        self.query_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(count)
            })
            .expect("live-query slot accounting must not underflow");
    }
    fn decrease_queries_per_user(&self, authority: AccountId) {
        let Entry::Occupied(mut entry) = self.queries_per_user.entry(authority) else {
            return;
        };
        let counter = entry.get_mut();
        *counter -= 1;
        if *counter == 0 {
            entry.remove_entry();
        }
    }
    fn random_query_id() -> QueryId {
        let mut bytes = [0_u8; QUERY_ID_BYTES];
        if rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes).is_err() {
            return String::new();
        }
        hex::encode(bytes)
    }
    fn insert_new_query(
        &self,
        live_query: LiveQuery,
        authority: AccountId,
        expected_cursor: NonZeroU64,
        ordinary_cursor_memory: Option<OrdinaryQueryCursorMemory>,
    ) -> Result<QueryId, QueryExecutionFail> {
        self.insert_new_query_with_generator(
            live_query,
            authority,
            expected_cursor,
            ordinary_cursor_memory,
            Self::random_query_id,
        )
    }
    fn insert_new_query_with_generator(
        &self,
        live_query: LiveQuery,
        authority: AccountId,
        expected_cursor: NonZeroU64,
        ordinary_cursor_memory: Option<OrdinaryQueryCursorMemory>,
        mut generate_query_id: impl FnMut() -> QueryId,
    ) -> Result<QueryId, QueryExecutionFail> {
        if !self.try_reserve_query_slot() {
            warn!(
                max_queries = self.capacity,
                "Reached maximum allowed number of queries in LiveQueryStore"
            );
            return Err(QueryExecutionFail::CapacityLimit);
        }
        let mut user_count = self.queries_per_user.entry(authority.clone()).or_insert(0);
        if *user_count >= self.capacity_per_user.get() {
            drop(user_count);
            self.release_query_slots(1);
            warn!(
                max_queries_per_user = self.capacity_per_user,
                %authority,
                "Account reached maximum allowed number of queries in LiveQueryStore"
            );
            return Err(QueryExecutionFail::AuthorityQuotaExceeded);
        }
        *user_count += 1;
        drop(user_count);
        let mut live_query = Some(live_query);
        let mut ordinary_cursor_memory = ordinary_cursor_memory;
        for _ in 0..QUERY_ID_ALLOCATION_ATTEMPTS {
            let query_id = generate_query_id();
            if query_id.is_empty() {
                continue;
            }
            let Entry::Vacant(entry) = self.queries.entry(query_id.clone()) else {
                continue;
            };
            let Some(live_query) = live_query.take() else {
                self.decrease_queries_per_user(authority);
                self.release_query_slots(1);
                return Err(QueryExecutionFail::CapacityLimit);
            };
            entry.insert(QueryInfo {
                live_query,
                last_access_time: Instant::now(),
                authority,
                expected_cursor,
                revalidation_request: None,
                ordinary_cursor_memory: ordinary_cursor_memory.take(),
            });
            trace!(%query_id, "Inserted new query");
            return Ok(query_id);
        }
        self.decrease_queries_per_user(authority);
        self.release_query_slots(1);
        warn!(
            attempts = QUERY_ID_ALLOCATION_ATTEMPTS,
            "Failed to allocate a unique opaque query ID"
        );
        Err(QueryExecutionFail::CapacityLimit)
    }
    // For the existing query, takes and returns the first batch.
    // If query becomes depleted, it will be removed from the store.
    fn get_query_next_batch(
        &self,
        query_id: &QueryId,
        cursor: NonZeroU64,
        gas_budget: Option<u64>,
        authority: &AccountId,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<u64>, Option<NonZeroU64>), QueryExecutionFail>
    {
        trace!(%query_id, "Advancing existing query");
        let next = {
            let mut entry = self
                .queries
                .get_mut(query_id)
                .ok_or(QueryExecutionFail::Expired)?;
            // Return the same error as an absent/expired cursor so callers cannot
            // use continuation attempts to probe another authority's live-query IDs.
            // Do not advance the iterator or refresh its idle timeout on mismatch.
            if &entry.authority != authority {
                return Err(QueryExecutionFail::Expired);
            }
            if entry.expected_cursor != cursor {
                return Err(QueryExecutionFail::CursorMismatch);
            }
            let (next_batch, next_cursor) =
                match entry.live_query.next_batch(cursor.get(), gas_budget) {
                    Ok(next) => next,
                    Err(err) => {
                        return if matches!(
                            err,
                            QueryExecutionFail::Expired | QueryExecutionFail::CursorDone
                        ) {
                            drop(entry);
                            self.remove(query_id);
                            Err(err)
                        } else {
                            Err(err)
                        };
                    }
                };
            let remaining = entry.live_query.remaining();
            if let Some(next_cursor) = next_cursor {
                entry.expected_cursor = next_cursor;
            }
            entry.last_access_time = Instant::now();
            (next_batch, remaining, next_cursor)
        };
        let (next_batch, remaining, next_cursor) = next;
        if next_cursor.is_none() {
            self.remove(query_id);
        }
        Ok((next_batch, remaining, next_cursor))
    }
    fn bind_revalidation_request(
        &self,
        query_id: &QueryId,
        authority: &AccountId,
        archive: Arc<[u8]>,
    ) -> Result<(), QueryExecutionFail> {
        let mut entry = self
            .queries
            .get_mut(query_id)
            .ok_or(QueryExecutionFail::Expired)?;
        if &entry.authority != authority {
            return Err(QueryExecutionFail::Expired);
        }
        if let Some(existing) = &entry.revalidation_request {
            return if existing.as_ref() == archive.as_ref() {
                Ok(())
            } else {
                Err(QueryExecutionFail::CursorMismatch)
            };
        }
        entry.revalidation_request = Some(archive);
        Ok(())
    }
    fn revalidation_request(
        &self,
        query_id: &QueryId,
        authority: &AccountId,
    ) -> Result<Arc<[u8]>, QueryExecutionFail> {
        let entry = self
            .queries
            .get(query_id)
            .ok_or(QueryExecutionFail::Expired)?;
        if &entry.authority != authority {
            return Err(QueryExecutionFail::Expired);
        }
        entry
            .revalidation_request
            .clone()
            .ok_or(QueryExecutionFail::Expired)
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    fn ordinary_cursor_retained_bytes(
        &self,
        cursor: &ForwardCursor,
        authority: &AccountId,
    ) -> Result<u64, QueryExecutionFail> {
        let entry = self
            .queries
            .get(&cursor.query)
            .ok_or(QueryExecutionFail::Expired)?;
        if &entry.authority != authority
            || entry.expected_cursor != cursor.cursor
            || entry.revalidation_request.is_none()
        {
            return Err(QueryExecutionFail::Expired);
        }
        entry
            .ordinary_cursor_memory
            .as_ref()
            .map(|memory| memory.binding().retained_bytes())
            .ok_or(QueryExecutionFail::Expired)
    }
    fn ordinary_cursor_binding(
        &self,
        cursor: &ForwardCursor,
        authority: &AccountId,
    ) -> Result<OrdinaryQueryCursorBinding, QueryExecutionFail> {
        let entry = self
            .queries
            .get(&cursor.query)
            .ok_or(QueryExecutionFail::Expired)?;
        if &entry.authority != authority
            || entry.expected_cursor != cursor.cursor
            || entry.revalidation_request.is_none()
        {
            return Err(QueryExecutionFail::Expired);
        }
        entry
            .ordinary_cursor_memory
            .as_ref()
            .map(OrdinaryQueryCursorMemory::binding)
            .ok_or(QueryExecutionFail::Expired)
    }
}
/// Handle to interact with [`LiveQueryStore`].
#[derive(Clone)]
pub struct LiveQueryStoreHandle {
    store: Arc<LiveQueryStore>,
    ordinary_memory_admission: Option<OrdinaryQueryMemoryAdmission>,
}
impl LiveQueryStoreHandle {
    /// Create a new handle for the store
    pub fn new(store: Arc<LiveQueryStore>) -> Self {
        Self {
            store,
            ordinary_memory_admission: None,
        }
    }
    /// Return a request-local handle that splits any newly stored cursor's
    /// retained-memory token from `admission`.
    pub(crate) fn with_ordinary_memory_admission(
        &self,
        admission: OrdinaryQueryMemoryAdmission,
    ) -> Self {
        Self {
            store: Arc::clone(&self.store),
            ordinary_memory_admission: Some(admission),
        }
    }
    /// Construct a batched response from a post-processed query output.
    ///
    /// # Parameters
    /// * `gas_budget` — optional per-request allowance carried in the returned cursor.
    ///   Budget-aware paged continuations receive the current cursor allowance
    ///   explicitly on every `Continue` request.
    ///
    /// # Errors
    ///
    /// - Returns [`QueryExecutionFail::CapacityLimit`] if [`LiveQueryStore`] capacity is reached.
    /// - Returns [`QueryExecutionFail::AuthorityQuotaExceeded`] when the per-authority quota is reached.
    /// - Otherwise throws up query output handling errors.
    pub(crate) fn handle_iter_start(
        &self,
        mut live_query: ErasedQueryIterator,
        authority: &AccountId,
        gas_budget: Option<u64>,
    ) -> Result<QueryOutput, QueryExecutionFail> {
        let curr_cursor = 0;
        let (batch, next_cursor) = live_query.next_batch(curr_cursor)?;
        // NOTE: we are checking remaining items _after_ the first batch is taken
        let remaining_items = live_query.remaining();
        // if the cursor is `None` - the query has ended, we can remove it from the store
        let query_id = if let Some(expected_cursor) = next_cursor {
            let ordinary_memory_lease = self
                .ordinary_memory_admission
                .as_ref()
                .map(OrdinaryQueryMemoryAdmission::split_cursor_lease)
                .transpose()?;
            self.store.insert_new_query(
                LiveQuery::ready(live_query),
                authority.clone(),
                expected_cursor,
                ordinary_memory_lease,
            )?
        } else {
            String::new()
        };
        Ok(Self::construct_query_response(
            batch,
            remaining_items,
            query_id,
            next_cursor,
            gas_budget,
        ))
    }
    /// Construct and store a query response when the first batch and continuation
    /// state were precomputed by the caller.
    ///
    /// # Errors
    /// Mirrors [`Self::handle_iter_start`] for capacity and authority quota failures.
    pub(crate) fn handle_iter_start_prepared(
        &self,
        PreparedQueryStart {
            first_batch,
            remaining_items,
            deferred_continuation,
        }: PreparedQueryStart,
        authority: &AccountId,
        gas_budget: Option<u64>,
    ) -> Result<QueryOutput, QueryExecutionFail> {
        let next_cursor = deferred_continuation
            .as_ref()
            .map(DeferredQueryContinuation::expected_cursor);
        let query_id = if let Some(deferred_continuation) = deferred_continuation {
            let expected_cursor = deferred_continuation.expected_cursor();
            let ordinary_memory_lease = self
                .ordinary_memory_admission
                .as_ref()
                .map(OrdinaryQueryMemoryAdmission::split_cursor_lease)
                .transpose()?;
            self.store.insert_new_query(
                LiveQuery::deferred(deferred_continuation),
                authority.clone(),
                expected_cursor,
                ordinary_memory_lease,
            )?
        } else {
            String::new()
        };
        Ok(Self::construct_query_response(
            first_batch,
            remaining_items,
            query_id,
            next_cursor,
            gas_budget,
        ))
    }
    /// Construct and store a bounded response whose continuation computes one
    /// page per request instead of storing a fully materialized tail.
    ///
    /// # Errors
    /// Mirrors [`Self::handle_iter_start`] for capacity and authority quota failures.
    pub(crate) fn handle_iter_start_paged_prepared(
        &self,
        PreparedPagedQueryStart {
            first_batch,
            paged_continuation,
        }: PreparedPagedQueryStart,
        authority: &AccountId,
        gas_budget: Option<u64>,
    ) -> Result<QueryOutput, QueryExecutionFail> {
        let next_cursor = paged_continuation
            .as_ref()
            .map(PagedQueryContinuation::expected_cursor);
        let remaining_items = paged_continuation
            .as_ref()
            .and_then(PagedQueryContinuation::remaining);
        let query_id = if let Some(paged_continuation) = paged_continuation {
            let expected_cursor = paged_continuation.expected_cursor();
            let ordinary_memory_lease = self
                .ordinary_memory_admission
                .as_ref()
                .map(OrdinaryQueryMemoryAdmission::split_cursor_lease)
                .transpose()?;
            self.store.insert_new_query(
                LiveQuery::paged(paged_continuation),
                authority.clone(),
                expected_cursor,
                ordinary_memory_lease,
            )?
        } else {
            String::new()
        };
        Ok(Self::construct_query_response(
            first_batch,
            remaining_items,
            query_id,
            next_cursor,
            gas_budget,
        ))
    }
    /// Retrieve the next batch of query output using `cursor` as `authority`.
    ///
    /// # Errors
    ///
    /// - Returns [`QueryExecutionFail::Expired`] if the query id is absent, expired,
    ///   or belongs to a different authority. These cases are deliberately
    ///   indistinguishable so cursor IDs cannot be used as an existence oracle.
    /// - Returns an [`QueryExecutionFail`] if the cursor position does not match
    ///   or cannot continue.
    pub(crate) fn handle_iter_continue(
        &self,
        ForwardCursor {
            query,
            cursor,
            gas_budget,
        }: ForwardCursor,
        authority: &AccountId,
    ) -> Result<QueryOutput, QueryExecutionFail> {
        let (batch, remaining, next_cursor) = self
            .store
            .get_query_next_batch(&query, cursor, gas_budget, authority)?;
        Ok(Self::construct_query_response(
            batch,
            remaining,
            query,
            next_cursor,
            gas_budget,
        ))
    }
    /// Bind the canonical original query to a newly allocated stored cursor.
    ///
    /// Binding does not refresh the idle timer. Rebinding the same bytes is
    /// idempotent; attempting to bind different bytes fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`QueryExecutionFail::Expired`] when the cursor is absent or
    /// belongs to another authority, and [`QueryExecutionFail::CursorMismatch`]
    /// when a different request is already bound.
    pub(crate) fn bind_revalidation_request(
        &self,
        cursor: &ForwardCursor,
        authority: &AccountId,
        archive: Vec<u8>,
    ) -> Result<(), QueryExecutionFail> {
        self.store
            .bind_revalidation_request(&cursor.query, authority, Arc::<[u8]>::from(archive))
    }
    /// Decode the original query bound to a stored cursor without advancing it.
    ///
    /// # Errors
    ///
    /// Returns [`QueryExecutionFail::Expired`] for an absent, foreign,
    /// unbound, malformed, non-canonical, or non-start request so those states
    /// cannot be distinguished through the cursor namespace.
    pub(crate) fn revalidation_request(
        &self,
        cursor: &ForwardCursor,
        authority: &AccountId,
    ) -> Result<QueryRequest, QueryExecutionFail> {
        let archive = self.store.revalidation_request(&cursor.query, authority)?;
        let request: QueryRequest =
            norito::decode_from_bytes(archive.as_ref()).map_err(|_| QueryExecutionFail::Expired)?;
        if !matches!(request, QueryRequest::Start(_))
            || norito::to_bytes(&request).map_err(|_| QueryExecutionFail::Expired)?
                != archive.as_ref()
        {
            return Err(QueryExecutionFail::Expired);
        }
        Ok(request)
    }
    /// Decode an ordinary cursor's archived Start under explicit schema limits
    /// and verify canonicality with one bounded re-encode buffer.
    ///
    /// # Errors
    /// Returns [`QueryExecutionFail::Expired`] for an absent, foreign,
    /// oversized, resource-amplifying, malformed, or non-canonical archive.
    pub(crate) fn ordinary_revalidation_request_bounded(
        &self,
        cursor: &ForwardCursor,
        authority: &AccountId,
        max_archive_bytes: u64,
        decode_limits: norito::DecodeLimits,
    ) -> Result<QueryRequest, QueryExecutionFail> {
        let archive = self.store.revalidation_request(&cursor.query, authority)?;
        let max_archive_bytes =
            usize::try_from(max_archive_bytes).map_err(|_| QueryExecutionFail::Expired)?;
        if archive.len() > max_archive_bytes {
            return Err(QueryExecutionFail::Expired);
        }
        let request: QueryRequest =
            norito::decode_from_bytes_with_limits(archive.as_ref(), decode_limits)
                .map_err(|_| QueryExecutionFail::Expired)?;
        if !matches!(request, QueryRequest::Start(_)) {
            return Err(QueryExecutionFail::Expired);
        }
        let _canonical_flags =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let canonical = norito::core::to_bytes_bounded(&request, max_archive_bytes)
            .map_err(|_| QueryExecutionFail::Expired)?;
        if canonical.as_slice() != archive.as_ref() {
            return Err(QueryExecutionFail::Expired);
        }
        Ok(request)
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Return the weighted bytes retained by an ordinary stored cursor.
    ///
    /// The lookup validates the opaque query ID, authority, expected cursor, completed revalidation
    /// binding, and presence of a server-owned lease. No map guard escapes this synchronous method,
    /// so callers may acquire continuation headroom asynchronously after it returns.
    ///
    /// # Errors
    /// Returns [`QueryExecutionFail::Expired`] for every absent, foreign,
    /// stale, unbound, or legacy-unleased cursor.
    pub fn ordinary_cursor_retained_bytes(
        &self,
        cursor: &ForwardCursor,
        authority: &AccountId,
    ) -> Result<u64, QueryExecutionFail> {
        self.store.ordinary_cursor_retained_bytes(cursor, authority)
    }
    /// Return the retained-memory and archived-policy binding for a cursor.
    ///
    /// This validates the opaque ID, authority, exact cursor position, completed Start archive,
    /// and ordinary-memory ownership. The returned value is copyable, so no map guard survives
    /// into execution.
    pub(crate) fn ordinary_cursor_binding(
        &self,
        cursor: &ForwardCursor,
        authority: &AccountId,
    ) -> Result<OrdinaryQueryCursorBinding, QueryExecutionFail> {
        self.store.ordinary_cursor_binding(cursor, authority)
    }
    /// Remove query from the storage if there is any.
    pub fn drop_query(&self, query_id: &QueryId) {
        self.store.remove(query_id);
    }
    fn construct_query_response(
        batch: QueryOutputBatchBoxTuple,
        remaining_items: Option<u64>,
        query_id: QueryId,
        cursor: Option<NonZeroU64>,
        gas_budget: Option<u64>,
    ) -> QueryOutput {
        let cursor = cursor.map(|cursor| ForwardCursor {
            query: query_id,
            cursor,
            gas_budget,
        });
        match remaining_items {
            Some(remaining_items) => QueryOutput::new(batch, remaining_items, cursor),
            None => QueryOutput::new_bounded(batch, cursor.is_some(), cursor),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::query::{
        ORDINARY_NAME_ID_SOURCE_BYTES, OrdinaryQueryExecutionLimits, OrdinaryQueryMemoryLease,
        OrdinaryQueryMemoryReservation, QueryCountMode, QueryExecutionBudget, QueryLimits,
    };
    use iroha_data_model::{
        permission::Permission,
        prelude::SelectorTuple,
        query::{
            error::QueryExecutionFail,
            parameters::{FetchSize, Pagination, QueryParams, Sorting},
        },
    };
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use nonzero_ext::nonzero;
    use std::{
        num::NonZeroU64,
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[test]
    fn inert_handle_can_be_created_without_a_runtime_or_pruning_worker() {
        let handle = LiveQueryStore::from_config(Config::default(), ShutdownSignal::new())
            .into_inert_handle();

        assert!(handle.store.queries.is_empty());
        assert_eq!(handle.store.query_slots.load(Ordering::Relaxed), 0);
    }

    #[derive(Debug)]
    struct TestMemoryReservation {
        bytes: u64,
        pool_generation: u64,
        released: Arc<AtomicU64>,
    }
    impl Drop for TestMemoryReservation {
        fn drop(&mut self) {
            self.released.fetch_add(self.bytes, Ordering::SeqCst);
        }
    }
    impl OrdinaryQueryMemoryReservation for TestMemoryReservation {
        fn reserved_bytes(&self) -> u64 {
            self.bytes
        }
        fn pool_generation(&self) -> u64 {
            self.pool_generation
        }
        fn split_off(&mut self, bytes: u64) -> Option<Box<dyn OrdinaryQueryMemoryReservation>> {
            if bytes == 0 || bytes > self.bytes {
                return None;
            }
            self.bytes -= bytes;
            Some(Box::new(Self {
                bytes,
                pool_generation: self.pool_generation,
                released: Arc::clone(&self.released),
            }))
        }
    }
    fn ordinary_test_limits() -> OrdinaryQueryExecutionLimits {
        OrdinaryQueryExecutionLimits::try_new(
            5,
            QueryExecutionBudget::from_weighted_limit(128 * 1_024, 1, 1),
            16,
            64 * 1_024,
            ORDINARY_NAME_ID_SOURCE_BYTES,
            16 * 1_024,
            16,
            16 * ORDINARY_NAME_ID_SOURCE_BYTES,
            32 * 1_024,
            16 * 1_024,
            4 * 1_024,
            norito::DecodeLimits::new(64, 4 * 1_024, 256, 16 * 1_024, 16),
        )
        .expect("test ordinary geometry")
    }
    fn ordinary_test_admission(
        released: &Arc<AtomicU64>,
    ) -> (OrdinaryQueryMemoryAdmission, u64, u64) {
        let limits = ordinary_test_limits();
        let retained = limits.max_cursor_retained_bytes();
        let total = limits
            .execution_headroom_bytes()
            .checked_add(retained)
            .expect("test reservation");
        let policy = QueryLimits::new(limits.max_page_items())
            .with_count_mode(QueryCountMode::Bounded)
            .with_ordinary_execution_limits(limits)
            .ordinary_cursor_policy(13)
            .expect("ordinary policy");
        let admission = OrdinaryQueryMemoryAdmission::new(
            OrdinaryQueryMemoryLease::new(TestMemoryReservation {
                bytes: total,
                pool_generation: 13,
                released: Arc::clone(released),
            }),
            retained,
            Some(policy),
        )
        .expect("admit weighted memory");
        (admission, retained, total)
    }
    fn two_item_permission_iterator() -> ErasedQueryIterator {
        ErasedQueryIterator::new(
            (0..2).map(|index| Permission::new(format!("permission-{index}"), Json::from(false))),
            SelectorTuple::default(),
            nonzero!(1_u64),
        )
    }
    #[test]
    fn ordinary_cursor_charge_is_authority_and_position_bound() {
        let released = Arc::new(AtomicU64::new(0));
        let (admission, retained, total) = ordinary_test_admission(&released);
        let handle = LiveQueryStore::start_test();
        let scoped = handle.with_ordinary_memory_admission(admission.clone());
        let response = scoped
            .handle_iter_start(two_item_permission_iterator(), &ALICE_ID, None)
            .expect("store cursor");
        let (_, _, cursor) = response.into_parts();
        let cursor = cursor.expect("continuation");
        assert_eq!(
            handle.ordinary_cursor_retained_bytes(&cursor, &ALICE_ID),
            Err(QueryExecutionFail::Expired),
            "unbound cursors must not expose retained charge"
        );
        handle
            .bind_revalidation_request(&cursor, &ALICE_ID, vec![0xaa])
            .expect("bind archive");
        assert_eq!(
            handle
                .ordinary_cursor_retained_bytes(&cursor, &ALICE_ID)
                .expect("owner charge"),
            retained
        );
        let binding = handle
            .ordinary_cursor_binding(&cursor, &ALICE_ID)
            .expect("owner policy binding");
        assert_eq!(binding.retained_bytes(), retained);
        assert_eq!(
            handle.ordinary_cursor_retained_bytes(&cursor, &BOB_ID),
            Err(QueryExecutionFail::Expired)
        );
        assert_eq!(
            handle.ordinary_cursor_binding(&cursor, &BOB_ID),
            Err(QueryExecutionFail::Expired)
        );
        let mut stale = cursor.clone();
        stale.cursor = NonZeroU64::new(stale.cursor.get().saturating_add(1))
            .expect("stale cursor remains non-zero");
        assert_eq!(
            handle.ordinary_cursor_retained_bytes(&stale, &ALICE_ID),
            Err(QueryExecutionFail::Expired)
        );
        assert_eq!(
            handle.ordinary_cursor_binding(&stale, &ALICE_ID),
            Err(QueryExecutionFail::Expired)
        );
        let response_lease = admission
            .take_response_lease(false)
            .expect("response headroom");
        assert_eq!(
            response_lease.reserved_bytes(),
            total.checked_sub(retained).expect("response remainder")
        );
        handle.drop_query(&cursor.query);
        assert_eq!(released.load(Ordering::SeqCst), retained);
        drop(response_lease);
        assert_eq!(released.load(Ordering::SeqCst), total);
    }
    #[test]
    fn failed_cursor_insertion_releases_split_charge_once() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(1_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let first = handle
            .handle_iter_start(two_item_permission_iterator(), &ALICE_ID, None)
            .expect("fill only cursor slot");
        assert!(first.continue_cursor.is_some());
        let released = Arc::new(AtomicU64::new(0));
        let (admission, retained, total) = ordinary_test_admission(&released);
        let scoped = handle.with_ordinary_memory_admission(admission.clone());
        let error = scoped
            .handle_iter_start(two_item_permission_iterator(), &ALICE_ID, None)
            .expect_err("full store must reject second cursor");
        assert_eq!(error, QueryExecutionFail::CapacityLimit);
        assert_eq!(released.load(Ordering::SeqCst), retained);
        let response_lease = admission
            .take_response_lease(false)
            .expect("unsplit response remainder");
        assert_eq!(
            response_lease.reserved_bytes(),
            total.checked_sub(retained).expect("response remainder")
        );
        drop(response_lease);
        assert_eq!(released.load(Ordering::SeqCst), total);
    }
    #[test]
    fn bounded_revalidation_rejects_hostile_field_before_cursor_mutation() {
        let handle = LiveQueryStore::start_test();
        let response = handle
            .handle_iter_start(two_item_permission_iterator(), &ALICE_ID, None)
            .expect("store cursor");
        let (_, _, cursor) = response.into_parts();
        let cursor = cursor.expect("continuation");
        let hostile = QueryRequest::Start(iroha_data_model::query::QueryWithParams {
            query: (),
            query_payload: Vec::new(),
            item: iroha_data_model::query::QueryItemKind::RoleId,
            predicate_bytes: vec![0; 1_024],
            selector_bytes: Vec::new(),
            params: QueryParams::default(),
        });
        let archive = norito::encode_canonical(&hostile).expect("encode hostile archive");
        handle
            .bind_revalidation_request(&cursor, &ALICE_ID, archive)
            .expect("bind hostile archive");
        let error = match handle.ordinary_revalidation_request_bounded(
            &cursor,
            &ALICE_ID,
            16 * 1_024,
            norito::DecodeLimits::new(8, 16, 16, 128, 4),
        ) {
            Ok(_) => panic!("oversized nested field must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, QueryExecutionFail::Expired);
        let next = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect("bounded revalidation failure must not mutate cursor");
        assert_eq!(next.batch.len(), 1);
    }
    #[test]
    fn query_message_order_preserved() {
        let threaded_rt = tokio::runtime::Runtime::new().unwrap();
        let query_handle = threaded_rt.block_on(async { LiveQueryStore::start_test() });
        for i in 0..10_000 {
            let pagination = Pagination::default();
            let fetch_size = FetchSize {
                fetch_size: Some(nonzero!(1_u64)),
            };
            let sorting = Sorting::default();
            let query_params = QueryParams {
                pagination,
                sorting,
                fetch_size,
            };
            // it's not important which type we use here, just to test the flow
            let query_output =
                (0..100).map(|_| Permission::new(String::default(), Json::from(false)));
            let query_output = crate::smartcontracts::query::apply_query_postprocessing(
                query_output,
                SelectorTuple::default(),
                &query_params,
                QueryLimits::default(),
            )
            .unwrap();
            let (batch, _remaining_items, mut current_cursor) = query_handle
                .handle_iter_start(query_output, &ALICE_ID, None)
                .unwrap()
                .into_parts();
            let mut counter = 0;
            counter += batch.len();
            while let Some(cursor) = current_cursor {
                let Ok(batched) = query_handle.handle_iter_continue(cursor, &ALICE_ID) else {
                    break;
                };
                let (batch, _remaining_items, cursor) = batched.into_parts();
                counter += batch.len();
                current_cursor = cursor;
            }
            assert_eq!(counter, 100, "failed on {i} iteration");
        }
    }
    #[test]
    fn cursor_ttl_eviction_returns_expired_error() {
        let config = Config {
            idle_time: Duration::from_millis(1),
            capacity: nonzero!(4_usize),
            capacity_per_user: nonzero!(4_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(Arc::clone(&store));
        let query_output = (0..3).map(|i| Permission::new(format!("p{i}"), Json::from(false)));
        let query_params = QueryParams {
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(1_u64)),
            },
            ..QueryParams::default()
        };
        let query_output = crate::smartcontracts::query::apply_query_postprocessing(
            query_output,
            SelectorTuple::default(),
            &query_params,
            QueryLimits::default(),
        )
        .unwrap();
        let response = handle
            .handle_iter_start(query_output, &ALICE_ID, Some(10))
            .unwrap();
        let (_batch, _remaining, cursor) = response.into_parts();
        let mut cursor = cursor.expect("cursor stored");
        // Age the query beyond idle_time to trigger eviction.
        if let Some(mut entry) = store.queries.get_mut(cursor.query()) {
            let now = Instant::now();
            let drift = config
                .idle_time
                .checked_add(Duration::from_millis(1))
                .unwrap_or(config.idle_time);
            entry.last_access_time = now.checked_sub(drift).unwrap_or(now);
        }
        store.prune_expired_queries();
        cursor.gas_budget = Some(10);
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("expired");
        assert_eq!(err, QueryExecutionFail::Expired);
    }
    #[test]
    fn revalidation_binding_is_authority_bound_immutable_and_non_consuming() {
        let handle = LiveQueryStore::start_test();
        let params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            ..QueryParams::default()
        };
        let iter = crate::smartcontracts::query::apply_query_postprocessing(
            (0..2).map(|index| Permission::new(format!("permission-{index}"), Json::from(false))),
            SelectorTuple::default(),
            &params,
            QueryLimits::default(),
        )
        .expect("build paged query");
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start(iter, &ALICE_ID, None)
            .expect("store query")
            .into_parts();
        let cursor = cursor.expect("query has a continuation");
        assert_eq!(
            handle.bind_revalidation_request(&cursor, &BOB_ID, vec![0xaa]),
            Err(QueryExecutionFail::Expired)
        );
        handle
            .bind_revalidation_request(&cursor, &ALICE_ID, vec![0xaa])
            .expect("bind owner request");
        handle
            .bind_revalidation_request(&cursor, &ALICE_ID, vec![0xaa])
            .expect("identical binding is idempotent");
        assert_eq!(
            handle.bind_revalidation_request(&cursor, &ALICE_ID, vec![0xbb]),
            Err(QueryExecutionFail::CursorMismatch)
        );
        assert!(matches!(
            handle.revalidation_request(&cursor, &BOB_ID),
            Err(QueryExecutionFail::Expired)
        ));
        assert!(matches!(
            handle.revalidation_request(&cursor, &ALICE_ID),
            Err(QueryExecutionFail::Expired)
        ));
        let next = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect("failed revalidation lookup must not consume the cursor");
        assert_eq!(next.batch.len(), 1);
    }
    #[test]
    fn stored_cursor_rejects_foreign_authority_without_advancing_or_refreshing() {
        let store = Arc::new(LiveQueryStore::from_config(
            Config {
                idle_time: Duration::from_secs(60),
                capacity: nonzero!(4_usize),
                capacity_per_user: nonzero!(4_usize),
            },
            ShutdownSignal::new(),
        ));
        let handle = LiveQueryStoreHandle::new(Arc::clone(&store));
        let query_output = (0..3).map(|i| Permission::new(format!("p{i}"), Json::from(false)));
        let query_params = QueryParams {
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(1_u64)),
            },
            ..QueryParams::default()
        };
        let query_output = crate::smartcontracts::query::apply_query_postprocessing(
            query_output,
            SelectorTuple::default(),
            &query_params,
            QueryLimits::default(),
        )
        .unwrap();
        let (_first_batch, _remaining, cursor) = handle
            .handle_iter_start(query_output, &ALICE_ID, Some(10))
            .expect("start cursor")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        let last_access_before = store
            .queries
            .get(cursor.query())
            .expect("stored query")
            .last_access_time;
        let foreign = handle
            .handle_iter_continue(cursor.clone(), &BOB_ID)
            .expect_err("another authority must not continue Alice's cursor");
        assert_eq!(foreign, QueryExecutionFail::Expired);
        let last_access_after = store
            .queries
            .get(cursor.query())
            .expect("foreign attempt must not evict the cursor")
            .last_access_time;
        assert_eq!(
            last_access_after, last_access_before,
            "foreign attempts must not refresh cursor retention"
        );
        let mut unknown = cursor.clone();
        unknown.query = "18446744073709551615".to_owned();
        let unknown = handle
            .handle_iter_continue(unknown, &BOB_ID)
            .expect_err("guessed unknown cursor must fail");
        assert_eq!(
            unknown, foreign,
            "foreign and unknown cursor IDs must be indistinguishable"
        );
        let (batch, remaining, next) = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect("the owning authority can still continue")
            .into_parts();
        assert_eq!(batch.len(), 1);
        assert_eq!(remaining, 1);
        assert!(next.is_some());
    }
    #[test]
    fn per_authority_quota_is_enforced() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(4_usize),
            capacity_per_user: nonzero!(1_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let build_iter = || {
            let query_output = (0..2).map(|_| Permission::new(String::default(), Json::from(true)));
            let query_params = QueryParams {
                fetch_size: FetchSize {
                    fetch_size: Some(nonzero!(1_u64)),
                },
                ..QueryParams::default()
            };
            crate::smartcontracts::query::apply_query_postprocessing(
                query_output,
                SelectorTuple::default(),
                &query_params,
                QueryLimits::default(),
            )
            .unwrap()
        };
        handle
            .handle_iter_start(build_iter(), &ALICE_ID, Some(5))
            .unwrap();
        let err = handle
            .handle_iter_start(build_iter(), &ALICE_ID, Some(5))
            .expect_err("quota");
        assert_eq!(err, QueryExecutionFail::AuthorityQuotaExceeded);
    }
    #[test]
    fn stored_cursor_echoes_budget_hint() {
        let handle = LiveQueryStore::start_test();
        let query_output = (0..2).map(|_| Permission::new(String::default(), Json::from(false)));
        let query_params = QueryParams {
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(1_u64)),
            },
            ..QueryParams::default()
        };
        let query_output = crate::smartcontracts::query::apply_query_postprocessing(
            query_output,
            SelectorTuple::default(),
            &query_params,
            QueryLimits::default(),
        )
        .unwrap();
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start(query_output, &ALICE_ID, Some(42))
            .unwrap()
            .into_parts();
        let cursor = cursor.expect("cursor present");
        assert_eq!(cursor.gas_budget, Some(42));
    }
    #[test]
    fn cursor_mismatch_does_not_evict_query() {
        let handle = LiveQueryStore::start_test();
        let query_output = (0..2).map(|i| Permission::new(format!("p{i}"), Json::from(false)));
        let query_params = QueryParams {
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(1_u64)),
            },
            ..QueryParams::default()
        };
        let query_output = crate::smartcontracts::query::apply_query_postprocessing(
            query_output,
            SelectorTuple::default(),
            &query_params,
            QueryLimits::default(),
        )
        .unwrap();
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start(query_output, &ALICE_ID, Some(7))
            .unwrap()
            .into_parts();
        let cursor = cursor.expect("cursor present");
        let mut bad_cursor = cursor.clone();
        bad_cursor.cursor =
            NonZeroU64::new(cursor.cursor.get().saturating_add(1)).expect("non-zero");
        let err = handle
            .handle_iter_continue(bad_cursor, &ALICE_ID)
            .expect_err("mismatch");
        assert_eq!(err, QueryExecutionFail::CursorMismatch);
        let (batch, remaining, next) = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect("cursor still valid")
            .into_parts();
        assert_eq!(batch.len(), 1);
        assert_eq!(remaining, 0);
        assert!(next.is_none(), "query should be drained");
    }
    #[test]
    fn capacity_limit_is_enforced_with_opaque_ids() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(4_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let build_iter = || {
            let query_output = (0..2).map(|i| Permission::new(format!("p{i}"), Json::from(false)));
            let query_params = QueryParams {
                fetch_size: FetchSize {
                    fetch_size: Some(nonzero!(1_u64)),
                },
                ..QueryParams::default()
            };
            crate::smartcontracts::query::apply_query_postprocessing(
                query_output,
                SelectorTuple::default(),
                &query_params,
                QueryLimits::default(),
            )
            .unwrap()
        };
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start(build_iter(), &ALICE_ID, Some(1))
            .expect("first query")
            .into_parts();
        assert!(cursor.is_some(), "first query should allocate a cursor");
        let err = handle
            .handle_iter_start(build_iter(), &ALICE_ID, Some(1))
            .expect_err("capacity");
        assert_eq!(err, QueryExecutionFail::CapacityLimit);
    }
    #[test]
    fn global_capacity_reservations_are_atomic_across_concurrent_callers() {
        const CALLERS: usize = 32;
        const CAPACITY: usize = 3;
        let store = Arc::new(LiveQueryStore::from_config(
            Config {
                idle_time: Duration::from_secs(60),
                capacity: nonzero!(3_usize),
                capacity_per_user: nonzero!(32_usize),
            },
            ShutdownSignal::new(),
        ));
        let start = Arc::new(Barrier::new(CALLERS + 1));
        let mut callers = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            callers.push(std::thread::spawn(move || {
                start.wait();
                store.try_reserve_query_slot()
            }));
        }
        start.wait();
        let admitted = callers
            .into_iter()
            .map(|caller| caller.join().expect("capacity caller must not panic"))
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, CAPACITY);
        assert_eq!(store.query_slots.load(Ordering::Acquire), CAPACITY);
        assert!(
            store.queries.is_empty(),
            "slot reservations alone must not manufacture live cursors"
        );
        store.release_query_slots(admitted);
        assert_eq!(store.query_slots.load(Ordering::Acquire), 0);
    }
    #[test]
    fn query_ids_are_distinct_opaque_256_bit_values() {
        let handle = LiveQueryStore::start_test();
        let build_iter = || {
            let query_output = (0..2).map(|i| Permission::new(format!("p{i}"), Json::from(false)));
            let query_params = QueryParams {
                fetch_size: FetchSize {
                    fetch_size: Some(nonzero!(1_u64)),
                },
                ..QueryParams::default()
            };
            crate::smartcontracts::query::apply_query_postprocessing(
                query_output,
                SelectorTuple::default(),
                &query_params,
                QueryLimits::default(),
            )
            .unwrap()
        };
        let (_batch, _remaining, first_cursor) = handle
            .handle_iter_start(build_iter(), &ALICE_ID, None)
            .expect("first query")
            .into_parts();
        let first_cursor = first_cursor.expect("first cursor");
        let (_batch, _remaining, second_cursor) = handle
            .handle_iter_start(build_iter(), &ALICE_ID, None)
            .expect("second query")
            .into_parts();
        let second_cursor = second_cursor.expect("second cursor");
        for query_id in [&first_cursor.query, &second_cursor.query] {
            assert_eq!(query_id.len(), QUERY_ID_BYTES * 2);
            assert!(
                query_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                "query IDs must use canonical lowercase hexadecimal"
            );
        }
        assert_ne!(first_cursor.query, second_cursor.query);
    }
    #[test]
    fn opaque_query_id_allocation_retries_without_overwriting_on_collision() {
        let store = LiveQueryStore::from_config(Config::default(), ShutdownSignal::new());
        let make_query = |label: &'static str| {
            LiveQuery::ready(ErasedQueryIterator::new(
                vec![Permission::new(label.to_owned(), Json::from(false))].into_iter(),
                SelectorTuple::default(),
                nonzero!(1_u64),
            ))
        };
        let first_id = "11".repeat(QUERY_ID_BYTES);
        let second_id = "22".repeat(QUERY_ID_BYTES);
        let inserted = store
            .insert_new_query_with_generator(
                make_query("first"),
                ALICE_ID.clone(),
                nonzero!(1_u64),
                None,
                || first_id.clone(),
            )
            .expect("insert first fixed test ID");
        assert_eq!(inserted, first_id);
        let mut candidates = [first_id.clone(), second_id.clone()].into_iter();
        let inserted = store
            .insert_new_query_with_generator(
                make_query("second"),
                ALICE_ID.clone(),
                nonzero!(1_u64),
                None,
                || {
                    candidates
                        .next()
                        .expect("test generator has a unique retry")
                },
            )
            .expect("retry after forced collision");
        assert_eq!(inserted, second_id);
        assert_eq!(store.queries.len(), 2);
        assert!(store.queries.contains_key(&first_id));
        assert!(store.queries.contains_key(&second_id));
    }
    #[test]
    fn dropping_prepared_query_does_not_materialize_deferred_state() {
        let handle = LiveQueryStore::start_test();
        let materialized = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&materialized);
        let prepared = PreparedQueryStart {
            first_batch: QueryOutputBatchBoxTuple::from_batch(
                iroha_data_model::query::QueryOutputBatchBox::Permission(vec![Permission::new(
                    "p0".to_owned(),
                    Json::from(false),
                )]),
            ),
            remaining_items: Some(1),
            deferred_continuation: Some(DeferredQueryContinuation::new(
                nonzero!(1_u64),
                Some(1),
                move || {
                    flag.store(true, Ordering::SeqCst);
                    ErasedQueryIterator::new_with_cursor(
                        vec![Permission::new("p1".to_owned(), Json::from(false))].into_iter(),
                        SelectorTuple::default(),
                        nonzero!(1_u64),
                        1,
                    )
                },
            )),
        };
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_prepared(prepared, &ALICE_ID, None)
            .expect("prepared start")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        handle.drop_query(cursor.query());
        assert!(
            !materialized.load(Ordering::SeqCst),
            "dropping a stored cursor should not force deferred materialization"
        );
    }
    #[test]
    fn paged_cursor_mismatch_does_not_call_batcher_or_evict_query() {
        let handle = LiveQueryStore::start_test();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_batcher = Arc::clone(&calls);
        let prepared = PreparedPagedQueryStart {
            first_batch: permission_batch(["p0"]),
            paged_continuation: Some(PagedQueryContinuation::new(
                nonzero!(1_u64),
                move |cursor| {
                    calls_for_batcher.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(cursor, 1);
                    Ok((permission_batch(["p1"]), None))
                },
            )),
        };
        let (_batch, remaining, cursor) = handle
            .handle_iter_start_paged_prepared(prepared, &ALICE_ID, Some(9))
            .expect("paged start")
            .into_parts();
        assert_eq!(remaining, 0);
        let cursor = cursor.expect("paged cursor");
        let mut bad_cursor = cursor.clone();
        bad_cursor.cursor =
            NonZeroU64::new(cursor.cursor.get().saturating_add(1)).expect("non-zero");
        let err = handle
            .handle_iter_continue(bad_cursor, &ALICE_ID)
            .expect_err("cursor mismatch");
        assert_eq!(err, QueryExecutionFail::CursorMismatch);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "mismatched paged cursors must be rejected before replay work starts"
        );
        let (batch, remaining, next) = handle
            .handle_iter_continue(cursor.clone(), &ALICE_ID)
            .expect("original cursor remains valid")
            .into_parts();
        assert_eq!(batch.len(), 1);
        assert_eq!(remaining, 0);
        assert!(next.is_none(), "query should be drained");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("drained cursor expires");
        assert_eq!(err, QueryExecutionFail::Expired);
    }
    #[test]
    fn paged_prepared_start_enforces_capacity_limit() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(4_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("first"),
                &ALICE_ID,
                None,
            )
            .expect("first query fits");
        let err = handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("second"),
                &ALICE_ID,
                None,
            )
            .expect_err("capacity");
        assert_eq!(err, QueryExecutionFail::CapacityLimit);
    }
    #[test]
    fn exhausted_paged_start_does_not_consume_capacity_or_quota() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(1_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        for label in ["first", "second"] {
            let (batch, remaining, cursor) = handle
                .handle_iter_start_paged_prepared(
                    PreparedPagedQueryStart {
                        first_batch: permission_batch([label]),
                        paged_continuation: None,
                    },
                    &ALICE_ID,
                    None,
                )
                .expect("exhausted starts should not allocate live-query slots")
                .into_parts();
            assert_eq!(batch.len(), 1);
            assert_eq!(remaining, 0);
            assert!(cursor.is_none());
        }
        handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("third"),
                &ALICE_ID,
                None,
            )
            .expect("exhausted starts should leave capacity available");
    }
    #[test]
    fn paged_expired_error_evicts_cursor_and_releases_capacity() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(4_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let calls = Arc::new(AtomicUsize::new(0));
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_paged_prepared(
                prepared_failing_paged_permission_query(
                    "expired",
                    QueryExecutionFail::Expired,
                    Arc::clone(&calls),
                ),
                &ALICE_ID,
                None,
            )
            .expect("first query fits")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        let err = handle
            .handle_iter_continue(cursor.clone(), &ALICE_ID)
            .expect_err("expired continuation");
        assert_eq!(err, QueryExecutionFail::Expired);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("replacement"),
                &ALICE_ID,
                None,
            )
            .expect("expired paged cursor should release capacity");
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("evicted cursor is expired");
        assert_eq!(err, QueryExecutionFail::Expired);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "evicted permanent failures must not call replay work again"
        );
    }
    #[test]
    fn paged_cursor_done_error_evicts_cursor_and_releases_capacity() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(4_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let calls = Arc::new(AtomicUsize::new(0));
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_paged_prepared(
                prepared_failing_paged_permission_query(
                    "done",
                    QueryExecutionFail::CursorDone,
                    Arc::clone(&calls),
                ),
                &ALICE_ID,
                None,
            )
            .expect("first query fits")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        let err = handle
            .handle_iter_continue(cursor.clone(), &ALICE_ID)
            .expect_err("done continuation");
        assert_eq!(err, QueryExecutionFail::CursorDone);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("replacement"),
                &ALICE_ID,
                None,
            )
            .expect("cursor-done paged cursor should release capacity");
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("evicted cursor is expired");
        assert_eq!(err, QueryExecutionFail::Expired);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "evicted done cursors must not call replay work again"
        );
    }
    #[test]
    fn paged_non_advancing_next_cursor_is_rejected_and_releases_capacity() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(4_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_batcher = Arc::clone(&calls);
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_paged_prepared(
                PreparedPagedQueryStart {
                    first_batch: permission_batch(["first"]),
                    paged_continuation: Some(PagedQueryContinuation::new(
                        nonzero!(1_u64),
                        move |_| {
                            calls_for_batcher.fetch_add(1, Ordering::SeqCst);
                            Ok((permission_batch(["loop"]), Some(nonzero!(1_u64))))
                        },
                    )),
                },
                &ALICE_ID,
                None,
            )
            .expect("first query fits")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        let err = handle
            .handle_iter_continue(cursor.clone(), &ALICE_ID)
            .expect_err("non-advancing cursor must be rejected");
        assert_eq!(err, QueryExecutionFail::CursorDone);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("replacement"),
                &ALICE_ID,
                None,
            )
            .expect("non-advancing cursor should release capacity");
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("rejected cursor should be evicted");
        assert_eq!(err, QueryExecutionFail::Expired);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn counted_paged_cursor_reports_exact_remaining_items() {
        let handle = LiveQueryStore::start_test();
        let prepared = PreparedPagedQueryStart {
            first_batch: permission_batch(["p0"]),
            paged_continuation: Some(PagedQueryContinuation::new_counted(
                nonzero!(1_u64),
                2,
                |cursor| match cursor {
                    1 => Ok((permission_batch(["p1"]), 1, Some(nonzero!(2_u64)))),
                    2 => Ok((permission_batch(["p2"]), 0, None)),
                    _ => Err(QueryExecutionFail::CursorMismatch),
                },
            )),
        };
        let first = handle
            .handle_iter_start_paged_prepared(prepared, &ALICE_ID, None)
            .expect("counted paged start");
        assert_eq!(first.remaining_items, Some(2));
        let first_cursor = first.continue_cursor.expect("first cursor");
        let second = handle
            .handle_iter_continue(first_cursor, &ALICE_ID)
            .expect("second counted page");
        assert_eq!(second.remaining_items, Some(1));
        let second_cursor = second.continue_cursor.expect("second cursor");
        let third = handle
            .handle_iter_continue(second_cursor, &ALICE_ID)
            .expect("terminal counted page");
        assert_eq!(third.remaining_items, Some(0));
        assert!(third.continue_cursor.is_none());
    }
    #[test]
    fn counted_paged_cursor_rejects_inconsistent_remaining_items() {
        let mut increasing = PagedQueryContinuation::new_counted(nonzero!(1_u64), 2, |_| {
            Ok((permission_batch(["p1"]), 3, Some(nonzero!(2_u64))))
        });
        assert!(matches!(
            increasing.next_batch(1, None),
            Err(QueryExecutionFail::Conversion(message))
                if message.contains("remaining count increased")
        ));
        let mut premature_terminal =
            PagedQueryContinuation::new_counted(nonzero!(1_u64), 2, |_| {
                Ok((permission_batch(["p1"]), 1, None))
            });
        assert!(matches!(
            premature_terminal.next_batch(1, None),
            Err(QueryExecutionFail::Conversion(message))
                if message.contains("cursor disagrees")
        ));
    }
    #[test]
    fn paged_permanent_error_releases_per_authority_quota() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(4_usize),
            capacity_per_user: nonzero!(1_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let calls = Arc::new(AtomicUsize::new(0));
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_paged_prepared(
                prepared_failing_paged_permission_query(
                    "expired",
                    QueryExecutionFail::Expired,
                    Arc::clone(&calls),
                ),
                &ALICE_ID,
                None,
            )
            .expect("first query fits quota")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        let err = handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("blocked"),
                &ALICE_ID,
                None,
            )
            .expect_err("authority quota should be occupied before terminal error");
        assert_eq!(err, QueryExecutionFail::AuthorityQuotaExceeded);
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("expired continuation");
        assert_eq!(err, QueryExecutionFail::Expired);
        handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("replacement"),
                &ALICE_ID,
                None,
            )
            .expect("terminal paged error should release authority quota");
    }
    #[test]
    fn paged_transient_error_does_not_release_capacity_or_quota() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(1_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let calls = Arc::new(AtomicUsize::new(0));
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_paged_prepared(
                prepared_failing_paged_permission_query(
                    "gas",
                    QueryExecutionFail::GasBudgetExceeded,
                    Arc::clone(&calls),
                ),
                &ALICE_ID,
                None,
            )
            .expect("first query fits")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        let err = handle
            .handle_iter_continue(cursor.clone(), &ALICE_ID)
            .expect_err("transient continuation error");
        assert_eq!(err, QueryExecutionFail::GasBudgetExceeded);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let err = handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("blocked"),
                &ALICE_ID,
                None,
            )
            .expect_err("transient error should keep the cursor resident");
        assert_eq!(err, QueryExecutionFail::CapacityLimit);
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("resident cursor can be retried");
        assert_eq!(err, QueryExecutionFail::GasBudgetExceeded);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "non-terminal replay errors must not evict or disable the cursor"
        );
    }
    #[test]
    fn dropping_paged_cursor_releases_capacity_and_quota_without_replay() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(1_usize),
            capacity_per_user: nonzero!(1_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_batcher = Arc::clone(&calls);
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_paged_prepared(
                PreparedPagedQueryStart {
                    first_batch: permission_batch(["first"]),
                    paged_continuation: Some(PagedQueryContinuation::new(
                        nonzero!(1_u64),
                        move |_| {
                            calls_for_batcher.fetch_add(1, Ordering::SeqCst);
                            Ok((permission_batch(["second"]), None))
                        },
                    )),
                },
                &ALICE_ID,
                None,
            )
            .expect("first query fits")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        handle.drop_query(cursor.query());
        handle.drop_query(cursor.query());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "dropping a paged cursor must not run replay work"
        );
        handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("replacement"),
                &ALICE_ID,
                None,
            )
            .expect("dropping paged cursor should release capacity and quota");
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("dropped cursor should expire");
        assert_eq!(err, QueryExecutionFail::Expired);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn paged_transient_error_does_not_release_per_authority_quota() {
        let config = Config {
            idle_time: Duration::from_secs(60),
            capacity: nonzero!(4_usize),
            capacity_per_user: nonzero!(1_usize),
        };
        let store = Arc::new(LiveQueryStore::from_config(config, ShutdownSignal::new()));
        let handle = LiveQueryStoreHandle::new(store);
        let calls = Arc::new(AtomicUsize::new(0));
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_paged_prepared(
                prepared_failing_paged_permission_query(
                    "gas",
                    QueryExecutionFail::GasBudgetExceeded,
                    Arc::clone(&calls),
                ),
                &ALICE_ID,
                None,
            )
            .expect("first query fits")
            .into_parts();
        let cursor = cursor.expect("stored cursor");
        let err = handle
            .handle_iter_continue(cursor.clone(), &ALICE_ID)
            .expect_err("transient continuation error");
        assert_eq!(err, QueryExecutionFail::GasBudgetExceeded);
        let err = handle
            .handle_iter_start_paged_prepared(
                prepared_paged_permission_query("blocked"),
                &ALICE_ID,
                None,
            )
            .expect_err("same-authority quota should remain occupied");
        assert_eq!(err, QueryExecutionFail::AuthorityQuotaExceeded);
        let err = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect_err("resident cursor can still be retried");
        assert_eq!(err, QueryExecutionFail::GasBudgetExceeded);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    fn prepared_paged_permission_query(label: &'static str) -> PreparedPagedQueryStart {
        PreparedPagedQueryStart {
            first_batch: permission_batch([label]),
            paged_continuation: Some(PagedQueryContinuation::new(nonzero!(1_u64), move |_| {
                Ok((permission_batch([label]), None))
            })),
        }
    }
    fn prepared_failing_paged_permission_query(
        label: &'static str,
        err: QueryExecutionFail,
        calls: Arc<AtomicUsize>,
    ) -> PreparedPagedQueryStart {
        PreparedPagedQueryStart {
            first_batch: permission_batch([label]),
            paged_continuation: Some(PagedQueryContinuation::new(nonzero!(1_u64), move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(err.clone())
            })),
        }
    }
    fn permission_batch(names: impl IntoIterator<Item = &'static str>) -> QueryOutputBatchBoxTuple {
        QueryOutputBatchBoxTuple::from_batch(
            iroha_data_model::query::QueryOutputBatchBox::Permission(
                names
                    .into_iter()
                    .map(|name| Permission::new(name.to_owned(), Json::from(false)))
                    .collect(),
            ),
        )
    }
}
