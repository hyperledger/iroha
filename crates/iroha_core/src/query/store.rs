//! This module contains [`LiveQueryStore`] actor.

use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::{mapref::entry::Entry, DashMap};
use iroha_config::parameters::actual::LiveQueryStore as Config;
use iroha_data_model::{
    account::AccountId,
    query::{
        error::QueryExecutionFail,
        parameters::{ForwardCursor, QueryId},
        QueryOutput, QueryOutputBatchBoxTuple,
    },
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_logger::{trace, warn};
use tokio::task::JoinHandle;

use super::cursor::ErasedQueryIterator;

type LiveQuery = ErasedQueryIterator;

/// Service which stores queries which might be non fully consumed by a client.
///
/// Clients can handle their queries using [`LiveQueryStoreHandle`]
#[derive(Debug)]
pub struct LiveQueryStore {
    queries: DashMap<QueryId, QueryInfo>,
    queries_per_user: DashMap<AccountId, usize>,
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
}

impl LiveQueryStore {
    /// Construct [`LiveQueryStore`] from configuration.
    pub fn from_config(cfg: Config, shutdown_signal: ShutdownSignal) -> Self {
        Self {
            queries: DashMap::new(),
            queries_per_user: DashMap::new(),
            idle_time: cfg.idle_time,
            capacity: cfg.capacity,
            capacity_per_user: cfg.capacity_per_user,
            shutdown_signal,
        }
    }

    /// Construct [`LiveQueryStore`] for tests.
    /// Default configuration will be used.
    ///
    /// Not marked as `#[cfg(test)]` because it is used in benches as well.
    pub fn start_test() -> LiveQueryStoreHandle {
        Self::from_config(Config::default(), ShutdownSignal::new())
            .start()
            .0
    }

    /// Start [`LiveQueryStore`]. Requires a [`tokio::runtime::Runtime`] being run
    /// as it will create new [`tokio::task`] and detach it.
    ///
    /// Returns a handle to interact with the service.
    pub fn start(self) -> (LiveQueryStoreHandle, Child) {
        let store = Arc::new(self);
        let handle = Arc::clone(&store).spawn_pruning_task();
        (
            LiveQueryStoreHandle { store },
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
                        self.queries.retain(|_, query| {
                            if query.last_access_time.elapsed() <= self.idle_time {
                                true
                            } else {
                                self.decrease_queries_per_user(query.authority.clone());
                                false
                            }
                        });
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

    fn insert(&self, query_id: QueryId, live_query: ErasedQueryIterator, authority: AccountId) {
        *self.queries_per_user.entry(authority.clone()).or_insert(0) += 1;
        let query_info = QueryInfo {
            live_query,
            last_access_time: Instant::now(),
            authority,
        };
        self.queries.insert(query_id, query_info);
    }

    fn remove(&self, query_id: &str) -> Option<QueryInfo> {
        let (_, query_info) = self.queries.remove(query_id)?;
        self.decrease_queries_per_user(query_info.authority.clone());
        Some(query_info)
    }

    fn decrease_queries_per_user(&self, authority: AccountId) {
        if let Entry::Occupied(mut entry) = self.queries_per_user.entry(authority) {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove_entry();
            }
        }
    }

    fn insert_new_query(
        &self,
        query_id: QueryId,
        live_query: ErasedQueryIterator,
        authority: AccountId,
    ) -> Result<(), QueryExecutionFail> {
        trace!(%query_id, "Inserting new query");
        self.check_capacity(&authority)?;
        self.insert(query_id, live_query, authority);
        Ok(())
    }

    // For the existing query, takes and returns the first batch.
    // If query becomes depleted, it will be removed from the store.
    fn get_query_next_batch(
        &self,
        query_id: QueryId,
        cursor: NonZeroU64,
    ) -> Result<(QueryOutputBatchBoxTuple, u64, Option<NonZeroU64>), QueryExecutionFail> {
        trace!(%query_id, "Advancing existing query");
        let QueryInfo {
            mut live_query,
            authority,
            ..
        } = self.remove(&query_id).ok_or(QueryExecutionFail::NotFound)?;
        let (next_batch, next_cursor) = live_query.next_batch(cursor.get())?;
        let remaining = live_query.remaining();
        if next_cursor.is_some() {
            self.insert(query_id, live_query, authority);
        }
        Ok((next_batch, remaining, next_cursor))
    }

    fn check_capacity(&self, authority: &AccountId) -> Result<(), QueryExecutionFail> {
        if self.queries.len() >= self.capacity.get() {
            warn!(
                max_queries = self.capacity,
                "Reached maximum allowed number of queries in LiveQueryStore"
            );
            return Err(QueryExecutionFail::CapacityLimit);
        }
        if let Some(value) = self.queries_per_user.get(authority) {
            if *value >= self.capacity_per_user.get() {
                warn!(
                    max_queries_per_user = self.capacity_per_user,
                    %authority,
                    "Account reached maximum allowed number of queries in LiveQueryStore"
                );
                return Err(QueryExecutionFail::CapacityLimit);
            }
        }
        Ok(())
    }
}

/// Handle to interact with [`LiveQueryStore`].
#[derive(Clone)]
pub struct LiveQueryStoreHandle {
    store: Arc<LiveQueryStore>,
}

impl LiveQueryStoreHandle {
    /// Construct a batched response from a post-processed query output.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::CapacityLimit`] if [`LiveQueryStore`] capacity is reached,
    /// - Otherwise throws up query output handling errors.
    pub fn handle_iter_start(
        &self,
        mut live_query: ErasedQueryIterator,
        authority: &AccountId,
    ) -> Result<QueryOutput, QueryExecutionFail> {
        let query_id = uuid::Uuid::new_v4().to_string();

        let curr_cursor = 0;
        let (batch, next_cursor) = live_query.next_batch(curr_cursor)?;

        // NOTE: we are checking remaining items _after_ the first batch is taken
        let remaining_items = live_query.remaining();

        // if the cursor is `None` - the query has ended, we can remove it from the store
        if next_cursor.is_some() {
            self.store
                .insert_new_query(query_id.clone(), live_query, authority.clone())?;
        }
        Ok(Self::construct_query_response(
            batch,
            remaining_items,
            query_id,
            next_cursor,
        ))
    }

    /// Retrieve next batch of query output using `cursor`.
    ///
    /// # Errors
    ///
    /// - Returns an [`Error`] if the query id is not found,
    ///   or if cursor position doesn't match or cannot continue.
    pub fn handle_iter_continue(
        &self,
        ForwardCursor { query, cursor }: ForwardCursor,
    ) -> Result<QueryOutput, QueryExecutionFail> {
        let (batch, remaining, next_cursor) =
            self.store.get_query_next_batch(query.clone(), cursor)?;

        Ok(Self::construct_query_response(
            batch,
            remaining,
            query,
            next_cursor,
        ))
    }

    /// Remove query from the storage if there is any.
    pub fn drop_query(&self, query_id: &QueryId) {
        self.store.remove(query_id);
    }

    fn construct_query_response(
        batch: QueryOutputBatchBoxTuple,
        remaining_items: u64,
        query_id: QueryId,
        cursor: Option<NonZeroU64>,
    ) -> QueryOutput {
        QueryOutput::new(
            batch,
            remaining_items,
            cursor.map(|cursor| ForwardCursor {
                query: query_id,
                cursor,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::{
        permission::Permission,
        prelude::SelectorTuple,
        query::parameters::{FetchSize, Pagination, QueryParams},
    };
    use iroha_primitives::json::Json;
    use iroha_test_samples::ALICE_ID;
    use nonzero_ext::nonzero;

    use super::*;

    #[test]
    fn query_message_order_preserved() {
        let threaded_rt = tokio::runtime::Runtime::new().unwrap();
        let query_handle = threaded_rt.block_on(async { LiveQueryStore::start_test() });

        for i in 0..10_000 {
            let pagination = Pagination::default();
            let fetch_size = FetchSize {
                fetch_size: Some(nonzero!(1_u64)),
            };

            let query_params = QueryParams {
                pagination,
                fetch_size,
            };

            // it's not important which type we use here, just to test the flow
            let query_output =
                (0..100).map(|_| Permission::new(String::default(), Json::from(false)));
            let query_output = crate::smartcontracts::query::apply_query_postprocessing(
                query_output,
                SelectorTuple::default(),
                &query_params,
            )
            .unwrap();

            let (batch, _remaining_items, mut current_cursor) = query_handle
                .handle_iter_start(query_output, &ALICE_ID)
                .unwrap()
                .into_parts();

            let mut counter = 0;
            counter += batch.len();

            while let Some(cursor) = current_cursor {
                let Ok(batched) = query_handle.handle_iter_continue(cursor) else {
                    break;
                };
                let (batch, _remaining_items, cursor) = batched.into_parts();
                counter += batch.len();

                current_cursor = cursor;
            }

            assert_eq!(counter, 100, "failed on {i} iteration");
        }
    }
}
