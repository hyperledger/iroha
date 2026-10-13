//! Snapshot-owned ordinary cursors with exact, fallible page and tail storage.
//!
//! The admitted source has already charged its bounded scan. Start carries that work into tail
//! sizing and reserves the response envelope from the same budget. Each continuation owns only
//! its original tail and uses a fresh page budget; it never re-executes against live world state.
use super::{
    OrdinaryQueryExecutionLimits, QueryCountMode, QueryExecutionStats, QueryLimits,
    bounded_bare_encoded_len,
    ordinary_iterable::{ExactOwnedRows, exact_one_column_batch},
};
use crate::query::store::{LiveQueryStoreHandle, PagedQueryContinuation, PreparedPagedQueryStart};
use iroha_data_model::{
    account::AccountId,
    query::{
        QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple,
        dsl::{HasProjection, SelectorMarker},
        error::QueryExecutionFail as Error,
        parameters::QueryParams,
    },
};
use norito::core::NoritoSerialize;
use std::{num::NonZeroU64, sync::Mutex};

fn take_page<T>(
    rows: &mut ExactOwnedRows<T>,
    fetch: usize,
    ordinary: OrdinaryQueryExecutionLimits,
) -> Result<QueryOutputBatchBoxTuple, Error>
where
    QueryOutputBatchBox: From<Vec<T>>,
{
    let count = rows.len().min(fetch);
    let bytes = ordinary
        .max_page_items()
        .checked_mul(ordinary.max_source_item_bytes())
        .ok_or(Error::CapacityLimit)?;
    let mut values = ExactOwnedRows::new(count, bytes)?;
    for _ in 0..count {
        values.push(rows.next().ok_or(Error::CapacityLimit)?)?;
    }
    exact_one_column_batch(QueryOutputBatchBox::from(values.finish()?.into_vec()?))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle<I>(
    mut iter: I,
    params: &QueryParams,
    limits: QueryLimits,
    ordinary: OrdinaryQueryExecutionLimits,
    store: &LiveQueryStoreHandle,
    authority: &AccountId,
    gas_budget: Option<u64>,
    mut execution_stats: QueryExecutionStats,
) -> Result<QueryOutput, Error>
where
    I: Iterator,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    if limits.count_mode != QueryCountMode::Bounded
        || params.pagination.offset_value() != 0
        || params.sorting.sort_by_metadata_key.is_some()
    {
        // Admission refuses these shapes before execution; this is the
        // fail-closed backstop for the bounded stored adapters.
        return Err(super::ordinary_memory::signed_query_shape_not_admitted(
            "the stored iterable start",
            "requires bounded counting, zero offset and no sorting",
        ));
    }
    let fetch = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE)
        .get();
    if fetch > limits.max_fetch_size || fetch > ordinary.max_page_items() {
        return Err(Error::FetchSizeTooBig);
    }
    let fetch = usize::try_from(fetch).map_err(|_| Error::CapacityLimit)?;
    let (source_len, exact_len) = iter.size_hint();
    if exact_len != Some(source_len) {
        return Err(Error::CapacityLimit);
    }
    let first_len = source_len.min(fetch);
    let tail_len = source_len
        .checked_sub(first_len)
        .ok_or(Error::CapacityLimit)?;
    if u64::try_from(tail_len).map_err(|_| Error::CapacityLimit)?
        > ordinary.max_cursor_retained_items()
    {
        // The source-owned F + T + 1 probe proves that the requested snapshot cannot fit.
        return Err(Error::CapacityLimit);
    }
    // A stored response's cursor is allocated by the store after preparation. Reserve the full
    // server-owned frame ceiling before publishing it; the wire encoder enforces that same ceiling.
    // This deliberately conservative charge shares the source budget, including empty/short pages.
    let budget = Some(ordinary.execution_budget());
    execution_stats.record_precomputed_bytes(ordinary.max_response_bytes(), budget)?;
    let page_bytes = ordinary
        .max_page_items()
        .checked_mul(ordinary.max_source_item_bytes())
        .ok_or(Error::CapacityLimit)?;
    let tail_bytes = ordinary
        .max_cursor_retained_items()
        .checked_mul(ordinary.max_source_item_bytes())
        .ok_or(Error::CapacityLimit)?;
    let mut first = ExactOwnedRows::new(first_len, page_bytes)?;
    let mut tail = ExactOwnedRows::new(tail_len, tail_bytes)?;
    for _ in 0..first_len {
        first.push(iter.next().ok_or(Error::CapacityLimit)?)?;
    }
    let mut retained_bytes = 0_u64;
    for _ in 0..tail_len {
        let value = iter.next().ok_or(Error::CapacityLimit)?;
        let remaining = ordinary
            .max_cursor_value_bytes()
            .checked_sub(retained_bytes)
            .ok_or(Error::CapacityLimit)?;
        let bytes = bounded_bare_encoded_len(&value, remaining).map_err(|error| match error {
            Error::GasBudgetExceeded => Error::CapacityLimit,
            error => error,
        })?;
        execution_stats.record_preflighted_item(bytes, budget)?;
        retained_bytes = retained_bytes
            .checked_add(bytes)
            .ok_or(Error::CapacityLimit)?;
        tail.push(value)?;
    }
    if iter.next().is_some() {
        return Err(Error::CapacityLimit);
    }
    drop(iter);
    let first_batch =
        exact_one_column_batch(QueryOutputBatchBox::from(first.finish()?.into_vec()?))?;
    let tail = tail.finish()?;
    let paged_continuation = if tail_len == 0 {
        None
    } else {
        let cursor = NonZeroU64::new(u64::try_from(first_len).map_err(|_| Error::CapacityLimit)?)
            .ok_or(Error::CapacityLimit)?;
        let retained = Mutex::new(tail);
        Some(PagedQueryContinuation::new_budgeted(
            cursor,
            move |cursor, _gas_budget| {
                let mut rows = retained.lock().map_err(|_| Error::CapacityLimit)?;
                let count = rows.len().min(fetch);
                let mut page_stats = QueryExecutionStats::default();
                let row_work = ordinary
                    .max_source_item_bytes()
                    .checked_mul(3)
                    .ok_or(Error::CapacityLimit)?;
                for _ in 0..count {
                    page_stats.record_preflighted_item(row_work, budget)?;
                }
                page_stats.record_precomputed_bytes(ordinary.max_response_bytes(), budget)?;
                let batch = take_page(&mut rows, fetch, ordinary)?;
                let next = if rows.len() == 0 {
                    None
                } else {
                    NonZeroU64::new(
                        cursor
                            .checked_add(u64::try_from(count).map_err(|_| Error::CapacityLimit)?)
                            .ok_or(Error::CapacityLimit)?,
                    )
                };
                Ok((batch, next))
            },
        ))
    };
    store.handle_iter_start_paged_prepared(
        PreparedPagedQueryStart {
            first_batch,
            paged_continuation,
        },
        authority,
        gas_budget,
    )
}

#[cfg(test)]
mod tests {
    use super::super::{QueryExecutionBudget, ValidQueryRequest};
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        Registrable,
        account::Account,
        query::{
            ErasedIterQuery, QueryBox, QueryRequest, QueryResponse, QueryWithParams,
            account::prelude::FindAccountIds,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::{FetchSize, Pagination},
        },
    };
    use iroha_test_samples::ALICE_ID;

    fn ordinary(
        units: u64,
        retained: u64,
        retained_value_bytes: u64,
    ) -> OrdinaryQueryExecutionLimits {
        let source = 1024;
        let response = 4096;
        let graph = 4096;
        let archive = 1024;
        let decode = norito::DecodeLimits::new(64, 4096, 256, 16384, 16);
        let fresh = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            1, source, response, graph, archive, decode,
        )
        .unwrap();
        let cursor = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
            retained,
            source,
            retained_value_bytes,
            archive,
        )
        .unwrap();
        OrdinaryQueryExecutionLimits::try_new(
            1,
            QueryExecutionBudget::from_weighted_limit(units, 1, 1),
            1,
            fresh,
            source,
            response,
            retained,
            retained_value_bytes,
            cursor,
            graph,
            archive,
            decode,
        )
        .unwrap()
    }
    fn params(limit: Option<u64>) -> QueryParams {
        QueryParams {
            fetch_size: FetchSize::new(NonZeroU64::new(1)),
            pagination: Pagination {
                offset: 0,
                limit: limit.and_then(NonZeroU64::new),
            },
            ..QueryParams::default()
        }
    }
    fn request(ordinary: OrdinaryQueryExecutionLimits, params: QueryParams) -> ValidQueryRequest {
        let query: QueryBox<QueryOutputBatchBox> = Box::new(ErasedIterQuery::<AccountId>::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            norito::codec::Encode::encode(&FindAccountIds),
        ));
        ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams::new(&query, params).unwrap()),
            limits: QueryLimits::new(1)
                .with_count_mode(QueryCountMode::Bounded)
                .with_ordinary_execution_limits(ordinary),
        }
    }
    fn accounts(count: usize) -> Vec<AccountId> {
        let mut values: Vec<_> = (0..count)
            .map(|i| {
                AccountId::new(
                    KeyPair::try_from_seed(
                        vec![0xa0 + u8::try_from(i).unwrap(); 32],
                        Algorithm::Ed25519,
                    )
                    .unwrap()
                    .public_key()
                    .clone(),
                )
            })
            .collect();
        values.sort();
        values
    }
    fn state(ids: &[AccountId], handle: LiveQueryStoreHandle) -> State {
        State::new(
            World::with(
                [],
                ids.iter()
                    .cloned()
                    .map(|id| Account::new(id).build(&ALICE_ID)),
                [],
            ),
            Kura::blank_kura_for_testing(),
            handle,
        )
    }
    fn ids(output: &QueryOutput) -> &[AccountId] {
        match output.batch.columns().first().unwrap() {
            QueryOutputBatchBox::AccountId(ids) => ids,
            _ => panic!("account identity batch"),
        }
    }
    #[test]
    fn account_stored_pages_preserve_order_and_survive_initial_state_drop() {
        for count in 0..=3 {
            let expected = accounts(count);
            let handle = LiveQueryStore::start_test();
            let original = state(&expected, handle.clone());
            let view = original.view();
            let QueryResponse::Iterable(mut output) =
                request(ordinary(65536, 3, 4096), params(None))
                    .execute(&handle, &view, &ALICE_ID)
                    .expect("admitted account source")
            else {
                panic!("iterable");
            };
            drop(view);
            drop(original);
            // The cursor's source is the retained initial snapshot, independent of a live State.
            let replacement = state(&accounts(5), handle.clone());
            let mut actual = ids(&output).to_vec();
            while let Some(cursor) = output.continue_cursor.take() {
                output = handle
                    .handle_iter_continue(cursor, &ALICE_ID)
                    .expect("owned snapshot page");
                assert_eq!(output.remaining_items, None);
                actual.extend_from_slice(ids(&output));
            }
            assert_eq!(actual, expected);
            assert!(!output.has_more);
            drop(replacement);
        }
    }
    #[test]
    fn account_ephemeral_source_respects_limit_and_keeps_its_work_statistics() {
        let handle = LiveQueryStore::start_test();
        let expected = accounts(3);
        let state = state(&expected, handle.clone());
        let view = state.view();
        for (limit, has_more, items) in [(None, true, 4), (Some(1), false, 2)] {
            let (QueryResponse::Iterable(output), execution_stats) =
                request(ordinary(65536, 1, 4096), params(limit))
                    .execute_ephemeral_with_stats(&handle, &view, &ALICE_ID, None)
                    .expect("ephemeral account adapter")
            else {
                panic!("iterable");
            };
            assert_eq!(ids(&output), &expected[..1]);
            assert_eq!(output.has_more, has_more);
            assert!(output.continue_cursor.is_none());
            assert_eq!(execution_stats.processed_items(), items);
        }
        let mut offset = params(None);
        offset.pagination.offset = 1;
        assert!(matches!(
            request(ordinary(65536, 1, 4096), offset).execute(&handle, &view, &ALICE_ID),
            Err(Error::Conversion(_))
        ));
    }
    #[test]
    fn account_stored_limit_avoids_the_overflow_probe_beyond_requested_range() {
        let handle = LiveQueryStore::start_test();
        let expected = accounts(3);
        let state = state(&expected, handle.clone());
        let view = state.view();
        let limit = ordinary(65536, 1, 4096);
        assert!(matches!(
            request(limit, params(None)).execute(&handle, &view, &ALICE_ID),
            Err(Error::CapacityLimit)
        ));
        let QueryResponse::Iterable(first) = request(limit, params(Some(2)))
            .execute(&handle, &view, &ALICE_ID)
            .expect("bounded explicit limit")
        else {
            panic!("iterable");
        };
        assert_eq!(ids(&first), &expected[..1]);
        let last = handle
            .handle_iter_continue(first.continue_cursor.unwrap(), &ALICE_ID)
            .unwrap();
        assert_eq!(ids(&last), &expected[1..2]);
        assert!(!last.has_more);
    }
    #[test]
    fn stored_start_shares_source_tail_and_response_work_budget() {
        let handle = LiveQueryStore::start_test();
        let expected = accounts(3);
        let state = state(&expected, handle.clone());
        let view = state.view();
        let tail_bytes: u64 = expected[1..]
            .iter()
            .map(|value| bounded_bare_encoded_len(value, u64::MAX).unwrap())
            .sum();
        // The source performs two passes, with one item and three S-byte traversals per pass.
        let exact_units = 6 + 18 * 1024 + 2 + tail_bytes + 4096;
        assert!(matches!(
            request(ordinary(exact_units - 1, 3, 4096), params(None))
                .execute(&handle, &view, &ALICE_ID),
            Err(Error::GasBudgetExceeded)
        ));
        let QueryResponse::Iterable(output) = request(ordinary(exact_units, 3, 4096), params(None))
            .execute(&handle, &view, &ALICE_ID)
            .expect("shared exact work ceiling")
        else {
            panic!("iterable");
        };
        let cursor = output.continue_cursor.unwrap();
        handle.drop_query(&cursor.query);
        assert!(matches!(
            handle.handle_iter_continue(cursor, &ALICE_ID),
            Err(Error::Expired)
        ));
    }
    #[test]
    fn stored_tail_byte_ceiling_is_exact_and_dropped_cursor_cannot_continue() {
        let handle = LiveQueryStore::start_test();
        let expected = accounts(2);
        let state = state(&expected, handle.clone());
        let view = state.view();
        let bytes = bounded_bare_encoded_len(&expected[1], u64::MAX).unwrap();
        assert!(matches!(
            request(ordinary(65536, 1, bytes - 1), params(None)).execute(&handle, &view, &ALICE_ID),
            Err(Error::CapacityLimit)
        ));
        let QueryResponse::Iterable(output) = request(ordinary(65536, 1, bytes), params(None))
            .execute(&handle, &view, &ALICE_ID)
            .expect("exact retained value ceiling")
        else {
            panic!("iterable");
        };
        let cursor = output.continue_cursor.unwrap();
        handle.drop_query(&cursor.query);
        assert!(matches!(
            handle.handle_iter_continue(cursor, &ALICE_ID),
            Err(Error::Expired)
        ));
    }
}
