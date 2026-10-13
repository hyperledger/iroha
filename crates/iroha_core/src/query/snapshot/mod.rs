//! Snapshot query execution helpers with telemetry instrumentation.
//!
//! This module centralises snapshot-lane execution so that server-facing callers (Torii, pipeline
//! harnesses, etc.) can reuse the same validation, metrics, and policy enforcement.
use crate::{
    query::store::LiveQueryStoreHandle,
    smartcontracts::isi::query::{
        OrdinaryQueryExecutionLimits, OrdinaryQueryMemoryAdmission, OrdinaryQueryMemoryLease,
        QueryExecutionBudget, QueryLimits, ValidQueryRequest, ensure_ordinary_response_admitted,
        ensure_ordinary_stored_revalidation_admitted,
    },
    state::{State, StateReadOnly},
};
use iroha_data_model::{
    prelude::*,
    query::{QueryRequest, QueryResponse},
};
use std::sync::Arc;
#[cfg(feature = "telemetry")]
use std::time::Instant;
/// Error type for snapshot query lane execution.
#[derive(Debug)]
pub enum SnapshotQueryError {
    /// Validation failed in the executor before running the query.
    Validation(iroha_data_model::ValidationFail),
    /// Query execution failed while producing results.
    Execution(iroha_data_model::query::error::QueryExecutionFail),
}
/// Cursor handling mode for iterable queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorMode {
    /// Return only the first batch; do not store a cursor in the `LiveQueryStore`.
    Ephemeral,
    /// Store a server-side cursor in the `LiveQueryStore` and allow `Continue`.
    Stored,
}
/// Ordinary-query response paired with its move-only server memory lease.
///
/// Torii must keep the lease alive through bounded encoding and the final
/// response or proxy body. If a stored cursor was created, the live-query
/// store independently owns the split retained-state reservation.
#[derive(Debug)]
pub struct ServerOwnedQueryResponse {
    response: QueryResponse,
    memory_lease: OrdinaryQueryMemoryLease,
}
fn drop_response_cursor(live_query_store: &LiveQueryStoreHandle, response: &QueryResponse) {
    if let QueryResponse::Iterable(output) = response
        && let Some(cursor) = &output.continue_cursor
    {
        live_query_store.drop_query(&cursor.query);
    }
}
impl ServerOwnedQueryResponse {
    /// Separate the response from the lease that must cover its remaining
    /// encoding, proxy, and slow-body lifetime.
    #[must_use]
    pub fn into_parts(self) -> (QueryResponse, OrdinaryQueryMemoryLease) {
        (self.response, self.memory_lease)
    }
}
fn revalidate_stored_continuation(
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: &QueryRequest,
    state_ro: &impl StateReadOnly,
    limits: QueryLimits,
) -> Result<(), SnapshotQueryError> {
    let QueryRequest::Continue(cursor) = request else {
        return Ok(());
    };
    let original = if let Some(ordinary) = limits.ordinary_execution_limits() {
        live_query_store
            .ordinary_revalidation_request_bounded(
                cursor,
                authority,
                ordinary.max_revalidation_archive_bytes(),
                ordinary.revalidation_decode_limits(),
            )
            .map_err(SnapshotQueryError::Execution)?
    } else {
        live_query_store
            .revalidation_request(cursor, authority)
            .map_err(SnapshotQueryError::Execution)?
    };
    if let Some(ordinary) = limits.ordinary_execution_limits() {
        ensure_ordinary_stored_revalidation_admitted(&original, limits, ordinary)
            .map_err(SnapshotQueryError::Execution)?;
    }
    ValidQueryRequest::validate_for_client_parts(original, authority, state_ro, limits)
        .map_err(SnapshotQueryError::Validation)?;
    Ok(())
}
/// Execute a query against a point-in-time snapshot of the state with the provided cursor mode
/// and query limits.
///
/// Captures a lightweight query snapshot, validates the query, and executes it. Stored cursor mode
/// persists iterators inside the [`LiveQueryStore`] so subsequent `Continue` requests can resume.
///
/// # Errors
/// Returns a validation error if the request is rejected by the executor, or an execution
/// error if producing results fails.
pub fn run_on_snapshot_with_mode(
    state: &State,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: QueryRequest,
    mode: CursorMode,
    limits: QueryLimits,
) -> Result<QueryResponse, SnapshotQueryError> {
    let view = state.query_view();
    if matches!(mode, CursorMode::Ephemeral) && matches!(request, QueryRequest::Continue(_)) {
        return Err(SnapshotQueryError::Validation(
            ValidationFail::NotPermitted(
                "cursor continuation requires stored cursor mode".to_owned(),
            ),
        ));
    }
    if let (CursorMode::Stored, QueryRequest::Continue(cursor)) = (&mode, &request) {
        let min_gas = view.pipeline().query_stored_min_gas_units;
        if min_gas > 0 && cursor.gas_budget.unwrap_or(0) < min_gas {
            return Err(SnapshotQueryError::Validation(
                ValidationFail::NotPermitted(format!(
                    "stored cursor continuation requires at least {min_gas} gas units"
                )),
            ));
        }
    }
    if matches!(mode, CursorMode::Stored) {
        revalidate_stored_continuation(live_query_store, authority, &request, &view, limits)?;
    }
    let validated = ValidQueryRequest::validate_for_client_parts(request, authority, &view, limits)
        .map_err(SnapshotQueryError::Validation)?;
    #[cfg(feature = "telemetry")]
    let telemetry_start = Instant::now();
    let response = match mode {
        CursorMode::Ephemeral => validated
            .execute_ephemeral(live_query_store, &view, authority)
            .map_err(SnapshotQueryError::Execution)?,
        CursorMode::Stored => validated
            .execute(live_query_store, &view, authority)
            .map_err(SnapshotQueryError::Execution)?,
    };
    #[cfg(feature = "telemetry")]
    {
        let telemetry = view.telemetry;
        if telemetry.is_enabled()
            && let QueryResponse::Iterable(ref output) = response
        {
            let elapsed_ms = telemetry_start.elapsed().as_secs_f64() * 1000.0;
            let mode_label = match mode {
                CursorMode::Ephemeral => "ephemeral",
                CursorMode::Stored => "stored",
            };
            telemetry.observe_snapshot_iterable(mode_label, elapsed_ms, output);
        }
    }
    Ok(response)
}
#[cfg(test)]
/// Execute a query from an owning state handle.
///
/// Stored cursors retain continuation data derived from the initial query view; they never reopen
/// current state to fetch later pages. This gives both the borrowed and Arc-backed Torii paths the
/// same snapshot-consistent result semantics. Current authorization policy is still revalidated
/// separately on every continuation.
///
/// # Errors
/// Returns a validation error if the request is rejected by the executor, or an execution
/// error if producing results fails.
pub fn run_on_snapshot_with_mode_arc(
    state: &Arc<State>,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: QueryRequest,
    mode: CursorMode,
    limits: QueryLimits,
) -> Result<QueryResponse, SnapshotQueryError> {
    run_on_snapshot_with_mode_arc_inner(
        state,
        live_query_store,
        authority,
        request,
        mode,
        limits,
        None,
        false,
        None,
    )
}
/// Execute an Arc-backed snapshot query while carrying the validated client
/// budget for a stored `Start` request into query projection.
///
/// This entry point treats a missing budget as client input and rejects it when the configured
/// stored-query minimum is non-zero.
///
/// # Errors
/// Returns a validation error when the supplied budget is below the configured
/// minimum, or an execution error if producing results fails.
pub fn run_on_snapshot_with_mode_arc_and_start_budget(
    state: &Arc<State>,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: QueryRequest,
    mode: CursorMode,
    limits: QueryLimits,
    stored_start_budget: Option<u64>,
) -> Result<QueryResponse, SnapshotQueryError> {
    run_on_snapshot_with_mode_arc_inner(
        state,
        live_query_store,
        authority,
        request,
        mode,
        limits,
        stored_start_budget,
        true,
        None,
    )
}
/// Execute an Arc-backed query in a server-owned ephemeral lane under an
/// explicit deterministic work budget.
///
/// This entry point never accepts continuations and never inserts an iterator
/// into the live-query store. Canonical fanout behavior remains opt-in through
/// [`QueryLimits::with_canonical_output_limits`].
///
/// # Errors
/// Returns a validation error if the request is invalid or tries to continue a
/// cursor, or an execution error if it exceeds its work/output limits.
pub fn run_on_snapshot_ephemeral_with_budget_arc(
    state: &Arc<State>,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: QueryRequest,
    limits: QueryLimits,
    budget: QueryExecutionBudget,
) -> Result<QueryResponse, SnapshotQueryError> {
    run_on_snapshot_with_mode_arc_inner(
        state,
        live_query_store,
        authority,
        request,
        CursorMode::Ephemeral,
        limits,
        None,
        false,
        Some(budget),
    )
}
/// Execute one ordinary Torii query under a server-owned weighted memory reservation.
///
/// A stored Start reservation contains execution/response headroom `P` plus a cursor-retention
/// charge `R`. Cursor insertion atomically splits `R` into the live-query store. A Continue
/// reservation contains only fresh headroom `P`; the store validates and retains the pre-existing
/// `R` before this function mutates the cursor. No store guard crosses an asynchronous capacity
/// wait: Torii obtains this reservation before entering the blocking worker.
///
/// # Errors
/// Returns a validation error for cursor-mode misuse, or an execution error when admission, query
/// execution, cursor retention, or response preflight exceeds the server-owned limits.
#[allow(clippy::too_many_arguments)]
pub fn run_on_snapshot_with_server_owned_memory_arc(
    state: &Arc<State>,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: QueryRequest,
    mode: CursorMode,
    limits: QueryLimits,
    stored_start_budget: Option<u64>,
    ordinary_limits: OrdinaryQueryExecutionLimits,
    memory_lease: OrdinaryQueryMemoryLease,
) -> Result<ServerOwnedQueryResponse, SnapshotQueryError> {
    let limits = limits.with_ordinary_execution_limits(ordinary_limits);
    let current_cursor_policy = limits
        .ordinary_cursor_policy(memory_lease.pool_generation())
        .expect("ordinary limits were attached above");
    if let QueryRequest::Continue(cursor) = &request {
        if mode != CursorMode::Stored {
            return Err(SnapshotQueryError::Validation(
                ValidationFail::NotPermitted(
                    "cursor continuation requires stored cursor mode".to_owned(),
                ),
            ));
        }
        // This validates opaque query ID, authority, exact cursor position,
        // completed revalidation binding, and the retained cursor lease. The
        // DashMap read guard is dropped before execution begins.
        let binding = live_query_store
            .ordinary_cursor_binding(cursor, authority)
            .map_err(SnapshotQueryError::Execution)?;
        if !binding.is_compatible_with(current_cursor_policy) {
            return Err(SnapshotQueryError::Execution(
                iroha_data_model::query::error::QueryExecutionFail::Expired,
            ));
        }
    }
    let cursor_retained_bytes =
        if mode == CursorMode::Stored && matches!(&request, QueryRequest::Start(_)) {
            ordinary_limits.max_cursor_retained_bytes()
        } else {
            0
        };
    let required_reservation = ordinary_limits
        .execution_headroom_bytes()
        .checked_add(cursor_retained_bytes)
        .ok_or(SnapshotQueryError::Execution(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ))?;
    if memory_lease.reserved_bytes() < required_reservation {
        return Err(SnapshotQueryError::Execution(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ));
    }
    let cursor_policy = (cursor_retained_bytes != 0).then_some(current_cursor_policy);
    let admission =
        OrdinaryQueryMemoryAdmission::new(memory_lease, cursor_retained_bytes, cursor_policy)
            .map_err(SnapshotQueryError::Execution)?;
    let scoped_store = live_query_store.with_ordinary_memory_admission(admission.clone());
    let response = run_on_snapshot_with_mode_arc_inner(
        state,
        &scoped_store,
        authority,
        request,
        mode,
        limits,
        stored_start_budget,
        true,
        Some(ordinary_limits.execution_budget()),
    )?;
    if let Err(error) = ensure_ordinary_response_admitted(&response, ordinary_limits) {
        drop_response_cursor(&scoped_store, &response);
        return Err(SnapshotQueryError::Execution(error));
    }
    let has_cursor = matches!(
        &response,
        QueryResponse::Iterable(output) if output.continue_cursor.is_some()
    );
    let memory_lease = match admission.take_response_lease(!has_cursor) {
        Ok(lease) => lease,
        Err(error) => {
            drop_response_cursor(&scoped_store, &response);
            return Err(SnapshotQueryError::Execution(error));
        }
    };
    Ok(ServerOwnedQueryResponse {
        response,
        memory_lease,
    })
}
#[allow(clippy::too_many_arguments)]
fn run_on_snapshot_with_mode_arc_inner(
    state: &Arc<State>,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: QueryRequest,
    mode: CursorMode,
    limits: QueryLimits,
    stored_start_budget: Option<u64>,
    validate_start_budget: bool,
    execution_budget: Option<QueryExecutionBudget>,
) -> Result<QueryResponse, SnapshotQueryError> {
    let limits = if execution_budget.is_some() {
        limits.with_server_memory_budget()
    } else {
        limits
    };
    let view = state.query_view();
    if matches!(mode, CursorMode::Ephemeral) && matches!(request, QueryRequest::Continue(_)) {
        return Err(SnapshotQueryError::Validation(
            ValidationFail::NotPermitted(
                "cursor continuation requires stored cursor mode".to_owned(),
            ),
        ));
    }
    if let (CursorMode::Stored, QueryRequest::Continue(cursor)) = (&mode, &request) {
        let min_gas = view.pipeline().query_stored_min_gas_units;
        if min_gas > 0 && cursor.gas_budget.unwrap_or(0) < min_gas {
            return Err(SnapshotQueryError::Validation(
                ValidationFail::NotPermitted(format!(
                    "stored cursor continuation requires at least {min_gas} gas units"
                )),
            ));
        }
    }
    if validate_start_budget
        && matches!(mode, CursorMode::Stored)
        && matches!(request, QueryRequest::Start(_))
    {
        let min_gas = view.pipeline().query_stored_min_gas_units;
        if min_gas > 0 && stored_start_budget.unwrap_or(0) < min_gas {
            return Err(SnapshotQueryError::Validation(
                ValidationFail::NotPermitted(format!(
                    "stored cursor start requires at least {min_gas} gas units"
                )),
            ));
        }
    }
    if matches!(mode, CursorMode::Stored) {
        revalidate_stored_continuation(live_query_store, authority, &request, &view, limits)?;
    }
    let validated = ValidQueryRequest::validate_for_client_parts(request, authority, &view, limits)
        .map_err(SnapshotQueryError::Validation)?;
    #[cfg(feature = "telemetry")]
    let telemetry_start = Instant::now();
    let response = match mode {
        CursorMode::Ephemeral => validated
            .execute_ephemeral_with_stats(live_query_store, &view, authority, execution_budget)
            .map(|(response, _)| response)
            .map_err(crate::smartcontracts::isi::query::query_transport_error)
            .map_err(SnapshotQueryError::Execution)?,
        CursorMode::Stored => validated
            .execute_with_replay_state_and_start_budget(
                live_query_store,
                &view,
                authority,
                Arc::downgrade(state),
                stored_start_budget,
            )
            .map_err(SnapshotQueryError::Execution)?,
    };
    #[cfg(feature = "telemetry")]
    {
        let telemetry = view.telemetry;
        if telemetry.is_enabled()
            && let QueryResponse::Iterable(ref output) = response
        {
            let elapsed_ms = telemetry_start.elapsed().as_secs_f64() * 1000.0;
            let mode_label = match mode {
                CursorMode::Ephemeral => "ephemeral",
                CursorMode::Stored => "stored",
            };
            telemetry.observe_snapshot_iterable(mode_label, elapsed_ms, output);
        }
    }
    Ok(response)
}
/// Convenience wrapper for ephemeral cursor semantics.
///
/// # Errors
/// Propagates validation and execution errors from [`run_on_snapshot_with_mode`].
pub fn run_on_snapshot(
    state: &State,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    request: QueryRequest,
    limits: QueryLimits,
) -> Result<QueryResponse, SnapshotQueryError> {
    run_on_snapshot_with_mode(
        state,
        live_query_store,
        authority,
        request,
        CursorMode::Ephemeral,
        limits,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::{cursor::ErasedQueryIterator, store::LiveQueryStore},
        smartcontracts::{
            Execute,
            isi::query::{
                OrdinaryQueryMemoryAdmission, OrdinaryQueryMemoryLease,
                OrdinaryQueryMemoryReservation,
            },
        },
        state::{State, World},
    };
    use iroha_data_model::{
        permission::Permission,
        query::{
            dsl::SelectorTuple,
            parameters::{FetchSize, Pagination, QueryParams, Sorting},
        },
    };
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use mv::storage::StorageReadOnly;
    use nonzero_ext::nonzero;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    /// Commit the query limit through the same typed parameter owner read by queries.
    fn set_stored_query_minimum_for_fixture(state: &State, minimum: u64) {
        let policy = crate::pipeline_validity_policy::PipelineValidityPolicyV1 {
            query_stored_min_gas_units: minimum,
            ..crate::pipeline_validity_policy::PipelineValidityPolicyV1::protocol_default()
        };
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                policy.into_custom_parameter(),
            ))
            .expect("valid committed query policy");
        world.commit();
        assert_eq!(state.view().pipeline().query_stored_min_gas_units, minimum);
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
    #[test]
    fn post_execution_failure_drops_cursor_retention_once() {
        let released = Arc::new(AtomicU64::new(0));
        let ordinary_limits = OrdinaryQueryExecutionLimits::try_new(
            3,
            QueryExecutionBudget::from_weighted_limit(128 * 1_024, 1, 1),
            16,
            64 * 1_024,
            crate::smartcontracts::isi::query::ORDINARY_NAME_ID_SOURCE_BYTES,
            16 * 1_024,
            16,
            16 * crate::smartcontracts::isi::query::ORDINARY_NAME_ID_SOURCE_BYTES,
            32 * 1_024,
            16 * 1_024,
            4 * 1_024,
            norito::DecodeLimits::new(64, 4 * 1_024, 256, 16 * 1_024, 16),
        )
        .expect("test ordinary geometry");
        let cursor_retained_bytes = ordinary_limits.max_cursor_retained_bytes();
        let total = ordinary_limits
            .execution_headroom_bytes()
            .checked_add(cursor_retained_bytes)
            .expect("test reservation");
        let query_limits = QueryLimits::new(16)
            .with_count_mode(crate::smartcontracts::isi::query::QueryCountMode::Bounded)
            .with_ordinary_execution_limits(ordinary_limits);
        let policy = query_limits
            .ordinary_cursor_policy(9)
            .expect("ordinary cursor policy");
        let admission = OrdinaryQueryMemoryAdmission::new(
            OrdinaryQueryMemoryLease::new(TestMemoryReservation {
                bytes: total,
                pool_generation: 9,
                released: Arc::clone(&released),
            }),
            cursor_retained_bytes,
            Some(policy),
        )
        .expect("memory admission");
        let store = LiveQueryStore::start_test();
        let scoped = store.with_ordinary_memory_admission(admission.clone());
        let iter = ErasedQueryIterator::new(
            (0..2).map(|index| Permission::new(format!("permission-{index}"), Json::from(false))),
            SelectorTuple::default(),
            nonzero!(1_u64),
        );
        let output = scoped
            .handle_iter_start(iter, &ALICE_ID, None)
            .expect("cursor start");
        let cursor = output.continue_cursor.clone().expect("stored continuation");
        scoped
            .bind_revalidation_request(&cursor, &ALICE_ID, vec![0xaa])
            .expect("bind archive");
        let response = QueryResponse::Iterable(output);
        drop_response_cursor(&scoped, &response);
        assert_eq!(released.load(Ordering::SeqCst), cursor_retained_bytes);
        assert!(matches!(
            scoped.handle_iter_continue(cursor.clone(), &ALICE_ID),
            Err(iroha_data_model::query::error::QueryExecutionFail::Expired)
        ));
        drop_response_cursor(&scoped, &response);
        assert_eq!(released.load(Ordering::SeqCst), cursor_retained_bytes);
        let response_lease = admission
            .take_response_lease(false)
            .expect("response headroom");
        drop(response_lease);
        assert_eq!(released.load(Ordering::SeqCst), total);
    }
    fn alice_account() -> Account {
        Account::new(ALICE_ID.clone()).build(&ALICE_ID)
    }
    fn find_domains_start(params: QueryParams) -> iroha_data_model::query::QueryRequest {
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let erased = iroha_data_model::query::ErasedIterQuery::<Domain>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            iroha_data_model::query::dsl::SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
        iroha_data_model::query::QueryRequest::Start(
            iroha_data_model::query::QueryWithParams::new(&qbox, params)
                .expect("domain query type has a canonical mapping"),
        )
    }
    fn find_permissions_start(
        account: AccountId,
        params: QueryParams,
    ) -> iroha_data_model::query::QueryRequest {
        let payload = norito::codec::Encode::encode(
            &iroha_data_model::query::permission::prelude::FindPermissionsByAccountId::new(account),
        );
        let erased = iroha_data_model::query::ErasedIterQuery::<Permission>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            iroha_data_model::query::dsl::SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
        iroha_data_model::query::QueryRequest::Start(
            iroha_data_model::query::QueryWithParams::new(&qbox, params)
                .expect("permission query type has a canonical mapping"),
        )
    }
    fn domain_ids_from_batch(
        batch: iroha_data_model::query::QueryOutputBatchBoxTuple,
    ) -> Vec<DomainId> {
        let mut tuple_iter = batch.into_iter();
        match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => {
                v.into_iter().map(|domain| domain.id().clone()).collect()
            }
            other => panic!("unexpected batch variant: {other:?}"),
        }
    }
    #[tokio::test]
    async fn snapshot_iterable_is_ephemeral() {
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1.clone(), d2.clone(), d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, store.clone(), ChainId::from("chain"));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let erased = iroha_data_model::query::ErasedIterQuery::<Domain>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            iroha_data_model::query::dsl::SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
        let qreq = iroha_data_model::query::QueryRequest::Start(
            iroha_data_model::query::QueryWithParams::new(&qbox, params)
                .expect("domain query type has a canonical mapping"),
        );
        let resp = run_on_snapshot(&state, &store, &ALICE_ID, qreq, QueryLimits::default())
            .expect("query ok");
        let iroha_data_model::query::QueryResponse::Iterable(batch) = resp else {
            panic!("expected iterable")
        };
        let (_out, _rem, cursor) = batch.into_parts();
        assert!(cursor.is_none());
    }
    include!("canonical_topk_tests.rs");
    #[tokio::test]
    async fn snapshot_sorted_asset_definitions_returns_first_batch_without_cursor() {
        use iroha_primitives::json::Json;
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let mut ad1 = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let mut ad2 = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "tulip".parse().unwrap(),
            ),
            "tulip".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let ad3 = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "peony".parse().unwrap(),
            ),
            "peony".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        ad1.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        ad2.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        // Listing every definition requires the ledger-wide read root.
        let world = canonical_reader_world(World::with(
            [domain],
            [account],
            [ad1.clone(), ad2.clone(), ad3.clone()],
        ));
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, store.clone(), ChainId::from("chain"));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::by_metadata_key("rank".parse().unwrap()),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(1_u64).into()),
        };
        let payload = norito::codec::Encode::encode(
            &iroha_data_model::query::asset::prelude::FindAssetDefinitions,
        );
        let erased = iroha_data_model::query::ErasedIterQuery::<AssetDefinition>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            iroha_data_model::query::dsl::SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
        let qreq = iroha_data_model::query::QueryRequest::Start(
            iroha_data_model::query::QueryWithParams::new(&qbox, params)
                .expect("asset-definition query type has a canonical mapping"),
        );
        let resp = run_on_snapshot(&state, &store, &ALICE_ID, qreq, QueryLimits::default())
            .expect("query ok");
        let iroha_data_model::query::QueryResponse::Iterable(batch) = resp else {
            panic!("expected iterable")
        };
        let (output, remaining, cursor) = batch.into_parts();
        let defs = match output.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(defs) => defs,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].id(), ad2.id());
        assert_eq!(remaining, 2);
        assert!(cursor.is_none());
    }
    #[tokio::test]
    async fn snapshot_sorted_asset_definitions_stored_cursor_continues_in_order() {
        use iroha_primitives::json::Json;
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let mut ad1 = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let mut ad2 = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "tulip".parse().unwrap(),
            ),
            "tulip".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let ad3 = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "peony".parse().unwrap(),
            ),
            "peony".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        ad1.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        ad2.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        // Listing every definition requires the ledger-wide read root.
        let world = canonical_reader_world(World::with(
            [domain],
            [account],
            [ad1.clone(), ad2.clone(), ad3.clone()],
        ));
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, store.clone(), ChainId::from("chain"));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::by_metadata_key("rank".parse().unwrap()),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(1_u64).into()),
        };
        let payload = norito::codec::Encode::encode(
            &iroha_data_model::query::asset::prelude::FindAssetDefinitions,
        );
        let erased = iroha_data_model::query::ErasedIterQuery::<AssetDefinition>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            iroha_data_model::query::dsl::SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
        let qreq = iroha_data_model::query::QueryRequest::Start(
            iroha_data_model::query::QueryWithParams::new(&qbox, params)
                .expect("asset-definition query type has a canonical mapping"),
        );
        let resp = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            qreq,
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect("query ok");
        let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
            panic!("expected iterable")
        };
        let (output, remaining, cursor) = first.into_parts();
        let defs = match output.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(defs) => defs,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].id(), ad2.id());
        assert_eq!(remaining, 2);
        let cursor = cursor.expect("stored lane must return cursor");
        let next = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect("continuation ok");
        let iroha_data_model::query::QueryResponse::Iterable(next) = next else {
            panic!("expected iterable")
        };
        let (output, remaining, cursor) = next.into_parts();
        let defs = match output.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(defs) => defs,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].id(), ad1.id());
        assert_eq!(remaining, 1);
        assert!(cursor.is_some());
    }
    #[tokio::test]
    async fn snapshot_iterable_continuation_is_snapshot_consistent() {
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1.clone(), d2.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state =
            State::new_with_chain(world, kura.clone(), store.clone(), ChainId::from("chain"));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(1_u64).into()),
        };
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let erased = iroha_data_model::query::ErasedIterQuery::<Domain>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            iroha_data_model::query::dsl::SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
        let req = iroha_data_model::query::QueryRequest::Start(
            iroha_data_model::query::QueryWithParams::new(&qbox, params)
                .expect("domain query type has a canonical mapping"),
        );
        let snapshot_ids: std::collections::BTreeSet<_> = state
            .view()
            .world
            .domains
            .iter()
            .map(|(id, _)| id.clone())
            .collect();
        assert_eq!(snapshot_ids.len(), 2);
        let iroha_data_model::query::QueryResponse::Iterable(first) = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            req,
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect("query ok") else {
            panic!("expected iterable")
        };
        let (batch, _rem, mut cursor) = first.into_parts();
        let mut seen: std::collections::BTreeSet<DomainId> = std::collections::BTreeSet::new();
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        for dom in v {
            seen.insert(dom.id().clone());
        }
        assert!(cursor.is_some(), "should have continuation");
        let header =
            crate::block::ValidBlock::new_dummy(iroha_test_samples::ALICE_KEYPAIR.private_key())
                .as_ref()
                .header();
        let mut sblock = state.block(header);
        let mut stx = sblock.transaction();
        let new_id: DomainId = DomainId::try_new("d3", "universal").unwrap();
        Register::domain(Domain::new(new_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register domain");
        stx.apply();
        let _ = sblock.commit_world_overlay_for_testing();
        while let Some(cur) = cursor.take() {
            let next = store
                .handle_iter_continue(cur, &ALICE_ID)
                .expect("continue ok");
            let (batch, _rem, next_cur) = next.into_parts();
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
                other => panic!("unexpected batch variant: {other:?}"),
            };
            for dom in v {
                seen.insert(dom.id().clone());
            }
            cursor = next_cur;
        }
        assert_eq!(seen, snapshot_ids);
        assert!(!seen.contains(&DomainId::try_new("d3", "universal").unwrap()));
    }
    #[tokio::test]
    async fn bounded_stored_arc_continuation_returns_next_snapshot_page() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1.clone(), d2.clone(), d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let erased = iroha_data_model::query::ErasedIterQuery::<Domain>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            iroha_data_model::query::dsl::SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
        let req = iroha_data_model::query::QueryRequest::Start(
            iroha_data_model::query::QueryWithParams::new(&qbox, params)
                .expect("domain query type has a canonical mapping"),
        );
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                req,
                CursorMode::Stored,
                limits,
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        assert_eq!(first.remaining_items, None);
        assert!(first.has_more);
        let (batch, remaining_hint, cursor) = first.into_parts();
        assert_eq!(remaining_hint, 0);
        let first_domains = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(first_domains, vec![d1, d2]);
        let cursor = cursor.expect("bounded stored cursor");
        let iroha_data_model::query::QueryResponse::Iterable(next) = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            limits,
        )
        .expect("continuation ok") else {
            panic!("expected iterable")
        };
        assert_eq!(next.remaining_items, None);
        assert!(!next.has_more);
        let (batch, remaining_hint, cursor) = next.into_parts();
        assert_eq!(remaining_hint, 0);
        assert!(cursor.is_none());
        let next_domains = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(next_domains, vec![d3]);
    }
    #[tokio::test]
    async fn bounded_stored_arc_wrong_cursor_does_not_consume_original_cursor() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        use std::num::NonZeroU64;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1.clone(), d2.clone(), d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                limits,
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        let (_batch, _remaining_hint, cursor) = first.into_parts();
        let cursor = cursor.expect("bounded stored cursor");
        let mut bad_cursor = cursor.clone();
        bad_cursor.cursor =
            NonZeroU64::new(cursor.cursor.get().saturating_add(1)).expect("non-zero");
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(bad_cursor),
            CursorMode::Stored,
            limits,
        )
        .expect_err("wrong cursor should fail");
        match err {
            SnapshotQueryError::Execution(
                iroha_data_model::query::error::QueryExecutionFail::CursorMismatch,
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
        let iroha_data_model::query::QueryResponse::Iterable(next) = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            limits,
        )
        .expect("original cursor still valid") else {
            panic!("expected iterable")
        };
        let (batch, remaining_hint, cursor) = next.into_parts();
        assert_eq!(remaining_hint, 0);
        assert!(cursor.is_none());
        assert_eq!(domain_ids_from_batch(batch), vec![d3.id]);
    }
    #[tokio::test]
    async fn bounded_stored_arc_forged_or_foreign_cursor_does_not_consume_original() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1, d2, d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                limits,
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        let (_batch, _remaining_hint, cursor) = first.into_parts();
        let cursor = cursor.expect("bounded stored cursor");
        let mut forged = cursor.clone();
        forged.query = format!("{}-forged", forged.query);
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(forged),
            CursorMode::Stored,
            limits,
        )
        .expect_err("unknown query id should expire");
        match err {
            SnapshotQueryError::Execution(
                iroha_data_model::query::error::QueryExecutionFail::Expired,
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &BOB_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor.clone()),
            CursorMode::Stored,
            limits,
        )
        .expect_err("another authority must not continue Alice's cursor");
        match err {
            SnapshotQueryError::Execution(
                iroha_data_model::query::error::QueryExecutionFail::Expired,
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
        let iroha_data_model::query::QueryResponse::Iterable(next) = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            limits,
        )
        .expect("original cursor still valid") else {
            panic!("expected iterable")
        };
        let (batch, _remaining_hint, cursor) = next.into_parts();
        assert!(cursor.is_none());
        assert_eq!(domain_ids_from_batch(batch), vec![d3.id]);
    }
    #[tokio::test]
    async fn arc_ephemeral_continue_with_real_cursor_does_not_consume_it() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1, d2, d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                limits,
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        let (_batch, _remaining_hint, cursor) = first.into_parts();
        let cursor = cursor.expect("bounded stored cursor");
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor.clone()),
            CursorMode::Ephemeral,
            limits,
        )
        .expect_err("ephemeral continuation must fail validation");
        match err {
            SnapshotQueryError::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("stored cursor mode"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let iroha_data_model::query::QueryResponse::Iterable(next) = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            limits,
        )
        .expect("validation failure must not consume cursor") else {
            panic!("expected iterable")
        };
        let (batch, _remaining_hint, cursor) = next.into_parts();
        assert!(cursor.is_none());
        assert_eq!(domain_ids_from_batch(batch), vec![d3.id]);
    }
    #[tokio::test]
    async fn arc_underfunded_continue_with_real_cursor_does_not_consume_it() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1, d2, d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, store.clone(), ChainId::from("chain"));
        set_stored_query_minimum_for_fixture(&state, 10);
        let state = Arc::new(state);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                limits,
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        let (_batch, _remaining_hint, cursor) = first.into_parts();
        let mut cursor = cursor.expect("bounded stored cursor");
        let mut underfunded = cursor.clone();
        underfunded.gas_budget = Some(1);
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(underfunded),
            CursorMode::Stored,
            limits,
        )
        .expect_err("underfunded continuation must fail validation");
        match err {
            SnapshotQueryError::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("gas"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        cursor.gas_budget = Some(10);
        let iroha_data_model::query::QueryResponse::Iterable(next) = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            limits,
        )
        .expect("underfunded validation failure must not consume cursor") else {
            panic!("expected iterable")
        };
        let (batch, _remaining_hint, cursor) = next.into_parts();
        assert!(cursor.is_none());
        assert_eq!(domain_ids_from_batch(batch), vec![d3.id]);
    }
    #[tokio::test]
    async fn arc_stored_start_carries_validated_client_budget_above_minimum() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1, d2, d3], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, store.clone(), ChainId::from("chain"));
        set_stored_query_minimum_for_fixture(&state, 10);
        let state = Arc::new(state);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let err = run_on_snapshot_with_mode_arc_and_start_budget(
            &state,
            &store,
            &ALICE_ID,
            find_domains_start(params.clone()),
            CursorMode::Stored,
            limits,
            Some(9),
        )
        .expect_err("client Start budget below the minimum must be rejected");
        assert!(matches!(
            err,
            SnapshotQueryError::Validation(ValidationFail::NotPermitted(message))
                if message.contains("gas")
        ));
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc_and_start_budget(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                limits,
                Some(25),
            )
            .expect("client Start budget above the minimum must be honored")
        else {
            panic!("expected iterable output");
        };
        assert_eq!(
            first.continue_cursor.expect("stored cursor").gas_budget,
            Some(25),
            "returned cursor must carry the validated client budget"
        );
    }
    #[tokio::test]
    async fn bounded_stored_arc_limit_boundary_returns_no_cursor_despite_extra_rows() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let d4 = Domain::new(DomainId::try_new("d4", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1.clone(), d2.clone(), d3, d4], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let params = QueryParams {
            pagination: Pagination {
                limit: Some(nonzero_ext::nonzero!(2_u64)),
                offset: 0,
            },
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        assert_eq!(first.remaining_items, None);
        assert!(!first.has_more);
        let (batch, remaining_hint, cursor) = first.into_parts();
        assert_eq!(remaining_hint, 0);
        assert!(cursor.is_none());
        assert_eq!(domain_ids_from_batch(batch), vec![d1.id, d2.id]);
    }
    #[tokio::test]
    async fn bounded_stored_arc_cursor_excludes_later_state_on_continue() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1, d2, d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                limits,
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        let (_batch, _remaining_hint, cursor) = first.into_parts();
        let cursor = cursor.expect("bounded stored cursor");
        let d4_id = DomainId::try_new("d4", "universal").unwrap();
        let header =
            crate::block::ValidBlock::new_dummy(iroha_test_samples::ALICE_KEYPAIR.private_key())
                .as_ref()
                .header();
        let mut sblock = state.block(header);
        let mut stx = sblock.transaction();
        Register::domain(Domain::new(d4_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register domain");
        stx.apply();
        let _ = sblock.commit_world_overlay_for_testing();
        let iroha_data_model::query::QueryResponse::Iterable(next) = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            limits,
        )
        .expect("continuation ok") else {
            panic!("expected iterable")
        };
        let (batch, _remaining_hint, cursor) = next.into_parts();
        assert!(cursor.is_none());
        assert_eq!(domain_ids_from_batch(batch), vec![d3.id]);
    }
    #[tokio::test]
    async fn stored_account_cursor_revalidates_exact_grant_without_advancing_on_denial() {
        let exact: Permission = iroha_executor_data_model::permission::query::CanReadAccountData {
            account: BOB_ID.clone(),
        }
        .into();
        let bob_permissions = std::collections::BTreeSet::from([
            Permission::new(
                "cursor-page-a".to_owned(),
                iroha_primitives::json::Json::new(()),
            ),
            Permission::new(
                "cursor-page-b".to_owned(),
                iroha_primitives::json::Json::new(()),
            ),
            Permission::new(
                "cursor-page-c".to_owned(),
                iroha_primitives::json::Json::new(()),
            ),
        ]);
        let expected_permissions = bob_permissions.iter().cloned().collect::<Vec<_>>();
        let mut world = World::with(
            [],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
            ],
            [],
        );
        world.account_permissions.insert(
            ALICE_ID.clone(),
            std::collections::BTreeSet::from([exact.clone()]),
        );
        world
            .account_permissions
            .insert(BOB_ID.clone(), bob_permissions.clone());
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            store.clone(),
            ChainId::from("account-cursor-revalidation"),
        );
        let params = QueryParams {
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(1_u64).into()),
            ..QueryParams::default()
        };
        let QueryResponse::Iterable(first) = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            find_permissions_start(BOB_ID.clone(), params),
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect("the exact direct grant must authorize the stored Start") else {
            panic!("expected iterable response")
        };
        let (first_batch, _, first_cursor) = first.into_parts();
        let first_permission = match first_batch.into_iter().next().expect("permission slice") {
            iroha_data_model::query::QueryOutputBatchBox::Permission(permissions) => {
                assert_eq!(permissions.len(), 1);
                permissions.into_iter().next().expect("first permission")
            }
            other => panic!("unexpected permission batch: {other:?}"),
        };
        let first_cursor = first_cursor.expect("three permissions require a continuation");
        assert_eq!(
            first_permission, expected_permissions[0],
            "the first stored page must match the canonical permission order"
        );
        let mut block = state.block(BlockHeader::new(
            nonzero_ext::nonzero!(1_u64),
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        Revoke::account_permission(exact.clone(), ALICE_ID.clone())
            .execute(&BOB_ID, &mut transaction)
            .expect("revoke exact direct reader grant");
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit explicit test world overlay");
        let denied = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            QueryRequest::Continue(first_cursor.clone()),
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect_err("continuation must revalidate the archived Start request");
        assert!(matches!(denied, SnapshotQueryError::Validation(
            ValidationFail::NotPermitted(message)
        ) if message.contains("CanReadAccountData")));
        let role_id: RoleId = "cursor_account_reader".parse().expect("role id");
        let mut block = state.block(BlockHeader::new(
            nonzero_ext::nonzero!(2_u64),
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        Register::role(Role::new(role_id.clone(), ALICE_ID.clone()).add_permission(exact.clone()))
            .execute(&ALICE_ID, &mut transaction)
            .expect("restore the exact reader through an assigned role");
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit explicit test world overlay");
        let QueryResponse::Iterable(second) = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            QueryRequest::Continue(first_cursor),
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect("the same cursor must remain usable after authorization is restored") else {
            panic!("expected iterable response")
        };
        let (second_batch, _, second_cursor) = second.into_parts();
        let second_permission = match second_batch.into_iter().next().expect("permission slice") {
            iroha_data_model::query::QueryOutputBatchBox::Permission(permissions) => {
                assert_eq!(permissions.len(), 1);
                permissions.into_iter().next().expect("second permission")
            }
            other => panic!("unexpected permission batch: {other:?}"),
        };
        assert_eq!(
            second_permission, expected_permissions[1],
            "the denied continuation must not consume the second page"
        );
        let second_cursor = second_cursor.expect("one archived page must remain");
        let mut block = state.block(BlockHeader::new(
            nonzero_ext::nonzero!(3_u64),
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        Unregister::account(BOB_ID.clone())
            .execute(&BOB_ID, &mut transaction)
            .expect("unregister the account whose private data was delegated");
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit explicit test world overlay");
        let view = state.view();
        let role = view.world.roles.get(&role_id).expect("reader role remains");
        assert!(!role.permissions().any(|permission| permission == &exact));
        assert!(!role.permission_epochs().contains_key(&exact));
        drop(view);
        let denied = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            QueryRequest::Continue(second_cursor),
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect_err("account removal must purge grants before continuation revalidation");
        assert!(matches!(denied, SnapshotQueryError::Validation(
            ValidationFail::NotPermitted(message)
        ) if message.contains("CanReadAccountData")));
    }
    #[tokio::test]
    async fn arc_ephemeral_continue_is_rejected_before_store_lookup() {
        let d = Domain::new(DomainId::try_new("lane", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let cursor = iroha_data_model::query::parameters::ForwardCursor {
            query: "missing".to_owned(),
            cursor: nonzero_ext::nonzero!(1_u64),
            gas_budget: None,
        };
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Ephemeral,
            QueryLimits::default(),
        )
        .expect_err("ephemeral continuation must fail validation");
        match err {
            SnapshotQueryError::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("stored cursor mode"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[tokio::test]
    async fn arc_stored_cursor_requires_budget_before_store_lookup() {
        let d = Domain::new(DomainId::try_new("lane", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, store.clone(), ChainId::from("chain"));
        set_stored_query_minimum_for_fixture(&state, 10);
        let state = Arc::new(state);
        let cursor = iroha_data_model::query::parameters::ForwardCursor {
            query: "missing".to_owned(),
            cursor: nonzero_ext::nonzero!(1_u64),
            gas_budget: Some(1),
        };
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect_err("underfunded stored continuation must fail validation");
        match err {
            SnapshotQueryError::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("gas"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[tokio::test]
    async fn arc_stored_missing_cursor_with_sufficient_budget_reaches_store_and_expires() {
        let d = Domain::new(DomainId::try_new("lane", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, store.clone(), ChainId::from("chain"));
        set_stored_query_minimum_for_fixture(&state, 10);
        let state = Arc::new(state);
        let cursor = iroha_data_model::query::parameters::ForwardCursor {
            query: "missing".to_owned(),
            cursor: nonzero_ext::nonzero!(1_u64),
            gas_budget: Some(10),
        };
        let err = run_on_snapshot_with_mode_arc(
            &state,
            &store,
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Continue(cursor),
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect_err("missing stored cursor should reach the store and expire");
        match err {
            SnapshotQueryError::Execution(
                iroha_data_model::query::error::QueryExecutionFail::Expired,
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[tokio::test]
    async fn bounded_stored_arc_cursor_owns_snapshot_after_state_is_dropped() {
        use crate::smartcontracts::isi::query::QueryCountMode;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d1, d2, d3], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = Arc::new(State::new_with_chain(
            world,
            kura,
            store.clone(),
            ChainId::from("chain"),
        ));
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let iroha_data_model::query::QueryResponse::Iterable(first) =
            run_on_snapshot_with_mode_arc(
                &state,
                &store,
                &ALICE_ID,
                find_domains_start(params),
                CursorMode::Stored,
                QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
            )
            .expect("query ok")
        else {
            panic!("expected iterable")
        };
        let (_batch, _remaining_hint, cursor) = first.into_parts();
        let cursor = cursor.expect("bounded stored cursor");
        drop(state);
        let next = store
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect("stored snapshot does not borrow the state");
        let (batch, remaining, cursor) = next.into_parts();
        assert_eq!(remaining, 0);
        assert!(cursor.is_none());
        assert_eq!(
            domain_ids_from_batch(batch),
            vec![DomainId::try_new("d3", "universal").unwrap()]
        );
    }
    #[tokio::test]
    async fn snapshot_singular_find_parameters_smoke() {
        let d = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let a = alice_account();
        let world = World::with([d], [a], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new(world, kura, store.clone());
        let req = iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::prelude::FindParameters.into(),
        );
        let resp = run_on_snapshot(&state, &store, &ALICE_ID, req, QueryLimits::default())
            .expect("query ok");
        let iroha_data_model::query::QueryResponse::Singular(out) = resp else {
            panic!("expected singular")
        };
        match &out {
            iroha_data_model::query::SingularQueryOutputBox::Parameters(_p) => {}
            other => panic!("expected Parameters, got {other:?}"),
        }
    }
    #[tokio::test]
    async fn stored_cursor_requires_budget_on_continue() {
        let d = Domain::new(DomainId::try_new("lane", "universal").unwrap()).build(&ALICE_ID);
        let account = alice_account();
        let world = World::with([d], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = LiveQueryStore::start_test();
        let state = State::new(world, kura, store.clone());
        set_stored_query_minimum_for_fixture(&state, 10);
        let cursor = iroha_data_model::query::parameters::ForwardCursor {
            query: "q".to_owned(),
            cursor: nonzero_ext::nonzero!(1_u64),
            gas_budget: Some(1),
        };
        let req = QueryRequest::Continue(cursor);
        let err = run_on_snapshot_with_mode(
            &state,
            &store,
            &ALICE_ID,
            req,
            CursorMode::Stored,
            QueryLimits::default(),
        )
        .expect_err("validation should fail");
        match err {
            SnapshotQueryError::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("gas"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
