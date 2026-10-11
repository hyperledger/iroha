//! Server-owned memory admission for ordinary Torii queries.
//!
//! This module is deliberately opt-in. IVM and other in-process callers keep the existing query
//! behavior unless they attach [`OrdinaryQueryExecutionLimits`] to [`super::QueryLimits`]. Torii
//! admits every singular producer only with the source-specific preflight and output limits
//! installed below. Iterable admission is coupled to source-specific immutable-world adapters in
//! `ordinary_iterable` before a query implementation can clone any row.
use super::{QueryCountMode, QueryExecutionBudget, QueryLimits, STREAMING_SORTED_PREFIX_LIMIT};
use crate::state::{StateReadOnly, WorldReadOnly};
use iroha_data_model::{
    query::{
        QueryRequest, QueryResponse, SingularQueryBox, error::QueryExecutionFail as Error,
        parameters::QueryParams,
    },
    sns::{NameSelectorV1, SuffixId},
};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly as _;
use norito::core::{DecodeFlagsGuard, SerializePayload};
use std::{
    fmt,
    str::FromStr,
    sync::{Arc, Mutex},
};
/// Conservative resident charge for one name-backed identifier source row.
///
/// `Name` is protocol-limited to 255 bytes. The additional allowance covers
/// the owned string, the identifier wrapper, and allocator bookkeeping before
/// post-processing can measure the exact encoded row.
pub const ORDINARY_NAME_ID_SOURCE_BYTES: u64 = 1_024;
/// Conservative resident charge for the fixed-width ABI-version result.
pub const ORDINARY_ABI_VERSION_SOURCE_BYTES: u64 = 64;
/// Fixed resident charge for query/cursor containers, allocator metadata, and
/// move-only ownership tokens that do not scale with the result count.
pub const ORDINARY_QUERY_FIXED_CONTAINER_OVERHEAD_BYTES: u64 = 4 * 1_024;
/// Conservative resident charge for each slot in a page or retained cursor.
///
/// This is deliberately separate from the source-value charge. It covers the
/// `Vec` slot, enum/tuple wrappers, iterator bookkeeping, and allocator
/// metadata that remain live alongside the value itself.
pub const ORDINARY_QUERY_RETAINED_ITEM_OVERHEAD_BYTES: u64 = 128;
/// The admitted peer adapter measures once, then owns the bounded prefix in a
/// second immutable-world pass.
const ORDINARY_SOURCE_SCAN_PASSES: u64 = 2;
/// One row is traversed once for its exact length and twice by the canonical
/// writer in each of the two source passes.
const ORDINARY_SOURCE_FRAME_TRAVERSALS: u64 = 6;
/// Fixed failure categories for invalid ordinary-query memory geometry.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OrdinaryQueryExecutionLimitError {
    /// A page cannot contain zero items because bounded scans need an `F + 1` continuation probe.
    ZeroPageItems,
    /// A checked geometry calculation overflowed.
    GeometryOverflow,
    /// Neither items nor source bytes consume deterministic work units.
    UnmeteredExecutionBudget,
    /// The deterministic execution budget cannot cover both immutable-source
    /// passes for one full page plus its continuation probe and response.
    ExecutionBudgetTooSmall,
    /// The retained request-graph ceiling exceeds the schema-audited allocation
    /// ceiling used when replaying its canonical Start archive.
    RequestGraphExceedsDecodeLimit,
    /// The configured peak reservation does not cover source, page, response, and encoding overlap.
    ExecutionHeadroomTooSmall,
    /// The configured cursor reservation does not cover retained values, the
    /// archived Start request, and deterministic container overhead.
    CursorRetentionTooSmall,
}
impl fmt::Display for OrdinaryQueryExecutionLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroPageItems => "ordinary query page size must be non-zero",
            Self::GeometryOverflow => "ordinary query memory geometry overflowed",
            Self::UnmeteredExecutionBudget => {
                "ordinary query execution budget must charge items or source bytes"
            }
            Self::ExecutionBudgetTooSmall => {
                "ordinary query execution budget cannot cover two source passes, probe, and response"
            }
            Self::RequestGraphExceedsDecodeLimit => {
                "ordinary query request graph exceeds its replay decode limit"
            }
            Self::ExecutionHeadroomTooSmall => {
                "ordinary query execution headroom is below the required phase envelope"
            }
            Self::CursorRetentionTooSmall => {
                "ordinary query cursor reservation is below the required retained envelope"
            }
        };
        f.write_str(message)
    }
}
impl std::error::Error for OrdinaryQueryExecutionLimitError {}
/// A weighted reservation owned by the embedding server.
///
/// Core never assumes how the reservation is implemented. Torii may back it with a weighted byte
/// pool, while tests may use a counter. Splitting must be allocation-accounting neutral: the
/// returned reservation owns `bytes`, the receiver owns that many fewer bytes, and the aggregate
/// reserved weight must not change until either reservation is dropped.
pub trait OrdinaryQueryMemoryReservation: fmt::Debug + Send + Sync + 'static {
    /// Number of aggregate pool bytes represented by this reservation.
    fn reserved_bytes(&self) -> u64;
    /// Generation of the embedding server's weighted memory pool.
    ///
    /// Pool replacement or reconfiguration must advance this value. Every
    /// child returned by [`Self::split_off`] must report the same generation.
    fn pool_generation(&self) -> u64;
    /// Transfer `bytes` from this reservation into a new independently releasable reservation.
    ///
    /// Returning `None` must leave this reservation unchanged.
    fn split_off(&mut self, bytes: u64) -> Option<Box<dyn OrdinaryQueryMemoryReservation>>;
}
/// Move-only semantic ownership token for ordinary-query resident memory.
///
/// A token is moved through worker execution and response encoding. Stored
/// cursors own a split token for their complete lifetime; response bodies own
/// the remaining headroom until the last slow-body reference is dropped.
pub struct OrdinaryQueryMemoryLease {
    reservation: Box<dyn OrdinaryQueryMemoryReservation>,
}
impl OrdinaryQueryMemoryLease {
    /// Wrap an embedding-server weighted reservation.
    pub fn new(reservation: impl OrdinaryQueryMemoryReservation) -> Self {
        Self {
            reservation: Box::new(reservation),
        }
    }
    /// Return the aggregate pool weight owned by this token.
    #[must_use]
    pub fn reserved_bytes(&self) -> u64 {
        self.reservation.reserved_bytes()
    }
    /// Return the weighted-pool generation that owns this token.
    #[must_use]
    pub fn pool_generation(&self) -> u64 {
        self.reservation.pool_generation()
    }
    /// Split an independently releasable child token from this token.
    pub(crate) fn split_off(&mut self, bytes: u64) -> Option<Self> {
        if bytes == 0 {
            return None;
        }
        let pool_generation = self.pool_generation();
        let reservation = self.reservation.split_off(bytes)?;
        if reservation.pool_generation() != pool_generation {
            drop(reservation);
            return None;
        }
        Some(Self { reservation })
    }
}
impl fmt::Debug for OrdinaryQueryMemoryLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrdinaryQueryMemoryLease")
            .field("reserved_bytes", &self.reserved_bytes())
            .field("pool_generation", &self.pool_generation())
            .finish_non_exhaustive()
    }
}
/// Server-owned limits for one ordinary Torii query execution.
///
/// Encoded-byte ceilings are deterministic codec work limits, not estimates
/// of Rust heap usage. The embedding server's weighted reservation separately
/// covers the conservative resident phase envelope.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct OrdinaryQueryExecutionLimits {
    policy_generation: u64,
    execution_budget: QueryExecutionBudget,
    max_page_items: u64,
    execution_headroom_bytes: u64,
    max_source_item_bytes: u64,
    max_response_bytes: u64,
    max_cursor_retained_items: u64,
    max_cursor_value_bytes: u64,
    max_cursor_retained_bytes: u64,
    max_revalidation_archive_bytes: u64,
    max_request_graph_bytes: u64,
    revalidation_decode_limits: norito::DecodeLimits,
}
impl OrdinaryQueryExecutionLimits {
    /// Construct and validate the complete Core-side limit set.
    ///
    /// `execution_headroom_bytes` and `max_cursor_retained_bytes` are accepted reservations, not
    /// independent tuning knobs: construction fails unless they cover the checked phase envelopes
    /// returned by [`Self::required_execution_headroom_bytes`] and
    /// [`Self::required_cursor_retained_bytes`].
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        policy_generation: u64,
        execution_budget: QueryExecutionBudget,
        max_page_items: u64,
        execution_headroom_bytes: u64,
        max_source_item_bytes: u64,
        max_response_bytes: u64,
        max_cursor_retained_items: u64,
        max_cursor_value_bytes: u64,
        max_cursor_retained_bytes: u64,
        max_request_graph_bytes: u64,
        max_revalidation_archive_bytes: u64,
        revalidation_decode_limits: norito::DecodeLimits,
    ) -> Result<Self, OrdinaryQueryExecutionLimitError> {
        if max_page_items == 0 {
            return Err(OrdinaryQueryExecutionLimitError::ZeroPageItems);
        }
        if execution_budget.units_per_item == 0 && execution_budget.units_per_byte == 0 {
            return Err(OrdinaryQueryExecutionLimitError::UnmeteredExecutionBudget);
        }
        let page_with_probe = max_page_items
            .checked_add(1)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let source_items = page_with_probe
            .checked_mul(ORDINARY_SOURCE_SCAN_PASSES)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let probe_source_bytes = page_with_probe
            .checked_mul(max_source_item_bytes)
            .and_then(|bytes| bytes.checked_mul(ORDINARY_SOURCE_FRAME_TRAVERSALS))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let complete_bytes = probe_source_bytes
            .checked_add(max_response_bytes)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        execution_budget
            .ensure(source_items, complete_bytes)
            .map_err(|_| OrdinaryQueryExecutionLimitError::ExecutionBudgetTooSmall)?;
        let revalidation_graph_bytes =
            u64::try_from(revalidation_decode_limits.max_total_allocated_bytes())
                .map_err(|_| OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        if max_request_graph_bytes > revalidation_graph_bytes {
            return Err(OrdinaryQueryExecutionLimitError::RequestGraphExceedsDecodeLimit);
        }
        let required_execution = Self::required_execution_headroom_bytes(
            max_page_items,
            max_source_item_bytes,
            max_response_bytes,
            max_request_graph_bytes,
            max_revalidation_archive_bytes,
            revalidation_decode_limits,
        )?;
        if execution_headroom_bytes < required_execution {
            return Err(OrdinaryQueryExecutionLimitError::ExecutionHeadroomTooSmall);
        }
        let required_cursor = Self::required_cursor_retained_bytes(
            max_cursor_retained_items,
            max_source_item_bytes,
            max_cursor_value_bytes,
            max_revalidation_archive_bytes,
        )?;
        if max_cursor_retained_bytes < required_cursor {
            return Err(OrdinaryQueryExecutionLimitError::CursorRetentionTooSmall);
        }
        Ok(Self {
            policy_generation,
            execution_budget,
            max_page_items,
            execution_headroom_bytes,
            max_source_item_bytes,
            max_response_bytes,
            max_cursor_retained_items,
            max_cursor_value_bytes,
            max_cursor_retained_bytes,
            max_revalidation_archive_bytes,
            max_request_graph_bytes,
            revalidation_decode_limits,
        })
    }
    /// Compute the minimum fresh execution reservation for the decoded request, source/work, page
    /// materialization, response ownership, and encoding overlap.
    ///
    /// The decoded request graph is bounded by the same server-supplied allocation ceiling used to
    /// decode a canonical Start archive. Stored Start execution concurrently owns its canonical
    /// archive, but that archive is already included in [`Self::required_cursor_retained_bytes`];
    /// Torii reserves both returned parts before decoding or execution begins.
    pub fn required_execution_headroom_bytes(
        max_page_items: u64,
        max_source_item_bytes: u64,
        max_response_bytes: u64,
        max_request_graph_bytes: u64,
        max_revalidation_archive_bytes: u64,
        revalidation_decode_limits: norito::DecodeLimits,
    ) -> Result<u64, OrdinaryQueryExecutionLimitError> {
        let replay_graph_limit =
            u64::try_from(revalidation_decode_limits.max_total_allocated_bytes())
                .map_err(|_| OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        if max_request_graph_bytes > replay_graph_limit {
            return Err(OrdinaryQueryExecutionLimitError::RequestGraphExceedsDecodeLimit);
        }
        let page_with_probe = max_page_items
            .checked_add(1)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let source_work = page_with_probe
            .checked_mul(max_source_item_bytes)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let owned_page_values = max_page_items
            .checked_mul(max_source_item_bytes)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let page_container = max_page_items
            .checked_mul(ORDINARY_QUERY_RETAINED_ITEM_OVERHEAD_BYTES)
            .and_then(|bytes| bytes.checked_add(ORDINARY_QUERY_FIXED_CONTAINER_OVERHEAD_BYTES))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let request_inline = u64::try_from(core::mem::size_of::<QueryRequest>())
            .map_err(|_| OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let request_graph = max_request_graph_bytes
            .checked_add(request_inline)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        // The Start request remains live while its exact (Q, T) source plan is
        // consumed and while the first page is materialized. The response frame
        // is encoded only after that request and the source iterator are gone.
        let source_phase = request_graph
            .checked_add(source_work)
            .and_then(|bytes| bytes.checked_add(owned_page_values))
            .and_then(|bytes| bytes.checked_add(page_container))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        // Selector projection begins only after the immutable source iterator
        // is dropped, but the unprojected page remains live until the projected
        // page is complete. Both page-value representations therefore belong
        // to fresh execution headroom.
        let selector_phase = request_graph
            .checked_add(owned_page_values)
            .and_then(|bytes| bytes.checked_add(owned_page_values))
            .and_then(|bytes| bytes.checked_add(page_container))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let response_phase = owned_page_values
            .checked_add(page_container)
            .and_then(|bytes| bytes.checked_add(max_response_bytes))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        // On `Continue`, the retained archive remains charged to `R` while a
        // decoded Start request and its bounded canonical re-encode coexist in
        // fresh headroom `P`. Revalidation completes before source execution,
        // so the required peak is the larger phase rather than their sum.
        let revalidation_phase = max_revalidation_archive_bytes
            .checked_add(request_graph)
            .and_then(|bytes| bytes.checked_add(ORDINARY_QUERY_FIXED_CONTAINER_OVERHEAD_BYTES))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        Ok(source_phase
            .max(selector_phase)
            .max(response_phase)
            .max(revalidation_phase))
    }
    /// Compute the minimum retained reservation `R` for cursor values, the
    /// canonical Start archive, and deterministic container overhead.
    pub fn required_cursor_retained_bytes(
        max_cursor_retained_items: u64,
        max_source_item_bytes: u64,
        max_cursor_value_bytes: u64,
        max_revalidation_archive_bytes: u64,
    ) -> Result<u64, OrdinaryQueryExecutionLimitError> {
        let resident_values = max_cursor_retained_items
            .checked_mul(max_source_item_bytes)
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        let retained_value_envelope = resident_values.max(max_cursor_value_bytes);
        let container = max_cursor_retained_items
            .checked_mul(ORDINARY_QUERY_RETAINED_ITEM_OVERHEAD_BYTES)
            .and_then(|bytes| bytes.checked_add(ORDINARY_QUERY_FIXED_CONTAINER_OVERHEAD_BYTES))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)?;
        retained_value_envelope
            .checked_add(max_revalidation_archive_bytes)
            .and_then(|bytes| bytes.checked_add(container))
            .ok_or(OrdinaryQueryExecutionLimitError::GeometryOverflow)
    }
    /// Configuration generation that produced this policy.
    #[must_use]
    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
    /// Deterministic work budget applied while producing an ephemeral page.
    #[must_use]
    pub const fn execution_budget(self) -> QueryExecutionBudget {
        self.execution_budget
    }
    /// Maximum response-page item count covered by the peak geometry.
    #[must_use]
    pub const fn max_page_items(self) -> u64 {
        self.max_page_items
    }
    /// Weighted resident bytes required in addition to any stored cursor.
    #[must_use]
    pub const fn execution_headroom_bytes(self) -> u64 {
        self.execution_headroom_bytes
    }
    /// Maximum resident bytes allowed for one source row before exact sizing.
    #[must_use]
    pub const fn max_source_item_bytes(self) -> u64 {
        self.max_source_item_bytes
    }
    /// Maximum canonical preflight and final HTTP response-body bytes.
    ///
    /// Core checks the canonical Norito frame before returning ownership;
    /// Torii applies the same ceiling to its negotiated checked JSON body.
    #[must_use]
    pub const fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }
    /// Maximum values retained by one stored cursor.
    #[must_use]
    pub const fn max_cursor_retained_items(self) -> u64 {
        self.max_cursor_retained_items
    }
    /// Maximum encoded bytes occupied by retained cursor values.
    #[must_use]
    pub const fn max_cursor_value_bytes(self) -> u64 {
        self.max_cursor_value_bytes
    }
    /// Aggregate weighted charge split into a stored cursor token.
    #[must_use]
    pub const fn max_cursor_retained_bytes(self) -> u64 {
        self.max_cursor_retained_bytes
    }
    /// Maximum canonical request archive retained for continuation revalidation.
    #[must_use]
    pub const fn max_revalidation_archive_bytes(self) -> u64 {
        self.max_revalidation_archive_bytes
    }
    /// Maximum allocator-owned graph retained by one decoded Start request.
    ///
    /// This is the embedding server's measured decode-allocation ceiling, not
    /// an estimate derived from an item discriminant or encoded byte length.
    #[must_use]
    pub const fn max_request_graph_bytes(self) -> u64 {
        self.max_request_graph_bytes
    }
    /// Schema-audited limits for decoding a stored Start archive during continuation revalidation.
    #[must_use]
    pub const fn revalidation_decode_limits(self) -> norito::DecodeLimits {
        self.revalidation_decode_limits
    }
}
/// Immutable policy identity archived alongside one ordinary stored cursor.
///
/// Exact equality is intentional. A continuation may not combine retained memory admitted under an
/// old configuration with execution headroom from a different policy or weighted-pool generation,
/// even when the new values look individually wider.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct OrdinaryQueryCursorPolicy {
    limits: OrdinaryQueryExecutionLimits,
    max_fetch_size: u64,
    count_mode: QueryCountMode,
    pool_generation: u64,
}
impl OrdinaryQueryCursorPolicy {
    pub(crate) const fn new(
        limits: OrdinaryQueryExecutionLimits,
        max_fetch_size: u64,
        count_mode: QueryCountMode,
        pool_generation: u64,
    ) -> Self {
        Self {
            limits,
            max_fetch_size,
            count_mode,
            pool_generation,
        }
    }
    pub(crate) const fn pool_generation(self) -> u64 {
        self.pool_generation
    }
    pub(crate) const fn retained_bytes(self) -> u64 {
        self.limits.max_cursor_retained_bytes()
    }
}
/// Move-only retained cursor memory and the exact policy that admitted it.
#[derive(Debug)]
pub(crate) struct OrdinaryQueryCursorMemory {
    lease: OrdinaryQueryMemoryLease,
    policy: OrdinaryQueryCursorPolicy,
}
impl OrdinaryQueryCursorMemory {
    fn new(lease: OrdinaryQueryMemoryLease, policy: OrdinaryQueryCursorPolicy) -> Option<Self> {
        if lease.pool_generation() != policy.pool_generation()
            || lease.reserved_bytes() < policy.retained_bytes()
        {
            return None;
        }
        Some(Self { lease, policy })
    }
    pub(crate) fn binding(&self) -> OrdinaryQueryCursorBinding {
        OrdinaryQueryCursorBinding {
            retained_bytes: self.lease.reserved_bytes(),
            policy: self.policy,
        }
    }
}
/// Copyable continuation admission facts returned without leaking a map guard.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct OrdinaryQueryCursorBinding {
    retained_bytes: u64,
    policy: OrdinaryQueryCursorPolicy,
}
impl OrdinaryQueryCursorBinding {
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }
    pub(crate) fn is_compatible_with(self, current: OrdinaryQueryCursorPolicy) -> bool {
        self.policy == current && self.retained_bytes >= current.retained_bytes()
    }
}
/// Shared mutable ownership used only while a Start request may split a cursor
/// reservation from its admitted peak reservation.
///
/// The mutex is never held while waiting for capacity or while executing a
/// query. It protects one synchronous `split_off`/`take` handoff because
/// [`crate::query::store::LiveQueryStoreHandle`] methods accept `&self`.
#[derive(Clone, Debug)]
pub(crate) struct OrdinaryQueryMemoryAdmission {
    state: Arc<Mutex<OrdinaryQueryMemoryAdmissionState>>,
    cursor_retained_bytes: u64,
    cursor_policy: Option<OrdinaryQueryCursorPolicy>,
}
#[derive(Debug)]
struct OrdinaryQueryMemoryAdmissionState {
    lease: Option<OrdinaryQueryMemoryLease>,
    cursor_split: bool,
}
impl OrdinaryQueryMemoryAdmission {
    pub(crate) fn new(
        lease: OrdinaryQueryMemoryLease,
        cursor_retained_bytes: u64,
        cursor_policy: Option<OrdinaryQueryCursorPolicy>,
    ) -> Result<Self, Error> {
        let cursor_policy_invalid = match cursor_policy {
            Some(policy) => {
                cursor_retained_bytes == 0
                    || policy.retained_bytes() != cursor_retained_bytes
                    || policy.pool_generation() != lease.pool_generation()
            }
            None => cursor_retained_bytes != 0,
        };
        if lease.reserved_bytes() < cursor_retained_bytes || cursor_policy_invalid {
            return Err(Error::CapacityLimit);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(OrdinaryQueryMemoryAdmissionState {
                lease: Some(lease),
                cursor_split: false,
            })),
            cursor_retained_bytes,
            cursor_policy,
        })
    }
    pub(crate) fn split_cursor_lease(&self) -> Result<OrdinaryQueryCursorMemory, Error> {
        let mut state = self.state.lock().map_err(|_| Error::CapacityLimit)?;
        if state.cursor_split {
            return Err(Error::CapacityLimit);
        }
        let cursor_lease = state
            .lease
            .as_mut()
            .and_then(|lease| lease.split_off(self.cursor_retained_bytes))
            .ok_or(Error::CapacityLimit)?;
        let policy = self.cursor_policy.ok_or(Error::CapacityLimit)?;
        let cursor_memory =
            OrdinaryQueryCursorMemory::new(cursor_lease, policy).ok_or(Error::CapacityLimit)?;
        state.cursor_split = true;
        Ok(cursor_memory)
    }
    pub(crate) fn take_response_lease(
        &self,
        release_unused_cursor_charge: bool,
    ) -> Result<OrdinaryQueryMemoryLease, Error> {
        let mut state = self.state.lock().map_err(|_| Error::CapacityLimit)?;
        if release_unused_cursor_charge && state.cursor_split {
            return Err(Error::CapacityLimit);
        }
        let mut lease = state.lease.take().ok_or(Error::CapacityLimit)?;
        if release_unused_cursor_charge && self.cursor_retained_bytes != 0 {
            drop(
                lease
                    .split_off(self.cursor_retained_bytes)
                    .ok_or(Error::CapacityLimit)?,
            );
        }
        Ok(lease)
    }
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum OrdinaryCursorMode {
    Ephemeral,
    Stored,
}
pub(super) fn ensure_request_admitted(
    request: &QueryRequest,
    mode: OrdinaryCursorMode,
    query_limits: QueryLimits,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<(), Error> {
    match request {
        QueryRequest::Singular(SingularQueryBox::FindAbiVersion(_)) => {
            ensure_source_bound(limits, ORDINARY_ABI_VERSION_SOURCE_BYTES)
        }
        QueryRequest::Singular(_) if query_limits.singular_output_limits.is_some() => Ok(()),
        QueryRequest::Singular(_) => {
            // Every non-scalar producer needs the singular output guard before
            // source preflight can decode, project, or build an owned result.
            // Torii installs that guard only after reserving the complete
            // singular working set; legacy in-process callers remain closed.
            Err(Error::Conversion(
                "ordinary Torii query requires a server-owned singular output lane before query execution"
                    .to_owned(),
            ))
        }
        QueryRequest::Start(start) => {
            ensure_world_state_start_shape(start, mode, query_limits, limits)
        }
        QueryRequest::Continue(_) if mode == OrdinaryCursorMode::Stored => Ok(()),
        QueryRequest::Continue(_) => Err(Error::Conversion(
            "ordinary ephemeral query rejects continuation before cursor execution".to_owned(),
        )),
    }
}
pub(crate) fn ensure_stored_revalidation_admitted(
    request: &QueryRequest,
    query_limits: QueryLimits,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<(), Error> {
    ensure_request_admitted(request, OrdinaryCursorMode::Stored, query_limits, limits)
}
pub(crate) fn ensure_response_admitted(
    response: &QueryResponse,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<(), Error> {
    super::bounded_framed_encoded_len(response, limits.max_response_bytes()).map(drop)
}
fn ensure_source_bound(
    limits: OrdinaryQueryExecutionLimits,
    required_bytes: u64,
) -> Result<(), Error> {
    if limits.max_source_item_bytes() < required_bytes {
        return Err(Error::CapacityLimit);
    }
    Ok(())
}
/// Stable reason code that starts every signed `POST /v1/query` refusal of an
/// iterable query shape.
///
/// Torii returns the refusal as HTTP 400 `query_validation_failed`; the message
/// is `signed_query_shape_not_admitted: <query> <reason>. …` and always lists
/// [`TORII_COLLECTION_ENDPOINTS`].
pub const SIGNED_QUERY_SHAPE_NOT_ADMITTED: &str = "signed_query_shape_not_admitted";
/// Torii collection endpoints that serve listing reads (`specs/torii/collection_queries.md`).
pub const TORII_COLLECTION_ENDPOINTS: [&str; 9] = [
    "/v1/domains",
    "/v1/accounts",
    "/v1/assets/definitions",
    "/v1/nfts",
    "/v1/rwas",
    "/v1/accounts/{id}/assets",
    "/v1/assets/{definition}/holders",
    "/v1/transactions/query",
    "/v1/repo/agreements",
];
/// Build the stable, actionable refusal for an iterable shape that signed
/// `POST /v1/query` does not admit.
///
/// `query` names the refused query (for example `FindDomains`) and `reason`
/// the refused modifier; the message always lists [`TORII_COLLECTION_ENDPOINTS`].
pub fn signed_query_shape_not_admitted(query: &str, reason: &str) -> Error {
    Error::Conversion(format!(
        "{SIGNED_QUERY_SHAPE_NOT_ADMITTED}: {query} {reason}. Signed POST /v1/query admits \
         singular queries and FindPeers, FindAccountIds, FindTriggers and \
         FindActiveTriggerIds starts with a pass predicate, bounded counting, zero offset \
         and no sorting (FindPeers in ephemeral cursor mode only). Read listings through \
         the Torii collection endpoints: {}.",
        TORII_COLLECTION_ENDPOINTS.join(", ")
    ))
}
/// Iterable producers that signed `POST /v1/query` admits.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum AdmittedIterableSource {
    /// `FindPeers`, ephemeral cursor mode only.
    Peers,
    /// `FindAccountIds`.
    AccountIds,
    /// `FindTriggers`.
    Triggers,
    /// `FindActiveTriggerIds`.
    ActiveTriggerIds,
}
impl AdmittedIterableSource {
    fn for_item(item: iroha_data_model::query::QueryItemKind) -> Option<Self> {
        use iroha_data_model::query::QueryItemKind;
        match item {
            QueryItemKind::PeerId => Some(Self::Peers),
            QueryItemKind::AccountId => Some(Self::AccountIds),
            QueryItemKind::Trigger => Some(Self::Triggers),
            QueryItemKind::TriggerId => Some(Self::ActiveTriggerIds),
            _ => None,
        }
    }
}
/// Name the iterable query carried by a canonical Start the same way the
/// typed dispatch resolves it: by item kind and, where two queries share an
/// item kind, by whether the query payload is empty.
fn iterable_query_name(
    item: iroha_data_model::query::QueryItemKind,
    query_payload: &[u8],
) -> &'static str {
    use iroha_data_model::query::QueryItemKind;
    let parameterized = !query_payload.is_empty();
    match item {
        QueryItemKind::Domain if parameterized => "FindDomainsByAccountId",
        QueryItemKind::Domain => "FindDomains",
        QueryItemKind::Account if parameterized => "FindAccountsWithAsset",
        QueryItemKind::Account => "FindAccounts",
        QueryItemKind::AccountId => "FindAccountIds",
        QueryItemKind::Asset if parameterized => "FindAssetsByAccountId",
        QueryItemKind::Asset => "FindAssets",
        QueryItemKind::AssetDefinition => "FindAssetDefinitions",
        QueryItemKind::RepoAgreement => "FindRepoAgreements",
        QueryItemKind::Nft if parameterized => "FindNftsByAccountId",
        QueryItemKind::Nft => "FindNfts",
        QueryItemKind::Rwa => "FindRwas",
        QueryItemKind::Role => "FindRoles",
        QueryItemKind::RoleId if parameterized => "FindRolesByAccountId",
        QueryItemKind::RoleId => "FindRoleIds",
        QueryItemKind::PeerId => "FindPeers",
        QueryItemKind::TriggerId => "FindActiveTriggerIds",
        QueryItemKind::Trigger => "FindTriggers",
        QueryItemKind::CommittedTransaction => "FindTransactions",
        QueryItemKind::SignedBlock => "FindBlocks",
        QueryItemKind::BlockHeader => "FindBlockHeaders",
        QueryItemKind::ProofRecord if parameterized => {
            "FindProofRecordsByBackend/FindProofRecordsByStatus"
        }
        QueryItemKind::ProofRecord => "FindProofRecords",
        QueryItemKind::OracleFeedConfig => "FindOracleFeeds",
        QueryItemKind::OracleFeedEventRecord => "FindOracleHistoryByFeedId",
        QueryItemKind::OracleProviderStatsRecord => "FindOracleProviderStatsByFeedId",
        QueryItemKind::OracleDispute if parameterized => "FindOracleDisputesByFeedId",
        QueryItemKind::OracleDispute => "FindOracleDisputes",
        QueryItemKind::OracleChangeProposal => "FindOracleChanges",
        QueryItemKind::TwitterBindingRecord => "FindTwitterBindingsByUaid",
        QueryItemKind::DefiOracleAttestation => "FindDefiOracleAttestationsByKey",
        QueryItemKind::Permission => "FindPermissionsByAccountId",
        QueryItemKind::AssetEscrowRecord => "FindAssetEscrows",
        QueryItemKind::AssetEscrowsBySeller => "FindAssetEscrowsBySeller",
        QueryItemKind::AssetEscrowsByBuyer => "FindAssetEscrowsByBuyer",
        QueryItemKind::AssetEscrowsByStatus => "FindAssetEscrowsByStatus",
        QueryItemKind::FeeSponsorProgram if parameterized => "FindFeeSponsorProgramsBySponsor",
        QueryItemKind::FeeSponsorProgram => "FindFeeSponsorPrograms",
        QueryItemKind::FeeSponsorProgramId => "FindFeeSponsorProgramIds",
    }
}
fn ensure_world_state_start_shape(
    start: &iroha_data_model::query::QueryWithParams,
    mode: OrdinaryCursorMode,
    query_limits: QueryLimits,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<(), Error> {
    ensure_source_bound(limits, ORDINARY_NAME_ID_SOURCE_BYTES)?;
    let (item, _, _, query_payload) = start.parts();
    let query = iterable_query_name(item, query_payload);
    // Listing reads belong to the Torii collection endpoints. A further shape
    // is admitted here only together with a source-specific borrowed adapter
    // in `ordinary_iterable` that bounds its scan before any row is cloned.
    let Some(source) = AdmittedIterableSource::for_item(item) else {
        return Err(signed_query_shape_not_admitted(
            query,
            "has no bounded signed-query source",
        ));
    };
    if query_limits.count_mode != QueryCountMode::Bounded {
        return Err(signed_query_shape_not_admitted(
            query,
            "requires bounded counting",
        ));
    }
    if !admitted_source_has_pass_predicate(start, source, query_limits)? {
        return Err(signed_query_shape_not_admitted(
            query,
            "admits only the pass (match-all) predicate",
        ));
    }
    if start.params.sorting.sort_by_metadata_key.is_some() {
        return Err(signed_query_shape_not_admitted(
            query,
            "does not admit metadata sorting",
        ));
    }
    if start.params.pagination.offset_value() != 0 {
        return Err(signed_query_shape_not_admitted(
            query,
            "admits only a zero offset",
        ));
    }
    if source == AdmittedIterableSource::Peers && mode != OrdinaryCursorMode::Ephemeral {
        return Err(signed_query_shape_not_admitted(
            query,
            "is admitted only in ephemeral cursor mode",
        ));
    }
    ensure_iterable_params(&start.params, mode, query_limits, limits)
}
/// Exactly decode an admitted source's query, predicate and selector, and
/// report whether the predicate is the pass predicate.
///
/// The selector is decoded only to require its single canonical (empty)
/// encoding; it never projects.
fn admitted_source_has_pass_predicate(
    start: &iroha_data_model::query::QueryWithParams,
    source: AdmittedIterableSource,
    query_limits: QueryLimits,
) -> Result<bool, Error> {
    use iroha_data_model::query::{
        account::prelude::FindAccountIds,
        dsl::{CompoundPredicate, SelectorTuple},
        peer::prelude::FindPeers,
        trigger::prelude::{FindActiveTriggerIds, FindTriggers},
    };
    use iroha_data_model::{
        account::AccountId,
        trigger::{Trigger, TriggerId},
    };
    use iroha_model_base::peer::PeerId;
    let (_, predicate, selector, payload) = start.parts();
    let mut decoder =
        super::FastIterComponentDecoder::new(query_limits, [payload, predicate, selector])?;
    macro_rules! pass_shape {
        ($query:ty, $item:ty) => {{
            let _: $query = decoder.decode(payload)?;
            let predicate: CompoundPredicate<$item> = decoder.decode(predicate)?;
            let _: SelectorTuple<$item> = decoder.decode(selector)?;
            Ok(predicate.is_pass())
        }};
    }
    match source {
        AdmittedIterableSource::Peers => pass_shape!(FindPeers, PeerId),
        AdmittedIterableSource::AccountIds => pass_shape!(FindAccountIds, AccountId),
        AdmittedIterableSource::Triggers => pass_shape!(FindTriggers, Trigger),
        AdmittedIterableSource::ActiveTriggerIds => {
            pass_shape!(FindActiveTriggerIds, TriggerId)
        }
    }
}
fn ensure_iterable_params(
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    query_limits: QueryLimits,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<(), Error> {
    let fetch_size = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE)
        .get();
    if fetch_size > limits.max_page_items() || fetch_size > limits.execution_budget().max_items() {
        return Err(Error::CapacityLimit);
    }
    if mode == OrdinaryCursorMode::Stored {
        if params.sorting.sort_by_metadata_key.is_some() {
            let requested = params.pagination.limit_value().ok_or_else(|| {
                Error::Conversion(
                    "ordinary stored sorted query requires an explicit bounded limit".to_owned(),
                )
            })?;
            let requested = requested.get();
            let keep = params
                .pagination
                .offset_value()
                .checked_add(requested)
                .ok_or(Error::CapacityLimit)?;
            let configured = limits.max_cursor_retained_items();
            let streaming = u64::try_from(STREAMING_SORTED_PREFIX_LIMIT).unwrap_or(u64::MAX);
            if keep > configured || keep > streaming {
                return Err(Error::CapacityLimit);
            }
            let first_page = requested.min(fetch_size);
            let retained_items = requested
                .checked_sub(first_page)
                .ok_or(Error::CapacityLimit)?;
            let retained_bytes = retained_items
                .checked_mul(limits.max_source_item_bytes())
                .ok_or(Error::CapacityLimit)?;
            if retained_items > limits.max_cursor_retained_items()
                || retained_bytes > limits.max_cursor_value_bytes()
            {
                return Err(Error::CapacityLimit);
            }
            // The typed source plan charges the global scan and the top-K
            // heap against immutable state. Only the already-sorted bounded
            // tail is transferred to cursor retention.
            return Ok(());
        }
        let offset = params.pagination.offset_value();
        let (scanned_items, retained_items) = match query_limits.count_mode {
            QueryCountMode::Exact => {
                let Some(limit) = params.pagination.limit_value() else {
                    return Err(Error::Conversion(
                        "ordinary stored exact-count query requires an explicit bounded limit"
                            .to_owned(),
                    ));
                };
                let items = limit.get();
                let scanned_items = offset.checked_add(items).ok_or(Error::CapacityLimit)?;
                (scanned_items, items)
            }
            QueryCountMode::Bounded => {
                let requested = params.pagination.limit_value().map(|limit| limit.get());
                let first_page_items = requested.map_or(fetch_size, |limit| limit.min(fetch_size));
                let requested_tail = requested
                    .map(|limit| limit - first_page_items)
                    .unwrap_or(u64::MAX);
                let retained_items = requested_tail.min(limits.max_cursor_retained_items());
                let overflow_probe = u64::from(requested_tail > retained_items);
                let scanned_items = offset
                    .checked_add(first_page_items)
                    .and_then(|items| items.checked_add(retained_items))
                    .and_then(|items| items.checked_add(overflow_probe))
                    .ok_or(Error::CapacityLimit)?;
                (scanned_items, retained_items)
            }
        };
        let scanned_bytes = scanned_items
            .checked_mul(limits.max_source_item_bytes())
            .ok_or(Error::CapacityLimit)?;
        limits
            .execution_budget()
            .ensure(scanned_items, scanned_bytes)
            .map_err(|_| Error::CapacityLimit)?;
        let retained_bytes = retained_items
            .checked_mul(limits.max_source_item_bytes())
            .ok_or(Error::CapacityLimit)?;
        // Stored bounded adapters own at most T rows under the resident R lease and measure
        // their actual canonical tail bytes before publishing a cursor. A source-row resident
        // ceiling is not the serialized value length; requiring T*S <= the wire quota would
        // reject a valid exact-byte tail even though both ownership and wire bytes fit.
        if retained_items > limits.max_cursor_retained_items()
            || (query_limits.count_mode == QueryCountMode::Exact
                && retained_bytes > limits.max_cursor_value_bytes())
        {
            return Err(Error::CapacityLimit);
        }
        return Ok(());
    }
    let Some(_sort_key) = params.sorting.sort_by_metadata_key.as_ref() else {
        return Ok(());
    };
    let offset = usize::try_from(params.pagination.offset_value()).unwrap_or(usize::MAX);
    let limit = params.pagination.limit_value().map_or(usize::MAX, |limit| {
        usize::try_from(limit.get()).unwrap_or(usize::MAX)
    });
    let fetch_size = usize::try_from(fetch_size).unwrap_or(usize::MAX);
    let keep = offset
        .checked_add(limit.min(fetch_size))
        .ok_or(Error::CapacityLimit)?;
    let configured = usize::try_from(limits.max_cursor_retained_items()).unwrap_or(usize::MAX);
    if keep > STREAMING_SORTED_PREFIX_LIMIT || keep > configured {
        return Err(Error::CapacityLimit);
    }
    Ok(())
}
fn sns_record_source_bytes(
    world: &impl WorldReadOnly,
    selector: &NameSelectorV1,
) -> Result<u64, Error> {
    let key = crate::sns::record_storage_key(selector);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(0);
    };
    u64::try_from(key.as_ref().len())
        .ok()
        .and_then(|key_bytes| {
            u64::try_from(bytes.len())
                .ok()
                .and_then(|value_bytes| key_bytes.checked_add(value_bytes))
        })
        .ok_or(Error::GasBudgetExceeded)
}
fn sns_record_prefix_source_bytes(
    world: &impl WorldReadOnly,
    suffix_id: SuffixId,
) -> Result<u64, Error> {
    let prefix_literal = format!("sns/records/{suffix_id}/");
    let prefix = StatePath::from_str(&prefix_literal)
        .map_err(|error| Error::Conversion(format!("invalid SNS state prefix: {error}")))?;
    let mut total = 0_u64;
    for (key, bytes) in world.smart_contract_state().range(prefix..) {
        if !key.as_ref().starts_with(&prefix_literal) {
            break;
        }
        let row = u64::try_from(key.as_ref().len())
            .ok()
            .and_then(|key_bytes| {
                u64::try_from(bytes.len())
                    .ok()
                    .and_then(|value_bytes| key_bytes.checked_add(value_bytes))
            })
            .ok_or(Error::GasBudgetExceeded)?;
        total = total.checked_add(row).ok_or(Error::GasBudgetExceeded)?;
    }
    Ok(total)
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SingularSourceAdmission {
    ProvenBounded,
}
#[cfg(test)]
macro_rules! define_singular_source_admission {
    ($($variant:ident: $class:ident),+ $(,)?) => {
        fn singular_source_admission(query: &SingularQueryBox) -> SingularSourceAdmission {
            match query {
                $(SingularQueryBox::$variant(_) => SingularSourceAdmission::$class,)+
            }
        }
        const SINGULAR_SOURCE_ADMISSION_AUDIT: &[(&str, SingularSourceAdmission)] = &[
            $((stringify!($variant), SingularSourceAdmission::$class),)+
        ];
    };
}
#[cfg(test)]
define_singular_source_admission! {
    FindExecutorDataModel: ProvenBounded,
    FindParameters: ProvenBounded,
    FindAccountById: ProvenBounded,
    FindAccountByAlias: ProvenBounded,
    FindAliasesByAccountId: ProvenBounded,
    FindAccountRecoveryPolicyByAlias: ProvenBounded,
    FindAccountRecoveryRequestByAlias: ProvenBounded,
    FindProofRecordById: ProvenBounded,
    FindContractManifestByArtifactId: ProvenBounded,
    FindAbiVersion: ProvenBounded,
    FindAssetById: ProvenBounded,
    FindAssetDefinitionById: ProvenBounded,
    FindAssetDefinitionDirectHome: ProvenBounded,
    FindNftById: ProvenBounded,
    FindAssetEscrowById: ProvenBounded,
    FindTriggerById: ProvenBounded,
    FindTwitterBindingByHash: ProvenBounded,
    FindOracleFeedById: ProvenBounded,
    FindOracleDisputeById: ProvenBounded,
    FindOracleChangeById: ProvenBounded,
    FindOracleProviderStatsByKey: ProvenBounded,
    FindLatestDefiOracleAttestation: ProvenBounded,
    FindDaPinIntentByTicket: ProvenBounded,
    FindDaPinIntentByManifest: ProvenBounded,
    FindDaPinIntentByAlias: ProvenBounded,
    FindDaPinIntentByLaneEpochSequence: ProvenBounded,
    FindSorafsProviderOwner: ProvenBounded,
    FindSorafsOrderbookPolicy: ProvenBounded,
    FindSorafsOrderbookOrderById: ProvenBounded,
    FindSorafsOrderbookCancellationByOrderId: ProvenBounded,
    FindSorafsOrderbookReceiptById: ProvenBounded,
    FindSorafsOrderbookTradeById: ProvenBounded,
    FindSorafsOrderbookChannelById: ProvenBounded,
    FindSorafsOrderbookStatus: ProvenBounded,
    FindSorafsOrderbookOrders: ProvenBounded,
    FindSorafsOrderbookReceipts: ProvenBounded,
    FindSorafsOrderbookTrades: ProvenBounded,
    FindSorafsOrderbookChannels: ProvenBounded,
    FindSorafsOrderbookEvents: ProvenBounded,
    FindSorafsReservePolicy: ProvenBounded,
    FindSorafsReserveProviderById: ProvenBounded,
    FindSorafsReserveMovementById: ProvenBounded,
    FindSorafsReserveAppealById: ProvenBounded,
    FindSorafsReserveProviders: ProvenBounded,
    FindSorafsReserveMovements: ProvenBounded,
    FindSorafsReserveAppeals: ProvenBounded,
    FindSorafsReserveEvents: ProvenBounded,
    FindSorafsPopIssuerPolicy: ProvenBounded,
    FindSorafsPopCredentialCommitmentByDigest: ProvenBounded,
    FindSorafsPopCommitmentRootByVersion: ProvenBounded,
    FindSorafsPopRevocationPublicationByVersion: ProvenBounded,
    FindSorafsPopRevocationByNonceCommitment: ProvenBounded,
    FindSorafsPopAuditDigestBySequence: ProvenBounded,
    FindSorafsPopRegistryStatus: ProvenBounded,
    FindSorafsCitizenBondBySerialCommitment: ProvenBounded,
    FindSorafsCitizenBondSnapshot: ProvenBounded,
    FindSorafsPinManifest: ProvenBounded,
    FindSorafsPinManifests: ProvenBounded,
    FindSorafsRepairTask: ProvenBounded,
    FindSorafsRepairTasks: ProvenBounded,
    FindSorafsRepairStatus: ProvenBounded,
    FindSorafsRepairEvents: ProvenBounded,
    FindSorafsProofOutcome: ProvenBounded,
    FindSorafsProofOutcomeEvents: ProvenBounded,
    FindSorafsReputationJournalAuthorityPolicy: ProvenBounded,
    FindSorafsReputationJournalEventBySourceId: ProvenBounded,
    FindSorafsReputationJournalEvents: ProvenBounded,
    FindSorafsModerationPolicy: ProvenBounded,
    FindSorafsModerationAppeal: ProvenBounded,
    FindSorafsModerationJurorEligibility: ProvenBounded,
    FindSorafsModerationCase: ProvenBounded,
    FindSorafsModerationCommit: ProvenBounded,
    FindSorafsModerationReveal: ProvenBounded,
    FindSorafsModerationChallenge: ProvenBounded,
    FindSorafsModerationOutcome: ProvenBounded,
    FindSorafsModerationNoShow: ProvenBounded,
    FindSorafsModerationStatus: ProvenBounded,
    FindSorafsModerationSnapshot: ProvenBounded,
    FindSorafsModerationEvents: ProvenBounded,
    FindDataspaceNameOwnerById: ProvenBounded,
    FindMusubiExactPackageV1: ProvenBounded,
    FindMusubiExactReleaseV1: ProvenBounded,
    FindMusubiProviderBundleAttestationV1: ProvenBounded,
    FindMusubiResolverIndexV1: ProvenBounded,
    FindMusubiVersionsV1: ProvenBounded,
    FindMusubiMaintainersV1: ProvenBounded,
    FindMusubiArchiveLocationsV1: ProvenBounded,
    FindMusubiArchiveRetentionV1: ProvenBounded,
    FindMusubiAliasV1: ProvenBounded,
    FindMusubiAliasHistoryV1: ProvenBounded,
    FindMusubiOrderedPrefixV1: ProvenBounded,
    FindDomainById: ProvenBounded,
    FindFeeSponsorProgramById: ProvenBounded,
    FindSettlementReceiptById: ProvenBounded,
    FindFxCorridorPolicyRegistry: ProvenBounded,
    FindFxCorridorPolicyById: ProvenBounded,
    FindDomainEndorsements: ProvenBounded,
    FindDomainEndorsementPolicy: ProvenBounded,
    FindDomainCommittee: ProvenBounded,
    FindGameSessionById: ProvenBounded,
    FindExecutionProofVerificationById: ProvenBounded,
    FindNftSaleOfferById: ProvenBounded,
}
fn sns_server_source_error(error: crate::sns::SnsError) -> Error {
    match error.into_attempt_error(|error| Error::Conversion(error.to_string())) {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
        crate::execution_attempt::ExecutionAttemptError::Deferred(_) => Error::CapacityLimit,
    }
}

/// Measure a singular source before a metered server lane can clone or decode it.
///
/// The capability match is deliberately exhaustive. A new singular query must
/// opt into a pre-execute bounded producer before it can use the singular
/// output lane. Without that lane, only the borrowed source adapters below are
/// accepted; legacy in-process callers never invoke this function.
pub(super) fn preflight_server_singular_source_materialization(
    query: &SingularQueryBox,
    state: &impl StateReadOnly,
    budget: QueryExecutionBudget,
    singular_output_lane_active: bool,
) -> Result<u64, Error> {
    fn charge<T: SerializePayload>(value: &T, remaining: &mut u64) -> Result<(), Error> {
        let resident_frame_limit =
            super::singular_query_frame_limit(usize::try_from(*remaining).unwrap_or(usize::MAX));
        let resident_frame_limit = u64::try_from(resident_frame_limit).unwrap_or(u64::MAX);
        let bytes = super::bounded_bare_encoded_len(value, (*remaining).min(resident_frame_limit))?;
        *remaining = remaining
            .checked_sub(bytes)
            .ok_or(Error::GasBudgetExceeded)?;
        Ok(())
    }
    fn charge_fixed(bytes: u64, remaining: &mut u64) -> Result<(), Error> {
        *remaining = remaining
            .checked_sub(bytes)
            .ok_or(Error::GasBudgetExceeded)?;
        Ok(())
    }
    fn reject_unbounded(name: &str) -> Error {
        Error::Conversion(format!(
            "metered server singular query `{name}` has no pre-execute bounded materialization adapter"
        ))
    }
    fn require_active_adapter(active: bool, name: &str) -> Result<(), Error> {
        if active {
            Ok(())
        } else {
            Err(reject_unbounded(name))
        }
    }
    let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let limit = budget.remaining_bytes(1, 0)?;
    let world = state.world();
    let catalog = &state.nexus().dataspace_catalog;
    let now_ms = state.query_ledger_time_ms();
    let mut remaining = limit;
    let charge_alias_resolution = |alias: &iroha_data_model::account::rekey::AccountAlias,
                                   repetitions: u64,
                                   remaining: &mut u64|
     -> Result<(), Error> {
        let dataspace_scan =
            sns_record_prefix_source_bytes(world, crate::sns::DATASPACE_ALIAS_SUFFIX_ID)?
                .checked_mul(repetitions)
                .ok_or(Error::GasBudgetExceeded)?;
        charge_fixed(dataspace_scan, remaining)?;
        if let Ok(selector) =
            crate::sns::active_account_alias_selector(world, catalog, alias, now_ms)
        {
            let record_bytes = sns_record_source_bytes(world, &selector)?
                .checked_mul(repetitions)
                .ok_or(Error::GasBudgetExceeded)?;
            charge_fixed(record_bytes, remaining)?;
        }
        if let Some(account_id) = world.account_aliases().get(alias) {
            for _ in 0..repetitions {
                charge(account_id, remaining)?;
            }
        }
        if let Some(rekey) = world.account_rekey_records().get(alias) {
            for _ in 0..repetitions {
                charge(&rekey.active_account_id, remaining)?;
            }
        }
        Ok(())
    };
    match query {
        SingularQueryBox::FindExecutorDataModel(_) => {
            let model = world.executor_data_model();
            if model.permissions().is_empty() {
                // The fallback is built solely from the compile-time
                // permission-name table. Materialize and measure that same
                // fixed producer here so an empty on-chain model preserves
                // its public query behavior without opening an unbounded
                // state-derived source path.
                let fallback = crate::executor::initial_executor_data_model_fallback();
                charge(&fallback, &mut remaining)?;
            } else {
                charge(model, &mut remaining)?;
            }
        }
        SingularQueryBox::FindGameSessionById(query) => {
            if let Some(session) = world.game_sessions().get(&query.session_id) {
                charge(session, &mut remaining)?;
            }
        }
        SingularQueryBox::FindNftSaleOfferById(query) => {
            if let Some(offer) = world.nft_sale_offers().get(&query.offer_id) {
                charge(offer, &mut remaining)?;
            }
        }
        SingularQueryBox::FindExecutionProofVerificationById(query) => {
            if let Some(receipt) = world
                .execution_proof_verifications()
                .get(&query.verification_id)
            {
                charge(receipt, &mut remaining)?;
            }
        }
        SingularQueryBox::FindParameters(_) => charge(world.parameters(), &mut remaining)?,
        SingularQueryBox::FindAccountById(query) => {
            if let Some((account_id, account_value)) =
                world.accounts().get_key_value(query.account_id())
            {
                charge(account_id, &mut remaining)?;
                charge(account_value.as_ref(), &mut remaining)?;
                charge_fixed(64, &mut remaining)?;
            }
        }
        SingularQueryBox::FindAccountByAlias(query) => {
            require_active_adapter(singular_output_lane_active, "FindAccountByAlias")?;
            charge_alias_resolution(query.alias(), 1, &mut remaining)?;
            if let Some(account_id) = world.account_aliases().get(query.alias())
                && let Some((stored_id, account_value)) = world.accounts().get_key_value(account_id)
            {
                charge(stored_id, &mut remaining)?;
                charge(account_value.as_ref(), &mut remaining)?;
                charge_fixed(64, &mut remaining)?;
            }
        }
        SingularQueryBox::FindAliasesByAccountId(query) => {
            require_active_adapter(singular_output_lane_active, "FindAliasesByAccountId")?;
            if let Some(account) = world.accounts().get(query.account_id()) {
                charge(query.account_id(), &mut remaining)?;
                charge_fixed(64, &mut remaining)?;
                if let Some(primary) = account.as_ref().label() {
                    charge(primary, &mut remaining)?;
                }
            }
            let labels = world.account_aliases_by_account().get(query.account_id());
            let label_count = u64::try_from(labels.map_or(0, |labels| labels.len()))
                .map_err(|_| Error::GasBudgetExceeded)?;
            let label_source_bytes = label_count
                .checked_mul(ORDINARY_NAME_ID_SOURCE_BYTES)
                .ok_or(Error::GasBudgetExceeded)?;
            charge_fixed(label_source_bytes, &mut remaining)?;
            let dataspace_scans_per_label = 4_u64;
            let filter_scans = u64::from(query.dataspace().is_some());
            let scan_repetitions = label_count
                .checked_mul(dataspace_scans_per_label)
                .and_then(|scans| scans.checked_add(filter_scans))
                .ok_or(Error::GasBudgetExceeded)?;
            let dataspace_scan =
                sns_record_prefix_source_bytes(world, crate::sns::DATASPACE_ALIAS_SUFFIX_ID)?
                    .checked_mul(scan_repetitions)
                    .ok_or(Error::GasBudgetExceeded)?;
            charge_fixed(dataspace_scan, &mut remaining)?;
            if let Some(filter) = query.dataspace()
                && let Ok(selector) = crate::sns::selector_for_dataspace_alias(filter.trim())
            {
                charge_fixed(sns_record_source_bytes(world, &selector)?, &mut remaining)?;
            }
            if let Some(labels) = labels {
                for label in labels {
                    let selector = match crate::sns::active_account_alias_selector(
                        world, catalog, label, now_ms,
                    ) {
                        Ok(selector) => selector,
                        Err(crate::sns::SnsError::NotFound(_)) => continue,
                        Err(error) => return Err(sns_server_source_error(error)),
                    };
                    {
                        let record_bytes = sns_record_source_bytes(world, &selector)?
                            .checked_mul(2)
                            .ok_or(Error::GasBudgetExceeded)?;
                        charge_fixed(record_bytes, &mut remaining)?;
                    }
                }
            }
        }
        SingularQueryBox::FindAccountRecoveryPolicyByAlias(query) => {
            require_active_adapter(
                singular_output_lane_active,
                "FindAccountRecoveryPolicyByAlias",
            )?;
            charge_alias_resolution(query.alias(), 1, &mut remaining)?;
            if let Some(policy) = world.account_recovery_policies().get(query.alias()) {
                charge(policy, &mut remaining)?;
            }
        }
        SingularQueryBox::FindAccountRecoveryRequestByAlias(query) => {
            require_active_adapter(
                singular_output_lane_active,
                "FindAccountRecoveryRequestByAlias",
            )?;
            // The request path resolves the active alias once directly and
            // once again while validating its canonical rekey lineage.
            charge_alias_resolution(query.alias(), 2, &mut remaining)?;
            if let Some(request) = world.account_recovery_requests().get(query.alias()) {
                charge(request, &mut remaining)?;
            }
            if let Some(rekey) = world.account_rekey_records().get(query.alias()) {
                let predecessor_bytes = u64::try_from(rekey.previous_account_ids.len())
                    .ok()
                    .and_then(|count| count.checked_mul(ORDINARY_NAME_ID_SOURCE_BYTES))
                    .ok_or(Error::GasBudgetExceeded)?;
                charge_fixed(predecessor_bytes, &mut remaining)?;
            }
        }
        SingularQueryBox::FindProofRecordById(query) => {
            if let Some(record) = world.proofs().get(&query.id) {
                charge(record, &mut remaining)?;
            }
        }
        SingularQueryBox::FindContractManifestByArtifactId(query) => {
            if let Some(manifest) = world.contract_manifests().get(&query.artifact_id) {
                charge(manifest, &mut remaining)?;
            }
        }
        SingularQueryBox::FindAbiVersion(_) => {}
        SingularQueryBox::FindAssetById(query) => {
            if let Ok(asset) = world.asset(query.asset_id()) {
                charge(asset.id(), &mut remaining)?;
                charge(asset.value().as_ref(), &mut remaining)?;
                charge_fixed(32, &mut remaining)?;
            }
        }
        SingularQueryBox::FindDomainById(query) => {
            if let Ok(domain) = world.domain(query.domain_id()) {
                charge(domain, &mut remaining)?;
            }
        }
        SingularQueryBox::FindAssetDefinitionById(query) => {
            if let Some(definition) = world.asset_definitions().get(query.asset_definition_id()) {
                charge(definition, &mut remaining)?;
                if let Some(binding) = world
                    .asset_definition_alias_bindings()
                    .get(query.asset_definition_id())
                {
                    charge(binding, &mut remaining)?;
                }
                charge_fixed(128, &mut remaining)?;
            }
        }
        SingularQueryBox::FindAssetDefinitionDirectHome(query) => {
            if let Some(home) = world
                .asset_definition_direct_homes()
                .get(query.asset_definition_id())
            {
                charge(home, &mut remaining)?;
            }
        }
        SingularQueryBox::FindAssetEscrowById(query) => {
            if let Some(record) = world.asset_escrows().get(&query.escrow_id) {
                charge(record, &mut remaining)?;
            }
        }
        SingularQueryBox::FindTriggerById(_) => {
            require_active_adapter(singular_output_lane_active, "FindTriggerById")?;
        }
        SingularQueryBox::FindTwitterBindingByHash(query) => {
            if let Some(record) = world.twitter_bindings().get(&query.binding_hash.digest) {
                charge(record, &mut remaining)?;
            }
        }
        SingularQueryBox::FindOracleFeedById(query) => {
            if let Some(record) = world.oracle_feeds().get(&query.feed_id) {
                charge(record, &mut remaining)?;
            }
        }
        SingularQueryBox::FindOracleDisputeById(query) => {
            if let Some(record) = world.oracle_disputes().get(&query.dispute_id) {
                charge(record, &mut remaining)?;
            }
        }
        SingularQueryBox::FindOracleChangeById(query) => {
            if let Some(record) = world.oracle_changes().get(&query.change_id) {
                charge(record, &mut remaining)?;
            }
        }
        SingularQueryBox::FindOracleProviderStatsByKey(_) => {}
        SingularQueryBox::FindLatestDefiOracleAttestation(query) => {
            if let Some(record) = world
                .defi_oracle_attestations()
                .get(&query.key)
                .and_then(|records| records.last())
            {
                charge(record, &mut remaining)?;
            }
        }
        SingularQueryBox::FindDomainEndorsements(query) => {
            if let Some(hashes) = world.domain_endorsements_by_domain().get(&query.domain_id) {
                charge(hashes, &mut remaining)?;
                for hash in hashes {
                    if let Some(record) = world.domain_endorsements().get(hash) {
                        charge(record, &mut remaining)?;
                    }
                }
            }
        }
        SingularQueryBox::FindDomainEndorsementPolicy(query) => {
            if let Some(policy) = world.domain_endorsement_policies().get(&query.domain_id) {
                charge(policy, &mut remaining)?;
            }
        }
        SingularQueryBox::FindDomainCommittee(query) => {
            if let Some(committee) = world.domain_committees().get(&query.committee_id) {
                charge(committee, &mut remaining)?;
            }
        }
        SingularQueryBox::FindDaPinIntentByTicket(query) => {
            if let Some(intent) = world.da_pin_intents_by_ticket().get(&query.storage_ticket) {
                charge(intent, &mut remaining)?;
            }
        }
        SingularQueryBox::FindDaPinIntentByManifest(query) => {
            if let Some(ticket) = world.da_pin_intents_by_manifest().get(&query.manifest_hash)
                && let Some(intent) = world.da_pin_intents_by_ticket().get(ticket)
            {
                charge(intent, &mut remaining)?;
            }
        }
        SingularQueryBox::FindDaPinIntentByAlias(query) => {
            if let Some(ticket) = world.da_pin_intents_by_alias().get(&query.alias)
                && let Some(intent) = world.da_pin_intents_by_ticket().get(ticket)
            {
                charge(intent, &mut remaining)?;
            }
        }
        SingularQueryBox::FindDaPinIntentByLaneEpochSequence(query) => {
            if let Some(ticket) = world.da_pin_intents_by_lane_epoch().get(&(
                query.lane_id,
                query.epoch,
                query.sequence,
            )) && let Some(intent) = world.da_pin_intents_by_ticket().get(ticket)
            {
                charge(intent, &mut remaining)?;
            }
        }
        SingularQueryBox::FindFeeSponsorProgramById(query) => {
            if let Some(policy) = world.fee_sponsor_programs().get(&query.id) {
                charge(policy, &mut remaining)?;
            }
        }
        SingularQueryBox::FindSettlementReceiptById(query) => {
            if let Some(receipt) = world.settlement_receipts().get(&query.id) {
                charge(receipt, &mut remaining)?;
            }
        }
        SingularQueryBox::FindFxCorridorPolicyRegistry(_) => {
            require_active_adapter(
                singular_output_lane_active,
                "FX corridor policy materialization",
            )?;
            let parameter_id =
                iroha_data_model::isi::settlement::FxCorridorPolicyRegistry::parameter_id();
            if let Some(parameter) = world.parameters().custom().get(&parameter_id) {
                charge(parameter.payload(), &mut remaining)?;
            }
        }
        SingularQueryBox::FindFxCorridorPolicyById(_) => {
            require_active_adapter(singular_output_lane_active, "FindFxCorridorPolicyById")?;
        }
        SingularQueryBox::FindSorafsProviderOwner(query) => {
            if let Some(owner) = world.provider_owners().get(&query.provider_id) {
                charge(owner, &mut remaining)?;
            }
        }
        SingularQueryBox::FindSorafsPinManifest(query) => {
            if let Some(manifest) = world.pin_manifests().get(&query.digest) {
                charge(manifest, &mut remaining)?;
            }
        }
        SingularQueryBox::FindSorafsPinManifests(_) => {
            require_active_adapter(
                singular_output_lane_active,
                "SoraFS pin-manifest page query",
            )?;
        }
        SingularQueryBox::FindSorafsOrderbookPolicy(_) => {
            require_active_adapter(singular_output_lane_active, "FindSorafsOrderbookPolicy")?;
        }
        SingularQueryBox::FindSorafsOrderbookOrderById(_)
        | SingularQueryBox::FindSorafsOrderbookCancellationByOrderId(_)
        | SingularQueryBox::FindSorafsOrderbookReceiptById(_)
        | SingularQueryBox::FindSorafsOrderbookTradeById(_)
        | SingularQueryBox::FindSorafsOrderbookChannelById(_)
        | SingularQueryBox::FindSorafsOrderbookStatus(_)
        | SingularQueryBox::FindSorafsOrderbookOrders(_)
        | SingularQueryBox::FindSorafsOrderbookReceipts(_)
        | SingularQueryBox::FindSorafsOrderbookTrades(_)
        | SingularQueryBox::FindSorafsOrderbookChannels(_)
        | SingularQueryBox::FindSorafsOrderbookEvents(_) => {
            require_active_adapter(singular_output_lane_active, "SoraFS orderbook query")?;
        }
        SingularQueryBox::FindSorafsReservePolicy(_)
        | SingularQueryBox::FindSorafsReserveProviderById(_)
        | SingularQueryBox::FindSorafsReserveMovementById(_)
        | SingularQueryBox::FindSorafsReserveAppealById(_)
        | SingularQueryBox::FindSorafsReserveProviders(_)
        | SingularQueryBox::FindSorafsReserveMovements(_)
        | SingularQueryBox::FindSorafsReserveAppeals(_)
        | SingularQueryBox::FindSorafsReserveEvents(_) => {
            require_active_adapter(singular_output_lane_active, "SoraFS reserve query")?;
        }
        SingularQueryBox::FindSorafsPopIssuerPolicy(_)
        | SingularQueryBox::FindSorafsPopCredentialCommitmentByDigest(_)
        | SingularQueryBox::FindSorafsPopCommitmentRootByVersion(_)
        | SingularQueryBox::FindSorafsPopRevocationPublicationByVersion(_)
        | SingularQueryBox::FindSorafsPopRevocationByNonceCommitment(_)
        | SingularQueryBox::FindSorafsPopAuditDigestBySequence(_)
        | SingularQueryBox::FindSorafsPopRegistryStatus(_) => {
            require_active_adapter(singular_output_lane_active, "SoraFS PoP registry query")?;
        }
        SingularQueryBox::FindSorafsCitizenBondBySerialCommitment(_)
        | SingularQueryBox::FindSorafsCitizenBondSnapshot(_) => {
            require_active_adapter(singular_output_lane_active, "SoraFS anonymity query")?;
        }
        SingularQueryBox::FindSorafsRepairTask(_)
        | SingularQueryBox::FindSorafsRepairTasks(_)
        | SingularQueryBox::FindSorafsRepairStatus(_)
        | SingularQueryBox::FindSorafsRepairEvents(_) => {
            require_active_adapter(singular_output_lane_active, "SoraFS repair query")?;
        }
        SingularQueryBox::FindSorafsProofOutcome(_)
        | SingularQueryBox::FindSorafsProofOutcomeEvents(_) => {
            require_active_adapter(singular_output_lane_active, "SoraFS proof-outcome query")?;
        }
        SingularQueryBox::FindSorafsReputationJournalAuthorityPolicy(_)
        | SingularQueryBox::FindSorafsReputationJournalEventBySourceId(_)
        | SingularQueryBox::FindSorafsReputationJournalEvents(_) => {
            require_active_adapter(
                singular_output_lane_active,
                "SoraFS reputation-journal query",
            )?;
        }
        SingularQueryBox::FindSorafsModerationPolicy(_)
        | SingularQueryBox::FindSorafsModerationAppeal(_)
        | SingularQueryBox::FindSorafsModerationJurorEligibility(_)
        | SingularQueryBox::FindSorafsModerationCase(_)
        | SingularQueryBox::FindSorafsModerationCommit(_)
        | SingularQueryBox::FindSorafsModerationReveal(_)
        | SingularQueryBox::FindSorafsModerationChallenge(_)
        | SingularQueryBox::FindSorafsModerationOutcome(_)
        | SingularQueryBox::FindSorafsModerationNoShow(_)
        | SingularQueryBox::FindSorafsModerationStatus(_)
        | SingularQueryBox::FindSorafsModerationSnapshot(_)
        | SingularQueryBox::FindSorafsModerationEvents(_) => {
            require_active_adapter(singular_output_lane_active, "SoraFS moderation query")?;
        }
        SingularQueryBox::FindDataspaceNameOwnerById(query) => {
            require_active_adapter(singular_output_lane_active, "FindDataspaceNameOwnerById")?;
            charge_fixed(
                sns_record_prefix_source_bytes(world, crate::sns::DATASPACE_ALIAS_SUFFIX_ID)?,
                &mut remaining,
            )?;
            let alias = match crate::sns::resolve_active_dataspace_alias_by_id(
                world,
                catalog,
                query.dataspace_id(),
                now_ms,
            ) {
                Ok(alias) => Some(alias),
                Err(crate::sns::SnsError::NotFound(_)) => None,
                Err(error) => return Err(sns_server_source_error(error)),
            };
            if let Some(alias) = alias {
                let selector = crate::sns::selector_for_dataspace_alias(&alias)
                    .map_err(|error| Error::Conversion(error.to_string()))?;
                charge_fixed(sns_record_source_bytes(world, &selector)?, &mut remaining)?;
                if let Some(owner) =
                    crate::sns::active_dataspace_owner_by_alias(world, &alias, now_ms)
                        .map_err(sns_server_source_error)?
                {
                    charge(&owner, &mut remaining)?;
                }
            }
        }
        SingularQueryBox::FindMusubiExactPackageV1(_)
        | SingularQueryBox::FindMusubiExactReleaseV1(_)
        | SingularQueryBox::FindMusubiProviderBundleAttestationV1(_)
        | SingularQueryBox::FindMusubiResolverIndexV1(_)
        | SingularQueryBox::FindMusubiVersionsV1(_)
        | SingularQueryBox::FindMusubiMaintainersV1(_)
        | SingularQueryBox::FindMusubiArchiveLocationsV1(_)
        | SingularQueryBox::FindMusubiArchiveRetentionV1(_)
        | SingularQueryBox::FindMusubiAliasV1(_)
        | SingularQueryBox::FindMusubiAliasHistoryV1(_)
        | SingularQueryBox::FindMusubiOrderedPrefixV1(_) => {
            require_active_adapter(singular_output_lane_active, "Musubi V1 query")?;
        }
        SingularQueryBox::FindNftById(query) => {
            if let Ok(nft) = world.nft(query.nft_id()) {
                charge(nft.id(), &mut remaining)?;
                charge(nft.value().as_ref(), &mut remaining)?;
                charge_fixed(48, &mut remaining)?;
            }
        }
    }
    limit.checked_sub(remaining).ok_or(Error::GasBudgetExceeded)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::query::{
        parameters::{FetchSize, Pagination},
        runtime::prelude::FindAbiVersion,
    };
    use nonzero_ext::nonzero;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    #[derive(Debug)]
    struct TestReservation {
        bytes: u64,
        pool_generation: u64,
        released: Arc<AtomicU64>,
    }
    impl Drop for TestReservation {
        fn drop(&mut self) {
            self.released.fetch_add(self.bytes, Ordering::SeqCst);
        }
    }
    impl OrdinaryQueryMemoryReservation for TestReservation {
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
    #[derive(Debug)]
    struct FailingSplitReservation(TestReservation);
    impl OrdinaryQueryMemoryReservation for FailingSplitReservation {
        fn reserved_bytes(&self) -> u64 {
            self.0.bytes
        }
        fn pool_generation(&self) -> u64 {
            self.0.pool_generation
        }
        fn split_off(&mut self, _bytes: u64) -> Option<Box<dyn OrdinaryQueryMemoryReservation>> {
            None
        }
    }
    fn limits() -> OrdinaryQueryExecutionLimits {
        OrdinaryQueryExecutionLimits::try_new(
            11,
            QueryExecutionBudget::from_weighted_limit(128 * 1024, 1, 1),
            16,
            64 * 1024,
            ORDINARY_NAME_ID_SOURCE_BYTES,
            16 * 1024,
            16,
            16 * ORDINARY_NAME_ID_SOURCE_BYTES,
            32 * 1024,
            16 * 1024,
            4 * 1024,
            norito::DecodeLimits::new(64, 4 * 1024, 256, 16 * 1024, 16),
        )
        .expect("valid ordinary query geometry")
    }
    fn cursor_policy(
        limits: OrdinaryQueryExecutionLimits,
        pool_generation: u64,
    ) -> OrdinaryQueryCursorPolicy {
        QueryLimits::new(limits.max_page_items())
            .with_count_mode(QueryCountMode::Bounded)
            .with_ordinary_execution_limits(limits)
            .ordinary_cursor_policy(pool_generation)
            .expect("ordinary policy")
    }
    fn peer_start(params: QueryParams) -> QueryRequest {
        use iroha_data_model::query::{
            ErasedIterQuery, QueryBox, QueryOutputBatchBox, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            peer::prelude::FindPeers,
        };
        use iroha_model_base::peer::PeerId;
        let query: QueryBox<QueryOutputBatchBox> = Box::new(ErasedIterQuery::<PeerId>::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            norito::codec::Encode::encode(&FindPeers),
        ));
        let query =
            QueryWithParams::new(&query, params).expect("peer query type has a canonical mapping");
        QueryRequest::Start(query)
    }
    fn peer_params() -> QueryParams {
        let mut params = QueryParams::default();
        params.fetch_size = FetchSize::new(Some(nonzero!(16_u64)));
        params
    }
    #[test]
    fn singular_source_admission_audit_covers_every_variant() {
        assert_eq!(SINGULAR_SOURCE_ADMISSION_AUDIT.len(), 102);
        let mut names = std::collections::BTreeSet::new();
        for (name, class) in SINGULAR_SOURCE_ADMISSION_AUDIT {
            assert!(!name.is_empty());
            assert!(
                names.insert(*name),
                "each production variant has one source admission owner"
            );
            assert_eq!(*class, SingularSourceAdmission::ProvenBounded);
        }
        let representative = SingularQueryBox::FindAbiVersion(
            iroha_data_model::query::runtime::prelude::FindAbiVersion,
        );
        assert_eq!(
            singular_source_admission(&representative),
            SingularSourceAdmission::ProvenBounded
        );
    }
    #[test]
    fn validated_geometry_requires_two_exact_source_passes_and_response() {
        let max_page_items = 4_u64;
        let max_source_item_bytes = 1_024_u64;
        let page_with_probe = max_page_items.checked_add(1).expect("F + 1");
        let source_items = page_with_probe
            .checked_mul(ORDINARY_SOURCE_SCAN_PASSES)
            .expect("two source passes");
        let probe_bytes = page_with_probe
            .checked_mul(max_source_item_bytes)
            .and_then(|bytes| bytes.checked_mul(ORDINARY_SOURCE_FRAME_TRAVERSALS))
            .expect("probe bytes");
        let exact_units = source_items
            .checked_add(probe_bytes)
            .and_then(|units| units.checked_add(4 * 1_024))
            .expect("weighted units");
        let decode = norito::DecodeLimits::new(16, 1_024, 32, 4 * 1_024, 8);
        let execution_headroom = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            max_page_items,
            max_source_item_bytes,
            4 * 1_024,
            4 * 1_024,
            1_024,
            decode,
        )
        .expect("execution geometry");
        let cursor_retained = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
            4,
            max_source_item_bytes,
            4 * 1_024,
            1_024,
        )
        .expect("cursor geometry");
        OrdinaryQueryExecutionLimits::try_new(
            1,
            QueryExecutionBudget::from_weighted_limit(exact_units, 1, 1),
            max_page_items,
            execution_headroom,
            max_source_item_bytes,
            4 * 1_024,
            4,
            4 * 1_024,
            cursor_retained,
            4 * 1_024,
            1_024,
            decode,
        )
        .expect("two exact F + 1 source passes must be admitted");
        assert_eq!(
            OrdinaryQueryExecutionLimits::try_new(
                1,
                QueryExecutionBudget::from_weighted_limit(exact_units - 1, 1, 1),
                max_page_items,
                execution_headroom,
                max_source_item_bytes,
                4 * 1_024,
                4,
                4 * 1_024,
                cursor_retained,
                4 * 1_024,
                1_024,
                decode,
            ),
            Err(OrdinaryQueryExecutionLimitError::ExecutionBudgetTooSmall)
        );
    }
    #[test]
    fn validated_geometry_rejects_a_zero_weight_work_budget() {
        let decode = norito::DecodeLimits::new(16, 1_024, 32, 4 * 1_024, 8);
        let execution_headroom = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            4,
            1_024,
            4 * 1_024,
            4 * 1_024,
            1_024,
            decode,
        )
        .expect("execution geometry");
        let cursor_retained = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
            4,
            1_024,
            4 * 1_024,
            1_024,
        )
        .expect("cursor geometry");
        assert_eq!(
            OrdinaryQueryExecutionLimits::try_new(
                1,
                QueryExecutionBudget::from_weighted_limit(u64::MAX, 0, 0),
                4,
                execution_headroom,
                1_024,
                4 * 1_024,
                4,
                4 * 1_024,
                cursor_retained,
                4 * 1_024,
                1_024,
                decode,
            ),
            Err(OrdinaryQueryExecutionLimitError::UnmeteredExecutionBudget)
        );
    }
    #[test]
    fn validated_geometry_rejects_underreservation_and_overflow() {
        let decode = norito::DecodeLimits::new(16, 1_024, 32, 4 * 1_024, 8);
        let required_execution = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            4,
            1_024,
            4 * 1_024,
            4 * 1_024,
            1_024,
            decode,
        )
        .expect("execution geometry");
        let required_cursor = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
            4,
            1_024,
            4 * 1_024,
            1_024,
        )
        .expect("cursor geometry");
        let budget = QueryExecutionBudget::from_weighted_limit(64 * 1_024, 1, 1);
        assert_eq!(
            OrdinaryQueryExecutionLimits::try_new(
                1,
                budget,
                4,
                required_execution - 1,
                1_024,
                4 * 1_024,
                4,
                4 * 1_024,
                required_cursor,
                4 * 1_024,
                1_024,
                decode,
            ),
            Err(OrdinaryQueryExecutionLimitError::ExecutionHeadroomTooSmall)
        );
        assert_eq!(
            OrdinaryQueryExecutionLimits::try_new(
                1,
                budget,
                4,
                required_execution,
                1_024,
                4 * 1_024,
                4,
                4 * 1_024,
                required_cursor - 1,
                4 * 1_024,
                1_024,
                decode,
            ),
            Err(OrdinaryQueryExecutionLimitError::CursorRetentionTooSmall)
        );
        assert_eq!(
            OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
                u64::MAX,
                2,
                1,
                1,
                1,
                decode,
            ),
            Err(OrdinaryQueryExecutionLimitError::GeometryOverflow)
        );
        assert_eq!(
            OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(u64::MAX, 2, 1, 1),
            Err(OrdinaryQueryExecutionLimitError::GeometryOverflow)
        );
    }
    #[test]
    fn validated_geometry_covers_continue_decode_and_reencode_overlap() {
        let decode = norito::DecodeLimits::new(8, 32, 8, 16 * 1_024, 4);
        let required = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            1,
            1,
            1,
            16 * 1_024,
            8 * 1_024,
            decode,
        )
        .expect("revalidation geometry");
        assert_eq!(
            required,
            8 * 1_024
                + 16 * 1_024
                + u64::try_from(core::mem::size_of::<QueryRequest>()).expect("request size")
                + ORDINARY_QUERY_FIXED_CONTAINER_OVERHEAD_BYTES
        );
        let retained =
            OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(1, 1, 1, 8 * 1_024)
                .expect("cursor geometry");
        assert_eq!(
            OrdinaryQueryExecutionLimits::try_new(
                1,
                QueryExecutionBudget::from_weighted_limit(13, 0, 1),
                1,
                required - 1,
                1,
                1,
                1,
                1,
                retained,
                16 * 1_024,
                8 * 1_024,
                decode,
            ),
            Err(OrdinaryQueryExecutionLimitError::ExecutionHeadroomTooSmall)
        );
    }
    #[test]
    fn cursor_policy_rejects_config_and_pool_generation_changes() {
        let limits = limits();
        let original = cursor_policy(limits, 7);
        let binding = OrdinaryQueryCursorBinding {
            retained_bytes: limits.max_cursor_retained_bytes(),
            policy: original,
        };
        assert!(binding.is_compatible_with(original));
        assert!(!binding.is_compatible_with(cursor_policy(limits, 8)));
        let changed_limits = OrdinaryQueryExecutionLimits::try_new(
            limits.policy_generation() + 1,
            limits.execution_budget(),
            limits.max_page_items(),
            limits.execution_headroom_bytes(),
            limits.max_source_item_bytes(),
            limits.max_response_bytes(),
            limits.max_cursor_retained_items(),
            limits.max_cursor_value_bytes(),
            limits.max_cursor_retained_bytes(),
            limits.max_request_graph_bytes(),
            limits.max_revalidation_archive_bytes(),
            limits.revalidation_decode_limits(),
        )
        .expect("same geometry with a new policy generation");
        assert!(!binding.is_compatible_with(cursor_policy(changed_limits, 7)));
    }
    #[test]
    fn split_cursor_charge_releases_independently() {
        let released = Arc::new(AtomicU64::new(0));
        let limits = limits();
        let retained = limits.max_cursor_retained_bytes();
        let total = limits
            .execution_headroom_bytes()
            .checked_add(retained)
            .expect("test geometry");
        let lease = OrdinaryQueryMemoryLease::new(TestReservation {
            bytes: total,
            pool_generation: 7,
            released: Arc::clone(&released),
        });
        let admission =
            OrdinaryQueryMemoryAdmission::new(lease, retained, Some(cursor_policy(limits, 7)))
                .expect("admission");
        let cursor = admission.split_cursor_lease().expect("cursor split");
        let response = admission
            .take_response_lease(false)
            .expect("response remainder");
        assert_eq!(cursor.binding().retained_bytes(), retained);
        assert_eq!(response.reserved_bytes(), limits.execution_headroom_bytes());
        drop(cursor);
        assert_eq!(released.load(Ordering::SeqCst), retained);
        drop(response);
        assert_eq!(released.load(Ordering::SeqCst), total);
    }
    #[test]
    fn failed_split_leaves_the_whole_reservation_owned() {
        let released = Arc::new(AtomicU64::new(0));
        let limits = limits();
        let retained = limits.max_cursor_retained_bytes();
        let total = limits
            .execution_headroom_bytes()
            .checked_add(retained)
            .expect("test geometry");
        let lease = OrdinaryQueryMemoryLease::new(FailingSplitReservation(TestReservation {
            bytes: total,
            pool_generation: 7,
            released: Arc::clone(&released),
        }));
        let admission =
            OrdinaryQueryMemoryAdmission::new(lease, retained, Some(cursor_policy(limits, 7)))
                .expect("admission");
        assert!(matches!(
            admission.split_cursor_lease(),
            Err(Error::CapacityLimit)
        ));
        let response = admission
            .take_response_lease(false)
            .expect("failed split must leave the parent token available");
        assert_eq!(response.reserved_bytes(), total);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        drop(response);
        assert_eq!(released.load(Ordering::SeqCst), total);
    }
    #[test]
    fn fixed_scalar_singular_is_admitted() {
        let request = QueryRequest::Singular(FindAbiVersion.into());
        ensure_request_admitted(
            &request,
            OrdinaryCursorMode::Ephemeral,
            QueryLimits::new(16),
            limits(),
        )
        .expect("fixed scalar must be admitted");
    }
    #[test]
    fn peer_adapter_admission_is_exact_and_pre_source() {
        let ordinary = limits();
        let query_limits = QueryLimits::new(16)
            .with_count_mode(QueryCountMode::Bounded)
            .with_ordinary_execution_limits(ordinary);
        ensure_request_admitted(
            &peer_start(peer_params()),
            OrdinaryCursorMode::Ephemeral,
            query_limits,
            ordinary,
        )
        .expect("the exact peer pass-through shape must be admitted");
        let mut offset = peer_params();
        offset.pagination = Pagination::new(None, 1);
        assert!(matches!(
            ensure_request_admitted(
                &peer_start(offset),
                OrdinaryCursorMode::Ephemeral,
                query_limits,
                ordinary,
            ),
            Err(Error::Conversion(_))
        ));
        assert!(matches!(
            ensure_request_admitted(
                &peer_start(peer_params()),
                OrdinaryCursorMode::Ephemeral,
                QueryLimits::new(16).with_ordinary_execution_limits(ordinary),
                ordinary,
            ),
            Err(Error::Conversion(_))
        ));
        assert!(matches!(
            ensure_request_admitted(
                &peer_start(peer_params()),
                OrdinaryCursorMode::Stored,
                query_limits,
                ordinary,
            ),
            Err(Error::Conversion(_))
        ));
    }
    #[test]
    fn state_backed_singular_requires_an_active_output_lane() {
        let request = QueryRequest::Singular(
            iroha_data_model::query::account::prelude::FindAccountById::new(
                iroha_test_samples::ALICE_ID.clone(),
            )
            .into(),
        );
        let error = ensure_request_admitted(
            &request,
            OrdinaryCursorMode::Ephemeral,
            QueryLimits::new(16),
            limits(),
        )
        .expect_err("state-backed output requires the singular lane");
        assert!(matches!(error, Error::Conversion(_)));
        ensure_request_admitted(
            &request,
            OrdinaryCursorMode::Ephemeral,
            QueryLimits::new(16).with_singular_output_limits(
                crate::smartcontracts::isi::query::SingularQueryOutputLimits::new(
                    4 * 1_024,
                    4 * 1_024,
                ),
            ),
            limits(),
        )
        .expect("the server-owned singular lane admits the bounded producer");
    }
    #[test]
    fn stored_exact_requires_and_bounds_pagination_before_execution() {
        let query_limits = QueryLimits::new(16);
        let mut params = QueryParams::default();
        params.fetch_size = FetchSize::new(Some(nonzero!(16_u64)));
        let error =
            ensure_iterable_params(&params, OrdinaryCursorMode::Stored, query_limits, limits())
                .expect_err("exact count without a limit must fail closed");
        assert!(matches!(error, Error::Conversion(_)));
        params.pagination = Pagination::new(Some(nonzero!(16_u64)), 0);
        ensure_iterable_params(&params, OrdinaryCursorMode::Stored, query_limits, limits())
            .expect("the configured retained bound is admitted");
        params.pagination = Pagination::new(Some(nonzero!(17_u64)), 0);
        assert_eq!(
            ensure_iterable_params(&params, OrdinaryCursorMode::Stored, query_limits, limits(),),
            Err(Error::CapacityLimit)
        );
        params.pagination = Pagination::new(Some(nonzero!(16_u64)), 112);
        assert_eq!(
            ensure_iterable_params(&params, OrdinaryCursorMode::Stored, query_limits, limits(),),
            Err(Error::CapacityLimit),
            "offset plus limit may not scan beyond the server work budget"
        );
    }
    #[test]
    fn stored_bounded_offset_and_tail_share_the_weighted_work_budget() {
        let query_limits = QueryLimits::new(16).with_count_mode(QueryCountMode::Bounded);
        let mut params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(16_u64))),
            ..QueryParams::default()
        };
        params.pagination = Pagination::new(Some(nonzero!(16_u64)), 111);
        ensure_iterable_params(&params, OrdinaryCursorMode::Stored, query_limits, limits())
            .expect("offset plus page fits the shared item/byte budget exactly enough");
        params.pagination = Pagination::new(Some(nonzero!(16_u64)), 112);
        assert_eq!(
            ensure_iterable_params(&params, OrdinaryCursorMode::Stored, query_limits, limits(),),
            Err(Error::CapacityLimit),
            "offset and page bytes may not each consume the same weighted pool"
        );
        params.pagination = Pagination::new(None, 95);
        assert_eq!(
            ensure_iterable_params(&params, OrdinaryCursorMode::Stored, query_limits, limits(),),
            Err(Error::CapacityLimit),
            "bounded Start must account for offset, first page, retained tail, and overflow probe"
        );
    }
    fn bounded_ordinary_limits() -> QueryLimits {
        QueryLimits::new(16)
            .with_count_mode(QueryCountMode::Bounded)
            .with_ordinary_execution_limits(limits())
    }
    fn erased_start<T>(
        predicate: iroha_data_model::query::dsl::CompoundPredicate<T>,
        query_payload: Vec<u8>,
        params: QueryParams,
    ) -> QueryRequest
    where
        T: iroha_data_model::query::dsl::HasProjection<
                iroha_data_model::query::dsl::PredicateMarker,
            > + iroha_data_model::query::dsl::HasProjection<
                iroha_data_model::query::dsl::SelectorMarker,
                AtomType = (),
            > + Send
            + Sync
            + 'static,
        iroha_data_model::query::ErasedIterQuery<T>:
            iroha_data_model::query::ErasedQuery<iroha_data_model::query::QueryOutputBatchBox>,
    {
        use iroha_data_model::query::{
            ErasedIterQuery, QueryBox, QueryOutputBatchBox, QueryWithParams, dsl::SelectorTuple,
        };
        let query: QueryBox<QueryOutputBatchBox> = Box::new(ErasedIterQuery::<T>::new(
            predicate,
            SelectorTuple::default(),
            query_payload,
        ));
        QueryRequest::Start(
            QueryWithParams::new(&query, params).expect("query type has a canonical mapping"),
        )
    }
    fn shape_refusal(
        request: &QueryRequest,
        mode: OrdinaryCursorMode,
        query_limits: QueryLimits,
    ) -> String {
        match ensure_request_admitted(request, mode, query_limits, limits()) {
            Err(Error::Conversion(message)) => message,
            other => panic!("expected a signed-query shape refusal, got {other:?}"),
        }
    }
    fn assert_shape_refusal(message: &str, query: &str, reason: &str) {
        let expected = format!("{SIGNED_QUERY_SHAPE_NOT_ADMITTED}: {query} {reason}. ");
        assert!(
            message.starts_with(&expected),
            "refusal must start with `{expected}`: {message}"
        );
        for endpoint in TORII_COLLECTION_ENDPOINTS {
            assert!(
                message.contains(endpoint),
                "refusal must point listing reads to {endpoint}: {message}"
            );
        }
    }
    #[test]
    fn listing_queries_are_refused_with_their_name_and_collection_endpoints() {
        use iroha_data_model::{
            account::Account,
            asset::{definition::AssetDefinition, value::Asset},
            domain::Domain,
            query::{
                account::prelude::FindAccounts,
                asset::prelude::{FindAssetDefinitions, FindAssetsByAccountId},
                domain::prelude::FindDomains,
                dsl::CompoundPredicate,
            },
        };
        use norito::codec::Encode as _;
        for (request, query) in [
            (
                erased_start::<Domain>(
                    CompoundPredicate::PASS,
                    FindDomains.encode(),
                    peer_params(),
                ),
                "FindDomains",
            ),
            (
                erased_start::<Account>(
                    CompoundPredicate::PASS,
                    FindAccounts.encode(),
                    peer_params(),
                ),
                "FindAccounts",
            ),
            (
                erased_start::<AssetDefinition>(
                    CompoundPredicate::PASS,
                    FindAssetDefinitions.encode(),
                    peer_params(),
                ),
                "FindAssetDefinitions",
            ),
            (
                erased_start::<Asset>(
                    CompoundPredicate::PASS,
                    FindAssetsByAccountId::new(iroha_test_samples::ALICE_ID.clone()).encode(),
                    peer_params(),
                ),
                "FindAssetsByAccountId",
            ),
        ] {
            let wire = norito::encode_canonical(&request).expect("canonical listing request");
            let request: QueryRequest =
                norito::decode_from_bytes(&wire).expect("decode canonical listing request");
            for mode in [OrdinaryCursorMode::Ephemeral, OrdinaryCursorMode::Stored] {
                let message = shape_refusal(&request, mode, bounded_ordinary_limits());
                assert_shape_refusal(&message, query, "has no bounded signed-query source");
            }
        }
    }
    #[test]
    fn admitted_iterable_shapes_survive_canonical_transport() {
        use iroha_data_model::{
            account::AccountId,
            query::{
                account::FindAccountIds,
                dsl::CompoundPredicate,
                trigger::{FindActiveTriggerIds, FindTriggers},
            },
            trigger::{Trigger, TriggerId},
        };
        use norito::codec::Encode as _;
        for request in [
            peer_start(peer_params()),
            erased_start::<AccountId>(
                CompoundPredicate::PASS,
                FindAccountIds.encode(),
                peer_params(),
            ),
            erased_start::<Trigger>(
                CompoundPredicate::PASS,
                FindTriggers.encode(),
                peer_params(),
            ),
            erased_start::<TriggerId>(
                CompoundPredicate::PASS,
                FindActiveTriggerIds.encode(),
                peer_params(),
            ),
        ] {
            let wire = norito::encode_canonical(&request).expect("canonical admitted request");
            let request: QueryRequest =
                norito::decode_from_bytes(&wire).expect("decode canonical admitted request");
            ensure_request_admitted(
                &request,
                OrdinaryCursorMode::Ephemeral,
                bounded_ordinary_limits(),
                limits(),
            )
            .expect("documented ephemeral iterable shape");
            let QueryRequest::Start(start) = &request else {
                unreachable!("only iterable starts in the matrix");
            };
            if start.parts().0 != iroha_data_model::query::QueryItemKind::PeerId {
                ensure_request_admitted(
                    &request,
                    OrdinaryCursorMode::Stored,
                    bounded_ordinary_limits(),
                    limits(),
                )
                .expect("documented stored iterable shape");
            }
        }
    }
    #[test]
    fn admitted_sources_name_each_refused_modifier() {
        use iroha_data_model::query::account::prelude::FindAccountIds;
        use iroha_data_model::{account::AccountId, query::dsl::CompoundPredicate};
        use norito::codec::Encode as _;
        let account_ids = |predicate: CompoundPredicate<AccountId>, params: QueryParams| {
            erased_start::<AccountId>(predicate, FindAccountIds.encode(), params)
        };
        let filtered = account_ids(
            CompoundPredicate::<AccountId>::build(|p| {
                p.equals("id", iroha_test_samples::ALICE_ID.to_string())
            }),
            peer_params(),
        );
        assert_shape_refusal(
            &shape_refusal(
                &filtered,
                OrdinaryCursorMode::Ephemeral,
                bounded_ordinary_limits(),
            ),
            "FindAccountIds",
            "admits only the pass (match-all) predicate",
        );
        let mut sorted = peer_params();
        sorted.sorting.sort_by_metadata_key = Some("rank".parse().expect("metadata key"));
        assert_shape_refusal(
            &shape_refusal(
                &account_ids(CompoundPredicate::PASS, sorted),
                OrdinaryCursorMode::Stored,
                bounded_ordinary_limits(),
            ),
            "FindAccountIds",
            "does not admit metadata sorting",
        );
        let mut offset = peer_params();
        offset.pagination = Pagination::new(None, 1);
        assert_shape_refusal(
            &shape_refusal(
                &peer_start(offset),
                OrdinaryCursorMode::Ephemeral,
                bounded_ordinary_limits(),
            ),
            "FindPeers",
            "admits only a zero offset",
        );
        assert_shape_refusal(
            &shape_refusal(
                &peer_start(peer_params()),
                OrdinaryCursorMode::Stored,
                bounded_ordinary_limits(),
            ),
            "FindPeers",
            "is admitted only in ephemeral cursor mode",
        );
        assert_shape_refusal(
            &shape_refusal(
                &peer_start(peer_params()),
                OrdinaryCursorMode::Ephemeral,
                QueryLimits::new(16).with_ordinary_execution_limits(limits()),
            ),
            "FindPeers",
            "requires bounded counting",
        );
        ensure_request_admitted(
            &account_ids(CompoundPredicate::PASS, peer_params()),
            OrdinaryCursorMode::Stored,
            bounded_ordinary_limits(),
            limits(),
        )
        .expect("the unfiltered account-identifier shape stays admitted");
    }
    #[test]
    fn iterable_query_names_follow_the_typed_dispatch() {
        use iroha_data_model::query::QueryItemKind;
        assert_eq!(iterable_query_name(QueryItemKind::Asset, &[]), "FindAssets");
        assert_eq!(
            iterable_query_name(QueryItemKind::Asset, &[1]),
            "FindAssetsByAccountId"
        );
        assert_eq!(
            iterable_query_name(QueryItemKind::AssetDefinition, &[]),
            "FindAssetDefinitions"
        );
        assert_eq!(
            iterable_query_name(QueryItemKind::RoleId, &[1]),
            "FindRolesByAccountId"
        );
        assert_eq!(iterable_query_name(QueryItemKind::PeerId, &[]), "FindPeers");
        assert_eq!(
            iterable_query_name(QueryItemKind::CommittedTransaction, &[]),
            "FindTransactions"
        );
    }
}
