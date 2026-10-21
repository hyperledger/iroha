//! Query functionality. The common error type is also defined here,
//! alongside functions for converting them into HTTP responses.
#[cfg(test)]
mod accounting_tests;
mod fast_iter_decode;
pub(crate) mod json_predicate;
mod ordinary_iterable;
mod ordinary_memory;
mod ordinary_stored;
#[cfg(test)]
mod payload_sort_tests;
mod settlement_receipts;
mod singular_memory;
use crate::{
    prelude::ValidSingularQuery,
    query::{
        cursor::ErasedQueryIterator,
        store::{
            DeferredQueryContinuation, LiveQueryStoreHandle, PagedQueryContinuation,
            PreparedPagedQueryStart, PreparedQueryStart,
        },
    },
    smartcontracts::ValidQuery,
    smartcontracts::isi::tx::{
        TransactionHistoryAnchor, TransactionHistoryCursor, visit_committed_transactions,
    },
    state::{State, StateReadOnly, WorldReadOnly},
};
use eyre::Result;
use fast_iter_decode::FastIterComponentDecoder;
#[cfg(test)]
use fast_iter_decode::decode_exact_in_scope;
use iroha_config::parameters::{
    actual::{Pipeline as PipelineActual, Torii as ToriiActual},
    defaults::pipeline as pipeline_defaults,
};
use iroha_data_model::{
    escrow::AssetEscrowRecord,
    prelude::*,
    query::{
        CommittedTransaction, QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple,
        QueryRequest, QueryResponse, SingularQueryBox, SingularQueryOutputBox,
        dsl::{CompoundPredicate, HasProjection, SelectorMarker},
        error::{FindError, QueryExecutionFail as Error},
        parameters::{DEFAULT_FETCH_SIZE, QueryParams, SortOrder},
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use norito::core::{Header, NoritoSerialize, SerializePayload};
pub(crate) use ordinary_iterable::predicate_json_value_for_execution as ordinary_predicate_json_value;
pub use ordinary_memory::{
    ORDINARY_ABI_VERSION_SOURCE_BYTES, ORDINARY_NAME_ID_SOURCE_BYTES,
    ORDINARY_QUERY_FIXED_CONTAINER_OVERHEAD_BYTES, ORDINARY_QUERY_RETAINED_ITEM_OVERHEAD_BYTES,
    OrdinaryQueryExecutionLimitError, OrdinaryQueryExecutionLimits, OrdinaryQueryMemoryLease,
    OrdinaryQueryMemoryReservation, SIGNED_QUERY_SHAPE_NOT_ADMITTED, TORII_COLLECTION_ENDPOINTS,
    signed_query_shape_not_admitted,
};
pub(crate) use ordinary_memory::{
    OrdinaryQueryCursorBinding, OrdinaryQueryCursorMemory, OrdinaryQueryCursorPolicy,
    OrdinaryQueryMemoryAdmission, ensure_response_admitted as ensure_ordinary_response_admitted,
    ensure_stored_revalidation_admitted as ensure_ordinary_stored_revalidation_admitted,
};
pub use singular_memory::SingularQueryOutputLimits;
#[cfg(test)]
pub(crate) use singular_memory::encode_singular_query_source_for_test;
pub(crate) use singular_memory::{
    BorrowedSingularOption, BorrowedSingularStruct, SingularQueryCurrentAllocation,
    SingularQueryRetainedVec, SingularQueryVecBuilder, own_singular_query_serialized_source,
    own_singular_query_struct, own_singular_query_value, own_singular_query_values,
    singular_query_decode_limits, singular_query_frame_limit, singular_query_limits_active,
};
use std::{
    cell::Cell,
    collections::BinaryHeap,
    num::NonZeroU64,
    ops::ControlFlow,
    sync::{Arc, Mutex, Weak},
};
/// Allows to generalize retrieving the metadata key for all the query output types
pub trait SortableQueryOutput {
    /// Type used for deterministic tie-breaking when metadata sort keys are equal.
    type TiebreakKey: Ord + Send + Sync;
    /// Get the sorting key for the output, from metadata
    ///
    /// If the type doesn't have metadata or metadata key doesn't exist - return None
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<&Json>;
    /// Deterministic tie-breaker key for stable ordering across equal metadata keys.
    ///
    /// Implementations should return a deterministic key that uniquely and
    /// stably identifies the item so that sorting remains stable across nodes.
    fn tiebreak_key(&self) -> Self::TiebreakKey;
    /// Measure the encoded tiebreak key without materializing it.
    ///
    /// Metered sorting calls this before [`Self::tiebreak_key`], so an
    /// attacker-sized key is rejected before any key allocation or clone.
    ///
    /// # Errors
    /// Returns `GasBudgetExceeded` if bounded encoding exceeds `limit`, or a
    /// conversion error if the key cannot be serialized for measurement.
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error>;
    /// Compare two items by their deterministic tie-break order.
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.tiebreak_key().cmp(&other.tiebreak_key())
    }
}
/// Query execution limits derived from configuration snapshots.
#[derive(Debug, Copy, Clone)]
pub struct QueryLimits {
    max_fetch_size: u64,
    count_mode: QueryCountMode,
    singular_output_limits: Option<SingularQueryOutputLimits>,
    ordinary_execution_limits: Option<OrdinaryQueryExecutionLimits>,
    server_memory_budget: bool,
}
/// Whether query pagination should compute exact counts or only bounded continuation metadata.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QueryCountMode {
    /// Compute exact totals and remaining item counts.
    Exact,
    /// Avoid an exact total. Ephemeral queries stop after the requested page
    /// and `has_more`; stored cursors may additionally retain a hard-bounded
    /// immutable tail so later pages cannot observe newer state.
    Bounded,
}
/// Maximum number of raw values retained by one generic stored cursor.
///
/// Generic world-state iterators borrow an MVCC view and cannot outlive the
/// request. Retaining a bounded tail gives continuations snapshot semantics
/// without allowing one cursor to clone an unbounded state surface.
const MAX_STORED_QUERY_RETAINED_ITEMS: usize = 4_096;
/// Maximum canonical payload bytes retained by one generic stored cursor.
const MAX_STORED_QUERY_RETAINED_BYTES: u64 = 8 * 1024 * 1024;
/// Deterministic work budget for an ephemeral query.
///
/// The weighted limit prevents callers from independently exhausting the item and byte ceilings
/// from the same pool of execution units. Bytes are measured without allocating an encoded buffer
/// and include every value traversed by sorting or pagination, plus the final framed response.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct QueryExecutionBudget {
    max_items: u64,
    max_bytes: u64,
    max_units: u64,
    units_per_item: u64,
    units_per_byte: u64,
}
impl QueryExecutionBudget {
    /// Build a budget from one shared weighted work limit.
    #[must_use]
    pub const fn from_weighted_limit(
        max_units: u64,
        units_per_item: u64,
        units_per_byte: u64,
    ) -> Self {
        let max_items = if units_per_item == 0 {
            u64::MAX
        } else {
            max_units / units_per_item
        };
        let max_bytes = if units_per_byte == 0 {
            u64::MAX
        } else {
            max_units / units_per_byte
        };
        Self {
            max_items,
            max_bytes,
            max_units,
            units_per_item,
            units_per_byte,
        }
    }
    /// Maximum number of charged items when no bytes are consumed.
    #[must_use]
    pub const fn max_items(self) -> u64 {
        self.max_items
    }
    /// Maximum number of charged bytes when no items are consumed.
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }
    pub(super) fn ensure(self, items: u64, bytes: u64) -> Result<(), Error> {
        let weighted = self
            .units_per_item
            .checked_mul(items)
            .and_then(|item_units| {
                self.units_per_byte
                    .checked_mul(bytes)
                    .and_then(|byte_units| item_units.checked_add(byte_units))
            })
            .ok_or(Error::GasBudgetExceeded)?;
        if items > self.max_items || bytes > self.max_bytes || weighted > self.max_units {
            return Err(Error::GasBudgetExceeded);
        }
        Ok(())
    }
    fn remaining_bytes(self, items: u64, bytes: u64) -> Result<u64, Error> {
        self.ensure(items, bytes)?;
        let cap_remaining = self
            .max_bytes
            .checked_sub(bytes)
            .ok_or(Error::GasBudgetExceeded)?;
        if self.units_per_byte == 0 {
            return Ok(cap_remaining);
        }
        let item_units = self
            .units_per_item
            .checked_mul(items)
            .ok_or(Error::GasBudgetExceeded)?;
        let byte_units = self
            .units_per_byte
            .checked_mul(bytes)
            .ok_or(Error::GasBudgetExceeded)?;
        let used_units = item_units
            .checked_add(byte_units)
            .ok_or(Error::GasBudgetExceeded)?;
        let units_remaining = self
            .max_units
            .checked_sub(used_units)
            .ok_or(Error::GasBudgetExceeded)?;
        Ok(cap_remaining.min(units_remaining / self.units_per_byte))
    }
}
/// Work observed while executing an ephemeral query.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct QueryExecutionStats {
    processed_items: u64,
    processed_bytes: u64,
}
impl QueryExecutionStats {
    /// Number of source items or history projection work units charged by query execution.
    /// Retained sort-key bytes do not add another source item.
    #[must_use]
    pub const fn processed_items(self) -> u64 {
        self.processed_items
    }
    /// Number of encoded bytes charged by query execution.
    ///
    /// This intentionally includes both source values traversed by the query and the final framed
    /// response: scanning/sorting and response encoding are separate pieces of deterministic work.
    #[must_use]
    pub const fn processed_bytes(self) -> u64 {
        self.processed_bytes
    }
    fn record_item<T: SerializePayload>(
        &mut self,
        value: &T,
        budget: Option<QueryExecutionBudget>,
    ) -> Result<(), Error> {
        self.processed_items = self
            .processed_items
            .checked_add(1)
            .ok_or(Error::GasBudgetExceeded)?;
        self.record_value_bytes(value, budget)
    }
    fn record_value_bytes<T: SerializePayload>(
        &mut self,
        value: &T,
        budget: Option<QueryExecutionBudget>,
    ) -> Result<(), Error> {
        let Some(budget) = budget else {
            return Ok(());
        };
        let remaining = budget.remaining_bytes(self.processed_items, self.processed_bytes)?;
        let encoded = bounded_bare_encoded_len(value, remaining)?;
        self.processed_bytes = self
            .processed_bytes
            .checked_add(encoded)
            .ok_or(Error::GasBudgetExceeded)?;
        budget.ensure(self.processed_items, self.processed_bytes)
    }
    fn record_response<T: NoritoSerialize>(
        &mut self,
        value: &T,
        budget: Option<QueryExecutionBudget>,
    ) -> Result<(), Error> {
        let Some(budget) = budget else {
            return Ok(());
        };
        let remaining = budget.remaining_bytes(self.processed_items, self.processed_bytes)?;
        let encoded = bounded_framed_encoded_len(value, remaining)?;
        self.processed_bytes = self
            .processed_bytes
            .checked_add(encoded)
            .ok_or(Error::GasBudgetExceeded)?;
        budget.ensure(self.processed_items, self.processed_bytes)
    }
    fn record_precomputed_bytes(
        &mut self,
        encoded: u64,
        budget: Option<QueryExecutionBudget>,
    ) -> Result<(), Error> {
        let Some(budget) = budget else {
            return Ok(());
        };
        let remaining = budget.remaining_bytes(self.processed_items, self.processed_bytes)?;
        if encoded > remaining {
            return Err(Error::GasBudgetExceeded);
        }
        self.processed_bytes = self
            .processed_bytes
            .checked_add(encoded)
            .ok_or(Error::GasBudgetExceeded)?;
        budget.ensure(self.processed_items, self.processed_bytes)
    }
    fn record_preflighted_item(
        &mut self,
        encoded: u64,
        budget: Option<QueryExecutionBudget>,
    ) -> Result<(), Error> {
        self.processed_items = self
            .processed_items
            .checked_add(1)
            .ok_or(Error::GasBudgetExceeded)?;
        self.record_precomputed_bytes(encoded, budget)
    }
}
struct BoundedLengthWriter {
    bytes: u64,
    limit: u64,
    exceeded: bool,
}
impl BoundedLengthWriter {
    const fn new(limit: u64) -> Self {
        Self {
            bytes: 0,
            limit,
            exceeded: false,
        }
    }
}
impl std::io::Write for BoundedLengthWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let Some(next) = self.bytes.checked_add(len) else {
            self.exceeded = true;
            return Err(std::io::Error::other("query byte budget exceeded"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("query byte budget exceeded"));
        }
        self.bytes = next;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn bounded_bare_encoded_len<T: SerializePayload>(
    value: &T,
    limit: u64,
) -> Result<u64, Error> {
    if let Some(exact) = value.encoded_len_exact() {
        let exact = u64::try_from(exact).unwrap_or(u64::MAX);
        if exact > limit {
            return Err(Error::GasBudgetExceeded);
        }
    }
    // Exact lengths are optimization hints, not admission certificates; only
    // a real bounded serialization pass may admit source bytes.
    let mut writer = BoundedLengthWriter::new(limit);
    let serialization = norito::core::serialize_to_writer(value, &mut writer);
    // The sink owns the authoritative limit state. A hostile custom serializer
    // can ignore a failed `write_all` and return `Ok(())`; once the sink has
    // observed an overrun, no serializer result may clear that sticky failure.
    if writer.exceeded {
        return Err(Error::GasBudgetExceeded);
    }
    serialization
        .map_err(|_| Error::Conversion("failed to measure query result encoding".to_owned()))?;
    Ok(writer.bytes)
}
fn bounded_framed_encoded_len<T: NoritoSerialize>(value: &T, limit: u64) -> Result<u64, Error> {
    let header = u64::try_from(Header::SIZE).unwrap_or(u64::MAX);
    let align = norito::core::archived_payload_align::<T>();
    let padding = if align <= 1 {
        0
    } else {
        let remainder = Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    };
    let overhead = header
        .checked_add(u64::try_from(padding).map_err(|_| Error::GasBudgetExceeded)?)
        .ok_or(Error::GasBudgetExceeded)?;
    if overhead > limit {
        return Err(Error::GasBudgetExceeded);
    }
    let payload = bounded_bare_encoded_len(value, limit - overhead)?;
    overhead
        .checked_add(payload)
        .ok_or(Error::GasBudgetExceeded)
}
fn bounded_encoded_vec_tiebreak_len<T: SerializePayload>(
    value: &T,
    limit: u64,
) -> Result<u64, Error> {
    // `Encode::encode(value)` is the bare archived payload. The resulting
    // `Vec<u8>` tiebreak key adds Norito's fixed u64 sequence length prefix.
    const VEC_LENGTH_PREFIX: u64 = 8;
    if limit < VEC_LENGTH_PREFIX {
        return Err(Error::GasBudgetExceeded);
    }
    let payload = bounded_bare_encoded_len(value, limit - VEC_LENGTH_PREFIX)?;
    VEC_LENGTH_PREFIX
        .checked_add(payload)
        .ok_or(Error::GasBudgetExceeded)
}
fn materialize_admitted_tiebreak_key<T: SortableQueryOutput>(
    value: &T,
    execution_stats: &mut QueryExecutionStats,
    budget: Option<QueryExecutionBudget>,
) -> Result<T::TiebreakKey, Error> {
    if let Some(budget) = budget {
        let remaining = budget.remaining_bytes(
            execution_stats.processed_items,
            execution_stats.processed_bytes,
        )?;
        let encoded = value.bounded_tiebreak_key_len(remaining)?;
        execution_stats.record_precomputed_bytes(encoded, Some(budget))?;
    }
    Ok(value.tiebreak_key())
}
impl QueryLimits {
    /// Construct limits from a Torii configuration snapshot.
    #[must_use]
    pub fn from_torii(cfg: &ToriiActual) -> Self {
        Self::new(u64::from(cfg.app_api.max_fetch_size.get()))
    }
    /// Construct limits from the pipeline settings of a State view or block.
    ///
    /// `query_max_fetch_size` there is the committed pipeline validity policy
    /// (`pipeline_validity_policy_v1`) or the protocol default; the node
    /// configuration has no key for it.
    #[must_use]
    pub fn from_pipeline(cfg: &PipelineActual) -> Self {
        Self::new(cfg.query_max_fetch_size)
    }
    /// Construct limits from pipeline defaults (used outside Torii contexts).
    #[must_use]
    pub fn from_defaults() -> Self {
        Self::new(pipeline_defaults::QUERY_MAX_FETCH_SIZE)
    }
    /// Construct limits from a maximum fetch size value.
    #[must_use]
    pub fn new(max_fetch_size: u64) -> Self {
        Self {
            max_fetch_size: max_fetch_size.max(1),
            count_mode: QueryCountMode::Exact,
            singular_output_limits: None,
            ordinary_execution_limits: None,
            server_memory_budget: false,
        }
    }
    /// Return limits with a different count mode.
    #[must_use]
    pub fn with_count_mode(mut self, count_mode: QueryCountMode) -> Self {
        self.count_mode = count_mode;
        self
    }
    /// Enable bounded singular-output ownership for a server-owned ephemeral lane.
    #[must_use]
    pub fn with_singular_output_limits(mut self, limits: SingularQueryOutputLimits) -> Self {
        self.singular_output_limits = Some(limits);
        self.server_memory_budget = true;
        self
    }
    /// Enable the server-owned memory corridor for one ordinary Torii query.
    ///
    /// This remains disabled for IVM and other in-process query callers.
    #[must_use]
    pub(crate) fn with_ordinary_execution_limits(
        mut self,
        limits: OrdinaryQueryExecutionLimits,
    ) -> Self {
        self.ordinary_execution_limits = Some(limits);
        self.server_memory_budget = true;
        self
    }
    pub(crate) fn with_server_memory_budget(mut self) -> Self {
        self.server_memory_budget = true;
        self
    }
    pub(crate) const fn ordinary_execution_limits(self) -> Option<OrdinaryQueryExecutionLimits> {
        self.ordinary_execution_limits
    }
    pub(crate) fn ordinary_cursor_policy(
        self,
        pool_generation: u64,
    ) -> Option<OrdinaryQueryCursorPolicy> {
        self.ordinary_execution_limits.map(|ordinary| {
            OrdinaryQueryCursorPolicy::new(
                ordinary,
                self.max_fetch_size,
                self.count_mode,
                pool_generation,
            )
        })
    }
}
impl Default for QueryLimits {
    fn default() -> Self {
        Self::from_defaults()
    }
}
impl SortableQueryOutput for Account {
    type TiebreakKey = AccountId;
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<&Json> {
        self.metadata().get(key)
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for AccountId {
    type TiebreakKey = Self;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self, limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp(other)
    }
}
impl SortableQueryOutput for Domain {
    type TiebreakKey = DomainId;
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<&Json> {
        self.metadata().get(key)
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for AssetDefinition {
    type TiebreakKey = AssetDefinitionId;
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<&Json> {
        self.metadata().get(key)
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for Asset {
    type TiebreakKey = AssetId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for Nft {
    type TiebreakKey = iroha_data_model::nft::NftId;
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<&Json> {
        self.content().get(key)
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for Rwa {
    type TiebreakKey = iroha_data_model::rwa::RwaId;
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<&Json> {
        self.metadata().get(key)
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for Role {
    type TiebreakKey = iroha_data_model::role::RoleId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.id, limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}
impl SortableQueryOutput for RoleId {
    type TiebreakKey = Self;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self, limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp(other)
    }
}
impl SortableQueryOutput for CommittedTransaction {
    type TiebreakKey = Vec<u8>;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        norito::codec::Encode::encode(self)
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_encoded_vec_tiebreak_len(self, limit)
    }
}
impl SortableQueryOutput for PeerId {
    type TiebreakKey = Vec<u8>;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        norito::codec::Encode::encode(self)
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_encoded_vec_tiebreak_len(self, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::nexus::FeeSponsorProgram {
    type TiebreakKey = iroha_data_model::nexus::FeeSponsorProgramId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.id, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::nexus::FeeSponsorProgramId {
    type TiebreakKey = Self;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self, limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp(other)
    }
}
impl SortableQueryOutput for Permission {
    type TiebreakKey = Vec<u8>;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        norito::codec::Encode::encode(self)
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_encoded_vec_tiebreak_len(self, limit)
    }
}
impl SortableQueryOutput for Trigger {
    type TiebreakKey = TriggerId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for TriggerId {
    type TiebreakKey = Self;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self, limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp(other)
    }
}
impl SortableQueryOutput for RepoAgreement {
    type TiebreakKey = iroha_data_model::repo::RepoAgreementId;
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<&Json> {
        self.collateral_leg().metadata().get(key)
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id().clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(self.id(), limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}
impl SortableQueryOutput for iroha_data_model::bond::BondRecord {
    type TiebreakKey = iroha_data_model::bond::BondId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.id, limit)
    }
}
impl SortableQueryOutput for AssetEscrowRecord {
    type TiebreakKey = iroha_data_model::escrow::EscrowId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.id, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::asset::uid::AssetUidPolicyViewV1 {
    type TiebreakKey = [u8; 32];
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> { None }
    fn tiebreak_key(&self) -> Self::TiebreakKey { self.policy.uid }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.policy.uid, limit)
    }
}
type QueryAttemptError = crate::execution_attempt::ExecutionAttemptError<Error>;

// Transport projection is used only after leaving consensus execution.
pub(crate) fn query_transport_error(error: QueryAttemptError) -> Error {
    match error {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
        crate::execution_attempt::ExecutionAttemptError::Deferred(_) => Error::GasBudgetExceeded,
    }
}

trait ExecuteSingularQuery {
    fn execute(
        self,
        state: &impl StateReadOnly,
    ) -> Result<SingularQueryOutputBox, QueryAttemptError>;
}
impl ExecuteSingularQuery for SingularQueryBox {
    fn execute(
        self,
        state: &impl StateReadOnly,
    ) -> Result<SingularQueryOutputBox, QueryAttemptError> {
        /// Route each uniform singular query to its own `execute` implementation.
        macro_rules! dispatch_uniform {
            ($query:expr; $($variant:ident),+ $(,)?) => {
                match $query {
                    // These two query schemas are reserved for the native anonymity
                    // ledger. Until that ledger owns an authenticated storage and ZK
                    // admission boundary, fail closed instead of interpreting bytes
                    // from the generic smart-contract state namespace.
                    SingularQueryBox::FindSorafsCitizenBondBySerialCommitment(q) => Err(
                        Error::Find(FindError::SorafsCitizenBond(q.serial_commitment)).into(),
                    ),
                    SingularQueryBox::FindSorafsCitizenBondSnapshot(_) => {
                        Err(Error::Find(FindError::SorafsCitizenBondSnapshot).into())
                    }
                    $(SingularQueryBox::$variant(q) => {
                        Ok(SingularQueryOutputBox::from(q.execute(state)?))
                    })+
                }
            };
        }
        dispatch_uniform!(
            self;
            FindExecutorDataModel,
            FindParameters,
            FindAccountById,
            FindAccountByAlias,
            FindAliasesByAccountId,
            FindAccountRecoveryPolicyByAlias,
            FindAccountRecoveryRequestByAlias,
            FindProofRecordById,
            FindContractManifestByArtifactId,
            FindAbiVersion,
            FindAssetById,
            FindAssetDefinitionById,
            FindAssetDefinitionDirectHome,
            FindNftSaleOfferById,
            FindGameSessionById,
            FindExecutionProofVerificationById,
            FindAssetEscrowById,
            FindBondById,
            FindTriggerById,
            FindTwitterBindingByHash,
            FindOracleFeedById,
            FindOracleDisputeById,
            FindOracleChangeById,
            FindOracleProviderStatsByKey,
            FindLatestDefiOracleAttestation,
            FindDomainEndorsements,
            FindDomainEndorsementPolicy,
            FindDomainCommittee,
            FindDaPinIntentByTicket,
            FindDaPinIntentByManifest,
            FindDaPinIntentByAlias,
            FindDaPinIntentByLaneEpochSequence,
            FindFeeSponsorProgramById,
            FindSettlementReceiptById,
            FindFxCorridorPolicyRegistry,
            FindFxCorridorPolicyById,
            FindSorafsProviderOwner,
            FindSorafsPinManifest,
            FindSorafsPinManifests,
            FindSorafsOrderbookPolicy,
            FindSorafsOrderbookOrderById,
            FindSorafsOrderbookCancellationByOrderId,
            FindSorafsOrderbookReceiptById,
            FindSorafsOrderbookTradeById,
            FindSorafsOrderbookChannelById,
            FindSorafsOrderbookStatus,
            FindSorafsOrderbookOrders,
            FindSorafsOrderbookReceipts,
            FindSorafsOrderbookTrades,
            FindSorafsOrderbookChannels,
            FindSorafsOrderbookEvents,
            FindSorafsReservePolicy,
            FindSorafsReserveProviderById,
            FindSorafsReserveMovementById,
            FindSorafsReserveAppealById,
            FindSorafsReserveProviders,
            FindSorafsReserveMovements,
            FindSorafsReserveAppeals,
            FindSorafsReserveEvents,
            FindSorafsPopIssuerPolicy,
            FindSorafsPopCredentialCommitmentByDigest,
            FindSorafsPopCommitmentRootByVersion,
            FindSorafsPopRevocationPublicationByVersion,
            FindSorafsPopRevocationByNonceCommitment,
            FindSorafsPopAuditDigestBySequence,
            FindSorafsPopRegistryStatus,
            FindSorafsRepairTask,
            FindSorafsRepairTasks,
            FindSorafsRepairStatus,
            FindSorafsRepairEvents,
            FindSorafsProofOutcome,
            FindSorafsProofOutcomeEvents,
            FindSorafsReputationJournalAuthorityPolicy,
            FindSorafsReputationJournalEventBySourceId,
            FindSorafsReputationJournalEvents,
            FindSorafsModerationPolicy,
            FindSorafsModerationAppeal,
            FindSorafsModerationJurorEligibility,
            FindSorafsModerationCase,
            FindSorafsModerationCommit,
            FindSorafsModerationReveal,
            FindSorafsModerationChallenge,
            FindSorafsModerationOutcome,
            FindSorafsModerationNoShow,
            FindSorafsModerationStatus,
            FindSorafsModerationSnapshot,
            FindSorafsModerationEvents,
            FindDataspaceNameOwnerById,
            FindMusubiExactPackageV1,
            FindMusubiExactReleaseV1,
            FindMusubiProviderBundleAttestationV1,
            FindMusubiResolverIndexV1,
            FindMusubiVersionsV1,
            FindMusubiMaintainersV1,
            FindMusubiArchiveLocationsV1,
            FindMusubiArchiveRetentionV1,
            FindMusubiAliasV1,
            FindMusubiAliasHistoryV1,
            FindMusubiOrderedPrefixV1,
            FindDomainById,
            FindNftById,
        )
    }
}
/// Execute through a source-specific ordinary adapter when limits are attached.
fn execute_iterable_source<T, Q, E>(
    query: Q,
    predicate: CompoundPredicate<T>,
    params: &QueryParams,
    limits: QueryLimits,
    mode: ordinary_memory::OrdinaryCursorMode,
    state: &impl StateReadOnly,
) -> Result<(impl Iterator<Item = T>, QueryExecutionStats), QueryAttemptError>
where
    T: NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de> + Send + Sync + 'static,
    Q: ValidQuery<E, Item = T> + 'static,
    E: Into<QueryAttemptError>,
{
    ordinary_iterable::execute(
        query,
        predicate,
        params,
        mode,
        limits.ordinary_execution_limits,
        state,
    )
}
fn encode_stored_query_revalidation_request(
    request: &QueryRequest,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, Error> {
    if let Some(max_bytes) = max_bytes {
        let max_bytes = usize::try_from(max_bytes).map_err(|_| Error::CapacityLimit)?;
        return ordinary_iterable::encode_bounded_frame(request, max_bytes);
    }
    norito::encode_canonical(request).map_err(|error| {
        Error::Conversion(format!(
            "failed to encode stored-query authorization request: {error}"
        ))
    })
}
impl SortableQueryOutput for iroha_data_model::block::SignedBlock {
    type TiebreakKey = Vec<u8>;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        norito::codec::Encode::encode(self)
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_encoded_vec_tiebreak_len(self, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::block::BlockHeader {
    type TiebreakKey = Vec<u8>;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        norito::codec::Encode::encode(self)
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_encoded_vec_tiebreak_len(self, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::proof::ProofRecord {
    type TiebreakKey = iroha_data_model::proof::ProofId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.id, limit)
    }
    fn tiebreak_cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}
impl SortableQueryOutput for iroha_data_model::oracle::FeedConfig {
    type TiebreakKey = iroha_data_model::oracle::FeedId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.feed_id.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.feed_id, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::events::data::oracle::FeedEventRecord {
    type TiebreakKey = Vec<u8>;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        norito::codec::Encode::encode(&self.event)
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_encoded_vec_tiebreak_len(&self.event, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::oracle::OracleProviderStatsRecord {
    type TiebreakKey = iroha_data_model::oracle::OracleProviderKey;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.key.clone()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.key, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::oracle::OracleDispute {
    type TiebreakKey = iroha_data_model::oracle::OracleDisputeId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.id, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::oracle::OracleChangeProposal {
    type TiebreakKey = iroha_data_model::oracle::OracleChangeId;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.id
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.id, limit)
    }
}
impl SortableQueryOutput for iroha_data_model::oracle::TwitterBindingRecord {
    type TiebreakKey = iroha_crypto::Hash;
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        self.binding_digest()
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&self.binding_digest(), limit)
    }
}
impl SortableQueryOutput for iroha_data_model::oracle::DefiOracleAttestation {
    type TiebreakKey = (iroha_data_model::oracle::DefiOracleAttestationKey, u64);
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
        None
    }
    fn tiebreak_key(&self) -> Self::TiebreakKey {
        (self.key, self.oracle_slot)
    }
    fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
        bounded_bare_encoded_len(&(self.key, self.oracle_slot), limit)
    }
}
/// Applies sorting and pagination to the query output and wraps it into a type-erasing batching iterator.
///
/// # Errors
///
/// Returns an error if the fetch size exceeds the configured limits.
pub fn apply_query_postprocessing<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
) -> Result<ErasedQueryIterator, Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    let (output, _processed_items) =
        apply_query_postprocessing_with_budget(iter, selector, params, limits, None)?;
    Ok(output)
}
fn compare_sorted_query_keys<K: Ord>(
    left_key: Option<&Json>,
    left_tiebreak: &K,
    right_key: Option<&Json>,
    right_tiebreak: &K,
    order: SortOrder,
) -> core::cmp::Ordering {
    use core::cmp::Ordering::*;
    match (left_key, right_key) {
        (None, None) => left_tiebreak.cmp(right_tiebreak),
        (None, Some(_)) => Greater,
        (Some(_), None) => Less,
        (Some(left_key), Some(right_key)) => {
            let primary = match order {
                SortOrder::Asc => left_key.cmp(right_key),
                SortOrder::Desc => right_key.cmp(left_key),
            };
            if primary == Equal {
                left_tiebreak.cmp(right_tiebreak)
            } else {
                primary
            }
        }
    }
}
fn compare_sorted_query_indices<T: SortableQueryOutput>(
    left_index: usize,
    right_index: usize,
    sort_keys: &[Option<Json>],
    tiebreak_keys: &[T::TiebreakKey],
    order: SortOrder,
) -> core::cmp::Ordering {
    compare_sorted_query_keys(
        sort_keys[left_index].as_ref(),
        &tiebreak_keys[left_index],
        sort_keys[right_index].as_ref(),
        &tiebreak_keys[right_index],
        order,
    )
}
struct EphemeralSortedEntry<T: SortableQueryOutput> {
    value: T,
    sort_key: Option<Json>,
    tiebreak_key: T::TiebreakKey,
    order: SortOrder,
}
impl<T: SortableQueryOutput> PartialEq for EphemeralSortedEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == core::cmp::Ordering::Equal
    }
}
impl<T: SortableQueryOutput> Eq for EphemeralSortedEntry<T> {}
impl<T: SortableQueryOutput> PartialOrd for EphemeralSortedEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: SortableQueryOutput> Ord for EphemeralSortedEntry<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        compare_sorted_query_keys(
            self.sort_key.as_ref(),
            &self.tiebreak_key,
            other.sort_key.as_ref(),
            &other.tiebreak_key,
            self.order,
        )
    }
}
const STREAMING_SORTED_PREFIX_LIMIT: usize = 4096;
struct ScannedTransactionPage {
    values: Vec<CommittedTransaction>,
    remaining_items: Option<u64>,
    has_more: bool,
    execution_stats: QueryExecutionStats,
    history_cursor: Option<TransactionHistoryCursor>,
}
struct TransactionReplayCheckpoint {
    history_cursor: TransactionHistoryCursor,
    remaining_items: Option<u64>,
}
fn transaction_fetch_size(params: &QueryParams, limits: QueryLimits) -> Result<NonZeroU64, Error> {
    let fetch_size = params.fetch_size.fetch_size.unwrap_or(DEFAULT_FETCH_SIZE);
    if fetch_size.get() > limits.max_fetch_size {
        return Err(Error::FetchSizeTooBig);
    }
    Ok(fetch_size)
}
fn scan_unsorted_transaction_page(
    state: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    params: &QueryParams,
    limits: QueryLimits,
    returned_offset: u64,
    anchor: TransactionHistoryAnchor,
    history_cursor: Option<TransactionHistoryCursor>,
    known_remaining_items: Option<u64>,
    budget_items: Option<u64>,
    execution_budget: Option<QueryExecutionBudget>,
) -> Result<ScannedTransactionPage, Error> {
    let fetch_size = transaction_fetch_size(params, limits)?;
    let remaining_limit = params
        .pagination
        .limit_value()
        .map(|limit| limit.get().saturating_sub(returned_offset));
    if remaining_limit == Some(0) {
        return Err(Error::CursorDone);
    }
    let exact = limits.count_mode == QueryCountMode::Exact;
    if known_remaining_items.is_some() && !exact {
        return Err(Error::Conversion(
            "bounded transaction scan received an exact remaining count".to_owned(),
        ));
    }
    let fetch_size = usize::try_from(fetch_size.get()).unwrap_or(usize::MAX);
    let page_capacity = remaining_limit.map_or(fetch_size, |limit| {
        usize::try_from(limit).unwrap_or(usize::MAX).min(fetch_size)
    });
    let page_capacity = known_remaining_items.map_or(page_capacity, |remaining| {
        usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(page_capacity)
    });
    let source_offset = if history_cursor.is_none() {
        params.pagination.offset_value()
    } else {
        0
    };
    let scan_limit = remaining_limit;
    let limit_allows_probe = remaining_limit
        .is_none_or(|remaining| remaining > u64::try_from(page_capacity).unwrap_or(u64::MAX));
    let exact_full_scan = exact && known_remaining_items.is_none();
    let mut matched = 0_u64;
    let processed_items = Cell::new(0_u64);
    let processed_bytes = Cell::new(0_u64);
    let scan_work_limit =
        budget_items.unwrap_or(iroha_data_model::query::parameters::MAX_FETCH_SIZE.get());
    let scan_byte_limit = super::tx::transaction_history_byte_limit(scan_work_limit);
    let mut values = Vec::with_capacity(page_capacity.min(1024));
    let mut has_more = false;
    let mut next_history_cursor = None;
    visit_committed_transactions(
        state,
        filter,
        anchor,
        history_cursor,
        scan_byte_limit,
        |projection_work, source_bytes| {
            let next_items = processed_items
                .get()
                .checked_add(projection_work)
                .ok_or(Error::GasBudgetExceeded)?;
            let next_bytes = processed_bytes
                .get()
                .checked_add(source_bytes)
                .ok_or(Error::GasBudgetExceeded)?;
            processed_items.set(next_items);
            processed_bytes.set(next_bytes);
            if next_items > scan_work_limit || next_bytes > scan_byte_limit {
                return Err(Error::GasBudgetExceeded);
            }
            if let Some(budget) = execution_budget {
                budget.ensure(next_items, processed_bytes.get())?;
            }
            Ok(())
        },
        |transaction, matches, cursor_after| {
            if !matches {
                return Ok(ControlFlow::Continue(()));
            }
            let position = matched;
            matched = matched.saturating_add(1);
            let Some(after_offset) = position.checked_sub(source_offset) else {
                return Ok(ControlFlow::Continue(()));
            };
            if scan_limit.is_some_and(|limit| after_offset >= limit) {
                // Exact mode continues to validate every selected carrier even after
                // the requested pagination window is fully counted.
                return Ok(if exact_full_scan {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(())
                });
            }
            if values.len() < page_capacity {
                values.push(transaction);
                if values.len() == page_capacity {
                    next_history_cursor = Some(cursor_after);
                }
                if values.len() == page_capacity
                    && (known_remaining_items.is_some()
                        || (!exact_full_scan && !limit_allows_probe))
                {
                    return Ok(ControlFlow::Break(()));
                }
                return Ok(ControlFlow::Continue(()));
            }
            if !exact_full_scan {
                has_more = true;
                return Ok(ControlFlow::Break(()));
            }
            Ok(ControlFlow::Continue(()))
        },
    )?;
    let execution_stats = QueryExecutionStats {
        processed_items: processed_items.get(),
        processed_bytes: processed_bytes.get(),
    };
    if let Some(known_remaining_items) = known_remaining_items {
        let returned = u64::try_from(values.len()).unwrap_or(u64::MAX);
        let expected = known_remaining_items
            .min(scan_limit.unwrap_or(u64::MAX))
            .min(u64::try_from(fetch_size).unwrap_or(u64::MAX));
        if returned != expected {
            return Err(Error::Expired);
        }
        let remaining_items = known_remaining_items.saturating_sub(returned);
        has_more = remaining_items > 0;
        Ok(ScannedTransactionPage {
            values,
            remaining_items: Some(remaining_items),
            has_more,
            execution_stats,
            history_cursor: next_history_cursor,
        })
    } else if exact {
        let total_after_pagination = matched
            .saturating_sub(source_offset)
            .min(scan_limit.unwrap_or(u64::MAX));
        let returned = u64::try_from(values.len()).unwrap_or(u64::MAX);
        let remaining_items = total_after_pagination.saturating_sub(returned);
        has_more = remaining_items > 0;
        Ok(ScannedTransactionPage {
            values,
            remaining_items: Some(remaining_items),
            has_more,
            execution_stats,
            history_cursor: next_history_cursor,
        })
    } else {
        Ok(ScannedTransactionPage {
            values,
            remaining_items: None,
            has_more,
            execution_stats,
            history_cursor: next_history_cursor,
        })
    }
}
fn transaction_sorted_prefix_keep(
    params: &QueryParams,
    limits: QueryLimits,
    returned_offset: u64,
) -> Result<usize, Error> {
    let fetch_size = transaction_fetch_size(params, limits)?;
    let remaining_limit = params
        .pagination
        .limit_value()
        .map(|limit| limit.get().saturating_sub(returned_offset));
    if remaining_limit == Some(0) {
        return Err(Error::CursorDone);
    }
    let take =
        remaining_limit.map_or_else(|| fetch_size.get(), |limit| limit.min(fetch_size.get()));
    let keep = params
        .pagination
        .offset_value()
        .saturating_add(returned_offset)
        .saturating_add(take);
    Ok(usize::try_from(keep).unwrap_or(usize::MAX))
}
#[allow(clippy::too_many_arguments)]
fn collect_sorted_transaction_prefix(
    state: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    key: &Name,
    order: SortOrder,
    keep: usize,
    anchor: TransactionHistoryAnchor,
    budget_items: Option<u64>,
    execution_budget: Option<QueryExecutionBudget>,
) -> Result<(Vec<CommittedTransaction>, u64, QueryExecutionStats), Error> {
    if keep > STREAMING_SORTED_PREFIX_LIMIT {
        return Err(Error::GasBudgetExceeded);
    }
    let mut heap = BinaryHeap::new();
    heap.try_reserve(keep).map_err(|_| Error::CapacityLimit)?;
    let mut matched = 0_u64;
    let processed_items = Cell::new(0_u64);
    let processed_bytes = Cell::new(0_u64);
    let scan_work_limit =
        budget_items.unwrap_or(iroha_data_model::query::parameters::MAX_FETCH_SIZE.get());
    let scan_byte_limit = super::tx::transaction_history_byte_limit(scan_work_limit);
    visit_committed_transactions(
        state,
        filter,
        anchor,
        None,
        scan_byte_limit,
        |projection_work, source_bytes| {
            let next_items = processed_items
                .get()
                .checked_add(projection_work)
                .ok_or(Error::GasBudgetExceeded)?;
            let next_bytes = processed_bytes
                .get()
                .checked_add(source_bytes)
                .ok_or(Error::GasBudgetExceeded)?;
            processed_items.set(next_items);
            processed_bytes.set(next_bytes);
            if next_items > scan_work_limit || next_bytes > scan_byte_limit {
                return Err(Error::GasBudgetExceeded);
            }
            if let Some(budget) = execution_budget {
                budget.ensure(next_items, processed_bytes.get())?;
            }
            Ok(())
        },
        |value, matches, _| {
            let mut current_stats = QueryExecutionStats {
                processed_items: processed_items.get(),
                processed_bytes: processed_bytes.get(),
            };
            // Carrier bytes and this row were admitted before loading/cloning.
            if !matches {
                processed_bytes.set(current_stats.processed_bytes);
                return Ok(ControlFlow::Continue(()));
            }
            matched = matched.saturating_add(1);
            if keep == 0 {
                processed_bytes.set(current_stats.processed_bytes);
                return Ok(ControlFlow::Continue(()));
            }
            let sort_key = value.get_metadata_sorting_key(key);
            if let Some(sort_key) = sort_key {
                current_stats.record_value_bytes(sort_key, execution_budget)?;
            }
            let tiebreak_key =
                materialize_admitted_tiebreak_key(&value, &mut current_stats, execution_budget)?;
            processed_bytes.set(current_stats.processed_bytes);
            let entry = EphemeralSortedEntry {
                sort_key: sort_key.cloned(),
                tiebreak_key,
                value,
                order,
            };
            if heap.len() < keep {
                heap.push(entry);
            } else if heap
                .peek()
                .is_some_and(|worst| entry.cmp(worst) == core::cmp::Ordering::Less)
            {
                let _ = heap.pop();
                heap.push(entry);
            }
            Ok(ControlFlow::Continue(()))
        },
    )?;
    let execution_stats = QueryExecutionStats {
        processed_items: processed_items.get(),
        processed_bytes: processed_bytes.get(),
    };
    let mut entries = heap.into_vec();
    entries.sort_unstable();
    Ok((
        entries.into_iter().map(|entry| entry.value).collect(),
        matched,
        execution_stats,
    ))
}
fn scan_sorted_transaction_page(
    state: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    params: &QueryParams,
    limits: QueryLimits,
    returned_offset: u64,
    anchor: TransactionHistoryAnchor,
    budget_items: Option<u64>,
    execution_budget: Option<QueryExecutionBudget>,
) -> Result<ScannedTransactionPage, Error> {
    let keep = transaction_sorted_prefix_keep(params, limits, returned_offset)?;
    let key = params
        .sorting
        .sort_by_metadata_key
        .as_ref()
        .ok_or_else(|| Error::Conversion("sorted transaction scan has no metadata key".into()))?;
    let order = params.sorting.order.unwrap_or(SortOrder::Asc);
    let (entries, matched, execution_stats) = collect_sorted_transaction_prefix(
        state,
        filter,
        key,
        order,
        keep,
        anchor,
        budget_items,
        execution_budget,
    )?;
    let offset = params
        .pagination
        .offset_value()
        .saturating_add(returned_offset);
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let values = entries.into_iter().skip(offset).collect::<Vec<_>>();
    let total_after_pagination = matched
        .saturating_sub(params.pagination.offset_value())
        .min(
            params
                .pagination
                .limit_value()
                .map_or(u64::MAX, NonZeroU64::get),
        );
    let returned = returned_offset.saturating_add(u64::try_from(values.len()).unwrap_or(u64::MAX));
    let remaining_items = total_after_pagination.saturating_sub(returned);
    let exact = limits.count_mode == QueryCountMode::Exact;
    Ok(ScannedTransactionPage {
        values,
        remaining_items: exact.then_some(remaining_items),
        has_more: remaining_items > 0,
        execution_stats,
        history_cursor: None,
    })
}
fn materialize_sorted_transaction_window(
    state: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    params: &QueryParams,
    anchor: TransactionHistoryAnchor,
    budget_items: Option<u64>,
    execution_budget: Option<QueryExecutionBudget>,
) -> Result<Vec<CommittedTransaction>, Error> {
    let limit = params
        .pagination
        .limit_value()
        .ok_or(Error::GasBudgetExceeded)?;
    let offset = params.pagination.offset_value();
    let keep = offset.saturating_add(limit.get());
    let keep = usize::try_from(keep).map_err(|_| Error::GasBudgetExceeded)?;
    let key = params
        .sorting
        .sort_by_metadata_key
        .as_ref()
        .ok_or_else(|| Error::Conversion("sorted transaction scan has no metadata key".into()))?;
    let order = params.sorting.order.unwrap_or(SortOrder::Asc);
    let (prefix, _, _) = collect_sorted_transaction_prefix(
        state,
        filter,
        key,
        order,
        keep,
        anchor,
        budget_items,
        execution_budget,
    )?;
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let limit = usize::try_from(limit.get()).unwrap_or(usize::MAX);
    Ok(prefix.into_iter().skip(offset).take(limit).collect())
}
fn project_transaction_page(
    values: Vec<CommittedTransaction>,
    selector: SelectorTuple<CommittedTransaction>,
    fetch_size: NonZeroU64,
) -> Result<QueryOutputBatchBoxTuple, Error> {
    let mut iter = ErasedQueryIterator::new(values.into_iter(), selector, fetch_size);
    iter.next_batch(0).map(|(batch, _)| batch)
}
fn prepare_materialized_transaction_start(
    values: Vec<CommittedTransaction>,
    selector: SelectorTuple<CommittedTransaction>,
    fetch_size: NonZeroU64,
    count_mode: QueryCountMode,
) -> Result<PreparedQueryStart, Error> {
    let fetch_size_usize = usize::try_from(fetch_size.get()).unwrap_or(usize::MAX);
    let mut values = values.into_iter();
    let first_values = values.by_ref().take(fetch_size_usize).collect::<Vec<_>>();
    let first_len = first_values.len();
    let deferred_values = values.collect::<Vec<_>>();
    let remaining = u64::try_from(deferred_values.len()).unwrap_or(u64::MAX);
    let first_batch = project_transaction_page(first_values, selector.clone(), fetch_size)?;
    let reported_remaining = (count_mode == QueryCountMode::Exact).then_some(remaining);
    if deferred_values.is_empty() {
        return Ok(PreparedQueryStart {
            first_batch,
            remaining_items: reported_remaining,
            deferred_continuation: None,
        });
    }
    let first_cursor =
        NonZeroU64::new(u64::try_from(first_len).unwrap_or(u64::MAX)).ok_or_else(|| {
            Error::Conversion("materialized transaction window has an empty first page".to_owned())
        })?;
    let deferred_continuation = DeferredQueryContinuation::new(
        first_cursor,
        reported_remaining,
        move || match count_mode {
            QueryCountMode::Exact => ErasedQueryIterator::new_with_cursor(
                deferred_values.into_iter(),
                selector,
                fetch_size,
                first_cursor.get(),
            ),
            QueryCountMode::Bounded => ErasedQueryIterator::new_streaming_with_cursor(
                deferred_values.into_iter(),
                selector,
                fetch_size,
                first_cursor.get(),
            ),
        },
    );
    Ok(PreparedQueryStart {
        first_batch,
        remaining_items: reported_remaining,
        deferred_continuation: Some(deferred_continuation),
    })
}
fn validate_transaction_sorted_materialization_budget(
    params: &QueryParams,
    limits: QueryLimits,
) -> Result<(), Error> {
    let _ = transaction_fetch_size(params, limits)?;
    if params.sorting.sort_by_metadata_key.is_none() {
        return Ok(());
    }
    // Sorting requires a global scan. Require a finite, bounded prefix so a
    // client cannot turn the transaction query into history-sized retained
    // materialization. `GasBudgetExceeded` is also the public materialization-
    // budget error.
    let Some(limit) = params.pagination.limit_value() else {
        return Err(Error::GasBudgetExceeded);
    };
    let keep = params.pagination.offset_value().saturating_add(limit.get());
    if !usize::try_from(keep).is_ok_and(|keep| keep <= STREAMING_SORTED_PREFIX_LIMIT) {
        return Err(Error::GasBudgetExceeded);
    }
    Ok(())
}
fn scan_transaction_page(
    state: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    params: &QueryParams,
    limits: QueryLimits,
    returned_offset: u64,
    anchor: TransactionHistoryAnchor,
    history_cursor: Option<TransactionHistoryCursor>,
    known_remaining_items: Option<u64>,
    budget_items: Option<u64>,
    execution_budget: Option<QueryExecutionBudget>,
) -> Result<ScannedTransactionPage, Error> {
    let budget_items = Some(
        budget_items
            .unwrap_or(limits.max_fetch_size)
            .min(limits.max_fetch_size),
    );
    if params.sorting.sort_by_metadata_key.is_some() {
        if history_cursor.is_some() || known_remaining_items.is_some() {
            return Err(Error::Conversion(
                "sorted transaction scans do not accept history cursors".to_owned(),
            ));
        }
        scan_sorted_transaction_page(
            state,
            filter,
            params,
            limits,
            returned_offset,
            anchor,
            budget_items,
            execution_budget,
        )
    } else {
        scan_unsorted_transaction_page(
            state,
            filter,
            params,
            limits,
            returned_offset,
            anchor,
            history_cursor,
            known_remaining_items,
            budget_items,
            execution_budget,
        )
    }
}
#[allow(clippy::too_many_arguments)]
fn try_handle_find_transactions_stored(
    state: &impl StateReadOnly,
    filter: CompoundPredicate<CommittedTransaction>,
    selector: SelectorTuple<CommittedTransaction>,
    params: &QueryParams,
    limits: QueryLimits,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    gas_budget: Option<u64>,
    replay_state: Option<Weak<State>>,
) -> Result<QueryOutput, Error> {
    validate_transaction_sorted_materialization_budget(params, limits)?;
    let fixed_anchor = TransactionHistoryAnchor::capture(state);
    let fetch_size = transaction_fetch_size(params, limits)?;
    if params.sorting.sort_by_metadata_key.is_some() {
        let values = materialize_sorted_transaction_window(
            state,
            &filter,
            params,
            fixed_anchor,
            Some(
                gas_budget
                    .unwrap_or(limits.max_fetch_size)
                    .min(limits.max_fetch_size),
            ),
            limits
                .ordinary_execution_limits
                .map(OrdinaryQueryExecutionLimits::execution_budget),
        )?;
        let continuation_required =
            values.len() > usize::try_from(fetch_size.get()).unwrap_or(usize::MAX);
        if continuation_required && replay_state.is_none() {
            return Err(Error::Conversion(
                "FindTransactions continuation requires replay-capable stored query state"
                    .to_owned(),
            ));
        }
        let prepared = prepare_materialized_transaction_start(
            values,
            selector,
            fetch_size,
            limits.count_mode,
        )?;
        return live_query_store.handle_iter_start_prepared(prepared, authority, gas_budget);
    }
    let page = scan_transaction_page(
        state,
        &filter,
        params,
        limits,
        0,
        fixed_anchor,
        None,
        None,
        gas_budget,
        limits
            .ordinary_execution_limits
            .map(OrdinaryQueryExecutionLimits::execution_budget),
    )?;
    let page_len = page.values.len();
    let first_batch = project_transaction_page(page.values, selector.clone(), fetch_size)?;
    let continuation_required = page.has_more;
    if !continuation_required {
        return live_query_store.handle_iter_start_prepared(
            PreparedQueryStart {
                first_batch,
                remaining_items: page.remaining_items,
                deferred_continuation: None,
            },
            authority,
            gas_budget,
        );
    }
    let Some(replay_state) = replay_state else {
        return Err(Error::Conversion(
            "FindTransactions continuation requires replay-capable stored query state".to_owned(),
        ));
    };
    let history_cursor = page.history_cursor.ok_or_else(|| {
        Error::Conversion("transaction continuation omitted its history checkpoint".to_owned())
    })?;
    let first_cursor =
        NonZeroU64::new(u64::try_from(page_len).unwrap_or(u64::MAX)).ok_or_else(|| {
            Error::Conversion("transaction continuation has an empty first page".to_owned())
        })?;
    let params_for_replay = params.clone();
    let filter_for_replay = filter.clone();
    let selector_for_replay = selector;
    let checkpoint = Arc::new(Mutex::new(TransactionReplayCheckpoint {
        history_cursor,
        remaining_items: page.remaining_items,
    }));
    let make_next_page = Arc::new(move |cursor: u64, gas_budget: Option<u64>| {
        let state = replay_state.upgrade().ok_or(Error::Expired)?;
        let view = state.query_view();
        let mut checkpoint = checkpoint.lock().map_err(|_| {
            Error::Conversion("transaction replay checkpoint lock is poisoned".to_owned())
        })?;
        let page = scan_transaction_page(
            &view,
            &filter_for_replay,
            &params_for_replay,
            limits,
            cursor,
            fixed_anchor,
            Some(checkpoint.history_cursor),
            checkpoint.remaining_items,
            gas_budget,
            limits
                .ordinary_execution_limits
                .map(OrdinaryQueryExecutionLimits::execution_budget),
        )?;
        let page_len = u64::try_from(page.values.len()).unwrap_or(u64::MAX);
        let batch = project_transaction_page(page.values, selector_for_replay.clone(), fetch_size)?;
        let next_cursor = if page.has_more {
            if page_len == 0 {
                return Err(Error::Conversion(
                    "transaction continuation made no progress".to_owned(),
                ));
            }
            Some(
                cursor
                    .checked_add(page_len)
                    .and_then(NonZeroU64::new)
                    .ok_or_else(|| {
                        Error::Conversion("transaction continuation cursor overflowed".to_owned())
                    })?,
            )
        } else {
            None
        };
        if page.has_more {
            checkpoint.history_cursor = page.history_cursor.ok_or_else(|| {
                Error::Conversion(
                    "transaction continuation omitted its next history checkpoint".to_owned(),
                )
            })?;
        }
        checkpoint.remaining_items = page.remaining_items;
        Ok((batch, page.remaining_items, next_cursor))
    });
    let paged_continuation = if let Some(remaining_items) = page.remaining_items {
        let make_next_page = Arc::clone(&make_next_page);
        PagedQueryContinuation::new_counted_budgeted(
            first_cursor,
            remaining_items,
            move |cursor, gas_budget| {
                let (batch, remaining_items, next_cursor) = make_next_page(cursor, gas_budget)?;
                let remaining_items = remaining_items.ok_or_else(|| {
                    Error::Conversion(
                        "exact transaction page omitted its remaining count".to_owned(),
                    )
                })?;
                Ok((batch, remaining_items, next_cursor))
            },
        )
    } else {
        let make_next_page = Arc::clone(&make_next_page);
        PagedQueryContinuation::new_budgeted(first_cursor, move |cursor, gas_budget| {
            let (batch, _, next_cursor) = make_next_page(cursor, gas_budget)?;
            Ok((batch, next_cursor))
        })
    };
    live_query_store.handle_iter_start_paged_prepared(
        PreparedPagedQueryStart {
            first_batch,
            paged_continuation: Some(paged_continuation),
        },
        authority,
        gas_budget,
    )
}
fn try_handle_find_transactions_ephemeral(
    state: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    selector: SelectorTuple<CommittedTransaction>,
    params: &QueryParams,
    limits: QueryLimits,
    budget: Option<QueryExecutionBudget>,
) -> Result<(QueryOutput, QueryExecutionStats), Error> {
    validate_transaction_sorted_materialization_budget(params, limits)?;
    let page = scan_transaction_page(
        state,
        filter,
        params,
        limits,
        0,
        TransactionHistoryAnchor::capture(state),
        None,
        None,
        budget.map(QueryExecutionBudget::max_items),
        budget,
    )?;
    let batch = project_transaction_page(
        page.values,
        selector,
        transaction_fetch_size(params, limits)?,
    )?;
    let output = match page.remaining_items {
        Some(remaining_items) => QueryOutput::new(batch, remaining_items, None),
        None => QueryOutput::new_bounded(batch, page.has_more, None),
    };
    Ok((output, page.execution_stats))
}
#[allow(clippy::too_many_arguments)]
fn handle_find_transactions_stored(
    state: &impl StateReadOnly,
    filter: CompoundPredicate<CommittedTransaction>,
    selector: SelectorTuple<CommittedTransaction>,
    params: &QueryParams,
    limits: QueryLimits,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    gas_budget: Option<u64>,
    replay_state: Option<Weak<State>>,
) -> Result<QueryOutput, Error> {
    try_handle_find_transactions_stored(
        state,
        filter,
        selector,
        params,
        limits,
        live_query_store,
        authority,
        gas_budget,
        replay_state,
    )
}
fn handle_find_transactions_ephemeral(
    state: &impl StateReadOnly,
    filter: CompoundPredicate<CommittedTransaction>,
    selector: SelectorTuple<CommittedTransaction>,
    params: &QueryParams,
    limits: QueryLimits,
    budget: Option<QueryExecutionBudget>,
) -> Result<(QueryOutput, QueryExecutionStats), Error> {
    try_handle_find_transactions_ephemeral(state, &filter, selector, params, limits, budget)
}
fn collect_ephemeral_sorted_prefix<I>(
    iter: I,
    key: &Name,
    order: SortOrder,
    keep: usize,
    budget: Option<QueryExecutionBudget>,
    execution_stats: &mut QueryExecutionStats,
) -> Result<(Vec<I::Item>, u64), Error>
where
    I: Iterator,
    I::Item: SortableQueryOutput + SerializePayload,
{
    let mut count = 0_u64;
    if keep == 0 {
        for value in iter {
            count = count.saturating_add(1);
            execution_stats.record_item(&value, budget)?;
        }
        return Ok((Vec::new(), count));
    }
    let (mut heap, _) = ordinary_iterable::ExactTopK::new(keep, u64::MAX)?;
    for value in iter {
        count = count.saturating_add(1);
        execution_stats.record_item(&value, budget)?;
        let sort_key = value.get_metadata_sorting_key(key);
        if let Some(sort_key) = sort_key {
            execution_stats.record_value_bytes(sort_key, budget)?;
        }
        let sort_key = sort_key.cloned();
        let tiebreak_key = materialize_admitted_tiebreak_key(&value, execution_stats, budget)?;
        let entry = EphemeralSortedEntry {
            value,
            sort_key,
            tiebreak_key,
            order,
        };
        let _ = heap.retain_smallest(entry);
    }
    Ok((heap.into_sorted().map(|entry| entry.value).collect(), count))
}
fn prepare_ordinary_stored_sorted_start<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
) -> Result<PreparedQueryStart, Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    let key = params
        .sorting
        .sort_by_metadata_key
        .as_ref()
        .ok_or_else(|| Error::Conversion("missing stored sort key".to_owned()))?;
    let requested = params.pagination.limit_value().ok_or_else(|| {
        Error::Conversion(
            "ordinary stored sorted query requires an explicit bounded limit".to_owned(),
        )
    })?;
    let offset =
        usize::try_from(params.pagination.offset_value()).map_err(|_| Error::CapacityLimit)?;
    let requested = usize::try_from(requested.get()).map_err(|_| Error::CapacityLimit)?;
    let keep = offset.checked_add(requested).ok_or(Error::CapacityLimit)?;
    let fetch_size = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE);
    let fetch_size_usize = usize::try_from(fetch_size.get()).map_err(|_| Error::CapacityLimit)?;
    let order = params.sorting.order.unwrap_or(SortOrder::Asc);
    let budget = limits
        .ordinary_execution_limits
        .map(OrdinaryQueryExecutionLimits::execution_budget);
    let mut execution_stats = QueryExecutionStats::default();
    let (values, count) =
        collect_ephemeral_sorted_prefix(iter, key, order, keep, budget, &mut execution_stats)?;
    debug_assert_eq!(execution_stats.processed_items(), count);
    let available = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .saturating_sub(offset)
        .min(requested);
    let first_len = available.min(fetch_size_usize);
    let mut requested_values = values.into_iter().skip(offset).take(available);
    let mut first_values = Vec::new();
    first_values
        .try_reserve_exact(first_len)
        .map_err(|_| Error::CapacityLimit)?;
    first_values.extend(requested_values.by_ref().take(first_len));
    let mut deferred_values = Vec::new();
    deferred_values
        .try_reserve_exact(available.saturating_sub(first_len))
        .map_err(|_| Error::CapacityLimit)?;
    deferred_values.extend(requested_values);
    let selector_for_deferred = selector.clone();
    let mut batch_iter = ErasedQueryIterator::new(first_values.into_iter(), selector, fetch_size);
    let (first_batch, _next) = batch_iter.next_batch(0)?;
    let remaining_items = u64::try_from(deferred_values.len()).map_err(|_| Error::CapacityLimit)?;
    if deferred_values.is_empty() {
        return Ok(PreparedQueryStart {
            first_batch,
            remaining_items: Some(0),
            deferred_continuation: None,
        });
    }
    let first_cursor = NonZeroU64::new(u64::try_from(first_len).map_err(|_| Error::CapacityLimit)?)
        .ok_or(Error::CapacityLimit)?;
    let deferred_continuation =
        DeferredQueryContinuation::new(first_cursor, Some(remaining_items), move || {
            ErasedQueryIterator::new_streaming_with_cursor(
                deferred_values.into_iter(),
                selector_for_deferred,
                fetch_size,
                first_cursor.get(),
            )
        });
    Ok(PreparedQueryStart {
        first_batch,
        remaining_items: Some(remaining_items),
        deferred_continuation: Some(deferred_continuation),
    })
}
#[derive(Debug, Clone)]
struct StoredSortedFastStartParams {
    key: Name,
    order: SortOrder,
    fetch_size: NonZeroU64,
    offset: usize,
    offset_u64: u64,
    limit: usize,
    keep: usize,
}
fn stored_sorted_fast_start_params(
    params: &QueryParams,
    limits: QueryLimits,
) -> Result<Option<StoredSortedFastStartParams>, Error> {
    let fetch_size = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE);
    if fetch_size.get() > limits.max_fetch_size {
        return Err(Error::FetchSizeTooBig);
    }
    let Some(key) = params.sorting.sort_by_metadata_key.clone() else {
        return Ok(None);
    };
    let offset_u64 = params.pagination.offset_value();
    let offset = usize::try_from(offset_u64).unwrap_or(usize::MAX);
    let limit = params.pagination.limit_value().map_or(usize::MAX, |limit| {
        usize::try_from(limit.get()).unwrap_or(usize::MAX)
    });
    let fetch_size_usize = usize::try_from(fetch_size.get()).unwrap_or(usize::MAX);
    let keep = offset.saturating_add(limit.min(fetch_size_usize));
    if keep > STREAMING_SORTED_PREFIX_LIMIT {
        return Ok(None);
    }
    Ok(Some(StoredSortedFastStartParams {
        key,
        order: params.sorting.order.unwrap_or(SortOrder::Asc),
        fetch_size,
        offset,
        offset_u64,
        limit,
        keep,
    }))
}
fn prepare_stored_sorted_start<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    fast: StoredSortedFastStartParams,
    budget_items: Option<u64>,
) -> Result<PreparedQueryStart, Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    let StoredSortedFastStartParams {
        key,
        order,
        fetch_size,
        offset,
        offset_u64,
        limit,
        keep,
    } = fast;
    let mut count = 0_u64;
    let mut overflow_values = Vec::new();
    let (mut heap, _) = ordinary_iterable::ExactTopK::new(keep, u64::MAX)?;
    for value in iter {
        count = count.saturating_add(1);
        if budget_items.is_some_and(|limit| count > limit) {
            return Err(Error::GasBudgetExceeded);
        }
        if keep == 0 {
            overflow_values.push(value);
            continue;
        }
        let entry = EphemeralSortedEntry {
            sort_key: value.get_metadata_sorting_key(&key).cloned(),
            tiebreak_key: value.tiebreak_key(),
            value,
            order,
        };
        if let Some(dropped) = heap.retain_smallest(entry) {
            overflow_values.push(dropped.value);
        }
    }
    let total_after_pagination = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .saturating_sub(offset)
        .min(limit);
    let batch_len =
        total_after_pagination.min(usize::try_from(fetch_size.get()).unwrap_or(usize::MAX));
    let mut first_batch_values = Vec::with_capacity(batch_len);
    let mut deferred_raw_values = Vec::with_capacity(overflow_values.len().saturating_add(offset));
    for (index, entry) in heap.into_sorted().enumerate() {
        if index < offset {
            deferred_raw_values.push(entry.value);
        } else if first_batch_values.len() < batch_len {
            first_batch_values.push(entry.value);
        } else {
            deferred_raw_values.push(entry.value);
        }
    }
    deferred_raw_values.append(&mut overflow_values);
    let selector_for_deferred = selector.clone();
    let mut batch_iter =
        ErasedQueryIterator::new(first_batch_values.into_iter(), selector, fetch_size);
    let (first_batch, _next) = batch_iter.next_batch(0)?;
    let remaining_items =
        u64::try_from(total_after_pagination.saturating_sub(batch_len)).unwrap_or(u64::MAX);
    if remaining_items == 0 {
        return Ok(PreparedQueryStart {
            first_batch,
            remaining_items: Some(remaining_items),
            deferred_continuation: None,
        });
    }
    let first_cursor = NonZeroU64::new(u64::try_from(batch_len).unwrap_or(u64::MAX))
        .expect("non-empty first batch is required for continuation");
    let continuation_limit =
        NonZeroU64::new(remaining_items).expect("continuation limit must be non-zero");
    let deferred_continuation =
        DeferredQueryContinuation::new(first_cursor, Some(remaining_items), move || {
            let mut values = Vec::with_capacity(deferred_raw_values.len());
            let mut sort_keys = Vec::with_capacity(deferred_raw_values.len());
            let mut tiebreak_keys = Vec::with_capacity(deferred_raw_values.len());
            for value in deferred_raw_values {
                sort_keys.push(value.get_metadata_sorting_key(&key).cloned());
                tiebreak_keys.push(value.tiebreak_key());
                values.push(Some(value));
            }
            let pagination = iroha_data_model::query::parameters::Pagination {
                offset: offset_u64,
                limit: Some(continuation_limit),
            };
            ErasedQueryIterator::new_with_cursor(
                IncrementalSortedValues::new(
                    values,
                    sort_keys,
                    tiebreak_keys,
                    pagination,
                    fetch_size,
                    order,
                ),
                selector_for_deferred,
                fetch_size,
                first_cursor.get(),
            )
        });
    Ok(PreparedQueryStart {
        first_batch,
        remaining_items: Some(remaining_items),
        deferred_continuation: Some(deferred_continuation),
    })
}
fn prepare_stored_unsorted_bounded_start<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
) -> Result<PreparedQueryStart, Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    let fetch_size = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE);
    if fetch_size.get() > limits.max_fetch_size {
        return Err(Error::FetchSizeTooBig);
    }
    let offset = params.pagination.offset_value();
    let limit = params.pagination.limit_value().map(|limit| limit.get());
    let fetch_size_usize = usize::try_from(fetch_size.get()).unwrap_or(usize::MAX);
    let first_take = limit.map_or_else(|| fetch_size.get(), |limit| limit.min(fetch_size.get()));
    let first_take = usize::try_from(first_take).map_err(|_| Error::CapacityLimit)?;
    let budget = limits
        .ordinary_execution_limits
        .map(OrdinaryQueryExecutionLimits::execution_budget);
    let mut execution_stats = QueryExecutionStats::default();
    let mut iter = iter;
    let mut skipped = 0_u64;
    while skipped < offset {
        let Some(value) = iter.next() else {
            break;
        };
        execution_stats.record_item(&value, budget)?;
        skipped = skipped.checked_add(1).ok_or(Error::GasBudgetExceeded)?;
    }
    let mut first_batch_values = Vec::new();
    first_batch_values
        .try_reserve_exact(first_take.min(fetch_size_usize))
        .map_err(|_| Error::CapacityLimit)?;
    while first_batch_values.len() < first_take {
        let Some(value) = iter.next() else {
            break;
        };
        execution_stats.record_item(&value, budget)?;
        first_batch_values.push(value);
    }
    let batch_len = first_batch_values.len();
    let batch_len_u64 = u64::try_from(batch_len).map_err(|_| Error::CapacityLimit)?;
    let remaining_limit = limit
        .map(|limit| limit.checked_sub(batch_len_u64).ok_or(Error::CapacityLimit))
        .transpose()?;
    if remaining_limit == Some(0) {
        drop(iter);
        let mut batch_iter =
            ErasedQueryIterator::new(first_batch_values.into_iter(), selector, fetch_size);
        let (first_batch, _next) = batch_iter.next_batch(0)?;
        return Ok(PreparedQueryStart {
            first_batch,
            remaining_items: None,
            deferred_continuation: None,
        });
    }
    let requested_tail = remaining_limit.unwrap_or(u64::MAX);
    let configured_retained_items = limits.ordinary_execution_limits.map_or_else(
        || u64::try_from(MAX_STORED_QUERY_RETAINED_ITEMS).unwrap_or(u64::MAX),
        |ordinary| ordinary.max_cursor_retained_items(),
    );
    let retained_item_limit = requested_tail.min(configured_retained_items);
    let retained_item_limit =
        usize::try_from(retained_item_limit).map_err(|_| Error::CapacityLimit)?;
    let must_detect_item_overflow =
        requested_tail > u64::try_from(retained_item_limit).map_err(|_| Error::CapacityLimit)?;
    let configured_retained_bytes = limits
        .ordinary_execution_limits
        .map_or(MAX_STORED_QUERY_RETAINED_BYTES, |ordinary| {
            ordinary.max_cursor_value_bytes()
        });
    let mut deferred_values = Vec::new();
    deferred_values
        .try_reserve_exact(retained_item_limit)
        .map_err(|_| Error::CapacityLimit)?;
    let mut retained_bytes = 0_u64;
    while deferred_values.len() < retained_item_limit {
        let Some(value) = iter.next() else {
            break;
        };
        execution_stats.record_item(&value, budget)?;
        let remaining_bytes = configured_retained_bytes
            .checked_sub(retained_bytes)
            .ok_or(Error::CapacityLimit)?;
        let value_bytes = match bounded_bare_encoded_len(&value, remaining_bytes) {
            Ok(bytes) => bytes,
            Err(Error::GasBudgetExceeded) => return Err(Error::CapacityLimit),
            Err(error) => return Err(error),
        };
        retained_bytes = retained_bytes
            .checked_add(value_bytes)
            .ok_or(Error::CapacityLimit)?;
        deferred_values.push(value);
    }
    if must_detect_item_overflow && let Some(value) = iter.next() {
        execution_stats.record_item(&value, budget)?;
        return Err(Error::CapacityLimit);
    }
    drop(iter);
    let selector_for_deferred = selector.clone();
    let mut batch_iter =
        ErasedQueryIterator::new(first_batch_values.into_iter(), selector, fetch_size);
    let (first_batch, _next) = batch_iter.next_batch(0)?;
    if deferred_values.is_empty() {
        return Ok(PreparedQueryStart {
            first_batch,
            remaining_items: None,
            deferred_continuation: None,
        });
    }
    let first_cursor = NonZeroU64::new(batch_len_u64)
        .expect("stored bounded continuation requires a non-empty first batch");
    let deferred_continuation = DeferredQueryContinuation::new(first_cursor, None, move || {
        ErasedQueryIterator::new_streaming_with_cursor(
            deferred_values.into_iter(),
            selector_for_deferred,
            fetch_size,
            first_cursor.get(),
        )
    });
    Ok(PreparedQueryStart {
        first_batch,
        remaining_items: None,
        deferred_continuation: Some(deferred_continuation),
    })
}
#[cfg(test)]
fn collect_unsorted_bounded_page<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
    returned_offset: u64,
) -> Result<(QueryOutputBatchBoxTuple, usize, bool), Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    let fetch_size = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE);
    if fetch_size.get() > limits.max_fetch_size {
        return Err(Error::FetchSizeTooBig);
    }
    let remaining_limit = params
        .pagination
        .limit_value()
        .map(|limit| limit.get().saturating_sub(returned_offset));
    if remaining_limit == Some(0) {
        return Err(Error::CursorDone);
    }
    let source_offset = params
        .pagination
        .offset_value()
        .saturating_add(returned_offset);
    let source_offset = usize::try_from(source_offset).unwrap_or(usize::MAX);
    let fetch_size_usize = usize::try_from(fetch_size.get()).unwrap_or(usize::MAX);
    let first_take = remaining_limit.map_or(fetch_size_usize, |limit| {
        usize::try_from(limit)
            .unwrap_or(usize::MAX)
            .min(fetch_size_usize)
    });
    let mut iter = iter.skip(source_offset).peekable();
    let first_batch_values: Vec<_> = iter.by_ref().take(first_take).collect();
    let batch_len = first_batch_values.len();
    let mut batch_iter =
        ErasedQueryIterator::new(first_batch_values.into_iter(), selector, fetch_size);
    let (first_batch, _next) = batch_iter.next_batch(0)?;
    let batch_len_u64 = u64::try_from(batch_len).unwrap_or(u64::MAX);
    let limit_allows_more = remaining_limit != Some(batch_len_u64);
    let has_more = batch_len > 0 && limit_allows_more && iter.peek().is_some();
    Ok((first_batch, batch_len, has_more))
}
#[cfg(test)]
fn prepare_stored_unsorted_bounded_replay_start<I, Q, E>(
    iter: I,
    query: Q,
    predicate: CompoundPredicate<I::Item>,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
    replay_state: Weak<State>,
) -> Result<PreparedPagedQueryStart, Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
    Q: ValidQuery<E, Item = I::Item> + Clone + Send + Sync + 'static,
    E: Into<QueryAttemptError>,
{
    let (first_batch, batch_len, has_more) =
        collect_unsorted_bounded_page(iter, selector.clone(), params, limits, 0)?;
    if !has_more {
        return Ok(PreparedPagedQueryStart {
            first_batch,
            paged_continuation: None,
        });
    }
    let first_cursor = NonZeroU64::new(u64::try_from(batch_len).unwrap_or(u64::MAX))
        .expect("stored bounded continuation requires a non-empty first batch");
    let params_for_replay = params.clone();
    let continuation = PagedQueryContinuation::new(first_cursor, move |cursor| {
        let state = replay_state.upgrade().ok_or(Error::Expired)?;
        let view = state.query_view();
        let iter = ValidQuery::execute(query.clone(), predicate.clone(), &view)
            .map_err(Into::into)
            .map_err(query_transport_error)?;
        let (batch, batch_len, has_more) = collect_unsorted_bounded_page(
            iter,
            selector.clone(),
            &params_for_replay,
            limits,
            cursor,
        )?;
        let next_cursor = has_more.then(|| {
            NonZeroU64::new(cursor.saturating_add(u64::try_from(batch_len).unwrap_or(u64::MAX)))
                .expect("cursor remains non-zero after a non-empty page")
        });
        Ok((batch, next_cursor))
    });
    Ok(PreparedPagedQueryStart {
        first_batch,
        paged_continuation: Some(continuation),
    })
}
fn handle_iter_start_stored<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    gas_budget: Option<u64>,
) -> Result<QueryOutput, Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    if params.sorting.sort_by_metadata_key.is_some() {
        if limits.ordinary_execution_limits.is_some() {
            let prepared = prepare_ordinary_stored_sorted_start(iter, selector, params, limits)?;
            return live_query_store.handle_iter_start_prepared(prepared, authority, gas_budget);
        }
        if let Some(fast) = stored_sorted_fast_start_params(params, limits)? {
            let prepared = prepare_stored_sorted_start(iter, selector, fast, None)?;
            return live_query_store.handle_iter_start_prepared(prepared, authority, gas_budget);
        }
    } else if limits.count_mode == QueryCountMode::Bounded {
        let prepared = prepare_stored_unsorted_bounded_start(iter, selector, params, limits)?;
        return live_query_store.handle_iter_start_prepared(prepared, authority, gas_budget);
    }
    let server_execution_budget = limits
        .ordinary_execution_limits
        .map(OrdinaryQueryExecutionLimits::execution_budget);
    let (batched, _) = apply_query_postprocessing_with_budget(
        iter,
        selector,
        params,
        limits,
        server_execution_budget,
    )?;
    live_query_store.handle_iter_start(batched, authority, gas_budget)
}
#[allow(clippy::too_many_arguments)]
fn handle_iter_start_stored_replayable<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
    live_query_store: &LiveQueryStoreHandle,
    authority: &AccountId,
    gas_budget: Option<u64>,
    _replay_state: Option<Weak<State>>,
    source_stats: QueryExecutionStats,
) -> Result<QueryOutput, Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    if let Some(ordinary) = limits.ordinary_execution_limits {
        return ordinary_stored::handle(
            iter,
            params,
            limits,
            ordinary,
            live_query_store,
            authority,
            gas_budget,
            source_stats,
        );
    }
    // A live `State` handle is not an immutable query snapshot: replaying a
    // generic continuation through it can observe later commits, and a weak
    // handle expires when the request owner drops its `Arc`. Keep generic
    // cursors snapshot-consistent by owning their deferred values. Transaction
    // history has a separate, fixed-anchor replay path in
    // `try_handle_find_transactions_stored`.
    handle_iter_start_stored(
        iter,
        selector,
        params,
        limits,
        live_query_store,
        authority,
        gas_budget,
    )
}
struct IncrementalSortedValues<T: SortableQueryOutput> {
    values: Vec<Option<T>>,
    sort_keys: Vec<Option<Json>>,
    tiebreak_keys: Vec<T::TiebreakKey>,
    order_indices: Vec<usize>,
    prepared: usize,
    next: usize,
    end: usize,
    chunk_size: usize,
    order: SortOrder,
}
impl<T: SortableQueryOutput> IncrementalSortedValues<T> {
    fn new(
        values: Vec<Option<T>>,
        sort_keys: Vec<Option<Json>>,
        tiebreak_keys: Vec<T::TiebreakKey>,
        pagination: iroha_data_model::query::parameters::Pagination,
        chunk_size: NonZeroU64,
        order: SortOrder,
    ) -> Self {
        let order_indices: Vec<_> = (0..values.len()).collect();
        let next = usize::try_from(pagination.offset_value())
            .unwrap_or(usize::MAX)
            .min(order_indices.len());
        let len = pagination
            .limit_value()
            .map_or(order_indices.len() - next, |limit| {
                usize::try_from(limit.get())
                    .unwrap_or(usize::MAX)
                    .min(order_indices.len() - next)
            });
        let end = next.saturating_add(len);
        Self {
            values,
            sort_keys,
            tiebreak_keys,
            order_indices,
            prepared: 0,
            next,
            end,
            chunk_size: usize::try_from(chunk_size.get())
                .unwrap_or(usize::MAX)
                .max(1),
            order,
        }
    }
    fn ensure_prepared(&mut self, required: usize) {
        let required = required.min(self.end).min(self.order_indices.len());
        if required <= self.prepared {
            return;
        }
        let sort_keys = &self.sort_keys;
        let tiebreak_keys = &self.tiebreak_keys;
        let order = self.order;
        let additional = required - self.prepared;
        let tail = &mut self.order_indices[self.prepared..];
        if additional < tail.len() {
            tail.select_nth_unstable_by(additional - 1, |left, right| {
                compare_sorted_query_indices::<T>(*left, *right, sort_keys, tiebreak_keys, order)
            });
        }
        tail[..additional].sort_by(|left, right| {
            compare_sorted_query_indices::<T>(*left, *right, sort_keys, tiebreak_keys, order)
        });
        self.prepared = required;
    }
}
impl<T: SortableQueryOutput> Iterator for IncrementalSortedValues<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.end {
            return None;
        }
        if self.next >= self.prepared {
            self.ensure_prepared(self.next.saturating_add(self.chunk_size));
        }
        let value_index = self.order_indices[self.next];
        self.next += 1;
        Some(
            self.values[value_index]
                .take()
                .expect("sorted query item should be present"),
        )
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end.saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}
impl<T: SortableQueryOutput> ExactSizeIterator for IncrementalSortedValues<T> {
    fn len(&self) -> usize {
        self.end.saturating_sub(self.next)
    }
}
#[cfg(test)]
fn apply_query_postprocessing_ephemeral_with_budget<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
    budget: Option<QueryExecutionBudget>,
) -> Result<(QueryOutput, QueryExecutionStats), Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    apply_query_postprocessing_ephemeral_with_budget_from_stats(
        iter,
        selector,
        params,
        limits,
        budget,
        QueryExecutionStats::default(),
    )
}
fn apply_query_postprocessing_ephemeral_with_budget_from_stats<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
    budget: Option<QueryExecutionBudget>,
    mut execution_stats: QueryExecutionStats,
) -> Result<(QueryOutput, QueryExecutionStats), Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    let initial_processed_items = execution_stats.processed_items();
    let batch_size = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE);
    let max_fetch = limits.max_fetch_size;
    if batch_size.get() > max_fetch {
        return Err(Error::FetchSizeTooBig);
    }
    if limits.count_mode == QueryCountMode::Bounded && params.sorting.sort_by_metadata_key.is_none()
    {
        let fetch_size = usize::try_from(batch_size.get()).unwrap_or(usize::MAX);
        let offset = params.pagination.offset_value();
        let limit = params.pagination.limit_value().map(|limit| limit.get());
        if let Some(ordinary) = limits.ordinary_execution_limits {
            if offset != 0 {
                // Admission refuses non-zero offsets before execution; this is
                // the fail-closed backstop for the bounded ordinary adapters.
                return Err(ordinary_memory::signed_query_shape_not_admitted(
                    "the iterable start",
                    "admits only a zero offset",
                ));
            }
            let (source_len, exact_len) = iter.size_hint();
            if exact_len != Some(source_len) {
                return Err(Error::CapacityLimit);
            }
            let batch_len = source_len.min(fetch_size);
            let maximum = ordinary
                .max_page_items()
                .checked_mul(ordinary.max_source_item_bytes())
                .ok_or(Error::CapacityLimit)?;
            let mut values = ordinary_iterable::ExactOwnedRows::new(batch_len, maximum)?;
            let mut iter = iter;
            for _ in 0..batch_len {
                let value = iter.next().ok_or(Error::CapacityLimit)?;
                values.push(value)?;
            }
            let limit_allows_more = limit.is_none_or(|limit| limit > batch_size.get());
            let has_more = if limit_allows_more {
                iter.next().is_some()
            } else {
                false
            };
            drop(iter);
            let batch = ordinary_iterable::exact_one_column_batch(QueryOutputBatchBox::from(
                values.finish()?.into_vec()?,
            ))?;
            return Ok((
                QueryOutput::new_bounded(batch, has_more, None),
                execution_stats,
            ));
        }
        let probe = limit.map_or_else(
            || fetch_size.saturating_add(1),
            |limit| {
                usize::try_from(limit)
                    .unwrap_or(usize::MAX)
                    .min(fetch_size.saturating_add(1))
            },
        );
        let mut processed = 0_u64;
        let mut skipped = 0_u64;
        let mut has_more = false;
        let mut first_batch_values = Vec::with_capacity(fetch_size.min(1024));
        let mut iter = iter;
        while skipped < offset {
            let Some(value) = iter.next() else {
                break;
            };
            execution_stats.record_item(&value, budget)?;
            skipped = skipped.saturating_add(1);
        }
        while usize::try_from(processed).unwrap_or(usize::MAX) < probe {
            let Some(value) = iter.next() else {
                break;
            };
            processed = processed.saturating_add(1);
            execution_stats.record_item(&value, budget)?;
            if first_batch_values.len() < fetch_size {
                first_batch_values.push(value);
            } else {
                has_more = true;
                break;
            }
        }
        drop(iter);
        let mut batch_iter =
            ErasedQueryIterator::new(first_batch_values.into_iter(), selector, batch_size);
        let (batch, _next) = batch_iter.next_batch(0)?;
        debug_assert_eq!(
            execution_stats.processed_items(),
            initial_processed_items
                .saturating_add(skipped)
                .saturating_add(processed)
        );
        return Ok((
            QueryOutput::new_bounded(batch, has_more, None),
            execution_stats,
        ));
    }
    if let Some(key) = params.sorting.sort_by_metadata_key.as_ref() {
        let offset = usize::try_from(params.pagination.offset_value()).unwrap_or(usize::MAX);
        let limit = params.pagination.limit_value().map_or(usize::MAX, |limit| {
            usize::try_from(limit.get()).unwrap_or(usize::MAX)
        });
        let fetch_size = usize::try_from(batch_size.get()).unwrap_or(usize::MAX);
        let order = params.sorting.order.unwrap_or(SortOrder::Asc);
        let keep = offset.saturating_add(limit.min(fetch_size));
        if keep <= STREAMING_SORTED_PREFIX_LIMIT {
            let (values, count) = collect_ephemeral_sorted_prefix(
                iter,
                key,
                order,
                keep,
                budget,
                &mut execution_stats,
            )?;
            let total_after_pagination = usize::try_from(count)
                .unwrap_or(usize::MAX)
                .saturating_sub(offset)
                .min(limit);
            let batch_len = total_after_pagination.min(fetch_size);
            let batch_values: Vec<_> = values.into_iter().skip(offset).take(batch_len).collect();
            let mut batch_iter =
                ErasedQueryIterator::new(batch_values.into_iter(), selector, batch_size);
            let (batch, _next) = batch_iter.next_batch(0)?;
            let remaining_items =
                u64::try_from(total_after_pagination.saturating_sub(batch_len)).unwrap_or(u64::MAX);
            debug_assert_eq!(
                execution_stats.processed_items(),
                initial_processed_items.saturating_add(count)
            );
            return Ok((
                QueryOutput::new(batch, remaining_items, None),
                execution_stats,
            ));
        }
        let mut count = 0_u64;
        let mut values = Vec::new();
        let mut sort_keys = Vec::new();
        let mut tiebreak_keys = Vec::new();
        for value in iter {
            count = count.saturating_add(1);
            execution_stats.record_item(&value, budget)?;
            let sort_key = value.get_metadata_sorting_key(key);
            if let Some(sort_key) = sort_key {
                execution_stats.record_value_bytes(sort_key, budget)?;
            }
            sort_keys.push(sort_key.cloned());
            let tiebreak_key =
                materialize_admitted_tiebreak_key(&value, &mut execution_stats, budget)?;
            tiebreak_keys.push(tiebreak_key);
            values.push(Some(value));
        }
        let total_after_pagination = values.len().saturating_sub(offset).min(limit);
        let batch_len = total_after_pagination.min(fetch_size);
        let mut order_indices: Vec<_> = (0..values.len()).collect();
        if batch_len > 0 {
            let keep = offset.saturating_add(batch_len);
            if keep < order_indices.len() {
                order_indices.select_nth_unstable_by(keep - 1, |left, right| {
                    compare_sorted_query_indices::<I::Item>(
                        *left,
                        *right,
                        &sort_keys,
                        &tiebreak_keys,
                        order,
                    )
                });
                order_indices.truncate(keep);
            }
            order_indices.sort_by(|left, right| {
                compare_sorted_query_indices::<I::Item>(
                    *left,
                    *right,
                    &sort_keys,
                    &tiebreak_keys,
                    order,
                )
            });
        }
        let batch_values: Vec<_> = order_indices
            .into_iter()
            .skip(offset)
            .take(batch_len)
            .map(|index| {
                values[index]
                    .take()
                    .expect("sorted query item should be present")
            })
            .collect();
        let mut batch_iter =
            ErasedQueryIterator::new(batch_values.into_iter(), selector, batch_size);
        let (batch, _next) = batch_iter.next_batch(0)?;
        let remaining_items =
            u64::try_from(total_after_pagination.saturating_sub(batch_len)).unwrap_or(u64::MAX);
        debug_assert_eq!(
            execution_stats.processed_items(),
            initial_processed_items.saturating_add(count)
        );
        return Ok((
            QueryOutput::new(batch, remaining_items, None),
            execution_stats,
        ));
    }
    let fetch_size = usize::try_from(batch_size.get()).unwrap_or(usize::MAX);
    let offset = params.pagination.offset_value();
    let limit = params.pagination.limit_value().map(|limit| limit.get());
    let mut skipped = 0_u64;
    let mut count = 0_u64;
    let mut first_batch_values = Vec::with_capacity(fetch_size.min(1024));
    let mut iter = iter;
    while skipped < offset {
        let Some(value) = iter.next() else {
            break;
        };
        execution_stats.record_item(&value, budget)?;
        skipped = skipped.checked_add(1).ok_or(Error::GasBudgetExceeded)?;
    }
    while limit.is_none_or(|limit| count < limit) {
        let Some(value) = iter.next() else {
            break;
        };
        execution_stats.record_item(&value, budget)?;
        count = count.checked_add(1).ok_or(Error::GasBudgetExceeded)?;
        if first_batch_values.len() < fetch_size {
            first_batch_values.push(value);
        }
    }
    let batch_len = first_batch_values.len();
    let mut batch_iter =
        ErasedQueryIterator::new(first_batch_values.into_iter(), selector, batch_size);
    let (batch, _next) = batch_iter.next_batch(0)?;
    let batch_len = u64::try_from(batch_len).map_err(|_| Error::GasBudgetExceeded)?;
    let remaining_items = count
        .checked_sub(batch_len)
        .ok_or(Error::GasBudgetExceeded)?;
    debug_assert_eq!(
        execution_stats.processed_items(),
        skipped.saturating_add(count)
    );
    Ok((
        QueryOutput::new(batch, remaining_items, None),
        execution_stats,
    ))
}
fn apply_query_postprocessing_with_budget<I>(
    iter: I,
    selector: SelectorTuple<I::Item>,
    params: &QueryParams,
    limits: QueryLimits,
    budget: Option<QueryExecutionBudget>,
) -> Result<(ErasedQueryIterator, u64), Error>
where
    I: Iterator<Item: SortableQueryOutput>,
    I::Item: HasProjection<SelectorMarker, AtomType = ()> + NoritoSerialize + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    // Validate and pick the fetch (aka batch) size from params
    let fetch_size = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE);
    let max_fetch = limits.max_fetch_size;
    if fetch_size.get() > max_fetch {
        return Err(Error::FetchSizeTooBig);
    }
    // sort & paginate, erase the iterator with QueryBatchedErasedIterator
    let materialized_item_limit = limits
        .ordinary_execution_limits
        .map(OrdinaryQueryExecutionLimits::max_cursor_retained_items);
    let mut execution_stats = QueryExecutionStats::default();
    let output = if let Some(key) = params.sorting.sort_by_metadata_key.as_ref() {
        // if sorting was requested, we need to retrieve all the results first
        let mut count = 0_u64;
        let mut values = Vec::new();
        let mut sort_keys = Vec::new();
        let mut tiebreak_keys = Vec::new();
        for value in iter {
            execution_stats.record_item(&value, budget)?;
            count = count.checked_add(1).ok_or(Error::GasBudgetExceeded)?;
            if materialized_item_limit.is_some_and(|limit| count > limit) {
                return Err(Error::CapacityLimit);
            }
            sort_keys.push(value.get_metadata_sorting_key(key).cloned());
            tiebreak_keys.push(value.tiebreak_key());
            values.push(Some(value));
        }
        let order = params.sorting.order.unwrap_or(SortOrder::Asc);
        ErasedQueryIterator::new(
            IncrementalSortedValues::new(
                values,
                sort_keys,
                tiebreak_keys,
                params.pagination,
                fetch_size,
                order,
            ),
            selector,
            fetch_size,
        )
    } else {
        // FP: this collect is very deliberate
        #[allow(clippy::needless_collect)]
        let mut count = 0_u64;
        let mut skipped = 0_u64;
        let offset = params.pagination.offset_value();
        let limit = params.pagination.limit_value().map(|limit| limit.get());
        let output = {
            let mut output = Vec::new();
            if let Some(materialized_item_limit) = materialized_item_limit {
                let requested = limit
                    .unwrap_or(materialized_item_limit)
                    .min(materialized_item_limit);
                let requested = usize::try_from(requested).map_err(|_| Error::CapacityLimit)?;
                output
                    .try_reserve_exact(requested)
                    .map_err(|_| Error::CapacityLimit)?;
            }
            let mut iter = iter;
            while skipped < offset {
                let Some(value) = iter.next() else {
                    break;
                };
                execution_stats.record_item(&value, budget)?;
                skipped = skipped.checked_add(1).ok_or(Error::GasBudgetExceeded)?;
            }
            while limit.is_none_or(|limit| count < limit) {
                let Some(value) = iter.next() else {
                    break;
                };
                execution_stats.record_item(&value, budget)?;
                count = count.checked_add(1).ok_or(Error::GasBudgetExceeded)?;
                if materialized_item_limit.is_some_and(|limit| count > limit) {
                    return Err(Error::CapacityLimit);
                }
                output.push(value);
            }
            output
        };
        ErasedQueryIterator::new(output.into_iter(), selector, fetch_size)
    };
    Ok((output, execution_stats.processed_items()))
}
fn validate_query_request_limits(
    request: &QueryRequest,
    limits: QueryLimits,
) -> Result<(), ValidationFail> {
    let max_fetch = limits.max_fetch_size;
    if let QueryRequest::Start(start) = request {
        let fetch_size = start
            .params
            .fetch_size
            .fetch_size
            .unwrap_or(DEFAULT_FETCH_SIZE);
        if fetch_size.get() > max_fetch {
            return Err(ValidationFail::QueryFailed(Error::FetchSizeTooBig));
        }
    }
    Ok(())
}
#[cfg(test)]
mod fetch_size_limit_tests {
    use super::*;
    use iroha_config::parameters::{actual::Root as ConfigRoot, defaults::torii as torii_defaults};
    use iroha_data_model::{
        permission::Permission,
        prelude::SelectorTuple,
        query::{
            QueryWithParams,
            parameters::{FetchSize, Pagination, QueryParams, Sorting},
        },
    };
    use iroha_primitives::json::Json;
    use nonzero_ext::nonzero;
    use std::io::Write;
    use tempfile::NamedTempFile;
    fn request_with_fetch_size(fetch_size: u64) -> QueryRequest {
        let fetch_size = std::num::NonZeroU64::new(fetch_size).expect("nonzero fetch size");
        QueryRequest::Start(QueryWithParams {
            query: (),
            query_payload: Vec::new(),
            item: iroha_data_model::query::QueryItemKind::Account,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams {
                fetch_size: FetchSize::new(Some(fetch_size)),
                ..QueryParams::default()
            },
        })
    }
    fn minimal_root_with_max_fetch(max_fetch_size: u32) -> ConfigRoot {
        let config = format!(
            r#"
chain = "00000000-0000-0000-0000-000000000000"
public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
private_key = "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
soranet_transport_public_key = "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B"
soranet_transport_private_key = "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89"
trusted_peers_pop = [
  {{ public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2", pop_hex = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08" }},
]

[network]
address = "addr:127.0.0.1:1337#8F78"
public_address = "addr:127.0.0.1:1337#8F78"

[torii]
address = "addr:127.0.0.1:8080#8942"
app_api_max_fetch_size = {max_fetch_size}
app_api_default_list_limit = {max_fetch_size}

[genesis]
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
expected_hash = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"

[streaming]
identity_public_key = "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB"
identity_private_key = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
"#
        );
        let mut file = NamedTempFile::new().expect("temp config file");
        file.write_all(config.as_bytes()).expect("write config");
        let source =
            iroha_config::base::toml::TomlSource::from_file(file.path()).expect("read config");
        ConfigRoot::from_toml_source(source).expect("load minimal config")
    }
    /// A State whose World commits `pipeline_validity_policy_v1` with the given
    /// IVM query fetch limit; `node` is the node's own pipeline settings.
    fn state_with_committed_max_fetch(
        max_fetch_size: u64,
        node: Option<PipelineActual>,
    ) -> crate::state::State {
        use iroha_data_model::{
            parameter::Parameter, pipeline_validity_policy::PipelineValidityPolicyV1,
        };
        let world = crate::state::World::default();
        let mut policy = PipelineValidityPolicyV1::protocol_default();
        policy.query_max_fetch_size = max_fetch_size;
        {
            let mut block = world.block();
            block
                .parameters
                .get_mut()
                .set_parameter(Parameter::Custom(policy.into_custom_parameter()))
                .expect("valid fixture parameters");
            block.commit();
        }
        let mut state = crate::state::State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        if let Some(node) = node {
            state
                .install_node_pipeline(node)
                .expect("node pipeline resources install");
        }
        state
    }
    #[test]
    fn reject_fetch_size_above_max() {
        let over = u64::from(torii_defaults::APP_API_MAX_FETCH_SIZE)
            .checked_add(1)
            .expect("nonzero add");
        let request = QueryRequest::Start(QueryWithParams {
            query: (),
            query_payload: Vec::new(),
            item: iroha_data_model::query::QueryItemKind::Account,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: QueryParams {
                fetch_size: FetchSize::new(Some(
                    std::num::NonZeroU64::new(over).expect("nonzero fetch size"),
                )),
                ..QueryParams::default()
            },
        });
        let err = validate_query_request_limits(&request, QueryLimits::from_defaults())
            .expect_err("must reject oversized fetch");
        assert!(matches!(
            err,
            ValidationFail::QueryFailed(Error::FetchSizeTooBig)
        ));
    }
    #[test]
    fn postprocessing_rejects_fetch_size_above_limits() {
        let params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
            ..QueryParams::default()
        };
        let iter = std::iter::once(Permission::new("p".to_owned(), Json::from(false)));
        let err = apply_query_postprocessing(
            iter,
            SelectorTuple::default(),
            &params,
            QueryLimits::new(1),
        )
        .expect_err("fetch size should be rejected");
        assert!(matches!(err, Error::FetchSizeTooBig));
    }
    #[test]
    fn postprocessing_reports_processed_items_for_sorted_queries() {
        let key: iroha_model_base::name::Name = "rank".parse().expect("name");
        let params = QueryParams {
            pagination: Pagination::new(Some(nonzero!(1_u64)), 0),
            sorting: Sorting::by_metadata_key(key),
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
        };
        let items = vec![
            Permission::new("p1".to_owned(), Json::from(false)),
            Permission::new("p2".to_owned(), Json::from(false)),
            Permission::new("p3".to_owned(), Json::from(false)),
        ];
        let (iter, processed_items) = apply_query_postprocessing_with_budget(
            items.into_iter(),
            SelectorTuple::default(),
            &params,
            QueryLimits::new(10),
            None,
        )
        .expect("postprocess sorted query");
        assert_eq!(processed_items, 3);
        assert_eq!(iter.remaining(), Some(1));
    }
    #[test]
    fn query_limits_new_clamps_to_one() {
        let request_ok = request_with_fetch_size(1);
        validate_query_request_limits(&request_ok, QueryLimits::new(0))
            .expect("clamped fetch size should be accepted");
        let request_over = request_with_fetch_size(2);
        let err = validate_query_request_limits(&request_over, QueryLimits::new(0))
            .expect_err("clamped limit should reject larger fetch sizes");
        assert!(matches!(
            err,
            ValidationFail::QueryFailed(Error::FetchSizeTooBig)
        ));
    }
    #[test]
    fn query_limits_from_torii_uses_configured_max_fetch() {
        let root = minimal_root_with_max_fetch(3);
        let limits = QueryLimits::from_torii(&root.torii);
        let request = request_with_fetch_size(4);
        let err = validate_query_request_limits(&request, limits)
            .expect_err("configured max fetch should be enforced");
        assert!(matches!(
            err,
            ValidationFail::QueryFailed(Error::FetchSizeTooBig)
        ));
    }
    #[test]
    fn query_limits_from_pipeline_use_the_committed_max_fetch_at_and_above_the_limit() {
        // The limit is the committed pipeline validity policy, not node
        // configuration: a node that holds another value decides the same.
        let divergent = iroha_config::parameters::actual::Pipeline {
            query_max_fetch_size: 1,
            ..Default::default()
        };
        for node in [None, Some(divergent)] {
            let state = state_with_committed_max_fetch(3, node);
            let view = state.view();
            let limits = QueryLimits::from_pipeline(&view.pipeline);
            validate_query_request_limits(&request_with_fetch_size(3), limits)
                .expect("a fetch of exactly the committed limit is accepted");
            let err = validate_query_request_limits(&request_with_fetch_size(4), limits)
                .expect_err("one item above the committed limit is rejected");
            assert!(matches!(
                err,
                ValidationFail::QueryFailed(Error::FetchSizeTooBig)
            ));
            // The block built on this State freezes the same limit.
            let block = state.block(iroha_data_model::block::BlockHeader::new(
                nonzero!(2_u64),
                None,
                None,
                0,
                0,
            ));
            let limits = QueryLimits::from_pipeline(&block.pipeline);
            validate_query_request_limits(&request_with_fetch_size(3), limits)
                .expect("the block accepts a fetch of exactly the committed limit");
            assert!(validate_query_request_limits(&request_with_fetch_size(4), limits).is_err());
        }
        // Without a committed policy the protocol default decides.
        let default_limit = pipeline_defaults::QUERY_MAX_FETCH_SIZE;
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let limits = QueryLimits::from_pipeline(&state.view().pipeline);
        validate_query_request_limits(&request_with_fetch_size(default_limit), limits)
            .expect("the protocol default limit is accepted");
        assert!(
            validate_query_request_limits(&request_with_fetch_size(default_limit + 1), limits)
                .is_err()
        );
    }
}
/// Validate a fresh client query without exposing a reusable execution capability.
///
/// Stored continuations must enter through [`crate::query::snapshot`], which revalidates the
/// archived `Start` request before advancing its cursor. This facade therefore accepts only
/// `Singular` and `Start` requests and returns no raw validated-query object.
///
/// # Errors
///
/// Returns an error when the request is a bare continuation, exceeds limits, or fails mandatory
/// native and executor authorization.
pub fn validate_fresh_query_for_client_world_parts(
    request: QueryRequest,
    authority: &AccountId,
    world_ro: &impl WorldReadOnly,
    latest_block: Option<&BlockHeader>,
    limits: QueryLimits,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<(), ValidationFail> {
    if matches!(request, QueryRequest::Continue(_)) {
        return Err(ValidationFail::NotPermitted(
            "bare query continuation must use the store-aware snapshot corridor".to_owned(),
        ));
    }
    ValidQueryRequest::validate_for_client_world_parts(
        request,
        authority,
        world_ro,
        latest_block,
        limits,
        budget,
    )
    .map(drop)
}
/// Query Request statefully validated on the Iroha node side.
pub(crate) struct ValidQueryRequest {
    request: QueryRequest,
    limits: QueryLimits,
}
/// Authority-bound query validation supplied by the current IVM host.
pub(crate) trait IvmQueryValidator {
    /// Account on whose behalf the query will run.
    fn authority(&self) -> &AccountId;
    /// Validate a query in the executor context.
    ///
    /// # Errors
    /// Returns [`ValidationFail`] if the query is not permitted.
    fn validate_query(
        &mut self,
        authority: &AccountId,
        query: &QueryRequest,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>>;
}
include!("query/valid_query_request.rs");
#[cfg(test)]
mod tests {
    #![allow(clippy::many_single_char_names)]
    use super::*;
    use crate::{
        block::*,
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::{Execute, ValidQuery},
        state::{State, StateReadOnly, World, WorldReadOnly},
        tx::AcceptedTransaction,
    };
    use core::time::Duration;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        AccountId, Level, NetworkId,
        isi::Log,
        query::{QueryRequest, SingularQueryBox, dsl::CompoundPredicate, prelude::FindParameters},
        transaction::TransactionBuilder,
    };
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, gen_account_in};
    use mv::storage::StorageReadOnly as _;
    use nonzero_ext::nonzero;
    use norito::core::SerializePayload;
    use std::{borrow::Cow, sync::Arc};
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("query fixture key generation should succeed")
    }
    fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("query algorithm-specific fixture key generation should succeed")
    }
    fn grant_global_reader(world: &mut World, authority: &AccountId) {
        let permission: Permission =
            iroha_executor_data_model::permission::query::CanReadAllLedgerData.into();
        let mut permissions = world
            .account_permissions
            .view()
            .get(authority)
            .cloned()
            .unwrap_or_default();
        permissions.insert(permission);
        world
            .account_permissions
            .insert(authority.clone(), permissions);
    }
    fn with_global_reader(mut world: World, authority: &AccountId) -> World {
        grant_global_reader(&mut world, authority);
        world
    }
    fn find_transactions_request_with_filter(
        params: QueryParams,
        filter: CompoundPredicate<CommittedTransaction>,
    ) -> QueryRequest {
        QueryRequest::Start(iroha_data_model::query::QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::transaction::prelude::FindTransactions,
            ),
            item: iroha_data_model::query::QueryItemKind::CommittedTransaction,
            predicate_bytes: norito::codec::Encode::encode(&filter),
            selector_bytes: norito::codec::Encode::encode(
                &SelectorTuple::<CommittedTransaction>::default(),
            ),
            params,
        })
    }
    fn find_transactions_request(params: QueryParams) -> QueryRequest {
        find_transactions_request_with_filter(params, CompoundPredicate::PASS)
    }
    fn transactions_from_batch(batch: QueryOutputBatchBoxTuple) -> Vec<CommittedTransaction> {
        match batch.into_iter().next().expect("transaction batch") {
            QueryOutputBatchBox::CommittedTransaction(transactions) => transactions,
            other => panic!("unexpected transaction batch: {other:?}"),
        }
    }
    fn domain_request_with_payload(payload: Vec<u8>) -> ValidQueryRequest {
        ValidQueryRequest {
            request: QueryRequest::Start(iroha_data_model::query::QueryWithParams {
                query: (),
                query_payload: payload,
                item: iroha_data_model::query::QueryItemKind::Domain,
                predicate_bytes: norito::codec::Encode::encode(
                    &CompoundPredicate::<iroha_data_model::domain::Domain>::PASS,
                ),
                selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<
                    iroha_data_model::domain::Domain,
                >::default()),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        }
    }
    fn transaction_request_with_payload(payload: Vec<u8>) -> ValidQueryRequest {
        ValidQueryRequest {
            request: QueryRequest::Start(iroha_data_model::query::QueryWithParams {
                query: (),
                query_payload: payload,
                item: iroha_data_model::query::QueryItemKind::CommittedTransaction,
                predicate_bytes: norito::codec::Encode::encode(
                    &CompoundPredicate::<CommittedTransaction>::PASS,
                ),
                selector_bytes: norito::codec::Encode::encode(
                    &SelectorTuple::<CommittedTransaction>::default(),
                ),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        }
    }
    fn block_request_with_payload(payload: Vec<u8>) -> ValidQueryRequest {
        ValidQueryRequest {
            request: QueryRequest::Start(iroha_data_model::query::QueryWithParams {
                query: (),
                query_payload: payload,
                item: iroha_data_model::query::QueryItemKind::SignedBlock,
                predicate_bytes: norito::codec::Encode::encode(
                    &CompoundPredicate::<iroha_data_model::block::SignedBlock>::PASS,
                ),
                selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<
                    iroha_data_model::block::SignedBlock,
                >::default()),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        }
    }
    fn role_request_with_payload(payload: Vec<u8>) -> ValidQueryRequest {
        ValidQueryRequest {
            request: QueryRequest::Start(iroha_data_model::query::QueryWithParams {
                query: (),
                query_payload: payload,
                item: iroha_data_model::query::QueryItemKind::Role,
                predicate_bytes: norito::codec::Encode::encode(
                    &CompoundPredicate::<iroha_data_model::role::Role>::PASS,
                ),
                selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<
                    iroha_data_model::role::Role,
                >::default()),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        }
    }
    include!("query_core_tests.rs");
    fn escrow_dispatch_fixture() -> (
        State,
        crate::query::store::LiveQueryStoreHandle,
        iroha_data_model::escrow::AssetEscrowRecord,
    ) {
        use iroha_data_model::{
            asset::AssetDefinitionId,
            escrow::{AssetEscrowKind, AssetEscrowRecord, AssetEscrowStatus, EscrowId},
        };
        use iroha_primitives::numeric::Quantity;
        let escrow_id = EscrowId::new(Hash::new("query-dispatch-escrow"));
        let record = AssetEscrowRecord {
            id: escrow_id,
            seller: ALICE_ID.clone(),
            buyer: Some(BOB_ID.clone()),
            asset_definition: AssetDefinitionId::derive_from_components(
                DomainId::try_new("escrow-query", "universal").expect("escrow domain id"),
                "xor".parse().expect("escrow asset name"),
            ),
            amount: Quantity::from(7_u32),
            custody: ALICE_ID.clone(),
            status: AssetEscrowStatus::PaymentSent,
            kind: AssetEscrowKind::Marketplace,
            remaining_amount: Quantity::from(7_u32),
            release_authority: None,
            expires_at_ms: None,
            evidence_hashes: Vec::new(),
            conditions: Vec::new(),
            created_at_ms: 1,
            accepted_at_ms: Some(2),
            payment_sent_at_ms: Some(3),
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        };
        let mut world = World::with(
            [],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&ALICE_ID),
            ],
            [],
        );
        world.asset_escrows.insert(escrow_id, record.clone());
        world
            .asset_escrows_by_seller
            .insert((ALICE_ID.clone(), escrow_id), ());
        world
            .asset_escrows_by_buyer
            .insert((BOB_ID.clone(), escrow_id), ());
        world
            .asset_escrows_by_status
            .insert((AssetEscrowStatus::PaymentSent, escrow_id), ());
        let handle = LiveQueryStore::start_test();
        let state = State::new(world, Kura::blank_kura_for_testing(), handle.clone());
        (state, handle, record)
    }
    #[test]
    fn stored_dispatch_distinguishes_escrow_seller_buyer_and_status_queries() {
        use iroha_data_model::{
            escrow::{AssetEscrowRecord, AssetEscrowStatus},
            query::{
                QueryItemKind, QueryOutputBatchBox, QueryWithParams,
                escrow::prelude::{
                    FindAssetEscrowsByBuyer, FindAssetEscrowsBySeller, FindAssetEscrowsByStatus,
                },
            },
        };
        let (state, handle, expected) = escrow_dispatch_fixture();
        let state_view = state.view();
        let predicate_bytes =
            norito::codec::Encode::encode(&CompoundPredicate::<AssetEscrowRecord>::PASS);
        let selector_bytes =
            norito::codec::Encode::encode(&SelectorTuple::<AssetEscrowRecord>::default());
        let seller_request = ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssetEscrowsBySeller {
                    seller: ALICE_ID.clone(),
                }),
                item: QueryItemKind::AssetEscrowsBySeller,
                predicate_bytes: predicate_bytes.clone(),
                selector_bytes: selector_bytes.clone(),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        };
        let QueryResponse::Iterable(seller_output) = seller_request
            .execute(&handle, &state_view, &ALICE_ID)
            .expect("execute stored seller escrow query")
        else {
            panic!("expected stored seller iterable response")
        };
        let (seller_batch, _seller_remaining, seller_cursor) = seller_output.into_parts();
        let seller_records = match seller_batch.into_iter().next().expect("seller batch") {
            QueryOutputBatchBox::AssetEscrowRecord(records) => records,
            other => panic!("unexpected seller batch: {other:?}"),
        };
        assert_eq!(seller_records, vec![expected.clone()]);
        assert!(seller_cursor.is_none());
        let buyer_request = ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssetEscrowsByBuyer {
                    buyer: BOB_ID.clone(),
                }),
                item: QueryItemKind::AssetEscrowsByBuyer,
                predicate_bytes: predicate_bytes.clone(),
                selector_bytes: selector_bytes.clone(),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        };
        let QueryResponse::Iterable(buyer_output) = buyer_request
            .execute(&handle, &state_view, &ALICE_ID)
            .expect("execute stored buyer escrow query")
        else {
            panic!("expected stored buyer iterable response")
        };
        let (buyer_batch, _buyer_remaining, buyer_cursor) = buyer_output.into_parts();
        let buyer_records = match buyer_batch.into_iter().next().expect("buyer batch") {
            QueryOutputBatchBox::AssetEscrowRecord(records) => records,
            other => panic!("unexpected buyer batch: {other:?}"),
        };
        assert_eq!(buyer_records, vec![expected.clone()]);
        assert!(buyer_cursor.is_none());
        let status_request = ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssetEscrowsByStatus {
                    status: AssetEscrowStatus::PaymentSent,
                }),
                item: QueryItemKind::AssetEscrowsByStatus,
                predicate_bytes,
                selector_bytes,
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        };
        let QueryResponse::Iterable(status_output) = status_request
            .execute(&handle, &state_view, &ALICE_ID)
            .expect("execute stored status escrow query")
        else {
            panic!("expected stored status iterable response")
        };
        let (status_batch, _status_remaining, status_cursor) = status_output.into_parts();
        let status_records = match status_batch.into_iter().next().expect("status batch") {
            QueryOutputBatchBox::AssetEscrowRecord(records) => records,
            other => panic!("unexpected status batch: {other:?}"),
        };
        assert_eq!(status_records, vec![expected]);
        assert!(status_cursor.is_none());
    }
    #[test]
    fn ephemeral_dispatch_distinguishes_escrow_seller_buyer_and_status_queries() {
        use iroha_data_model::{
            escrow::{AssetEscrowRecord, AssetEscrowStatus},
            query::{
                QueryItemKind, QueryOutputBatchBox, QueryWithParams,
                escrow::prelude::{
                    FindAssetEscrowsByBuyer, FindAssetEscrowsBySeller, FindAssetEscrowsByStatus,
                },
            },
        };
        let (state, handle, expected) = escrow_dispatch_fixture();
        let state_view = state.view();
        let predicate_bytes =
            norito::codec::Encode::encode(&CompoundPredicate::<AssetEscrowRecord>::PASS);
        let selector_bytes =
            norito::codec::Encode::encode(&SelectorTuple::<AssetEscrowRecord>::default());
        let seller_request = ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssetEscrowsBySeller {
                    seller: ALICE_ID.clone(),
                }),
                item: QueryItemKind::AssetEscrowsBySeller,
                predicate_bytes: predicate_bytes.clone(),
                selector_bytes: selector_bytes.clone(),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        };
        let QueryResponse::Iterable(seller_output) = seller_request
            .execute_ephemeral(&handle, &state_view, &ALICE_ID)
            .expect("execute ephemeral seller escrow query")
        else {
            panic!("expected ephemeral seller iterable response")
        };
        let (seller_batch, _seller_remaining, seller_cursor) = seller_output.into_parts();
        let seller_records = match seller_batch.into_iter().next().expect("seller batch") {
            QueryOutputBatchBox::AssetEscrowRecord(records) => records,
            other => panic!("unexpected seller batch: {other:?}"),
        };
        assert_eq!(seller_records, vec![expected.clone()]);
        assert!(seller_cursor.is_none());
        let buyer_request = ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssetEscrowsByBuyer {
                    buyer: BOB_ID.clone(),
                }),
                item: QueryItemKind::AssetEscrowsByBuyer,
                predicate_bytes: predicate_bytes.clone(),
                selector_bytes: selector_bytes.clone(),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        };
        let QueryResponse::Iterable(buyer_output) = buyer_request
            .execute_ephemeral(&handle, &state_view, &ALICE_ID)
            .expect("execute ephemeral buyer escrow query")
        else {
            panic!("expected ephemeral buyer iterable response")
        };
        let (buyer_batch, _buyer_remaining, buyer_cursor) = buyer_output.into_parts();
        let buyer_records = match buyer_batch.into_iter().next().expect("buyer batch") {
            QueryOutputBatchBox::AssetEscrowRecord(records) => records,
            other => panic!("unexpected buyer batch: {other:?}"),
        };
        assert_eq!(buyer_records, vec![expected.clone()]);
        assert!(buyer_cursor.is_none());
        let status_request = ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssetEscrowsByStatus {
                    status: AssetEscrowStatus::PaymentSent,
                }),
                item: QueryItemKind::AssetEscrowsByStatus,
                predicate_bytes,
                selector_bytes,
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        };
        let QueryResponse::Iterable(status_output) = status_request
            .execute_ephemeral(&handle, &state_view, &ALICE_ID)
            .expect("execute ephemeral status escrow query")
        else {
            panic!("expected ephemeral status iterable response")
        };
        let (status_batch, _status_remaining, status_cursor) = status_output.into_parts();
        let status_records = match status_batch.into_iter().next().expect("status batch") {
            QueryOutputBatchBox::AssetEscrowRecord(records) => records,
            other => panic!("unexpected status batch: {other:?}"),
        };
        assert_eq!(status_records, vec![expected]);
        assert!(status_cursor.is_none());
    }
    #[test]
    fn escrow_dispatch_rejects_noncanonical_payload_bytes() {
        use iroha_data_model::{
            escrow::AssetEscrowRecord,
            query::{QueryItemKind, QueryWithParams, escrow::prelude::FindAssetEscrowsBySeller},
        };
        let (state, handle, _) = escrow_dispatch_fixture();
        let state_view = state.view();
        let mut query_payload = norito::codec::Encode::encode(&FindAssetEscrowsBySeller {
            seller: ALICE_ID.clone(),
        });
        query_payload.push(0);
        let request = ValidQueryRequest {
            request: QueryRequest::Start(QueryWithParams {
                query: (),
                query_payload,
                item: QueryItemKind::AssetEscrowsBySeller,
                predicate_bytes: norito::codec::Encode::encode(
                    &CompoundPredicate::<AssetEscrowRecord>::PASS,
                ),
                selector_bytes: norito::codec::Encode::encode(
                    &SelectorTuple::<AssetEscrowRecord>::default(),
                ),
                params: QueryParams::default(),
            }),
            limits: QueryLimits::default(),
        };
        let error = request
            .execute_ephemeral(&handle, &state_view, &ALICE_ID)
            .expect_err("trailing escrow payload bytes must fail closed");
        assert!(matches!(error, Error::Conversion(_)));
    }
    #[test]
    fn fresh_client_facade_rejects_bare_continue_before_store_lookup() {
        let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        let world_view = world.view();
        let cursor = iroha_data_model::query::parameters::ForwardCursor {
            query: "unresolved-cursor".to_owned(),
            cursor: nonzero!(1_u64),
            gas_budget: None,
        };
        let error = validate_fresh_query_for_client_world_parts(
            QueryRequest::Continue(cursor),
            &ALICE_ID,
            &world_view,
            None,
            QueryLimits::default(),
            &iroha_allocation::AllocationBudget::new(0),
        )
        .expect_err("a bare continuation must never enter reusable raw validation");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message)
                if message.contains("store-aware snapshot corridor")),
            "unexpected bare-continuation rejection: {error:?}"
        );
    }
    #[tokio::test]
    async fn sorting_by_metadata_key_and_fetch_size() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use nonzero_ext::nonzero;
        // Build sample domains with a sortable metadata key "rank"
        let mut d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let mut d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID); // no rank
        d1.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        d2.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        let iter = vec![d1.clone(), d2.clone(), d3.clone()].into_iter();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting {
                sort_by_metadata_key: Some("rank".parse().unwrap()),
                order: Some(iroha_data_model::query::parameters::SortOrder::Asc),
            },
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(2_u64)),
            },
        };
        let selector = SelectorTuple::default();
        let mut erased =
            apply_query_postprocessing(iter, selector, &params, QueryLimits::default()).unwrap();
        // First batch should be [d2(rank=1), d1(rank=2)]
        let (batch, next) = erased.next_batch(0).expect("first batch");
        let mut tuple_iter = batch.into_iter();
        let v = match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, d2.id);
        assert_eq!(v[1].id, d1.id);
        assert!(next.is_some());
        // Second batch should be [d3] (no rank -> sorted last)
        let (batch2, next2) = erased
            .next_batch(next.unwrap().get())
            .expect("second batch");
        let mut tuple_iter2 = batch2.into_iter();
        let v2 = match tuple_iter2.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].id, d3.id);
        assert!(next2.is_none());
    }
    #[tokio::test]
    async fn sorting_descending_and_fetch_size() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, SortOrder, Sorting},
        };
        use nonzero_ext::nonzero;
        // Domains with rank metadata
        let mut d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let mut d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID); // no rank
        d1.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        d2.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        let iter = vec![d1.clone(), d2.clone(), d3.clone()].into_iter();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting {
                sort_by_metadata_key: Some("rank".parse().unwrap()),
                order: Some(SortOrder::Desc),
            },
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(2_u64)),
            },
        };
        let selector = SelectorTuple::default();
        let mut erased =
            apply_query_postprocessing(iter, selector, &params, QueryLimits::default()).unwrap();
        // First batch should be [d1(rank=2), d2(rank=1)] for descending
        let (batch, next) = erased.next_batch(0).expect("first batch");
        let mut tuple_iter = batch.into_iter();
        let v = match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, d1.id);
        assert_eq!(v[1].id, d2.id);
        assert!(next.is_some());
        // Second batch should be [d3]
        let (batch2, next2) = erased
            .next_batch(next.unwrap().get())
            .expect("second batch");
        let mut tuple_iter2 = batch2.into_iter();
        let v2 = match tuple_iter2.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].id, d3.id);
        assert!(next2.is_none());
    }
    include!("query/ephemeral_sorted_offset_test.rs");
    fn domain_with_query_payload(name: &str, payload_bytes: usize, rank: u64) -> Domain {
        let mut domain =
            Domain::new(DomainId::try_new(name, "universal").expect("domain id")).build(&ALICE_ID);
        domain.metadata_mut().insert(
            "payload".parse().expect("metadata key"),
            Json::new("x".repeat(payload_bytes)),
        );
        domain
            .metadata_mut()
            .insert("rank".parse().expect("metadata key"), Json::new(rank));
        domain
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_core::smartcontracts::isi::query::tests::StatefulLengthHint")]
    struct StatefulLengthHint {
        body: [u8; 32],
        actual: usize,
        exact_hint: usize,
        serializations: Cell<usize>,
    }
    impl StatefulLengthHint {
        fn new(exact_hint: usize, actual: usize) -> Self {
            Self {
                body: [0xA5; 32],
                actual,
                exact_hint,
                serializations: Cell::new(0),
            }
        }
    }
    impl SerializePayload for StatefulLengthHint {
        fn serialize(
            &self,
            encoder: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            self.serializations
                .set(self.serializations.get().saturating_add(1));
            std::io::Write::write_all(encoder, &self.body[..self.actual])?;
            Ok(())
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            Some(self.exact_hint)
        }
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::smartcontracts::isi::query::tests::ErrorSwallowingSerializer"
    )]
    struct ErrorSwallowingSerializer;
    impl SerializePayload for ErrorSwallowingSerializer {
        fn serialize(
            &self,
            encoder: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            let _ = std::io::Write::write_all(encoder, &[0x5A; 32]);
            Ok(())
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            Some(1)
        }
    }
    #[test]
    fn bounded_length_meter_never_admits_an_underreported_exact_hint() {
        let value = StatefulLengthHint::new(1, 16);
        assert_eq!(
            bounded_bare_encoded_len(&value, 8),
            Err(Error::GasBudgetExceeded)
        );
        assert_eq!(value.serializations.get(), 1);
    }
    #[test]
    fn bounded_length_meter_uses_actual_bytes_after_an_overreported_hint() {
        let value = StatefulLengthHint::new(16, 3);
        assert_eq!(bounded_bare_encoded_len(&value, 16), Ok(3));
        assert_eq!(value.serializations.get(), 1);
        let early_rejection = StatefulLengthHint::new(17, 1);
        assert_eq!(
            bounded_bare_encoded_len(&early_rejection, 16),
            Err(Error::GasBudgetExceeded)
        );
        assert_eq!(early_rejection.serializations.get(), 0);
    }
    #[test]
    fn bounded_length_meter_keeps_a_swallowed_sink_overrun_sticky() {
        assert_eq!(
            bounded_bare_encoded_len(&ErrorSwallowingSerializer, 8),
            Err(Error::GasBudgetExceeded)
        );
    }
    #[test]
    fn query_budget_enforces_the_shared_item_and_byte_limit() {
        let value = Permission::new("query_budget".to_owned(), Json::new("small"));
        let bytes = bounded_bare_encoded_len(&value, u64::MAX).expect("measure permission");
        let budget = QueryExecutionBudget::from_weighted_limit(bytes, bytes, 1);
        assert_eq!(budget.max_items(), 1);
        assert_eq!(budget.max_bytes(), bytes);
        let error = QueryExecutionStats::default()
            .record_item(&value, Some(budget))
            .expect_err("item and byte work must share one budget");
        assert!(matches!(error, Error::GasBudgetExceeded));
    }
    #[test]
    fn query_budget_rejects_cross_term_overflow_near_u64_max() {
        let budget = QueryExecutionBudget::from_weighted_limit(u64::MAX, 1, 1);
        let half_plus_one = u64::MAX / 2 + 1;
        assert_eq!(
            budget.ensure(half_plus_one, half_plus_one),
            Err(Error::GasBudgetExceeded),
            "individually in-range item and byte terms must not overflow into admission"
        );
        assert_eq!(
            budget.remaining_bytes(half_plus_one, half_plus_one),
            Err(Error::GasBudgetExceeded)
        );
        let multiply_overflow = QueryExecutionBudget::from_weighted_limit(u64::MAX, 2, 0);
        assert_eq!(
            multiply_overflow.ensure(half_plus_one, 0),
            Err(Error::GasBudgetExceeded),
            "an overflowing weighted term must fail before its independent cap is consulted"
        );
    }
    #[test]
    fn metered_singular_alias_query_preserves_ivm_execution() {
        let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let request = ValidQueryRequest {
            request: QueryRequest::Singular(
                iroha_data_model::query::account::prelude::FindAliasesByAccountId::new(
                    ALICE_ID.clone(),
                    None,
                    None,
                )
                .into(),
            ),
            limits: QueryLimits::default(),
        };
        let view = state.view();
        let (response, execution_stats) = request
            .execute_ephemeral_with_stats(
                view.query_handle(),
                &view,
                &ALICE_ID,
                Some(QueryExecutionBudget::from_weighted_limit(1_000_000, 1, 1)),
            )
            .expect("ordinary metered singular queries remain available to the IVM host");
        assert!(matches!(
            response,
            QueryResponse::Singular(SingularQueryOutputBox::AccountAliasBindingRecords(records))
                if records.is_empty()
        ));
        assert_eq!(execution_stats.processed_items(), 0);
    }
    #[test]
    fn sorafs_anonymity_queries_require_bounded_lane_and_fail_closed() {
        use iroha_data_model::query::sorafs::prelude::{
            FindSorafsCitizenBondBySerialCommitment, FindSorafsCitizenBondSnapshot,
        };

        let mut world = World::default();
        world.smart_contract_state.insert(
            "untrusted_sorafs_anonymity_query_payload"
                .parse()
                .expect("test state path"),
            vec![0xA5; 128],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let view = state.view();
        let budget = QueryExecutionBudget::from_weighted_limit(1_000_000, 1, 1);
        let cases: [(SingularQueryBox, FindError); 2] = [
            (
                FindSorafsCitizenBondBySerialCommitment::new([0x11; 32]).into(),
                FindError::SorafsCitizenBond([0x11; 32]),
            ),
            (
                FindSorafsCitizenBondSnapshot.into(),
                FindError::SorafsCitizenBondSnapshot,
            ),
        ];
        for (query, expected) in cases {
            let inactive = ordinary_memory::preflight_server_singular_source_materialization(
                &query, &view, budget, false,
            )
            .expect_err("an unbounded server lane must not admit an anonymity query");
            assert!(
                matches!(inactive, Error::Conversion(message) if message.contains("SoraFS anonymity query"))
            );
            assert_eq!(
                ordinary_memory::preflight_server_singular_source_materialization(
                    &query, &view, budget, true,
                )
                .expect("the bounded lane admits the fail-closed dispatcher"),
                0,
            );
            assert_eq!(
                crate::execution_attempt::expect_completed_rejection(
                    (query.execute(&view)).expect_err("completed rejection")
                ),
                Error::Find(expected)
            );
        }
    }
    #[test]
    fn server_metered_alias_query_preserves_bounded_resolution() {
        let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let alias = iroha_data_model::account::AccountAlias::domainless(
            "server-alias".parse().expect("alias label"),
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        );
        let request = ValidQueryRequest {
            request: QueryRequest::Singular(
                iroha_data_model::query::account::prelude::FindAccountByAlias { alias }.into(),
            ),
            limits: QueryLimits::default().with_singular_output_limits(
                SingularQueryOutputLimits::new(64 * 1_024, 64 * 1_024),
            ),
        };
        let view = state.view();
        let error = request
            .execute_ephemeral_with_stats(
                view.query_handle(),
                &view,
                &ALICE_ID,
                Some(QueryExecutionBudget::from_weighted_limit(1_000_000, 1, 1)),
            )
            .expect_err("the unregistered alias remains absent after bounded resolution");
        assert!(matches!(
            error,
            QueryAttemptError::Rejected(Error::NotFound)
        ));
    }
    #[test]
    fn server_singular_preflight_charges_synthesized_account_and_asset_shapes() {
        let domain_id = DomainId::try_new("preflight", "universal").expect("domain id");
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "coin".parse().expect("asset name"),
        );
        let definition = AssetDefinition::numeric(
            definition_id.clone(),
            "coin".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let asset_id = AssetId::new(definition_id, ALICE_ID.clone());
        let asset = Asset::new(asset_id.clone(), 7_u32);
        let world = World::with_assets([domain], [account], [definition], [asset], []);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let view = state.view();
        let budget = QueryExecutionBudget::from_weighted_limit(u64::MAX, 0, 1);
        let account_query = SingularQueryBox::FindAccountById(
            iroha_data_model::query::account::prelude::FindAccountById::new(ALICE_ID.clone()),
        );
        let (stored_account_id, stored_account) = view
            .world()
            .accounts()
            .get_key_value(&ALICE_ID)
            .expect("stored account");
        let expected_account = bounded_bare_encoded_len(stored_account_id, u64::MAX)
            .expect("account id length")
            .checked_add(
                bounded_bare_encoded_len(stored_account.as_ref(), u64::MAX)
                    .expect("account details length"),
            )
            .and_then(|bytes| bytes.checked_add(64))
            .expect("account preflight length");
        assert_eq!(
            ordinary_memory::preflight_server_singular_source_materialization(
                &account_query,
                &view,
                budget,
                true,
            )
            .expect("account preflight"),
            expected_account,
        );
        let asset_query = SingularQueryBox::FindAssetById(
            iroha_data_model::query::asset::prelude::FindAssetById::new(asset_id.clone()),
        );
        let stored_asset = view.world().asset(&asset_id).expect("stored asset");
        let expected_asset = bounded_bare_encoded_len(stored_asset.id(), u64::MAX)
            .expect("asset id length")
            .checked_add(
                bounded_bare_encoded_len(stored_asset.value().as_ref(), u64::MAX)
                    .expect("asset value length"),
            )
            .and_then(|bytes| bytes.checked_add(32))
            .expect("asset preflight length");
        assert_eq!(
            ordinary_memory::preflight_server_singular_source_materialization(
                &asset_query,
                &view,
                budget,
                true,
            )
            .expect("asset preflight"),
            expected_asset,
        );
    }
    #[test]
    fn ephemeral_offset_charges_bytes_for_skipped_values() {
        let oversized = domain_with_query_payload("oversized", 128 * 1024, 0);
        let retained = domain_with_query_payload("retained", 8, 1);
        let oversized_bytes =
            bounded_bare_encoded_len(&oversized, u64::MAX).expect("measure oversized domain");
        let params = QueryParams {
            pagination: Pagination::new(None, 1),
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            ..QueryParams::default()
        };
        let budget =
            QueryExecutionBudget::from_weighted_limit(oversized_bytes.saturating_sub(1), 0, 1);
        let error = apply_query_postprocessing_ephemeral_with_budget(
            vec![oversized, retained].into_iter(),
            SelectorTuple::default(),
            &params,
            QueryLimits::new(2),
            Some(budget),
        )
        .expect_err("an oversized skipped value must exhaust the byte budget");
        assert!(matches!(error, Error::GasBudgetExceeded));
    }
    #[test]
    fn ephemeral_sort_rejects_oversized_values_before_retaining_them() {
        let oversized = domain_with_query_payload("oversized-sort", 128 * 1024, 2);
        let small = domain_with_query_payload("small-sort", 8, 1);
        let oversized_bytes =
            bounded_bare_encoded_len(&oversized, u64::MAX).expect("measure oversized domain");
        let params = QueryParams {
            sorting: Sorting::by_metadata_key("rank".parse().expect("sort key")),
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            ..QueryParams::default()
        };
        let budget = QueryExecutionBudget::from_weighted_limit(oversized_bytes, 1, 1);
        let error = apply_query_postprocessing_ephemeral_with_budget(
            vec![oversized, small].into_iter(),
            SelectorTuple::default(),
            &params,
            QueryLimits::new(2),
            Some(budget),
        )
        .expect_err("sorting must meter a value before inserting it into the heap");
        assert!(matches!(error, Error::GasBudgetExceeded));
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_core::smartcontracts::isi::query::tests::CountingTiebreakValue")]
    #[derive(norito::derive::NoritoSerialize)]
    struct CountingTiebreakValue {
        id: u8,
        #[norito(skip)]
        derivations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl SortableQueryOutput for CountingTiebreakValue {
        type TiebreakKey = Vec<u8>;
        fn get_metadata_sorting_key(&self, _key: &Name) -> Option<&Json> {
            None
        }
        fn tiebreak_key(&self) -> Self::TiebreakKey {
            self.derivations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            vec![self.id; 16 * 1024]
        }
        fn bounded_tiebreak_key_len(&self, limit: u64) -> Result<u64, Error> {
            let encoded = 8_u64.saturating_add(16 * 1024);
            (encoded <= limit)
                .then_some(encoded)
                .ok_or(Error::GasBudgetExceeded)
        }
    }
    #[test]
    fn ephemeral_sort_derives_and_charges_each_large_tiebreak_key_once() {
        let derivations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut execution_stats = QueryExecutionStats::default();
        let values = (0_u8..32).map(|id| CountingTiebreakValue {
            id,
            derivations: derivations.clone(),
        });
        let budget = QueryExecutionBudget::from_weighted_limit(2_000_000, 1, 1);
        let (sorted, count) = collect_ephemeral_sorted_prefix(
            values,
            &"unused".parse().expect("sort key"),
            SortOrder::Asc,
            16,
            Some(budget),
            &mut execution_stats,
        )
        .expect("sort values with precomputed keys");
        assert_eq!(count, 32);
        assert_eq!(sorted.len(), 16);
        assert_eq!(
            derivations.load(std::sync::atomic::Ordering::Relaxed),
            32,
            "sorting comparisons must reuse the one admitted key per item",
        );
        assert!(execution_stats.processed_bytes() >= 32 * 16 * 1024);
    }
    #[test]
    fn ephemeral_sort_rejects_large_tiebreak_key_before_materialization() {
        let derivations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let value = CountingTiebreakValue {
            id: 7,
            derivations: derivations.clone(),
        };
        let item_bytes = bounded_bare_encoded_len(&value, u64::MAX).expect("measure item");
        let key_bytes = value
            .bounded_tiebreak_key_len(u64::MAX)
            .expect("measure tiebreak key");
        let budget = QueryExecutionBudget::from_weighted_limit(
            item_bytes.saturating_add(key_bytes).saturating_sub(1),
            0,
            1,
        );
        let mut execution_stats = QueryExecutionStats::default();
        execution_stats
            .record_item(&value, Some(budget))
            .expect("item fits before its large key");
        let error = materialize_admitted_tiebreak_key(&value, &mut execution_stats, Some(budget))
            .expect_err("oversized key must fail its allocation-free preflight");
        assert!(matches!(error, Error::GasBudgetExceeded));
        assert_eq!(
            derivations.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "rejected keys must never be constructed",
        );
    }
    #[test]
    fn tiebreak_derivations_are_fixture_owned_and_excluded_from_payload() {
        #[derive(norito::derive::NoritoSerialize)]
        struct ValuePayload {
            id: u8,
        }
        let first = CountingTiebreakValue {
            id: 7,
            derivations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let second = CountingTiebreakValue {
            id: 7,
            derivations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        assert_eq!(first.tiebreak_key(), vec![7; 16 * 1024]);
        assert_eq!(
            first.derivations.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            second
                .derivations
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        let expected = norito::codec::encode_adaptive(&ValuePayload { id: 7 });
        assert_eq!(norito::codec::encode_adaptive(&first), expected);
        assert_eq!(norito::codec::encode_adaptive(&second), expected);
    }
    #[test]
    fn singular_response_is_measured_before_host_serialization() {
        let domain = domain_with_query_payload("singular-budget", 64 * 1024, 0);
        let output = SingularQueryOutputBox::Domain(domain);
        let response = QueryResponse::Singular(output.clone());
        let item_bytes =
            bounded_bare_encoded_len(&output, u64::MAX).expect("measure singular output");
        let response_bytes =
            bounded_framed_encoded_len(&response, u64::MAX).expect("measure query response");
        assert_eq!(
            response_bytes,
            u64::try_from(
                norito::to_bytes(&response)
                    .expect("encode query response")
                    .len()
            )
            .expect("response length fits u64"),
            "manual Norito framing measurement must match the canonical codec",
        );
        let budget = QueryExecutionBudget::from_weighted_limit(
            item_bytes.saturating_add(response_bytes).saturating_sub(1),
            0,
            1,
        );
        let mut execution_stats = QueryExecutionStats::default();
        execution_stats
            .record_item(&output, Some(budget))
            .expect("singular item alone fits");
        let error = execution_stats
            .record_response(&response, Some(budget))
            .expect_err("framed response must be admitted before serialization");
        assert!(matches!(error, Error::GasBudgetExceeded));
    }
    #[test]
    fn query_budget_allows_a_legitimate_offset_page() {
        let skipped = domain_with_query_payload("skip-ok", 16, 0);
        let first = domain_with_query_payload("first-ok", 16, 1);
        let second = domain_with_query_payload("second-ok", 16, 2);
        let byte_budget = [&skipped, &first, &second]
            .into_iter()
            .map(|value| bounded_bare_encoded_len(value, u64::MAX).expect("measure domain"))
            .fold(0_u64, u64::saturating_add);
        let params = QueryParams {
            pagination: Pagination::new(Some(nonzero!(2_u64)), 1),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
            ..QueryParams::default()
        };
        let budget = QueryExecutionBudget::from_weighted_limit(
            byte_budget.checked_add(3).expect("item work"),
            1,
            1,
        );
        let (output, execution_stats) = apply_query_postprocessing_ephemeral_with_budget(
            vec![skipped, first.clone(), second.clone()].into_iter(),
            SelectorTuple::default(),
            &params,
            QueryLimits::new(3),
            Some(budget),
        )
        .expect("legitimate offset page should fit its exact budget");
        let iterable_response = QueryResponse::Iterable(output.clone());
        assert_eq!(
            bounded_framed_encoded_len(&iterable_response, u64::MAX)
                .expect("measure iterable response"),
            u64::try_from(
                norito::to_bytes(&iterable_response)
                    .expect("encode iterable response")
                    .len(),
            )
            .expect("response length fits u64"),
            "iterable framing measurement must match the canonical codec",
        );
        assert_eq!(execution_stats.processed_items(), 3);
        assert_eq!(execution_stats.processed_bytes(), byte_budget);
        assert_eq!(
            domain_ids_from_batch(output.batch),
            vec![first.id, second.id]
        );
    }
    #[tokio::test]
    async fn ephemeral_unsorted_query_returns_first_batch_and_remaining_without_cursor() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use nonzero_ext::nonzero;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(2_u64)),
            },
        };
        let selector = SelectorTuple::<Domain>::default();
        let (output, execution_stats) = apply_query_postprocessing_ephemeral_with_budget(
            vec![d1.clone(), d2.clone(), d3].into_iter(),
            selector,
            &params,
            QueryLimits::default(),
            None,
        )
        .expect("postprocess");
        let (batch, remaining, cursor) = output.into_parts();
        assert!(cursor.is_none());
        assert_eq!(remaining, 1);
        assert_eq!(execution_stats.processed_items(), 3);
        assert_eq!(domain_ids_from_batch(batch), vec![d1.id, d2.id]);
    }
    #[tokio::test]
    async fn ephemeral_unsorted_bounded_count_stops_after_probe_item() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use nonzero_ext::nonzero;
        let d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let d4 = Domain::new(DomainId::try_new("d4", "universal").unwrap()).build(&ALICE_ID);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(2_u64)),
            },
        };
        let selector = SelectorTuple::<Domain>::default();
        let (output, execution_stats) = apply_query_postprocessing_ephemeral_with_budget(
            vec![d1.clone(), d2.clone(), d3, d4].into_iter(),
            selector,
            &params,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
            None,
        )
        .expect("postprocess");
        assert_eq!(output.remaining_items, None);
        assert!(output.has_more);
        let (batch, remaining_hint, cursor) = output.into_parts();
        assert!(cursor.is_none());
        assert_eq!(remaining_hint, 0);
        assert_eq!(execution_stats.processed_items(), 3);
        assert_eq!(domain_ids_from_batch(batch), vec![d1.id, d2.id]);
    }
    #[tokio::test]
    async fn stored_unsorted_bounded_cursor_materializes_owned_tail_without_exact_count() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use nonzero_ext::nonzero;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let domains = ["d1", "d2", "d3", "d4", "d5"]
            .into_iter()
            .map(|name| Domain::new(DomainId::try_new(name, "universal").unwrap()).build(&ALICE_ID))
            .collect::<Vec<_>>();
        let expected_ids = domains
            .iter()
            .map(|domain| domain.id.clone())
            .collect::<Vec<_>>();
        let visited = Arc::new(AtomicUsize::new(0));
        let visited_for_iter = Arc::clone(&visited);
        let iter = domains.into_iter().inspect(move |_| {
            visited_for_iter.fetch_add(1, Ordering::SeqCst);
        });
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let prepared = prepare_stored_unsorted_bounded_start(
            iter,
            SelectorTuple::<Domain>::default(),
            &params,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
        )
        .expect("bounded prepared start");
        assert_eq!(
            visited.load(Ordering::SeqCst),
            expected_ids.len(),
            "stored bounded start must own the continuation tail before inserting it into the shared live query store"
        );
        assert_eq!(prepared.remaining_items, None);
        assert!(prepared.deferred_continuation.is_some());
        let handle = LiveQueryStore::start_test();
        let first = handle
            .handle_iter_start_prepared(prepared, &ALICE_ID, None)
            .expect("store prepared");
        assert_eq!(first.remaining_items, None);
        assert!(first.has_more);
        let (first_batch, first_remaining_hint, cursor) = first.into_parts();
        assert_eq!(first_remaining_hint, 0);
        assert_eq!(
            domain_ids_from_batch(first_batch),
            expected_ids[0..2].to_vec()
        );
        let second = handle
            .handle_iter_continue(cursor.expect("first cursor"), &ALICE_ID)
            .expect("second page");
        assert_eq!(second.remaining_items, None);
        assert!(second.has_more);
        let (second_batch, _, cursor) = second.into_parts();
        assert_eq!(
            domain_ids_from_batch(second_batch),
            expected_ids[2..4].to_vec()
        );
        let third = handle
            .handle_iter_continue(cursor.expect("second cursor"), &ALICE_ID)
            .expect("third page");
        assert_eq!(third.remaining_items, None);
        assert!(!third.has_more);
        let (third_batch, _, cursor) = third.into_parts();
        assert!(cursor.is_none());
        assert_eq!(
            domain_ids_from_batch(third_batch),
            expected_ids[4..5].to_vec()
        );
        assert_eq!(
            visited.load(Ordering::SeqCst),
            expected_ids.len(),
            "continuations should not revisit the source iterator"
        );
    }
    #[tokio::test]
    async fn stored_unsorted_bounded_cursor_rejects_tail_above_hard_item_bound() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use nonzero_ext::nonzero;
        let domain =
            Domain::new(DomainId::try_new("bounded", "universal").unwrap()).build(&ALICE_ID);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
        };
        let result = prepare_stored_unsorted_bounded_start(
            std::iter::repeat_n(domain, MAX_STORED_QUERY_RETAINED_ITEMS.saturating_add(2)),
            SelectorTuple::<Domain>::default(),
            &params,
            QueryLimits::new(1).with_count_mode(QueryCountMode::Bounded),
        );
        let error = match result {
            Ok(_) => panic!("a generic cursor must not retain an unbounded state tail"),
            Err(error) => error,
        };
        assert_eq!(error, Error::CapacityLimit);
    }
    #[test]
    fn stored_bounded_runtime_applies_the_server_execution_budget() {
        use iroha_data_model::query::parameters::FetchSize;
        let decode = norito::DecodeLimits::new(16, 1_024, 32, 4 * 1_024, 8);
        let source_bytes = ORDINARY_NAME_ID_SOURCE_BYTES;
        let response_bytes = 4 * 1_024;
        let archive_bytes = 1_024;
        let execution_headroom = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            1,
            source_bytes,
            response_bytes,
            4 * 1_024,
            archive_bytes,
            decode,
        )
        .expect("execution geometry");
        let cursor_retained = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
            3,
            source_bytes,
            source_bytes,
            archive_bytes,
        )
        .expect("cursor geometry");
        let ordinary = OrdinaryQueryExecutionLimits::try_new(
            1,
            QueryExecutionBudget::from_weighted_limit(4, 1, 0),
            1,
            execution_headroom,
            source_bytes,
            response_bytes,
            3,
            source_bytes,
            cursor_retained,
            4 * 1_024,
            archive_bytes,
            decode,
        )
        .expect("valid four-item work budget and three-item retained tail");
        let values = ["one", "two", "three", "four", "probe"].map(|name| {
            name.parse::<RoleId>()
                .expect("protocol-bounded role identifier")
        });
        let params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            ..QueryParams::default()
        };
        // One page and three retained rows fit; the fifth source row is an overflow probe.
        assert!(
            prepare_stored_unsorted_bounded_start(
                values[..4].iter().cloned(),
                SelectorTuple::<RoleId>::default(),
                &params,
                QueryLimits::new(1)
                    .with_count_mode(QueryCountMode::Bounded)
                    .with_ordinary_execution_limits(ordinary),
            )
            .is_ok()
        );
        let result = prepare_stored_unsorted_bounded_start(
            values.into_iter(),
            SelectorTuple::<RoleId>::default(),
            &params,
            QueryLimits::new(1)
                .with_count_mode(QueryCountMode::Bounded)
                .with_ordinary_execution_limits(ordinary),
        );
        let error = match result {
            Ok(_) => panic!("the overflow probe must share the actual server work budget"),
            Err(error) => error,
        };
        assert_eq!(error, Error::GasBudgetExceeded);
    }

    #[tokio::test]
    async fn stored_unsorted_bounded_cursor_rejects_tail_above_hard_byte_bound() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use nonzero_ext::nonzero;
        let first = domain_with_query_payload("bounded-first", 8, 0);
        let mut values = vec![first];
        let mut retained_bytes = 0_u64;
        while retained_bytes <= MAX_STORED_QUERY_RETAINED_BYTES {
            let index = values.len();
            let row = domain_with_query_payload(
                &format!("bounded-tail{index}"),
                iroha_primitives::json::MAX_JSON_BYTES / 2,
                u64::try_from(index).unwrap(),
            );
            let row_bytes = bounded_bare_encoded_len(&row, u64::MAX).expect("valid bounded row");
            assert!(row_bytes < MAX_STORED_QUERY_RETAINED_BYTES);
            retained_bytes += row_bytes;
            values.push(row);
        }
        assert!(values.len() - 1 < MAX_STORED_QUERY_RETAINED_ITEMS);
        assert!(retained_bytes > MAX_STORED_QUERY_RETAINED_BYTES);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
        };
        assert!(
            prepare_stored_unsorted_bounded_start(
                values[..values.len() - 1].iter().cloned(),
                SelectorTuple::<Domain>::default(),
                &params,
                QueryLimits::new(1).with_count_mode(QueryCountMode::Bounded),
            )
            .is_ok()
        );
        let result = prepare_stored_unsorted_bounded_start(
            values.into_iter(),
            SelectorTuple::<Domain>::default(),
            &params,
            QueryLimits::new(1).with_count_mode(QueryCountMode::Bounded),
        );
        let error = match result {
            Ok(_) => panic!("a generic cursor must not retain an oversized state tail"),
            Err(error) => error,
        };
        assert_eq!(error, Error::CapacityLimit);
    }
    #[tokio::test]
    async fn stored_unsorted_bounded_replay_cursor_does_not_materialize_tail_on_start() {
        use iroha_data_model::{
            domain::Domain,
            query::{
                domain::prelude::FindDomains,
                dsl::CompoundPredicate,
                parameters::{FetchSize, Pagination, QueryParams, Sorting},
            },
        };
        use nonzero_ext::nonzero;
        use std::sync::{
            Arc, Weak,
            atomic::{AtomicUsize, Ordering},
        };
        let domains = ["d1", "d2", "d3", "d4", "d5"]
            .into_iter()
            .map(|name| Domain::new(DomainId::try_new(name, "universal").unwrap()).build(&ALICE_ID))
            .collect::<Vec<_>>();
        let expected_ids = domains
            .iter()
            .map(|domain| domain.id.clone())
            .collect::<Vec<_>>();
        let visited = Arc::new(AtomicUsize::new(0));
        let visited_for_iter = Arc::clone(&visited);
        let iter = domains.into_iter().inspect(move |_| {
            visited_for_iter.fetch_add(1, Ordering::SeqCst);
        });
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let prepared = prepare_stored_unsorted_bounded_replay_start(
            iter,
            FindDomains,
            CompoundPredicate::PASS,
            SelectorTuple::<Domain>::default(),
            &params,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
            Weak::<State>::new(),
        )
        .expect("bounded replay prepared start");
        assert_eq!(
            visited.load(Ordering::SeqCst),
            3,
            "replay-backed bounded start should consume only the first batch plus a probe"
        );
        let handle = LiveQueryStore::start_test();
        let first = handle
            .handle_iter_start_paged_prepared(prepared, &ALICE_ID, None)
            .expect("store prepared");
        assert_eq!(first.remaining_items, None);
        assert!(first.has_more);
        let (first_batch, first_remaining_hint, cursor) = first.into_parts();
        assert_eq!(first_remaining_hint, 0);
        assert_eq!(
            domain_ids_from_batch(first_batch),
            expected_ids[0..2].to_vec()
        );
        assert_eq!(
            visited.load(Ordering::SeqCst),
            3,
            "storing the cursor must not force tail materialization"
        );
        let err = handle
            .handle_iter_continue(cursor.expect("first cursor"), &ALICE_ID)
            .expect_err("missing replay state expires the cursor");
        assert!(matches!(err, Error::Expired));
    }
    #[tokio::test]
    async fn stored_unsorted_bounded_replay_limit_boundary_does_not_probe_or_store_cursor() {
        use iroha_data_model::{
            domain::Domain,
            query::{
                domain::prelude::FindDomains,
                dsl::CompoundPredicate,
                parameters::{FetchSize, Pagination, QueryParams, Sorting},
            },
        };
        use nonzero_ext::nonzero;
        use std::sync::{
            Arc, Weak,
            atomic::{AtomicUsize, Ordering},
        };
        let domains = ["d1", "d2", "d3", "d4", "d5"]
            .into_iter()
            .map(|name| Domain::new(DomainId::try_new(name, "universal").unwrap()).build(&ALICE_ID))
            .collect::<Vec<_>>();
        let expected_ids = domains
            .iter()
            .map(|domain| domain.id.clone())
            .collect::<Vec<_>>();
        let visited = Arc::new(AtomicUsize::new(0));
        let visited_for_iter = Arc::clone(&visited);
        let iter = domains.into_iter().inspect(move |_| {
            visited_for_iter.fetch_add(1, Ordering::SeqCst);
        });
        let params = QueryParams {
            pagination: Pagination {
                limit: Some(nonzero!(2_u64)),
                offset: 1,
            },
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(5_u64))),
        };
        let prepared = prepare_stored_unsorted_bounded_replay_start(
            iter,
            FindDomains,
            CompoundPredicate::PASS,
            SelectorTuple::<Domain>::default(),
            &params,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
            Weak::<State>::new(),
        )
        .expect("bounded replay prepared start");
        assert_eq!(
            visited.load(Ordering::SeqCst),
            3,
            "explicit limit should consume offset plus the requested rows and skip the probe"
        );
        assert!(prepared.paged_continuation.is_none());
        let handle = LiveQueryStore::start_test();
        let first = handle
            .handle_iter_start_paged_prepared(prepared, &ALICE_ID, None)
            .expect("store prepared");
        assert_eq!(first.remaining_items, None);
        assert!(!first.has_more);
        let (first_batch, first_remaining_hint, cursor) = first.into_parts();
        assert_eq!(first_remaining_hint, 0);
        assert!(cursor.is_none());
        assert_eq!(
            domain_ids_from_batch(first_batch),
            expected_ids[1..3].to_vec()
        );
    }
    #[tokio::test]
    async fn collect_unsorted_bounded_page_rejects_returned_offset_at_limit_without_reading() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use nonzero_ext::nonzero;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let visited = Arc::new(AtomicUsize::new(0));
        let visited_for_iter = Arc::clone(&visited);
        let iter = ["d1", "d2", "d3"].into_iter().map(move |name| {
            visited_for_iter.fetch_add(1, Ordering::SeqCst);
            Domain::new(DomainId::try_new(name, "universal").unwrap()).build(&ALICE_ID)
        });
        let params = QueryParams {
            pagination: Pagination {
                limit: Some(nonzero!(2_u64)),
                offset: 0,
            },
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let err = collect_unsorted_bounded_page(
            iter,
            SelectorTuple::<Domain>::default(),
            &params,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
            2,
        )
        .expect_err("cursor at the limit is done");
        assert!(matches!(err, Error::CursorDone));
        assert_eq!(
            visited.load(Ordering::SeqCst),
            0,
            "limit-exhausted continuations must fail before reading source rows"
        );
    }
    #[tokio::test]
    async fn collect_unsorted_bounded_page_rejects_oversized_fetch_without_reading() {
        use iroha_data_model::{
            domain::Domain,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use nonzero_ext::nonzero;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let visited = Arc::new(AtomicUsize::new(0));
        let visited_for_iter = Arc::clone(&visited);
        let iter = ["d1", "d2", "d3"].into_iter().map(move |name| {
            visited_for_iter.fetch_add(1, Ordering::SeqCst);
            Domain::new(DomainId::try_new(name, "universal").unwrap()).build(&ALICE_ID)
        });
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let err = collect_unsorted_bounded_page(
            iter,
            SelectorTuple::<Domain>::default(),
            &params,
            QueryLimits::new(1).with_count_mode(QueryCountMode::Bounded),
            0,
        )
        .expect_err("oversized fetch should fail");
        assert!(matches!(err, Error::FetchSizeTooBig));
        assert_eq!(
            visited.load(Ordering::SeqCst),
            0,
            "fetch-size abuse must fail before reading source rows"
        );
    }
    fn domain_ids_from_batch(
        batch: iroha_data_model::query::QueryOutputBatchBoxTuple,
    ) -> Vec<DomainId> {
        let mut tuple_iter = batch.into_iter();
        match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => {
                v.into_iter().map(|domain| domain.id).collect()
            }
            other => panic!("unexpected batch variant: {other:?}"),
        }
    }
    fn sample_sorted_domains() -> Vec<Domain> {
        let mut d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
        let mut d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
        let mut d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
        let mut d4 = Domain::new(DomainId::try_new("d4", "universal").unwrap()).build(&ALICE_ID);
        let mut d5 = Domain::new(DomainId::try_new("d5", "universal").unwrap()).build(&ALICE_ID);
        let d6 = Domain::new(DomainId::try_new("d6", "universal").unwrap()).build(&ALICE_ID);
        d1.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        d2.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        d3.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        d4.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(3)));
        d5.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        vec![d6, d5, d4, d3, d2, d1]
    }
    #[tokio::test]
    async fn stored_sorted_fast_start_matches_legacy_first_batch_variants() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use std::num::NonZeroU64;
        let cases = [
            (0_u64, None, 1_u64),
            (0_u64, None, 2_u64),
            (1_u64, None, 2_u64),
            (1_u64, Some(3_u64), 2_u64),
            (2_u64, Some(3_u64), 1_u64),
            (3_u64, Some(2_u64), 2_u64),
        ];
        for (offset, limit, fetch_size) in cases {
            let params = QueryParams {
                pagination: Pagination {
                    offset,
                    limit: limit.and_then(NonZeroU64::new),
                },
                sorting: Sorting::by_metadata_key("rank".parse().unwrap()),
                fetch_size: FetchSize::new(Some(
                    NonZeroU64::new(fetch_size).expect("non-zero fetch size"),
                )),
            };
            let selector = SelectorTuple::<Domain>::default();
            let mut historical = apply_query_postprocessing(
                sample_sorted_domains().into_iter(),
                selector.clone(),
                &params,
                QueryLimits::default(),
            )
            .expect("historical path");
            let (legacy_first_batch, legacy_next) =
                historical.next_batch(0).expect("historical first");
            let legacy_remaining = historical.remaining();
            let fast = stored_sorted_fast_start_params(&params, QueryLimits::default())
                .expect("fast path selection")
                .expect("fast path should be available for this test");
            let prepared = prepare_stored_sorted_start(
                sample_sorted_domains().into_iter(),
                selector,
                fast,
                None,
            )
            .expect("prepared start");
            assert_eq!(
                domain_ids_from_batch(prepared.first_batch),
                domain_ids_from_batch(legacy_first_batch),
                "offset={offset} limit={limit:?} fetch={fetch_size}"
            );
            assert_eq!(
                prepared.remaining_items, legacy_remaining,
                "offset={offset} limit={limit:?} fetch={fetch_size}"
            );
            assert_eq!(
                prepared.deferred_continuation.is_some(),
                legacy_next.is_some(),
                "offset={offset} limit={limit:?} fetch={fetch_size}"
            );
        }
    }
    #[tokio::test]
    async fn deferred_stored_start_first_continue_preserves_global_order() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use nonzero_ext::nonzero;
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::by_metadata_key("rank".parse().unwrap()),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let selector = SelectorTuple::<Domain>::default();
        let mut historical = apply_query_postprocessing(
            sample_sorted_domains().into_iter(),
            selector.clone(),
            &params,
            QueryLimits::default(),
        )
        .expect("historical path");
        let (_legacy_first, legacy_cursor) = historical.next_batch(0).expect("historical first");
        let expected_cursor = legacy_cursor.expect("historical continuation");
        let (legacy_second, _legacy_next) = historical
            .next_batch(expected_cursor.get())
            .expect("historical second");
        let expected_second_ids = domain_ids_from_batch(legacy_second);
        let fast = stored_sorted_fast_start_params(&params, QueryLimits::default())
            .expect("fast path selection")
            .expect("fast path should be available");
        let prepared =
            prepare_stored_sorted_start(sample_sorted_domains().into_iter(), selector, fast, None)
                .expect("prepared start");
        let handle = LiveQueryStore::start_test();
        let (_batch, _remaining, cursor) = handle
            .handle_iter_start_prepared(prepared, &ALICE_ID, None)
            .expect("store prepared")
            .into_parts();
        let cursor = cursor.expect("cursor");
        let next = handle
            .handle_iter_continue(cursor, &ALICE_ID)
            .expect("first continuation")
            .into_parts();
        assert_eq!(domain_ids_from_batch(next.0), expected_second_ids);
    }
    #[tokio::test]
    async fn validate_for_ivm_uses_validator() -> Result<()> {
        struct DummyValidator {
            authority: AccountId,
            validated: bool,
        }
        impl IvmQueryValidator for DummyValidator {
            fn authority(&self) -> &AccountId {
                &self.authority
            }
            fn validate_query(
                &mut self,
                authority: &AccountId,
                _query: &QueryRequest,
            ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>>
            {
                assert_eq!(authority, &self.authority);
                self.validated = true;
                Ok(())
            }
        }
        let mut validator = DummyValidator {
            authority: ALICE_ID.clone(),
            validated: false,
        };
        let query = QueryRequest::Singular(FindParameters.into());
        ValidQueryRequest::validate_for_ivm(query, &mut validator, QueryLimits::default())?;
        assert!(validator.validated);
        Ok(())
    }
    #[tokio::test]
    async fn validate_for_ivm_rejects_continue() {
        use iroha_data_model::query::parameters::ForwardCursor;
        struct DummyValidator {
            authority: AccountId,
        }
        impl IvmQueryValidator for DummyValidator {
            fn authority(&self) -> &AccountId {
                &self.authority
            }
            fn validate_query(
                &mut self,
                _authority: &AccountId,
                _query: &QueryRequest,
            ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>>
            {
                Ok(())
            }
        }
        let mut validator = DummyValidator {
            authority: ALICE_ID.clone(),
        };
        let cursor = ForwardCursor {
            query: "ivm-cursor".to_string(),
            cursor: nonzero!(1_u64),
            gas_budget: None,
        };
        let request = QueryRequest::Continue(cursor);
        let err = match ValidQueryRequest::validate_for_ivm(
            request,
            &mut validator,
            QueryLimits::default(),
        ) {
            Ok(_) => panic!("IVM must reject query continuations"),
            Err(err) => err,
        };
        assert!(
            matches!(err, crate::execution_attempt::ExecutionAttemptError::Rejected(ValidationFail::NotPermitted(msg)) if msg.contains("Continue"))
        );
    }
    fn world_with_test_domains() -> World {
        let domain_id = DomainId::try_new("wonderland", "universal").expect("Valid");
        let domain = Domain::new(domain_id).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let asset_definition_id =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id,
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        with_global_reader(
            World::with([domain], [account], [asset_definition]),
            &ALICE_ID,
        )
    }
    // Every positive history row is an original execution under native Sumeragi.
    fn state_with_test_blocks_and_transactions(
        blocks: u64,
        valid_tx_per_block: usize,
        invalid_tx_per_block: usize,
    ) -> Result<Arc<State>> {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        let mut config = TestChainConfig::new(world_with_test_domains(), 1000);
        config.genesis_key = ALICE_KEYPAIR.clone();
        let mut chain = CertifiedTestChain::start(config).expect("native query genesis");
        for height in 2..=blocks.max(2) {
            let sources = (0..valid_tx_per_block + invalid_tx_per_block)
                .map(|index| {
                    let instructions: Vec<InstructionBox> = if index < valid_tx_per_block {
                        vec![
                            Log::new(iroha_logger::Level::INFO, format!("pass {height}:{index}"))
                                .into(),
                        ]
                    } else {
                        vec![
                            Unregister::domain(DomainId::try_new("dummy", "universal").unwrap())
                                .into(),
                        ]
                    };
                    chain.sign(&ALICE_KEYPAIR, instructions, height * 1000 + index as u64)
                })
                .collect();
            chain.commit(sources);
        }
        Ok(Arc::clone(chain.state()))
    }
    #[tokio::test]
    async fn iter_dispatch_sorts_and_paginates_end_to_end() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use iroha_futures::supervisor::ShutdownSignal;
        use iroha_primitives::json::Json;
        // Build world with three domains and ALICE account
        let d1_id: DomainId = DomainId::try_new("d1", "universal").unwrap();
        let d2_id: DomainId = DomainId::try_new("d2", "universal").unwrap();
        let d3_id: DomainId = DomainId::try_new("d3", "universal").unwrap();
        let mut d1 = Domain::new(d1_id.clone()).build(&ALICE_ID);
        let mut d2 = Domain::new(d2_id.clone()).build(&ALICE_ID);
        let d3 = Domain::new(d3_id.clone()).build(&ALICE_ID);
        d1.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        d2.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([d1.clone(), d2.clone(), d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new_with_chain(world, kura, handle.clone(), ChainId::from("chain"));
        let state_view = state.view();
        // Build params: sort by metadata key asc, fetch_size=2
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::by_metadata_key("rank".parse().unwrap()),
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        // Build an erased iterable query for Domains and wrap with params
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let qbox: iroha_data_model::query::QueryBox<_> =
            Box::new(iroha_data_model::query::ErasedIterQuery::<Domain>::new(
                iroha_data_model::query::dsl::CompoundPredicate::<Domain>::PASS,
                SelectorTuple::<Domain>::default(),
                payload,
            ));
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first) =
            validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch, _remaining, cursor) = first.into_parts();
        let mut tuple_iter = batch.into_iter();
        let v = match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, d2_id);
        assert_eq!(v[1].id, d1_id);
        // Continue for the remaining item
        let cursor = cursor.expect("should continue");
        let next = handle.handle_iter_continue(cursor, &ALICE_ID).unwrap();
        let (batch2, _rem2, cur2) = next.into_parts();
        let mut tuple_iter2 = batch2.into_iter();
        let v2 = match tuple_iter2.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].id, d3_id);
        assert!(cur2.is_none());
    }
    #[tokio::test]
    async fn iter_dispatch_erased_and_canonical_parity_for_domains() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::{
            QueryBox, QueryOutputBatchBox, QueryRequest, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::{QueryParams, SortOrder, Sorting},
        };
        use iroha_futures::supervisor::ShutdownSignal;
        fn make_world() -> World {
            let d1_id: DomainId = DomainId::try_new("d1", "universal").unwrap();
            let d2_id: DomainId = DomainId::try_new("d2", "universal").unwrap();
            let d3_id: DomainId = DomainId::try_new("d3", "universal").unwrap();
            let mut d1 = Domain::new(d1_id).build(&ALICE_ID);
            let mut d2 = Domain::new(d2_id).build(&ALICE_ID);
            let d3 = Domain::new(d3_id).build(&ALICE_ID);
            d1.metadata_mut()
                .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
            d2.metadata_mut()
                .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
            let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
            World::with([d1, d2, d3], [account], [])
        }
        fn build_state(world: World) -> (State, crate::query::store::LiveQueryStoreHandle) {
            let kura = Kura::blank_kura_for_testing();
            let store = std::sync::Arc::new(LiveQueryStore::from_config(
                StoreCfg::default(),
                ShutdownSignal::new(),
            ));
            let handle = crate::query::store::LiveQueryStoreHandle::new(store);
            let state = State::new(world, kura, handle.clone());
            (state, handle)
        }
        let params = QueryParams {
            sorting: Sorting {
                sort_by_metadata_key: Some("rank".parse().unwrap()),
                order: Some(SortOrder::Asc),
            },
            ..Default::default()
        };
        // Erased query path using a boxed iterator payload.
        let (state_boxed, handle_boxed) = build_state(make_world());
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let qbox: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<Domain>::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            payload,
        ));
        let boxed_qwp = QueryWithParams::new(&qbox, params.clone())
            .expect("test query type has a canonical mapping");
        let boxed_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(boxed_qwp),
            &ALICE_ID,
            &state_boxed.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(boxed_output) = boxed_req
            .execute(&handle_boxed, &state_boxed.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (boxed_batch, _boxed_remaining, _boxed_cursor) = boxed_output.into_parts();
        let mut boxed_iter = boxed_batch.into_iter();
        let boxed_domains = match boxed_iter.next().expect("slice") {
            QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        // Canonical path with encoded predicate/selector and no boxed payload.
        let (state_fast, handle_fast) = build_state(make_world());
        let fast_qwp = QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::domain::prelude::FindDomains,
            ),
            item: iroha_data_model::query::QueryItemKind::Domain,
            predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Domain>::PASS),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Domain>::default()),
            params,
        };
        let fast_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(fast_qwp),
            &ALICE_ID,
            &state_fast.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(fast_output) = fast_req
            .execute(&handle_fast, &state_fast.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (fast_batch, _fast_remaining, _fast_cursor) = fast_output.into_parts();
        let mut fast_iter = fast_batch.into_iter();
        let fast_domains = match fast_iter.next().expect("slice") {
            QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        let boxed_ids: Vec<_> = boxed_domains.into_iter().map(|d| d.id).collect();
        let fast_ids: Vec<_> = fast_domains.into_iter().map(|d| d.id).collect();
        assert_eq!(boxed_ids, fast_ids);
    }
    #[tokio::test]
    async fn iter_dispatch_erased_and_canonical_parity_for_assets() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::{
            QueryBox, QueryOutputBatchBox, QueryRequest, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::QueryParams,
        };
        use iroha_futures::supervisor::ShutdownSignal;
        fn make_world() -> (World, AssetDefinitionId, AssetId) {
            let domain =
                iroha_data_model::domain::Domain::new(DomainId::try_new("w", "universal").unwrap())
                    .build(&ALICE_ID);
            let account =
                iroha_data_model::account::Account::new(ALICE_ID.clone()).build(&ALICE_ID);
            let ad_id: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("w", "universal").unwrap(),
                    "rose".parse().unwrap(),
                );
            let ad = iroha_data_model::asset::definition::AssetDefinition::numeric(
                ad_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&ALICE_ID);
            let asset_id = AssetId::new(ad_id.clone(), ALICE_ID.clone());
            let asset = iroha_data_model::asset::value::Asset::new(asset_id.clone(), 10_u32);
            let world = World::with_assets([domain], [account], [ad.clone()], [asset], []);
            (world, ad_id, asset_id)
        }
        fn build_state(world: World) -> (State, crate::query::store::LiveQueryStoreHandle) {
            let kura = Kura::blank_kura_for_testing();
            let store = std::sync::Arc::new(LiveQueryStore::from_config(
                StoreCfg::default(),
                ShutdownSignal::new(),
            ));
            let handle = crate::query::store::LiveQueryStoreHandle::new(store);
            let state = State::new(with_global_reader(world, &ALICE_ID), kura, handle.clone());
            (state, handle)
        }
        let params = QueryParams::default();
        // Erased query path
        let (world_boxed, ad_id, asset_id) = make_world();
        let (state_boxed, handle_boxed) = build_state(world_boxed);
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::asset::prelude::FindAssets);
        let qbox: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<
            iroha_data_model::asset::value::Asset,
        >::new(
            CompoundPredicate::PASS,
            SelectorTuple::<iroha_data_model::asset::value::Asset>::default(),
            payload,
        ));
        let boxed_qwp = QueryWithParams::new(&qbox, params.clone())
            .expect("test query type has a canonical mapping");
        let boxed_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(boxed_qwp),
            &ALICE_ID,
            &state_boxed.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(boxed_output) = boxed_req
            .execute(&handle_boxed, &state_boxed.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (boxed_batch, _boxed_remaining, _boxed_cursor) = boxed_output.into_parts();
        let mut boxed_iter = boxed_batch.into_iter();
        let boxed_assets = match boxed_iter.next().expect("slice") {
            QueryOutputBatchBox::Asset(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        // Canonical encoded-component path.
        let (world_fast, _ad_fast, _asset_fast) = make_world();
        let (state_fast, handle_fast) = build_state(world_fast);
        let predicate = CompoundPredicate::<iroha_data_model::asset::value::Asset>::PASS;
        let fast_qwp = QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::asset::prelude::FindAssets,
            ),
            item: iroha_data_model::query::QueryItemKind::Asset,
            predicate_bytes: norito::codec::Encode::encode(&predicate),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<
                iroha_data_model::asset::value::Asset,
            >::default()),
            params,
        };
        let fast_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(fast_qwp),
            &ALICE_ID,
            &state_fast.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(fast_output) = fast_req
            .execute(&handle_fast, &state_fast.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (fast_batch, _fast_remaining, _fast_cursor) = fast_output.into_parts();
        let mut fast_iter = fast_batch.into_iter();
        let fast_assets = match fast_iter.next().expect("slice") {
            QueryOutputBatchBox::Asset(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        let boxed_ids: Vec<_> = boxed_assets.into_iter().map(|a| a.id().clone()).collect();
        let fast_ids: Vec<_> = fast_assets.into_iter().map(|a| a.id().clone()).collect();
        assert_eq!(boxed_ids, fast_ids);
        assert_eq!(boxed_ids, vec![asset_id]);
        assert_eq!(ad_id, boxed_ids[0].definition().clone());
    }
    #[tokio::test]
    async fn iter_dispatch_erased_and_canonical_parity_for_nfts() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::{
            QueryBox, QueryOutputBatchBox, QueryRequest, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::QueryParams,
        };
        use iroha_futures::supervisor::ShutdownSignal;
        fn make_world() -> World {
            let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
            let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
            let n1 =
                Nft::new("n1$w.universal".parse().unwrap(), Metadata::default()).build(&ALICE_ID);
            let n2 =
                Nft::new("n2$w.universal".parse().unwrap(), Metadata::default()).build(&ALICE_ID);
            World::with_assets([domain], [account], [], [], [n1, n2])
        }
        fn build_state(world: World) -> (State, crate::query::store::LiveQueryStoreHandle) {
            let kura = Kura::blank_kura_for_testing();
            let store = std::sync::Arc::new(LiveQueryStore::from_config(
                StoreCfg::default(),
                ShutdownSignal::new(),
            ));
            let handle = crate::query::store::LiveQueryStoreHandle::new(store);
            let state = State::new(with_global_reader(world, &ALICE_ID), kura, handle.clone());
            (state, handle)
        }
        let params = QueryParams::default();
        // Erased query path
        let (state_boxed, handle_boxed) = build_state(make_world());
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::nft::prelude::FindNfts);
        let qbox: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<
            iroha_data_model::nft::Nft,
        >::new(
            CompoundPredicate::PASS,
            SelectorTuple::<iroha_data_model::nft::Nft>::default(),
            payload,
        ));
        let boxed_qwp = QueryWithParams::new(&qbox, params.clone())
            .expect("test query type has a canonical mapping");
        let boxed_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(boxed_qwp),
            &ALICE_ID,
            &state_boxed.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(boxed_output) = boxed_req
            .execute(&handle_boxed, &state_boxed.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (boxed_batch, _boxed_remaining, _boxed_cursor) = boxed_output.into_parts();
        let mut boxed_iter = boxed_batch.into_iter();
        let boxed_nfts = match boxed_iter.next().expect("slice") {
            QueryOutputBatchBox::Nft(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        // Canonical encoded-component path.
        let (state_fast, handle_fast) = build_state(make_world());
        let fast_qwp = QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::nft::prelude::FindNfts,
            ),
            item: iroha_data_model::query::QueryItemKind::Nft,
            predicate_bytes: norito::codec::Encode::encode(
                &CompoundPredicate::<iroha_data_model::nft::Nft>::PASS,
            ),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<
                iroha_data_model::nft::Nft,
            >::default()),
            params,
        };
        let fast_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(fast_qwp),
            &ALICE_ID,
            &state_fast.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(fast_output) = fast_req
            .execute(&handle_fast, &state_fast.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (fast_batch, _fast_remaining, _fast_cursor) = fast_output.into_parts();
        let mut fast_iter = fast_batch.into_iter();
        let fast_nfts = match fast_iter.next().expect("slice") {
            QueryOutputBatchBox::Nft(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        let mut boxed_ids: Vec<_> = boxed_nfts.into_iter().map(|n| n.id().clone()).collect();
        let mut fast_ids: Vec<_> = fast_nfts.into_iter().map(|n| n.id().clone()).collect();
        boxed_ids.sort();
        fast_ids.sort();
        assert_eq!(boxed_ids, fast_ids);
    }
    #[tokio::test]
    async fn iter_dispatch_erased_and_canonical_parity_for_accounts() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::{
            QueryBox, QueryOutputBatchBox, QueryRequest, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::QueryParams,
        };
        use iroha_futures::supervisor::ShutdownSignal;
        fn make_world() -> World {
            let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
            let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
            let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
            World::with([domain], [alice, bob], [])
        }
        fn build_state(world: World) -> (State, crate::query::store::LiveQueryStoreHandle) {
            let kura = Kura::blank_kura_for_testing();
            let store = std::sync::Arc::new(LiveQueryStore::from_config(
                StoreCfg::default(),
                ShutdownSignal::new(),
            ));
            let handle = crate::query::store::LiveQueryStoreHandle::new(store);
            let state = State::new(with_global_reader(world, &ALICE_ID), kura, handle.clone());
            (state, handle)
        }
        let params = QueryParams::default();
        // Erased query path
        let (state_boxed, handle_boxed) = build_state(make_world());
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::account::prelude::FindAccounts);
        let qbox: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<
            iroha_data_model::account::Account,
        >::new(
            CompoundPredicate::PASS,
            SelectorTuple::<iroha_data_model::account::Account>::default(),
            payload,
        ));
        let boxed_qwp = QueryWithParams::new(&qbox, params.clone())
            .expect("test query type has a canonical mapping");
        let boxed_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(boxed_qwp),
            &ALICE_ID,
            &state_boxed.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(boxed_output) = boxed_req
            .execute(&handle_boxed, &state_boxed.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (boxed_batch, _boxed_remaining, _boxed_cursor) = boxed_output.into_parts();
        let mut boxed_iter = boxed_batch.into_iter();
        let boxed_accounts = match boxed_iter.next().expect("slice") {
            QueryOutputBatchBox::Account(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        // Canonical encoded-component path.
        let (state_fast, handle_fast) = build_state(make_world());
        let fast_qwp = QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::account::prelude::FindAccounts,
            ),
            item: iroha_data_model::query::QueryItemKind::Account,
            predicate_bytes: norito::codec::Encode::encode(
                &CompoundPredicate::<iroha_data_model::account::Account>::PASS,
            ),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<
                iroha_data_model::account::Account,
            >::default()),
            params,
        };
        let fast_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(fast_qwp),
            &ALICE_ID,
            &state_fast.view(),
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(fast_output) = fast_req
            .execute(&handle_fast, &state_fast.view(), &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable");
        };
        let (fast_batch, _fast_remaining, _fast_cursor) = fast_output.into_parts();
        let mut fast_iter = fast_batch.into_iter();
        let fast_accounts = match fast_iter.next().expect("slice") {
            QueryOutputBatchBox::Account(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        let mut boxed_ids: Vec<_> = boxed_accounts.into_iter().map(|a| a.id().clone()).collect();
        let mut fast_ids: Vec<_> = fast_accounts.into_iter().map(|a| a.id().clone()).collect();
        boxed_ids.sort();
        fast_ids.sort();
        assert_eq!(boxed_ids, fast_ids);
        assert!(boxed_ids.contains(&ALICE_ID));
        assert!(boxed_ids.contains(&BOB_ID));
    }
    #[tokio::test]
    async fn iter_dispatch_erased_and_canonical_parity_for_block_headers() -> Result<()> {
        use iroha_data_model::query::{
            QueryBox, QueryOutputBatchBox, QueryRequest, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::QueryParams,
        };
        // Build a small chain with a few blocks.
        let state = state_with_test_blocks_and_transactions(3, 1, 0)?;
        let handle = LiveQueryStore::start_test();
        let state_view = state.view();
        let params = QueryParams::default();
        // Erased query path
        let payload = norito::codec::Encode::encode(
            &iroha_data_model::query::block::prelude::FindBlockHeaders,
        );
        let qbox: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<
            iroha_data_model::block::BlockHeader,
        >::new(
            CompoundPredicate::PASS,
            SelectorTuple::<iroha_data_model::block::BlockHeader>::default(),
            payload,
        ));
        let boxed_qwp = QueryWithParams::new(&qbox, params.clone())
            .expect("test query type has a canonical mapping");
        let boxed_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(boxed_qwp),
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )?;
        let QueryResponse::Iterable(boxed_output) =
            boxed_req.execute(&handle, &state_view, &ALICE_ID)?
        else {
            panic!("expected iterable");
        };
        let (boxed_batch, _boxed_remaining, _boxed_cursor) = boxed_output.into_parts();
        let mut boxed_iter = boxed_batch.into_iter();
        let boxed_headers = match boxed_iter.next().expect("slice") {
            QueryOutputBatchBox::BlockHeader(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        // Canonical encoded-component path.
        let fast_qwp = QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::block::prelude::FindBlockHeaders,
            ),
            item: iroha_data_model::query::QueryItemKind::BlockHeader,
            predicate_bytes: norito::codec::Encode::encode(
                &CompoundPredicate::<iroha_data_model::block::BlockHeader>::PASS,
            ),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<
                iroha_data_model::block::BlockHeader,
            >::default()),
            params,
        };
        let fast_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(fast_qwp),
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )?;
        let QueryResponse::Iterable(fast_output) =
            fast_req.execute(&handle, &state_view, &ALICE_ID)?
        else {
            panic!("expected iterable");
        };
        let (fast_batch, _fast_remaining, _fast_cursor) = fast_output.into_parts();
        let mut fast_iter = fast_batch.into_iter();
        let fast_headers = match fast_iter.next().expect("slice") {
            QueryOutputBatchBox::BlockHeader(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        let boxed_hashes: Vec<_> = boxed_headers
            .iter()
            .map(iroha_data_model::block::Header::hash)
            .collect();
        let fast_hashes: Vec<_> = fast_headers
            .iter()
            .map(iroha_data_model::block::Header::hash)
            .collect();
        assert_eq!(boxed_hashes, fast_hashes);
        Ok(())
    }
    #[tokio::test]
    async fn iter_dispatch_sorts_desc_end_to_end() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::parameters::{
            FetchSize, Pagination, QueryParams, SortOrder, Sorting,
        };
        use iroha_futures::supervisor::ShutdownSignal;
        use iroha_primitives::json::Json;
        // Build world with three domains and ALICE account
        let d1_id: DomainId = DomainId::try_new("d1", "universal").unwrap();
        let d2_id: DomainId = DomainId::try_new("d2", "universal").unwrap();
        let d3_id: DomainId = DomainId::try_new("d3", "universal").unwrap();
        let mut d1 = Domain::new(d1_id.clone()).build(&ALICE_ID);
        let mut d2 = Domain::new(d2_id.clone()).build(&ALICE_ID);
        let d3 = Domain::new(d3_id.clone()).build(&ALICE_ID);
        d1.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
        d2.metadata_mut()
            .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([d1.clone(), d2.clone(), d3.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new_with_chain(world, kura, handle.clone(), ChainId::from("chain"));
        let state_view = state.view();
        // Desc sort by rank; fetch_size 2
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting {
                sort_by_metadata_key: Some("rank".parse().unwrap()),
                order: Some(SortOrder::Desc),
            },
            fetch_size: FetchSize::new(nonzero_ext::nonzero!(2_u64).into()),
        };
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let qbox: iroha_data_model::query::QueryBox<_> =
            Box::new(iroha_data_model::query::ErasedIterQuery::<Domain>::new(
                iroha_data_model::query::dsl::CompoundPredicate::<Domain>::PASS,
                SelectorTuple::<Domain>::default(),
                payload,
            ));
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first) =
            validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch, _remaining, cursor) = first.into_parts();
        let mut tuple_iter = batch.into_iter();
        let v = match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, d1_id);
        assert_eq!(v[1].id, d2_id);
        // Continue for the last (no-rank) domain
        let next = handle
            .handle_iter_continue(cursor.expect("should continue"), &ALICE_ID)
            .unwrap();
        let (batch2, _rem2, cur2) = next.into_parts();
        let mut tuple_iter2 = batch2.into_iter();
        let v2 = match tuple_iter2.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].id, d3_id);
        assert!(cur2.is_none());
    }
    #[tokio::test]
    async fn iter_dispatch_nfts() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use iroha_futures::supervisor::ShutdownSignal;
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let n1 = Nft::new("n1$w.universal".parse().unwrap(), Metadata::default()).build(&ALICE_ID);
        let n2 = Nft::new("n2$w.universal".parse().unwrap(), Metadata::default()).build(&ALICE_ID);
        let world = World::with_assets([domain], [account], [], [], [n1.clone(), n2.clone()]);
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new_with_chain(
            with_global_reader(world, &ALICE_ID),
            kura,
            handle.clone(),
            ChainId::from("chain"),
        );
        let state_view = state.view();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        // Build an erased iterable query over NFTs with a pass predicate and empty selector
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::nft::prelude::FindNfts);
        let erased = iroha_data_model::query::ErasedIterQuery::<iroha_data_model::nft::Nft>::new(
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            SelectorTuple::default(),
            payload,
        );
        let qbox: iroha_data_model::query::QueryBox<iroha_data_model::query::QueryOutputBatchBox> =
            Box::new(erased);
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first) =
            validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch, _rem, _cur) = first.into_parts();
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Nft(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2);
        assert!(v.iter().any(|x| x.id() == n1.id()));
        assert!(v.iter().any(|x| x.id() == n2.id()));
    }
    #[tokio::test]
    async fn iter_dispatch_triggers_basic() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::{
            events::time::{ExecutionTime, TimeEventFilter},
            prelude::*,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use iroha_futures::supervisor::ShutdownSignal;
        // Minimal world with ALICE
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([domain], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new(with_global_reader(world, &ALICE_ID), kura, handle.clone());
        // Add two simple time triggers
        {
            let mut block = state.world.triggers.block();
            let mut tx = block.transaction();
            let exec = [Log::new(iroha_logger::Level::INFO, "x".into())];
            let filter = TimeEventFilter::new(ExecutionTime::PreCommit);
            let action = Action::new(exec, Repeats::Indefinitely, ALICE_ID.clone(), filter)
                .expect("trigger action fixture satisfies validation invariants");
            let t1 = Trigger::new("t1".parse().unwrap(), action.clone())
                .try_into()
                .unwrap();
            let t2 = Trigger::new("t2".parse().unwrap(), action)
                .try_into()
                .unwrap();
            tx.add_time_trigger(t1).unwrap();
            tx.add_time_trigger(t2).unwrap();
            tx.apply();
            block.commit();
        }
        let state_view = state.view();
        // Query active trigger ids
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        // Build erased iterable FindActiveTriggerIds query
        let payload = norito::codec::Encode::encode(
            &iroha_data_model::query::trigger::prelude::FindActiveTriggerIds,
        );
        let erased =
            iroha_data_model::query::ErasedIterQuery::<iroha_data_model::trigger::TriggerId>::new(
                iroha_data_model::query::dsl::CompoundPredicate::PASS,
                SelectorTuple::default(),
                payload,
            );
        let qbox: iroha_data_model::query::QueryBox<iroha_data_model::query::QueryOutputBatchBox> =
            Box::new(erased);
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first) =
            validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch, _rem, _cur) = first.into_parts();
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::TriggerId(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2);
        let ids: std::collections::BTreeSet<_> = v.into_iter().collect();
        assert!(ids.contains(&"t1".parse().unwrap()));
        assert!(ids.contains(&"t2".parse().unwrap()));
    }
    #[tokio::test]
    async fn iter_dispatch_pagination_offset_limit() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use iroha_futures::supervisor::ShutdownSignal;
        // World with ordered domains a,b,c
        let a: Domain = Domain::new(DomainId::try_new("a", "universal").unwrap()).build(&ALICE_ID);
        let b: Domain = Domain::new(DomainId::try_new("b", "universal").unwrap()).build(&ALICE_ID);
        let c: Domain = Domain::new(DomainId::try_new("c", "universal").unwrap()).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([a.clone(), b.clone(), c.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new(world, kura, handle.clone());
        let state_view = state.view();
        // Pagination: offset 1, limit 1, no sorting
        let params = QueryParams {
            pagination: Pagination::new(Some(nonzero_ext::nonzero!(1_u64)), 1),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        // Build erased iterable FindDomains query
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let erased =
            iroha_data_model::query::ErasedIterQuery::<iroha_data_model::domain::Domain>::new(
                iroha_data_model::query::dsl::CompoundPredicate::PASS,
                SelectorTuple::default(),
                payload,
            );
        let qbox: iroha_data_model::query::QueryBox<iroha_data_model::query::QueryOutputBatchBox> =
            Box::new(erased);
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first) =
            validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch, remaining, cursor) = first.into_parts();
        let mut tuple_iter = batch.into_iter();
        let v = match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, b.id);
        assert_eq!(remaining, 0);
        assert!(cursor.is_none());
    }
    #[tokio::test]
    async fn iter_dispatch_offset_and_fetch_size_interplay() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use iroha_futures::supervisor::ShutdownSignal;
        // World with ordered domains a,b,c,d
        let a: Domain = Domain::new(DomainId::try_new("a", "universal").unwrap()).build(&ALICE_ID);
        let b: Domain = Domain::new(DomainId::try_new("b", "universal").unwrap()).build(&ALICE_ID);
        let c: Domain = Domain::new(DomainId::try_new("c", "universal").unwrap()).build(&ALICE_ID);
        let d: Domain = Domain::new(DomainId::try_new("d", "universal").unwrap()).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([a.clone(), b.clone(), c.clone(), d.clone()], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new(world, kura, handle.clone());
        let state_view = state.view();
        // Pagination: offset 1, limit 3; fetch_size 2
        let params = QueryParams {
            pagination: Pagination::new(Some(nonzero_ext::nonzero!(3_u64)), 1),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero_ext::nonzero!(2_u64))),
        };
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
        let qbox: iroha_data_model::query::QueryBox<_> =
            Box::new(iroha_data_model::query::ErasedIterQuery::<Domain>::new(
                iroha_data_model::query::dsl::CompoundPredicate::<Domain>::PASS,
                SelectorTuple::<Domain>::default(),
                payload,
            ));
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first) =
            validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch, remaining, cursor) = first.into_parts();
        let mut tuple_iter = batch.into_iter();
        let v = match tuple_iter.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2); // fetch_size=2
        assert_eq!(v[0].id, b.id); // offset skips 'a'
        assert_eq!(v[1].id, c.id);
        assert_eq!(remaining, 1); // one more item within limit
        assert!(cursor.is_some());
        // Next batch should contain the last within limit: 'd'
        let next = handle
            .handle_iter_continue(cursor.unwrap(), &ALICE_ID)
            .unwrap();
        let (batch2, remaining2, cursor2) = next.into_parts();
        let mut tuple_iter2 = batch2.into_iter();
        let v2 = match tuple_iter2.next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].id, d.id);
        assert_eq!(remaining2, 0);
        assert!(cursor2.is_none());
    }
    #[tokio::test]
    async fn iter_dispatch_accounts_and_asset_definitions() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::{
            account::Account,
            asset::definition::AssetDefinition,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use iroha_futures::supervisor::ShutdownSignal;
        // Build world with two accounts and two asset definitions
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let acc1_id = ALICE_ID.clone();
        let (acc2_id, _) = iroha_test_samples::gen_account_in("w");
        let acc1 = Account::new(acc1_id.clone()).build(&ALICE_ID);
        let acc2 = Account::new(acc2_id.clone()).build(&ALICE_ID);
        let ad1 = AssetDefinition::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            "rose".to_owned(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let ad2 = AssetDefinition::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                "tulip".parse().unwrap(),
            ),
            "tulip".to_owned(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let world = World::with(
            [domain],
            [acc1.clone(), acc2.clone()],
            [ad1.clone(), ad2.clone()],
        );
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new(with_global_reader(world, &ALICE_ID), kura, handle.clone());
        let state_view = state.view();
        // Accounts: default params
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        let payload_acc =
            norito::codec::Encode::encode(&iroha_data_model::query::account::prelude::FindAccounts);
        let qbox_acc: iroha_data_model::query::QueryBox<_> =
            Box::new(iroha_data_model::query::ErasedIterQuery::<Account>::new(
                iroha_data_model::query::dsl::CompoundPredicate::<Account>::PASS,
                SelectorTuple::<Account>::default(),
                payload_acc,
            ));
        let qwp_acc = iroha_data_model::query::QueryWithParams::new(&qbox_acc, params.clone())
            .expect("account query type has a canonical mapping");
        let request_acc = QueryRequest::Start(qwp_acc);
        let validated_acc = ValidQueryRequest::validate_for_client_parts(
            request_acc,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first_acc) = validated_acc
            .execute(&handle, &state_view, &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch_acc, _rem_acc, _cur_acc) = first_acc.into_parts();
        let v_acc = match batch_acc.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Account(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v_acc.len(), 2);
        // AssetDefinitions: default params
        let payload_ad = norito::codec::Encode::encode(
            &iroha_data_model::query::asset::prelude::FindAssetDefinitions,
        );
        let qbox_ad: iroha_data_model::query::QueryBox<_> = Box::new(
            iroha_data_model::query::ErasedIterQuery::<AssetDefinition>::new(
                iroha_data_model::query::dsl::CompoundPredicate::<AssetDefinition>::PASS,
                SelectorTuple::<AssetDefinition>::default(),
                payload_ad,
            ),
        );
        let qwp_ad = iroha_data_model::query::QueryWithParams::new(&qbox_ad, params)
            .expect("asset-definition query type has a canonical mapping");
        let request_ad = QueryRequest::Start(qwp_ad);
        let validated_ad = ValidQueryRequest::validate_for_client_parts(
            request_ad,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first_ad) = validated_ad
            .execute(&handle, &state_view, &ALICE_ID)
            .unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch_ad, _rem_ad, _cur_ad) = first_ad.into_parts();
        let v_ad = match batch_ad.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v_ad.len(), 2);
    }
    #[derive(Clone, Copy)]
    enum IterDispatchRankFixture {
        Sparse,
        Dense,
    }

    struct IterDispatchRankSortCase {
        fixture: IterDispatchRankFixture,
        order: SortOrder,
        offset: u64,
        limit: Option<NonZeroU64>,
        fetch_size: Option<NonZeroU64>,
        expected_pages: &'static [&'static [usize]],
    }

    fn ranked_account(id: &AccountId, rank: Option<u32>) -> Account {
        let account = Account::new(id.clone());
        let Some(rank) = rank else {
            return account.build(id);
        };
        account
            .with_metadata({
                let mut metadata = Metadata::default();
                metadata.insert(
                    "rank".parse().unwrap(),
                    iroha_primitives::json::Json::from(norito::json!(rank)),
                );
                metadata
            })
            .build(id)
    }

    fn ranked_account_fixture(fixture: IterDispatchRankFixture) -> (World, [AccountId; 3]) {
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let account_ids = [
            ALICE_ID.clone(),
            iroha_test_samples::gen_account_in("w").0,
            iroha_test_samples::gen_account_in("w").0,
        ];
        let ranks = match fixture {
            IterDispatchRankFixture::Sparse => [Some(2), Some(1), None],
            IterDispatchRankFixture::Dense => [Some(0), Some(1), Some(2)],
        };
        let first = ranked_account(&account_ids[0], ranks[0]);
        let second = ranked_account(&account_ids[1], ranks[1]);
        let third = ranked_account(&account_ids[2], ranks[2]);
        (
            with_global_reader(World::with([domain], [first, second, third], []), &ALICE_ID),
            account_ids,
        )
    }

    fn ranked_asset_definition(name: &str, rank: Option<u32>) -> AssetDefinition {
        let mut definition = AssetDefinition::numeric(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("w", "universal").unwrap(),
                name.parse().unwrap(),
            ),
            name.to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let Some(rank) = rank else {
            return definition;
        };
        definition.metadata_mut().insert(
            "rank".parse().unwrap(),
            iroha_primitives::json::Json::from(norito::json!(rank)),
        );
        definition
    }

    fn ranked_asset_definition_fixture(
        fixture: IterDispatchRankFixture,
    ) -> (World, [iroha_data_model::asset::AssetDefinitionId; 3]) {
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let (names, ranks) = match fixture {
            IterDispatchRankFixture::Sparse => {
                (["rose", "tulip", "peony"], [Some(1), Some(2), None])
            }
            IterDispatchRankFixture::Dense => (["a0", "a1", "a2"], [Some(0), Some(1), Some(2)]),
        };
        let first = ranked_asset_definition(names[0], ranks[0]);
        let second = ranked_asset_definition(names[1], ranks[1]);
        let third = ranked_asset_definition(names[2], ranks[2]);
        let ids = [first.id().clone(), second.id().clone(), third.id().clone()];
        (
            with_global_reader(
                World::with([domain], [account], [first, second, third]),
                &ALICE_ID,
            ),
            ids,
        )
    }

    macro_rules! define_iter_dispatch_rank_sort_runner {
        ($runner:ident, $item:ty, $fixture:ident, $query:expr, $variant:ident) => {
            async fn $runner(case: IterDispatchRankSortCase) {
                use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
                use iroha_data_model::query::parameters::{
                    FetchSize, Pagination, QueryParams, Sorting,
                };
                use iroha_futures::supervisor::ShutdownSignal;

                let IterDispatchRankSortCase {
                    fixture,
                    order,
                    offset,
                    limit,
                    fetch_size,
                    expected_pages,
                } = case;
                let (world, ids) = $fixture(fixture);
                let kura = Kura::blank_kura_for_testing();
                let store = std::sync::Arc::new(LiveQueryStore::from_config(
                    StoreCfg::default(),
                    ShutdownSignal::new(),
                ));
                let handle = crate::query::store::LiveQueryStoreHandle::new(store);
                let state = State::new(world, kura, handle.clone());
                let state_view = state.view();
                let params = QueryParams {
                    pagination: Pagination::new(limit, offset),
                    sorting: Sorting {
                        sort_by_metadata_key: Some("rank".parse().unwrap()),
                        order: Some(order),
                    },
                    fetch_size: FetchSize::new(fetch_size),
                };
                let payload = norito::codec::Encode::encode(&$query);
                let query: iroha_data_model::query::QueryBox<_> =
                    Box::new(iroha_data_model::query::ErasedIterQuery::<$item>::new(
                        iroha_data_model::query::dsl::CompoundPredicate::<$item>::PASS,
                        SelectorTuple::<$item>::default(),
                        payload,
                    ));
                let request = QueryRequest::Start(
                    iroha_data_model::query::QueryWithParams::new(&query, params)
                        .expect("macro query type has a canonical mapping"),
                );
                let validated = ValidQueryRequest::validate_for_client_parts(
                    request,
                    &ALICE_ID,
                    &state_view,
                    QueryLimits::default(),
                )
                .unwrap();
                let QueryResponse::Iterable(first) =
                    validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
                else {
                    panic!("expected iterable")
                };
                let mut output = Some(first);
                let assert_progress = expected_pages.len() > 1;
                for (page_index, expected_indices) in expected_pages.iter().enumerate() {
                    let (batch, remaining, cursor) =
                        output.take().expect("expected query page").into_parts();
                    let values = match batch.into_iter().next().expect("slice") {
                        iroha_data_model::query::QueryOutputBatchBox::$variant(values) => values,
                        other => panic!("unexpected batch variant: {other:?}"),
                    };
                    assert_eq!(values.len(), expected_indices.len());
                    for (value, expected_position) in values.iter().zip(expected_indices.iter()) {
                        assert_eq!(value.id(), &ids[*expected_position]);
                    }
                    let has_next_page = page_index + 1 < expected_pages.len();
                    if assert_progress {
                        let mut expected_remaining = 0_u64;
                        for page in &expected_pages[page_index + 1..] {
                            let page_len =
                                u64::try_from(page.len()).expect("expected page length fits u64");
                            expected_remaining = expected_remaining
                                .checked_add(page_len)
                                .expect("expected remaining count fits u64");
                        }
                        assert_eq!(remaining, expected_remaining);
                        assert_eq!(cursor.is_some(), has_next_page);
                    }
                    if has_next_page {
                        output = Some(
                            handle
                                .handle_iter_continue(cursor.expect("should continue"), &ALICE_ID)
                                .unwrap(),
                        );
                    }
                }
            }
        };
    }

    define_iter_dispatch_rank_sort_runner!(
        run_account_rank_sort_case,
        Account,
        ranked_account_fixture,
        iroha_data_model::query::account::prelude::FindAccounts,
        Account
    );
    define_iter_dispatch_rank_sort_runner!(
        run_asset_definition_rank_sort_case,
        AssetDefinition,
        ranked_asset_definition_fixture,
        iroha_data_model::query::asset::prelude::FindAssetDefinitions,
        AssetDefinition
    );

    macro_rules! iter_dispatch_rank_sort_test {
        (
            $name:ident,
            $runner:ident,
            $fixture:ident,
            $order:ident,
            $offset:expr,
            $limit:expr,
            $fetch_size:expr,
            $expected_pages:expr
        ) => {
            #[tokio::test]
            async fn $name() {
                $runner(IterDispatchRankSortCase {
                    fixture: IterDispatchRankFixture::$fixture,
                    order: SortOrder::$order,
                    offset: $offset,
                    limit: $limit,
                    fetch_size: $fetch_size,
                    expected_pages: $expected_pages,
                })
                .await;
            }
        };
    }

    iter_dispatch_rank_sort_test!(
        iter_dispatch_accounts_sort_desc_end_to_end,
        run_account_rank_sort_case,
        Sparse,
        Desc,
        0,
        None,
        None,
        &[&[0, 1, 2]]
    );
    #[tokio::test]
    async fn iter_dispatch_accounts_sort_ties_stable_by_id() {
        use iroha_data_model::query::parameters::{
            FetchSize, Pagination, QueryParams, SortOrder, Sorting,
        };
        use iroha_primitives::json::Json;
        // Prepare three accounts with identical sortable metadata key "rank"
        let (a_id, _) = iroha_test_samples::gen_account_in("w");
        let (b_id, _) = iroha_test_samples::gen_account_in("w");
        let (c_id, _) = iroha_test_samples::gen_account_in("w");
        let make = |id: &AccountId| {
            Account::new(id.clone())
                .with_metadata({
                    let mut m = Metadata::default();
                    m.insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
                    m
                })
                .build(id)
        };
        let a = make(&a_id);
        let b = make(&b_id);
        let c = make(&c_id);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting {
                sort_by_metadata_key: Some("rank".parse().unwrap()),
                order: Some(SortOrder::Asc),
            },
            fetch_size: FetchSize::default(),
        };
        let selector = SelectorTuple::<Account>::default();
        // Run postprocessing on a local iterator; fetch_size=nonzero!(10)
        let mut it = apply_query_postprocessing(
            vec![a, b, c].into_iter(),
            selector,
            &params,
            QueryLimits::default(),
        )
        .expect("postprocess");
        let (batch, next) = it.next_batch(0).expect("first batch");
        assert!(next.is_none());
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Account(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 3);
        let mut ids = [a_id.clone(), b_id.clone(), c_id.clone()];
        ids.sort();
        assert_eq!(v[0].id(), &ids[0]);
        assert_eq!(v[1].id(), &ids[1]);
        assert_eq!(v[2].id(), &ids[2]);
    }
    #[tokio::test]
    async fn iter_dispatch_asset_definitions_sort_ties_stable_by_id() {
        use iroha_data_model::query::parameters::{
            FetchSize, Pagination, QueryParams, SortOrder, Sorting,
        };
        use iroha_primitives::json::Json;
        let make = |name: &str| {
            AssetDefinition::numeric(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("w", "universal").unwrap(),
                    name.parse().unwrap(),
                ),
                name.to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .with_metadata({
                let mut metadata = Metadata::default();
                metadata.insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
                metadata
            })
            .build(&ALICE_ID)
        };
        let ad_a = make("rose");
        let ad_b = make("tulip");
        let ad_c = make("peony");
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting {
                sort_by_metadata_key: Some("rank".parse().unwrap()),
                order: Some(SortOrder::Asc),
            },
            fetch_size: FetchSize::default(),
        };
        let selector = SelectorTuple::<AssetDefinition>::default();
        let mut it = apply_query_postprocessing(
            vec![ad_a.clone(), ad_b.clone(), ad_c.clone()].into_iter(),
            selector,
            &params,
            QueryLimits::default(),
        )
        .expect("postprocess");
        let (batch, next) = it.next_batch(0).expect("first batch");
        assert!(next.is_none());
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 3);
        let mut ids = [ad_a.id().clone(), ad_b.id().clone(), ad_c.id().clone()];
        ids.sort();
        assert_eq!(v[0].id(), &ids[0]);
        assert_eq!(v[1].id(), &ids[1]);
        assert_eq!(v[2].id(), &ids[2]);
    }
    iter_dispatch_rank_sort_test!(
        iter_dispatch_asset_definitions_sort_desc,
        run_asset_definition_rank_sort_case,
        Sparse,
        Desc,
        0,
        None,
        None,
        &[&[1, 0, 2]]
    );
    #[tokio::test]
    async fn iter_dispatch_find_triggers_full() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::{
            events::time::{ExecutionTime, TimeEventFilter},
            prelude::*,
            query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use iroha_futures::supervisor::ShutdownSignal;
        let domain = Domain::new(DomainId::try_new("w", "universal").unwrap()).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([domain], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new(with_global_reader(world, &ALICE_ID), kura, handle.clone());
        // Insert two time triggers
        {
            let mut block = state.world.triggers.block();
            let mut tx = block.transaction();
            let exec = [Log::new(iroha_logger::Level::INFO, "x".into())];
            let filter = TimeEventFilter::new(ExecutionTime::PreCommit);
            let action = Action::new(exec, Repeats::Indefinitely, ALICE_ID.clone(), filter)
                .expect("trigger action fixture satisfies validation invariants");
            let t1 = Trigger::new("t1".parse().unwrap(), action.clone())
                .try_into()
                .unwrap();
            let t2 = Trigger::new(
                "t2".parse().unwrap(),
                action.with_metadata(Metadata::default()),
            )
            .try_into()
            .unwrap();
            tx.add_time_trigger(t1).unwrap();
            tx.add_time_trigger(t2).unwrap();
            tx.apply();
            block.commit();
        }
        let state_view = state.view();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::trigger::prelude::FindTriggers);
        let qbox: iroha_data_model::query::QueryBox<_> =
            Box::new(iroha_data_model::query::ErasedIterQuery::<Trigger>::new(
                iroha_data_model::query::dsl::CompoundPredicate::<Trigger>::PASS,
                SelectorTuple::<Trigger>::default(),
                payload,
            ));
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .unwrap();
        let QueryResponse::Iterable(first) =
            validated.execute(&handle, &state_view, &ALICE_ID).unwrap()
        else {
            panic!("expected iterable")
        };
        let (batch, _rem, _cur) = first.into_parts();
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Trigger(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert_eq!(v.len(), 2);
        let ids: std::collections::BTreeSet<_> = v.iter().map(|t| t.id().clone()).collect();
        assert!(ids.contains(&"t1".parse().unwrap()));
        assert!(ids.contains(&"t2".parse().unwrap()));
        // Basic field assertions on the fetched triggers
        for tr in v {
            match tr.action().filter() {
                iroha_data_model::events::EventFilterBox::Time(_) => {}
                other => panic!("unexpected filter: {other:?}"),
            }
        }
    }
    #[tokio::test]
    async fn find_all_blocks() -> Result<()> {
        let num_blocks = 100;
        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let blocks = ValidQuery::execute(FindBlocks, CompoundPredicate::PASS, &state.view())?
            .collect::<Vec<_>>();
        assert_eq!(blocks.len() as u64, num_blocks);
        assert!(
            blocks
                .windows(2)
                .all(|wnd| wnd[0].header() >= wnd[1].header())
        );
        Ok(())
    }
    #[tokio::test]
    async fn find_all_block_headers() -> Result<()> {
        let num_blocks = 100;
        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let block_headers =
            ValidQuery::execute(FindBlockHeaders, CompoundPredicate::PASS, &state.view())?
                .collect::<Vec<_>>();
        assert_eq!(block_headers.len() as u64, num_blocks);
        assert!(block_headers.windows(2).all(|wnd| wnd[0] >= wnd[1]));
        Ok(())
    }
    include!("query/canonical_history_tests.rs");
    #[tokio::test]
    async fn find_blocks_and_headers_by_height() -> Result<()> {
        let state = state_with_test_blocks_and_transactions(10, 1, 1)?;
        let state_view = state.view();
        let blocks = ValidQuery::execute(
            FindBlocks,
            CompoundPredicate::<iroha_data_model::block::SignedBlock>::build(|p| {
                p.equals("height", 4_u64)
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].header().height().get(), 4);
        let target_hash = blocks[0].hash();
        let header_by_hash = ValidQuery::execute(
            FindBlockHeaders,
            CompoundPredicate::<iroha_data_model::block::BlockHeader>::build(|p| {
                p.equals("hash", target_hash)
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert_eq!(header_by_hash.len(), 1);
        assert_eq!(header_by_hash[0].height().get(), 4);
        let headers = ValidQuery::execute(
            FindBlockHeaders,
            CompoundPredicate::<iroha_data_model::block::BlockHeader>::build(|p| {
                p.in_values("height", [2_u64, 7_u64, 3_u64])
            }),
            &state_view,
        )?
        .map(|header| header.height().get())
        .collect::<Vec<_>>();
        assert_eq!(headers, vec![7, 3, 2]);
        let mut missing = ValidQuery::execute(
            FindBlockHeaders,
            CompoundPredicate::<iroha_data_model::block::BlockHeader>::build(|p| {
                p.equals("height", 42_u64)
            }),
            &state_view,
        )?;
        assert!(missing.next().is_none());
        Ok(())
    }
    #[tokio::test]
    async fn start_iterable_query_for_domains() -> Result<()> {
        use iroha_data_model::query::{
            ErasedIterQuery, QueryBox, QueryOutputBatchBox, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::QueryParams,
        };
        // Build a small state with a domain and account
        let state = state_with_test_blocks_and_transactions(1, 1, 0)?;
        let state_view = state.view();
        let query_handle = LiveQueryStore::start_test();
        // Build an erased iterable query over domains with a pass predicate and empty selector
        // Build an erased query with preserved payload for dispatch
        let payload = norito::codec::Encode::encode(&FindDomains);
        let erased: ErasedIterQuery<iroha_data_model::domain::Domain> =
            ErasedIterQuery::new(CompoundPredicate::PASS, SelectorTuple::default(), payload);
        let boxed: QueryBox<QueryOutputBatchBox> = Box::new(erased);
        let iter_query = QueryWithParams::new(&boxed, QueryParams::default())
            .expect("domain query type has a canonical mapping");
        let request = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(iter_query),
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )?;
        let response = request.execute(&query_handle, &state_view, &ALICE_ID)?;
        match response {
            QueryResponse::Iterable(output) => {
                // Should produce a batch and optionally a cursor
                let (_batch, _rem, _cursor) = output.into_parts();
            }
            _ => panic!("expected iterable response"),
        }
        Ok(())
    }
    #[tokio::test]
    async fn iterable_sorting_by_metadata_desc() -> Result<()> {
        use iroha_data_model::query::{
            QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::{QueryParams, Sorting},
        };
        // Build a state and add two domains with comparable metadata
        let kura = Kura::blank_kura_for_testing();
        let world = with_global_reader(
            World::with(
                [
                    Domain::new(DomainId::try_new("wonderland", "universal").unwrap())
                        .build(&ALICE_ID),
                ],
                [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
                [],
            ),
            &ALICE_ID,
        );
        let state = State::new(world, kura.clone(), LiveQueryStore::start_test());
        let parent_block = state
            .view()
            .latest_block()
            .expect("completed original State read");
        let unverified_block =
            BlockBuilder::new(vec![dummy_accepted_transaction(state.network_id)])
                .chain(0, parent_block.as_deref())
                .sign(ALICE_KEYPAIR.private_key())
                .unpack(|_| {});
        // Execution and autoscale samples belong to this exact block header.
        let mut state_block = state.block(unverified_block.header());
        let mut state_tx = state_block.transaction();
        // Register a second domain
        let alpha_id = DomainId::try_new("alpha", "universal").expect("valid");
        Register::domain(Domain::new(alpha_id.clone())).execute(&ALICE_ID, &mut state_tx)?;
        // Set metadata key "rank" on both domains: wonderland=1, alpha=2
        let key = "rank".parse::<Name>().expect("valid");
        SetKeyValue::domain(
            DomainId::try_new("wonderland", "universal").unwrap(),
            key.clone(),
            Json::new(1_u32),
        )
        .execute(&ALICE_ID, &mut state_tx)?;
        SetKeyValue::domain(alpha_id.clone(), key.clone(), Json::new(2_u32))
            .execute(&ALICE_ID, &mut state_tx)?;
        state_tx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        // Build a canonical iterable query over domains with metadata-descending sorting.
        let params = QueryParams {
            sorting: Sorting {
                sort_by_metadata_key: Some(key.clone()),
                order: Some(iroha_data_model::query::parameters::SortOrder::Desc),
            },
            ..Default::default()
        };
        let iter_query = QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::domain::prelude::FindDomains,
            ),
            item: iroha_data_model::query::QueryItemKind::Domain,
            predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Domain>::PASS),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Domain>::default()),
            params,
        };
        let req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(iter_query),
            &ALICE_ID,
            &state.view(),
            QueryLimits::default(),
        )?;
        let resp = req.execute(&LiveQueryStore::start_test(), &state.view(), &ALICE_ID)?;
        let QueryResponse::Iterable(output) = resp else {
            panic!("expected iterable response")
        };
        let (batch, remaining, cursor) = output.into_parts();
        let mut columns = batch.into_iter();
        let domains = match columns.next().expect("domain result column") {
            iroha_data_model::query::QueryOutputBatchBox::Domain(domains) => domains,
            other => panic!("expected domains, got {other:?}"),
        };
        assert!(columns.next().is_none());
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].id, alpha_id);
        assert_eq!(
            domains[1].id,
            DomainId::try_new("wonderland", "universal").expect("valid")
        );
        assert_eq!(remaining, 0);
        assert!(cursor.is_none());
        Ok(())
    }
    #[tokio::test]
    async fn iter_dispatch_assets_non_empty_and_contains_minted() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::parameters::{FetchSize, Pagination, QueryParams, Sorting};
        use iroha_futures::supervisor::ShutdownSignal;
        // World with a domain, ALICE account, one asset definition, and a minted asset
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let ad_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::new(ad_id.clone(), ALICE_ID.clone());
        let world = World::default();
        // Build state and register domain/account/asset def; then mint
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new(world, kura, handle.clone());
        let header = ValidBlock::new_dummy(ALICE_KEYPAIR.private_key())
            .as_ref()
            .header();
        let mut sblock = state.block(header);
        let mut stx = sblock.transaction();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register domain");
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register account");
        Register::asset_definition(AssetDefinition::numeric(
            ad_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("register asset definition");
        Mint::asset_quantity(13_u32, asset_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("mint asset");
        Grant::account_permission(
            Permission::from(iroha_executor_data_model::permission::query::CanReadAllLedgerData),
            ALICE_ID.clone(),
        )
        .execute(&ALICE_ID, &mut stx)
        .expect("grant authenticated query reader");
        stx.apply();
        let _ = sblock.commit_world_overlay_for_testing();
        let state_view = state.view();
        // Default params
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        // Build erased iterable FindAssets query
        let payload =
            norito::codec::Encode::encode(&iroha_data_model::query::asset::prelude::FindAssets);
        let qbox: iroha_data_model::query::QueryBox<_> =
            Box::new(iroha_data_model::query::ErasedIterQuery::<Asset>::new(
                iroha_data_model::query::dsl::CompoundPredicate::<Asset>::PASS,
                SelectorTuple::<Asset>::default(),
                payload,
            ));
        let qwp = iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("test query type has a canonical mapping");
        let request = QueryRequest::Start(qwp);
        let validated = ValidQueryRequest::validate_for_client_parts(
            request,
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .expect("validate");
        let QueryResponse::Iterable(first) = validated
            .execute(&handle, &state_view, &ALICE_ID)
            .expect("execute")
        else {
            panic!("expected iterable")
        };
        let (batch, _rem, _cur) = first.into_parts();
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Asset(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        assert!(!v.is_empty(), "expected at least one asset");
        let rose = v
            .iter()
            .find(|a| a.id() == &asset_id)
            .expect("minted asset not found");
        assert_eq!(*rose.value(), Quantity::from(13_u32));
    }
    #[tokio::test]
    async fn canonical_iter_accounts_with_asset_uses_payload() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::{
            QueryItemKind, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::{FetchSize, Pagination, QueryParams, Sorting},
        };
        use iroha_futures::supervisor::ShutdownSignal;
        // World with a domain, two accounts, one asset definition, and a minted asset to one account
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let acc1_id = ALICE_ID.clone();
        let (acc2_id, _) = iroha_test_samples::gen_account_in("wonderland");
        let ad_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::new(ad_id.clone(), acc1_id.clone());
        let kura = Kura::blank_kura_for_testing();
        let store = std::sync::Arc::new(LiveQueryStore::from_config(
            StoreCfg::default(),
            ShutdownSignal::new(),
        ));
        let handle = crate::query::store::LiveQueryStoreHandle::new(store);
        let state = State::new(World::default(), kura, handle.clone());
        let header = ValidBlock::new_dummy(ALICE_KEYPAIR.private_key())
            .as_ref()
            .header();
        let mut sblock = state.block(header);
        let mut stx = sblock.transaction();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register domain");
        Register::account(Account::new(acc1_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register account1");
        Register::account(Account::new(acc2_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register account2");
        Register::asset_definition(AssetDefinition::numeric(
            ad_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("register asset definition");
        Mint::asset_quantity(1_u32, asset_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("mint asset");
        Grant::account_permission(
            Permission::from(iroha_executor_data_model::permission::query::CanReadAllLedgerData),
            ALICE_ID.clone(),
        )
        .execute(&ALICE_ID, &mut stx)
        .expect("grant authenticated query reader");
        stx.apply();
        let _ = sblock.commit_world_overlay_for_testing();
        let state_view = state.view();
        // Canonical iterable-query bundle: Accounts + payload FindAccountsWithAsset.
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::default(),
        };
        let query_payload = norito::codec::Encode::encode(
            &iroha_data_model::query::account::prelude::FindAccountsWithAsset::new(ad_id.clone()),
        );
        let iter_query = QueryWithParams {
            query: (),
            query_payload,
            item: QueryItemKind::Account,
            predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Account>::PASS),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Account>::default()),
            params,
        };
        let validated = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(iter_query),
            &ALICE_ID,
            &state_view,
            QueryLimits::default(),
        )
        .expect("validate");
        let QueryResponse::Iterable(first) = validated
            .execute(&handle, &state_view, &ALICE_ID)
            .expect("execute")
        else {
            panic!("expected iterable")
        };
        let (batch, _rem, _cur) = first.into_parts();
        let v = match batch.into_iter().next().expect("slice") {
            iroha_data_model::query::QueryOutputBatchBox::Account(v) => v,
            other => panic!("unexpected batch variant: {other:?}"),
        };
        // Should only include account that holds the specified asset
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id(), &acc1_id);
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn iter_dispatch_accounts_with_asset_parity_and_continue() {
        use iroha_config::parameters::actual::LiveQueryStore as StoreCfg;
        use iroha_data_model::query::{
            QueryBox, QueryItemKind, QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryRequest,
            QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::{FetchSize, QueryParams, Sorting},
        };
        use iroha_futures::supervisor::ShutdownSignal;
        use std::collections::BTreeSet;
        fn build_state_with_holdings() -> (
            State,
            crate::query::store::LiveQueryStoreHandle,
            AssetDefinitionId,
        ) {
            let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            let ad_id: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "rose".parse().unwrap(),
                );
            let kura = Kura::blank_kura_for_testing();
            let store = std::sync::Arc::new(LiveQueryStore::from_config(
                StoreCfg::default(),
                ShutdownSignal::new(),
            ));
            let handle = crate::query::store::LiveQueryStoreHandle::new(store);
            let state = State::new(World::default(), kura, handle.clone());
            let header = ValidBlock::new_dummy(ALICE_KEYPAIR.private_key())
                .as_ref()
                .header();
            let mut sblock = state.block(header);
            let mut stx = sblock.transaction();
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register domain");
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register ALICE");
            Register::account(Account::new(BOB_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register BOB");
            Register::asset_definition(AssetDefinition::numeric(
                ad_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))
            .execute(&ALICE_ID, &mut stx)
            .expect("register asset definition");
            Mint::asset_quantity(5_u32, AssetId::new(ad_id.clone(), ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("mint asset for ALICE");
            Mint::asset_quantity(7_u32, AssetId::new(ad_id.clone(), BOB_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("mint asset for BOB");
            Grant::account_permission(
                Permission::from(
                    iroha_executor_data_model::permission::query::CanReadAllLedgerData,
                ),
                ALICE_ID.clone(),
            )
            .execute(&ALICE_ID, &mut stx)
            .expect("grant authenticated query reader");
            stx.apply();
            let _ = sblock.commit_world_overlay_for_testing();
            (state, handle, ad_id)
        }
        fn drain_accounts(
            first_batch: iroha_data_model::query::QueryOutput,
            handle: &crate::query::store::LiveQueryStoreHandle,
        ) -> Vec<AccountId> {
            fn to_ids(batch: QueryOutputBatchBoxTuple) -> Vec<AccountId> {
                let mut iter = batch.into_iter();
                let accounts = match iter.next().expect("single tuple element") {
                    QueryOutputBatchBox::Account(v) => v,
                    other => panic!("unexpected batch variant: {other:?}"),
                };
                accounts.into_iter().map(|acc| acc.id().clone()).collect()
            }
            let (batch, _remaining, mut cursor) = first_batch.into_parts();
            let mut ids = to_ids(batch);
            while let Some(c) = cursor {
                let next = handle
                    .handle_iter_continue(c, &ALICE_ID)
                    .expect("continue cursor");
                let (next_batch, _next_remaining, next_cursor) = next.into_parts();
                ids.extend(to_ids(next_batch));
                cursor = next_cursor;
            }
            ids
        }
        let params = QueryParams {
            sorting: Sorting::default(),
            pagination: Pagination::default(),
            fetch_size: FetchSize {
                fetch_size: Some(nonzero!(1_u64)),
            },
        };
        // Erased QueryBox path with encoded FindAccountsWithAsset payload.
        let (state_boxed, handle_boxed, ad_id) = build_state_with_holdings();
        let payload = norito::codec::Encode::encode(
            &iroha_data_model::query::account::prelude::FindAccountsWithAsset::new(ad_id.clone()),
        );
        let qbox: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<Account>::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            payload,
        ));
        let boxed_qwp = QueryWithParams::new(&qbox, params.clone())
            .expect("test query type has a canonical mapping");
        let boxed_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(boxed_qwp),
            &ALICE_ID,
            &state_boxed.view(),
            QueryLimits::default(),
        )
        .expect("validate boxed");
        let QueryResponse::Iterable(first_boxed) = boxed_req
            .execute(&handle_boxed, &state_boxed.view(), &ALICE_ID)
            .expect("execute boxed")
        else {
            panic!("expected iterable response");
        };
        let boxed_accounts = drain_accounts(first_boxed, &handle_boxed);
        // Canonical bundle using predicate/selector bytes and payload.
        let (state_fast, handle_fast, ad_id_fast) = build_state_with_holdings();
        let iter_query = QueryWithParams {
            query: (),
            query_payload: norito::codec::Encode::encode(
                &iroha_data_model::query::account::prelude::FindAccountsWithAsset::new(
                    ad_id_fast.clone(),
                ),
            ),
            item: QueryItemKind::Account,
            predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Account>::PASS),
            selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Account>::default()),
            params,
        };
        let fast_req = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Start(iter_query),
            &ALICE_ID,
            &state_fast.view(),
            QueryLimits::default(),
        )
        .expect("validate fast");
        let QueryResponse::Iterable(first_fast) = fast_req
            .execute(&handle_fast, &state_fast.view(), &ALICE_ID)
            .expect("execute fast")
        else {
            panic!("expected iterable response");
        };
        let fast_accounts = drain_accounts(first_fast, &handle_fast);
        let expected: BTreeSet<_> = [ALICE_ID.clone(), BOB_ID.clone()].into_iter().collect();
        let boxed_set: BTreeSet<_> = boxed_accounts.into_iter().collect();
        let fast_set: BTreeSet<_> = fast_accounts.into_iter().collect();
        assert_eq!(boxed_set, expected);
        assert_eq!(fast_set, expected);
        assert_eq!(boxed_set, fast_set);
    }
    #[tokio::test]
    async fn find_all_transactions() -> Result<()> {
        let num_blocks = 100;
        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let txs = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::PASS,
            &state.view(),
        )?
        .collect::<Vec<_>>();
        let genesis_rows = state
            .view()
            .kura()
            .get_block(nonzero!(1_usize), &state.ivm_execution_budget())
            .expect("completed original State read")
            .unwrap()
            .network_input_hashes()
            .len();
        assert_eq!(
            txs.len(),
            genesis_rows + (usize::try_from(num_blocks).expect("fixture value fits usize") - 1) * 2
        );
        assert_eq!(
            txs.iter().filter(|txn| txn.result().is_err()).count() as u64,
            num_blocks - 1
        );
        Ok(())
    }
    #[test]
    fn find_transactions_bounded_ephemeral_scans_only_the_page_carriers() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state_view = fixture.state.view();
        let query_handle = state_view.query_handle().clone();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(3_u64))),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            limits,
        )
        .expect("validate bounded transaction query");
        state_view.kura().reset_canonical_query_reads_for_test();
        let QueryResponse::Iterable(output) = validated
            .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
            .expect("execute bounded transaction query")
        else {
            panic!("expected iterable transaction output");
        };
        let (batch, remaining_items, has_more, cursor) = output.into_parts_with_count_mode();
        assert_eq!(transactions_from_batch(batch).len(), 3);
        assert_eq!(remaining_items, None);
        assert!(has_more);
        assert!(cursor.is_none());
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            2,
            "three transactions plus the bounded probe touch two two-entry carriers"
        );
    }
    #[test]
    fn find_transactions_bounded_replay_ignores_blocks_appended_after_start() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let mut fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state = Arc::clone(&fixture.state);
        let state_view = state.view();
        let query_handle = state_view.query_handle().clone();
        let expected = crate::smartcontracts::isi::tx::committed_transactions_snapshot(&state_view)
            .expect("bounded replay baseline");
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(3_u64))),
        };
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
        )
        .expect("validate bounded replay query");
        let QueryResponse::Iterable(first) = validated
            .execute_with_replay_state(
                &query_handle,
                &state_view,
                &ALICE_ID,
                Arc::downgrade(&state),
            )
            .expect("start bounded replay query")
        else {
            panic!("expected iterable transaction output");
        };
        let mut collected = transactions_from_batch(first.batch);
        let mut cursor = first.continue_cursor;
        // Durable custody extends through original execution; the captured query anchor stays fixed.
        fixture.store.append_next();
        while let Some(current) = cursor {
            let next = query_handle
                .handle_iter_continue(current, &ALICE_ID)
                .expect("continue bounded replay query");
            collected.extend(transactions_from_batch(next.batch));
            cursor = next.continue_cursor;
        }
        assert_eq!(collected, expected);
    }
    #[test]
    fn find_transactions_exact_ephemeral_counts_without_complete_carrier_snapshot() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        // The signed genesis carries three original Network transactions; the sixteen
        // successors each carry two. Empty-genesis accounting would omit real work.
        assert_eq!(fixture.store.blocks.len(), 17);
        assert_eq!(fixture.store.blocks[0].network_entrypoint_count(), 3);
        assert_eq!(fixture.store.blocks[0].execution_outputs().len(), 3);
        for block in &fixture.store.blocks[1..] {
            assert_eq!(block.network_entrypoint_count(), 2);
            assert_eq!(block.execution_outputs().len(), 2);
        }
        let original_work_units = 3 + 16 * 2;
        let state_view = fixture.state.view();
        let query_handle = state_view.query_handle().clone();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(3_u64))),
        };
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params.clone()),
            &ALICE_ID,
            &state_view,
            QueryLimits::default().with_count_mode(QueryCountMode::Exact),
        )
        .expect("validate exact transaction query");
        for refused_units in [32, original_work_units - 1] {
            let rejected = ValidQueryRequest::validate_for_client_parts(
                find_transactions_request(params.clone()),
                &ALICE_ID,
                &state_view,
                QueryLimits::default().with_count_mode(QueryCountMode::Exact),
            )
            .expect("validate exact transaction query")
            .execute_ephemeral_with_stats(
                &query_handle,
                &state_view,
                &ALICE_ID,
                Some(QueryExecutionBudget::from_weighted_limit(
                    refused_units,
                    1,
                    0,
                )),
            )
            .expect_err("every original genesis and successor work unit must be charged");
            assert_eq!(
                crate::execution_attempt::expect_completed_rejection(rejected),
                Error::GasBudgetExceeded
            );
        }
        state_view.kura().reset_canonical_query_reads_for_test();
        let item_budget = QueryExecutionBudget::from_weighted_limit(original_work_units, 1, 0);
        let (QueryResponse::Iterable(output), execution_stats) = validated
            .execute_ephemeral_with_stats(&query_handle, &state_view, &ALICE_ID, Some(item_budget))
            .expect("execute exact transaction query")
        else {
            panic!("expected iterable transaction output");
        };
        let (batch, remaining_items, has_more, cursor) = output.into_parts_with_count_mode();
        assert_eq!(transactions_from_batch(batch).len(), 3);
        assert_eq!(remaining_items, Some(32));
        assert!(has_more);
        assert!(cursor.is_none());
        assert_eq!(execution_stats.processed_items(), original_work_units);
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            17,
            "exact query reads every canonical body, including all three signed genesis inputs"
        );
    }
    #[test]
    fn find_transactions_exact_budget_charges_matches_outside_pagination_window() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state_view = fixture.state.view();
        let query_handle = state_view.query_handle().clone();
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Exact);
        for offset in [0, 31] {
            let params = QueryParams {
                pagination: Pagination::new(Some(nonzero!(1_u64)), offset),
                sorting: Sorting::default(),
                fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            };
            let validated = ValidQueryRequest::validate_for_client_parts(
                find_transactions_request(params),
                &ALICE_ID,
                &state_view,
                limits,
            )
            .expect("validate budgeted exact transaction query");
            let item_budget = QueryExecutionBudget::from_weighted_limit(1, 1, 0);
            let err = validated
                .execute_ephemeral_with_stats(
                    &query_handle,
                    &state_view,
                    &ALICE_ID,
                    Some(item_budget),
                )
                .expect_err("exact full-history scan must exceed a one-item budget");
            assert_eq!(
                crate::execution_attempt::expect_completed_rejection(err),
                Error::GasBudgetExceeded
            );
        }
    }
    #[test]
    fn find_transactions_false_predicate_cannot_force_uncharged_projection() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state_view = fixture.state.view();
        let query_handle = state_view.query_handle().clone();
        let false_filter = CompoundPredicate::<CommittedTransaction>::build(|prototype| {
            prototype.equals("field_that_does_not_exist", true)
        });
        for (count_mode, sorting) in [
            (QueryCountMode::Bounded, Sorting::default()),
            (QueryCountMode::Exact, Sorting::default()),
            (
                QueryCountMode::Bounded,
                Sorting {
                    sort_by_metadata_key: Some("rank".parse().expect("metadata key")),
                    order: Some(SortOrder::Asc),
                },
            ),
            (
                QueryCountMode::Exact,
                Sorting {
                    sort_by_metadata_key: Some("rank".parse().expect("metadata key")),
                    order: Some(SortOrder::Desc),
                },
            ),
        ] {
            let params = QueryParams {
                pagination: Pagination::new(Some(nonzero!(1_u64)), 0),
                sorting,
                fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            };
            let validated = ValidQueryRequest::validate_for_client_parts(
                find_transactions_request_with_filter(params, false_filter.clone()),
                &ALICE_ID,
                &state_view,
                QueryLimits::default().with_count_mode(count_mode),
            )
            .expect("validate false-predicate transaction query");
            crate::smartcontracts::isi::tx::reset_canonical_network_projection_calls_for_test();
            let item_budget = QueryExecutionBudget::from_weighted_limit(1, 1, 0);
            let err = validated
                .execute_ephemeral_with_stats(
                    &query_handle,
                    &state_view,
                    &ALICE_ID,
                    Some(item_budget),
                )
                .expect_err("eager carrier projection must be precharged before proof work");
            assert_eq!(
                crate::execution_attempt::expect_completed_rejection(err),
                Error::GasBudgetExceeded
            );
            assert_eq!(
                crate::smartcontracts::isi::tx::canonical_network_projection_calls_for_test(),
                0,
                "insufficient gas must reject before canonical Network proof reconstruction"
            );
        }
    }
    #[test]
    fn find_transactions_stored_start_precharges_before_false_predicate_or_sorted_projection() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture =
            crate::smartcontracts::isi::tx::tests::canonical_query_fixture_with_query_gas(1);
        let state = Arc::clone(&fixture.state);
        let state_view = state.view();
        let query_handle = state_view.query_handle().clone();
        let false_filter = CompoundPredicate::<CommittedTransaction>::build(|prototype| {
            prototype.equals("field_that_does_not_exist", true)
        });
        for (count_mode, sorting) in [
            (QueryCountMode::Bounded, Sorting::default()),
            (
                QueryCountMode::Exact,
                Sorting {
                    sort_by_metadata_key: Some("rank".parse().expect("metadata key")),
                    order: Some(SortOrder::Desc),
                },
            ),
        ] {
            let params = QueryParams {
                pagination: Pagination::new(Some(nonzero!(1_u64)), 0),
                sorting,
                fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            };
            let validated = ValidQueryRequest::validate_for_client_parts(
                find_transactions_request_with_filter(params, false_filter.clone()),
                &ALICE_ID,
                &state_view,
                QueryLimits::default().with_count_mode(count_mode),
            )
            .expect("validate stored transaction query");
            state_view.kura().reset_canonical_query_reads_for_test();
            crate::smartcontracts::isi::tx::reset_canonical_network_projection_calls_for_test();
            let err = validated
                .execute_with_replay_state_and_start_budget(
                    &query_handle,
                    &state_view,
                    &ALICE_ID,
                    Arc::downgrade(&state),
                    Some(1),
                )
                .expect_err("stored start must enforce its projection budget");
            assert_eq!(err, Error::GasBudgetExceeded);
            assert_eq!(
                crate::smartcontracts::isi::tx::canonical_network_projection_calls_for_test(),
                0,
                "stored start must reject before canonical Network proof reconstruction"
            );
            assert_eq!(
                state_view.kura().canonical_query_reads_for_test().0,
                1,
                "row work is charged after the admitted body read and before proof construction"
            );
        }
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
        };
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
        )
        .expect("validate sufficiently budgeted stored transaction query");
        let QueryResponse::Iterable(output) = validated
            .execute_with_replay_state_and_start_budget(
                &query_handle,
                &state_view,
                &ALICE_ID,
                Arc::downgrade(&state),
                Some(2),
            )
            .expect("client budget above the server minimum covers one carrier")
        else {
            panic!("expected iterable transaction output");
        };
        assert_eq!(
            output
                .continue_cursor
                .expect("stored continuation")
                .gas_budget,
            Some(2),
            "the actual validated Start budget must be carried into the cursor"
        );
    }
    #[test]
    fn find_transactions_stored_continue_precharges_and_underfunded_retry_does_not_advance() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture =
            crate::smartcontracts::isi::tx::tests::canonical_query_fixture_with_query_gas(4);
        // A one-item continuation replays its current two-entry carrier and
        // probes the next two-entry carrier to establish `has_more`.
        let state = Arc::clone(&fixture.state);
        let state_view = state.view();
        let query_handle = state_view.query_handle().clone();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
        };
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
        )
        .expect("validate stored transaction query");
        let QueryResponse::Iterable(first) = validated
            .execute_with_replay_state(
                &query_handle,
                &state_view,
                &ALICE_ID,
                Arc::downgrade(&state),
            )
            .expect("start budgeted stored transaction query")
        else {
            panic!("expected iterable transaction output");
        };
        let original_cursor = first.continue_cursor.expect("stored continuation");
        assert_eq!(original_cursor.gas_budget, Some(4));
        let mut underfunded = original_cursor.clone();
        underfunded.gas_budget = Some(1);
        state_view.kura().reset_canonical_query_reads_for_test();
        crate::smartcontracts::isi::tx::reset_canonical_network_projection_calls_for_test();
        let err = query_handle
            .handle_iter_continue(underfunded, &ALICE_ID)
            .expect_err("continuation must enforce its current request budget");
        assert_eq!(err, Error::GasBudgetExceeded);
        assert_eq!(
            crate::smartcontracts::isi::tx::canonical_network_projection_calls_for_test(),
            0,
            "underfunded continuation must reject before canonical Network proof reconstruction"
        );
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            1,
            "row work is charged after the admitted body read and before proof construction"
        );
        let next = query_handle
            .handle_iter_continue(original_cursor, &ALICE_ID)
            .expect("the same cursor remains retryable with sufficient budget");
        assert_eq!(transactions_from_batch(next.batch).len(), 1);
        assert!(
            crate::smartcontracts::isi::tx::canonical_network_projection_calls_for_test() > 0,
            "successful retry should reconstruct the selected carrier proof"
        );
    }
    #[test]
    fn find_transactions_exact_stored_replay_preserves_count_cursor_and_order() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state = Arc::clone(&fixture.state);
        let state_view = state.view();
        let query_handle = state_view.query_handle().clone();
        let expected = crate::smartcontracts::isi::tx::committed_transactions_snapshot(&state_view)
            .expect("exact transaction baseline");
        assert_eq!(
            fixture.store.blocks[0].network_entrypoint_count(),
            3,
            "signed genesis inputs remain part of exact Network history"
        );
        assert_eq!(
            expected.len(),
            35,
            "three original genesis inputs and sixteen two-input successors"
        );
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(5_u64))),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Exact);
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            limits,
        )
        .expect("validate exact stored transaction query");
        state_view.kura().reset_canonical_query_reads_for_test();
        let QueryResponse::Iterable(first) = validated
            .execute_with_replay_state(
                &query_handle,
                &state_view,
                &ALICE_ID,
                Arc::downgrade(&state),
            )
            .expect("start exact stored transaction query")
        else {
            panic!("expected iterable transaction output");
        };
        assert_eq!(first.remaining_items, Some(30));
        let mut collected = transactions_from_batch(first.batch);
        assert_eq!(collected.len(), 5);
        let mut cursor = first.continue_cursor;
        let mut expected_remaining = 30_u64;
        // Each five-row continuation authenticates from H17 to the carrier of its
        // fifth returned row. The final page includes all three signed genesis rows.
        let mut page_minimum_heights = [13, 10, 8, 5, 3, 1].into_iter();
        let mut expected_body_reads = 17;
        let mut expected_body_bytes = fixture.store.wire_bytes(1..=17);
        while let Some(current) = cursor {
            let next = query_handle
                .handle_iter_continue(current, &ALICE_ID)
                .expect("continue exact transaction query");
            let minimum_height = page_minimum_heights.next().expect("six continuation pages");
            expected_body_reads += 18 - minimum_height;
            expected_body_bytes += fixture.store.wire_bytes(minimum_height..=17);
            assert_eq!(
                state_view.kura().canonical_query_reads_for_test(),
                (expected_body_reads, expected_body_bytes),
                "continuation retains the complete original-tip ancestry cost"
            );
            let page = transactions_from_batch(next.batch);
            assert_eq!(page.len(), 5);
            expected_remaining = expected_remaining
                .saturating_sub(u64::try_from(page.len()).expect("page length fits u64"));
            assert_eq!(next.remaining_items, Some(expected_remaining));
            collected.extend(page);
            cursor = next.continue_cursor;
        }
        assert!(page_minimum_heights.next().is_none());
        assert_eq!(collected, expected);
        assert_eq!(expected_remaining, 0);
        let (body_reads, body_bytes) = state_view.kura().canonical_query_reads_for_test();
        assert_eq!(
            body_reads, 85,
            "each continuation pays for the original tip ancestry before its page carriers"
        );
        assert_eq!(body_bytes, expected_body_bytes);
    }
    #[test]
    fn find_transactions_sorted_prefix_matches_deterministic_full_order_across_pages() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state = Arc::clone(&fixture.state);
        let state_view = state.view();
        let query_handle = state_view.query_handle().clone();
        let mut expected =
            crate::smartcontracts::isi::tx::committed_transactions_snapshot(&state_view)
                .expect("sorted transaction baseline");
        expected.sort_unstable_by(|left, right| left.tiebreak_cmp(right));
        let expected = expected.into_iter().skip(2).take(7).collect::<Vec<_>>();
        let params = QueryParams {
            pagination: Pagination::new(Some(nonzero!(7_u64)), 2),
            sorting: Sorting {
                sort_by_metadata_key: Some("rank".parse().expect("metadata key")),
                order: Some(SortOrder::Asc),
            },
            fetch_size: FetchSize::new(Some(nonzero!(3_u64))),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Exact);
        let ephemeral = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params.clone()),
            &ALICE_ID,
            &state_view,
            limits,
        )
        .expect("validate sorted ephemeral transaction query");
        let QueryResponse::Iterable(first_ephemeral) = ephemeral
            .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
            .expect("execute sorted ephemeral transaction query")
        else {
            panic!("expected sorted iterable transaction output");
        };
        assert_eq!(first_ephemeral.remaining_items, Some(4));
        assert_eq!(
            transactions_from_batch(first_ephemeral.batch),
            expected[..3]
        );
        let stored = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            limits,
        )
        .expect("validate sorted stored transaction query");
        let QueryResponse::Iterable(first) = stored
            .execute_with_replay_state(
                &query_handle,
                &state_view,
                &ALICE_ID,
                Arc::downgrade(&state),
            )
            .expect("start sorted stored transaction query")
        else {
            panic!("expected sorted iterable transaction output");
        };
        let mut collected = transactions_from_batch(first.batch);
        let mut cursor = first.continue_cursor;
        while let Some(current) = cursor {
            let next = query_handle
                .handle_iter_continue(current, &ALICE_ID)
                .expect("continue sorted transaction query");
            collected.extend(transactions_from_batch(next.batch));
            cursor = next.continue_cursor;
        }
        assert_eq!(collected, expected);
    }
    #[test]
    fn find_transactions_exact_replay_fails_closed_on_body_corruption() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let target_height = fixture.target_height;
        let state = Arc::clone(&fixture.state);
        let state_view = state.view();
        let query_handle = state_view.query_handle().clone();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            QueryLimits::default().with_count_mode(QueryCountMode::Exact),
        )
        .expect("validate exact replay corruption query");
        let QueryResponse::Iterable(first) = validated
            .execute_with_replay_state(
                &query_handle,
                &state_view,
                &ALICE_ID,
                Arc::downgrade(&state),
            )
            .expect("start exact replay corruption query")
        else {
            panic!("expected iterable transaction output");
        };
        let mut cursor = first.continue_cursor.expect("exact query continuation");
        let mut corrupted_wire = fixture.store.blocks[target_height.get() - 1]
            .encode_wire()
            .expect("original canonical historical wire");
        *corrupted_wire
            .last_mut()
            .expect("original wire is nonempty") ^= 1;
        let codec_error = iroha_data_model::block::decode_framed_signed_block(&corrupted_wire)
            .expect_err("altered source must fail its canonical frame checksum");
        assert_eq!(
            codec_error.kind(),
            norito::core::DecodeAttemptErrorKind::Invalid
        );
        let codec_error = codec_error.into_error();
        assert!(matches!(codec_error, norito::Error::ChecksumMismatch));
        let expected_error = Error::Conversion(codec_error.to_string());
        fixture.store.corrupt_body(target_height);
        loop {
            match query_handle.handle_iter_continue(cursor, &ALICE_ID) {
                Ok(next) => {
                    cursor = next.continue_cursor.expect(
                        "replay must encounter selected corruption before exhausting the cursor",
                    );
                }
                Err(err) => {
                    assert_eq!(
                        err, expected_error,
                        "continuation must propagate the complete canonical source refusal"
                    );
                    break;
                }
            }
        }
    }
    #[test]
    fn find_transactions_stored_without_replay_rejects_required_continuation() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state_view = fixture.state.view();
        let query_handle = state_view.query_handle().clone();
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let validated = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params.clone()),
            &ALICE_ID,
            &state_view,
            limits,
        )
        .expect("validate stored transaction query");
        let err = validated
            .execute(&query_handle, &state_view, &ALICE_ID)
            .expect_err("borrowed stored execution cannot safely retain a transaction tail");
        assert!(matches!(err, Error::Conversion(message) if message.contains("replay-capable")));
        let terminal_params = QueryParams {
            pagination: Pagination::new(Some(nonzero!(2_u64)), 0),
            ..params
        };
        let terminal = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(terminal_params),
            &ALICE_ID,
            &state_view,
            limits,
        )
        .expect("validate terminal stored transaction query");
        let QueryResponse::Iterable(output) = terminal
            .execute(&query_handle, &state_view, &ALICE_ID)
            .expect("one-page bounded query does not need replay state")
        else {
            panic!("expected iterable transaction output");
        };
        assert_eq!(transactions_from_batch(output.batch).len(), 2);
        assert!(!output.has_more);
        assert!(output.continue_cursor.is_none());
    }
    #[test]
    fn find_transactions_bounded_defers_old_corruption_but_exact_fails() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let mut corrupted_wire = fixture.store.blocks[fixture.unrelated_height.get() - 1]
            .encode_wire()
            .expect("original canonical historical wire");
        *corrupted_wire
            .last_mut()
            .expect("original wire is nonempty") ^= 1;
        let codec_error = iroha_data_model::block::decode_framed_signed_block(&corrupted_wire)
            .expect_err("altered old source must fail its canonical frame checksum");
        assert_eq!(
            codec_error.kind(),
            norito::core::DecodeAttemptErrorKind::Invalid
        );
        let codec_error = codec_error.into_error();
        assert!(matches!(codec_error, norito::Error::ChecksumMismatch));
        let expected_error = Error::Conversion(codec_error.to_string());
        fixture.store.corrupt_body(fixture.unrelated_height);
        let state_view = fixture.state.view();
        let query_handle = state_view.query_handle().clone();
        let params = QueryParams {
            pagination: Pagination::default(),
            sorting: Sorting::default(),
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
        };
        let bounded = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params.clone()),
            &ALICE_ID,
            &state_view,
            QueryLimits::default().with_count_mode(QueryCountMode::Bounded),
        )
        .expect("validate bounded query");
        let QueryResponse::Iterable(output) = bounded
            .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
            .expect("bounded first page avoids corrupt oldest carrier")
        else {
            panic!("expected bounded transaction output");
        };
        assert_eq!(transactions_from_batch(output.batch).len(), 2);
        let exact = ValidQueryRequest::validate_for_client_parts(
            find_transactions_request(params),
            &ALICE_ID,
            &state_view,
            QueryLimits::default().with_count_mode(QueryCountMode::Exact),
        )
        .expect("validate exact query");
        let err = exact
            .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
            .expect_err("exact query must validate corrupt selected history");
        assert_eq!(
            err, expected_error,
            "exact history must propagate the complete canonical source refusal"
        );
    }
    #[test]
    fn find_transactions_rejects_unbounded_or_oversized_sorted_prefix() {
        use iroha_data_model::query::parameters::{FetchSize, Pagination, Sorting};
        let fixture = crate::smartcontracts::isi::tx::tests::canonical_query_fixture();
        let state_view = fixture.state.view();
        let query_handle = state_view.query_handle().clone();
        let sorted = Sorting {
            sort_by_metadata_key: Some("rank".parse().expect("metadata key")),
            order: Some(SortOrder::Asc),
        };
        let limits = QueryLimits::default().with_count_mode(QueryCountMode::Bounded);
        for pagination in [
            Pagination::default(),
            Pagination::new(Some(nonzero!(4_097_u64)), 0),
            Pagination::new(Some(nonzero!(1_u64)), 4_096),
        ] {
            let params = QueryParams {
                pagination,
                sorting: sorted.clone(),
                fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
            };
            let validated = ValidQueryRequest::validate_for_client_parts(
                find_transactions_request(params),
                &ALICE_ID,
                &state_view,
                limits,
            )
            .expect("materialization budget is enforced during execution");
            let err = validated
                .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
                .expect_err("unsafe sorted prefix must be rejected");
            assert_eq!(err, Error::GasBudgetExceeded);
        }
    }
    #[tokio::test]
    async fn find_transactions_by_block_hash_uses_block_index() -> Result<()> {
        let state = state_with_test_blocks_and_transactions(8, 1, 1)?;
        let state_view = state.view();
        let block = state_view
            .kura()
            .get_block(nonzero!(4_usize), &state_view.execution_budget())
            .expect("completed original State read")
            .expect("block available");
        let block_hash = block.hash();
        let txs = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("block_hash", block_hash.to_string())
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert_eq!(txs.len(), 2);
        assert!(txs.iter().all(|tx| tx.block_hash == block_hash));
        assert_eq!(
            txs.iter().map(|tx| tx.entrypoint_hash).collect::<Vec<_>>(),
            block.network_input_hashes().rev().collect::<Vec<_>>()
        );
        let unknown_hash =
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::new("missing block"),
            );
        let missing = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("block_hash", unknown_hash.to_string())
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert!(missing.is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn find_transactions_by_entrypoint_hash_uses_kura_index() -> Result<()> {
        let num_blocks = 8;
        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let state_view = state.view();
        let block = state_view
            .kura()
            .get_block(nonzero!(4_usize), &state_view.execution_budget())
            .expect("completed original State read")
            .expect("block available");
        let entrypoint_hash = block
            .network_input_hashes()
            .next()
            .expect("test block has transactions");
        let indexed_heights = state_view
            .kura()
            .get_block_heights_by_entrypoint_hash(entrypoint_hash)
            .expect("test Kura transaction index is complete");
        assert_eq!(
            indexed_heights,
            std::collections::BTreeSet::from([nonzero!(4_usize)])
        );
        let txs = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("entrypoint_hash", entrypoint_hash.to_string())
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert_eq!(txs.len(), 1);
        assert!(txs.iter().all(|tx| tx.entrypoint_hash == entrypoint_hash));
        assert_eq!(txs[0].block_hash, block.hash());
        let unknown_hash = iroha_crypto::HashOf::<
            iroha_data_model::transaction::signed::TransactionEntrypoint,
        >::from_untyped_unchecked(Hash::new(
            "missing transaction entrypoint",
        ));
        let missing = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("entrypoint_hash", unknown_hash.to_string())
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert!(missing.is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn find_transactions_by_authority_timestamp_and_result_use_kura_indexes() -> Result<()> {
        let num_blocks = 8;
        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let state_view = state.view();
        let all_txs = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::PASS,
            &state_view,
        )?
        .collect::<Vec<_>>();
        let first_tx = all_txs.first().expect("test state has transactions");
        let authority = first_tx
            .entrypoint
            .authority_opt()
            .expect("test transaction has authority")
            .clone();
        let timestamp_ms = first_tx
            .entrypoint
            .creation_time_ms()
            .expect("test transaction has timestamp");
        assert_eq!(
            state_view
                .kura()
                .get_block_heights_by_transaction_authority(&authority)
                .expect("test Kura transaction index is complete")
                .len() as u64,
            num_blocks
        );
        assert_eq!(
            state_view
                .kura()
                .get_block_heights_by_transaction_timestamp_ms(timestamp_ms)
                .expect("test Kura transaction index is complete")
                .len() as u64,
            1
        );
        assert_eq!(
            state_view
                .kura()
                .get_block_heights_by_transaction_result_status(false)
                .expect("test Kura transaction index is complete")
                .len() as u64,
            num_blocks - 1
        );
        let by_authority = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("authority", authority.to_string())
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        let expected_by_authority = all_txs
            .iter()
            .filter(|tx| tx.entrypoint.authority_opt() == Some(&authority))
            .count();
        assert_eq!(by_authority.len(), expected_by_authority);
        assert!(
            by_authority
                .iter()
                .all(|tx| tx.entrypoint.authority_opt() == Some(&authority))
        );
        let by_timestamp = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("timestamp_ms", timestamp_ms)
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        let expected_by_timestamp = all_txs
            .iter()
            .filter(|tx| tx.entrypoint.creation_time_ms() == Some(timestamp_ms))
            .count();
        assert_eq!(by_timestamp.len(), expected_by_timestamp);
        assert!(
            by_timestamp
                .iter()
                .all(|tx| tx.entrypoint.creation_time_ms() == Some(timestamp_ms))
        );
        let failed = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("result_ok", false)
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert_eq!(failed.len() as u64, num_blocks - 1);
        assert!(failed.iter().all(|tx| tx.result().as_ref().is_err()));
        let missing_authority = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("authority", BOB_ID.to_string())
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert!(missing_authority.is_empty());
        let contradictory_authority = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::build(|p| {
                p.equals("authority", authority.to_string())
                    .equals("authority", BOB_ID.to_string())
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert!(contradictory_authority.is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn find_transactions_by_filter_timestamp_range_uses_kura_index() -> Result<()> {
        let num_blocks = 8;
        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let state_view = state.view();
        let all_txs = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::PASS,
            &state_view,
        )?
        .collect::<Vec<_>>();
        let first_tx = all_txs.first().expect("test state has transactions");
        let timestamp_ms = first_tx
            .entrypoint
            .creation_time_ms()
            .expect("test transaction has timestamp");
        let result_ok = first_tx.result().as_ref().is_ok();
        let expected_heights = all_txs
            .iter()
            .filter(|tx| tx.entrypoint.creation_time_ms() == Some(timestamp_ms))
            .filter_map(|tx| state_view.kura().get_block_height_by_hash(tx.block_hash))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            state_view
                .kura()
                .get_block_heights_by_transaction_timestamp_range(
                    Some(timestamp_ms),
                    Some(timestamp_ms)
                )
                .expect("test Kura transaction index is complete"),
            expected_heights
        );
        let by_timestamp_range = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::from_filters(
                iroha_data_model::query::CommittedTxFilters {
                    ts_ge: Some(timestamp_ms),
                    ts_le: Some(timestamp_ms),
                    ..Default::default()
                },
            ),
            &state_view,
        )?
        .collect::<Vec<_>>();
        let expected_by_range = all_txs
            .iter()
            .filter(|tx| tx.entrypoint.creation_time_ms() == Some(timestamp_ms))
            .count();
        assert_eq!(by_timestamp_range.len(), expected_by_range);
        assert!(
            by_timestamp_range
                .iter()
                .all(|tx| tx.entrypoint.creation_time_ms() == Some(timestamp_ms))
        );
        let by_timestamp_and_result = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::from_filters(
                iroha_data_model::query::CommittedTxFilters {
                    ts_ge: Some(timestamp_ms),
                    ts_le: Some(timestamp_ms),
                    result_ok: Some(result_ok),
                    ..Default::default()
                },
            ),
            &state_view,
        )?
        .collect::<Vec<_>>();
        let expected_by_timestamp_and_result = all_txs
            .iter()
            .filter(|tx| {
                tx.entrypoint.creation_time_ms() == Some(timestamp_ms)
                    && tx.result().as_ref().is_ok() == result_ok
            })
            .count();
        assert_eq!(
            by_timestamp_and_result.len(),
            expected_by_timestamp_and_result
        );
        assert!(by_timestamp_and_result.iter().all(|tx| {
            tx.entrypoint.creation_time_ms() == Some(timestamp_ms)
                && tx.result().as_ref().is_ok() == result_ok
        }));
        let impossible_lower_bound = timestamp_ms + 1;
        assert!(
            state_view
                .kura()
                .get_block_heights_by_transaction_timestamp_range(
                    Some(impossible_lower_bound),
                    Some(timestamp_ms)
                )
                .expect("test Kura transaction index is complete")
                .is_empty()
        );
        let impossible_range = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::<iroha_data_model::query::CommittedTransaction>::from_filters(
                iroha_data_model::query::CommittedTxFilters {
                    ts_ge: Some(impossible_lower_bound),
                    ts_le: Some(timestamp_ms),
                    ..Default::default()
                },
            ),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert!(impossible_range.is_empty());
        assert_eq!(state_view.height() as u64, num_blocks);
        assert_eq!(
            expected_heights,
            std::collections::BTreeSet::from([std::num::NonZeroUsize::new(
                usize::try_from(num_blocks).expect("fixture value fits usize")
            )
            .unwrap(),]),
            "distinct source timestamps select only the latest matching carrier"
        );
        Ok(())
    }
    #[tokio::test]
    async fn find_proof_records_intersects_backend_and_status_indexes() -> Result<()> {
        fn proof_record(
            backend: &str,
            proof_byte: u8,
            status: iroha_data_model::proof::ProofStatus,
        ) -> iroha_data_model::proof::ProofRecord {
            iroha_data_model::proof::ProofRecord {
                id: iroha_data_model::proof::ProofId {
                    backend: backend.into(),
                    proof_hash: [proof_byte; 32],
                },
                vk_ref: None,
                vk_commitment: None,
                status,
                verified_at_height: Some(1),
                bridge: None,
            }
        }
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut state = State::new_for_testing(World::default(), kura, query_handle);
        let target = proof_record(
            "halo2/test",
            1,
            iroha_data_model::proof::ProofStatus::Verified,
        );
        let same_backend_wrong_status = proof_record(
            "halo2/test",
            2,
            iroha_data_model::proof::ProofStatus::Rejected,
        );
        let wrong_backend_same_status = proof_record(
            "stark/test",
            3,
            iroha_data_model::proof::ProofStatus::Verified,
        );
        let mut proof_status_index = std::collections::BTreeMap::<
            iroha_data_model::proof::ProofStatus,
            std::collections::BTreeSet<iroha_data_model::proof::ProofId>,
        >::new();
        for record in [
            target.clone(),
            same_backend_wrong_status.clone(),
            wrong_backend_same_status.clone(),
        ] {
            state.world.proofs.insert(record.id.clone(), record.clone());
            proof_status_index
                .entry(record.status)
                .or_default()
                .insert(record.id);
        }
        for (status, proof_ids) in proof_status_index {
            for proof_id in proof_ids {
                state.world.proofs_by_status.insert((status, proof_id), ());
            }
        }
        let state_view = state.view();
        assert_eq!(
            state_view
                .world()
                .proofs_by_backend_iter("halo2/test")
                .count(),
            2,
            "fixture should populate the backend range used by the query planner",
        );
        let matching = ValidQuery::execute(
            iroha_data_model::query::proof::prelude::FindProofRecords,
            CompoundPredicate::<iroha_data_model::proof::ProofRecord>::build(|p| {
                p.equals("backend", "halo2/test")
                    .equals("status", iroha_data_model::proof::ProofStatus::Verified)
            }),
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert_eq!(matching, vec![target.clone()]);
        let backend_only = ValidQuery::execute(
            iroha_data_model::query::proof::prelude::FindProofRecordsByBackend {
                backend: "halo2/test".into(),
            },
            CompoundPredicate::<iroha_data_model::proof::ProofRecord>::PASS,
            &state_view,
        )?
        .collect::<Vec<_>>();
        assert_eq!(
            backend_only,
            vec![target.clone(), same_backend_wrong_status.clone()],
            "backend-specific proof query must not leak records from another backend",
        );
        let mut missing_backend = ValidQuery::execute(
            iroha_data_model::query::proof::prelude::FindProofRecordsByBackend {
                backend: "missing/backend".into(),
            },
            CompoundPredicate::<iroha_data_model::proof::ProofRecord>::PASS,
            &state_view,
        )?;
        assert!(missing_backend.next().is_none());
        let mut contradictory_backend = ValidQuery::execute(
            iroha_data_model::query::proof::prelude::FindProofRecords,
            CompoundPredicate::<iroha_data_model::proof::ProofRecord>::build(|p| {
                p.equals("backend", "halo2/test")
                    .equals("backend", "stark/test")
            }),
            &state_view,
        )?;
        assert!(contradictory_backend.next().is_none());
        Ok(())
    }
    iter_dispatch_rank_sort_test!(
        iter_dispatch_asset_definitions_sort_asc,
        run_asset_definition_rank_sort_case,
        Sparse,
        Asc,
        0,
        None,
        None,
        &[&[0, 1, 2]]
    );
    iter_dispatch_rank_sort_test!(
        iter_dispatch_accounts_sort_asc_end_to_end,
        run_account_rank_sort_case,
        Sparse,
        Asc,
        0,
        None,
        None,
        &[&[1, 0, 2]]
    );
    iter_dispatch_rank_sort_test!(
        iter_dispatch_accounts_sort_desc_batched,
        run_account_rank_sort_case,
        Sparse,
        Desc,
        0,
        None,
        Some(nonzero!(2_u64)),
        &[&[0, 1], &[2]]
    );
    iter_dispatch_rank_sort_test!(
        iter_dispatch_asset_definitions_sort_desc_batched,
        run_asset_definition_rank_sort_case,
        Sparse,
        Desc,
        0,
        None,
        Some(nonzero!(2_u64)),
        &[&[1, 0], &[2]]
    );
    iter_dispatch_rank_sort_test!(
        iter_dispatch_asset_definitions_offset_and_fetch_size_interplay_asc,
        run_asset_definition_rank_sort_case,
        Dense,
        Asc,
        1,
        Some(nonzero!(2_u64)),
        Some(nonzero!(1_u64)),
        &[&[1], &[2]]
    );
    iter_dispatch_rank_sort_test!(
        iter_dispatch_asset_definitions_offset_and_fetch_size_interplay_desc,
        run_asset_definition_rank_sort_case,
        Dense,
        Desc,
        1,
        Some(nonzero!(2_u64)),
        Some(nonzero!(1_u64)),
        &[&[1], &[0]]
    );
    iter_dispatch_rank_sort_test!(
        iter_dispatch_accounts_offset_and_fetch_size_interplay,
        run_account_rank_sort_case,
        Dense,
        Asc,
        1,
        Some(nonzero!(2_u64)),
        Some(nonzero!(1_u64)),
        &[&[1], &[2]]
    );
    iter_dispatch_rank_sort_test!(
        iter_dispatch_accounts_offset_and_fetch_size_interplay_desc,
        run_account_rank_sort_case,
        Dense,
        Desc,
        1,
        Some(nonzero!(2_u64)),
        Some(nonzero!(1_u64)),
        &[&[1], &[0]]
    );
    include!("query_find_transaction_test.rs");
}
