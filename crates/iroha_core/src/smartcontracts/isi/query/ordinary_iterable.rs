//! Allocation primitives and the fail-closed boundary for ordinary iterables.
//!
//! A generic [`ValidQuery`] iterator is not a source proof: producer-local clones, candidate
//! collections, and synthetic-field predicate evaluators can allocate before pagination observes an
//! item. Unadapted producers stop before `ValidQuery::execute`; each admitted producer instead owns
//! rows through its query-specific bounded adapter.
#![allow(unsafe_code)]
mod asset_uid;
use asset_uid::collect_asset_uid_policies;
use super::{
    OrdinaryQueryExecutionLimits, QueryAttemptError, QueryExecutionStats,
    ordinary_memory::OrdinaryCursorMode, singular_memory::SingularQueryFrame,
};
use crate::{
    smartcontracts::{
        ValidQuery,
        isi::triggers::set::{BorrowedTriggerSourceReadOnly as _, SetReadOnly},
    },
    state::{StateReadOnly, WorldReadOnly},
};
use iroha_data_model::{
    account::{AccountController, AccountId, MultisigMember, MultisigPolicy},
    query::{
        QueryOutputBatchBox, QueryOutputBatchBoxTuple, dsl::CompoundPredicate,
        error::QueryExecutionFail as Error, parameters::QueryParams,
    },
    trigger::{Trigger, TriggerId},
};
use iroha_model_base::peer::PeerId;
use mv::storage::StorageReadOnly as _;
use norito::{
    core::NoritoSerialize,
    json::{JsonSerialize, Value},
};
use std::{
    alloc::{Layout, alloc},
    any::TypeId,
    io,
    mem::MaybeUninit,
    ptr::NonNull,
};
/// The world-state producer count admitted through a source-specific adapter.
#[cfg(test)]
pub(super) const ADMITTED_WORLD_PRODUCERS: usize = 5;
/// The world-state producer count still awaiting source-specific bounded
/// ownership and exact predicate parity.
#[cfg(test)]
pub(super) const WORLD_PRODUCER_RESIDUALS: usize = 33;
/// The Kura producer count awaiting an authenticated bounded reader/projection.
#[cfg(test)]
pub(super) const KURA_PRODUCER_RESIDUALS: usize = 3;
/// Execute a legacy iterable only for callers which did not attach the
/// server-owned ordinary memory corridor.
///
/// The limit-bearing branch deliberately returns before source execution. A
/// preflight followed by the legacy producer would not couple its infallible
/// clones and eager collections to the admitted allocation envelope.
pub(super) fn execute<T, Q, E>(
    query: Q,
    predicate: CompoundPredicate<T>,
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: Option<OrdinaryQueryExecutionLimits>,
    state: &impl StateReadOnly,
) -> Result<(impl Iterator<Item = T>, QueryExecutionStats), QueryAttemptError>
where
    T: NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de> + Send + Sync + 'static,
    Q: ValidQuery<E, Item = T> + 'static,
    E: Into<QueryAttemptError>,
{
    if let Some(limits) = limits {
        if TypeId::of::<Q>() == TypeId::of::<iroha_data_model::query::asset_uid::FindAssetUidPoliciesV1>()
            && TypeId::of::<T>() == TypeId::of::<iroha_data_model::asset::uid::AssetUidPolicyViewV1>()
            && params.pagination.offset_value() == 0
            && params.sorting.sort_by_metadata_key.is_none()
            && predicate.is_pass()
        {
            drop(predicate);
            let query = cast_owned_exact::<Q, iroha_data_model::query::asset_uid::FindAssetUidPoliciesV1>(query)?;
            let (rows, stats) = collect_asset_uid_policies(&query, params, mode, limits, state)?;
            return Ok((OrdinaryIterable::Owned(cast_owned_exact::<
                ExactOwnedRows<iroha_data_model::asset::uid::AssetUidPolicyViewV1>, ExactOwnedRows<T>,
            >(rows)?), stats));
        }
        if TypeId::of::<Q>() == TypeId::of::<iroha_data_model::query::peer::prelude::FindPeers>()
            && TypeId::of::<T>() == TypeId::of::<PeerId>()
            && mode == OrdinaryCursorMode::Ephemeral
            && params.pagination.offset_value() == 0
            && params.sorting.sort_by_metadata_key.is_none()
            && predicate.is_pass()
        {
            drop(predicate);
            let (rows, execution_stats) = collect_peers(params, limits, state)?;
            return Ok((
                OrdinaryIterable::Owned(cast_owned_exact::<
                    ExactOwnedRows<PeerId>,
                    ExactOwnedRows<T>,
                >(rows)?),
                execution_stats,
            ));
        }
        if TypeId::of::<Q>()
            == TypeId::of::<iroha_data_model::query::account::prelude::FindAccountIds>()
            && TypeId::of::<T>() == TypeId::of::<AccountId>()
            && params.pagination.offset_value() == 0
            && params.sorting.sort_by_metadata_key.is_none()
            && predicate.is_pass()
        {
            drop(predicate);
            let (rows, execution_stats) = collect_account_ids(params, mode, limits, state)?;
            return Ok((
                OrdinaryIterable::Owned(cast_owned_exact::<
                    ExactOwnedRows<AccountId>,
                    ExactOwnedRows<T>,
                >(rows)?),
                execution_stats,
            ));
        }
        if params.pagination.offset_value() == 0
            && params.sorting.sort_by_metadata_key.is_none()
            && predicate.is_pass()
        {
            if TypeId::of::<Q>()
                == TypeId::of::<iroha_data_model::query::trigger::prelude::FindActiveTriggerIds>()
                && TypeId::of::<T>() == TypeId::of::<TriggerId>()
            {
                drop(predicate);
                let (rows, execution_stats) =
                    collect_active_trigger_ids(params, mode, limits, state)?;
                return Ok((
                    OrdinaryIterable::Owned(cast_owned_exact::<
                        ExactOwnedRows<TriggerId>,
                        ExactOwnedRows<T>,
                    >(rows)?),
                    execution_stats,
                ));
            }
            if TypeId::of::<Q>()
                == TypeId::of::<iroha_data_model::query::trigger::prelude::FindTriggers>()
                && TypeId::of::<T>() == TypeId::of::<Trigger>()
            {
                drop(predicate);
                let (rows, execution_stats) = collect_triggers(params, mode, limits, state)?;
                return Ok((
                    OrdinaryIterable::Owned(cast_owned_exact::<
                        ExactOwnedRows<Trigger>,
                        ExactOwnedRows<T>,
                    >(rows)?),
                    execution_stats,
                ));
            }
        }
        // Admission refuses every other shape before execution; this is the
        // fail-closed backstop. Admitting another of the remaining 33 world
        // producers requires a query-specific borrowed scan which preserves its
        // synthetic-field predicate rules and owns only the requested
        // prefix/top-K through fallible exact storage. The three Kura producers
        // additionally need an authenticated fixed projection in the reader.
        let query = std::any::type_name::<Q>()
            .rsplit("::")
            .next()
            .unwrap_or("iterable query");
        return Err(super::ordinary_memory::signed_query_shape_not_admitted(
            query,
            "has no bounded signed-query source for this predicate, offset, sorting or cursor mode",
        )
        .into());
    }
    Ok((
        OrdinaryIterable::Legacy(ValidQuery::execute(query, predicate, state).map_err(Into::into)?),
        QueryExecutionStats::default(),
    ))
}
enum OrdinaryIterable<I, T> {
    Legacy(I),
    Owned(ExactOwnedRows<T>),
}
impl<I, T> Iterator for OrdinaryIterable<I, T>
where
    I: Iterator<Item = T>,
{
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Legacy(iter) => iter.next(),
            Self::Owned(iter) => iter.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Legacy(iter) => iter.size_hint(),
            Self::Owned(iter) => iter.size_hint(),
        }
    }
}
fn cast_owned_exact<From: 'static, To: 'static>(value: From) -> Result<To, Error> {
    if TypeId::of::<From>() != TypeId::of::<To>() {
        return Err(Error::Conversion(
            "ordinary iterable source/item type mismatch".to_owned(),
        ));
    }
    let value = core::mem::ManuallyDrop::new(value);
    // SAFETY: equality of `'static` TypeIds proves the concrete types match;
    // `ManuallyDrop` transfers the one owned value through this read.
    let source: *const From = &raw const *value;
    Ok(unsafe { source.cast::<To>().read() })
}
/// Serialize a predicate candidate through the checked ordinary JSON helper.
pub(crate) fn predicate_json_value_for_execution<T: JsonSerialize + ?Sized>(
    value: &T,
) -> Option<Value> {
    iroha_data_model::query::json::predicate_json_value_for_execution(value)
}
fn try_exact_uninit_box<T>(len: usize) -> Result<(Box<[MaybeUninit<T>]>, u64), Error> {
    let layout = Layout::array::<MaybeUninit<T>>(len).map_err(|_| Error::CapacityLimit)?;
    let bytes = u64::try_from(layout.size()).map_err(|_| Error::CapacityLimit)?;
    let allocation = if layout.size() == 0 {
        NonNull::<MaybeUninit<T>>::dangling()
    } else {
        // SAFETY: `layout` describes exactly `len` consecutive slots. Null is
        // handled before ownership is constructed; `Box` later deallocates the
        // identical slice layout.
        NonNull::new(unsafe { alloc(layout).cast::<MaybeUninit<T>>() })
            .ok_or(Error::CapacityLimit)?
    };
    let slice = core::ptr::slice_from_raw_parts_mut(allocation.as_ptr(), len);
    // SAFETY: `slice` is the exact allocation above (or the aligned dangling
    // representation permitted for a zero-sized allocation) and is unique.
    Ok((unsafe { Box::from_raw(slice) }, bytes))
}
fn exact_slot_bytes<T>(len: usize) -> Result<u64, Error> {
    let layout = Layout::array::<MaybeUninit<T>>(len).map_err(|_| Error::CapacityLimit)?;
    u64::try_from(layout.size()).map_err(|_| Error::CapacityLimit)
}

/// Aggregate graph budget left after reserving exact inline row slots.
///
/// The per-row ceiling is enforced again immediately before every decode, so
/// neither one row nor the retained set as a whole can exceed the admitted
/// `selected * S` envelope.
struct RetainedDecodeBudget {
    per_item_graph_bytes: u64,
    remaining_graph_bytes: u64,
}
impl RetainedDecodeBudget {
    fn new<T>(rows: usize, per_item_bytes: u64) -> Result<(Self, u64), Error> {
        let rows_u64 = u64::try_from(rows).map_err(|_| Error::CapacityLimit)?;
        let slot_bytes = exact_slot_bytes::<T>(rows)?;
        let aggregate_bytes = rows_u64
            .checked_mul(per_item_bytes)
            .ok_or(Error::CapacityLimit)?;
        let remaining_graph_bytes = aggregate_bytes
            .checked_sub(slot_bytes)
            .ok_or(Error::CapacityLimit)?;
        let inline_bytes =
            u64::try_from(core::mem::size_of::<T>()).map_err(|_| Error::CapacityLimit)?;
        let per_item_graph_bytes = per_item_bytes
            .checked_sub(inline_bytes)
            .ok_or(Error::CapacityLimit)?;
        Ok((
            Self {
                per_item_graph_bytes,
                remaining_graph_bytes,
            },
            slot_bytes,
        ))
    }

    fn next_limit(&self) -> Result<usize, Error> {
        usize::try_from(self.per_item_graph_bytes.min(self.remaining_graph_bytes))
            .map_err(|_| Error::CapacityLimit)
    }

    fn record_decoded(&mut self, allocated_bytes: usize) -> Result<(), Error> {
        let allocated_bytes = u64::try_from(allocated_bytes).map_err(|_| Error::CapacityLimit)?;
        self.remaining_graph_bytes = self
            .remaining_graph_bytes
            .checked_sub(allocated_bytes)
            .ok_or(Error::CapacityLimit)?;
        Ok(())
    }
}
pub(super) struct ExactOwnedRows<T> {
    slots: Box<[MaybeUninit<T>]>,
    len: usize,
    next: usize,
}

/// Build the one-column response tuple without an infallible `vec![..]`
/// allocation at the ordinary-query memory boundary.
pub(super) fn exact_one_column_batch(
    batch: QueryOutputBatchBox,
) -> Result<QueryOutputBatchBoxTuple, Error> {
    let slot_bytes = exact_slot_bytes::<QueryOutputBatchBox>(1)?;
    let mut columns = ExactOwnedRows::new(1, slot_bytes)?;
    columns.push(batch)?;
    QueryOutputBatchBoxTuple::new(columns.finish()?.into_vec()?)
        .map_err(|error| Error::Conversion(error.to_string()))
}
impl<T> ExactOwnedRows<T> {
    pub(super) fn new(len: usize, maximum_bytes: u64) -> Result<Self, Error> {
        let layout = Layout::array::<MaybeUninit<T>>(len).map_err(|_| Error::CapacityLimit)?;
        let bytes = u64::try_from(layout.size()).map_err(|_| Error::CapacityLimit)?;
        if bytes > maximum_bytes {
            return Err(Error::CapacityLimit);
        }
        let (slots, allocated_bytes) = try_exact_uninit_box(len)?;
        debug_assert_eq!(bytes, allocated_bytes);
        Ok(Self {
            slots,
            len: 0,
            next: 0,
        })
    }
    pub(super) fn push(&mut self, value: T) -> Result<(), Error> {
        let Some(slot) = self.slots.get_mut(self.len) else {
            return Err(Error::CapacityLimit);
        };
        slot.write(value);
        self.len += 1;
        Ok(())
    }
    pub(super) fn finish(self) -> Result<Self, Error> {
        if self.len != self.slots.len() {
            return Err(Error::CapacityLimit);
        }
        Ok(self)
    }
    pub(super) fn into_vec(self) -> Result<Vec<T>, Error> {
        if self.next != 0 || self.len != self.slots.len() {
            return Err(Error::CapacityLimit);
        }
        let this = core::mem::ManuallyDrop::new(self);
        let slots = unsafe { core::ptr::read(&raw const this.slots) };
        let len = slots.len();
        let raw = Box::into_raw(slots).cast::<MaybeUninit<T>>();
        let raw = core::ptr::slice_from_raw_parts_mut(raw.cast::<T>(), len);
        // SAFETY: `finish` established that every slot is initialized, and
        // `MaybeUninit<T>` has the same layout as `T`.
        Ok(unsafe { Box::from_raw(raw) }.into_vec())
    }
}
impl<T> Iterator for ExactOwnedRows<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.len {
            return None;
        }
        let index = self.next;
        self.next += 1;
        // SAFETY: `index < len` is initialized and transferred once.
        Some(unsafe { self.slots[index].assume_init_read() })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}
impl<T> ExactSizeIterator for ExactOwnedRows<T> {}
impl<T> Drop for ExactOwnedRows<T> {
    fn drop(&mut self) {
        for slot in &mut self.slots[self.next..self.len] {
            // SAFETY: precisely the unconsumed initialized suffix remains.
            unsafe { slot.assume_init_drop() };
        }
    }
}
struct ExactFrameWriter {
    bytes: Box<[MaybeUninit<u8>]>,
    written: usize,
}
impl ExactFrameWriter {
    fn new(len: usize) -> Result<Self, Error> {
        let (bytes, _) = try_exact_uninit_box(len)?;
        Ok(Self { bytes, written: 0 })
    }
    fn finish(self) -> Result<Box<[u8]>, Error> {
        if self.written != self.bytes.len() {
            return Err(Error::CapacityLimit);
        }
        // SAFETY: the exact writer initialized every byte in the box.
        Ok(unsafe { self.bytes.assume_init() })
    }
}
impl io::Write for ExactFrameWriter {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        let remaining = self.bytes.len().saturating_sub(self.written);
        if remaining == 0 && !source.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "canonical frame exceeded its counted length",
            ));
        }
        let take = remaining.min(source.len());
        for (slot, byte) in self.bytes[self.written..self.written + take]
            .iter_mut()
            .zip(&source[..take])
        {
            slot.write(*byte);
        }
        self.written += take;
        Ok(take)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
/// Encode one canonical frame through an exact fallible allocation. Converting
/// the completed box into a vector is zero-copy and preserves `capacity == len`.
pub(super) fn encode_bounded_frame<T: NoritoSerialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let encoded_len = norito::core::encoded_frame_len_bounded(value, maximum)
        .map_err(|_| Error::CapacityLimit)?;
    if encoded_len > maximum {
        return Err(Error::CapacityLimit);
    }
    let mut writer = ExactFrameWriter::new(encoded_len)?;
    norito::core::write_canonical_to_writer(value, &mut writer)
        .map_err(|_| Error::CapacityLimit)?;
    Ok(writer.finish()?.into_vec())
}
/// Copy an already validated world-state peer into its exact admitted key allocation.
///
/// Peer constructors and decoders establish key validity before world-state insertion. Re-decoding
/// a canonical frame here would charge parser scratch against the retained graph allowance and
/// reject BLS keys that fit that allowance. The compact clone preserves the validated key bytes;
/// its fallible allocation remains charged to both this row and any enclosing Norito budget.
fn clone_peer_for_admission(
    peer: &PeerId,
    maximum_allocated_bytes: usize,
) -> Result<(PeerId, usize), Error> {
    // This operation allocates a compact key but does not decode a wire value.
    let limits = norito::DecodeLimits::new(0, 0, 0, maximum_allocated_bytes, 0);
    let (cloned, usage) = norito::core::with_decode_limits_measured(limits, || {
        peer.public_key().try_clone_for_admission().map(PeerId::new)
    });
    Ok((
        cloned.map_err(|_| Error::CapacityLimit)?,
        usage.total_allocated_bytes(),
    ))
}
/// Copy a canonical account identity with exact, fallible member/key ownership.
/// The key and member-vector charges share the enclosing Norito allocation budget.
fn clone_account_for_admission(
    account: &AccountId,
    maximum_allocated_bytes: usize,
) -> Result<(AccountId, usize), Error> {
    let limits = norito::DecodeLimits::new(0, 0, 0, maximum_allocated_bytes, 0);
    let (cloned, usage) =
        norito::core::with_decode_limits_measured(limits, || match account.controller() {
            AccountController::Single(key) => key
                .try_clone_for_admission()
                .map(AccountId::new)
                .map_err(|_| Error::CapacityLimit),
            AccountController::Multisig(policy) => {
                let bytes = exact_slot_bytes::<MultisigMember>(policy.members().len())?;
                norito::core::reserve_decode_allocation(
                    usize::try_from(bytes).map_err(|_| Error::CapacityLimit)?,
                )
                .map_err(|_| Error::CapacityLimit)?;
                let mut members = ExactOwnedRows::new(policy.members().len(), bytes)?;
                for member in policy.members() {
                    let key = member
                        .public_key()
                        .try_clone_for_admission()
                        .map_err(|_| Error::CapacityLimit)?;
                    members.push(
                        MultisigMember::new(key, member.weight())
                            .map_err(|_| Error::CapacityLimit)?,
                    )?;
                }
                let policy = MultisigPolicy::from_serialized(
                    policy.version(),
                    policy.threshold(),
                    members.finish()?.into_vec()?,
                )
                .map_err(|_| Error::CapacityLimit)?;
                Ok(AccountId::new_multisig(policy))
            }
        });
    Ok((cloned?, usage.total_allocated_bytes()))
}
fn account_prefix_target(
    fetch: u64,
    limit: Option<u64>,
    mode: OrdinaryCursorMode,
    retained: u64,
) -> Result<u64, Error> {
    let keep = match mode {
        OrdinaryCursorMode::Ephemeral => fetch,
        OrdinaryCursorMode::Stored => fetch.checked_add(retained).ok_or(Error::CapacityLimit)?,
    };
    let probe = keep.checked_add(1).ok_or(Error::CapacityLimit)?;
    Ok(limit.map_or(probe, |limit| limit.min(probe)))
}
/// Bound the borrowed controller graph before encoding can traverse every member.
fn ensure_account_source_graph(account: &AccountId, maximum: usize) -> Result<(), Error> {
    let graph_limit = maximum
        .checked_sub(core::mem::size_of::<AccountId>())
        .ok_or(Error::CapacityLimit)?;
    let mut total = match account.controller() {
        AccountController::Single(_) => 0,
        AccountController::Multisig(policy) => policy
            .members()
            .len()
            .checked_mul(core::mem::size_of::<MultisigMember>())
            .ok_or(Error::CapacityLimit)?,
    };
    // Reject an oversized member vector before walking its keys.
    if total > graph_limit {
        return Err(Error::CapacityLimit);
    }
    let mut key = |key: &iroha_crypto::PublicKey| -> Result<(), Error> {
        let (_, bytes) = key.try_to_bytes().map_err(|_| Error::CapacityLimit)?;
        total = total
            .checked_add(bytes.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::CapacityLimit)?;
        if total > graph_limit {
            return Err(Error::CapacityLimit);
        }
        Ok(())
    };
    match account.controller() {
        AccountController::Single(public_key) => key(public_key),
        AccountController::Multisig(policy) => {
            for member in policy.members() {
                key(member.public_key())?;
            }
            Ok(())
        }
    }
}
fn collect_account_ids(
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<AccountId>, QueryExecutionStats), Error> {
    let fetch = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE)
        .get();
    if fetch > limits.max_page_items() {
        return Err(Error::CapacityLimit);
    }
    let maximum_rows = usize::try_from(account_prefix_target(
        fetch,
        params.pagination.limit_value().map(|limit| limit.get()),
        mode,
        limits.max_cursor_retained_items(),
    )?)
    .map_err(|_| Error::CapacityLimit)?;
    let maximum =
        usize::try_from(limits.max_source_item_bytes()).map_err(|_| Error::CapacityLimit)?;
    let work = limits
        .max_source_item_bytes()
        .checked_mul(3)
        .ok_or(Error::CapacityLimit)?;
    let budget = Some(limits.execution_budget());
    let mut execution_stats = QueryExecutionStats::default();
    let mut selected = 0_usize;
    for (account, _) in state.world().accounts().iter().take(maximum_rows) {
        execution_stats.record_preflighted_item(work, budget)?;
        ensure_account_source_graph(account, maximum)?;
        drop(encode_bounded_frame(account, maximum)?);
        selected = selected.checked_add(1).ok_or(Error::CapacityLimit)?;
    }
    let (mut graph, slot_bytes) =
        RetainedDecodeBudget::new::<AccountId>(selected, limits.max_source_item_bytes())?;
    let mut rows = ExactOwnedRows::new(selected, slot_bytes)?;
    for (account, _) in state.world().accounts().iter().take(selected) {
        execution_stats.record_preflighted_item(work, budget)?;
        ensure_account_source_graph(account, maximum)?;
        drop(encode_bounded_frame(account, maximum)?);
        let (owned, allocated) = clone_account_for_admission(account, graph.next_limit()?)?;
        graph.record_decoded(allocated)?;
        rows.push(owned)?;
    }
    Ok((rows.finish()?, execution_stats))
}
/// Share the same finite prefix/probe contract for ids and complete trigger rows.
fn trigger_source_limits(
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<(usize, usize, u64), Error> {
    let fetch = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE)
        .get();
    if fetch > limits.max_page_items() {
        return Err(Error::CapacityLimit);
    }
    let rows = usize::try_from(account_prefix_target(
        fetch,
        params.pagination.limit_value().map(|limit| limit.get()),
        mode,
        limits.max_cursor_retained_items(),
    )?)
    .map_err(|_| Error::CapacityLimit)?;
    let bytes =
        usize::try_from(limits.max_source_item_bytes()).map_err(|_| Error::CapacityLimit)?;
    let work = limits
        .max_source_item_bytes()
        .checked_mul(3)
        .ok_or(Error::CapacityLimit)?;
    Ok((rows, bytes, work))
}
/// Decode only after frame and exact row slots are admitted. Nested allocations
/// consume both the per-row and aggregate retained graph allowance.
fn decode_trigger_row<T>(frame: &[u8], graph: &mut RetainedDecodeBudget) -> Result<T, Error>
where
    T: NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>,
{
    let elements = frame.len().checked_mul(8).ok_or(Error::CapacityLimit)?;
    let limits =
        norito::DecodeLimits::new(elements, frame.len(), elements, graph.next_limit()?, 64);
    let (owned, usage) = norito::core::with_decode_limits_measured(limits, || {
        norito::decode_from_bytes_with_limits::<T>(frame, limits)
    });
    let owned = owned.map_err(|_| Error::CapacityLimit)?;
    graph.record_decoded(usage.total_allocated_bytes())?;
    Ok(owned)
}
fn collect_active_trigger_ids(
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<TriggerId>, QueryExecutionStats), Error> {
    let (maximum_rows, maximum, work) = trigger_source_limits(params, mode, limits)?;
    let source = state.world().triggers();
    let mut execution_stats = QueryExecutionStats::default();
    let mut selected = 0usize;
    for id in source.active_trigger_ids_iter().take(maximum_rows) {
        execution_stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
        drop(encode_bounded_frame(id, maximum)?);
        selected = selected.checked_add(1).ok_or(Error::CapacityLimit)?;
    }
    let (mut graph, slot_bytes) =
        RetainedDecodeBudget::new::<TriggerId>(selected, limits.max_source_item_bytes())?;
    let mut rows = ExactOwnedRows::new(selected, slot_bytes)?;
    for id in source.active_trigger_ids_iter().take(selected) {
        execution_stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
        let frame = encode_bounded_frame(id, maximum)?;
        rows.push(decode_trigger_row(&frame, &mut graph)?)?;
    }
    Ok((rows.finish()?, execution_stats))
}
/// Own validated identities and metadata without parser staging allocations.
/// Empty executable vectors and fixed-size typed selectors need no decoder
/// staging. Other projections retain strict canonical decoding; all final
/// owners and decoder work share the original row and aggregate allowance.
fn own_trigger_row(
    source: &crate::smartcontracts::isi::triggers::set::BorrowedTriggerSource<'_>,
    maximum: usize,
    graph: &mut RetainedDecodeBudget,
) -> Result<Trigger, Error> {
    use iroha_data_model::{
        events::EventFilterBox, transaction::Executable, trigger::action::Action,
    };
    let executable = encode_bounded_frame(
        &SingularQueryFrame::<Executable>::new(source.executable()),
        maximum,
    )?;
    let filter = encode_bounded_frame(
        &SingularQueryFrame::<EventFilterBox>::new(source.filter()),
        maximum
            .checked_sub(executable.len())
            .ok_or(Error::CapacityLimit)?,
    )?;
    let bytes = executable
        .len()
        .checked_add(filter.len())
        .ok_or(Error::CapacityLimit)?;
    let elements = bytes.checked_mul(8).ok_or(Error::CapacityLimit)?;
    let limits = norito::DecodeLimits::new(elements, bytes, elements, graph.next_limit()?, 64);
    let (owned, usage) = norito::core::with_decode_limits_measured(limits, || {
        let id = TriggerId::new(
            source
                .id()
                .name()
                .try_clone_for_admission()
                .map_err(|_| Error::CapacityLimit)?,
        );
        let authority = source
            .authority()
            .try_clone_for_admission()
            .map_err(|_| Error::CapacityLimit)?;
        let executable = match source.allocation_free_executable() {
            Some(executable) => executable,
            None => norito::decode_from_bytes_with_limits::<Executable>(&executable, limits)
                .map_err(|_| Error::CapacityLimit)?,
        };
        let filter = match source
            .try_own_filter_without_staging()
            .map_err(|_| Error::CapacityLimit)?
        {
            Some(filter) => filter,
            None => norito::decode_from_bytes_with_limits::<EventFilterBox>(&filter, limits)
                .map_err(|_| Error::CapacityLimit)?,
        };
        // Stored by-call actions already bind their authority. Refuse a missing
        // binding before the public constructor could create an uncharged clone.
        if matches!(&filter, EventFilterBox::ExecuteTrigger(filter) if filter.authority().is_none())
        {
            return Err(Error::CapacityLimit);
        }
        let mut action = Action::new(executable, source.repeats(), authority, filter)
            .map_err(|_| Error::CapacityLimit)?;
        if let Some(retry_policy) = source.retry_policy() {
            action = action
                .with_retry_policy(retry_policy)
                .map_err(|_| Error::CapacityLimit)?;
        }
        action.metadata = source
            .metadata()
            .try_clone_for_admission()
            .map_err(|_| Error::CapacityLimit)?;
        Ok::<_, Error>(Trigger::new(id, action))
    });
    let owned = owned?;
    graph.record_decoded(usage.total_allocated_bytes())?;
    Ok(owned)
}
fn collect_triggers(
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<Trigger>, QueryExecutionStats), Error> {
    use std::ops::ControlFlow;
    let (maximum_rows, maximum, work) = trigger_source_limits(params, mode, limits)?;
    let source = state.world().triggers();
    let mut execution_stats = QueryExecutionStats::default();
    let mut selected = 0usize;
    if maximum_rows != 0 {
        source.visit_borrowed_trigger_sources(|source| {
            execution_stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
            if let Some(source) = source {
                drop(encode_bounded_frame(
                    &SingularQueryFrame::<Trigger>::new(source),
                    maximum,
                )?);
                selected = selected.checked_add(1).ok_or(Error::CapacityLimit)?;
            }
            Ok(if selected == maximum_rows {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            })
        })?;
    }
    let (mut graph, slot_bytes) =
        RetainedDecodeBudget::new::<Trigger>(selected, limits.max_source_item_bytes())?;
    let mut rows = ExactOwnedRows::new(selected, slot_bytes)?;
    if selected != 0 {
        source.visit_borrowed_trigger_sources(|source| {
            execution_stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
            if let Some(source) = source {
                rows.push(own_trigger_row(source, maximum, &mut graph)?)?;
            }
            Ok(if rows.len == selected {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            })
        })?;
    }
    Ok((rows.finish()?, execution_stats))
}
fn collect_peers(
    params: &QueryParams,
    limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<PeerId>, QueryExecutionStats), Error> {
    let maximum =
        usize::try_from(limits.max_source_item_bytes()).map_err(|_| Error::CapacityLimit)?;
    let fetch = params
        .fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE)
        .get();
    let maximum_rows = peer_prefix_target(
        fetch,
        params.pagination.limit_value().map(|limit| limit.get()),
    )?;
    if maximum_rows
        > limits
            .max_page_items()
            .checked_add(1)
            .ok_or(Error::CapacityLimit)?
    {
        return Err(Error::CapacityLimit);
    }
    let mut selected = 0_u64;
    let mut execution_stats = QueryExecutionStats::default();
    let budget = limits.execution_budget();
    let source_work_per_item = limits
        .max_source_item_bytes()
        .checked_mul(3)
        .ok_or(Error::CapacityLimit)?;
    for peer in state.world().peers() {
        let frame = encode_bounded_frame(peer, maximum)?;
        execution_stats.record_preflighted_item(source_work_per_item, Some(budget))?;
        drop(frame);
        selected = selected.checked_add(1).ok_or(Error::CapacityLimit)?;
        if selected == maximum_rows {
            break;
        }
    }
    let selected = usize::try_from(selected).map_err(|_| Error::CapacityLimit)?;
    let (mut retained_decode, slot_bytes) =
        RetainedDecodeBudget::new::<PeerId>(selected, limits.max_source_item_bytes())?;
    let mut rows = ExactOwnedRows::new(selected, slot_bytes)?;
    if selected == 0 {
        return Ok((rows.finish()?, execution_stats));
    }
    for peer in state.world().peers() {
        let frame = encode_bounded_frame(peer, maximum)?;
        execution_stats.record_preflighted_item(source_work_per_item, Some(budget))?;
        let decode_limit = retained_decode.next_limit()?;
        drop(frame);
        let (owned, allocated) = clone_peer_for_admission(peer, decode_limit)?;
        retained_decode.record_decoded(allocated)?;
        rows.push(owned)?;
        if rows.len == selected {
            break;
        }
    }
    Ok((rows.finish()?, execution_stats))
}
fn peer_prefix_target(fetch: u64, limit: Option<u64>) -> Result<u64, Error> {
    let probe = fetch.checked_add(1).ok_or(Error::CapacityLimit)?;
    Ok(limit.map_or(probe, |limit| limit.min(probe)))
}
/// Fixed-layout fallible max-heap used to retain the smallest `capacity`
/// values without `Vec`/`BinaryHeap` capacity excess.
pub(super) struct ExactTopK<T> {
    slots: Box<[MaybeUninit<T>]>,
    len: usize,
    next: usize,
}
impl<T: Ord> ExactTopK<T> {
    /// Allocate exactly `keep` slots, rejecting layout overflow, the caller's
    /// byte ceiling, or allocator failure before any item is inserted.
    pub(super) fn new(keep: usize, maximum_bytes: u64) -> Result<(Self, u64), Error> {
        let layout = Layout::array::<MaybeUninit<T>>(keep).map_err(|_| Error::CapacityLimit)?;
        let bytes = u64::try_from(layout.size()).map_err(|_| Error::CapacityLimit)?;
        if bytes > maximum_bytes {
            return Err(Error::CapacityLimit);
        }
        let (slots, allocated_bytes) = try_exact_uninit_box(keep)?;
        debug_assert_eq!(bytes, allocated_bytes);
        Ok((
            Self {
                slots,
                len: 0,
                next: 0,
            },
            bytes,
        ))
    }
    fn initialized(&self) -> &[T] {
        // SAFETY: every slot below `len` is initialized and `MaybeUninit<T>`
        // has the same layout as `T`.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr().cast::<T>(), self.len) }
    }
    fn initialized_mut(&mut self) -> &mut [T] {
        // SAFETY: every slot below `len` is initialized and uniquely borrowed.
        unsafe { core::slice::from_raw_parts_mut(self.slots.as_mut_ptr().cast::<T>(), self.len) }
    }
    fn sift_up(&mut self, mut index: usize) {
        let values = self.initialized_mut();
        while index > 0 {
            let parent = (index - 1) / 2;
            if values[parent] >= values[index] {
                break;
            }
            values.swap(parent, index);
            index = parent;
        }
    }
    fn sift_down(&mut self, mut index: usize) {
        let len = self.len;
        let values = self.initialized_mut();
        loop {
            let left = index.saturating_mul(2).saturating_add(1);
            if left >= len {
                break;
            }
            let right = left + 1;
            let largest = if right < len && values[right] > values[left] {
                right
            } else {
                left
            };
            if values[index] >= values[largest] {
                break;
            }
            values.swap(index, largest);
            index = largest;
        }
    }
    /// Retain the smallest `capacity` values and return the displaced value.
    pub(super) fn retain_smallest(&mut self, value: T) -> Option<T> {
        if self.slots.is_empty() {
            return Some(value);
        }
        if self.len < self.slots.len() {
            self.slots[self.len].write(value);
            self.len += 1;
            self.sift_up(self.len - 1);
            return None;
        }
        if self.initialized()[0] <= value {
            return Some(value);
        }
        let displaced = core::mem::replace(&mut self.initialized_mut()[0], value);
        self.sift_down(0);
        Some(displaced)
    }
    /// Convert the retained heap into ascending iterator order in-place.
    pub(super) fn into_sorted(mut self) -> Self {
        self.initialized_mut().sort_unstable();
        self.next = 0;
        self
    }
}
impl<T> Iterator for ExactTopK<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.len {
            return None;
        }
        let index = self.next;
        self.next += 1;
        // SAFETY: `index < len` is initialized and advancing `next` transfers
        // that slot's ownership exactly once.
        Some(unsafe { self.slots[index].assume_init_read() })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}
impl<T> ExactSizeIterator for ExactTopK<T> {}
impl<T> Drop for ExactTopK<T> {
    fn drop(&mut self) {
        for slot in &mut self.slots[self.next..self.len] {
            // SAFETY: precisely the unconsumed initialized suffix remains
            // owned by this container.
            unsafe { slot.assume_init_drop() };
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn residual_inventory_is_explicit_and_exhaustive() {
        assert_eq!(ADMITTED_WORLD_PRODUCERS, 5);
        assert_eq!(WORLD_PRODUCER_RESIDUALS, 33);
        assert_eq!(KURA_PRODUCER_RESIDUALS, 3);
        assert_eq!(
            ADMITTED_WORLD_PRODUCERS + WORLD_PRODUCER_RESIDUALS + KURA_PRODUCER_RESIDUALS,
            41
        );
    }
    fn trigger_test_limits(source_bytes: u64) -> OrdinaryQueryExecutionLimits {
        let items = 2;
        let response = 16 * 1024;
        let archive = 1024;
        let decode = norito::DecodeLimits::new(64, 4096, 256, 16 * 1024, 16);
        let execution = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            items,
            source_bytes,
            response,
            4096,
            archive,
            decode,
        )
        .unwrap();
        let cursor = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
            items,
            source_bytes,
            source_bytes,
            archive,
        )
        .unwrap();
        OrdinaryQueryExecutionLimits::try_new(
            1,
            super::super::QueryExecutionBudget::from_weighted_limit(256 * 1024, 1, 1),
            items,
            execution,
            source_bytes,
            response,
            items,
            source_bytes,
            cursor,
            4096,
            archive,
            decode,
        )
        .unwrap()
    }
    fn trigger_test_state() -> crate::state::State {
        use crate::smartcontracts::isi::triggers::specialized::{
            SpecializedAction, SpecializedTrigger,
        };
        use iroha_data_model::{events::pipeline::BlockEventFilter, prelude::*};
        use iroha_primitives::const_vec::ConstVec;
        let world = crate::state::World::default();
        {
            let mut block = world.block();
            let mut triggers = block.triggers.transaction();
            let authority = iroha_test_samples::ALICE_ID.clone();
            let instructions = || Executable::Instructions(ConstVec::new_empty());
            let mut data = SpecializedAction::new(
                instructions(),
                Repeats::Indefinitely,
                authority.clone(),
                DataEventFilter::Any,
            )
            .unwrap();
            data.metadata = crate::smartcontracts::isi::triggers::global_data_trigger_scope_metadata_for_testing(&authority);
            assert!(
                triggers
                    .add_data_trigger(SpecializedTrigger::new("zdata".parse().unwrap(), data))
                    .unwrap()
            );
            assert!(
                triggers
                    .add_pipeline_trigger(SpecializedTrigger::new(
                        "apipeline".parse().unwrap(),
                        SpecializedAction::new(
                            instructions(),
                            Repeats::Exactly(1),
                            authority.clone(),
                            PipelineEventFilterBox::from(BlockEventFilter::new()),
                        )
                        .unwrap(),
                    ))
                    .unwrap()
            );
            assert!(
                triggers
                    .add_time_trigger(SpecializedTrigger::new(
                        "mtime".parse().unwrap(),
                        SpecializedAction::new(
                            instructions(),
                            Repeats::Exactly(1),
                            authority.clone(),
                            TimeEventFilter(ExecutionTime::PreCommit),
                        )
                        .unwrap(),
                    ))
                    .unwrap()
            );
            assert!(
                triggers
                    .add_by_call_trigger(SpecializedTrigger::new(
                        "bcall".parse().unwrap(),
                        SpecializedAction::new(
                            instructions(),
                            Repeats::Exactly(0),
                            authority,
                            ExecuteTriggerEventFilter::new(),
                        )
                        .unwrap(),
                    ))
                    .unwrap()
            );
            triggers.apply();
            block.commit();
        }
        crate::state::State::new(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        )
    }
    #[test]
    fn bounded_uid_roster_source_is_exact_and_preserves_stored_cursor() {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            smartcontracts::Execute,
            state::{State, World},
        };
        use iroha_data_model::{
            asset::{
                AssetBalancePolicy,
                uid::{AssetUidDailyWindowV1, AssetUidPolicyV1, AssetUidPolicyViewV1},
            },
            isi::asset_uid::SetAssetUidPolicyV1,
            prelude::*,
            query::{asset_uid::FindAssetUidPoliciesV1, parameters::FetchSize},
        };
        use std::{collections::BTreeSet, num::NonZeroU64};
        let owner = iroha_test_samples::ALICE_ID.clone();
        let second = iroha_test_samples::BOB_ID.clone();
        let definition = AssetDefinitionId::from_uuid_bytes([
            0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0x48, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8,
            0xa8,
        ])
        .unwrap();
        let world = World::with(
            [],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(second.clone()).build(&owner),
            ],
            [
                AssetDefinition::numeric(definition.clone(), "DS", AssetBalancePolicy::Global, None)
                    .build(&owner),
            ],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let query = FindAssetUidPoliciesV1 {
            asset_definition_id: definition.clone(),
            uid: None,
        };
        let limits = trigger_test_limits(4_096);
        let params = QueryParams {
            fetch_size: FetchSize::new(NonZeroU64::new(1)),
            ..QueryParams::default()
        };
        assert!(
            collect_asset_uid_policies(
                &query,
                &params,
                OrdinaryCursorMode::Stored,
                limits,
                &state.view()
            )
            .is_err(),
            "missing authenticated time must not look like an empty roster"
        );
        {
            let header = BlockHeader::new(
                NonZeroU64::new(1).unwrap(),
                None,
                None,
                1_000,
                0,
            );
            let mut block = state.block(header.clone());
            let mut tx = block.transaction();
            for (uid, account) in [(7, owner.clone()), (8, second)] {
                SetAssetUidPolicyV1 {
                    policy: AssetUidPolicyV1 {
                        asset_definition_id: definition.clone(),
                        uid: [uid; 32],
                        revision: 1,
                        accounts: BTreeSet::from([account]),
                        holding_limit: Some(50_u32.into()),
                        daily_window: AssetUidDailyWindowV1::UtcDay,
                        daily_limit: Some(50_u32.into()),
                    },
                }
                .execute(&owner, &mut tx)
                .unwrap();
            }
            tx.apply();
            block.commit_empty_block_for_testing().unwrap();
            state.update_latest_block_header_cache_for_tests(header);
        }
        let view = state.view();
        let (rows, stats) =
            collect_asset_uid_policies(&query, &params, OrdinaryCursorMode::Stored, limits, &view)
                .unwrap();
        let rows: Vec<AssetUidPolicyViewV1> = rows.collect();
        assert_eq!(
            rows.iter().map(|row| row.policy.uid).collect::<Vec<_>>(),
            [[7; 32], [8; 32]]
        );
        assert!(
            rows.iter()
                .all(|row| row.ledger_time_ms == 1_000 && row.as_of_height == 1)
        );
        assert!(stats.processed_items() >= 4);
        let point = FindAssetUidPoliciesV1 {
            uid: Some([8; 32]),
            ..query.clone()
        };
        assert_eq!(
            collect_asset_uid_policies(&point, &params, OrdinaryCursorMode::Stored, limits, &view)
                .unwrap()
                .0
                .count(),
            1
        );
        let (rows, stats) =
            collect_asset_uid_policies(&query, &params, OrdinaryCursorMode::Stored, limits, &view)
                .unwrap();
        let output = super::super::ordinary_stored::handle(
            rows,
            &params,
            super::super::QueryLimits::new(2)
                .with_count_mode(super::super::QueryCountMode::Bounded)
                .with_ordinary_execution_limits(limits),
            limits,
            view.query_handle(),
            &owner,
            None,
            stats,
        )
        .unwrap();
        assert!(output.has_more);
        assert!(output.continue_cursor.is_some());
        assert_eq!(output.batch.len(), 1);
        let cursor = output.continue_cursor.unwrap();
        assert!(
            view.query_handle()
                .handle_iter_continue(cursor.clone(), &iroha_test_samples::BOB_ID)
                .is_err(),
            "another participant cannot take the owner's UID cursor"
        );
        let next = view
            .query_handle()
            .handle_iter_continue(cursor, &owner)
            .unwrap();
        assert_eq!(next.batch.len(), 1);
        assert!(!next.has_more);
        assert!(next.continue_cursor.is_none());
        let tiny = trigger_test_limits(1_024);
        let mut invalid = query.clone();
        invalid.asset_definition_id = AssetDefinitionId::from_uuid_bytes([
            0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0x48, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8,
            0xb8,
        ])
        .unwrap();
        assert_eq!(
            collect_asset_uid_policies(&invalid, &params, OrdinaryCursorMode::Stored, tiny, &view)
                .unwrap()
                .0
                .count(),
            0
        );
    }
    #[test]
    fn bounded_trigger_rows_preserve_typed_order_and_frozen_cursor_prefix() {
        use iroha_data_model::query::parameters::FetchSize;
        use nonzero_ext::nonzero;
        let state = trigger_test_state();
        let view = state.view();
        let limits = trigger_test_limits(super::super::ORDINARY_NAME_ID_SOURCE_BYTES);
        let params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
            ..QueryParams::default()
        };
        let expected = view.world().triggers().triggers_iter().collect::<Vec<_>>();
        assert_eq!(
            expected
                .iter()
                .map(|t| t.id().to_string())
                .collect::<Vec<_>>(),
            ["zdata", "apipeline", "mtime", "bcall"]
        );
        let (ephemeral, execution_stats) =
            collect_triggers(&params, OrdinaryCursorMode::Ephemeral, limits, &view).unwrap();
        assert_eq!(
            ephemeral
                .map(|row| norito::encode_canonical(&row).unwrap())
                .collect::<Vec<_>>(),
            expected[..3]
                .iter()
                .map(|row| norito::encode_canonical(row).unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(execution_stats.processed_items(), 6);
        assert_eq!(
            execution_stats.processed_bytes(),
            18 * limits.max_source_item_bytes()
        );
        {
            use iroha_data_model::query::{
                ErasedIterQuery, QueryBox, QueryRequest, QueryWithParams,
                dsl::SelectorTuple,
                trigger::prelude::{FindActiveTriggerIds, FindTriggers},
            };
            let queries: [QueryBox<QueryOutputBatchBox>; 2] = [
                Box::new(ErasedIterQuery::<Trigger>::new(
                    CompoundPredicate::PASS,
                    SelectorTuple::default(),
                    norito::codec::Encode::encode(&FindTriggers),
                )),
                Box::new(ErasedIterQuery::<TriggerId>::new(
                    CompoundPredicate::PASS,
                    SelectorTuple::default(),
                    norito::codec::Encode::encode(&FindActiveTriggerIds),
                )),
            ];
            for query in queries {
                let request = super::super::ValidQueryRequest {
                    request: QueryRequest::Start(
                        QueryWithParams::new(&query, params.clone()).unwrap(),
                    ),
                    limits: super::super::QueryLimits::new(2)
                        .with_count_mode(super::super::QueryCountMode::Bounded)
                        .with_ordinary_execution_limits(limits),
                };
                request
                    .execute_ephemeral_with_stats(
                        view.query_handle(),
                        &view,
                        &iroha_test_samples::ALICE_ID,
                        None,
                    )
                    .expect("actual server-owned start shape and source adapter");
            }
        }
        let (stored, execution_stats) =
            collect_triggers(&params, OrdinaryCursorMode::Stored, limits, &view).unwrap();
        assert_eq!(execution_stats.processed_items(), 8);
        drop(view);
        {
            let mut block = state.world.block();
            let mut triggers = block.triggers.transaction();
            assert!(triggers.remove(&"zdata".parse().unwrap()));
            triggers.apply();
            block.commit();
        }
        assert_eq!(
            stored
                .map(|row| norito::encode_canonical(&row).unwrap())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|row| norito::encode_canonical(row).unwrap())
                .collect::<Vec<_>>(),
            "retained rows own the original immutable action bytes"
        );
    }
    #[test]
    fn bounded_active_trigger_ids_exclude_depleted_actions_and_honor_exact_limits() {
        use iroha_data_model::query::parameters::FetchSize;
        use nonzero_ext::nonzero;
        let state = trigger_test_state();
        let view = state.view();
        let limits = trigger_test_limits(super::super::ORDINARY_NAME_ID_SOURCE_BYTES);
        let params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
            ..QueryParams::default()
        };
        let (ids, execution_stats) =
            collect_active_trigger_ids(&params, OrdinaryCursorMode::Stored, limits, &view).unwrap();
        assert_eq!(
            ids.map(|id| id.to_string()).collect::<Vec<_>>(),
            ["zdata", "apipeline", "mtime"]
        );
        assert_eq!(execution_stats.processed_items(), 6);
        assert_eq!(
            execution_stats.processed_bytes(),
            18 * limits.max_source_item_bytes()
        );
        let frame = encode_bounded_frame(&"zdata".parse::<TriggerId>().unwrap(), 1024).unwrap();
        assert!(RetainedDecodeBudget::new::<TriggerId>(1, 1).is_err());
        assert!(
            encode_bounded_frame(&"zdata".parse::<TriggerId>().unwrap(), frame.len() - 1).is_err()
        );
        let (mut graph, _) =
            RetainedDecodeBudget::new::<TriggerId>(1, core::mem::size_of::<TriggerId>() as u64)
                .unwrap();
        assert!(decode_trigger_row::<TriggerId>(&frame, &mut graph).is_err());
        let too_many = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(3_u64))),
            ..QueryParams::default()
        };
        assert!(trigger_source_limits(&too_many, OrdinaryCursorMode::Ephemeral, limits).is_err());
    }
    #[test]
    fn trigger_field_ownership_preserves_canonical_bytes_and_exact_shared_graph_limits() {
        let state = trigger_test_state();
        let view = state.view();
        let expected = view.world().triggers().triggers_iter().collect::<Vec<_>>();
        let source_bytes = super::super::ORDINARY_NAME_ID_SOURCE_BYTES;
        let maximum = usize::try_from(source_bytes).unwrap();
        let mut ordinal = 0;
        view.world()
            .triggers()
            .visit_borrowed_trigger_sources(|source| {
                let source = source.expect("all four original executable sources exist");
                let canonical = norito::encode_canonical(&expected[ordinal]).unwrap();
                let frame =
                    encode_bounded_frame(&SingularQueryFrame::<Trigger>::new(source), maximum)?;
                assert_eq!(frame, canonical);
                assert!(
                    encode_bounded_frame(
                        &SingularQueryFrame::<Trigger>::new(source),
                        frame.len() - 1
                    )
                    .is_err()
                );
                let (mut graph, inline) = RetainedDecodeBudget::new::<Trigger>(1, source_bytes)?;
                let before = graph.remaining_graph_bytes;
                let owned = own_trigger_row(source, maximum, &mut graph)?;
                let allocated = before - graph.remaining_graph_bytes;
                assert!(allocated > 0);
                assert_eq!(norito::encode_canonical(&owned).unwrap(), canonical);
                let exact = inline.checked_add(allocated).unwrap();
                let (mut exact_graph, _) = RetainedDecodeBudget::new::<Trigger>(1, exact)?;
                let exact_owned = own_trigger_row(source, maximum, &mut exact_graph)?;
                assert_eq!(exact_graph.remaining_graph_bytes, 0);
                assert_eq!(norito::encode_canonical(&exact_owned).unwrap(), canonical);
                let (mut short_graph, _) = RetainedDecodeBudget::new::<Trigger>(1, exact - 1)?;
                assert!(matches!(
                    own_trigger_row(source, maximum, &mut short_graph),
                    Err(Error::CapacityLimit)
                ));
                let (mut outer_graph, _) = RetainedDecodeBudget::new::<Trigger>(1, source_bytes)?;
                let outer = norito::DecodeLimits::new(
                    usize::MAX,
                    usize::MAX,
                    usize::MAX,
                    usize::try_from(allocated - 1).unwrap(),
                    usize::MAX,
                );
                assert!(
                    norito::core::with_decode_limits_measured(outer, || own_trigger_row(
                        source,
                        maximum,
                        &mut outer_graph
                    ))
                    .0
                    .is_err()
                );
                ordinal += 1;
                Ok(std::ops::ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(ordinal, 4);
    }
    #[test]
    fn account_prefix_target_bounds_each_cursor_mode_and_explicit_limit() {
        assert_eq!(
            account_prefix_target(2, None, OrdinaryCursorMode::Ephemeral, 8).unwrap(),
            3
        );
        assert_eq!(
            account_prefix_target(2, None, OrdinaryCursorMode::Stored, 8).unwrap(),
            11
        );
        assert_eq!(
            account_prefix_target(2, Some(2), OrdinaryCursorMode::Stored, 8).unwrap(),
            2
        );
        assert_eq!(
            account_prefix_target(2, Some(10), OrdinaryCursorMode::Stored, 8).unwrap(),
            10
        );
        assert!(account_prefix_target(u64::MAX, None, OrdinaryCursorMode::Stored, 1).is_err());
    }
    #[test]
    fn account_graph_preflight_bounds_large_keys_before_encoding() {
        use iroha_crypto::{Algorithm, KeyPair};
        for algorithm in [Algorithm::Ed25519, Algorithm::BlsNormal, Algorithm::MlDsa] {
            let key = KeyPair::try_from_seed(vec![0x94; 32], algorithm)
                .unwrap()
                .public_key()
                .clone();
            let graph = key.try_to_bytes().unwrap().1.len() + 1;
            let account = AccountId::new(key);
            let maximum = core::mem::size_of::<AccountId>() + graph;
            ensure_account_source_graph(&account, maximum).expect("exact graph");
            assert!(matches!(
                ensure_account_source_graph(&account, maximum - 1),
                Err(Error::CapacityLimit)
            ));
            let (copy, allocated) =
                clone_account_for_admission(&account, graph).expect("exact large key copy");
            assert_eq!(allocated, graph);
            assert_eq!(copy, account);
        }
    }
    #[test]
    fn account_clone_admission_preserves_single_and_multisig_identity_at_exact_graph_limit() {
        use iroha_crypto::{Algorithm, KeyPair};
        let keys: Vec<_> = [0x91_u8, 0x92, 0x93]
            .into_iter()
            .map(|seed| {
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .expect("key")
                    .public_key()
                    .clone()
            })
            .collect();
        let single = AccountId::new(keys[0].clone());
        let members = keys
            .into_iter()
            .map(|key| MultisigMember::new(key, 1).unwrap())
            .collect();
        let multi = AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap());
        for (id, graph) in [
            (single, 33),
            (multi, 3 * core::mem::size_of::<MultisigMember>() + 3 * 33),
        ] {
            let (copy, allocated) =
                clone_account_for_admission(&id, graph).expect("exact graph allowance");
            assert_eq!(copy, id);
            assert_eq!(allocated, graph);
            ensure_account_source_graph(&id, core::mem::size_of::<AccountId>() + graph).unwrap();
            assert!(
                ensure_account_source_graph(&id, core::mem::size_of::<AccountId>() + graph - 1)
                    .is_err()
            );
            assert_eq!(
                norito::to_bytes(&copy).unwrap(),
                norito::to_bytes(&id).unwrap()
            );
            assert!(matches!(
                clone_account_for_admission(&id, graph - 1),
                Err(Error::CapacityLimit)
            ));
            let outer = norito::DecodeLimits::new(0, 0, 0, graph - 1, 0);
            assert!(
                norito::core::with_decode_limits_measured(outer, || clone_account_for_admission(
                    &id, graph
                ))
                .0
                .is_err()
            );
        }
    }
    #[test]
    fn bounded_peer_prefix_matches_ephemeral_pagination_probe() {
        assert_eq!(peer_prefix_target(16, None).expect("probe"), 17);
        assert_eq!(peer_prefix_target(16, Some(7)).expect("short limit"), 7);
        assert_eq!(peer_prefix_target(16, Some(16)).expect("page limit"), 16);
        assert_eq!(peer_prefix_target(16, Some(32)).expect("long limit"), 17);
    }
    #[test]
    fn exact_topk_retains_smallest_values_in_order() {
        let (mut heap, bytes) = ExactTopK::new(3, 3 * 8).expect("three exact u64 slots");
        assert_eq!(bytes, 3 * 8);
        for value in [7_u64, 2, 11, 5, 3] {
            let _ = heap.retain_smallest(value);
        }
        assert_eq!(heap.into_sorted().collect::<Vec<_>>(), [2, 3, 5]);
    }
    #[test]
    fn exact_topk_rejects_max_minus_one_before_allocation() {
        assert!(ExactTopK::<u64>::new(3, 3 * 8 - 1).is_err());
    }
    #[test]
    fn retained_decode_budget_reserves_slots_before_graph_decodes() {
        let (mut budget, slot_bytes) =
            RetainedDecodeBudget::new::<u64>(2, 16).expect("two admitted rows");
        assert_eq!(slot_bytes, 2 * 8);
        assert_eq!(budget.remaining_graph_bytes, 2 * 16 - slot_bytes);
        assert_eq!(budget.next_limit().expect("first cap"), 8);
        budget.record_decoded(7).expect("first graph");
        assert_eq!(budget.next_limit().expect("second cap"), 8);
        budget.record_decoded(8).expect("second graph");
        assert_eq!(budget.next_limit().expect("aggregate remainder"), 1);
    }
    #[test]
    fn retained_decode_budget_rejects_inline_slots_above_aggregate_cap() {
        assert!(RetainedDecodeBudget::new::<u64>(1, 7).is_err());
    }
    #[test]
    fn exact_one_column_batch_uses_the_fallible_exact_container() {
        let batch = QueryOutputBatchBox::String(Vec::new());
        let tuple = exact_one_column_batch(batch).expect("one exact column");
        assert_eq!(tuple.column_count(), 1);
    }
    #[test]
    fn ordinary_postprocessing_does_not_recharge_precounted_source_rows() {
        use iroha_data_model::{
            query::{dsl::SelectorTuple, parameters::FetchSize},
            role::RoleId,
        };
        use nonzero_ext::nonzero;
        let budget = super::super::QueryExecutionBudget::from_weighted_limit(128 * 1_024, 1, 1);
        let ordinary = OrdinaryQueryExecutionLimits::try_new(
            1,
            budget,
            16,
            64 * 1_024,
            1_024,
            16 * 1_024,
            16,
            16 * 1_024,
            32 * 1_024,
            16 * 1_024,
            4 * 1_024,
            norito::DecodeLimits::new(64, 4 * 1_024, 256, 16 * 1_024, 16),
        )
        .expect("ordinary limits");
        let params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
            ..QueryParams::default()
        };
        let source_stats = super::super::QueryExecutionStats {
            processed_items: 6,
            processed_bytes: 18 * 1_024,
        };
        let values = ["one", "two", "probe"].map(|value| {
            value
                .parse::<RoleId>()
                .expect("protocol-bounded role identifier")
        });
        let (output, execution_stats) =
            super::super::apply_query_postprocessing_ephemeral_with_budget_from_stats(
                values.into_iter(),
                SelectorTuple::default(),
                &params,
                super::super::QueryLimits::new(16)
                    .with_count_mode(super::super::QueryCountMode::Bounded)
                    .with_ordinary_execution_limits(ordinary),
                Some(budget),
                source_stats,
            )
            .expect("bounded ordinary postprocessing");
        assert!(output.has_more);
        assert_eq!(execution_stats, source_stats);
    }
    #[test]
    fn peer_adapter_carries_mixed_key_source_work_into_the_final_response_budget() {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, StateReadOnly, World},
        };
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::query::{
            ErasedIterQuery, QueryBox, QueryRequest, QueryResponse, QueryWithParams,
            dsl::{CompoundPredicate, SelectorTuple},
            parameters::FetchSize,
            peer::prelude::FindPeers,
        };
        use iroha_test_samples::ALICE_ID;
        use nonzero_ext::nonzero;

        let world = World::default();
        {
            let mut world_block = world.block();
            let mut peers = world_block.peers_mut_for_testing().transaction();
            for (seed, algorithm) in [
                (0x31_u8, Algorithm::Ed25519),
                (0x32, Algorithm::BlsNormal),
                (0x33, Algorithm::BlsSmall),
            ] {
                let peer = PeerId::new(
                    KeyPair::try_from_seed(vec![seed; 32], algorithm)
                        .expect("peer key")
                        .public_key()
                        .clone(),
                );
                let _ = peers.push(peer);
            }
            peers.apply();
            world_block.commit();
        }
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let view = state.view();
        let max_page_items = 2_u64;
        let source_bytes = super::super::ORDINARY_NAME_ID_SOURCE_BYTES;
        let response_bytes = 16 * 1_024;
        let archive_bytes = 1_024;
        let decode = norito::DecodeLimits::new(64, 4 * 1_024, 256, 16 * 1_024, 16);
        let execution_headroom = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            max_page_items,
            source_bytes,
            response_bytes,
            4 * 1_024,
            archive_bytes,
            decode,
        )
        .expect("execution geometry");
        let cursor_retained = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
            max_page_items,
            source_bytes,
            source_bytes,
            archive_bytes,
        )
        .expect("cursor geometry");
        let ordinary = OrdinaryQueryExecutionLimits::try_new(
            1,
            super::super::QueryExecutionBudget::from_weighted_limit(256 * 1_024, 1, 1),
            max_page_items,
            execution_headroom,
            source_bytes,
            response_bytes,
            max_page_items,
            source_bytes,
            cursor_retained,
            4 * 1_024,
            archive_bytes,
            decode,
        )
        .expect("peer corridor limits");
        let query: QueryBox<QueryOutputBatchBox> = Box::new(ErasedIterQuery::<PeerId>::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            norito::codec::Encode::encode(&FindPeers),
        ));
        let params = QueryParams {
            fetch_size: FetchSize::new(Some(nonzero!(2_u64))),
            ..QueryParams::default()
        };
        let request = super::super::ValidQueryRequest {
            request: QueryRequest::Start(
                QueryWithParams::new(&query, params)
                    .expect("peer query type has a canonical mapping"),
            ),
            limits: super::super::QueryLimits::new(max_page_items)
                .with_count_mode(super::super::QueryCountMode::Bounded)
                .with_ordinary_execution_limits(ordinary),
        };
        let (response, execution_stats) = request
            .execute_ephemeral_with_stats(view.query_handle(), &view, &ALICE_ID, None)
            .expect("bounded peer query");
        let response_work = super::super::bounded_framed_encoded_len(&response, response_bytes)
            .expect("bounded response length");
        assert_eq!(
            execution_stats.processed_items(),
            6,
            "two passes over F + 1 rows"
        );
        assert_eq!(
            execution_stats.processed_bytes(),
            18 * source_bytes + response_work
        );
        let QueryResponse::Iterable(output) = response else {
            panic!("expected iterable response")
        };
        assert_eq!(
            output.batch.columns().first().map(QueryOutputBatchBox::len),
            Some(2)
        );
        assert!(output.has_more);
        let expected = view
            .world()
            .peers()
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            output.batch.columns(),
            &[QueryOutputBatchBox::from(expected)],
            "the bounded copy preserves peer order and exact key bytes"
        );
    }
    #[test]
    fn peer_clone_admission_charges_exact_key_bytes_and_enforces_row_budget() {
        use iroha_crypto::{Algorithm, KeyPair};

        for (algorithm, compact_bytes) in [
            (Algorithm::Ed25519, 33),
            (Algorithm::BlsNormal, 49),
            (Algorithm::BlsSmall, 97),
        ] {
            let peer = PeerId::new(
                KeyPair::try_from_seed(vec![0xb9; 32], algorithm)
                    .expect("validated peer fixture key")
                    .public_key()
                    .clone(),
            );
            let (copy, charged) = clone_peer_for_admission(&peer, compact_bytes)
                .expect("exact compact key budget admits the validated peer");
            assert_eq!(copy, peer);
            assert_eq!(charged, compact_bytes);
            assert!(matches!(
                clone_peer_for_admission(&peer, compact_bytes - 1),
                Err(Error::CapacityLimit)
            ));
            let mut copied_wire = Vec::new();
            norito::core::write_canonical_to_writer(&copy, &mut copied_wire)
                .expect("copied peer wire");
            let mut original_wire = Vec::new();
            norito::core::write_canonical_to_writer(&peer, &mut original_wire)
                .expect("original peer wire");
            assert_eq!(copied_wire, original_wire);
        }
    }
    #[test]
    fn peer_clone_admission_preserves_enclosing_aggregate_budget() {
        use iroha_crypto::{Algorithm, KeyPair};

        let peer = PeerId::new(
            KeyPair::try_from_seed(vec![0xbb; 32], Algorithm::BlsSmall)
                .expect("validated BLS peer fixture key")
                .public_key()
                .clone(),
        );
        let outer = norito::DecodeLimits::new(0, 0, 0, 193, 0);
        let ((first, second), usage) = norito::core::with_decode_limits_measured(outer, || {
            (
                clone_peer_for_admission(&peer, 97),
                clone_peer_for_admission(&peer, 97),
            )
        });
        assert_eq!(first.expect("first peer fits the aggregate").0, peer);
        assert!(matches!(second, Err(Error::CapacityLimit)));
        assert_eq!(usage.total_allocated_bytes(), 97);
    }
    #[test]
    fn exact_canonical_frame_has_no_capacity_excess() {
        let expected = norito::core::encoded_frame_len(&17_u64).expect("count frame");
        let bytes = encode_bounded_frame(&17_u64, expected).expect("exact maximum");
        assert_eq!(bytes.len(), expected);
        assert_eq!(bytes.capacity(), expected);
        assert!(encode_bounded_frame(&17_u64, expected - 1).is_err());
    }
    #[test]
    fn ordinary_source_never_reaches_legacy_execute() {
        let source = include_str!("ordinary_iterable.rs");
        let boundary = source
            .split_once("pub(super) fn execute")
            .expect("ordinary execution boundary")
            .1
            .split_once("pub(crate) fn predicate_json_value_for_execution")
            .expect("end of execution boundary")
            .0;
        let limited = boundary
            .find("if let Some(limits) = limits")
            .expect("limit gate");
        assert!(limited < boundary.find("ValidQuery::execute").expect("legacy path"));
        assert!(!source.contains(concat!("new_uninit_", "slice")));
        assert!(!source.contains(concat!("BinaryHeap", "::with_capacity")));
        assert!(!source.contains(concat!("to_bytes_", "bounded(")));
    }
}
