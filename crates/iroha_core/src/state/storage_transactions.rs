//! Multi-version append-only storage for canonical carrier and replay identities.
#![allow(clippy::disallowed_types)]
use iroha_allocation::shared::{Reserved, Shared};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferFromChargeError,
};
use iroha_crypto::HashOf;
use iroha_data_model::prelude::TransactionEntrypoint;
#[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
use norito::json::JsonDeserialize as JsonDeserializeTrait;
use norito::json::JsonKeyCodec;
use norito::json::{self, FastJsonWrite, JsonSerialize as JsonSerializeTrait};
use parking_lot::{Mutex, RawMutex, RwLock, lock_api::MutexGuard};
#[cfg(test)]
use std::sync::Arc;
use std::{
    alloc::Layout,
    borrow::Borrow,
    collections::{BTreeMap, HashSet},
    hash::Hash,
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, Ordering},
};
type Key = HashOf<TransactionEntrypoint>;
type Value = NonZeroUsize;
#[path = "storage_transactions/history.rs"]
mod history;
#[path = "storage_transactions/history_slot.rs"]
mod history_slot;
pub use history::MembershipAdmissionError;
pub(crate) use history::Pending as PreparedMembershipStart;
use history::{Identity, Reader as HistoryReader};

/// Preserve snapshot syntax separately from an original local resource refusal.
#[derive(Debug, thiserror::Error)]
pub enum MembershipRestoreError {
    /// Canonical snapshot parsing or shape failure.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// Local finite-pool or physical-history failure; never empty-State fallback.
    #[error(transparent)]
    Admission(#[from] MembershipAdmissionError),
}
/// Multi-version membership for canonical carriers and sealed-reveal execution aliases.
/// The original configured pool funds historical generations, publication
/// identities, distinct logical/physical release controls, prior-tip preparation,
/// and the latest block's immutable keys and shared shell. Old readers retain
/// their exact historical generation and tip.
///
/// TODO: prepay the upstream ordinary carrier Vec and merge-carrier HashSet
/// before their construction, and admit snapshot decoding/comparison scratch
/// through its original snapshot owner before claiming complete admission.
pub struct TransactionsStorage {
    /// Latest block. Stored separately because of reverts.
    /// `None` when there are no blocks yet, otherwise must be not `None`.
    latest_block: TipStore,
    /// Map with aggregated entrypoints of multiple blocks, EXCEPT for the latest block. Entries
    /// are retained only for finalised blocks (with heights strictly lower than the current latest
    /// block) so that stale transactions are discarded after rollbacks.
    blocks: history::Map,
    // The opaque identity covers both the hot tip and the historical map.
    // It rotates while the writer is held, never from a caller-provided scalar.
    write_lock: Mutex<Identity>,
    pub(in crate::state) budget: iroha_allocation::AllocationBudget,
    pending: Mutex<Option<history::Pending>>,
    publication_sequence: AtomicU64,
    // Original-pool control for logical membership and outstanding preparation loans.
    released: iroha_allocation::release::ReleaseNotification,
    // Original-pool control for the distinct physical history writer. Logical
    // observation/abort cleanup must never wake this source while it is held.
    history_released: iroha_allocation::release::ReleaseNotification,
}

/// How one physical field of [`TransactionsStorage`] relates to State authority.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) enum MembershipFieldRole {
    /// Holds rows, or the cell value, of the named canonical registry identities.
    Canonical(&'static [&'static str]),
    /// Node-local machinery whose value cannot affect a canonical row.
    Local(&'static str),
}

// The authority registry declares the three semantic membership identities by hand
// (`authority_registry::state::TRANSACTION_MEMBERSHIP_FIELDS`): they are projections of
// two physical fields, not fields themselves. This declaration destructures the owner
// without `..` and pins every field type, so a new or re-typed physical field does not
// compile until it is classified here. The State table inventory lists the result.
macro_rules! classified_transactions_storage {
    ($( $field:ident : $ty:ty => $role:expr; )+) => {
        /// Every physical field of [`TransactionsStorage`] in declaration order, with the
        /// canonical registry identities it holds or the reason it is node-local.
        #[cfg(test)]
        pub(in crate::state) const TRANSACTIONS_STORAGE_FIELDS: &[(&str, MembershipFieldRole)] =
            &[ $( (stringify!($field), $role), )+ ];
        fn check_transactions_storage_fields(owner: &TransactionsStorage) {
            let TransactionsStorage { $( $field, )+ } = owner;
            $( let _: &$ty = $field; )+
        }
        const _: fn(&TransactionsStorage) = check_transactions_storage_fields;
    };
}
classified_transactions_storage! {
    latest_block: TipStore => MembershipFieldRole::Canonical(
        &["state.transactions.frontier", "state.transactions.current"]);
    blocks: history::Map => MembershipFieldRole::Canonical(
        &["state.transactions.current", "state.transactions.rollback"]);
    write_lock: Mutex<Identity> => MembershipFieldRole::Local(
        "Writer lease and opaque publication identity; it rotates per writer and is never a row");
    budget: iroha_allocation::AllocationBudget => MembershipFieldRole::Local(
        "Original process-local allocation pool; a refusal defers and cannot change membership");
    pending: Mutex<Option<history::Pending>> => MembershipFieldRole::Local(
        "In-flight preparation of the next history generation; unpublished work, never committed membership");
    publication_sequence: AtomicU64 => MembershipFieldRole::Local(
        "Counter of local publications observed by readers; it orders publications and is no row");
    released: iroha_allocation::release::ReleaseNotification => MembershipFieldRole::Local(
        "Original-pool release notification of logical membership and preparation loans");
    history_released: iroha_allocation::release::ReleaseNotification => MembershipFieldRole::Local(
        "Original-pool release notification of the physical history writer");
}
type Tip = Shared<BlockInfo, AllocationCharge>;

/// Short lock protecting the shared committed tip pointer. The payload and its
/// charged backing stay alive independently through cloned readers.
#[derive(Default)]
struct TipStore(RwLock<Option<Tip>>);

impl TipStore {
    fn load_full(&self) -> Option<Tip> {
        self.0.read().clone()
    }

    fn load(&self) -> Option<Tip> {
        self.load_full()
    }

    fn swap(&self, next: Option<Tip>) -> Option<Tip> {
        std::mem::replace(&mut *self.0.write(), next)
    }

    fn store(&self, next: Option<Tip>) {
        drop(self.swap(next));
    }
}

/// Canonically sorted immutable keys in one exact charged backing allocation.
pub(crate) struct TipKeys(ChargedBuffer<Key>);

impl TipKeys {
    fn len(&self) -> usize {
        self.0.as_slice().len()
    }

    fn iter(&self) -> std::slice::Iter<'_, Key> {
        self.0.as_slice().iter()
    }

    fn contains<Q>(&self, key: &Q) -> bool
    where
        Key: Borrow<Q>,
        Q: Hash + Eq + Ord + ?Sized,
    {
        self.0
            .as_slice()
            .binary_search_by(|candidate| candidate.borrow().cmp(key))
            .is_ok()
    }
}

impl<'a> IntoIterator for &'a TipKeys {
    type Item = &'a Key;
    type IntoIter = std::slice::Iter<'a, Key>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl PartialEq for TipKeys {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}
impl Eq for TipKeys {}

impl PartialEq<HashSet<Key>> for TipKeys {
    fn eq(&self, other: &HashSet<Key>) -> bool {
        self.len() == other.len() && self.iter().all(|key| other.contains(key))
    }
}

impl std::fmt::Debug for TipKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

impl JsonSerializeTrait for TipKeys {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, key) in self.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            key.json_serialize(out);
        }
        out.push(']');
    }
}

struct BlockInfo {
    /// Transactions added in the block
    transactions: TipKeys,
    /// Height of the block.
    height: NonZeroUsize,
    #[cfg(test)]
    retirement_observer: std::sync::OnceLock<Arc<()>>,
}

#[cfg(test)]
struct TipWeak {
    pointer: *const BlockInfo,
    marker: std::sync::Weak<()>,
}

#[cfg(test)]
impl TipWeak {
    fn as_ptr(&self) -> *const BlockInfo {
        self.pointer
    }

    fn upgrade(&self) -> Option<Arc<()>> {
        self.marker.upgrade()
    }
}

#[cfg(test)]
fn tip_ptr(tip: &Tip) -> *const BlockInfo {
    std::ptr::from_ref(&**tip)
}

#[cfg(test)]
fn tip_weak_for_tests(tip: &Tip) -> TipWeak {
    TipWeak {
        pointer: tip_ptr(tip),
        marker: Arc::downgrade(tip.retirement_observer.get_or_init(|| Arc::new(()))),
    }
}

impl JsonSerializeTrait for BlockInfo {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        json::write_json_string("transactions", out);
        out.push(':');
        self.transactions.json_serialize(out);
        out.push(',');
        json::write_json_string("height", out);
        out.push(':');
        self.height.json_serialize(out);
        out.push('}');
    }
}

#[derive(crate::json_macros::JsonSerialize, crate::json_macros::JsonDeserialize)]
struct BlockInfoInput {
    transactions: HashSet<Key>,
    height: NonZeroUsize,
}

fn admit_tip(
    budget: &AllocationBudget,
    transactions: &HashSet<Key>,
    height: Value,
) -> Result<Tip, MembershipAdmissionError> {
    let backing = Layout::array::<Key>(transactions.len()).map_err(|_| {
        MembershipAdmissionError::Capacity(iroha_allocation::AllocationRefusal::DemandOverflow)
    })?;
    let shell = Tip::layout();
    let mut reservation = budget
        .try_reserve_layouts([shell, backing])
        .map_err(MembershipAdmissionError::Capacity)?;
    let shell_charge = reservation.try_split(shell).expect("admitted tip shell");
    let backing_charge = reservation
        .try_split(backing)
        .expect("admitted tip backing");
    let shell = Reserved::<BlockInfo, AllocationCharge>::try_new(shell_charge).map_err(
        |(_charge, error)| MembershipAdmissionError::Allocator {
            requested_bytes: error.layout().size(),
        },
    )?;
    let mut keys = ChargedBuffer::try_from_charge(transactions.len(), backing_charge).map_err(
        |(_charge, error)| match error {
            ChargedBufferFromChargeError::Allocator { layout } => {
                MembershipAdmissionError::Allocator {
                    requested_bytes: layout.size(),
                }
            }
            ChargedBufferFromChargeError::DemandOverflow
            | ChargedBufferFromChargeError::LayoutMismatch { .. } => {
                unreachable!("checked tip backing layout and charge")
            }
        },
    )?;
    for key in transactions {
        keys.append(std::slice::from_ref(key))
            .expect("admitted exact tip key count");
    }
    keys.as_mut_slice().sort_unstable();
    Ok(shell.initialize(BlockInfo {
        transactions: TipKeys(keys),
        height,
        #[cfg(test)]
        retirement_observer: Default::default(),
    }))
}

/// Staging refusal without converting local capacity into an invalid carrier.
#[derive(Debug)]
pub(crate) enum TipStageError {
    /// The original transaction-history pool or allocator refused this tip.
    Admission(MembershipAdmissionError),
    /// One ordinary input repeats a certified merge input.
    Overlap,
    /// The already staged height or canonical set differs from this attempt.
    ChangedPayload,
}

fn admit_tip_from_sources<I: ExactSizeIterator<Item = Key>>(
    budget: &AllocationBudget,
    ordinary: I,
    merge: &HashSet<Key>,
    height: Value,
) -> Result<Tip, TipStageError> {
    let capacity = ordinary.len().checked_add(merge.len()).ok_or_else(|| {
        TipStageError::Admission(MembershipAdmissionError::Capacity(
            iroha_allocation::AllocationRefusal::DemandOverflow,
        ))
    })?;
    let backing = Layout::array::<Key>(capacity).map_err(|_| {
        TipStageError::Admission(MembershipAdmissionError::Capacity(
            iroha_allocation::AllocationRefusal::DemandOverflow,
        ))
    })?;
    let shell = Tip::layout();
    let mut reservation = budget
        .try_reserve_layouts([shell, backing])
        .map_err(|error| TipStageError::Admission(MembershipAdmissionError::Capacity(error)))?;
    let shell_charge = reservation.try_split(shell).expect("admitted tip shell");
    let backing_charge = reservation
        .try_split(backing)
        .expect("admitted tip backing");
    let shell = Reserved::<BlockInfo, AllocationCharge>::try_new(shell_charge).map_err(
        |(_charge, error)| {
            TipStageError::Admission(MembershipAdmissionError::Allocator {
                requested_bytes: error.layout().size(),
            })
        },
    )?;
    let mut keys =
        ChargedBuffer::try_from_charge(capacity, backing_charge).map_err(|(_charge, error)| {
            match error {
                ChargedBufferFromChargeError::Allocator { layout } => {
                    TipStageError::Admission(MembershipAdmissionError::Allocator {
                        requested_bytes: layout.size(),
                    })
                }
                ChargedBufferFromChargeError::DemandOverflow
                | ChargedBufferFromChargeError::LayoutMismatch { .. } => {
                    unreachable!("checked tip backing layout and charge")
                }
            }
        })?;
    for key in ordinary {
        if merge.contains(&key) {
            return Err(TipStageError::Overlap);
        }
        keys.append(std::slice::from_ref(&key))
            .expect("admitted ordinary key capacity");
    }
    for key in merge {
        keys.append(std::slice::from_ref(key))
            .expect("admitted merge key capacity");
    }
    let sorted = keys.as_mut_slice();
    sorted.sort_unstable();
    let mut unique = 0;
    for index in 0..sorted.len() {
        if unique == 0 || sorted[index] != sorted[unique - 1] {
            sorted[unique] = sorted[index];
            unique += 1;
        }
    }
    keys.truncate(unique);
    Ok(shell.initialize(BlockInfo {
        transactions: TipKeys(keys),
        height,
        #[cfg(test)]
        retirement_observer: Default::default(),
    }))
}
impl TransactionsStorage {
    /// Observe the original physical history writer, independently of logical
    /// membership observation or cleanup. Readiness only permits a fresh probe.
    fn history_release_wait(&self) -> iroha_allocation::release::ReleaseWait {
        #[cfg(all(test, sumeragi_core_mutation = "HC73"))]
        return self.released.observe();
        #[cfg(not(all(test, sumeragi_core_mutation = "HC73")))]
        self.history_released.observe()
    }

    /// Construct a finite-pool fixture; production supplies its original Kura pool.
    #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
    pub fn new() -> Self {
        Self::try_new(iroha_allocation::AllocationBudget::new(256 * 1024 * 1024))
            .expect("finite fixture membership pool")
    }
    #[cfg(test)]
    pub(in crate::state) fn reader_release_wait_for_tests(
        &self,
    ) -> iroha_allocation::release::ReleaseWait {
        self.blocks.observe_reader_release()
    }
    #[cfg(test)]
    pub(in crate::state) fn reader_test_writer_available(&self) -> bool {
        self.write_lock
            .try_lock()
            .map(|guard| self.released.guard(guard))
            .is_some()
    }
    /// Probe both original writer mutexes independently; poison is a separate result.
    #[cfg(test)]
    pub(in crate::state) fn replay_writer_probe_for_tests(&self) -> (bool, bool, bool) {
        let logical = self.write_lock.try_lock();
        let physical = self.blocks.try_acquire_writer();
        let result = (
            logical.is_some(),
            physical.is_some(),
            self.blocks.is_poisoned(),
        );
        drop((logical, physical));
        result
    }
    /// Retain the actual reader-lock source outside an enclosing physical owner.
    pub(crate) fn reader_release_batch(&self) -> iroha_allocation::release::DeferredReleaseBatch {
        self.blocks.reader_release_batch()
    }
    /// Pin one complete original membership generation without waiting.
    /// Actual reader unlocks remain in the caller's source-bound release owner.
    pub(crate) fn try_view_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<TransactionsView<'_>, super::StateViewError> {
        let publication = self.released.observe();
        let before = self.publication_sequence.load(Ordering::Acquire);
        if before & 1 != 0 {
            return Err(super::StateViewError::Busy(publication));
        }
        let latest_block = self.latest_block.load_full();
        let reader = self.blocks.observe_reader_release();
        let blocks = self
            .blocks
            .try_read_retaining(releases)
            .map_err(|error| match error {
                concread::bptree::OwnedWriteError::Busy => super::StateViewError::Busy(reader),
                concread::bptree::OwnedWriteError::Poisoned => super::StateViewError::Poisoned,
                concread::bptree::OwnedWriteError::Changed => super::StateViewError::Changed,
            })?;
        if before != self.publication_sequence.load(Ordering::Acquire) {
            return Err(super::StateViewError::Busy(publication));
        }
        Ok(TransactionsView {
            latest_block,
            blocks,
        })
    }
    /// Synchronously retry the same reader kernel, retaining notices outside the caller.
    pub(crate) fn view_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<TransactionsView<'_>, concread::bptree::OwnedWriteError> {
        loop {
            match self.try_view_retaining(releases) {
                Ok(view) => return Ok(view),
                Err(super::StateViewError::Busy(_)) => std::thread::yield_now(),
                Err(super::StateViewError::Poisoned) => {
                    return Err(concread::bptree::OwnedWriteError::Poisoned);
                }
                Err(_) => return Err(concread::bptree::OwnedWriteError::Changed),
            }
        }
    }
    /// Pin one exact committed generation through the same original reader kernel.
    pub fn view(&self) -> TransactionsView<'_> {
        let mut releases = self.reader_release_batch();
        self.view_retaining(&mut releases)
            .expect("original membership reader source must be healthy")
    }
    /// Return the latest committed block height recorded by entrypoint storage.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn latest_height(&self) -> usize {
        self.latest_block
            .load()
            .as_ref()
            .map_or(0, |block| block.height.get())
    }
    /// Seed canonical entrypoint membership without constructing fixture blocks.
    #[cfg(test)]
    pub(crate) fn record_committed_entrypoint_membership_for_tests(
        &self,
        entrypoints: impl IntoIterator<Item = HashOf<TransactionEntrypoint>>,
        height: NonZeroUsize,
    ) {
        self.budget.with_deferred_refund_notifications(|_| {
            let mut guard = self.released.guard(self.write_lock.lock());
            let next_identity =
                history::new_identity(&self.budget).expect("fixture identity admission");
            let entrypoints = entrypoints.into_iter().collect::<HashSet<_>>();
            let latest = self.latest_block.load_full();
            let mut writer = self
                .blocks
                .try_write_admitted(|d| history::admit(&self.budget, d))
                .expect("fixture history cursor");
            let next_tip = match latest.as_deref() {
                Some(block) if block.height > height => {
                    for key in entrypoints {
                        writer
                            .try_insert_admitted(key, height, |d| history::admit(&self.budget, d))
                            .expect("fixture history insert");
                    }
                    latest
                }
                Some(block) if block.height == height => {
                    let mut updated = block.transactions.iter().copied().collect::<HashSet<_>>();
                    updated.extend(entrypoints);
                    Some(admit_tip(&self.budget, &updated, height).expect("fixture tip admission"))
                }
                Some(block) => {
                    for key in &block.transactions {
                        writer
                            .try_insert_admitted(*key, block.height, |d| {
                                history::admit(&self.budget, d)
                            })
                            .expect("fixture history promotion");
                    }
                    Some(
                        admit_tip(&self.budget, &entrypoints, height)
                            .expect("fixture tip admission"),
                    )
                }
                None => Some(
                    admit_tip(&self.budget, &entrypoints, height).expect("fixture tip admission"),
                ),
            };
            let sequence = self.publication_sequence.load(Ordering::Relaxed);
            let next = sequence
                .checked_add(2)
                .expect("fixture publication sequence");
            self.publication_sequence
                .store(sequence + 1, Ordering::Release);
            let retirement = writer.prepare_commit().publish().release();
            let old_tip = self.latest_block.swap(next_tip);
            let old_identity = std::mem::replace(&mut **guard, next_identity);
            self.publication_sequence.store(next, Ordering::Release);
            drop(guard);
            drop((retirement, old_tip, old_identity));
        });
    }
    /// Deliberately corrupt an existing fixture membership without advancing its cut.
    #[cfg(test)]
    pub(crate) fn overwrite_committed_entrypoint_membership_for_tests(
        &self,
        entrypoint: Key,
        height: Value,
    ) {
        self.budget.with_deferred_refund_notifications(|_| {
            let mut guard = self.released.guard(self.write_lock.lock());
            let next_identity =
                history::new_identity(&self.budget).expect("fixture identity admission");
            assert!(
                self.view().get(&entrypoint).is_some(),
                "overwrite needs existing membership"
            );
            let latest = self
                .latest_block
                .load_full()
                .expect("existing membership has a frontier");
            assert!(
                height <= latest.height,
                "corruption must not advance the fixture frontier"
            );
            let mut updated = latest.transactions.iter().copied().collect::<HashSet<_>>();
            updated.remove(&entrypoint);
            let mut writer = self
                .blocks
                .try_write_admitted(|d| history::admit(&self.budget, d))
                .expect("fixture history cursor");
            writer
                .try_remove_admitted(&entrypoint, |d| history::admit(&self.budget, d))
                .expect("fixture history removal");
            if height == latest.height {
                updated.insert(entrypoint);
            } else {
                writer
                    .try_insert_admitted(entrypoint, height, |d| history::admit(&self.budget, d))
                    .expect("fixture history corruption");
            }
            let sequence = self.publication_sequence.load(Ordering::Relaxed);
            let next = sequence
                .checked_add(2)
                .expect("fixture publication sequence");
            self.publication_sequence
                .store(sequence + 1, Ordering::Release);
            let retirement = writer.prepare_commit().publish().release();
            let replacement = admit_tip(&self.budget, &updated, latest.height)
                .expect("fixture replacement tip admission");
            let old_tip = self.latest_block.swap(Some(replacement));
            let old_identity = std::mem::replace(&mut **guard, next_identity);
            self.publication_sequence.store(next, Ordering::Release);
            drop(guard);
            drop((retirement, old_tip, old_identity));
        });
    }
    /// Create a fixture block with the same finite original preparation owner.
    #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
    pub fn block(&self) -> TransactionsBlock<'_> {
        self.block_impl(false)
    }
    /// Create a fixture replacement using the same original history authority.
    #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
    pub fn block_and_revert(&self) -> TransactionsBlock<'_> {
        self.block_impl(true)
    }
    #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
    fn block_impl(&self, replacement: bool) -> TransactionsBlock<'_> {
        let mut pending = Some(
            self.prepare_next_block(replacement)
                .expect("fixture history admission"),
        );
        self.attach_prepared(&mut pending)
            .expect("fixture original predecessor")
    }
    /// Attach only the retained original pre-World preparation. On refusal the
    /// caller still owns it; no charged cursor is destroyed under other fences.
    pub(crate) fn attach_prepared<'a>(
        &'a self,
        pending: &mut Option<history::Pending>,
    ) -> Result<TransactionsBlock<'a>, MembershipAdmissionError> {
        let original = pending
            .as_mut()
            .expect("original pre-World membership preparation");
        let wait = self.released.observe();
        // A foreign family cannot acquire this target's notification authority.
        let baseline = self
            .blocks
            .read_predecessor(original.baseline.as_ref().expect("original history cut"))
            .ok_or_else(|| MembershipAdmissionError::Changed(wait.clone()))?;
        let guard = self
            .write_lock
            .try_lock()
            .ok_or_else(|| MembershipAdmissionError::Busy(wait.clone()))?;
        if !Identity::ptr_eq(&guard, &original.predecessor) {
            let released = self
                .released
                .guard(guard)
                .try_release_into(&mut original.attachment_releases, drop);
            assert!(released.is_ok(), "original preparation release family");
            return Err(MembershipAdmissionError::Changed(wait));
        }
        let original = pending.take().expect("checked original preparation");
        let revert = original.replacement;
        Ok(TransactionsBlock {
            latest_block_ref: &self.latest_block,
            budget_ref: &self.budget,
            blocks_ref: &self.blocks,
            baseline,
            publication_sequence: &self.publication_sequence,
            _guard: block::MembershipWriter::new(
                self.released.guard(guard),
                Some(history_slot::Slot::new(self, original)),
            ),
            revert,
            current_block: None,
        })
    }
}
/// Read the logical committed cut, excluding the abandoned tip during replacement.
fn membership_at_cut<Q>(
    latest: Option<&BlockInfo>,
    history: &HistoryReader<'_>,
    undo_latest: bool,
    key: &Q,
) -> Option<Value>
where
    Key: Borrow<Q>,
    Q: Hash + Eq + Ord + ?Sized,
{
    let latest = latest?;
    if !undo_latest && latest.transactions.contains(key) {
        Some(latest.height)
    } else {
        history
            .get(key)
            .map(|height| *height)
            .filter(|height| *height < latest.height)
    }
}

/// Persistent view of storage at certain point in time
pub trait TransactionsReadOnly {
    /// Read entry from the storage
    fn get<Q>(&self, key: &Q) -> Option<Value>
    where
        Key: Borrow<Q>,
        Q: Hash + Eq + Ord + ?Sized;
}
/// Module for [`TransactionsView`] and it's related impls
mod view {
    use super::*;
    /// Consistent view of the storage at the certain version
    #[derive(Clone)]
    pub struct TransactionsView<'storage> {
        pub(super) latest_block: Option<Tip>,
        /// Some transactions may be added to the map after `Self` is created,
        /// but for us exists only transactions with `height < latest_block.height`
        pub(super) blocks: HistoryReader<'storage>,
    }
    impl TransactionsReadOnly for TransactionsView<'_> {
        fn get<Q>(&self, key: &Q) -> Option<Value>
        where
            Key: Borrow<Q>,
            Q: Hash + Eq + Ord + ?Sized,
        {
            membership_at_cut(self.latest_block.as_deref(), &self.blocks, false, key)
        }
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    impl TransactionsView<'_> {
        /// Test helper: return the latest committed block height (0 when empty).
        pub fn latest_height_for_tests(&self) -> usize {
            self.latest_block
                .as_ref()
                .map_or(0, |block| block.height.get())
        }
    }
}
pub use view::TransactionsView;
/// Module for [`TransactionsBlock`] and it's related impls
mod block {
    use super::*;
    use crate::state::LaneLifecycleError;
    /// Batched update to the storage that can be reverted later.
    ///
    /// The block aggregates transaction hashes for a particular block height. Call [`insert_block`]
    /// exactly once to register the transactions and height. After all updates are collected,
    /// [`commit`](Self::commit) can be used to persist them in [`TransactionsStorage`].
    ///
    /// Committing a block without first calling [`insert_block`] is considered an error and will
    /// cause [`commit`](Self::commit) to fail. See the release-mode tests for examples. Errors that
    /// can occur when committing [`TransactionsBlock`]
    #[derive(thiserror::Error, Debug, displaydoc::Display)]
    #[ignore_extra_doc_attributes]
    pub enum TransactionsBlockError {
        /// Original local State storage refusal; never a consensus rejection: {0}
        LocalStateStorage(#[source] crate::state::StateStorageAdmissionError),
        /// The original prepaid history could not acquire its publication locks.
        MembershipAdmission(#[source] MembershipAdmissionError),
        /// The original hash publication reader or writer is busy
        BlockHashesBusy(iroha_allocation::release::ReleaseWait),
        /// An original World, runtime or membership publication participant is busy
        PublicationBusy(iroha_allocation::release::ReleaseWait),
        /// Local execution resources refused publication before any effects: {0}
        ExecutionDeferred(#[source] crate::execution_attempt::ExecutionDeferred),
        /// `TransactionsBlock::insert_block()` was not called
        MissingInsertBlock,
        /// Block height `{actual_current_height}` does not match expected `{expected_current_height}`;
        /// callers should abort the block and retry against the latest state view.
        HeightMismatch {
            /// Height expected by the storage while committing the block.
            expected_current_height: usize,
            /// Height encoded in the block being committed.
            actual_current_height: usize,
        },
        /// The next transaction-membership height exceeds the storage representation
        HeightOverflow,
        /// Deterministic autoscale lane lifecycle failed while preparing block commit
        AutoscaleLaneLifecycle,
        /// Local lane geometry publication retains its original refusal: {0}
        LocalLaneGeometry(#[source] crate::state::LaneLifecycleError),
        /// Certified merge admission changed before the block could commit
        MergeAdmission,
        /// Finalized FASTPQ source ownership is invalid at block commit
        FastpqSourceInventory,
        /// Execution outputs require their canonical consuming publication owner
        ExecutionOutputCapacity,
        /// Frozen lane consensus metadata changed after its authenticated capture
        LaneConsensusContexts,
        /// Permanent AXT handle counter could not finalize its block transition
        AxtCounterRatchet,
        /// Live asset-definition incarnations are inconsistent with the registry
        AxtAssetIncarnation,
        /// Prepared World commit does not match the actual State or target height
        WorldCommitPreparation,
        /// The applying State was busy or changed during its complete snapshot observation
        SnapshotObservationChanged,
        /// A stable State snapshot projection or encoding is malformed
        SnapshotProjection,
        /// This original State publication has already entered terminal recovery
        PublicationRecoveryRequired,
    }
    impl From<crate::state::LaneLifecycleError> for TransactionsBlockError {
        fn from(error: crate::state::LaneLifecycleError) -> Self {
            match error {
                error @ (LaneLifecycleError::Storage(_)
                | LaneLifecycleError::GeometryStorage(_)
                | LaneLifecycleError::DrainObservation(_)
                | LaneLifecycleError::PublicationBusy { .. }) => Self::LocalLaneGeometry(error),
                _ => Self::AutoscaleLaneLifecycle,
            }
        }
    }
    /// Batched update to the storage that can be reverted later
    pub struct TransactionsBlock<'storage> {
        /// References to [`TransactionsStorage`] struct
        pub(super) latest_block_ref: &'storage TipStore,
        pub(super) budget_ref: &'storage AllocationBudget,
        pub(super) blocks_ref: &'storage history::Map,
        pub(super) baseline: HistoryReader<'storage>,
        pub(super) publication_sequence: &'storage AtomicU64,
        pub(super) _guard: MembershipWriter<'storage>,
        /// Own fields
        pub(super) revert: bool,
        pub(super) current_block: Option<Tip>,
    }
    /// An admitted membership transition retaining its original exclusive writer.
    ///
    /// Dropping this owner leaves storage unchanged. Publication consumes the
    /// exact admitted action without consulting a new frontier or admitting a
    /// different payload. Shared reads remain available for State snapshots.
    pub(crate) struct PreparedTransactionsBlock<'storage> {
        block: TransactionsBlock<'storage>,
        publication: MembershipPublication,
        next_identity: Identity,
        // Fixed original-owner metadata. During publication the admitted action
        // stays in place, and every displaced allocation stays in this caller.
        retired_tip: Option<Tip>,
        publication_started: bool,
        published: bool,
    }

    /// An admitted transition whose original physical writer has been released.
    ///
    /// All payload sets are moved or share their original immutable allocation.
    /// This owner exposes no live-history reader. Publication preparation must
    /// reacquire its exact predecessor; the aggregate State publisher must
    /// retain every prepared component before publishing any of them.
    pub(crate) struct DetachedTransactionsBlock {
        predecessor_identity: Identity,
        history: history::Pending,
        predecessor: Option<Tip>,
        current: Tip,
        revert: bool,
        publication: MembershipPublication,
        next_identity: Identity,
    }

    /// Exact admitted membership with its writer reacquired for publication.
    ///
    /// The installation admission outlives the writer even when this owner is
    /// abandoned. Publication returns that admission to the aggregate owner.
    pub(crate) struct PreparedDetachedTransactionsBlock<'storage, Installation> {
        prepared: PreparedTransactionsBlock<'storage>,
        installation: Installation,
        preflight_release: Option<iroha_allocation::release::DeferredRelease>,
    }

    /// All original history retirement and physical release observations.
    pub(crate) struct MembershipRelease {
        _history: Option<history_slot::Cleanup>,
        _writer: iroha_allocation::release::DeferredRelease,
    }

    /// Original membership payloads and notification after its physical unlock.
    /// The enclosing publisher retires this only after all its fences release.
    pub(crate) struct TransactionsPublicationRetirement {
        _tip: Option<Tip>,
        _staged: Option<Tip>,
        _identity: Identity,
        _publication: MembershipPublication,
        _release: MembershipRelease,
    }

    /// Original abort or refusal cleanup retained with installation admission.
    pub(crate) struct AbortedTransactions<Installation> {
        _installation: Option<Installation>,
        _preflight_release: Option<iroha_allocation::release::DeferredRelease>,
        _release: Option<MembershipRelease>,
    }

    /// Published membership cleanup retained with its installation admission.
    pub(crate) struct PublishedTransactions<Installation> {
        _retirement: TransactionsPublicationRetirement,
        _installation: Installation,
        _preflight_release: Option<iroha_allocation::release::DeferredRelease>,
    }

    /// A short observation, never authorization to publish a detached journal.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum MembershipPredecessorStatus {
        /// Another writer owns the observation boundary.
        Busy,
        /// Both membership representations still have the captured identity.
        Current,
        /// Some committed membership changed after capture.
        Changed,
    }

    #[path = "capture.rs"]
    mod capture;
    pub(super) use capture::MembershipWriter;
    pub use capture::TransactionsBlockField;
    #[cfg(test)]
    pub(crate) use capture::TransactionsCaptureSlot;

    #[path = "detached_publication.rs"]
    mod detached_publication;
    pub(crate) use detached_publication::DetachedTransactionsPublicationSlot;

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: retain authenticated membership roots in the complete State publisher"
        )
    )]
    #[path = "membership_root.rs"]
    mod membership_root;

    #[cfg(test)]
    #[path = "detached_publication_tests.rs"]
    mod detached_publication_tests;

    #[cfg(test)]
    #[path = "capture_tests.rs"]
    mod capture_tests;

    enum MembershipPublication {
        Repeated,
        Replace {
            current: Tip,
        },
        Advance {
            // Keep the exact previous hot tip through publication-owner retirement.
            _previous: Option<Tip>,
            current: Tip,
        },
    }

    impl TransactionsBlock<'_> {
        /// Return whether a canonical block membership update was staged.
        pub(crate) fn has_staged_block(&self) -> bool {
            self._guard.identity();
            self.current_block.is_some()
        }
        /// Return whether the staged canonical carrier has the exact height and
        /// entrypoint membership.
        pub(crate) fn has_exact_staged_block(
            &self,
            height: NonZeroUsize,
            transactions: &HashSet<Key>,
        ) -> bool {
            self._guard.identity();
            self.current_block
                .as_ref()
                .is_some_and(|block| block.height == height && &block.transactions == transactions)
        }
        /// Build the canonical tip directly in prepaid storage. An overlap or
        /// local refusal changes neither the staged nor committed membership.
        pub(crate) fn try_stage_block(
            &mut self,
            ordinary: &mut [Key],
            merge: &HashSet<Key>,
            height: Value,
        ) -> Result<(), TipStageError> {
            self._guard.identity();
            if ordinary.iter().any(|key| merge.contains(key)) {
                return Err(TipStageError::Overlap);
            }
            if let Some(current) = &self.current_block {
                ordinary.sort_unstable();
                let unique_ordinary = usize::from(!ordinary.is_empty())
                    + ordinary
                        .windows(2)
                        .filter(|pair| pair[0] != pair[1])
                        .count();
                let expected_len = unique_ordinary.checked_add(merge.len());
                return if current.height == height
                    && expected_len == Some(current.transactions.len())
                    && ordinary
                        .iter()
                        .all(|key| current.transactions.contains(key))
                    && merge.iter().all(|key| current.transactions.contains(key))
                {
                    Ok(())
                } else {
                    Err(TipStageError::ChangedPayload)
                };
            }
            let candidate =
                admit_tip_from_sources(self.budget_ref, ordinary.iter().copied(), merge, height)?;
            self.current_block = Some(candidate);
            Ok(())
        }
        /// Register transactions belonging to the block.
        ///
        /// This method **must** be called before [`commit`]. Calling it more than once with the
        /// same block payload is a no-op, while changing the height or the transaction set triggers
        /// a panic. Attempting to commit without inserting a block results in an error (see
        /// `commit_without_insert_block_fails`).
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        pub(crate) fn try_insert_block(
            &mut self,
            transactions: HashSet<Key>,
            height: Value,
        ) -> Result<(), MembershipAdmissionError> {
            self._guard.identity();
            if let Some(current_block) = &self.current_block {
                assert_eq!(
                    current_block.height, height,
                    "`TransactionsBlock::insert_block()` called multiple times with different height"
                );
                assert_eq!(
                    current_block.transactions, transactions,
                    "`TransactionsBlock::insert_block()` called multiple times with different transactions"
                );
                return Ok(());
            }
            self.current_block = Some(admit_tip(self.budget_ref, &transactions, height)?);
            Ok(())
        }
        /// Infallible finite-pool fixture staging; runtime calls the typed path.
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        pub fn insert_block(&mut self, transactions: HashSet<Key>, height: Value) {
            self.try_insert_block(transactions, height)
                .expect("fixture hot-tip admission");
        }
        #[cfg(test)]
        pub fn insert_block_with_single_tx(&mut self, tx: Key, height: Value) {
            let transactions = [tx].into_iter().collect();
            self.insert_block(transactions, height);
        }
        /// Apply aggregated changes to the storage.
        ///
        /// # Errors
        /// Returns an error if [`insert_block`] was not called prior to committing or if the block
        /// height being committed does not match the expected height derived from the current
        /// storage state. These behaviours are illustrated in the release-mode tests.
        pub fn commit(self) -> Result<(), TransactionsBlockError> {
            let mut capture = self.capture_slot();
            capture.try_prepare()?;
            capture.try_prepare_physical()?;
            capture.publish_prepared();
            Ok(())
        }
        /// Validate that this block can be committed without mutating the storage.
        ///
        /// This lets callers perform other fallible commit preparation after the transaction height
        /// has been proven acceptable, but before consuming the transaction block.
        pub(crate) fn validate_commit(&self) -> Result<(), TransactionsBlockError> {
            self.admit_publication().map(|_| ())
        }
        fn admit_publication(&self) -> Result<MembershipPublication, TransactionsBlockError> {
            self._guard.identity();
            let previous_block = self.latest_block_ref.load_full();
            let previous_height = previous_block.as_ref().map_or(0, |b| b.height.get());
            let Some(current_block) = self.current_block.as_ref() else {
                return Err(TransactionsBlockError::MissingInsertBlock);
            };
            if !self.revert
                && previous_block.as_ref().is_some_and(|previous_block| {
                    previous_block.height == current_block.height
                        && previous_block.transactions == current_block.transactions
                })
            {
                return Ok(MembershipPublication::Repeated);
            }
            let addition = usize::from(!self.revert);
            let expected_current_height = previous_height
                .checked_add(addition)
                .ok_or(TransactionsBlockError::HeightOverflow)?;
            let current_height = current_block.height.get();
            if expected_current_height != current_height {
                return Err(TransactionsBlockError::HeightMismatch {
                    expected_current_height,
                    actual_current_height: current_height,
                });
            }
            if self.revert {
                Ok(MembershipPublication::Replace {
                    current: current_block.clone(),
                })
            } else {
                Ok(MembershipPublication::Advance {
                    _previous: previous_block,
                    current: current_block.clone(),
                })
            }
        }
    }
    #[cfg(test)]
    impl<'storage> TransactionsBlock<'storage> {
        /// Admit the exact staged transition and retain its exclusive writer.
        ///
        /// This performs all membership validation before publication. Failure
        /// drops the staging scope without modifying committed membership.
        pub(crate) fn prepare_commit(
            self,
        ) -> Result<PreparedTransactionsBlock<'storage>, TransactionsBlockError> {
            let mut capture = self.capture_slot();
            capture.try_prepare()?;
            Ok(capture.into_prepared())
        }
    }

    impl<'storage> PreparedTransactionsBlock<'storage> {
        fn new(
            block: TransactionsBlock<'storage>,
            publication: MembershipPublication,
            next_identity: Identity,
        ) -> Self {
            Self {
                block,
                publication,
                next_identity,
                retired_tip: None,
                publication_started: false,
                published: false,
            }
        }

        /// Terminal publication markers never grant a fresh capture borrow.
        fn is_unpublished_for_capture(&self) -> bool {
            #[cfg(all(test, sumeragi_core_mutation = "HC155"))]
            {
                true
            }
            #[cfg(not(all(test, sumeragi_core_mutation = "HC155")))]
            {
                !self.publication_started && !self.published
            }
        }

        /// Borrow only the logically admitted unpublished original membership writer.
        pub(in crate::state::storage_transactions) fn unpublished_membership_block(
            &self,
        ) -> &TransactionsBlock<'storage> {
            self.assert_unpublished();
            &self.block
        }

        fn assert_unpublished(&self) {
            assert!(
                !self.publication_started && !self.published,
                "membership publication was already attempted"
            );
        }

        /// Move the admitted action and exact cut, then release the writer.
        ///
        /// This adds no collection allocation or copy. Snapshot/checkpoint
        /// projections must already have consumed the original locked reader.
        #[cfg(test)]
        pub(crate) fn detach(self) -> DetachedTransactionsBlock {
            self.detach_retaining().0
        }

        fn detach_retaining(self) -> (DetachedTransactionsBlock, MembershipRelease) {
            self.assert_unpublished();
            let Self {
                block,
                publication,
                next_identity,
                retired_tip: _,
                publication_started: _,
                published: _,
            } = self;
            let mut block = block;
            let history = block
                ._guard
                .history
                .as_mut()
                .expect("original history")
                .recover_detached();
            let detached = DetachedTransactionsBlock {
                history,
                predecessor_identity: block._guard.identity().clone(),
                predecessor: block.latest_block_ref.load_full(),
                current: block
                    .current_block
                    .as_ref()
                    .expect("admitted membership")
                    .clone(),
                revert: block.revert,
                publication,
                next_identity,
            };
            let TransactionsBlock {
                _guard,
                current_block,
                ..
            } = block;
            let release = _guard.into_release();
            // The detached journal owns the original staged allocation.
            drop(current_block);
            (detached, release)
        }

        /// Borrow immutable staged membership and its actual predecessor.
        pub(crate) fn as_block(&self) -> &TransactionsBlock<'storage> {
            &self.block
        }

        /// Publish the admitted transition once, retaining its writer throughout.
        ///
        /// All semantic refusal happened during preparation. The retained mutex
        /// prevents any other membership writer from changing the admitted cut.
        /// The separate fallible physical phase must already own the native
        /// writer/reader pair; the tip-pointer swap takes only its short
        /// in-process lock and does not perform fallible admission.
        /// The returned owner defers payload cleanup and retry callbacks until
        /// the caller has released every enclosing publication fence.
        fn publish_prepared(mut self) -> TransactionsPublicationRetirement {
            self.publish_in_place();
            self.into_retirement()
        }

        /// Standalone fixture publication uses the same explicit physical phase.
        #[cfg(test)]
        pub(crate) fn publish(mut self) -> TransactionsPublicationRetirement {
            self.try_prepare_physical()
                .expect("fixture physical membership admission");
            self.publish_prepared()
        }

        /// Retain the exact native writer/reader pair before the publication kernel.
        /// Refusal leaves this original prepared owner available for local retry.
        pub(in crate::state) fn try_prepare_physical(
            &mut self,
        ) -> Result<(), TransactionsBlockError> {
            self.assert_unpublished();
            if !matches!(&self.publication, MembershipPublication::Repeated) {
                self.block
                    ._guard
                    .history
                    .as_mut()
                    .expect("original history")
                    .prepare()
                    .map_err(TransactionsBlockError::MembershipAdmission)?;
            }
            Ok(())
        }

        fn is_physically_prepared(&self) -> bool {
            matches!(&self.publication, MembershipPublication::Repeated)
                || self
                    .block
                    ._guard
                    .history
                    .as_ref()
                    .expect("original history")
                    .is_prepared()
        }

        // The caller retains this complete owner throughout every map operation.
        // No original action, guard, or displaced payload is moved to a callee
        // local that could notify or reclaim under a sibling on unwind.
        fn publish_in_place(&mut self) {
            self.assert_unpublished();
            assert!(
                self.is_physically_prepared(),
                "original physical membership preparation must precede publication"
            );
            self.block._guard.identity();
            self.publication_started = true;
            if !matches!(&self.publication, MembershipPublication::Repeated) {
                let next = self
                    .block
                    ._guard
                    .history
                    .as_ref()
                    .expect("original history")
                    .next_sequence();
                self.block
                    .publication_sequence
                    .store(next - 1, Ordering::Release);
                self.block
                    ._guard
                    .history
                    .as_mut()
                    .expect("original history")
                    .publish();
                let current = match &self.publication {
                    MembershipPublication::Replace { current }
                    | MembershipPublication::Advance { current, .. } => current,
                    MembershipPublication::Repeated => unreachable!(),
                };
                self.retired_tip = self.block.latest_block_ref.swap(Some(current.clone()));
                self.block
                    .publication_sequence
                    .store(next, Ordering::Release);
            }
            if !matches!(&self.publication, MembershipPublication::Repeated) {
                // Install the exact pre-admitted identity and retain its exact
                // predecessor in the same field. No identity is reconstructed.
                std::mem::swap(self.block._guard.identity_mut(), &mut self.next_identity);
            }
            self.block.release_writers();
            self.published = true;
        }

        fn into_retirement(self) -> TransactionsPublicationRetirement {
            assert!(
                self.published,
                "original membership publication must complete"
            );
            let Self {
                block,
                publication,
                next_identity,
                retired_tip,
                publication_started: _,
                published: _,
            } = self;
            let TransactionsBlock {
                current_block,
                _guard,
                ..
            } = block;
            let release = _guard.into_release();
            TransactionsPublicationRetirement {
                _tip: retired_tip,
                _staged: current_block,
                _identity: next_identity,
                _publication: publication,
                _release: release,
            }
        }
    }
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect retained journals to the consuming State publisher"
        )
    )]
    impl DetachedTransactionsBlock {
        /// Admit installation and reacquire the original predecessor without waiting.
        ///
        /// No transaction set is rebuilt or admitted again. The callback must
        /// account for history-map insertion and reader retention before the
        /// writer is acquired. A refusal returns the original journal intact.
        /// This component does not establish aggregate State/finality authority.
        pub(crate) fn try_prepare_publication<'storage, Installation, E>(
            self,
            storage: &'storage TransactionsStorage,
            admit: impl FnOnce(&Self, &TransactionsStorage) -> Result<Installation, E>,
        ) -> Result<
            PreparedDetachedTransactionsBlock<'storage, Installation>,
            (
                Self,
                mv::PublicationPreparationError<E>,
                AbortedTransactions<Installation>,
            ),
        > {
            let mut slot = self.publication_slot(storage);
            match slot.try_prepare(admit) {
                Ok(()) => Ok(slot.into_prepared()),
                Err(error) => {
                    let original = slot.recover_original();
                    Err((original, error, slot.into_cleanup()))
                }
            }
        }

        /// Borrow the exact admitted carrier height and immutable membership.
        pub(crate) fn staged_membership(&self) -> (Value, &TipKeys) {
            (self.current.height, &self.current.transactions)
        }

        /// Whether admission reverted the original committed tip first.
        pub(crate) fn replaces_tip(&self) -> bool {
            self.revert
        }

        /// Height of the original committed cut, including a replaced tip.
        pub(crate) fn predecessor_height(&self) -> usize {
            self.predecessor
                .as_ref()
                .map_or(0, |block| block.height.get())
        }

        /// Observe a target's exact captured identity without blocking on its writer.
        /// A different storage, including one restored from identical bytes, differs.
        ///
        /// The result is advisory: an aggregate publisher must retain all
        /// journal writers while checking identities and publishing together.
        pub(crate) fn observe_predecessor(
            &self,
            storage: &TransactionsStorage,
        ) -> MembershipPredecessorStatus {
            let Some(guard) = storage.write_lock.try_lock() else {
                return MembershipPredecessorStatus::Busy;
            };
            let guard = storage.released.guard(guard);
            if Identity::ptr_eq(&guard, &self.predecessor_identity) {
                MembershipPredecessorStatus::Current
            } else {
                MembershipPredecessorStatus::Changed
            }
        }
    }
    impl<Installation> PreparedDetachedTransactionsBlock<'_, Installation> {
        /// Release the physical writer and recover the same admitted journal.
        pub(crate) fn abort(
            self,
        ) -> (DetachedTransactionsBlock, AbortedTransactions<Installation>) {
            let Self {
                prepared,
                installation,
                preflight_release,
            } = self;
            let (journal, release) = prepared.detach_retaining();
            (
                journal,
                AbortedTransactions {
                    _release: Some(release),
                    _installation: Some(installation),
                    _preflight_release: preflight_release,
                },
            )
        }

        /// Consume the original action and retain cleanup with installation admission.
        ///
        /// The caller must already hold all other component writers and the
        /// exact aggregate publication authorization before calling this method.
        pub(crate) fn publish(self) -> PublishedTransactions<Installation> {
            let Self {
                prepared,
                installation,
                preflight_release,
            } = self;
            PublishedTransactions {
                _retirement: prepared.publish_prepared(),
                _installation: installation,
                _preflight_release: preflight_release,
            }
        }
    }
    impl TransactionsReadOnly for PreparedTransactionsBlock<'_> {
        fn get<Q>(&self, key: &Q) -> Option<Value>
        where
            Key: Borrow<Q>,
            Q: Hash + Eq + Ord + ?Sized,
        {
            self.block.get(key)
        }
    }
    impl TransactionsReadOnly for TransactionsBlock<'_> {
        fn get<Q>(&self, key: &Q) -> Option<Value>
        where
            Key: Borrow<Q>,
            Q: Hash + Eq + Ord + ?Sized,
        {
            self._guard.identity();
            if let Some(height) = self
                .current_block
                .as_ref()
                .and_then(|block| block.transactions.contains(key).then_some(block.height))
            {
                return Some(height);
            }
            let latest = self.latest_block_ref.load();
            membership_at_cut(latest.as_deref(), &self.baseline, self.revert, key)
        }
    }
}
#[cfg(test)]
pub(crate) use block::MembershipPredecessorStatus;
pub(crate) use block::PreparedTransactionsBlock;
#[cfg(test)]
pub(crate) use block::{DetachedTransactionsBlock, PreparedDetachedTransactionsBlock};
#[allow(unused_imports)]
pub use block::{TransactionsBlock, TransactionsBlockError, TransactionsBlockField};

/// Local identity of an immutable pending row under its retained predecessor.
///
/// The exclusive writer freezes both historical membership and its opaque
/// predecessor identity. The pending `BlockInfo` allocation is immutable and is
/// replaced only by staging a different row. Pointer equality therefore binds
/// the exact publication without copying or sorting its membership set.
pub(in crate::state) struct TransactionsPublicationSurface {
    predecessor: Identity,
    current: Option<Tip>,
    revert: bool,
}

impl std::fmt::Debug for TransactionsPublicationSurface {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransactionsPublicationSurface")
            .field("has_current", &self.current.is_some())
            .field("revert", &self.revert)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TransactionsPublicationSurface {
    fn eq(&self, other: &Self) -> bool {
        Identity::ptr_eq(&self.predecessor, &other.predecessor)
            && self.revert == other.revert
            && match (&self.current, &other.current) {
                (None, None) => true,
                (Some(left), Some(right)) => Tip::ptr_eq(left, right),
                _ => false,
            }
    }
}

impl Eq for TransactionsPublicationSurface {}

impl TransactionsBlock<'_> {
    /// Return how this block acquired its original membership predecessor.
    pub(in crate::state) fn mode(&self) -> mv::BlockMode {
        if self.revert {
            mv::BlockMode::Replace
        } else {
            mv::BlockMode::Ordinary
        }
    }

    /// Check the exact original membership owner without reading its history.
    pub(in crate::state) fn belongs_to(&self, storage: &TransactionsStorage) -> bool {
        std::ptr::eq(self.latest_block_ref, &storage.latest_block)
            && std::ptr::eq(self.blocks_ref, &storage.blocks)
    }

    /// Bind this owner's exact predecessor and immutable pending membership row.
    pub(in crate::state) fn publication_surface(&self) -> TransactionsPublicationSurface {
        TransactionsPublicationSurface {
            predecessor: self._guard.identity().clone(),
            current: self.current_block.clone(),
            revert: self.revert,
        }
    }
}

/// Borrowed logical membership, independent of the latest/history representation.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: connect retained journals to the consuming State publisher"
    )
)]
mod membership_projection {
    use super::*;

    /// One validated transition borrowed from the actual membership owner.
    ///
    /// The block's existing write guard remains held for this borrow. No key set
    /// is copied and no caller-supplied inventory participates. Visits have
    /// unspecified order: use a history-independent map or canonicalize in the
    /// consumer rather than folding callback order into a commitment.
    /// This describes membership only, not carrier or sealed-alias admission.
    pub(in crate::state) struct TransactionsMembershipTransition<'block> {
        before: Snapshot<'block>,
        current: &'block BlockInfo,
    }

    struct Snapshot<'block> {
        latest: Option<Tip>,
        history: &'block HistoryReader<'block>,
        revert: bool,
    }

    impl TransactionsBlock<'_> {
        fn membership_snapshot(&self) -> Snapshot<'_> {
            self._guard.identity();
            Snapshot {
                latest: self.latest_block_ref.load_full(),
                history: &self.baseline,
                revert: self.revert,
            }
        }

        /// Visit the exact currently committed logical hash-to-height map.
        ///
        /// This cold visit scans history and the latest set, borrowing each key
        /// while the block's write fence is held. It can run before staging.
        /// Callback order is unspecified and callbacks must not acquire a writer
        /// for this storage. Callback errors stop the visit without changing it.
        pub(in crate::state) fn visit_committed_membership<E>(
            &self,
            visit: impl FnMut(&Key, Value) -> Result<(), E>,
        ) -> Result<(), E> {
            self.membership_snapshot().visit(false, visit)
        }

        /// Visit the exact rollback cut of the currently committed tip.
        /// This cold visit always excludes that tip, independently of whether
        /// the caller opened an ordinary or replacement block scope. It binds
        /// older values shadowed by the latest set, which current membership
        /// alone cannot authenticate for durable restoration.
        pub(in crate::state) fn visit_committed_predecessor_membership<E>(
            &self,
            visit: impl FnMut(&Key, Value) -> Result<(), E>,
        ) -> Result<(), E> {
            self.membership_snapshot().visit(true, visit)
        }

        /// Visit the exact logical predecessor used by this block scope.
        ///
        /// For replacement this excludes the abandoned latest set and retains
        /// only earlier history, matching commit's undo cut. Ordinary scopes
        /// visit the committed tip. The same cold-visit rules as
        /// [`Self::visit_committed_membership`] apply.
        pub(in crate::state) fn visit_predecessor_membership<E>(
            &self,
            visit: impl FnMut(&Key, Value) -> Result<(), E>,
        ) -> Result<(), E> {
            let snapshot = self.membership_snapshot();
            snapshot.visit(snapshot.revert, visit)
        }

        /// Borrow an exact transition only after existing commit validation.
        ///
        /// Missing staging or an invalid height fails before any consumer can
        /// observe staged rows. The borrow prevents staging or committing a
        /// different payload while the transition is in use.
        pub(in crate::state) fn membership_transition(
            &self,
        ) -> Result<TransactionsMembershipTransition<'_>, TransactionsBlockError> {
            self.validate_commit()?;
            let current = self
                .current_block
                .as_deref()
                .ok_or(TransactionsBlockError::MissingInsertBlock)?;
            Ok(self.transition_from_admitted_row(current))
        }

        fn transition_from_admitted_row<'block>(
            &'block self,
            current: &'block BlockInfo,
        ) -> TransactionsMembershipTransition<'block> {
            TransactionsMembershipTransition {
                before: self.membership_snapshot(),
                current,
            }
        }
    }

    impl PreparedTransactionsBlock<'_> {
        /// Borrow the same row and predecessor that logical publication already admitted.
        /// No writer, staged payload or latest generation is reacquired here.
        pub(in crate::state) fn membership_transition(
            &self,
        ) -> TransactionsMembershipTransition<'_> {
            let block = self.unpublished_membership_block();
            block.transition_from_admitted_row(
                block
                    .current_block
                    .as_deref()
                    .expect("admitted staged membership"),
            )
        }
    }

    impl Snapshot<'_> {
        fn history_before(&self, key: &Key, ceiling: Value) -> Option<Value> {
            self.history
                .get(key)
                .map(|entry| *entry)
                .filter(|height| *height < ceiling)
        }

        fn get(&self, undo_latest: bool, key: &Key) -> Option<Value> {
            membership_at_cut(self.latest.as_deref(), self.history, undo_latest, key)
        }

        fn visit<E>(
            &self,
            undo_latest: bool,
            mut visit: impl FnMut(&Key, Value) -> Result<(), E>,
        ) -> Result<(), E> {
            let Some(latest) = self.latest.as_ref() else {
                return Ok(());
            };
            if !undo_latest {
                for key in &latest.transactions {
                    visit(key, latest.height)?;
                }
            }
            for (key, value) in self.history.iter() {
                if *value < latest.height && (undo_latest || !latest.transactions.contains(key)) {
                    visit(key, *value)?;
                }
            }
            Ok(())
        }
    }

    impl TransactionsMembershipTransition<'_> {
        /// Admit every physical entry inspection in both successor streams.
        /// Staged/current and predecessor/rollback visitors share this same cut.
        pub(in crate::state) fn successor_row_visits(&self) -> Option<usize> {
            let latest = self
                .before
                .latest
                .as_ref()
                .map_or(0, |tip| tip.transactions.len());
            let promoted = if self.before.revert { 0 } else { latest };
            let rollback =
                if self.before.revert || self.staged_height().get() == self.committed_height() {
                    0
                } else {
                    latest
                };
            self.before
                .history
                .len()
                .checked_mul(2)?
                .checked_add(self.current.transactions.len())?
                .checked_add(promoted)?
                .checked_add(rollback)
        }

        /// Exact rollback of the staged successor, including a repeated publication.
        /// Ordinary advance retains the former tip; replacement and repetition exclude it.
        pub(in crate::state) fn visit_staged_predecessor_membership<E>(
            &self,
            visit: impl FnMut(&Key, Value) -> Result<(), E>,
        ) -> Result<(), E> {
            #[cfg(all(test, sumeragi_core_mutation = "HC154"))]
            let undo_latest = self.before.revert;
            #[cfg(not(all(test, sumeragi_core_mutation = "HC154")))]
            let undo_latest =
                self.before.revert || self.staged_height().get() == self.committed_height();
            self.before.visit(undo_latest, visit)
        }

        /// Height of the committed tip before this publication; zero if empty.
        pub(in crate::state) fn committed_height(&self) -> usize {
            self.before
                .latest
                .as_ref()
                .map_or(0, |block| block.height.get())
        }

        /// Height of the logical predecessor, after undo for replacement.
        pub(in crate::state) fn predecessor_height(&self) -> usize {
            let committed = self.committed_height();
            if self.before.revert {
                committed.saturating_sub(1)
            } else {
                committed
            }
        }

        /// Height whose exact membership has passed existing commit validation.
        pub(in crate::state) fn staged_height(&self) -> Value {
            self.current.height
        }

        /// Visit the exact post-commit logical map without publishing it.
        ///
        /// Cold traversal scans history plus the current/latest sets; duplicate
        /// physical keys are visited once with their actual lookup precedence.
        /// The underlying stores are borrowed and callback order is unspecified.
        pub(in crate::state) fn visit_staged_membership<E>(
            &self,
            mut visit: impl FnMut(&Key, Value) -> Result<(), E>,
        ) -> Result<(), E> {
            if cfg!(all(test, sumeragi_core_mutation = "HC153")) {
                return self.before.visit(false, visit);
            }
            for key in &self.current.transactions {
                visit(key, self.current.height)?;
            }
            let promoted = (!self.before.revert)
                .then_some(self.before.latest.as_deref())
                .flatten();
            if let Some(previous) = promoted {
                for key in &previous.transactions {
                    if !self.current.transactions.contains(key) {
                        visit(key, previous.height)?;
                    }
                }
            }
            for (key, value) in self.before.history.iter() {
                if *value < self.current.height
                    && !self.current.transactions.contains(key)
                    && !promoted.is_some_and(|previous| previous.transactions.contains(key))
                {
                    visit(key, *value)?;
                }
            }
            Ok(())
        }

        /// Visit net changes from the logical predecessor to the staged map.
        ///
        /// This visits only the actual staged set. Ordinary latest-set promotion
        /// changes representation, not logical values. Replacement starts from
        /// the earlier history cut, not the abandoned committed tip.
        pub(in crate::state) fn visit_predecessor_changes<E>(
            &self,
            mut visit: impl FnMut(&Key, Option<Value>, Option<Value>) -> Result<(), E>,
        ) -> Result<(), E> {
            for key in &self.current.transactions {
                let before = self.before.get(self.before.revert, key);
                let after = Some(self.current.height);
                if before != after {
                    visit(key, before, after)?;
                }
            }
            Ok(())
        }

        /// Visit net changes from the committed tip to the staged map.
        ///
        /// Unlike predecessor changes, replacement includes removal of abandoned
        /// tip-only keys and restoration of their earlier historical values.
        /// Work is bounded by the actual staged and latest sets, without scanning
        /// history. This relies on the private storage invariant: history has
        /// heights below the committed tip; exact repeated commits preserve it.
        pub(in crate::state) fn visit_committed_changes<E>(
            &self,
            mut visit: impl FnMut(&Key, Option<Value>, Option<Value>) -> Result<(), E>,
        ) -> Result<(), E> {
            for key in &self.current.transactions {
                let before = self.before.get(false, key);
                let after = Some(self.current.height);
                if before != after {
                    visit(key, before, after)?;
                }
            }
            if self.before.revert
                && let Some(previous) = &self.before.latest
            {
                for key in &previous.transactions {
                    if !self.current.transactions.contains(key) {
                        let after = self.before.history_before(key, self.current.height);
                        visit(key, Some(previous.height), after)?;
                    }
                }
            }
            Ok(())
        }
    }
}
pub(in crate::state) use membership_projection::TransactionsMembershipTransition;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the exact membership projection in the complete State root owner"
    )
)]
#[path = "storage_transactions/authority.rs"]
pub(in crate::state) mod authority;

#[cfg(test)]
#[path = "storage_transactions_projection_tests.rs"]
mod projection_tests;

#[cfg(test)]
#[path = "storage_transactions_preparation_tests.rs"]
mod preparation_tests;

#[cfg(test)]
#[path = "storage_transactions_publication_tests.rs"]
mod publication_tests;

/// Module with serialization and deserialization of [`TransactionsStorage`]
mod serialization {
    use super::*;
    fn write_transactions_view_json(view: &TransactionsView<'_>, out: &mut String) {
        out.push('{');
        json::write_json_string("latest_block", out);
        out.push(':');
        match view.latest_block.as_ref() {
            Some(block) => JsonSerializeTrait::json_serialize(&**block, out),
            None => out.push_str("null"),
        }
        out.push(',');
        json::write_json_string("blocks", out);
        out.push(':');
        let mut map = BTreeMap::new();
        #[allow(clippy::explicit_iter_loop)]
        for (key, value) in view.blocks.iter() {
            map.insert(*key, *value);
        }
        JsonSerializeTrait::json_serialize(&map, out);
        out.push('}');
    }
    fn write_transactions_block_json(block: &TransactionsBlock<'_>, out: &mut String) {
        let predecessor = block.latest_block_ref.load();
        write_transactions_cut_json(
            block.current_block.as_ref(),
            predecessor.as_deref(),
            &block.baseline,
            block.revert,
            out,
        );
    }
    pub(super) fn write_transactions_cut_json(
        current: Option<&Tip>,
        predecessor: Option<&BlockInfo>,
        baseline: &HistoryReader<'_>,
        revert: bool,
        out: &mut String,
    ) {
        out.push('{');
        json::write_json_string("latest_block", out);
        out.push(':');
        match current {
            Some(current) => JsonSerializeTrait::json_serialize(&**current, out),
            None => out.push_str("null"),
        }
        out.push(',');
        json::write_json_string("blocks", out);
        out.push(':');
        let mut map = BTreeMap::new();
        #[allow(clippy::explicit_iter_loop)]
        for (key, value) in baseline.iter() {
            map.insert(*key, *value);
        }
        if revert {
            if let Some(current) = current {
                map.retain(|_, height| *height < current.height);
            }
        } else {
            if let Some(previous) = predecessor {
                let repeated = current.is_some_and(|current| {
                    current.height == previous.height
                        && current.transactions == previous.transactions
                });
                if !repeated {
                    for transaction in &previous.transactions {
                        map.insert(*transaction, previous.height);
                    }
                }
            }
        }
        JsonSerializeTrait::json_serialize(&map, out);
        out.push('}');
    }
    impl JsonSerializeTrait for TransactionsStorage {
        fn json_serialize(&self, out: &mut String) {
            write_transactions_view_json(&self.view(), out)
        }
    }
    impl JsonSerializeTrait for TransactionsBlock<'_> {
        fn json_serialize(&self, out: &mut String) {
            write_transactions_block_json(self, out)
        }
    }
    impl JsonSerializeTrait for PreparedTransactionsBlock<'_> {
        fn json_serialize(&self, out: &mut String) {
            write_transactions_block_json(self.as_block(), out)
        }
    }
    impl FastJsonWrite for TransactionsView<'_> {
        fn write_json(&self, out: &mut String) {
            write_transactions_view_json(self, out)
        }
    }
    impl TransactionsStorage {
        /// Restore the canonical snapshot layout into the original configured pool.
        /// The JSON parser's input/scratch belongs to the snapshot owner; every
        /// historical node, native cursor and generation identity is prepaid here.
        pub(crate) fn from_json_with_budget(
            source: &str,
            budget: iroha_allocation::AllocationBudget,
        ) -> Result<Self, MembershipRestoreError> {
            let value = json::from_str::<json::Value>(source)?;
            Self::from_value_with_budget(value, budget)
        }
        fn from_value_with_budget(
            value: json::Value,
            budget: iroha_allocation::AllocationBudget,
        ) -> Result<Self, MembershipRestoreError> {
            let json::Value::Object(mut map) = value else {
                return Err(json::Error::InvalidField {
                    field: "transactions_storage".into(),
                    message: "expected object".into(),
                }
                .into());
            };
            let latest = map
                .remove("latest_block")
                .ok_or_else(|| json::Error::missing_field("latest_block"))?;
            let entries = map
                .remove("blocks")
                .ok_or_else(|| json::Error::missing_field("blocks"))?;
            if let Some(field) = map.keys().next() {
                return Err(json::Error::unknown_field(field.as_str()).into());
            }
            let latest = match latest {
                json::Value::Null => None,
                other => Some(json::value::from_value::<BlockInfoInput>(other)?),
            };
            let json::Value::Object(entries) = entries else {
                return Err(json::Error::InvalidField {
                    field: "blocks".into(),
                    message: "expected object".into(),
                }
                .into());
            };
            budget.with_deferred_refund_notifications(|_| {
                let owner = Self::try_new(budget.clone())?;
                let mut physical_releases = owner.history_released.deferred_batch();
                let latest = latest
                    .as_ref()
                    .map(|input| admit_tip(&budget, &input.transactions, input.height))
                    .transpose()?;
                let mut writer =
                    owner.try_history_writer(&mut physical_releases, |_, demand| {
                        history::admit(&budget, demand).map_err(MembershipAdmissionError::Capacity)
                    })?;
                for (key_str, value) in entries {
                    let key = Key::decode_json_key(&key_str).map_err(|e| {
                        json::Error::Message(format!("invalid transaction hash `{key_str}`: {e}"))
                    })?;
                    let value: Value = json::value::from_value(value)?;
                    if latest.as_ref().is_some_and(|tip| value < tip.height) {
                        writer
                            .try_insert_admitted(key, value, |d| history::admit(&budget, d))
                            .map_err(|(_, e)| {
                                history::edit_error(e, owner.history_release_wait())
                            })?;
                    }
                }
                let retired = writer
                    .try_release_into_observed(
                        &mut physical_releases,
                        |writer| writer.prepare_commit().publish().release(),
                        || owner.blocks.is_poisoned(),
                    )
                    .unwrap_or_else(|_| unreachable!("original restored history release family"));
                owner.latest_block.store(latest);
                drop(retired);
                drop(physical_releases);
                Ok(owner)
            })
        }
    }
    #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
    impl JsonDeserializeTrait for TransactionsStorage {
        fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
            Self::from_value_with_budget(
                json::Value::json_deserialize(parser)?,
                iroha_allocation::AllocationBudget::new(256 * 1024 * 1024),
            )
            .map_err(|error| match error {
                MembershipRestoreError::Json(error) => error,
                MembershipRestoreError::Admission(error) => json::Error::Message(error.to_string()),
            })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_TEST_HASH: AtomicU64 = AtomicU64::new(1);
    fn random_hash() -> Key {
        let counter = NEXT_TEST_HASH.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0_u8; iroha_crypto::Hash::LENGTH];
        bytes[..8].copy_from_slice(&counter.to_le_bytes());
        let hash = iroha_crypto::Hash::prehashed(bytes);
        HashOf::from_untyped_unchecked(hash)
    }
    fn get_keys<const N: usize>() -> [Key; N] {
        [(); N].map(|()| random_hash())
    }
    fn get_values<const N: usize>() -> [Value; N] {
        let mut i = 0;
        [(); N].map(|()| {
            i += 1;
            NonZeroUsize::new(i).unwrap()
        })
    }
    #[test]
    fn charged_tip_matches_canonical_hashset_json_after_duplicate_compaction() {
        let [ordinary, merge_key, extra] = get_keys();
        let merge = HashSet::from([merge_key]);
        let charged = admit_tip_from_sources(
            &AllocationBudget::new(1024 * 1024),
            [ordinary, extra, ordinary].into_iter(),
            &merge,
            NonZeroUsize::MIN,
        )
        .expect("prepaid tip from exact source count");
        assert_eq!(charged.transactions.len(), 3);
        assert!(charged.transactions.contains(&ordinary));
        assert!(charged.transactions.contains(&merge_key));
        let former = BlockInfoInput {
            transactions: HashSet::from([ordinary, extra, merge_key]),
            height: NonZeroUsize::MIN,
        };
        let former_tip_json = norito::json::to_json(&former).unwrap();
        assert_eq!(norito::json::to_json(&*charged).unwrap(), former_tip_json);
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        block
            .try_stage_block(
                &mut vec![ordinary, extra, ordinary],
                &merge,
                NonZeroUsize::MIN,
            )
            .expect("canonical tip stages with duplicate ordinary input");
        block.commit().expect("publish charged snapshot tip");
        assert_eq!(
            norito::json::to_json(&storage).unwrap(),
            format!("{{\"latest_block\":{former_tip_json},\"blocks\":{{}}}}")
        );
    }

    #[test]
    fn exact_capacity_repeat_checks_original_tip_without_second_charge() {
        let [ordinary, merge_key, changed] = get_keys();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        let merge = HashSet::from([merge_key]);
        block
            .try_stage_block(&mut vec![ordinary, ordinary], &merge, NonZeroUsize::MIN)
            .expect("admit first canonical tip");
        let remaining = storage.budget.limit_bytes() - storage.budget.reserved_bytes();
        let filler = storage
            .budget
            .try_reserve_bytes(remaining)
            .expect("fill every remaining pool byte");
        assert_eq!(
            storage.budget.reserved_bytes(),
            storage.budget.limit_bytes()
        );
        block
            .try_stage_block(&mut vec![ordinary, ordinary], &merge, NonZeroUsize::MIN)
            .expect("same canonical set uses the original charged tip");
        assert!(matches!(
            block.try_stage_block(&mut vec![changed], &merge, NonZeroUsize::MIN),
            Err(TipStageError::ChangedPayload)
        ));
        assert_eq!(
            storage.budget.reserved_bytes(),
            storage.budget.limit_bytes()
        );
        drop(filler);
        block
            .commit()
            .expect("original tip publishes after capacity hold");
        assert_eq!(storage.view().get(&ordinary), Some(NonZeroUsize::MIN));
        assert_eq!(storage.view().get(&changed), None);
    }

    #[test]
    fn one_byte_tip_refusal_keeps_old_view_and_retries_same_source() {
        let [old_key, new_key] = get_keys();
        let [first, second] = get_values();
        let storage = TransactionsStorage::new();
        let merge = HashSet::new();
        let mut first_block = storage.block();
        first_block
            .try_stage_block(&mut vec![old_key], &merge, first)
            .expect("first charged tip");
        first_block.commit().expect("first committed tip");
        let old_view = storage.view();
        let before = norito::json::to_json(&storage).unwrap();
        let mut next = storage.block();
        let tip_bytes = Tip::layout().size() + Layout::array::<Key>(1).unwrap().size();
        let remaining = storage.budget.limit_bytes() - storage.budget.reserved_bytes();
        assert!(remaining > tip_bytes);
        let filler = storage
            .budget
            .try_reserve_bytes(remaining - tip_bytes + 1)
            .expect("leave exactly one byte less than the tip demand");
        let mut original_source = vec![new_key];
        assert!(matches!(
            next.try_stage_block(&mut original_source, &merge, second),
            Err(TipStageError::Admission(MembershipAdmissionError::Capacity(
                iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. }
            ))) if requested_bytes == tip_bytes
        ));
        assert!(!next.has_staged_block());
        assert_eq!(norito::json::to_json(&storage).unwrap(), before);
        assert_eq!(old_view.get(&old_key), Some(first));
        assert_eq!(old_view.get(&new_key), None);
        drop(filler);
        next.try_stage_block(&mut original_source, &merge, second)
            .expect("retry with the unchanged original source");
        next.commit().expect("publish admitted original retry");
        assert_eq!(old_view.get(&new_key), None);
        let new_view = storage.view();
        assert_eq!(new_view.get(&old_key), Some(first));
        assert_eq!(new_view.get(&new_key), Some(second));
        let restored: TransactionsStorage =
            norito::json::from_str(&norito::json::to_json(&storage).unwrap()).unwrap();
        assert_eq!(restored.view().get(&old_key), Some(first));
        assert_eq!(restored.view().get(&new_key), Some(second));
    }

    #[test]
    fn ordinary_merge_overlap_refuses_without_staging_a_tip() {
        let [key] = get_keys();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        let merge = HashSet::from([key]);
        let mut ordinary = vec![key];
        let remaining = storage.budget.limit_bytes() - storage.budget.reserved_bytes();
        let full_pool = storage
            .budget
            .try_reserve_bytes(remaining)
            .expect("hold all available tip capacity");
        assert!(matches!(
            block.try_stage_block(&mut ordinary, &merge, NonZeroUsize::MIN),
            Err(TipStageError::Overlap)
        ));
        assert_eq!(ordinary, vec![key]);
        assert!(!block.has_staged_block());
        drop(full_pool);
        assert_eq!(storage.latest_height(), 0);
    }
    fn insert_keys(block: &mut TransactionsBlock, keys: &[Key], value: Value) {
        let keys = keys.iter().copied().collect();
        block.insert_block(keys, value);
    }
    #[test]
    fn publication_surface_binds_original_predecessor_and_immutable_row() {
        let storage = TransactionsStorage::new();
        let foreign_storage = TransactionsStorage::new();
        let mut block = storage.block();
        assert!(block.belongs_to(&storage));
        assert!(!block.belongs_to(&foreign_storage));
        assert_eq!(block.mode(), mv::BlockMode::Ordinary);
        let empty = block.publication_surface();
        assert_eq!(empty, block.publication_surface());
        assert_ne!(empty, foreign_storage.block().publication_surface());
        let [key] = get_keys();
        insert_keys(&mut block, &[key], NonZeroUsize::MIN);
        let staged = block.publication_surface();
        assert_ne!(empty, staged);
        insert_keys(&mut block, &[key], NonZeroUsize::MIN);
        assert_eq!(staged, block.publication_surface());
        block.commit().unwrap();
        assert_ne!(empty, storage.block().publication_surface());
        let replacement = storage.block_and_revert();
        assert_eq!(replacement.mode(), mv::BlockMode::Replace);
        assert_ne!(staged, replacement.publication_surface());
    }
    #[test]
    fn fixture_membership_overwrite_reaches_public_reader_without_moving_frontier() {
        let [corrupted, untouched] = get_keys();
        let [historical, current] = get_values();
        let storage = TransactionsStorage::new();
        storage.record_committed_entrypoint_membership_for_tests([corrupted, untouched], current);
        storage.overwrite_committed_entrypoint_membership_for_tests(corrupted, historical);
        assert_eq!(storage.view().get(&corrupted), Some(historical));
        assert_eq!(storage.view().get(&untouched), Some(current));
        assert_eq!(storage.latest_height(), current.get());
        storage.overwrite_committed_entrypoint_membership_for_tests(corrupted, current);
        assert_eq!(storage.view().get(&corrupted), Some(current));
        assert_eq!(storage.view().get(&untouched), Some(current));
        assert!(storage.blocks.read().get(&corrupted).is_none());
        assert_eq!(storage.latest_height(), current.get());
    }
    #[test]
    fn get() {
        let [k0, k1, k2, k3, k4] = get_keys();
        let [v1, v2, v3] = get_values();
        let storage = TransactionsStorage::new();
        let view0 = storage.view();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k0, k1, k2], v1);
            block.commit().unwrap()
        }
        let view1 = storage.view();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k0, k1, k3], v2);
            block.commit().unwrap()
        }
        let view2 = storage.view();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k1, k4], v3);
            block.commit().unwrap()
        }
        let view3 = storage.view();
        assert_eq!(view0.get(&k0), None);
        assert_eq!(view0.get(&k1), None);
        assert_eq!(view0.get(&k2), None);
        assert_eq!(view0.get(&k3), None);
        assert_eq!(view1.get(&k0), Some(v1));
        assert_eq!(view1.get(&k1), Some(v1));
        assert_eq!(view1.get(&k2), Some(v1));
        assert_eq!(view1.get(&k3), None);
        assert_eq!(view2.get(&k0), Some(v2));
        assert_eq!(view2.get(&k1), Some(v2));
        assert_eq!(view2.get(&k2), Some(v1));
        assert_eq!(view2.get(&k3), Some(v2));
        assert_eq!(view2.get(&k4), None);
        assert_eq!(view3.get(&k0), Some(v2));
        assert_eq!(view3.get(&k1), Some(v3));
        assert_eq!(view3.get(&k2), Some(v1));
        assert_eq!(view3.get(&k3), Some(v2));
        assert_eq!(view3.get(&k4), Some(v3));
    }
    #[test]
    fn revert() {
        let [k0] = get_keys();
        let [v1, v2] = get_values();
        let storage = TransactionsStorage::new();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k0], v1);
            block.commit().unwrap()
        }
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k0], v2);
            block.commit().unwrap()
        }
        let view1 = storage.view();
        {
            let mut block = storage.block_and_revert();
            block.insert_block(HashSet::new(), v2);
            block.commit().unwrap();
        }
        let view2 = storage.view();
        // View is persistent so revert is not visible
        assert_eq!(view1.get(&k0), Some(v2));
        // Revert is visible in the view created after revert was applied
        assert_eq!(view2.get(&k0), Some(v1));
    }
    #[test]
    fn revert_drops_discarded_transactions() {
        let [tx_a, tx_b, tx_b_prime] = get_keys();
        let [height_a, height_b] = get_values();
        let storage = TransactionsStorage::new();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[tx_a], height_a);
            block.commit().unwrap();
        }
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[tx_b], height_b);
            block.commit().unwrap();
        }
        let view_before_revert = storage.view();
        assert_eq!(view_before_revert.get(&tx_b), Some(height_b));
        {
            let mut block = storage.block_and_revert();
            block.insert_block(HashSet::from([tx_b_prime]), height_b);
            block.commit().unwrap();
        }
        let view_after_revert = storage.view();
        assert_eq!(view_after_revert.get(&tx_a), Some(height_a));
        assert_eq!(view_after_revert.get(&tx_b_prime), Some(height_b));
        assert_eq!(view_after_revert.get(&tx_b), None);
    }
    #[cfg(not(debug_assertions))]
    #[test]
    fn commit_succeeds_in_release() {
        let [key] = get_keys();
        let [height] = get_values();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        insert_keys(&mut block, &[key], height);
        assert!(block.commit().is_ok());
    }
    #[test]
    fn serialization() {
        fn assert_views_equal(view1: &TransactionsView, view2: &TransactionsView, keys: &[Key]) {
            for key in keys {
                let value1 = view1.get(key);
                let value2 = view2.get(key);
                assert_eq!(value1, value2);
            }
        }
        fn check_view(view1: &TransactionsView, keys: &[Key]) {
            let json = norito::json::to_json(&view1).unwrap();
            let storage2: TransactionsStorage = norito::json::from_str(&json).unwrap();
            let view2 = storage2.view();
            assert_views_equal(view1, &view2, keys);
        }
        fn check_views(views: &[TransactionsView], keys: &[Key]) {
            for view in views {
                check_view(view, keys);
            }
        }
        let keys = get_keys();
        let [k0, k1, k2, k3, k4] = keys;
        let [v1, v2, v3] = get_values();
        let mut views = Vec::new();
        let storage = TransactionsStorage::new();
        views.push(storage.view());
        check_views(&views, &keys);
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k0, k1, k2], v1);
            block.commit().unwrap()
        }
        views.push(storage.view());
        check_views(&views, &keys);
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k0, k1, k3], v2);
            block.commit().unwrap()
        }
        views.push(storage.view());
        check_views(&views, &keys);
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[k1, k4], v3);
            block.commit().unwrap()
        }
        views.push(storage.view());
        check_views(&views, &keys);
        {
            let mut block = storage.block_and_revert();
            insert_keys(&mut block, &[k2], v3);
            block.commit().unwrap()
        }
        views.push(storage.view());
        check_views(&views, &keys);
    }
    #[test]
    fn lane_geometry_commit_refusal_preserves_storage_source_and_deterministic_errors() {
        use crate::state::LaneLifecycleError;
        use std::error::Error as _;

        let path = std::path::PathBuf::from("retained/lane_geometry_journal.norito");
        let error = TransactionsBlockError::from(LaneLifecycleError::GeometryStorage(
            crate::kura::Error::IO(
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "original journal owner",
                ),
                path.clone(),
            ),
        ));
        let lifecycle = error
            .source()
            .and_then(|source| source.downcast_ref::<LaneLifecycleError>())
            .expect("commit refusal retains the typed lifecycle source");
        let Some(crate::kura::Error::IO(io, actual_path)) = lifecycle
            .source()
            .and_then(|source| source.downcast_ref::<crate::kura::Error>())
        else {
            panic!("commit refusal must retain the original Kura IO source");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(io.to_string(), "original journal owner");
        assert_eq!(actual_path, &path);
        let original_observation = Box::new(crate::state::MergeLedgerCommitError::Persistence(
            crate::kura::Error::IO(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "original drain owner"),
                path.clone(),
            ),
        ));
        let original_owner = std::ptr::from_ref(original_observation.as_ref());
        let drain = TransactionsBlockError::from(LaneLifecycleError::DrainObservation(
            original_observation,
        ));
        let lifecycle = drain
            .source()
            .and_then(|source| source.downcast_ref::<LaneLifecycleError>())
            .expect("drain refusal remains a local lifecycle source");
        let observation = lifecycle
            .source()
            .and_then(|source| source.downcast_ref::<Box<crate::state::MergeLedgerCommitError>>())
            .expect("drain refusal retains its exact boxed observation error")
            .as_ref();
        assert_eq!(std::ptr::from_ref(observation), original_owner);
        assert!(
            matches!(observation, crate::state::MergeLedgerCommitError::Persistence(
            crate::kura::Error::IO(io, actual_path)
        ) if io.kind() == std::io::ErrorKind::PermissionDenied
            && io.to_string() == "original drain owner" && actual_path == &path)
        );
        assert!(matches!(
            TransactionsBlockError::from(LaneLifecycleError::Storage("tiered capture".to_owned())),
            TransactionsBlockError::LocalLaneGeometry(source)
                if matches!(&source, LaneLifecycleError::Storage(detail) if detail == "tiered capture")
        ));
        assert!(matches!(
            TransactionsBlockError::from(LaneLifecycleError::PhysicalPrimaryReplacement),
            TransactionsBlockError::AutoscaleLaneLifecycle
        ));
    }

    #[test]
    fn lane_geometry_commit_refusal_retains_original_release_observation() {
        // This conversion-only fixture has no State operation owner. Admit its
        // sole observer from the explicitly bounded fixture pool before refusal.
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut release_registration_0 =
            crate::unit_test_support::release_registration(&observer_budget);
        use crate::state::LaneLifecycleError;
        use std::{
            future::Future as _,
            pin::Pin,
            task::{Context, Waker},
        };

        let release = iroha_allocation::release::ReleaseNotification::default();
        let original_owner = release.guard(());
        let observation = release.observe();
        let error = TransactionsBlockError::from(LaneLifecycleError::PublicationBusy {
            field: "original geometry writer",
            wait: observation.clone(),
        });
        let TransactionsBlockError::LocalLaneGeometry(source) = error else {
            panic!("local publication refusal must retain its source");
        };
        let LaneLifecycleError::PublicationBusy { field, wait } = source else {
            panic!("original release observation must survive conversion");
        };
        assert_eq!(field, "original geometry writer");
        assert_eq!(wait, observation);
        let mut future = wait.wait_for_release(&mut release_registration_0);
        let mut context = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut future).poll(&mut context).is_pending());
        drop(original_owner);
        assert!(Pin::new(&mut future).poll(&mut context).is_ready());
    }

    #[test]
    fn commit_without_insert_block_fails() {
        let storage = TransactionsStorage::new();
        let block = storage.block();
        assert!(matches!(
            block.commit(),
            Err(TransactionsBlockError::MissingInsertBlock)
        ));
    }
    #[test]
    fn validate_commit_height_mismatch_does_not_mutate_storage() {
        let [key] = get_keys();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        let wrong_height = NonZeroUsize::new(2).unwrap();
        block.insert_block(HashSet::from([key]), wrong_height);
        assert!(matches!(
            block.validate_commit(),
            Err(TransactionsBlockError::HeightMismatch {
                expected_current_height: 1,
                actual_current_height,
            }) if actual_current_height == wrong_height.get()
        ));
        assert_eq!(storage.latest_height(), 0);
        drop(block);
        assert_eq!(storage.latest_height(), 0);
    }
    #[cfg(not(debug_assertions))]
    #[test]
    fn commit_height_mismatch_fails_in_release() {
        let [first_key, second_key] = get_keys();
        let [first_height, _] = get_values();
        let storage = TransactionsStorage::new();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[first_key], first_height);
            block.commit().unwrap();
        }
        let mut block = storage.block();
        let transactions = HashSet::from([second_key]);
        let wrong_height = NonZeroUsize::new(first_height.get() + 2).unwrap();
        let expected_height = first_height.get() + 1;
        block.insert_block(transactions, wrong_height);
        assert!(matches!(
            block.commit(),
            Err(TransactionsBlockError::HeightMismatch {
                expected_current_height,
                actual_current_height,
            }) if expected_current_height == expected_height
                && actual_current_height == wrong_height.get()
        ));
    }
    #[test]
    fn commit_with_insert_block_succeeds() {
        let [key] = get_keys();
        let [value] = get_values();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        insert_keys(&mut block, &[key], value);
        block.commit().unwrap();
    }
    #[test]
    fn latest_height_tracks_committed_block() {
        let [key] = get_keys();
        let [value] = get_values();
        let storage = TransactionsStorage::new();
        assert_eq!(storage.latest_height(), 0);
        let mut block = storage.block();
        insert_keys(&mut block, &[key], value);
        block.commit().unwrap();
        assert_eq!(storage.latest_height(), value.get());
    }
    #[test]
    fn carrier_membership_is_atomic_with_canonical_revert() {
        let [
            canonical_key,
            ordinary_carrier_key,
            merge_carrier_key,
            replacement_key,
        ] = get_keys();
        let [height1, height2] = get_values();
        let storage = TransactionsStorage::new();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[canonical_key], height1);
            block.commit().unwrap();
        }
        {
            let mut block = storage.block();
            insert_keys(
                &mut block,
                &[ordinary_carrier_key, merge_carrier_key],
                height2,
            );
            block.commit().unwrap();
        }
        {
            let mut block = storage.block_and_revert();
            insert_keys(&mut block, &[replacement_key], height2);
            block.commit().unwrap();
        }
        let view = storage.view();
        assert_eq!(view.get(&canonical_key), Some(height1));
        assert_eq!(view.get(&replacement_key), Some(height2));
        assert_eq!(view.get(&ordinary_carrier_key), None);
        assert_eq!(view.get(&merge_carrier_key), None);
    }
    #[test]
    fn retired_direct_membership_json_is_rejected() {
        let error = match norito::json::from_str::<TransactionsStorage>(
            r#"{"latest_block":null,"blocks":{},"direct_committed":{}}"#,
        ) {
            Ok(_) => panic!("retired membership field must not be accepted"),
            Err(error) => error,
        };
        assert!(
            matches!(error, json::Error::UnknownField { field } if field == "direct_committed")
        );
    }
    #[test]
    fn insert_block_allowed_twice_for_same_payload() {
        let [key] = get_keys();
        let [value] = get_values();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        let payload: HashSet<_> = HashSet::from([key]);
        block.insert_block(payload.clone(), value);
        block.insert_block(payload, value);
        block.commit().unwrap();
    }
    #[test]
    fn commit_same_block_twice_is_idempotent() {
        let [key] = get_keys();
        let [value] = get_values();
        let storage = TransactionsStorage::new();
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[key], value);
            block.commit().unwrap();
        }
        {
            let mut block = storage.block();
            insert_keys(&mut block, &[key], value);
            block.commit().unwrap();
        }
        assert_eq!(storage.view().get(&key), Some(value));
    }
    #[test]
    #[should_panic(
        expected = "`TransactionsBlock::insert_block()` called multiple times with different height"
    )]
    fn insert_block_rejects_height_mismatch() {
        let [key] = get_keys();
        let [value1, value2] = get_values();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        let payload = HashSet::from([key]);
        block.insert_block(payload.clone(), value1);
        block.insert_block(payload, value2);
    }
    #[test]
    #[should_panic(
        expected = "`TransactionsBlock::insert_block()` called multiple times with different transactions"
    )]
    fn insert_block_rejects_transaction_mismatch() {
        let [key1, key2] = get_keys();
        let [value] = get_values();
        let storage = TransactionsStorage::new();
        let mut block = storage.block();
        block.insert_block(HashSet::from([key1]), value);
        block.insert_block(HashSet::from([key2]), value);
    }
}

#[cfg(test)]
impl TransactionsStorage {
    /// Hold the actual membership mutex after the original execution has frozen its journal.
    /// This is a physical blocker, not an injected outcome or replacement predecessor.
    pub(in crate::state) fn with_membership_publication_blocked_for_test<R>(
        &self,
        action: impl FnOnce() -> R,
    ) -> R {
        let blocker = self.released.guard(self.write_lock.lock());
        let result = action();
        drop(blocker);
        result
    }

    /// Hold the actual native history writer while a caller probes publication.
    pub(in crate::state) fn with_physical_publication_blocked_for_test<R>(
        &self,
        action: impl FnOnce() -> R,
    ) -> R {
        let blocker = self.history_released.guard(self.blocks.acquire_writer());
        let result = action();
        drop(blocker);
        result
    }
}
