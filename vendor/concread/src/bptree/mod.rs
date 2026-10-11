//! See the documentation for [BptreeMap]

#[cfg(feature = "asynch")]
pub mod asynch;

#[cfg(feature = "serde")]
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, SerializeMap, Serializer},
};

#[cfg(feature = "serde")]
use crate::utils::MapCollector;

pub use crate::internals::lincowcell::OwnedWriteError;
use crate::internals::lincowcell::{
    LinCowCell, LinCowCellCommitRetirement, LinCowCellCommitSlot, LinCowCellFamily,
    LinCowCellOwned, LinCowCellOwnedAcquisition, LinCowCellPredecessor, LinCowCellPreparedCommit,
    LinCowCellPublished, LinCowCellReadTxn, LinCowCellRetainedPredecessor, LinCowCellRetainedWork,
    LinCowCellWriteTxn, LinCowCellWriterAcquisition,
};

mod admission;
mod mode;
mod row_positions;

pub use row_positions::{
    BptreeMapFrozenOwned, BptreeMapFrozenReader, BptreeMapRowPosition, BptreeMapRowPositions,
    RowPositionError,
};

pub use crate::internals::bptree::allocation::{NodeCloning, NodeFunding};
pub use crate::internals::bptree::tracking::{FixedTrackingBuffer, TrackingBuffer};
pub use crate::internals::lincowcell::Untracked;
pub use admission::{
    AllocationDemand, BptreeMapCheckpoint, BptreeMapPreparedInsert, BptreeMapPreparedKeyCopyInsert,
    BptreeMapPreparedOptionalCopyInsert, CheckpointRetirement, ClonePlanning, MapAdmissionError,
    PairInsertError, PairRemoveError, PlanningError,
};
pub use mode::{MapMode, Prepaid};

mod types;
use types::*;

include!("impl.rs");

/// Opaque custody of one original map family, independent of its generation.
///
/// Cloning retains the existing charged root allocation; it creates no identity
/// allocation and does not require the original move-only charge to be cloneable.
pub struct BptreeMapFamily<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapFamily<K, V, M>,
}

impl<K, V, M> Clone for BptreeMapFamily<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<K, V, M> BptreeMapFamily<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Match only this actual original map, without locking or allocating.
    pub fn matches(&self, target: &BptreeMap<K, V, M>) -> bool {
        self.inner.matches(&target.inner)
    }

    /// Compare original root allocations, not map contents or mutable heights.
    pub fn same_family(&self, other: &Self) -> bool {
        self.inner.same_family(&other.inner)
    }
}

/// Borrowed original map family and reader generation.
/// This immutable comparison grants no mutation or publication authority.
pub struct BptreeMapPredecessor<'a, K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapPredecessor<'a, K, V, M>,
}

impl<K, V, M> BptreeMapPredecessor<'_, K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Retain only these original root and reader allocations, without copying work.
    pub fn retain(&self) -> BptreeMapRetainedPredecessor<K, V, M> {
        BptreeMapRetainedPredecessor {
            inner: self.inner.retain(),
        }
    }

    /// Compare exact roots and retained reader allocations across owner scopes.
    pub fn same_predecessor(&self, other: &BptreeMapPredecessor<'_, K, V, M>) -> bool {
        self.inner.same_predecessor(&other.inner)
    }
}

/// Original family and predecessor retained independently of the private cursor.
/// This identity-only owner allocates nothing and grants no edit/publication rights.
pub struct BptreeMapRetainedPredecessor<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapRetainedPredecessor<K, V, M>,
}
impl<K, V, M> Clone for BptreeMapRetainedPredecessor<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
impl<K, V, M> Debug for BptreeMapRetainedPredecessor<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BptreeMapRetainedPredecessor")
            .finish_non_exhaustive()
    }
}
impl<K, V, M> PartialEq for BptreeMapRetainedPredecessor<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}
impl<K, V, M> Eq for BptreeMapRetainedPredecessor<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
}
impl<K, V, M> BptreeMapRetainedPredecessor<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Compare the same original family and reader; equality is never by value.
    pub fn matches(&self, other: &BptreeMapPredecessor<'_, K, V, M>) -> bool {
        self.inner.matches(&other.inner)
    }
}

/// Actual original map writer before planning or admitting a successor.
/// No mutable cursor or allocation exists until a closed admission succeeds.
#[must_use = "admit a successor or release the original acquired map writer"]
pub struct BptreeMapWriterAcquisition<'a, K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapWriterAcquisition<'a, K, V, M>,
}

/// Actual original map writer awaiting predecessor validation.
/// No mutable tree access or publication is possible before validation succeeds.
#[must_use = "validate or abort the original acquired map writer"]
pub struct BptreeMapOwnedAcquisition<'a, K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapOwnedAcquisition<'a, K, V, M>,
}
impl<'a, K, V, M> BptreeMapOwnedAcquisition<'a, K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Keep actual lock custody on stale or poisoned predecessor refusal.
    pub fn validate(self) -> Result<BptreeMapWriteTxn<'a, K, V, M>, (Self, OwnedWriteError)> {
        self.inner
            .validate()
            .map(|inner| BptreeMapWriteTxn { inner })
            .map_err(|(inner, error)| (Self { inner }, error))
    }
    /// Unlock without changing the original private nodes or cursor allocation.
    pub fn abort(self) -> BptreeMapOwned<K, V, M> {
        BptreeMapOwned {
            inner: self.inner.abort(),
        }
    }
}

/// The exact unpublished successor of a synchronous [`BptreeMap`].
///
/// This move-only owner retains the original cursor allocation, working nodes,
/// base reader and root, so its immutable snapshot remains valid even if the
/// map is dropped. The cursor is allocated during original writer acquisition
/// and its same allocation moves through detach, refusal and reattachment.
/// Reattachment accepts only that original map and unchanged reader generation.
/// It does not recreate a cursor, copy entries or grant higher-level publication
/// authority. Destruction aborts the unpublished work.
pub struct BptreeMapOwned<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapOwned<K, V, M>,
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    BptreeMapOwned<K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
{
    /// Borrow this original unpublished owner's family and predecessor.
    pub fn predecessor(&self) -> BptreeMapPredecessor<'_, K, V, M> {
        BptreeMapPredecessor {
            inner: self.inner.predecessor(),
        }
    }

    /// Compare the retained predecessor with the current target without waiting.
    /// This advisory result grants no lease and cannot replace exact reacquisition.
    pub fn try_matches_current(
        &self,
        target: &BptreeMap<K, V, M>,
    ) -> Result<bool, OwnedWriteError> {
        self.inner.try_matches_current(&target.inner)
    }

    /// Observe the original predecessor without waiting, retaining the actual
    /// reader release until the caller has unlocked its enclosing aggregate.
    /// A true result is advisory and must be reauthenticated by writer acquisition.
    pub fn try_matches_current_retaining(
        &self,
        target: &BptreeMap<K, V, M>,
    ) -> Result<(bool, Option<iroha_allocation::release::DeferredRelease>), OwnedWriteError> {
        self.inner.try_matches_current_retaining(&target.inner)
    }

    /// Borrow a value from the original unpublished successor.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.as_ref().search(key)
    }

    /// Number of entries retained in this original private generation.
    pub fn len(&self) -> usize {
        self.inner.as_ref().len()
    }

    /// Whether this original private generation has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrow an ordered range directly from this retained original cursor.
    pub fn range<R, T>(&self, range: R) -> RangeIter<'_, K, V, M::Charge>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.inner.as_ref().range(range)
    }

    /// Borrow original entries in key order without reconstructing the successor.
    pub fn iter(&self) -> Iter<'_, K, V, M::Charge> {
        self.inner.as_ref().kv_iter()
    }

    /// Borrow an immutable snapshot of the retained successor.
    pub fn to_snapshot(&self) -> BptreeMapReadSnapshot<'_, K, V, M> {
        BptreeMapReadSnapshot {
            inner: SnapshotType::W(self.inner.as_ref()),
        }
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static>
    BptreeMapOwned<K, V, Untracked>
{
    /// Edit this exclusively owned private generation without taking a map lock.
    /// Publication still requires reacquiring its unchanged original predecessor.
    /// A mutation panic makes the private cursor unusable; drop that owner.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.get_mut().insert(key, value)
    }

    /// Remove from the original private generation without reacquiring its map.
    /// The original base remains retained, even after another generation publishes.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.get_mut().remove(key)
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    BptreeMap<K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
{
    /// Retain this map's original charged root without a new identity allocation.
    pub fn family(&self) -> BptreeMapFamily<K, V, M> {
        BptreeMapFamily {
            inner: self.inner.family(),
        }
    }

    /// Borrow an exact retained predecessor from this original map family.
    /// Foreign families refuse; advancing this map never changes the returned
    /// immutable cut. No physical lock, allocation or callback is involved.
    pub fn read_predecessor(
        &self,
        predecessor: &BptreeMapRetainedPredecessor<K, V, M>,
    ) -> Option<BptreeMapReadTxn<'_, K, V, M>> {
        self.inner
            .read_predecessor(&predecessor.inner)
            .map(|inner| BptreeMapReadTxn { inner })
    }

    /// Initiate a read transaction for the tree, concurrent to any
    /// other readers or writers.
    pub fn read(&self) -> BptreeMapReadTxn<'_, K, V, M> {
        let inner = self.inner.read();
        BptreeMapReadTxn { inner }
    }

    /// Observe the original active-reader mutex before probing read or commit
    /// preparation. Retained snapshots and writer releases cannot satisfy it.
    pub fn observe_reader_release(&self) -> iroha_allocation::release::ReleaseWait {
        self.inner.observe_reader_release()
    }

    /// Retain the original current reader without waiting or allocating.
    /// `Busy` and `Poisoned` describe the reader lock, not a writer lease.
    pub fn try_read(&self) -> Result<BptreeMapReadTxn<'_, K, V, M>, OwnedWriteError> {
        self.inner
            .try_read()
            .map(|inner| BptreeMapReadTxn { inner })
    }

    /// Constant-space custody for this original map's actual reader-lock releases.
    /// Drop only after all enclosing State/effect/publication fences are released.
    pub fn reader_release_batch(&self) -> iroha_allocation::release::DeferredReleaseBatch {
        self.inner.reader_release_batch()
    }

    /// Pin the current original generation and defer the actual reader-lock release.
    /// A foreign batch returns Changed before acquisition; a poisoned acquisition
    /// returns Poisoned and retains its actual release/poison in the original batch.
    pub fn read_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<BptreeMapReadTxn<'_, K, V, M>, OwnedWriteError> {
        self.inner
            .read_retaining(releases)
            .map(|inner| BptreeMapReadTxn { inner })
    }

    /// Nonblocking current-reader acquisition with caller-retained actual release.
    /// Busy acquires nothing and records no release; foreign batches refuse first.
    pub fn try_read_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<BptreeMapReadTxn<'_, K, V, M>, OwnedWriteError> {
        self.inner
            .try_read_retaining(releases)
            .map(|inner| BptreeMapReadTxn { inner })
    }

    /// Wait for the actual writer without constructing a cursor or invoking a callback.
    /// The returned owner retains poison so aggregate cleanup can bind it first.
    pub fn acquire_writer(&self) -> BptreeMapWriterAcquisition<'_, K, V, M> {
        BptreeMapWriterAcquisition {
            inner: self.inner.acquire_writer(),
        }
    }

    /// Acquire the actual writer before planning or invoking admission callbacks.
    /// Only contention returns `None`; an acquired poisoned writer is retained
    /// until admission rejects it, without invoking the caller's provider.
    pub fn try_acquire_writer(&self) -> Option<BptreeMapWriterAcquisition<'_, K, V, M>> {
        self.inner
            .try_acquire_writer()
            .map(|inner| BptreeMapWriterAcquisition { inner })
    }

    /// Acquire the original physical writer and retain it through validation.
    /// Foreign roots and contention return without a physical release. Stale
    /// predecessors and poison remain inside the returned acquired owner.
    pub fn try_acquire_owned(
        &self,
        owned: BptreeMapOwned<K, V, M>,
    ) -> MapOwnedAcquireResult<'_, K, V, M> {
        owned.inner.as_ref().assert_operable();
        self.inner
            .try_acquire_owned(owned.inner)
            .map(|inner| BptreeMapOwnedAcquisition { inner })
            .map_err(|(inner, error)| (BptreeMapOwned { inner }, error))
    }

    /// Reacquire the original private successor for retained publication custody.
    /// Unrelated outer unwind can abandon unchanged roots; actual original
    /// mutation still poisons them. This does not prepare or publish the cursor,
    /// and every refusal preserves its exact ownership for caller cleanup.
    /// The acquired physical guard remains on its original thread.
    ///
    /// ```compile_fail
    /// use concread::bptree::BptreeMap;
    /// let map: &'static BptreeMap<usize, usize> = Box::leak(Box::new(BptreeMap::new()));
    /// let owned = map.write().detach();
    /// let acquired = map.try_acquire_owned_retained(owned).unwrap_or_else(|_| panic!());
    /// std::thread::spawn(move || drop(acquired));
    /// ```
    pub fn try_acquire_owned_retained(
        &self,
        owned: BptreeMapOwned<K, V, M>,
    ) -> MapOwnedAcquireResult<'_, K, V, M> {
        owned.inner.as_ref().assert_operable();
        self.inner
            .try_acquire_owned_retained(owned.inner)
            .map(|inner| BptreeMapOwnedAcquisition { inner })
            .map_err(|(inner, error)| (BptreeMapOwned { inner }, error))
    }

    /// Reacquire the original writer without copying or allocating a successor.
    ///
    /// Both the physical map and its exact base reader generation must match.
    /// Every refusal returns the same retained owner. Acquisition never waits
    /// and never takes the reader mutex; `Busy` identifies writer contention.
    pub fn try_write_owned(
        &self,
        owned: BptreeMapOwned<K, V, M>,
    ) -> MapOwnedWriteResult<'_, K, V, M> {
        self.try_acquire_owned(owned)?
            .validate()
            .map_err(|(acquired, error)| (acquired.abort(), error))
    }

    /// Whether an unwind poisoned the map's original writer lock.
    pub fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    BptreeMapReadTxn<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
{
    /// Borrow this pinned reader's original map and exact predecessor generation.
    /// The projection remains stable across publications and grants no writer lease.
    pub fn predecessor(&self) -> BptreeMapPredecessor<'_, K, V, M> {
        BptreeMapPredecessor {
            inner: self.inner.predecessor(),
        }
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    BptreeMapWriteTxn<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
{
    /// Borrow this writer's original family and reader, regardless of private edits.
    pub fn predecessor(&self) -> BptreeMapPredecessor<'_, K, V, M> {
        BptreeMapPredecessor {
            inner: self.inner.predecessor(),
        }
    }

    /// Commit the changes from this write transaction. Readers after this point
    /// will be able to perceive these changes.
    ///
    /// To abort (unstage changes), just do not call this function.
    pub fn commit(self) {
        drop(self.prepare_commit().publish().release());
    }

    /// Retain the exact unpublished successor and release its original lock.
    ///
    /// This moves the original cursor and preallocated publication shell. It
    /// neither publishes changes nor clones keys or values.
    pub fn detach(self) -> BptreeMapOwned<K, V, M> {
        self.inner.as_ref().assert_operable();
        BptreeMapOwned {
            inner: self.inner.detach(),
        }
    }

    /// Unlock an abandoned cursor while retaining its exact allocation cleanup.
    ///
    /// This accepts a cursor whose edit unwound. Unlike detachment, the returned
    /// opaque owner has no read, mutation, attachment or publication capability.
    /// Keep it until every enclosing writer has released, then drop to reclaim
    /// the original private nodes, cursor, shells and charges.
    pub fn abort_retaining(self) -> BptreeMapAbandonment<K, V, M> {
        BptreeMapAbandonment {
            _inner: self.inner.detach(),
        }
    }
}

/// Cleanup-only custody of an abandoned original private map generation.
/// It contains no physical writer and grants no way to reuse a failed cursor.
#[must_use = "retain cleanup until every enclosing physical writer has released"]
pub struct BptreeMapAbandonment<K, V, M = Untracked>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    _inner: MapOwned<K, V, M>,
}

/// An original map successor checked under both physical publication locks.
/// Dropping it abandons the private successor after releasing its locks.
pub struct BptreeMapPreparedCommit<'a, K, V, M = Untracked>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapPreparedCommit<'a, K, V, M>,
}

/// The original map writer retained by its caller during physical preparation.
/// No cursor, node, identity or charge is copied or allocated by this phase.
#[must_use = "retain original preparation until aggregate release or publication"]
pub struct BptreeMapCommitSlot<'a, K, V, M = Untracked>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapCommitSlot<'a, K, V, M>,
}

impl<'a, K, V, M> BptreeMapCommitSlot<'a, K, V, M>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Prepare under caller custody, retaining physical ownership on unwind.
    pub fn prepare(&mut self) {
        self.inner.as_ref().assert_operable();
        self.inner.prepare();
    }

    /// Try preparation without releasing the original writer on local refusal.
    pub fn try_prepare(&mut self) -> Result<(), OwnedWriteError> {
        self.inner.as_ref().assert_operable();
        self.inner.try_prepare()
    }

    /// Whether all original physical owners and cursor invariants are checked.
    pub fn is_prepared(&self) -> bool {
        self.inner.is_prepared()
    }

    /// Transfer checked ownership without another lock, clone or allocation.
    pub fn into_prepared(self) -> BptreeMapPreparedCommit<'a, K, V, M> {
        BptreeMapPreparedCommit {
            inner: self.inner.into_prepared(),
        }
    }

    /// Release any acquired reader while retaining its original notification.
    /// The original writer is returned even when cursor validation unwound.
    pub fn abort_retaining(
        self,
    ) -> (
        BptreeMapWriteTxn<'a, K, V, M>,
        Option<iroha_allocation::release::DeferredRelease>,
    ) {
        let (inner, release) = self.inner.abort_retaining();
        (BptreeMapWriteTxn { inner }, release)
    }
}

/// Published original map owners retaining physical locks and cleanup custody.
/// Aggregate owners release every participating map before dropping cleanup.
pub struct BptreeMapPublished<'a, K, V, M = Untracked>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapPublished<'a, K, V, M>,
}

/// Original cursor and reader cleanup retained after physical publication.
/// Destruction frees original bookkeeping and retired payloads before refunding
/// their charges. This owner grants no mutation or publication authority.
pub struct BptreeMapCommitRetirement<K, V, M = Untracked>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    _inner: MapCommitRetirement<K, V, M>,
}

impl<'a, K, V, M> BptreeMapWriteTxn<'a, K, V, M>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Install the original writer in a caller-owned slot without validating yet.
    /// This inert move lets aggregate cleanup remain armed across preparation.
    pub fn commit_slot(self) -> BptreeMapCommitSlot<'a, K, V, M> {
        BptreeMapCommitSlot {
            inner: self.inner.commit_slot(),
        }
    }

    /// Prepare without waiting for the map's short active-reader lock.
    /// Busy or poison returns the exact original writer with its lock still held.
    pub fn try_prepare_commit(
        self,
    ) -> Result<BptreeMapPreparedCommit<'a, K, V, M>, (Self, OwnedWriteError)> {
        let mut slot = self.commit_slot();
        if let Err(error) = slot.try_prepare() {
            let (writer, release) = slot.abort_retaining();
            debug_assert!(release.is_none(), "failed acquisition owned no reader");
            return Err((writer, error));
        }
        Ok(slot.into_prepared())
    }

    /// Acquire and check all physical owners before any aggregate publication.
    /// Preparation allocates nothing and preserves the original cursor. Failed
    /// logical state, poison or inconsistent original ownership panics before
    /// transferring any nodes; aggregate owners prepare every map first.
    pub fn prepare_commit(self) -> BptreeMapPreparedCommit<'a, K, V, M> {
        let mut slot = self.commit_slot();
        slot.prepare();
        slot.into_prepared()
    }
}

impl<'a, K, V, M> BptreeMapPreparedCommit<'a, K, V, M>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Release preparation's reader lock and return the same held original writer.
    /// No nodes, reader shell, cursor or admission are recreated or abandoned.
    pub fn abort(self) -> BptreeMapWriteTxn<'a, K, V, M> {
        BptreeMapWriteTxn {
            inner: self.inner.abort(),
        }
    }

    /// Return the original writer while retaining the released reader notification.
    /// Aggregate abort must unlock its remaining participants before dropping it.
    pub fn abort_retaining(
        self,
    ) -> (
        BptreeMapWriteTxn<'a, K, V, M>,
        iroha_allocation::release::DeferredRelease,
    ) {
        let (inner, release) = self.inner.abort_retaining();
        (BptreeMapWriteTxn { inner }, release)
    }

    /// Publish original nodes without allocation or user destruction.
    /// Both physical locks remain held through the returned owner. Publish all
    /// prepared participants and their shared identity before releasing any.
    pub fn publish(self) -> BptreeMapPublished<'a, K, V, M> {
        BptreeMapPublished {
            inner: self.inner.publish(),
        }
    }
}

impl<K, V, M> BptreeMapPublished<'_, K, V, M>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Unlock this map without invoking any payload or charge destructor.
    /// Release every participating map and aggregate physical lock before
    /// dropping the returned cleanup owners or issuing release notifications.
    pub fn release(self) -> BptreeMapCommitRetirement<K, V, M> {
        BptreeMapCommitRetirement {
            _inner: self.inner.release(),
        }
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static>
    BptreeMap<K, V>
{
    /// Initiate a write transaction for the tree, exclusive to this
    /// writer, and concurrently to all existing reads.
    pub fn write(&self) -> BptreeMapWriteTxn<'_, K, V> {
        self.acquire_writer().write()
    }
}

impl<K, V, M> BptreeMapWriterAcquisition<'_, K, V, M>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Whether this actual acquired writer was already poisoned.
    pub fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }
}

impl<'a, K, V> BptreeMapWriterAcquisition<'a, K, V>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Construct the original untracked writer; poison panics before construction.
    pub fn write(self) -> BptreeMapWriteTxn<'a, K, V> {
        BptreeMapWriteTxn {
            inner: self.inner.write_with(|_| ()),
        }
    }
}

#[cfg(feature = "serde")]
impl<K, V, M> Serialize for BptreeMapReadTxn<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
    K: Serialize + Clone + Ord + Debug + Sync + Send + 'static,
    V: Serialize + Clone + Sync + Send + 'static,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_map(Some(self.len()))?;

        for (key, val) in self.iter() {
            state.serialize_entry(key, val)?;
        }

        state.end()
    }
}

#[cfg(feature = "serde")]
impl<K, V, M> Serialize for BptreeMap<K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
    K: Serialize + Clone + Ord + Debug + Sync + Send + 'static,
    V: Serialize + Clone + Sync + Send + 'static,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.read().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, K, V> Deserialize<'de> for BptreeMap<K, V>
where
    K: Deserialize<'de> + Clone + Ord + Debug + Sync + Send + 'static,
    V: Deserialize<'de> + Clone + Sync + Send + 'static,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(MapCollector::new())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Bound;

    use super::BptreeMap;
    use crate::internals::bptree::node::{assert_released, L_CAPACITY};
    // use rand::prelude::*;
    use rand::seq::SliceRandom;

    #[test]
    fn public_map_owners_account_for_original_policy_and_charge_thread_safety() {
        use std::{cell::Cell, marker::PhantomData, rc::Rc};

        struct Policy<C, P>(PhantomData<(C, P)>);
        impl<C, P> super::NodeFunding for Policy<C, P> {
            type Charge = C;

            fn take_node_charge(&mut self, _layout: std::alloc::Layout) -> C {
                unreachable!("type-only capability assertion")
            }
        }
        impl<C, P> super::NodeCloning<usize, usize> for Policy<C, P> {
            fn clone_key(&mut self, key: &usize) -> usize {
                *key
            }

            fn clone_value(&mut self, value: &usize) -> usize {
                *value
            }
        }
        type Mode<C, P> = super::Prepaid<Policy<C, P>>;
        fn send_sync<T: Send + Sync>() {}
        send_sync::<BptreeMap<usize, usize, Mode<usize, ()>>>();
        send_sync::<super::BptreeMapReadTxn<'_, usize, usize, Mode<usize, ()>>>();
        send_sync::<super::BptreeMapOwned<usize, usize, Mode<usize, ()>>>();
        send_sync::<super::BptreeMapFamily<usize, usize, Mode<usize, ()>>>();
        send_sync::<super::BptreeMapPredecessor<'_, usize, usize, Mode<usize, ()>>>();
        send_sync::<super::BptreeMapRetainedPredecessor<usize, usize, Mode<usize, ()>>>();
        #[cfg(feature = "asynch")]
        send_sync::<super::asynch::BptreeMap<usize, usize, Mode<usize, ()>>>();

        trait AmbiguousIfSend<A> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfSend<()> for T {}
        impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
        trait AmbiguousIfSync<A> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
        let _ = <BptreeMap<usize, usize, Mode<Rc<()>, ()>> as AmbiguousIfSend<_>>::probe;
        let _ = <BptreeMap<usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSend<_>>::probe;
        let _ = <BptreeMap<usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSync<_>>::probe;
        let _ = <BptreeMap<usize, usize, Mode<usize, Rc<()>>> as AmbiguousIfSend<_>>::probe;
        let _ = <BptreeMap<usize, usize, Mode<usize, Cell<usize>>> as AmbiguousIfSync<_>>::probe;
        let _ = <super::BptreeMapReadTxn<'_, usize, usize, Mode<Rc<()>, ()>> as AmbiguousIfSend<
            _,
        >>::probe;
        let _ =
            <super::BptreeMapReadTxn<'_, usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSync<
                _,
            >>::probe;
        let _ =
            <super::BptreeMapOwned<usize, usize, Mode<Rc<()>, ()>> as AmbiguousIfSend<_>>::probe;
        let _ = <super::BptreeMapOwned<usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSync<
            _,
        >>::probe;
        let _ =
            <super::BptreeMapFamily<usize, usize, Mode<Rc<()>, ()>> as AmbiguousIfSend<_>>::probe;
        let _ = <super::BptreeMapFamily<usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSync<
            _,
        >>::probe;
        let _ =
            <super::BptreeMapPredecessor<'_, usize, usize, Mode<Rc<()>, ()>> as AmbiguousIfSend<
                _,
            >>::probe;
        let _ = <super::BptreeMapPredecessor<'_, usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSync<_>>::probe;
        let _ = <super::BptreeMapRetainedPredecessor<usize, usize, Mode<Rc<()>, ()>> as AmbiguousIfSend<_>>::probe;
        let _ = <super::BptreeMapRetainedPredecessor<usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSync<_>>::probe;
        #[cfg(feature = "asynch")]
        {
            let _ = <super::asynch::BptreeMap<usize, usize, Mode<Cell<usize>, ()>> as AmbiguousIfSend<_>>::probe;
            let _ = <super::asynch::BptreeMapReadTxn<'_, usize, usize, Mode<Rc<()>, ()>> as AmbiguousIfSync<_>>::probe;
        }
    }

    #[test]
    fn original_family_and_predecessor_comparisons_reject_foreign_equal_and_aba_maps() {
        use crate::internals::bptree::node::allocation_tests::without_allocations;
        let map = BptreeMap::new();
        let foreign = BptreeMap::new();
        for map in [&map, &foreign] {
            let mut writer = map.write();
            writer.insert(1usize, 7usize);
            writer.commit();
        }
        let (family, other_family) = without_allocations(|| (map.family(), foreign.family()));
        without_allocations(|| {
            assert!(family.clone().same_family(&family));
            assert!(family.matches(&map));
            assert!(!family.matches(&foreign));
            assert!(!family.same_family(&other_family));
        });
        let old = map.write().detach();
        let retained = without_allocations(|| old.predecessor().retain());
        without_allocations(|| {
            assert_eq!(retained, retained.clone());
            assert!(retained.matches(&old.predecessor()));
        });
        let mut writer = map.write();
        without_allocations(|| {
            assert!(old.predecessor().same_predecessor(&writer.predecessor()));
            assert_eq!(old.try_matches_current(&map), Ok(true));
            assert_eq!(old.try_matches_current(&foreign), Ok(false));
        });
        writer.insert(1, 8);
        assert!(
            old.predecessor().same_predecessor(&writer.predecessor()),
            "private edits do not replace predecessor"
        );
        writer.commit();
        let mut writer = map.write();
        writer.insert(1, 7);
        writer.commit();
        assert_eq!(map.read().get(&1), Some(&7));
        let unchanged = map.write().detach();
        without_allocations(|| {
            assert!(family.matches(&map), "family persists through publications");
            assert!(!old.predecessor().same_predecessor(&unchanged.predecessor()));
            assert!(!retained.matches(&unchanged.predecessor()));
            assert_eq!(
                old.try_matches_current(&map),
                Ok(false),
                "equal bytes do not undo generation advance"
            );
            assert_eq!(unchanged.try_matches_current(&map), Ok(true));
        });
        // Even an untouched publication consumes its own original reader shell.
        map.write().commit();
        assert_eq!(unchanged.try_matches_current(&map), Ok(false));
        drop(old);
        drop(unchanged);
        drop(map);
        drop(foreign);
        drop(family);
        drop(other_family);
        drop(retained);
        assert_released();
    }

    #[test]
    fn original_prepared_abort_returns_same_private_payload_and_cursor_for_publication() {
        use crate::internals::bptree::node::allocation_tests::without_allocations;
        let map = BptreeMap::<usize, Box<[u8]>>::new();
        let old_read = without_allocations(|| map.try_read().expect("original reader"));
        let mut writer = map.write();
        writer.insert(1, vec![7; 137].into_boxed_slice());
        let cursor = writer.inner.as_ref() as *const _;
        let value = writer.get(&1).unwrap().as_ptr();
        for _ in 0..3 {
            writer = without_allocations(|| {
                writer
                    .try_prepare_commit()
                    .unwrap_or_else(|_| panic!("uncontended original preparation"))
                    .abort()
            });
            assert_eq!(writer.inner.as_ref() as *const _, cursor);
            assert_eq!(writer.get(&1).unwrap().as_ptr(), value);
            assert!(old_read.get(&1).is_none());
            assert!(
                map.try_write().is_none(),
                "returned writer retains physical lease"
            );
        }
        let owned = without_allocations(|| writer.detach());
        assert_eq!(owned.inner.as_ref() as *const _, cursor);
        let writer = without_allocations(|| {
            map.try_write_owned(owned)
                .unwrap_or_else(|_| panic!("original retry"))
        });
        let retirement = without_allocations(|| {
            writer
                .try_prepare_commit()
                .unwrap_or_else(|_| panic!("original publication"))
                .publish()
                .release()
        });
        without_allocations(|| {
            let current = map.try_read().expect("published reader");
            assert_eq!(current.get(&1).unwrap().as_ptr(), value);
        });
        assert!(old_read.get(&1).is_none());
        drop(retirement);
        drop(old_read);
        drop(map);
        assert_released();
    }

    #[test]
    fn original_owned_untracked_edits_need_no_map_writer_and_cannot_publish_stale_work() {
        use crate::internals::bptree::node::allocation_tests::without_allocations;
        let map = BptreeMap::<usize, usize>::new();
        let mut writer = map.write();
        writer.insert(0, 7);
        writer.commit();
        let old_read = map.read();
        let mut owned = map.write().detach();
        let cursor = owned.inner.as_ref() as *const _;
        let mut held = map.write();
        assert_eq!(owned.insert(1, 11), None);
        assert_eq!(owned.remove(&0), Some(7));
        assert_eq!(old_read.get(&0), Some(&7));
        assert_eq!(old_read.get(&1), None);
        assert_eq!(held.get(&0), Some(&7));
        held.insert(9, 99);
        held.commit();
        // A newer publication cannot invalidate retained immutable source nodes.
        assert_eq!(owned.insert(2, 22), None);
        assert_eq!(owned.get(&9), None);
        let (owned, error) = without_allocations(|| {
            map.try_write_owned(owned)
                .err()
                .expect("stale original source")
        });
        assert_eq!(error, super::OwnedWriteError::Changed);
        assert_eq!(owned.inner.as_ref() as *const _, cursor);
        assert_eq!(owned.get(&1), Some(&11));
        assert_eq!(owned.get(&2), Some(&22));
        without_allocations(|| {
            assert_eq!(owned.len(), 2);
            assert!(!owned.is_empty());
            let mut range = owned.range(1..=2);
            assert_eq!(range.next_back(), Some((&2, &22)));
            assert_eq!(range.next(), Some((&1, &11)));
            assert_eq!(range.next(), None);
        });
        assert_eq!(map.read().get(&1), None);
        assert_eq!(map.read().get(&9), Some(&99));
        drop(owned);
        drop(old_read);
        drop(map);
        assert_released();
    }

    #[test]
    fn test_bptree2_map_basic_write() {
        let bptree: BptreeMap<usize, usize> = BptreeMap::new();
        {
            let mut bpwrite = bptree.write();
            // We should be able to insert.
            bpwrite.insert(0, 0);
            bpwrite.insert(1, 1);
            assert!(bpwrite.get(&0) == Some(&0));
            assert!(bpwrite.get(&1) == Some(&1));
            bpwrite.insert(2, 2);
            bpwrite.commit();
            // println!("commit");
        }
        {
            // Do a clear, but roll it back.
            let mut bpwrite = bptree.write();
            bpwrite.clear();
            // DO NOT commit, this triggers the rollback.
            // println!("post clear");
        }
        {
            let bpwrite = bptree.write();
            assert!(bpwrite.get(&0) == Some(&0));
            assert!(bpwrite.get(&1) == Some(&1));
            // println!("fin write");
        }
        std::mem::drop(bptree);
        assert_released();
    }

    #[test]
    fn test_bptree2_map_cursed_get_mut() {
        let bptree: BptreeMap<usize, usize> = BptreeMap::new();
        {
            let mut w = bptree.write();
            w.insert(0, 0);
            w.commit();
        }
        let r1 = bptree.read();
        {
            let mut w = bptree.write();
            let cursed_zone = w.get_mut(&0).unwrap();
            *cursed_zone = 1;
            // Correctly fails to work as it's a second borrow, which isn't
            // possible once w.remove occurs
            // w.remove(&0);
            // *cursed_zone = 2;
            w.commit();
        }
        let r2 = bptree.read();
        assert!(r1.get(&0) == Some(&0));
        assert!(r2.get(&0) == Some(&1));

        /*
        // Correctly fails to compile. PHEW!
        let fail = {
            let mut w = bptree.write();
            w.get_mut(&0).unwrap()
        };
        */
        std::mem::drop(r1);
        std::mem::drop(r2);
        std::mem::drop(bptree);
        assert_released();
    }

    #[test]
    fn test_bptree2_map_from_iter_1() {
        let ins: Vec<usize> = (0..(L_CAPACITY << 4)).collect();

        let map = BptreeMap::from_iter(ins.into_iter().map(|v| (v, v)));

        {
            let w = map.write();
            assert!(w.verify());
            println!("{:?}", w.tree_density());
        }
        // assert!(w.tree_density() == ((L_CAPACITY << 4), (L_CAPACITY << 4)));
        std::mem::drop(map);
        assert_released();
    }

    #[test]
    fn test_bptree2_map_from_iter_2() {
        let mut rng = rand::rng();
        let mut ins: Vec<usize> = (0..(L_CAPACITY << 4)).collect();
        ins.shuffle(&mut rng);

        let map = BptreeMap::from_iter(ins.into_iter().map(|v| (v, v)));

        {
            let w = map.write();
            assert!(w.verify());
            // w.compact_force();
            assert!(w.verify());
            // assert!(w.tree_density() == ((L_CAPACITY << 4), (L_CAPACITY << 4)));
        }

        std::mem::drop(map);
        assert_released();
    }

    fn bptree_map_basic_concurrency(lower: usize, upper: usize) {
        // Create a map
        let map = BptreeMap::new();

        // add values
        {
            let mut w = map.write();
            w.extend((0..lower).map(|v| (v, v)));
            w.commit();
        }

        // read
        let r = map.read();
        assert!(r.len() == lower);
        for i in 0..lower {
            assert!(r.contains_key(&i))
        }

        // Check a second write doesn't interfere
        {
            let mut w = map.write();
            w.extend((lower..upper).map(|v| (v, v)));
            w.commit();
        }

        assert!(r.len() == lower);

        // But a new write can see
        let r2 = map.read();
        assert!(r2.len() == upper);
        for i in 0..upper {
            assert!(r2.contains_key(&i))
        }

        // Now drain the tree, and the reader should be unaffected.
        {
            let mut w = map.write();
            for i in 0..upper {
                assert!(w.remove(&i).is_some())
            }
            w.commit();
        }

        // All consistent!
        assert!(r.len() == lower);
        assert!(r2.len() == upper);
        for i in 0..upper {
            assert!(r2.contains_key(&i))
        }

        let r3 = map.read();
        // println!("{:?}", r3.len());
        assert!(r3.is_empty());

        std::mem::drop(r);
        std::mem::drop(r2);
        std::mem::drop(r3);

        std::mem::drop(map);
        assert_released();
    }

    #[test]
    fn test_bptree2_map_acb_order() {
        // Need to ensure that txns are dropped in order.

        // Add data, enough to cause a split. All data should be *2
        let map = BptreeMap::new();
        // add values
        {
            let mut w = map.write();
            w.extend((0..(L_CAPACITY * 2)).map(|v| (v * 2, v * 2)));
            w.commit();
        }
        let ro_txn_a = map.read();

        // New write, add 1 val
        {
            let mut w = map.write();
            w.insert(1, 1);
            w.commit();
        }

        let ro_txn_b = map.read();
        // ro_txn_b now owns nodes from a

        // New write, update a value
        {
            let mut w = map.write();
            w.insert(1, 10001);
            w.commit();
        }

        let ro_txn_c = map.read();
        // ro_txn_c
        // Drop ro_txn_b
        assert!(ro_txn_b.verify());
        std::mem::drop(ro_txn_b);
        // Are both still valid?
        assert!(ro_txn_a.verify());
        assert!(ro_txn_c.verify());
        // Drop remaining
        std::mem::drop(ro_txn_a);
        std::mem::drop(ro_txn_c);
        std::mem::drop(map);
        assert_released();
    }

    #[test]
    fn test_bptree2_map_weird_txn_behaviour() {
        let map: BptreeMap<usize, usize> = BptreeMap::new();

        let mut wr = map.write();
        let rd = map.read();

        wr.insert(1, 1);
        assert!(rd.get(&1).is_none());
        wr.commit();
        assert!(rd.get(&1).is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_bptree2_map_basic_concurrency_small() {
        bptree_map_basic_concurrency(100, 200)
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_bptree2_map_basic_concurrency_large() {
        bptree_map_basic_concurrency(10_000, 20_000)
    }

    #[test]
    fn test_bptree2_map_rangeiter_1() {
        let ins: Vec<usize> = (0..100).collect();

        let map = BptreeMap::from_iter(ins.into_iter().map(|v| (v, v)));

        {
            let w = map.write();
            assert!(w.range(0..100).count() == 100);
            assert!(w.range(25..100).count() == 75);
            assert!(w.range(0..75).count() == 75);
            assert!(w.range(25..75).count() == 50);
        }
        // assert!(w.tree_density() == ((L_CAPACITY << 4), (L_CAPACITY << 4)));
        std::mem::drop(map);
        assert_released();
    }

    #[test]
    fn test_bptree2_map_rangeiter_2() {
        let map = BptreeMap::from_iter([(3, ()), (4, ()), (0, ())]);

        let r = map.read();
        assert!(r.range(1..=2).count() == 0);
    }

    #[test]
    fn test_bptree2_map_rangeiter_3() {
        let map = BptreeMap::from_iter([0, 1, 2, 3, 4, 5, 6, 8].map(|v| (v, ())));

        let r = map.read();
        assert!(r.range((Bound::Excluded(6), Bound::Included(7))).count() == 0);
        assert!(r.range((Bound::Excluded(6), Bound::Excluded(8))).count() == 0);
    }

    /*
    #[test]
    fn test_bptree2_map_write_compact() {
        let mut rng = rand::thread_rng();
        let insa: Vec<usize> = (0..(L_CAPACITY << 4)).collect();

        let map = BptreeMap::from_iter(insa.into_iter().map(|v| (v, v)));

        let mut w = map.write();
        // Created linearly, should not need compact
        assert!(w.compact() == false);
        assert!(w.verify());
        assert!(w.tree_density() == ((L_CAPACITY << 4), (L_CAPACITY << 4)));

        // Even in reverse, we shouldn't need it ...
        let insb: Vec<usize> = (0..(L_CAPACITY << 4)).collect();
        let bmap = BptreeMap::from_iter(insb.into_iter().rev().map(|v| (v, v)));
        let mut bw = bmap.write();
        assert!(bw.compact() == false);
        assert!(bw.verify());
        // Assert the density is "best"
        assert!(bw.tree_density() == ((L_CAPACITY << 4), (L_CAPACITY << 4)));

        // Random however, may.
        let mut insc: Vec<usize> = (0..(L_CAPACITY << 4)).collect();
        insc.shuffle(&mut rng);
        let cmap = BptreeMap::from_iter(insc.into_iter().map(|v| (v, v)));
        let mut cw = cmap.write();
        let (_n, d1) = cw.tree_density();
        cw.compact_force();
        assert!(cw.verify());
        let (_n, d2) = cw.tree_density();
        assert!(d2 <= d1);
    }
    */

    /*
    use std::sync::atomic::{AtomicUsize, Ordering};
    use crossbeam_utils::thread::scope;
    use rand::Rng;
    const MAX_TARGET: usize = 210_000;

    #[test]
    fn test_bptree2_map_thread_stress() {
        let start = time::now();
        let reader_completions = AtomicUsize::new(0);
        // Setup a tree with some initial data.
        let map: BptreeMap<usize, usize> = BptreeMap::from_iter(
            (0..10_000).map(|v| (v, v))
        );
        // now setup the threads.
        scope(|scope| {
            let mref = &map;
            let rref = &reader_completions;

            let _readers: Vec<_> = (0..7)
                .map(|_| {
                    scope.spawn(move || {
                        println!("Started reader ...");
                        let mut rng = rand::thread_rng();
                        let mut proceed = true;
                        while proceed {
                            let m_read = mref.read();
                            proceed = ! m_read.contains_key(&MAX_TARGET);
                            // Get a random number.
                            // Add 10_000 * random
                            // Remove 10_000 * random
                            let v1 = rng.gen_range(1, 18) * 10_000;
                            let r1 = v1 + 10_000;
                            for i in v1..r1 {
                                m_read.get(&i);
                            }
                            assert!(m_read.verify());
                            rref.fetch_add(1, Ordering::Relaxed);
                        }
                        println!("Closing reader ...");
                    })
                })
                .collect();

            let _writers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(move || {
                        println!("Started writer ...");
                        let mut rng = rand::thread_rng();
                        let mut proceed = true;
                        while proceed {
                            let mut m_write = mref.write();
                            proceed = ! m_write.contains_key(&MAX_TARGET);
                            // Get a random number.
                            // Add 10_000 * random
                            // Remove 10_000 * random
                            let v1 = rng.gen_range(1, 18) * 10_000;
                            let r1 = v1 + 10_000;
                            let v2 = rng.gen_range(1, 19) * 10_000;
                            let r2 = v2 + 10_000;

                            for i in v1..r1 {
                                m_write.insert(i, i);
                            }
                            for i in v2..r2 {
                                m_write.remove(&i);
                            }
                            m_write.commit();
                        }
                        println!("Closing writer ...");
                    })
                })
                .collect();

            let _complete = scope.spawn(move || {
                let mut last_value = 200_000;
                while last_value < MAX_TARGET {
                    let mut m_write = mref.write();
                    last_value += 1;
                    if last_value % 1000 == 0 {
                        println!("{:?}", last_value);
                    }
                    m_write.insert(last_value, last_value);
                    assert!(m_write.verify());
                    m_write.commit();
                }
            });

        });
        let end = time::now();
        print!("BptreeMap MT create :{} reader completions :{}", end - start, reader_completions.load(Ordering::Relaxed));
        // Done!
    }

    #[test]
    fn test_std_mutex_btreemap_thread_stress() {
        use std::collections::BTreeMap;
        use std::sync::Mutex;

        let start = time::now();
        let reader_completions = AtomicUsize::new(0);
        // Setup a tree with some initial data.
        let map: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::from_iter(
            (0..10_000).map(|v| (v, v))
        ));
        // now setup the threads.
        scope(|scope| {
            let mref = &map;
            let rref = &reader_completions;

            let _readers: Vec<_> = (0..7)
                .map(|_| {
                    scope.spawn(move || {
                        println!("Started reader ...");
                        let mut rng = rand::thread_rng();
                        let mut proceed = true;
                        while proceed {
                            let m_read = mref.lock().unwrap();
                            proceed = ! m_read.contains_key(&MAX_TARGET);
                            // Get a random number.
                            // Add 10_000 * random
                            // Remove 10_000 * random
                            let v1 = rng.gen_range(1, 18) * 10_000;
                            let r1 = v1 + 10_000;
                            for i in v1..r1 {
                                m_read.get(&i);
                            }
                            rref.fetch_add(1, Ordering::Relaxed);
                        }
                        println!("Closing reader ...");
                    })
                })
                .collect();

            let _writers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(move || {
                        println!("Started writer ...");
                        let mut rng = rand::thread_rng();
                        let mut proceed = true;
                        while proceed {
                            let mut m_write = mref.lock().unwrap();
                            proceed = ! m_write.contains_key(&MAX_TARGET);
                            // Get a random number.
                            // Add 10_000 * random
                            // Remove 10_000 * random
                            let v1 = rng.gen_range(1, 18) * 10_000;
                            let r1 = v1 + 10_000;
                            let v2 = rng.gen_range(1, 19) * 10_000;
                            let r2 = v2 + 10_000;

                            for i in v1..r1 {
                                m_write.insert(i, i);
                            }
                            for i in v2..r2 {
                                m_write.remove(&i);
                            }
                        }
                        println!("Closing writer ...");
                    })
                })
                .collect();

            let _complete = scope.spawn(move || {
                let mut last_value = 200_000;
                while last_value < MAX_TARGET {
                    let mut m_write = mref.lock().unwrap();
                    last_value += 1;
                    if last_value % 1000 == 0 {
                        println!("{:?}", last_value);
                    }
                    m_write.insert(last_value, last_value);
                }
            });

        });
        let end = time::now();
        print!("Mutex<BTreeMap> MT create :{} reader completions :{}", end - start, reader_completions.load(Ordering::Relaxed));
        // Done!
    }

    #[test]
    fn test_std_rwlock_btreemap_thread_stress() {
        use std::collections::BTreeMap;
        use std::sync::RwLock;

        let start = time::now();
        let reader_completions = AtomicUsize::new(0);
        // Setup a tree with some initial data.
        let map: RwLock<BTreeMap<usize, usize>> = RwLock::new(BTreeMap::from_iter(
            (0..10_000).map(|v| (v, v))
        ));
        // now setup the threads.
        scope(|scope| {
            let mref = &map;
            let rref = &reader_completions;

            let _readers: Vec<_> = (0..7)
                .map(|_| {
                    scope.spawn(move || {
                        println!("Started reader ...");
                        let mut rng = rand::thread_rng();
                        let mut proceed = true;
                        while proceed {
                            let m_read = mref.read().unwrap();
                            proceed = ! m_read.contains_key(&MAX_TARGET);
                            // Get a random number.
                            // Add 10_000 * random
                            // Remove 10_000 * random
                            let v1 = rng.gen_range(1, 18) * 10_000;
                            let r1 = v1 + 10_000;
                            for i in v1..r1 {
                                m_read.get(&i);
                            }
                            rref.fetch_add(1, Ordering::Relaxed);
                        }
                        println!("Closing reader ...");
                    })
                })
                .collect();

            let _writers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(move || {
                        println!("Started writer ...");
                        let mut rng = rand::thread_rng();
                        let mut proceed = true;
                        while proceed {
                            let mut m_write = mref.write().unwrap();
                            proceed = ! m_write.contains_key(&MAX_TARGET);
                            // Get a random number.
                            // Add 10_000 * random
                            // Remove 10_000 * random
                            let v1 = rng.gen_range(1, 18) * 10_000;
                            let r1 = v1 + 10_000;
                            let v2 = rng.gen_range(1, 19) * 10_000;
                            let r2 = v2 + 10_000;

                            for i in v1..r1 {
                                m_write.insert(i, i);
                            }
                            for i in v2..r2 {
                                m_write.remove(&i);
                            }
                        }
                        println!("Closing writer ...");
                    })
                })
                .collect();

            let _complete = scope.spawn(move || {
                let mut last_value = 200_000;
                while last_value < MAX_TARGET {
                    let mut m_write = mref.write().unwrap();
                    last_value += 1;
                    if last_value % 1000 == 0 {
                        println!("{:?}", last_value);
                    }
                    m_write.insert(last_value, last_value);
                }
            });

        });
        let end = time::now();
        print!("RwLock<BTreeMap> MT create :{} reader completions :{}", end - start, reader_completions.load(Ordering::Relaxed));
        // Done!
    }
    */

    #[cfg(feature = "serde")]
    #[test]
    fn test_bptreee2_serialize_deserialize() {
        let map: BptreeMap<usize, usize> = vec![(10, 11), (15, 16), (20, 21)].into_iter().collect();

        let value = serde_json::to_value(&map).unwrap();
        assert_eq!(value, serde_json::json!({ "10": 11, "15": 16, "20": 21 }));

        let map: BptreeMap<usize, usize> = serde_json::from_value(value).unwrap();
        let mut vec: Vec<(usize, usize)> = map.read().iter().map(|(k, v)| (*k, *v)).collect();
        vec.sort_unstable();
        assert_eq!(vec, [(10, 11), (15, 16), (20, 21)]);
    }
}

#[cfg(test)]
mod acquisition_tests;

#[cfg(test)]
mod abandonment_tests;

#[cfg(all(test, not(feature = "dhat-heap"), not(miri)))]
mod retained_reader_tests;
