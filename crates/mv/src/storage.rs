use crate::{
    BlockMode, Key, PublicationCleanup, PublicationPreparationError, PublicationPreparationResult,
    ReleaseGuard, ReleaseNotification, Value,
    publication::{CapturedPublication, NextPublication, Publication},
};
use concread::bptree::{
    BptreeMap, BptreeMapAbandonment, BptreeMapCheckpoint, BptreeMapOwned, BptreeMapReadSnapshot,
    BptreeMapReadTxn, BptreeMapWriteTxn, Iter, MapMode, NodeCloning, OwnedWriteError, RangeIter,
    Untracked,
};
use std::{borrow::Borrow, collections::BTreeSet, ops::RangeBounds};

#[path = "storage/detached_publication.rs"]
mod detached_publication;
#[path = "storage/frozen_read.rs"]
mod frozen_read;
#[path = "storage/original_read.rs"]
mod original_read;
pub use original_read::CommittedStorageView;
#[path = "storage/original_images.rs"]
mod original_images;
pub use original_images::FrozenStorageImages;
#[path = "storage/frozen_pair.rs"]
mod frozen_pair;
pub use frozen_pair::{FrozenDetached, FrozenDetachedRead};
#[path = "storage/physical.rs"]
mod physical;
pub use detached_publication::DetachedPublicationSlot;
use detached_publication::DetachedPublicationSlotInner;
use physical::PreparedStorageWriters;
#[path = "storage/acquisition.rs"]
mod acquisition;
pub use acquisition::BlockAcquisitionSlot;
#[path = "storage/capture.rs"]
mod capture;
pub use capture::BlockCaptureSlot;
pub use physical::PublicationRetirement;

/// An original physical map writer joined to its release notification.
type MapWriter<'a, K, V, M> = ReleaseGuard<'a, BptreeMapWriteTxn<'a, K, V, M>>;

/// Original current and undo owners released from both writers, with the
/// cleanup that must outlive every enclosing participant.
type DetachedPair<K, V, M, Cleanup> = (
    BptreeMapOwned<K, V, M>,
    BptreeMapOwned<K, Option<V>, M>,
    Cleanup,
);

/// Published map cleanup and its original capture/installation reservations.
/// Physical locks are already free. Retain this owner through all enclosing
/// publication fences; cleanup drops before either reservation on every exit.
pub struct PublishedPublication<
    K: Key,
    V: Value,
    Admission,
    Installation,
    M: StorageMode<K, V> = Untracked,
> {
    retirement: PublicationRetirement<K, V, M>,
    admission: Admission,
    installation: Installation,
}

impl<K: Key, V: Value, Admission, Installation, M: StorageMode<K, V>>
    PublishedPublication<K, V, Admission, Installation, M>
{
    /// Finish cleanup after the enclosing fences, returning separate reservations.
    pub fn into_reservations(self) -> (Admission, Installation) {
        let Self {
            retirement,
            admission,
            installation,
        } = self;
        drop(retirement);
        (admission, installation)
    }
}
/// Original Concread mode for both current values and first undo preimages.
///
/// Implementations cannot introduce another map engine: `MapMode` is sealed by
/// Concread. Both roles retain the same mode and its original allocation owners.
pub trait StorageMode<K: Key, V: Value>:
    MapMode + NodeCloning<K, V> + NodeCloning<K, Option<V>>
{
    /// Physical acquisition custody carried by this mode's original block.
    /// Ordinary storage has no allocation scope; prepaid storage retains the
    /// original thread-bound refund scope until its physical writers release.
    type AcquisitionCustody: Clone;
}
impl<K: Key, V: Value> StorageMode<K, V> for Untracked {
    type AcquisitionCustody = ();
}
impl<K: Key, V: Value, P> StorageMode<K, V> for concread::bptree::Prepaid<P>
where
    P: concread::bptree::NodeFunding,
    concread::bptree::Prepaid<P>: NodeCloning<K, V> + NodeCloning<K, Option<V>>,
{
    type AcquisitionCustody = AdmittedAcquisitionCustody;
}

/// Thread custody for physical prepaid storage acquisition.
///
/// Borrowed acquisition binds the storage lifetime to its original scope.
/// Returned acquisition instead retains that scope's prepaid control owner.
/// Both forms stay on the original thread and grant no new allocation authority;
/// ordinary storage keeps its separate zero-sized custody and covariance.
#[derive(Clone)]
pub struct AdmittedAcquisitionCustody {
    // A returned physical owner retains the actual original scope, not merely
    // a marker claiming a scope existed earlier during admission.
    _owned: Option<iroha_allocation::OwnedAllocationScope>,
    _thread: std::marker::PhantomData<*mut ()>,
}

/// Multi-version key value storage using the original current and undo maps.
pub struct Storage<K: Key, V: Value, M: StorageMode<K, V> = Untracked> {
    /// Process-local identity of the jointly published current/undo pair.
    pub(crate) publication: Publication,
    pub(crate) revert_released: ReleaseNotification,
    pub(crate) blocks_released: ReleaseNotification,
    /// Previous version of values in the `blocks` map, required to perform revert of the latest changes
    pub(crate) revert: BptreeMap<K, Option<V>, M>,
    /// Map which represent aggregated changes of multiple blocks
    pub(crate) blocks: BptreeMap<K, V, M>,
    // Only the admitted constructor installs a pool; ordinary constructors
    // remain explicitly Untracked and cannot create prepaid map owners.
    pub(crate) allocation: Option<iroha_allocation::AllocationBudget>,
}
impl<K: Key, V: Value> Storage<K, V> {
    /// Construct new [`Self`]
    pub fn new() -> Self {
        Self {
            allocation: None,
            publication: Publication::new(),
            revert_released: ReleaseNotification::default(),
            blocks_released: ReleaseNotification::default(),
            revert: BptreeMap::new(),
            blocks: BptreeMap::new(),
        }
    }
    /// Create an inert caller-owned slot before locking or constructing a cursor.
    pub fn block_acquisition(&self) -> BlockAcquisitionSlot<'_, K, V> {
        BlockAcquisitionSlot::new(self)
    }

    /// Create a block through the same aggregate-capable acquisition kernel.
    pub fn block(&self) -> Block<'_, K, V> {
        let mut slot = self.block_acquisition();
        crate::BlockAcquisition::initialize(&mut slot, BlockMode::Ordinary);
        crate::BlockAcquisition::into_block(slot)
    }

    /// Insert a value directly into the latest committed state.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let mut blocks = self.blocks_released.poisoning_guard(
            self.blocks_released
                .with_acquisition_unwind_notification(|| self.blocks.write()),
        );
        let prev_value = blocks.insert(key, value);
        let next = NextPublication::new();
        let prepared = blocks.map_preserving_release(|writer| writer.prepare_commit());
        let retirement = self.publication.publish_retaining(
            next,
            || prepared.map_preserving_release(|prepared| prepared.publish()),
            |published| published.release_retaining(|published| published.release()),
        );
        // The current-only change and its identity are visible before any old
        // payload can unwind or signal a retry. The undo tree is untouched.
        drop(retirement);
        prev_value
    }
    /// Revert the published tip through the same caller-owned acquisition kernel.
    pub fn block_and_revert(&self) -> Block<'_, K, V> {
        let mut slot = self.block_acquisition();
        crate::BlockAcquisition::initialize(&mut slot, BlockMode::Replace);
        crate::BlockAcquisition::into_block(slot)
    }
}
impl<K: Key, V: Value, M: StorageMode<K, V>> Storage<K, V, M> {
    /// Retain a read-only view of the current original allocation owners.
    /// This does not copy map entries or create an admitted iteration workspace.
    pub fn view(&self) -> View<'_, K, V, M> {
        let mut releases = self.reader_releases();
        self.view_retaining(&mut releases)
    }

    /// Retry the sole current-reader kernel while retaining its original notices.
    /// The caller drops this allocation-free holder after any enclosing fences.
    pub fn view_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> View<'_, K, V, M> {
        loop {
            match self.try_view_retaining(releases) {
                Ok(view) => return view,
                Err(PublicationPreparationError::Busy(_)) => std::thread::yield_now(),
                Err(error) => panic!("original storage reader refused: {error:?}"),
            }
        }
    }

    /// Retain original reader notifications beyond an enclosing physical owner.
    /// This clones only the existing control; no bookkeeping allocation is made.
    pub fn reader_releases(&self) -> iroha_allocation::release::DeferredReleaseBatch {
        self.blocks.reader_release_batch()
    }

    /// Observe this current-generation reader's actual physical release source.
    /// This allocation-free observation grants no authority to read the storage.
    pub fn observe_reader_release(&self) -> iroha_allocation::release::ReleaseWait {
        self.blocks.observe_reader_release()
    }

    /// Pin the original current generation without waiting for its reader mutex.
    /// Actual unlock notifications remain in the caller's original release owner.
    ///
    /// # Errors
    /// Preserves the exact busy source, poison, or a foreign release owner.
    pub fn try_view_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<View<'_, K, V, M>, PublicationPreparationError<std::convert::Infallible>> {
        let wait = self.blocks.observe_reader_release();
        self.blocks
            .try_read_retaining(releases)
            .map(View::from_read_txn)
            .map_err(|error| match error {
                concread::bptree::OwnedWriteError::Busy => PublicationPreparationError::Busy(wait),
                concread::bptree::OwnedWriteError::Poisoned => {
                    PublicationPreparationError::Poisoned
                }
                concread::bptree::OwnedWriteError::Changed => PublicationPreparationError::Changed,
            })
    }
}

#[path = "storage/touches.rs"]
mod touches;

#[path = "storage/admitted.rs"]
mod admitted;
#[cfg(test)]
#[path = "storage/admitted_tests.rs"]
mod admitted_tests;
pub use admitted::{
    AdmittedAbortedPublication, AdmittedBlockError, AdmittedDetachedPublicationSlot,
    AdmittedPreparedPublication, AdmittedPublishedPublication, AdmittedStorageError,
    AdmittedStoragePolicy, StorageRole,
};

impl<K: Key, V: Value> Default for Storage<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
impl<K: Key, V: Value> FromIterator<(K, V)> for Storage<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self {
            allocation: None,
            publication: Publication::new(),
            revert_released: ReleaseNotification::default(),
            blocks_released: ReleaseNotification::default(),
            revert: BptreeMap::new(),
            blocks: iter.into_iter().collect(),
        }
    }
}
pub trait StorageReadOnly<K: Key, V: Value> {
    /// Borrowed entries in canonical order, retaining traversal state inline.
    type Iter<'a>: DoubleEndedIterator<Item = (&'a K, &'a V)> + ExactSizeIterator
    where
        Self: 'a;
    /// Borrowed bounded traversal, with no heap allocation for the iterator.
    type RangeIter<'a>: DoubleEndedIterator<Item = (&'a K, &'a V)>
    where
        Self: 'a;
    /// Read entry from the storage
    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Ord + Borrow<Q>,
        Q: Ord + ?Sized;
    /// Read entry from the storage together with the canonical key reference.
    ///
    /// This helper is useful when callers need the key reference borrowed from
    /// the storage (for example to build a `Ref<'_, K, V>` pair) rather than a
    /// cloned key value.
    fn get_key_value(&self, key: &K) -> Option<(&K, &V)> {
        self.range(key..=key)
            .next()
            .filter(|(candidate, _)| *candidate == key)
    }
    /// Iterate over all entries in the storage
    fn iter(&self) -> Self::Iter<'_>;
    /// Iterate over range of entries in the storage
    fn range<Q>(&self, bounds: impl RangeBounds<Q>) -> Self::RangeIter<'_>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized;
    /// Read the entry with the smallest canonical key without walking the map.
    fn first_key_value(&self) -> Option<(&K, &V)>;
    /// Read the entry with the largest canonical key without walking the map.
    fn last_key_value(&self) -> Option<(&K, &V)>;
    /// Get amount of entries in the storage
    fn len(&self) -> usize;
    /// Check whether the storage contains no entries
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
/// Module for [`View`] and it's related impls
mod view {
    use super::*;
    enum ViewInner<'storage, K: Key, V: Value, M: StorageMode<K, V>> {
        Txn(BptreeMapReadTxn<'storage, K, V, M>),
        Snapshot(BptreeMapReadSnapshot<'storage, K, V, M>),
    }
    /// Consistent view of the storage at the certain version
    pub struct View<'storage, K: Key, V: Value, M: StorageMode<K, V> = Untracked> {
        blocks: ViewInner<'storage, K, V, M>,
    }
    impl<'storage, K: Key, V: Value, M: StorageMode<K, V>> View<'storage, K, V, M> {
        /// Borrow a current value without allocating iteration storage.
        pub fn get<Q>(&self, key: &Q) -> Option<&V>
        where
            K: Borrow<Q>,
            Q: Ord + ?Sized,
        {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.get(key),
                ViewInner::Snapshot(snapshot) => snapshot.get(key),
            }
        }
        /// Number of current entries retained by this view.
        pub fn len(&self) -> usize {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.len(),
                ViewInner::Snapshot(snapshot) => snapshot.len(),
            }
        }
        /// Whether this original view has no entries.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        pub(crate) fn from_read_txn(read: BptreeMapReadTxn<'storage, K, V, M>) -> Self {
            Self {
                blocks: ViewInner::Txn(read),
            }
        }
        pub(crate) fn from_snapshot(snapshot: BptreeMapReadSnapshot<'storage, K, V, M>) -> Self {
            Self {
                blocks: ViewInner::Snapshot(snapshot),
            }
        }
    }
    impl<K: Key, V: Value, M: StorageMode<K, V>> StorageReadOnly<K, V> for View<'_, K, V, M> {
        type Iter<'a>
            = Iter<'a, K, V, M::Charge>
        where
            Self: 'a;
        type RangeIter<'a>
            = RangeIter<'a, K, V, M::Charge>
        where
            Self: 'a;
        fn get<Q>(&self, key: &Q) -> Option<&V>
        where
            K: Ord + Borrow<Q>,
            Q: Ord + ?Sized,
        {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.get(key),
                ViewInner::Snapshot(snapshot) => snapshot.get(key),
            }
        }
        fn iter(&self) -> Self::Iter<'_> {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.iter(),
                ViewInner::Snapshot(snapshot) => snapshot.iter(),
            }
        }
        fn range<Q>(&self, bounds: impl RangeBounds<Q>) -> Self::RangeIter<'_>
        where
            K: Borrow<Q>,
            Q: Ord + ?Sized,
        {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.range(bounds),
                ViewInner::Snapshot(snapshot) => snapshot.range(bounds),
            }
        }
        fn first_key_value(&self) -> Option<(&K, &V)> {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.first_key_value(),
                ViewInner::Snapshot(snapshot) => snapshot.iter().next(),
            }
        }
        fn last_key_value(&self) -> Option<(&K, &V)> {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.last_key_value(),
                // `concread` does not expose endpoint lookup on a write-backed
                // snapshot. Such snapshots only exist inside an in-flight state
                // transaction; persistent read views take the indexed branch.
                ViewInner::Snapshot(snapshot) => snapshot.iter().last(),
            }
        }
        /// Get amount of entries in the storage
        fn len(&self) -> usize {
            match &self.blocks {
                ViewInner::Txn(txn) => txn.len(),
                ViewInner::Snapshot(snapshot) => snapshot.len(),
            }
        }
    }
}
pub use view::View;
/// Borrowed before/after values for one key touched by an overlay.
///
/// `None` represents absence, including removal of a missing key. A touched key
/// may have equal before/after values. Consumers which commit semantic changes
/// must compare their canonical value projections instead of hashing the fact
/// that a mutable accessor was used. Borrowing this record prevents further
/// mutation of its originating overlay until the borrow ends.
pub struct TouchedEntry<'a, K: Key, V: Value> {
    /// Key in the storage's canonical order.
    pub key: &'a K,
    /// Value before the overlay's first mutation of this key.
    pub before: Option<&'a V>,
    /// Current value, including changes from applied children.
    pub after: Option<&'a V>,
}

/// Exact original map and undo successors, without physical writer locks.
///
/// This move-only journal preserves the original nodes, keys and values, including
/// no-op touches. The map owner also retains its original root and base reader
/// generation so untouched shared nodes remain alive even if Storage is dropped.
/// Replacement semantics are already staged by the original block. Publication
/// reacquires and authenticates that same current/undo pair without rebuilding it.
pub struct Detached<K: Key, V: Value, Admission, M: StorageMode<K, V> = Untracked> {
    revert: BptreeMapOwned<K, Option<V>, M>,
    blocks: BptreeMapOwned<K, V, M>,
    // Release metadata admission after the original successors and their pins.
    metadata: DetachedMetadata<Admission>,
}

struct DetachedMetadata<Admission> {
    predecessor: CapturedPublication,
    mode: BlockMode,
    dirty: bool,
    next: NextPublication,
    admission: Admission,
}

impl<K: Key, V: Value, Admission, M: StorageMode<K, V>> Detached<K, V, Admission, M> {
    /// Return the actual original block's acquisition mode.
    pub fn mode(&self) -> BlockMode {
        self.metadata.mode
    }

    /// Return whether the original block requires current-map publication.
    pub fn is_dirty(&self) -> bool {
        self.metadata.dirty
    }

    /// Borrow original preimages and successors, including no-ops, in key order.
    pub fn touched_entries(
        &self,
    ) -> impl DoubleEndedIterator<Item = TouchedEntry<'_, K, V>> + ExactSizeIterator {
        self.revert.iter().map(|(key, before)| TouchedEntry {
            key,
            before: before.as_ref(),
            after: self.blocks.get(key),
        })
    }

    /// Borrow the caller's separate capture reservation.
    /// Actual node, nested payload and reader-chain custody needs its own admission.
    pub fn admission(&self) -> &Admission {
        &self.metadata.admission
    }

    /// Observe equality with the original published current/undo pair.
    /// This momentary observation grants no publication authority.
    pub fn matches_current(&self, storage: &Storage<K, V, M>) -> bool {
        self.metadata.predecessor.matches(&storage.publication)
    }

    /// Compare exact original owner/version and mode with an acquired block.
    pub fn matches_block_predecessor(&self, block: &Block<'_, K, V, M>) -> bool {
        self.metadata.mode == block.mode && self.metadata.predecessor.same_as(&block.predecessor)
    }

    /// Reacquire both original writers around the exact retained successors.
    ///
    /// No key/value clone, delta reconstruction or successor allocation occurs.
    /// The original next identity survives every refusal and abort. The callback
    /// may retain separately prepaid temporary installation resources; it cannot
    /// retroactively admit the original execution or nested allocations.
    ///
    /// Both MV pair identity and the map's exact root/base generation are checked.
    /// Acquisition never waits and every refusal returns the original journal.
    /// Aggregate publication and complete resource admission remain the caller's
    /// responsibility; prepare every component before publishing the first one.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the same map journals and deferred release custody without allocating a box under resource pressure"
    )]
    fn prepare_publication<'target, Installation, E>(
        self,
        target: &'target Storage<K, V, M>,
        admit: impl FnOnce(&Self, &Storage<K, V, M>) -> Result<Installation, E>,
    ) -> PublicationPreparationResult<
        PreparedPublication<'target, K, V, Admission, Installation, M>,
        Self,
        E,
        Installation,
    > {
        let mut slot = DetachedPublicationSlotInner::new(self, target);
        match slot.try_prepare(admit) {
            Ok(()) => Ok(slot.into_prepared()),
            Err(error) => {
                let original = slot.recover_original();
                Err((original, error, slot.into_cleanup()))
            }
        }
    }
}

impl<K: Key, V: Value, Admission> Detached<K, V, Admission> {
    /// Inertly install the original untracked journal in caller-owned custody.
    /// Preparation must borrow this slot while the aggregate retains siblings.
    pub fn publication_slot<'target, Installation>(
        self,
        target: &'target Storage<K, V>,
    ) -> DetachedPublicationSlot<'target, K, V, Admission, Installation> {
        DetachedPublicationSlot {
            inner: DetachedPublicationSlotInner::new(self, target),
        }
    }

    /// Reacquire the exact original untracked pair, returning custody on refusal.
    /// No successor allocation or payload copy occurs. The caller prepares every
    /// aggregate component before publication and owns separate resource admission.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the same map journals and deferred release custody without allocating a box under resource pressure"
    )]
    pub fn try_prepare_publication<'target, Installation, E>(
        self,
        target: &'target Storage<K, V>,
        admit: impl FnOnce(&Self, &Storage<K, V>) -> Result<Installation, E>,
    ) -> PublicationPreparationResult<
        PreparedPublication<'target, K, V, Admission, Installation>,
        Self,
        E,
        Installation,
    > {
        self.prepare_publication(target, admit)
    }
}

/// Original map and undo successors held under both exact target writers.
/// Drop abandons them without publication; abort returns the original owners.
#[must_use = "preparation must be published or aborted by its aggregate owner"]
pub struct PreparedPublication<
    'target,
    K: Key,
    V: Value,
    Admission,
    Installation,
    M: StorageMode<K, V> = Untracked,
> {
    writers: PreparedStorageWriters<'target, K, V, M>,
    metadata: DetachedMetadata<Admission>,
    // Release temporary resources after every retained successor and writer.
    installation: Installation,
}

struct OriginalWriters<'target, K: Key, V: Value, M: StorageMode<K, V>> {
    revert: MapWriter<'target, K, Option<V>, M>,
    blocks: MapWriter<'target, K, V, M>,
}

enum StorageWriterState<'a, K: Key, V: Value, M: StorageMode<K, V>> {
    Attached(OriginalWriters<'a, K, V, M>),
    Preparing(PreparedStorageWriters<'a, K, V, M>),
    Published {
        _retirement: PublicationRetirement<K, V, M>,
    },
    Released {
        _blocks: BptreeMapAbandonment<K, V, M>,
        _revert: BptreeMapAbandonment<K, Option<V>, M>,
        _blocks_release: iroha_allocation::release::DeferredRelease,
        _revert_release: iroha_allocation::release::DeferredRelease,
    },
}

// The same owner retains terminal cleanup through every enclosing aggregate.
struct StorageWriters<'target, K: Key, V: Value, M: StorageMode<K, V>> {
    state: Option<StorageWriterState<'target, K, V, M>>,
    target: &'target Storage<K, V, M>,
}

impl<'target, K: Key, V: Value, M: StorageMode<K, V>> StorageWriters<'target, K, V, M> {
    fn new(
        target: &'target Storage<K, V, M>,
        revert: MapWriter<'target, K, Option<V>, M>,
        blocks: MapWriter<'target, K, V, M>,
    ) -> Self {
        Self {
            state: Some(StorageWriterState::Attached(OriginalWriters {
                revert,
                blocks,
            })),
            target,
        }
    }

    fn as_ref(&self) -> &OriginalWriters<'target, K, V, M> {
        match self.state.as_ref() {
            Some(StorageWriterState::Attached(original)) => original,
            _ => panic!("original storage pair was released"),
        }
    }

    fn as_mut(&mut self) -> &mut OriginalWriters<'target, K, V, M> {
        match self.state.as_mut() {
            Some(StorageWriterState::Attached(original)) => original,
            _ => panic!("original storage pair was released"),
        }
    }

    fn into_original(mut self) -> OriginalWriters<'target, K, V, M> {
        match self.state.take() {
            Some(StorageWriterState::Attached(original)) => original,
            other => {
                self.state = other;
                panic!("original storage pair was released")
            }
        }
    }

    fn prepare_publication(&mut self, predecessor: &CapturedPublication, dirty: bool) {
        self.as_ref();
        let Some(StorageWriterState::Attached(original)) = self.state.take() else {
            unreachable!("original attached pair checked above");
        };
        self.state = Some(StorageWriterState::Preparing(
            PreparedStorageWriters::from_original(self.target, original, None),
        ));
        let Some(StorageWriterState::Preparing(writers)) = self.state.as_mut() else {
            unreachable!("original publication phase installed before preparation");
        };
        writers.prepare_attached(predecessor, dirty);
    }

    fn publish_prepared(&mut self, next: &mut Option<NextPublication>) {
        assert!(
            matches!(&self.state, Some(StorageWriterState::Preparing(writers)) if writers.is_prepared()),
            "original pair preparation must complete"
        );
        assert!(
            next.is_some(),
            "original successor identity retained until publication"
        );
        let Some(StorageWriterState::Preparing(writers)) = self.state.take() else {
            unreachable!("checked original publication phase");
        };
        let next = next.take().expect("checked original successor identity");
        self.state = Some(StorageWriterState::Published {
            _retirement: writers.publish(next),
        });
    }

    fn release(&mut self) {
        if let Some(StorageWriterState::Preparing(writers)) = self.state.as_mut() {
            writers.release();
            return;
        }
        if !matches!(&self.state, Some(StorageWriterState::Attached(_))) {
            return;
        }
        let Some(StorageWriterState::Attached(OriginalWriters { revert, blocks })) =
            self.state.take()
        else {
            unreachable!()
        };
        // Unlike detach, cleanup-only native retirement also accepts an edit-failed
        // private cursor. It grants no read or publication authority afterward.
        let (blocks, blocks_release) = blocks.release_deferred(|writer| writer.abort_retaining());
        let (revert, revert_release) = revert.release_deferred(|writer| writer.abort_retaining());
        self.state = Some(StorageWriterState::Released {
            _blocks: blocks,
            _revert: revert,
            _blocks_release: blocks_release,
            _revert_release: revert_release,
        });
    }
}

impl<K: Key, V: Value, M: StorageMode<K, V>> Drop for StorageWriters<'_, K, V, M> {
    fn drop(&mut self) {
        self.release();
    }
}

impl<K: Key, V: Value, Admission, Installation, M: StorageMode<K, V>>
    PreparedPublication<'_, K, V, Admission, Installation, M>
{
    /// Release physical writers and return the exact original successors and cleanup.
    /// Retain the cleanup until every enclosing component and fence has unlocked.
    pub fn abort(
        self,
    ) -> (
        Detached<K, V, Admission, M>,
        PublicationCleanup<Installation>,
    ) {
        let Self {
            writers,
            metadata,
            installation,
        } = self;
        let (blocks, revert, retirement) = writers.abort(installation);
        (
            Detached {
                revert,
                blocks,
                metadata,
            },
            retirement,
        )
    }

    /// Publish the original prepared pair and return separate reservations.
    ///
    /// Original map successors and the next identities were prepared before
    /// detachment. This does not establish complete heap admission: nested data,
    /// cursor/node custody and collector/control bookkeeping still need their own
    /// policy. The aggregate owner supplies joint visibility and finality.
    pub fn publish(self) -> PublishedPublication<K, V, Admission, Installation, M> {
        let Self {
            writers,
            metadata,
            installation,
        } = self;
        let DetachedMetadata {
            predecessor: _,
            mode: _,
            dirty: _,
            next,
            admission,
        } = metadata;
        let retirement = writers.publish(next);
        PublishedPublication {
            retirement,
            admission,
            installation,
        }
    }
}

// Retain both release signals until both original physical writers are free.
// Notification unwind must not poison an already released healthy writer.
fn detach_pair_retaining<K: Key, V: Value, M: StorageMode<K, V>>(
    blocks: MapWriter<'_, K, V, M>,
    revert: MapWriter<'_, K, Option<V>, M>,
) -> DetachedPair<K, V, M, crate::CaptureCleanup> {
    // Both cursor flags were checked while the caller still owned its Block.
    // Exclusive ownership prevents a new edit between that check and detach.
    let (blocks, current_release) = blocks.release_deferred(|writer| writer.detach());
    let (revert, undo_release) = revert.release_deferred(|writer| writer.detach());
    (
        blocks,
        revert,
        crate::CaptureCleanup::new(current_release, undo_release),
    )
}

#[cfg(test)]
#[path = "storage/publication_tests.rs"]
mod publication_tests;

/// Module for [`Block`] and it's related impls
mod block {
    use super::*;
    /// Batched update to the storage that can be reverted later
    pub struct Block<'store, K: Key, V: Value, M: StorageMode<K, V> = Untracked> {
        pub(super) writers: StorageWriters<'store, K, V, M>,
        pub(super) dirty: bool,
        pub(super) direct_write: bool,
        pub(super) applied_transactions: u64,
        pub(super) failed: bool,
        pub(super) predecessor: CapturedPublication,
        pub(super) next: Option<NextPublication>,
        pub(super) mode: BlockMode,
        // LAST: original physical writers and allocation owners release before
        // the returned-scope custodian can notify a capacity retry. Borrowed
        // acquisition instead binds 'store to the original synchronous scope.
        pub(super) _acquisition_custody: M::AcquisitionCustody,
    }
    impl<'store, K: Key, V: Value, M: StorageMode<K, V>> Block<'store, K, V, M> {
        pub(super) fn assert_operable(&self) {
            assert!(!self.failed, "block edit unwound; abandon the block");
            // A child checkpoint can poison only one cursor while restoring
            // its root. Check the complete pair before either can publish.
            self.writers.as_ref().blocks.len();
            self.writers.as_ref().revert.len();
        }

        pub(super) fn detach_owned<Admission>(
            self,
            admission: Admission,
        ) -> Detached<K, V, Admission, M> {
            let mut slot = self.capture_slot();
            slot.capture_admitted(admission);
            let (journal, cleanup) = crate::BlockCapture::into_detached(slot);
            drop(cleanup);
            journal
        }

        pub(super) fn publish(mut self) {
            self.prepare_attached_publication();
            self.publish_attached_prepared();
        }

        /// Observe this block's original owner, current/undo predecessor and mode.
        /// The opaque identity permits only local equality, never publication.
        pub fn publication_identity(&self) -> crate::BlockPublicationIdentity {
            crate::BlockPublicationIdentity::capture(&self.predecessor, self.mode)
        }

        /// Check the original storage owner without reading values or taking locks.
        /// This observation grants no mutation or publication authority.
        pub fn belongs_to(&self, storage: &Storage<K, V, M>) -> bool {
            self.predecessor.belongs_to(&storage.publication)
        }

        /// Read the value that existed before this block's first mutation of `key`.
        ///
        /// The block undo log retains the first pre-block value across direct
        /// mutations and applied child transactions. An undo entry containing
        /// `None` means the key was absent before the block; an untouched key is
        /// read from the current map.
        pub fn get_before_block(&self, key: &K) -> Option<&V> {
            self.assert_operable();
            match self.writers.as_ref().revert.get(key) {
                Some(previous) => previous.as_ref(),
                None => self.get(key),
            }
        }
        /// Visit this block's touched keys with their exact pre-block and current values.
        ///
        /// Entries are ordered by `K::Ord`, independent of mutation order. The
        /// iterator borrows the undo journal and current storage without cloning
        /// keys/values or allocating another change list. Aborted transactions
        /// contribute no entries; applied transactions retain the first block
        /// preimage. No-op touches remain visible, including absent-to-absent.
        /// For `block_and_revert`, the preimage starts after the prior block was
        /// reverted, just like [`Self::get_before_block`].
        pub fn touched_entries(
            &self,
        ) -> impl DoubleEndedIterator<Item = TouchedEntry<'_, K, V>> + ExactSizeIterator {
            self.assert_operable();
            self.writers
                .as_ref()
                .revert
                .iter()
                .map(|(key, before)| TouchedEntry {
                    key,
                    before: before.as_ref(),
                    after: self.get(key),
                })
        }

        /// Return the actual acquisition mode, including an untouched replacement.
        pub fn mode(&self) -> BlockMode {
            self.mode
        }

        /// Return whether this block has staged any storage mutation.
        pub fn is_dirty(&self) -> bool {
            self.assert_operable();
            self.dirty
        }
        /// Read-only access to the block revert map (keys touched in this block).
        pub fn revert_map(&self) -> &BptreeMapWriteTxn<'store, K, Option<V>, M> {
            self.assert_operable();
            &self.writers.as_ref().revert
        }
    }
    impl<'store, K: Key, V: Value> Block<'store, K, V> {
        /// Local executing-writer observation for an enclosing complete-effect owner.
        ///
        /// Direct mutable leases remain visible even after value restoration. Child
        /// transactions count only after successful application; rollback changes neither
        /// field. This diagnostic grants no write, source or publication authority.
        pub fn write_observation(&self) -> (bool, u64) {
            self.assert_operable();
            (self.direct_write, self.applied_transactions)
        }
        pub(super) fn new(
            writers: StorageWriters<'store, K, V, Untracked>,
            dirty: bool,
            predecessor: CapturedPublication,
            mode: BlockMode,
        ) -> Self {
            Self {
                writers,
                dirty,
                direct_write: false,
                applied_transactions: 0,
                failed: false,
                predecessor,
                next: Some(NextPublication::new()),
                mode,
                _acquisition_custody: (),
            }
        }
        /// Retain both original parent roots, refusing generation exhaustion.
        pub fn try_transaction(
            &mut self,
        ) -> Result<Transaction<'_, K, V>, concread::bptree::PlanningError> {
            self.assert_operable();
            let OriginalWriters { revert, blocks } = self.writers.as_mut();
            let blocks = blocks.checkpoint()?;
            let revert = revert.checkpoint()?;
            Ok(Transaction {
                blocks: Some(blocks),
                revert: Some(revert),
                touched: TransactionTouches::Untracked(BTreeSet::new()),
                dirty: self.dirty,
                parent_dirty: &mut self.dirty,
                parent_applied_transactions: &mut self.applied_transactions,
                failed: false,
                allocation: None,
                parent_failure: Some(super::admitted_transaction::ParentFailure::new(
                    &mut self.failed,
                )),
            })
        }
        /// Apply aggregated changes to the storage
        pub fn commit(self) {
            self.publish();
        }

        /// Admit capture metadata, then retain the exact original successors.
        ///
        /// The next identity is retained from block opening. No key/value clone
        /// or delta vector is needed: current and undo move with their original
        /// allocation owners. The map retains its original root/base generation
        /// to protect untouched shared nodes after releasing the physical writer.
        /// Original execution, nested payload growth and retained-reader resources
        /// require their own earlier admission; this callback cannot fund them
        /// retroactively. Rejection abandons the block without publication.
        pub fn try_detach<Admission, E>(
            self,
            admit: impl FnOnce(&Self) -> Result<Admission, E>,
        ) -> Result<Detached<K, V, Admission>, E> {
            let mut slot = self.capture_slot();
            crate::BlockCapture::try_capture(&mut slot, admit)?;
            let (journal, cleanup) = crate::BlockCapture::into_detached(slot);
            drop(cleanup);
            Ok(journal)
        }
        /// Create transaction for the block.
        pub fn transaction(&mut self) -> Transaction<'_, K, V> {
            // TODO: propagate generation exhaustion through State admission.
            self.try_transaction()
                .expect("transaction checkpoint generation exhausted")
        }

        /// Get mutable access to the value stored in
        pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
            self.assert_operable();
            self.failed = true;
            let dirty = &mut self.dirty;
            let direct_write = &mut self.direct_write;
            let OriginalWriters { revert, blocks } = self.writers.as_mut();
            let value = blocks.get_mut(key).inspect(|value| {
                *dirty = true;
                *direct_write = true;
                if !revert.contains_key(key) {
                    revert.insert(key.clone(), Some((*value).clone()));
                }
            });
            self.failed = false;
            value
        }
        /// Insert key value into the storage
        pub fn insert(&mut self, key: K, value: V) -> Option<V> {
            self.assert_operable();
            // The first-preimage clone runs outside either tree cursor. Keep
            // aggregate failure armed until both edits and input cleanup finish.
            self.failed = true;
            self.direct_write = true;
            let OriginalWriters { revert, blocks } = self.writers.as_mut();
            let prev_value = blocks.insert(key.clone(), value);
            if !revert.contains_key(&key) {
                revert.insert(key, prev_value.clone());
            } else {
                drop(key);
            }
            self.dirty = true;
            self.failed = false;
            prev_value
        }
        /// Remove key value from storage
        pub fn remove(&mut self, key: K) -> Option<V> {
            self.assert_operable();
            self.failed = true;
            self.direct_write = true;
            let OriginalWriters { revert, blocks } = self.writers.as_mut();
            let prev_value = blocks.remove(&key);
            if !revert.contains_key(&key) {
                revert.insert(key, prev_value.clone());
            } else {
                drop(key);
            }
            if prev_value.is_some() {
                self.dirty = true;
            }
            self.failed = false;
            prev_value
        }
    }
    impl<K: Key, V: Value, M: StorageMode<K, V>> StorageReadOnly<K, V> for Block<'_, K, V, M> {
        type Iter<'a>
            = Iter<'a, K, V, M::Charge>
        where
            Self: 'a;
        type RangeIter<'a>
            = RangeIter<'a, K, V, M::Charge>
        where
            Self: 'a;
        fn get<Q>(&self, key: &Q) -> Option<&V>
        where
            K: Borrow<Q>,
            Q: Ord + ?Sized,
        {
            self.assert_operable();
            self.writers.as_ref().blocks.get(key)
        }
        fn iter(&self) -> Self::Iter<'_> {
            self.assert_operable();
            self.writers.as_ref().blocks.iter()
        }
        fn range<Q>(&self, bounds: impl RangeBounds<Q>) -> Self::RangeIter<'_>
        where
            K: Borrow<Q>,
            Q: Ord + ?Sized,
        {
            self.assert_operable();
            self.writers.as_ref().blocks.range(bounds)
        }
        fn first_key_value(&self) -> Option<(&K, &V)> {
            self.assert_operable();
            self.writers.as_ref().blocks.first_key_value()
        }
        fn last_key_value(&self) -> Option<(&K, &V)> {
            self.assert_operable();
            self.writers.as_ref().blocks.last_key_value()
        }
        fn len(&self) -> usize {
            self.assert_operable();
            self.writers.as_ref().blocks.len()
        }
    }
    /// A private transaction retaining both original parent tree generations.
    ///
    /// Drop restores the parent roots without inverse mutations or allocation.
    /// First preimages live in the block-undo checkpoint; transaction preimages
    /// are borrowed from the original current root instead of cloned into a log.
    pub struct Transaction<'block, K: Key, V: Value, M: StorageMode<K, V> = Untracked> {
        pub(super) blocks: Option<BptreeMapCheckpoint<'block, K, V, M>>,
        pub(super) revert: Option<BptreeMapCheckpoint<'block, K, Option<V>, M>>,
        // Constructors bind this one touch owner to the original map mode.
        pub(super) touched: TransactionTouches<K>,
        pub(super) parent_dirty: &'block mut bool,
        pub(super) parent_applied_transactions: &'block mut u64,
        pub(super) dirty: bool,
        pub(super) failed: bool,
        pub(super) allocation: Option<&'block iroha_allocation::AllocationBudget>,
        // LAST: both original checkpoints and all local touch keys/buffers must
        // finish rollback/apply cleanup before this parent-failure guard drops.
        pub(super) parent_failure: Option<super::admitted_transaction::ParentFailure<'block>>,
    }

    impl<K: Key, V: Value, M: StorageMode<K, V>> Drop for Transaction<'_, K, V, M> {
        fn drop(&mut self) {
            // This runs before automatic checkpoint and touched-key destruction.
            // Existing unwind, including refusal to apply a failed ordinary
            // child, can roll back under both checkpoints. New cleanup failures
            // must poison the parent; already armed failures remain sticky.
            if let Some(parent) = self.parent_failure.as_mut() {
                parent.begin_cleanup();
            }
        }
    }

    pub(super) enum TransactionTouches<K: Key> {
        Untracked(BTreeSet<K>),
        Admitted(super::touches::SortedTouches<K>),
    }
    impl<K: Key> TransactionTouches<K> {
        fn untracked(&self) -> &BTreeSet<K> {
            match self {
                Self::Untracked(touches) => touches,
                Self::Admitted(_) => {
                    panic!("Untracked transaction requires its original touch mode")
                }
            }
        }
        fn untracked_mut(&mut self) -> &mut BTreeSet<K> {
            match self {
                Self::Untracked(touches) => touches,
                Self::Admitted(_) => {
                    panic!("Untracked transaction requires its original touch mode")
                }
            }
        }
        pub(super) fn admitted(&self) -> &super::touches::SortedTouches<K> {
            match self {
                Self::Admitted(touches) => touches,
                Self::Untracked(_) => {
                    panic!("admitted transaction requires its original touch mode")
                }
            }
        }
        pub(super) fn admitted_mut(&mut self) -> &mut super::touches::SortedTouches<K> {
            match self {
                Self::Admitted(touches) => touches,
                Self::Untracked(_) => {
                    panic!("admitted transaction requires its original touch mode")
                }
            }
        }
    }
    impl<K: Key, V: Value, M: StorageMode<K, V>> Transaction<'_, K, V, M> {
        pub(super) fn assert_operable(&self) {
            assert!(
                !self.failed,
                "transaction edit unwound; abort the transaction"
            );
            assert!(
                !self
                    .parent_failure
                    .as_ref()
                    .is_some_and(|parent| parent.is_failed()),
                "parent block is unusable"
            );
        }

        pub(super) fn current(&self) -> &BptreeMapCheckpoint<'_, K, V, M> {
            self.assert_operable();
            self.blocks.as_ref().expect("live transaction current root")
        }
        /// Create a read-only view into this private transaction state.
        pub fn view(&self) -> View<'_, K, V, M> {
            View::from_snapshot(self.current().to_snapshot())
        }
    }
    impl<K: Key, V: Value> Transaction<'_, K, V> {
        fn record_touch(&mut self, key: &K) {
            self.touched.untracked_mut().insert(key.clone());
            let revert = self.revert.as_mut().expect("live transaction undo root");
            if revert.get(key).is_none() {
                let before = self
                    .blocks
                    .as_ref()
                    .expect("live transaction current root")
                    .get(key)
                    .cloned();
                revert.insert(key.clone(), before);
            }
        }

        /// Borrow the original block-start value, including applied siblings.
        pub fn get_before_block(&self, key: &K) -> Option<&V> {
            self.assert_operable();
            match self
                .revert
                .as_ref()
                .expect("live transaction undo root")
                .get(key)
            {
                Some(previous) => previous.as_ref(),
                None => self.current().get(key),
            }
        }
        /// Borrow the value retained in this transaction's original parent root.
        pub fn get_before_transaction(&self, key: &K) -> Option<&V> {
            self.current().get_before(key)
        }

        /// Iterate keys changed by this transaction or an earlier applied
        /// transaction in the current block. The undo checkpoint retains both.
        pub fn changed_keys_in_block(&self) -> impl Iterator<Item = &K> {
            self.assert_operable();
            self.revert
                .as_ref()
                .expect("live transaction undo root")
                .keys()
        }

        /// Visit touched keys and their original/current values in canonical order.
        ///
        /// No-op and absent-to-absent touches remain explicit. Values are borrowed
        /// from the original parent root and current private root without cloning.
        pub fn touched_entries(
            &self,
        ) -> impl DoubleEndedIterator<Item = TouchedEntry<'_, K, V>> + ExactSizeIterator {
            self.assert_operable();
            self.touched.untracked().iter().map(|key| TouchedEntry {
                key,
                before: self.current().get_before(key),
                after: self.current().get(key),
            })
        }

        /// Keep both private successors and their first preimages in the block.
        pub fn apply(mut self) {
            self.assert_operable();
            // Every destructor runs while rollback is available or aggregate
            // failure remains armed. Neither retained apply transfers nor
            // updating parent metadata runs user destruction.
            self.blocks
                .as_ref()
                .expect("live transaction current root")
                .len();
            self.revert
                .as_ref()
                .expect("live transaction undo root")
                .len();
            // Arm the aggregate before any touched-key destructor can unwind.
            // Both rollback guards still retain the original parent roots.
            self.parent_failure.as_mut().expect("original parent").arm();
            drop(core::mem::replace(
                &mut self.touched,
                TransactionTouches::Untracked(BTreeSet::new()),
            ));
            {
                let current_retirement = self
                    .blocks
                    .take()
                    .expect("live transaction current root")
                    .apply_retaining();
                let undo_retirement = self
                    .revert
                    .take()
                    .expect("live transaction undo root")
                    .apply_retaining();
                *self.parent_dirty = self.dirty;
                // Tuple fields retire current then undo before resolving the
                // parent below. Untracked buffers are empty, but this boundary
                // still keeps both transfers and metadata ahead of cleanup.
                let _retirements = (current_retirement, undo_retirement);
            }
            *self.parent_applied_transactions = self
                .parent_applied_transactions
                .checked_add(1)
                .expect("applied transaction count exceeds the finite block domain");
            self.parent_failure
                .as_mut()
                .expect("original parent")
                .resolve();
        }
        /// Mutably borrow a present value while retaining its original preimages.
        pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
            self.assert_operable();
            self.current().get(key)?;
            self.failed = true;
            self.record_touch(key);
            let value = self
                .blocks
                .as_mut()
                .expect("live transaction current root")
                .get_mut(key);
            self.dirty = true;
            self.failed = false;
            value
        }

        /// Insert a private value and retain the original first preimage.
        pub fn insert(&mut self, key: K, value: V) -> Option<V> {
            self.assert_operable();
            self.failed = true;
            self.record_touch(&key);
            let previous = self
                .blocks
                .as_mut()
                .expect("live transaction current root")
                .insert(key, value);
            self.dirty = true;
            self.failed = false;
            previous
        }

        /// Remove a private value, retaining an explicit missing-key touch.
        pub fn remove(&mut self, key: K) -> Option<V> {
            self.assert_operable();
            self.failed = true;
            self.record_touch(&key);
            let previous = self
                .blocks
                .as_mut()
                .expect("live transaction current root")
                .remove(&key);
            self.dirty |= previous.is_some();
            // The owned query may run user destruction; keep failure armed
            // until it has been released, just like edit-owned temporaries.
            drop(key);
            self.failed = false;
            previous
        }
    }
    impl<K: Key, V: Value, M: StorageMode<K, V>> StorageReadOnly<K, V> for Transaction<'_, K, V, M> {
        type Iter<'a>
            = Iter<'a, K, V, M::Charge>
        where
            Self: 'a;
        type RangeIter<'a>
            = RangeIter<'a, K, V, M::Charge>
        where
            Self: 'a;
        fn get<Q>(&self, key: &Q) -> Option<&V>
        where
            K: Borrow<Q>,
            Q: Ord + ?Sized,
        {
            self.current().get(key)
        }
        fn iter(&self) -> Self::Iter<'_> {
            self.current().iter()
        }
        fn range<Q>(&self, bounds: impl RangeBounds<Q>) -> Self::RangeIter<'_>
        where
            K: Borrow<Q>,
            Q: Ord + ?Sized,
        {
            self.current().range(bounds)
        }
        fn first_key_value(&self) -> Option<(&K, &V)> {
            self.current().first_key_value()
        }
        fn last_key_value(&self) -> Option<(&K, &V)> {
            self.current().last_key_value()
        }
        fn len(&self) -> usize {
            self.current().len()
        }
    }
}
pub use block::{Block, Transaction};
#[path = "storage/admitted_transaction.rs"]
mod admitted_transaction;
#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, ops::Bound};
    #[test]
    fn get() {
        let storage = Storage::<u64, u64>::new();
        let view0 = storage.view();
        {
            let mut block = storage.block();
            for (key, value) in [(0, 0), (1, 0), (2, 0)] {
                block.insert(key, value);
            }
            block.commit()
        }
        let view1 = storage.view();
        {
            let mut block = storage.block();
            for (key, value) in [(0, 1), (1, 1), (3, 1)] {
                block.insert(key, value);
            }
            block.commit()
        }
        let view2 = storage.view();
        {
            let mut block = storage.block();
            for (key, value) in [(1, 2), (4, 2)] {
                block.insert(key, value);
            }
            block.commit()
        }
        let view3 = storage.view();
        assert_eq!(view0.get(&0), None);
        assert_eq!(view0.get(&1), None);
        assert_eq!(view0.get(&2), None);
        assert_eq!(view0.get(&3), None);
        assert_eq!(view1.get(&0), Some(&0));
        assert_eq!(view1.get(&1), Some(&0));
        assert_eq!(view1.get(&2), Some(&0));
        assert_eq!(view1.get(&3), None);
        assert_eq!(view2.get(&0), Some(&1));
        assert_eq!(view2.get(&1), Some(&1));
        assert_eq!(view2.get(&2), Some(&0));
        assert_eq!(view2.get(&3), Some(&1));
        assert_eq!(view2.get(&4), None);
        assert_eq!(view3.get(&0), Some(&1));
        assert_eq!(view3.get(&1), Some(&2));
        assert_eq!(view3.get(&2), Some(&0));
        assert_eq!(view3.get(&3), Some(&1));
        assert_eq!(view3.get(&4), Some(&2));
    }
    #[test]
    fn endpoint_lookups_follow_canonical_key_order() {
        let storage = Storage::<u64, u64>::from_iter([(7, 70), (2, 20), (11, 110)]);
        let view = storage.view();
        assert_eq!(view.first_key_value(), Some((&2, &20)));
        assert_eq!(view.last_key_value(), Some((&11, &110)));
        let mut block = storage.block();
        assert_eq!(block.first_key_value(), Some((&2, &20)));
        assert_eq!(block.last_key_value(), Some((&11, &110)));
        {
            let mut transaction = block.transaction();
            transaction.insert(1, 10);
            transaction.insert(12, 120);
            assert_eq!(transaction.first_key_value(), Some((&1, &10)));
            assert_eq!(transaction.last_key_value(), Some((&12, &120)));
        }
    }
    #[test]
    fn transaction_step() {
        let storage = Storage::<u64, u64>::new();
        let mut block = storage.block();
        // Successful transaction
        {
            let mut transaction = block.transaction();
            transaction.insert(0, 0);
            transaction.apply();
        }
        // Aborted step
        {
            let mut transaction = block.transaction();
            transaction.insert(0, 1);
            transaction.insert(1, 1);
        }
        // Check that aborted transaction changes don't visible for subsequent transactions
        {
            let transaction = block.transaction();
            assert_eq!(transaction.get(&0), Some(&0));
            assert_eq!(transaction.get(&1), None);
        }
        block.commit();
        // Check that effect of aborted step is not visible in the storage after committing transaction
        {
            let view = storage.view();
            assert_eq!(view.get(&0), Some(&0));
            assert_eq!(view.get(&1), None);
        }
    }
    #[test]
    fn iter() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            for (key, value) in [(0, 0), (1, 0), (2, 0)] {
                block.insert(key, value);
            }
            block.commit()
        }
        {
            let mut block = storage.block();
            for (key, value) in [(0, 1), (1, 1), (3, 1)] {
                block.insert(key, value);
            }
            block.commit()
        }
        {
            let mut block = storage.block();
            for (key, value) in [(1, 2), (4, 2)] {
                block.insert(key, value);
            }
            block.commit()
        }
        let view = storage.view();
        for (kv_actual, kv_expected) in
            view.iter()
                .zip([(&0, &1), (&1, &2), (&2, &0), (&3, &1), (&4, &2)])
        {
            assert_eq!(kv_actual, kv_expected);
        }
        let mut block = storage.block();
        block.insert(0, 3);
        block.insert(5, 3);
        let mut transaction = block.transaction();
        transaction.insert(1, 4);
        transaction.insert(6, 4);
        for (kv_actual, kv_expected) in transaction.iter().zip([
            (&0, &3),
            (&1, &4),
            (&2, &0),
            (&3, &1),
            (&4, &2),
            (&5, &3),
            (&6, &4),
        ]) {
            assert_eq!(kv_actual, kv_expected);
        }
    }
    #[test]
    fn range() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            for (key, value) in [(0, 0), (1, 0), (2, 0)] {
                block.insert(key, value);
            }
            block.commit()
        }
        {
            let mut block = storage.block();
            for (key, value) in [(0, 1), (1, 1), (3, 1)] {
                block.insert(key, value);
            }
            block.commit()
        }
        {
            let mut block = storage.block();
            for (key, value) in [(1, 2), (4, 2)] {
                block.insert(key, value);
            }
            block.commit()
        }
        let view = storage.view();
        for (kv_actual, kv_expected) in view
            .range((Bound::<u64>::Unbounded, Bound::Unbounded))
            .zip([(&0, &1), (&1, &2), (&2, &0), (&3, &1), (&4, &2)])
        {
            assert_eq!(kv_actual, kv_expected);
        }
        for (kv_actual, kv_expected) in view
            .range((Bound::Included(&1), Bound::Included(&3)))
            .zip([(&1, &2), (&2, &0), (&3, &1)])
        {
            assert_eq!(kv_actual, kv_expected);
        }
        for (kv_actual, kv_expected) in view
            .range((Bound::Excluded(&1), Bound::Excluded(&3)))
            .zip([(&2, &0)])
        {
            assert_eq!(kv_actual, kv_expected);
        }
        assert_eq!(view.range(..=3).next_back(), Some((&3, &1)));
        let mut block = storage.block();
        block.insert(0, 3);
        block.insert(5, 3);
        let mut transaction = block.transaction();
        transaction.insert(1, 4);
        transaction.insert(6, 4);
        for (kv_actual, kv_expected) in transaction
            .range((Bound::<u64>::Unbounded, Bound::Unbounded))
            .zip([
                (&0, &3),
                (&1, &4),
                (&2, &0),
                (&3, &1),
                (&4, &2),
                (&5, &3),
                (&6, &4),
            ])
        {
            assert_eq!(kv_actual, kv_expected);
        }
        assert_eq!(transaction.range(..=5).next_back(), Some((&5, &3)));
        for (kv_actual, kv_expected) in transaction
            .range((Bound::Included(&1), Bound::Included(&3)))
            .zip([(&1, &4), (&2, &0), (&3, &1)])
        {
            assert_eq!(kv_actual, kv_expected);
        }
        for (kv_actual, kv_expected) in transaction
            .range((Bound::Excluded(&1), Bound::Excluded(&3)))
            .zip([(&2, &0)])
        {
            assert_eq!(kv_actual, kv_expected);
        }
    }
    #[test]
    fn revert() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            block.insert(0, 0);
            block.commit()
        }
        {
            let mut block = storage.block();
            block.insert(0, 1);
            block.commit()
        }
        let view1 = storage.view();
        {
            let block = storage.block_and_revert();
            block.commit();
        }
        let view2 = storage.view();
        // View is persistent so revert is not visible
        assert_eq!(view1.get(&0), Some(&1));
        // Revert is visible in the view created after revert was applied
        assert_eq!(view2.get(&0), Some(&0));
    }
    #[test]
    fn noop_commit_clears_revert_history() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            block.insert(0, 1);
            block.commit();
        }
        {
            let block = storage.block();
            block.commit();
        }
        {
            let block = storage.block_and_revert();
            block.commit();
        }
        let view = storage.view();
        assert_eq!(view.get(&0), Some(&1));
    }
    #[test]
    fn aborted_transaction_dirty_commit_keeps_state_unchanged() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            {
                let mut transaction = block.transaction();
                transaction.insert(0, 1);
            }
            assert!(!block.dirty);
            block.commit();
        }
        let view = storage.view();
        assert_eq!(view.get(&0), None);
    }
    #[test]
    fn aborted_transaction_preserves_existing_dirty_state() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            block.insert(0, 1);
            {
                let mut transaction = block.transaction();
                transaction.insert(1, 2);
            }
            assert!(block.dirty);
            block.commit();
        }
        let view = storage.view();
        assert_eq!(view.get(&0), Some(&1));
        assert_eq!(view.get(&1), None);
    }
    #[test]
    fn remove_missing_key_is_noop_commit() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            block.insert(0, 1);
            block.commit();
        }
        {
            let mut block = storage.block();
            assert_eq!(block.remove(1), None);
            assert!(!block.dirty);
            block.commit();
        }
        {
            let block = storage.block_and_revert();
            block.commit();
        }
        let view = storage.view();
        assert_eq!(view.get(&0), Some(&1));
        assert_eq!(view.get(&1), None);
    }
    #[test]
    fn transaction_remove_missing_key_keeps_block_clean() {
        let storage = Storage::<u64, u64>::new();
        {
            let mut block = storage.block();
            {
                let mut transaction = block.transaction();
                assert_eq!(transaction.remove(0), None);
                transaction.apply();
            }
            assert!(!block.dirty);
            block.commit();
        }
        let view = storage.view();
        assert_eq!(view.get(&0), None);
    }
    #[test]
    fn len() {
        let storage = Storage::<u64, u64>::new();
        // Newly created storage should have no entries
        assert!(storage.view().is_empty());
        {
            let mut block = storage.block();
            for (key, value) in [(0, 0), (1, 0), (2, 0)] {
                block.insert(key, value);
            }
            block.commit()
        }
        {
            let mut block = storage.block();
            for (key, value) in [(0, 1), (1, 1), (3, 1)] {
                block.insert(key, value);
            }
            block.commit()
        }
        {
            let mut block = storage.block();
            for (key, value) in [(1, 2), (4, 2)] {
                block.insert(key, value);
            }
            block.commit()
        }
        let view = storage.view();
        assert_eq!(view.len(), 5);
        assert!(!view.is_empty());
    }
    #[test]
    fn consistent_with_btreemap() {
        let storage = Storage::<u64, u64>::new();
        let mut map = BTreeMap::new();
        let txs = vec![
            (true, vec![(0, Some(10)), (1, Some(20)), (0, None)]),
            (true, vec![(2, Some(30))]),
            (false, vec![(1, Some(40))]),
        ];
        for (committed, tx) in txs {
            let mut block = storage.block();
            for (key, value) in tx {
                match value {
                    Some(v) => {
                        if committed {
                            map.insert(key, v);
                        }
                        block.insert(key, v);
                    }
                    None => {
                        if committed {
                            map.remove(&key);
                        }
                        block.remove(key);
                    }
                }
            }
            if committed {
                block.commit();
            }
        }
        let view = storage.view();
        for (k, v) in map.iter() {
            assert_eq!(view.get(k), Some(v));
        }
    }
    #[test]
    fn revert_map_tracks_changed_keys() {
        let storage = Storage::<u64, u64>::new();
        let mut block = storage.block();
        block.insert(1, 10);
        block.insert(2, 20);
        block.remove(1);
        let revert = block.revert_map();
        assert!(revert.contains_key(&1));
        assert!(revert.contains_key(&2));
    }
    #[test]
    fn pending_block_keys_include_applied_and_local_but_not_aborted_mutations() {
        let storage = Storage::<u64, u64>::new();
        let mut block = storage.block();
        {
            let mut first = block.transaction();
            first.insert(1, 10);
            first.apply();
        }
        {
            let mut aborted = block.transaction();
            aborted.insert(2, 20);
        }
        let mut current = block.transaction();
        current.insert(1, 11);
        current.insert(3, 30);
        let keys = current
            .changed_keys_in_block()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(keys, std::collections::BTreeSet::from([1, 3]));
        assert_eq!(current.get_before_block(&1), None);
        assert_eq!(current.get(&2), None);
    }
    #[test]
    fn get_before_block_tracks_first_value_across_direct_mutations() {
        let storage = Storage::from_iter([(1_u64, 10_u64), (2, 20), (4, 40)]);
        let mut block = storage.block();

        assert_eq!(block.get_before_block(&1), Some(&10), "untouched value");
        assert_eq!(block.get_before_block(&3), None, "untouched absence");

        block.insert(1, 11);
        block.insert(1, 12);
        assert_eq!(block.get(&1), Some(&12));
        assert_eq!(block.get_before_block(&1), Some(&10));

        block.insert(3, 30);
        block.insert(3, 31);
        assert_eq!(block.get(&3), Some(&31));
        assert_eq!(block.get_before_block(&3), None);

        assert_eq!(block.remove(2), Some(20));
        assert_eq!(block.get(&2), None);
        assert_eq!(block.get_before_block(&2), Some(&20));

        *block.get_mut(&4).expect("existing fixture value") += 1;
        assert_eq!(block.get_before_block(&4), Some(&40));
    }
    #[test]
    fn get_before_block_observes_only_applied_transaction_mutations() {
        let storage = Storage::from_iter([(1_u64, 10_u64)]);
        let mut block = storage.block();

        {
            let mut transaction = block.transaction();
            transaction.insert(1, 11);
            transaction.insert(2, 20);
        }
        assert_eq!(block.get(&1), Some(&10));
        assert_eq!(block.get(&2), None);
        assert_eq!(block.get_before_block(&1), Some(&10));
        assert_eq!(block.get_before_block(&2), None);

        {
            let mut transaction = block.transaction();
            transaction.insert(1, 12);
            transaction.insert(2, 21);
            transaction.apply();
        }
        assert_eq!(block.get(&1), Some(&12));
        assert_eq!(block.get(&2), Some(&21));
        assert_eq!(block.get_before_block(&1), Some(&10));
        assert_eq!(block.get_before_block(&2), None);

        {
            let mut transaction = block.transaction();
            transaction.insert(1, 13);
            transaction.apply();
        }
        assert_eq!(block.get_before_block(&1), Some(&10));
    }
    #[test]
    fn transaction_get_before_block_includes_its_local_undo_log() {
        let storage = Storage::from_iter([(1_u64, 10_u64), (3, 30)]);
        let mut block = storage.block();
        block.insert(1, 11);

        {
            let mut transaction = block.transaction();
            transaction.insert(1, 12);
            transaction.insert(2, 20);
            transaction.remove(3);
            assert_eq!(transaction.get_before_block(&1), Some(&10));
            assert_eq!(transaction.get_before_block(&2), None);
            assert_eq!(transaction.get_before_block(&3), Some(&30));
        }

        assert_eq!(block.get(&1), Some(&11));
        assert_eq!(block.get(&2), None);
        assert_eq!(block.get(&3), Some(&30));
        assert_eq!(block.get_before_block(&1), Some(&10));
    }
    #[test]
    fn get_before_block_uses_reverted_state_as_new_block_baseline() {
        let storage = Storage::from_iter([(1_u64, 10_u64)]);
        {
            let mut block = storage.block();
            block.insert(1, 11);
            block.insert(2, 20);
            block.commit();
        }

        let mut reverted = storage.block_and_revert();
        assert_eq!(reverted.get(&1), Some(&10));
        assert_eq!(reverted.get(&2), None);
        assert_eq!(reverted.get_before_block(&1), Some(&10));
        assert_eq!(reverted.get_before_block(&2), None);

        reverted.insert(1, 12);
        reverted.insert(2, 21);
        assert_eq!(reverted.get_before_block(&1), Some(&10));
        assert_eq!(reverted.get_before_block(&2), None);
    }
}

#[path = "storage/history.rs"]
mod history;
pub use history::History;
mod snapshot;
pub use snapshot::Snapshot;

#[cfg(test)]
#[path = "storage/overlay_preimage_tests.rs"]
mod overlay_preimage_tests;

#[cfg(test)]
#[path = "storage/detached_tests.rs"]
mod detached_tests;

impl<K: Key, V: Value, M: StorageMode<K, V>> crate::BlockRetirement for Block<'_, K, V, M> {
    fn release_writers(&mut self) {
        self.writers.release();
    }
}

#[cfg(test)]
#[path = "storage/aggregate_acquisition_tests.rs"]
mod aggregate_acquisition_tests;

impl<K: Key, V: Value, M: StorageMode<K, V>> Block<'_, K, V, M> {
    pub(super) fn prepare_attached_publication(&mut self) {
        self.assert_operable();
        self.writers
            .prepare_publication(&self.predecessor, self.dirty);
    }

    pub(super) fn publish_attached_prepared(&mut self) {
        self.writers.publish_prepared(&mut self.next);
    }
}

#[path = "storage/publication_slot.rs"]
mod publication_slot;
pub use publication_slot::BlockPublicationSlot;

#[cfg(test)]
mod quantity_write_observation_tests {
    use super::{Storage, StorageReadOnly};

    #[test]
    fn direct_mutation_leases_and_restored_writes_remain_visible() {
        for mutation in 0..4 {
            let storage = Storage::from_iter([(1_u64, 10_u64)]);
            let mut block = storage.block();
            assert_eq!(block.write_observation(), (false, 0));
            assert!(block.get_mut(&9).is_none());
            assert_eq!(block.write_observation(), (false, 0));
            match mutation {
                0 => {
                    *block.get_mut(&1).unwrap() = 11;
                    *block.get_mut(&1).unwrap() = 10;
                }
                1 => {
                    block.insert(1, 11);
                    block.insert(1, 10);
                }
                2 => {
                    let old = block.remove(1).unwrap();
                    block.insert(1, old);
                }
                3 => {
                    assert_eq!(block.remove(9), None);
                }
                _ => unreachable!(),
            }
            assert_eq!(block.get(&1), Some(&10));
            assert_eq!(block.write_observation(), (true, 0));
        }
    }

    #[test]
    fn child_rollback_and_unwind_preserve_original_observation_and_values() {
        let storage = Storage::from_iter([(1_u64, 10_u64)]);
        let mut block = storage.block();
        {
            let mut child = block.transaction();
            child.insert(1, 11);
        }
        assert_eq!(block.write_observation(), (false, 0));
        assert_eq!(block.get(&1), Some(&10));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut child = block.transaction();
            child.insert(1, 12);
            panic!("abort actual child owner before application");
        }));
        assert!(panic.is_err());
        assert_eq!(block.write_observation(), (false, 0));
        assert_eq!(block.get(&1), Some(&10));
        block.transaction().apply();
        assert_eq!(block.write_observation(), (false, 1));
    }

    #[test]
    fn every_successful_child_apply_counts_including_empty_and_restored_writes() {
        let storage = Storage::from_iter([(1_u64, 10_u64)]);
        let mut block = storage.block();
        block.transaction().apply();
        assert_eq!(block.write_observation(), (false, 1));
        {
            let mut child = block.transaction();
            child.insert(1, 11);
            child.insert(1, 10);
            child.apply();
        }
        assert_eq!(block.write_observation(), (false, 2));
        assert_eq!(block.get(&1), Some(&10));
        {
            let mut child = block.transaction();
            child.remove(9);
            child.apply();
        }
        assert_eq!(block.write_observation(), (false, 3));
        block.insert(1, 10);
        block.transaction().apply();
        assert_eq!(block.write_observation(), (true, 4));
    }

    #[test]
    fn exhausted_application_lineage_poison_cannot_be_published() {
        let storage = Storage::from_iter([(1_u64, 10_u64)]);
        let mut block = storage.block();
        block.applied_transactions = u64::MAX;
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block.transaction().apply();
        }));
        assert!(failure.is_err());
        let observation =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| block.write_observation()));
        assert!(
            observation.is_err(),
            "original MV failure owner remains armed"
        );
    }
}

#[cfg(test)]
#[path = "storage/current_reader_tests.rs"]
mod current_reader_tests;
