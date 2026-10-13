use crate::internals::bptree::cursor::CursorReadOps;
use crate::internals::bptree::cursor::{CursorRead, CursorWrite, SuperBlock};
pub use crate::internals::bptree::iter::{Iter, KeyIter, RangeIter, ValueIter};
use crate::internals::bptree::mutiter::RangeMutIter;
use crate::internals::lincowcell::LinCowCellCapable;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::iter::FromIterator;
use std::ops::RangeBounds;

/// A concurrently readable map based on a modified B+Tree structure.
///
/// This structure can be used in locations where you would otherwise us
/// `RwLock<BTreeMap>` or `Mutex<BTreeMap>`.
///
/// This is a concurrently readable structure, meaning it has transactional
/// properties. Writers are serialised (one after the other), and readers
/// can exist in parallel with stable views of the structure at a point
/// in time.
///
/// This is achieved through the use of [COW](https://en.wikipedia.org/wiki/Copy-on-write)
/// or [MVCC](https://en.wikipedia.org/wiki/Multiversion_concurrency_control).
/// As a write occurs, subsets of the tree are cloned into the writer thread
/// and then committed later. This may cause memory usage to increase in exchange
/// for a gain in concurrent behaviour.
///
/// Transactions can be rolled-back (aborted) without penalty by dropping
/// the `BptreeMapWriteTxn` without calling `commit()`.
/// The default mode permits ordinary mutation. A prepaid mode retains its
/// allocation policy through readers and unpublished successors, and admits
/// edits only through its closed operation API.
pub struct BptreeMap<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapCell<K, V, M>,
}

unsafe impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    Send for BptreeMap<K, V, M>
where
    M: MapMode + NodeCloning<K, V> + Send + Sync,
    M::Charge: Send + Sync,
{
}
unsafe impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    Sync for BptreeMap<K, V, M>
where
    M: MapMode + NodeCloning<K, V> + Send + Sync,
    M::Charge: Send + Sync,
{
}

/// An active read transaction over a [BptreeMap]. The data in this tree
/// is guaranteed to not change and will remain consistent for the life
/// of this transaction.
pub struct BptreeMapReadTxn<'a, K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapRead<'a, K, V, M>,
}

impl<K, V, M> Clone for BptreeMapReadTxn<'_, K, V, M>
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

unsafe impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    Send for BptreeMapReadTxn<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V> + Send + Sync,
    M::Charge: Send + Sync,
{
}
unsafe impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    Sync for BptreeMapReadTxn<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V> + Send + Sync,
    M::Charge: Send + Sync,
{
}

/// An active write transaction for a [BptreeMap]. The data in this tree
/// may be modified exclusively through this transaction without affecting
/// readers. The write may be rolledback/aborted by dropping this guard
/// without calling `commit()`. Once `commit()` is called, readers will be
/// able to access and perceive changes in new transactions.
/// Unrestricted edit methods exist only in the default mode. A reattached
/// prepaid successor permits inspection, publication, detachment or abort.
pub struct BptreeMapWriteTxn<'a, K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: MapWrite<'a, K, V, M>,
}

enum SnapshotType<'a, K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    R(&'a CursorRead<K, V, M>),
    W(&'a CursorWrite<K, V, M>),
}

/// A point-in-time snapshot of the tree from within a read OR write. This is
/// useful for building other transactional types on top of this structure, as
/// you need a way to downcast both BptreeMapReadTxn or BptreeMapWriteTxn to
/// a singular reader type for a number of get_inner() style patterns.
///
/// This snapshot IS safe within the read thread due to the nature of the
/// implementation borrowing the inner tree to prevent mutations within the
/// same thread while the read snapshot is open.
pub struct BptreeMapReadSnapshot<'a, K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: SnapshotType<'a, K, V, M>,
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static> Default
    for BptreeMap<K, V>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static>
    BptreeMap<K, V>
{
    /// Construct a new concurrent tree
    pub fn new() -> Self {
        // I acknowledge I understand what is required to make this safe.
        BptreeMap {
            inner: LinCowCell::new(unsafe { SuperBlock::new() }),
        }
    }

    /// Attempt to create a new write, returns None if another writer
    /// already exists.
    pub fn try_write(&self) -> Option<BptreeMapWriteTxn<'_, K, V>> {
        self.inner
            .try_write()
            .map(|inner| BptreeMapWriteTxn { inner })
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static>
    FromIterator<(K, V)> for BptreeMap<K, V>
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut new_sblock = unsafe { SuperBlock::new() };
        let prev = new_sblock.create_reader();
        let mut cursor = new_sblock.create_writer(());

        cursor.extend(iter);

        let _ = new_sblock.pre_commit(cursor, &prev);

        BptreeMap {
            inner: LinCowCell::new(new_sblock),
        }
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static>
    Extend<(K, V)> for BptreeMapWriteTxn<'_, K, V>
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        self.inner.as_mut().extend(iter);
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    BptreeMapWriteTxn<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
{
    // == RO methods

    /// Retrieve a value from the tree. If the value exists, a reference is returned
    /// as `Some(&V)`, otherwise if not present `None` is returned.
    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.as_ref().search(k)
    }

    /// Assert if a key exists in the tree.
    pub fn contains_key<Q>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.as_ref().contains_key(k)
    }

    /// returns the current number of k:v pairs in the tree
    pub fn len(&self) -> usize {
        self.inner.as_ref().len()
    }

    /// Determine if the set is currently empty
    pub fn is_empty(&self) -> bool {
        self.inner.as_ref().len() == 0
    }

    /// Iterate over a range of values
    pub fn range<R, T>(&self, range: R) -> RangeIter<'_, K, V, M::Charge>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.inner.as_ref().range(range)
    }

    /// Iterator over `(&K, &V)` of the set
    pub fn iter(&self) -> Iter<'_, K, V, M::Charge> {
        self.inner.as_ref().kv_iter()
    }

    /// Iterator over &K
    pub fn values(&self) -> ValueIter<'_, K, V, M::Charge> {
        self.inner.as_ref().v_iter()
    }

    /// Iterator over &V
    pub fn keys(&self) -> KeyIter<'_, K, V, M::Charge> {
        self.inner.as_ref().k_iter()
    }

    /// Retrieve the first (minimum) key-value pair from the map if it exists.
    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        self.inner.as_ref().first_key_value()
    }

    /// Retrieve the last (maximum) key-value pair from the map if it exists.
    pub fn last_key_value(&self) -> Option<(&K, &V)> {
        self.inner.as_ref().last_key_value()
    }

    // (adv) keys

    // (adv) values

    #[allow(unused)]
    pub(crate) fn get_txid(&self) -> u64 {
        self.inner.as_ref().get_txid()
    }

    /// Borrow a read-snapshot of the current unpublished tree. Its shared
    /// borrow prevents mutable access to this transaction while it remains live.
    pub fn to_snapshot(&self) -> BptreeMapReadSnapshot<'_, K, V, M> {
        BptreeMapReadSnapshot {
            inner: SnapshotType::W(self.inner.as_ref()),
        }
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static>
    BptreeMapWriteTxn<'_, K, V>
{
    // == RW methods

    /// Reset this tree to an empty state. As this is within the transaction this
    /// change only takes effect once committed.
    pub fn clear(&mut self) {
        self.inner.as_mut().clear()
    }

    /// Insert or update a value by key. If the value previously existed it is returned
    /// as `Some(V)`. If the value did not previously exist this returns `None`.
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.inner.as_mut().insert(k, v)
    }

    /// Remove a key if it exists in the tree. If the value exists, we return it as `Some(V)`,
    /// and if it did not exist, we return `None`
    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.inner.as_mut().remove(k)
    }

    // split_off
    /*
    pub fn split_off_gte(&mut self, key: &K) -> BptreeMap<K, V> {
        unimplemented!();
    }
    */

    /// Remove all values less than (but not including) key from the map.
    pub fn split_off_lt(&mut self, key: &K) {
        self.inner.as_mut().split_off_lt(key)
    }

    // ADVANCED
    // append (join two sets)

    /// Get a mutable reference to a value in the tree. This is correctly, and
    /// safely cloned before you attempt to mutate the value, isolating it from
    /// other transactions.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.as_mut().get_mut_ref(key)
    }

    /// Iterate over a mutable range of values
    pub fn range_mut<R, T>(&mut self, range: R) -> RangeMutIter<'_, K, V>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.inner.as_mut().range_mut(range)
    }

    // iter_mut

    // entry

    #[cfg(test)]
    pub(crate) fn tree_density(&self) -> (usize, usize) {
        self.inner.as_ref().tree_density()
    }

    #[cfg(test)]
    pub(crate) fn verify(&self) -> bool {
        self.inner.as_ref().verify()
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    BptreeMapReadTxn<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
{
    /// Retrieve a value from the tree. If the value exists, a reference is returned
    /// as `Some(&V)`, otherwise if not present `None` is returned.
    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.as_ref().search(k)
    }

    /// Assert if a key exists in the tree.
    pub fn contains_key<Q>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.as_ref().contains_key(k)
    }

    /// Returns the current number of k:v pairs in the tree
    pub fn len(&self) -> usize {
        self.inner.as_ref().len()
    }

    /// Determine if the set is currently empty
    pub fn is_empty(&self) -> bool {
        self.inner.as_ref().len() == 0
    }

    #[allow(unused)]
    pub(crate) fn get_txid(&self) -> u64 {
        self.inner.as_ref().get_txid()
    }

    /// Iterate over a range of values
    pub fn range<R, T>(&self, range: R) -> RangeIter<'_, K, V, M::Charge>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.inner.as_ref().range(range)
    }

    /// Iterator over `(&K, &V)` of the set
    pub fn iter(&self) -> Iter<'_, K, V, M::Charge> {
        self.inner.as_ref().kv_iter()
    }

    /// Iterator over &K
    pub fn values(&self) -> ValueIter<'_, K, V, M::Charge> {
        self.inner.as_ref().v_iter()
    }

    /// Iterator over &V
    pub fn keys(&self) -> KeyIter<'_, K, V, M::Charge> {
        self.inner.as_ref().k_iter()
    }

    /// Retrieve the first (minimum) key-value pair from the map if it exists.
    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        self.inner.as_ref().first_key_value()
    }

    /// Retrieve the last (maximum) key-value pair from the map if it exists.
    pub fn last_key_value(&self) -> Option<(&K, &V)> {
        self.inner.as_ref().last_key_value()
    }

    /// Create a read-snapshot of the current tree.
    /// As this is the read variant, it IS safe, and guaranteed the tree will not change.
    pub fn to_snapshot(&self) -> BptreeMapReadSnapshot<'_, K, V, M> {
        BptreeMapReadSnapshot {
            inner: SnapshotType::R(self.inner.as_ref()),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn verify(&self) -> bool {
        self.inner.as_ref().verify()
    }
}

impl<K: Clone + Ord + Debug + Sync + Send + 'static, V: Clone + Sync + Send + 'static, M>
    BptreeMapReadSnapshot<'_, K, V, M>
where
    M: MapMode + NodeCloning<K, V>,
{
    /// Retrieve a value from the tree. If the value exists, a reference is returned
    /// as `Some(&V)`, otherwise if not present `None` is returned.
    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match self.inner {
            SnapshotType::R(inner) => inner.search(k),
            SnapshotType::W(inner) => inner.search(k),
        }
    }

    /// Assert if a key exists in the tree.
    pub fn contains_key<Q>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match self.inner {
            SnapshotType::R(inner) => inner.contains_key(k),
            SnapshotType::W(inner) => inner.contains_key(k),
        }
    }

    /// Returns the current number of k:v pairs in the tree
    pub fn len(&self) -> usize {
        match self.inner {
            SnapshotType::R(inner) => inner.len(),
            SnapshotType::W(inner) => inner.len(),
        }
    }

    /// Determine if the set is currently empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over a range of values
    pub fn range<R, T>(&self, range: R) -> RangeIter<'_, K, V, M::Charge>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        match self.inner {
            SnapshotType::R(inner) => inner.range(range),
            SnapshotType::W(inner) => inner.range(range),
        }
    }

    /// Iterator over `(&K, &V)` of the set
    pub fn iter(&self) -> Iter<'_, K, V, M::Charge> {
        match self.inner {
            SnapshotType::R(inner) => inner.kv_iter(),
            SnapshotType::W(inner) => inner.kv_iter(),
        }
    }

    /// Iterator over &K
    pub fn values(&self) -> ValueIter<'_, K, V, M::Charge> {
        match self.inner {
            SnapshotType::R(inner) => inner.v_iter(),
            SnapshotType::W(inner) => inner.v_iter(),
        }
    }

    /// Iterator over &V
    pub fn keys(&self) -> KeyIter<'_, K, V, M::Charge> {
        match self.inner {
            SnapshotType::R(inner) => inner.k_iter(),
            SnapshotType::W(inner) => inner.k_iter(),
        }
    }
}
