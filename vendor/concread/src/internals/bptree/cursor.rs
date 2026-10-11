// The cursor is what actually knits a tree together from the parts
// we have, and has an important role to keep the system consistent.
//
// Additionally, the cursor also is responsible for general movement
// throughout the structure and how to handle that effectively

use super::allocation::NodeCloning;
use super::node::*;
use super::tracking::{NodeTrackingBuffer, TrackingBuffer};
use crate::bptree::MapMode;
use crate::internals::lincowcell::LinCowCellCapable;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::mem;

use super::iter::{Iter, KeyIter, RangeIter, ValueIter};
use super::mutiter::RangeMutIter;
use super::states::*;
use std::ops::RangeBounds;

use std::sync::OnceLock;

#[path = "checkpoint.rs"]
mod checkpoint;
pub(crate) use checkpoint::{CheckpointBuffers, CursorCheckpoint};

#[path = "remove.rs"]
mod remove;
pub(crate) use remove::remove_tracking_slots;

/// One shared bound for planning, cursor construction and private checkpoints.
pub(crate) fn checked_next_generation(txid: u64) -> Option<u64> {
    txid.checked_add(1)
        .filter(|next| *next < (TXID_MASK >> TXID_SHF))
}

/// Original node funding and bookkeeping selected before cursor construction.
/// Implementations must consume already admitted input, never obtain more pool
/// capacity midway through an edit. Only Untracked exposes unrestricted mutation.
pub(crate) trait CursorMode<K: Clone + Ord + Debug, V: Clone>:
    NodeCloning<K, V> + Sized
{
    type Buffer: TrackingBuffer<*mut Node<K, V, Self::Charge>, Charge = Self::Charge>;
    type Input;

    fn into_parts(input: Self::Input) -> (Self, Self::Buffer, Self::Buffer);
}

impl<K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> CursorMode<K, V> for M {
    type Buffer = M::Buffer<*mut Node<K, V, M::Charge>>;
    type Input = M::Input<*mut Node<K, V, M::Charge>>;

    fn into_parts(input: Self::Input) -> (Self, Self::Buffer, Self::Buffer) {
        <M as MapMode>::into_parts(input)
    }
}

/// The internal root of the tree, with associated garbage lists etc.
#[derive(Debug)]
pub(crate) struct SuperBlock<K, V, M: CursorMode<K, V> = Untracked>
where
    K: Ord + Clone + Debug,
    V: Clone,
{
    pub(crate) root: *mut Node<K, V, M::Charge>,
    pub(crate) size: usize,
    pub(crate) txid: u64,
    // Exact reachable node kinds, transferred with the original published root.
    node_counts: (usize, usize),
}

unsafe impl<
        K: Clone + Ord + Debug + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
        M: CursorMode<K, V>,
    > Send for SuperBlock<K, V, M>
where
    M::Charge: Send + Sync,
{
}
unsafe impl<
        K: Clone + Ord + Debug + Sync + Send + 'static,
        V: Clone + Sync + Send + 'static,
        M: CursorMode<K, V>,
    > Sync for SuperBlock<K, V, M>
where
    M::Charge: Send + Sync,
{
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>>
    LinCowCellCapable<CursorRead<K, V, M>, CursorWrite<K, V, M>> for SuperBlock<K, V, M>
{
    type WriterInput = M::Input;

    fn create_reader(&self) -> CursorRead<K, V, M> {
        // This sets up the first reader.
        CursorRead::new(self)
    }

    fn create_writer(&self, input: M::Input) -> CursorWrite<K, V, M> {
        // Create a writer.
        CursorWrite::with_input(self, input)
    }

    fn pre_commit(
        &mut self,
        new: CursorWrite<K, V, M>,
        prev: &CursorRead<K, V, M>,
    ) -> CursorRead<K, V, M> {
        use crate::internals::lincowcell::LinCowCellRetainedCommit;
        let (reader, retirement) = self.pre_commit_retaining(new, prev);
        drop(retirement);
        reader
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>>
    crate::internals::lincowcell::retained_commit::Sealed for SuperBlock<K, V, M>
{
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>>
    crate::internals::lincowcell::LinCowCellRetainedCommit<
        CursorRead<K, V, M>,
        CursorWrite<K, V, M>,
    > for SuperBlock<K, V, M>
{
    type Retirement = CursorWrite<K, V, M>;

    fn validate_commit(&self, new: &CursorWrite<K, V, M>, prev: &CursorRead<K, V, M>) {
        new.assert_operable();
        assert!(prev.last_seen.get().is_none());
        assert!(new.last_seen.is_some());
        assert!(
            self.counts_after(new).is_some(),
            "invalid original node accounting"
        );
    }

    fn pre_commit_retaining(
        &mut self,
        mut new: CursorWrite<K, V, M>,
        prev: &CursorRead<K, V, M>,
    ) -> (CursorRead<K, V, M>, Self::Retirement) {
        self.validate_commit(&new, prev);
        // This calculation was checked before any participating root publishes.
        // It reads only retained node metadata and cannot call user code.
        let node_counts = self.counts_after(&new).expect("validated node accounting");
        // The original writer retires this reader exactly once. Move the
        // existing buffer and its charge intact, without replacement or allocation.
        prev.last_seen
            .set(new.last_seen.take().expect("original retirement buffer"))
            .unwrap_or_else(|_| unreachable!("original reader already has retired nodes"));

        // We are done, time to seal everything.
        new.first_seen.as_slice().iter().for_each(|n| {
            Node::make_ro_raw(*n);
        });
        // Clear first seen, we won't be dropping them from here.
        new.first_seen.clear();

        // == Push data into our sb. ==
        self.root = new.root;
        self.size = new.length;
        self.txid = new.txid;
        self.node_counts = node_counts;

        // Create the new reader.
        // Keep the cleared first-seen allocation, sealed provider and original
        // cursor fields intact until the whole publication has released locks.
        (CursorRead::new(self), new)
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> SuperBlock<K, V, M> {
    /// Exact reachable leaf/branch counts of this original published tree.
    pub(crate) fn node_counts(&self) -> (usize, usize) {
        self.node_counts
    }

    fn counts_after(&self, new: &CursorWrite<K, V, M>) -> Option<(usize, usize)> {
        let (mut leaves, mut branches) = self.node_counts;
        // Newly allocated nodes may also be retired by later private edits.
        // Counting both lists cancels those entries; they are still alive under
        // the original cursor, so reading their node kind is safe. Checkpoint
        // abort restores both prefixes and needs no separate accounting journal.
        for &node in new.first_seen.as_slice() {
            if unsafe { &*node }.is_leaf() {
                leaves = leaves.checked_add(1)?;
            } else {
                branches = branches.checked_add(1)?;
            }
        }
        for &node in new.last_seen.as_ref()?.as_slice() {
            if unsafe { &*node }.is_leaf() {
                leaves = leaves.checked_sub(1)?;
            } else {
                branches = branches.checked_sub(1)?;
            }
        }
        (leaves > 0).then_some((leaves, branches))
    }

    /// Adopt one real test leaf without bypassing published node-count invariants.
    #[cfg(test)]
    pub(crate) fn from_leaf_test(root: *mut Node<K, V, M::Charge>, size: usize, txid: u64) -> Self {
        // SAFETY: test fixtures transfer their exclusive initialized leaf here.
        assert!(unsafe { &*root }.is_leaf());
        let leaf = unsafe { &*root.cast::<Leaf<K, V, M::Charge>>() };
        assert_eq!(leaf.get_txid(), txid);
        assert_eq!(leaf.count(), size);
        Node::make_ro_raw(root);
        Self {
            root,
            size,
            txid,
            node_counts: (1, 0),
        }
    }

    /// The caller must put this unique root under the original linear owner.
    pub(crate) unsafe fn new_with_funding(funding: &mut M) -> Self {
        let root = Node::<K, V, M::Charge>::new_leaf(1, funding).cast();
        Self {
            root,
            size: 0,
            txid: 1,
            node_counts: (1, 0),
        }
    }
}

impl<K: Clone + Ord + Debug, V: Clone> SuperBlock<K, V> {
    /// This is UNSAFE because you *MUST* understand how to manage the transactions
    /// of this type and to give a correct linearised transaction manager the ability
    /// to control this.
    ///
    /// More than likely, you WILL NOT do this so you should RUN AWAY and try to forget
    /// you ever saw this function at all.
    pub unsafe fn new() -> Self {
        unsafe { Self::new_with_funding(&mut Untracked) }
    }

    #[cfg(test)]
    pub(crate) fn new_test(txid: u64, root: *mut Node<K, V>) -> Self {
        assert!(txid < (TXID_MASK >> TXID_SHF));
        assert!(txid > 0);
        // let last_seen: Vec<*mut Node<K, V>> = Vec::with_capacity(16);
        let mut first_seen = Vec::with_capacity(16);
        // Do a pre-verify to be sure it's sane.
        assert!(Node::verify_raw(root));
        // Collect anythinng from root into this txid if needed.
        // Set txid to txid on all tree nodes from the root.
        first_seen.push(root);
        Node::sblock_collect_raw(root, &mut first_seen);

        // Lock them all
        first_seen.iter().for_each(|n| {
            Node::make_ro_raw(*n);
        });

        // Determine our count internally.
        let (length, _) = Node::tree_density_raw(root);

        // Good to go!
        let leaves = first_seen
            .iter()
            .filter(|&&node| unsafe { &*node }.is_leaf())
            .count();
        let branches = first_seen.len() - leaves;
        SuperBlock {
            txid,
            size: length,
            root,
            node_counts: (leaves, branches),
        }
    }
}

pub(crate) struct CursorRead<K, V, M: CursorMode<K, V> = Untracked>
where
    K: Ord + Clone + Debug,
    V: Clone,
{
    txid: u64,
    length: usize,
    root: *mut Node<K, V, M::Charge>,
    last_seen: OnceLock<M::Buffer>,
}

unsafe impl<
        K: Clone + Ord + Debug + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
        M: CursorMode<K, V>,
    > Send for CursorRead<K, V, M>
where
    M::Charge: Send + Sync,
{
}
unsafe impl<
        K: Clone + Ord + Debug + Sync + Send + 'static,
        V: Clone + Sync + Send + 'static,
        M: CursorMode<K, V>,
    > Sync for CursorRead<K, V, M>
where
    M::Charge: Send + Sync,
{
}

pub(crate) struct CursorWrite<K, V, M: CursorMode<K, V> = Untracked>
where
    K: Ord + Clone + Debug,
    V: Clone,
{
    txid: u64,
    length: usize,
    root: *mut Node<K, V, M::Charge>,
    last_seen: Option<M::Buffer>,
    first_seen: M::Buffer,
    // The original retained base, not the evolving private root. Checkpoints
    // preserve this count; all new allocations remain in first_seen until free.
    base_node_counts: (usize, usize),
    funding: M,
    // A borrowed admitted edit may unwind inside catch_unwind while its physical
    // writer stays held. Such a cursor must never become readable/publishable.
    edit_failed: bool,
}

unsafe impl<
        K: Clone + Ord + Debug + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
        M: CursorMode<K, V> + Send,
    > Send for CursorWrite<K, V, M>
where
    M::Charge: Send + Sync,
{
}
unsafe impl<
        K: Clone + Ord + Debug + Sync + Send + 'static,
        V: Clone + Sync + Send + 'static,
        M: CursorMode<K, V> + Send + Sync,
    > Sync for CursorWrite<K, V, M>
where
    M::Charge: Send + Sync,
{
}

pub(crate) trait CursorReadOps<K: Clone + Ord + Debug, V: Clone, C = Untracked> {
    #[allow(unused)]
    fn get_root_ref(&self) -> &Node<K, V, C>;

    fn get_root(&self) -> *mut Node<K, V, C>;

    fn len(&self) -> usize;

    fn get_txid(&self) -> u64;

    /// Checked structural positions borrowed from this actual immutable cursor.
    fn next_row_path(
        &self,
        previous: Option<&super::positions::RowPath>,
    ) -> Result<Option<super::positions::RowPath>, ()> {
        super::positions::next_path(self.get_root_ref(), previous)
    }

    /// Resolve only finite structural slots; the borrow never outlives this cursor.
    fn resolve_row_path<'a>(
        &'a self,
        position: &super::positions::RowPath,
    ) -> Option<(&'a K, &'a V)>
    where
        C: 'a,
    {
        super::positions::resolve(self.get_root_ref(), position)
    }

    #[cfg(test)]
    fn get_tree_density(&self) -> (usize, usize) {
        // Walk the tree and calculate the packing efficiency.
        let rref = self.get_root();
        Node::tree_density_raw(rref)
    }

    fn search<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut node = self.get_root();
        for _i in 0..65536 {
            if unsafe { (*node).is_leaf() } {
                let lref = leaf_ref_shared!(node, K, V, C);
                return lref.get_ref(k).map(|v| unsafe {
                    // Strip the lifetime and rebind to the lifetime of `self`.
                    // This is safe because we know that these nodes will NOT
                    // be altered during the lifetime of this txn, so the references
                    // will remain stable.
                    let x = v as *const V;
                    &*x as &V
                });
            } else {
                let bref = branch_ref_shared!(node, K, V, C);
                let idx = bref.locate_node(k);
                node = bref.get_idx_unchecked(idx);
            }
        }
        panic!("Tree depth exceeded max limit (65536). This may indicate memory corruption.");
    }

    fn contains_key<Q>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.search(k).is_some()
    }

    fn first_key_value<'a>(&'a self) -> Option<(&'a K, &'a V)>
    where
        C: 'a,
    {
        let mut node = self.get_root();
        for _i in 0..65536 {
            if unsafe { (*node).is_leaf() } {
                let lref = leaf_ref_shared!(node, K, V, C);
                return lref.min_value();
            } else {
                let bref = branch_ref_shared!(node, K, V, C);
                node = bref.min_node();
            }
        }
        panic!("Tree depth exceeded max limit (65536). This may indicate memory corruption.");
    }

    fn last_key_value<'a>(&'a self) -> Option<(&'a K, &'a V)>
    where
        C: 'a,
    {
        let mut node = self.get_root();
        for _i in 0..65536 {
            if unsafe { (*node).is_leaf() } {
                let lref = leaf_ref_shared!(node, K, V, C);
                return lref.max_value();
            } else {
                let bref = branch_ref_shared!(node, K, V, C);
                node = bref.max_node();
            }
        }
        panic!("Tree depth exceeded max limit (65536). This may indicate memory corruption.");
    }

    fn range<'n, R, T>(&'n self, range: R) -> RangeIter<'n, K, V, C>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        RangeIter::new(self.get_root(), range, self.len())
    }

    fn kv_iter<'n>(&'n self) -> Iter<'n, K, V, C> {
        Iter::new(self.get_root(), self.len())
    }

    fn k_iter<'n>(&'n self) -> KeyIter<'n, K, V, C> {
        KeyIter::new(self.get_root(), self.len())
    }

    fn v_iter<'n>(&'n self) -> ValueIter<'n, K, V, C> {
        ValueIter::new(self.get_root(), self.len())
    }

    #[cfg(test)]
    fn verify(&self) -> bool {
        Node::no_cycles_raw(self.get_root()) && Node::verify_raw(self.get_root()) && {
            let (l, _) = self.get_tree_density();
            l == self.len()
        }
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> CursorWrite<K, V, M> {
    pub(crate) fn with_input(sblock: &SuperBlock<K, V, M>, input: M::Input) -> Self {
        let txid = checked_next_generation(sblock.txid)
            .expect("B+tree writer generation exceeds its representable limit");
        // println!("starting wr txid -> {:?}", txid);
        let length = sblock.size;
        let root = sblock.root;
        let (funding, first_seen, last_seen) = M::into_parts(input);

        CursorWrite {
            txid,
            length,
            root,
            last_seen: Some(last_seen),
            first_seen,
            base_node_counts: sblock.node_counts(),
            funding,
            edit_failed: false,
        }
    }

    pub(crate) fn checkpoint(&mut self) -> Option<CursorCheckpoint<'_, K, V, M>>
    where
        M: MapMode,
    {
        CursorCheckpoint::new(self, None)
    }

    pub(crate) fn assert_operable(&self) {
        assert!(
            !self.edit_failed,
            "admitted edit unwound; abort the original cursor"
        );
    }

    pub(crate) fn begin_admitted_edit(&mut self) {
        self.assert_operable();
        self.edit_failed = true;
    }

    /// Replace only a value in a leaf already private to this exact cursor.
    /// No path cloning, funding, bookkeeping growth or callback is permitted.
    pub(crate) fn try_update_private(&mut self, key: &K, value: V) -> Result<V, V>
    where
        K: Copy,
        V: Copy,
    {
        self.begin_admitted_edit();
        let mut node = self.root;
        let result = loop {
            if self_meta_shared!(node).is_leaf() {
                if leaf_ref_shared!(node, K, V, M::Charge).get_txid() != self.txid {
                    break Err(value);
                }
                // SAFETY: the exact cursor generation owns this leaf. Shared
                // snapshots borrow the cursor and exclude this mutable borrow;
                // older published readers cannot contain this private leaf.
                let leaf = leaf_ref!(node, K, V, M::Charge);
                break match leaf.get_mut_ref(key) {
                    Some(slot) => Ok(mem::replace(slot, value)),
                    None => Err(value),
                };
            }
            let branch = branch_ref_shared!(node, K, V, M::Charge);
            node = branch.get_idx_unchecked(branch.locate_node(key));
        };
        // A key-comparison panic deliberately leaves the owner fail-closed.
        self.edit_failed = false;
        result
    }

    /// Refuse exhausted bookkeeping before cloning, splitting or changing nodes.
    /// The unchanged original entry is returned for a newly admitted operation.
    /// This checks structural slots only: complete node/payload funding remains
    /// the original mode's responsibility before constructing this cursor.
    pub(crate) fn try_insert(&mut self, k: K, v: V) -> Result<Option<V>, (K, V)> {
        if !self.insert_tracking_fits(&k) {
            return Err((k, v));
        }
        let r = match clone_and_insert(
            self.root,
            self.txid,
            k,
            v,
            self.last_seen.as_mut().expect("original retirement buffer"),
            &mut self.first_seen,
            &mut self.funding,
        ) {
            CRInsertState::NoClone(res) => res,
            CRInsertState::Clone(res, mut nnode) => {
                // We have a new root node, swap it in.
                // !!! It's already been cloned and marked for cleaning by the clone_and_insert
                // call.
                // eprintln!("swap: {:?}, {:?}", self.root, nnode);
                mem::swap(&mut self.root, &mut nnode);
                // Return the insert result
                res
            }
            CRInsertState::CloneSplit(lnode, rnode) => {
                // The previous root had to split - make a new
                // root now and put it inplace.
                let mut nroot = Node::new_branch(self.txid, lnode, rnode, &mut self.funding)
                    as *mut Node<K, V, M::Charge>;
                self.first_seen.push(nroot);
                // The root was cloned as part of clone split
                // This swaps the POINTERS not the content!
                mem::swap(&mut self.root, &mut nroot);
                // As we split, there must NOT have been an existing
                // key to overwrite.
                None
            }
            CRInsertState::Split(rnode) => {
                // The previous root was already part of this txn, but has now
                // split. We need to construct a new root and swap them.
                //
                // Note, that we have to briefly take an extra RC on the root so
                // that we can get it into the branch.
                let mut nroot = Node::new_branch(self.txid, self.root, rnode, &mut self.funding)
                    as *mut Node<K, V, M::Charge>;
                self.first_seen.push(nroot);
                // println!("ls push 2");
                // self.last_seen.push(self.root);
                mem::swap(&mut self.root, &mut nroot);
                // As we split, there must NOT have been an existing
                // key to overwrite.
                None
            }
            CRInsertState::RevSplit(lnode) => {
                let mut nroot = Node::new_branch(self.txid, lnode, self.root, &mut self.funding)
                    as *mut Node<K, V, M::Charge>;
                self.first_seen.push(nroot);
                // println!("ls push 3");
                // self.last_seen.push(self.root);
                mem::swap(&mut self.root, &mut nroot);
                None
            }
            CRInsertState::CloneRevSplit(rnode, lnode) => {
                let mut nroot = Node::new_branch(self.txid, lnode, rnode, &mut self.funding)
                    as *mut Node<K, V, M::Charge>;
                self.first_seen.push(nroot);
                // root was cloned in the rev split
                // println!("ls push 4");
                // self.last_seen.push(self.root);
                mem::swap(&mut self.root, &mut nroot);
                None
            }
        };
        // If this is none, it means a new slot is now occupied.
        if r.is_none() {
            self.length += 1;
        }
        Ok(r)
    }

    /// Clear using this mode's original provider and checked bookkeeping slots.
    /// No original node is mutated or freed; its retirement follows the reader.
    pub(crate) fn try_clear(&mut self) -> Option<()> {
        // SAFETY: this exclusive cursor retains every original reachable node.
        let count = unsafe { Node::tree_node_count(self.root) }?;
        if self.first_seen.remaining_capacity().is_some_and(|n| n < 1)
            || self
                .last_seen
                .as_ref()
                .expect("original retirement buffer")
                .remaining_capacity()
                .is_some_and(|n| n < count)
        {
            return None;
        }
        let empty = Node::<K, V, M::Charge>::new_leaf(self.txid, &mut self.funding).cast();
        // Preflight ensures this push cannot reject the newly owned raw node.
        self.first_seen.push(empty);
        let retired = self.last_seen.as_mut().expect("original retirement buffer");
        // SAFETY: the tree is unchanged and retained; only pointer bookkeeping
        // is appended, after capacity for every actual node was established.
        unsafe {
            Node::visit_tree(self.root, |node| {
                retired.push(node);
                Some(())
            })
        }
        .expect("preflighted tree depth");
        self.root = empty;
        self.length = 0;
        Some(())
    }

    fn insert_tracking_fits(&self, key: &K) -> bool {
        let new_slots = self.first_seen.remaining_capacity();
        let retired_slots = self
            .last_seen
            .as_ref()
            .expect("original retirement buffer")
            .remaining_capacity();
        if new_slots.is_none() && retired_slots.is_none() {
            return true;
        }
        // One insertion can clone each node on its path, split its leaf and
        // every branch above it, then grow one root. Count the complete checked
        // worst case before mutation; never seek another tracking allocation.
        let mut node = self.root;
        let mut branches = 0usize;
        while !self_meta_shared!(node).is_leaf() {
            branches = branches.checked_add(1).expect("valid tree depth");
            assert!(
                branches < usize::BITS as usize,
                "tree exceeds addressable depth"
            );
            let branch = branch_ref_shared!(node, K, V, M::Charge);
            node = branch.get_idx_unchecked(branch.locate_node(key));
        }
        let new_required = branches
            .checked_mul(2)
            .and_then(|n| n.checked_add(3))
            .expect("valid tree insertion bound");
        let retired_required = branches.checked_add(1).expect("valid retirement bound");
        new_slots.is_none_or(|remaining| remaining >= new_required)
            && retired_slots.is_none_or(|remaining| remaining >= retired_required)
    }
}

impl<K: Clone + Ord + Debug, V: Clone, P: NodeCloning<K, V>>
    CursorWrite<K, V, crate::bptree::Prepaid<P>>
{
    /// Original base plus every private node still owned by this cursor.
    /// This explicit diagnostic scans only first_seen, never the base tree or
    /// its successor chain. Retired private nodes are still live allocations.
    pub(crate) fn admitted_node_custody_counts(&self) -> Option<(usize, usize)> {
        self.assert_operable();
        assert!(self.funding.0.is_none(), "previous edit must be sealed");
        let (mut leaves, mut branches) = self.base_node_counts;
        for &node in self.first_seen.as_slice() {
            // SAFETY: every original first_seen pointer remains allocated until
            // cursor cleanup or checkpoint rollback removes and frees its suffix.
            if unsafe { &*node }.is_leaf() {
                leaves = leaves.checked_add(1)?;
            } else {
                branches = branches.checked_add(1)?;
            }
        }
        Some((leaves, branches))
    }

    /// Existing original bookkeeping counts, inspected before further admission.
    pub(crate) fn admitted_tracking(&self) -> [(usize, usize); 2] {
        let retired = self.last_seen.as_ref().expect("original retirement buffer");
        [
            (self.first_seen.as_slice().len(), self.first_seen.capacity()),
            (retired.as_slice().len(), retired.capacity()),
        ]
    }

    /// Install one prepaid edit without replacing the cursor or any tree owner.
    pub(crate) fn resume_admitted_funding(
        &mut self,
        provider: P,
        first: Option<NodeTrackingBuffer<K, V, P::Charge>>,
        last: Option<NodeTrackingBuffer<K, V, P::Charge>>,
        mut saved: Option<&mut CheckpointBuffers<K, V, crate::bptree::Prepaid<P>>>,
    ) {
        assert!(self.funding.0.is_none(), "previous edit must be sealed");
        self.funding.0 = Some(provider);
        if let Some(mut replacement) = first {
            for &node in self.first_seen.as_slice() {
                replacement.push(node);
            }
            // Install valid bookkeeping before an arbitrary old charge can
            // unwind, so cursor abort still sees the original node owners.
            let old = mem::replace(&mut self.first_seen, replacement);
            if let Some(saved) = saved.as_mut() {
                saved.retain_first(old);
            } else {
                drop(old);
            }
        }
        if let Some(mut replacement) = last {
            let retired = self.last_seen.as_mut().expect("original retirement buffer");
            for &node in retired.as_slice() {
                replacement.push(node);
            }
            let old = mem::replace(retired, replacement);
            if let Some(saved) = saved.as_mut() {
                saved.retain_last(old);
            } else {
                drop(old);
            }
        }
    }

    /// Observe the original tracking allocations in custody regression tests.
    #[cfg(test)]
    pub(crate) fn admitted_tracking_addresses(&self) -> [usize; 2] {
        self.assert_operable();
        [
            self.first_seen.as_ptr() as usize,
            self.last_seen
                .as_ref()
                .expect("original retirement buffer")
                .as_ptr() as usize,
        ]
    }

    /// Move the completed edit's exact provider into a closed joined operation.
    /// Keep failure armed through final cleanup under both original writers.
    pub(crate) fn take_completed_admitted_funding(&mut self) -> P {
        assert!(
            self.edit_failed,
            "only a completed unsealed edit can transfer funding"
        );
        self.funding.0.take().expect("original completed provider")
    }

    /// Seal after the one moved provider has been destroyed successfully.
    /// Both original checkpoints and writer guards remain held by the caller.
    pub(crate) fn seal_joined_admitted_edit(&mut self) {
        assert!(
            self.edit_failed,
            "joined edit must remain unsealed through cleanup"
        );
        assert!(
            self.funding.0.is_none(),
            "joined remainder must have moved out"
        );
        self.edit_failed = false;
    }

    /// Keep a caught joined-operation unwind from exposing either partial cursor.
    /// This is infallible and does not release storage or invoke user callbacks.
    pub(crate) fn poison_joined_edit(&mut self) {
        self.edit_failed = true;
    }

    /// Seal the one closed edit, returning only unused original admission.
    /// Allocated node/payload/buffer/shell charges remain in their own storage.
    pub(crate) fn finish_admitted_funding(&mut self) {
        drop(self.funding.0.take().expect("original completed provider"));
        self.edit_failed = false;
    }
}

impl<K: Clone + Ord + Debug, V: Clone> CursorWrite<K, V> {
    pub(crate) fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.begin_admitted_edit();
        let previous = self
            .try_insert(k, v)
            .unwrap_or_else(|_| unreachable!("untracked tracking can grow"));
        self.edit_failed = false;
        previous
    }

    pub(crate) fn clear(&mut self) {
        self.begin_admitted_edit();
        self.try_clear().expect("untracked tracking can grow");
        self.edit_failed = false;
    }

    pub(crate) fn remove(&mut self, k: &K) -> Option<V> {
        self.begin_admitted_edit();
        let previous = self
            .try_remove(k)
            .unwrap_or_else(|()| unreachable!("untracked tracking can grow"));
        self.edit_failed = false;
        previous
    }

    #[cfg(test)]
    pub(crate) fn path_clone(&mut self, k: &K) {
        match path_clone(
            self.root,
            self.txid,
            k,
            self.last_seen.as_mut().expect("original retirement buffer"),
            &mut self.first_seen,
        ) {
            CRCloneState::Clone(mut nroot) => {
                // We cloned the root, so swap it.
                mem::swap(&mut self.root, &mut nroot);
            }
            CRCloneState::NoClone => {}
        };
    }

    pub(crate) fn get_mut_ref(&mut self, k: &K) -> Option<&mut V> {
        self.begin_admitted_edit();
        match path_clone(
            self.root,
            self.txid,
            k,
            self.last_seen.as_mut().expect("original retirement buffer"),
            &mut self.first_seen,
        ) {
            CRCloneState::Clone(mut nroot) => {
                // We cloned the root, so swap it.
                mem::swap(&mut self.root, &mut nroot);
            }
            CRCloneState::NoClone => {}
        };
        // Resolve the borrowed slot while edits are still marked failed, so a
        // caught key-comparison panic cannot leave this cursor publishable.
        let value = path_get_mut_ref(self.root, k).map(|value| value as *mut V);
        self.edit_failed = false;
        // SAFETY: this path is private to the current generation. The returned
        // reference is tied to the exclusive cursor borrow and cannot escape it.
        value.map(|value| unsafe { &mut *value })
    }

    pub(crate) fn split_off_lt(&mut self, k: &K) {
        self.assert_operable();
        /*
        // Remove all the values less than from the top of the tree.
        loop {
            let result = clone_and_split_off_trim_lt(
                self.root,
                self.txid,
                k,
                self.last_seen.as_mut().expect("original retirement buffer"),
                &mut self.first_seen,
            );
            // println!("clone_and_split_off_trim_lt -> {:?}", result);
            match result {
                CRTrimState::Complete => break,
                CRTrimState::Clone(mut nroot) => {
                    // We cloned the root as we changed it, but don't need
                    // to recurse so we break the loop.
                    mem::swap(&mut self.root, &mut nroot);
                    break;
                }
                CRTrimState::Promote(mut nroot) => {
                    mem::swap(&mut self.root, &mut nroot);
                    // This will continue and try again.
                }
            }
        }
        */

        /*
        // Now work up the tree and clean up the remaining path in between
        let result = clone_and_split_off_prune_lt(&mut self.root, self.txid, k);
        // println!("clone_and_split_off_prune_lt -> {:?}", result);
        match result {
            CRPruneState::OkNoClone => {}
            CRPruneState::OkClone(mut nroot) => {
                mem::swap(&mut self.root, &mut nroot);
            }
            CRPruneState::Prune => {
                if self.root.is_leaf() {
                    // No action, the tree is now empty.
                } else {
                    // Root is being demoted, get the last branch and
                    // promote it to the root.
                    let rmut = Arc::get_mut(&mut self.root).unwrap().as_mut_branch();
                    let mut pnode = rmut.extract_last_node();
                    mem::swap(&mut self.root, &mut pnode);
                }
            }
            CRPruneState::ClonePrune(mut clone) => {
                if self.root.is_leaf() {
                    mem::swap(&mut self.root, &mut clone);
                } else {
                    let rmut = Arc::get_mut(&mut clone).unwrap().as_mut_branch();
                    let mut pnode = rmut.extract_last_node();
                    mem::swap(&mut self.root, &mut pnode);
                }
            }
        };
        */

        // Get rid of anything else dangling
        let mut rmkeys: Vec<K> = Vec::new();
        for ki in self.k_iter() {
            if ki >= k {
                break;
            }
            rmkeys.push(ki.clone());
        }

        for kr in rmkeys.into_iter() {
            let _ = self.remove(&kr);
        }

        // Iterate over the remaining kv's to fix our k,v count.
        let newsize = self.kv_iter().count();
        self.length = newsize;
    }

    #[cfg(test)]
    pub(crate) fn root_txid(&self) -> u64 {
        self.get_root_ref().get_txid()
    }

    #[cfg(test)]
    pub(crate) fn tree_density(&self) -> (usize, usize) {
        Node::<K, V>::tree_density_raw(self.get_root())
    }

    pub(crate) fn range_mut<'n, R, T>(&'n mut self, range: R) -> RangeMutIter<'n, K, V>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.assert_operable();
        RangeMutIter::new(self, range)
    }
}
impl<K: Clone + Ord + Debug, V: Clone> Extend<(K, V)> for CursorWrite<K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        iter.into_iter().for_each(|(k, v)| {
            let _ = self.insert(k, v);
        });
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> Drop for CursorWrite<K, V, M> {
    fn drop(&mut self) {
        // If there is content in first_seen, this means we aborted and must rollback
        // of these items!
        // println!("Releasing CW FS -> {:?}", self.first_seen);
        self.first_seen
            .as_slice()
            .iter()
            .for_each(|n| Node::free(*n))
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> Drop for CursorRead<K, V, M> {
    fn drop(&mut self) {
        // If there is content in last_seen, a future generation wants us to remove it!
        // Exclusive destruction cannot race the original writer: it retains
        // this reader generation until after the retirement vector is set.
        if let Some(last_seen) = self.last_seen.get_mut() {
            last_seen.as_slice().iter().for_each(|n| Node::free(*n));
        }
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> Drop for SuperBlock<K, V, M> {
    fn drop(&mut self) {
        // SAFETY: the final root owner has no remaining readers or cursors.
        // Detached writers retain this same root and drop their unpublished
        // nodes and base reader before releasing it. Reclamation must not need
        // another heap allocation in order to release the tree's capacity.
        unsafe { Node::free_tree(self.root) };
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> CursorRead<K, V, M> {
    pub(crate) fn new(sblock: &SuperBlock<K, V, M>) -> Self {
        // println!("starting rd txid -> {:?}", sblock.txid);
        CursorRead {
            txid: sblock.txid,
            length: sblock.size,
            root: sblock.root,
            last_seen: OnceLock::new(),
        }
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> CursorReadOps<K, V, M::Charge>
    for CursorRead<K, V, M>
{
    fn get_root_ref(&self) -> &Node<K, V, M::Charge> {
        unsafe { &*(self.root) }
    }

    fn get_root(&self) -> *mut Node<K, V, M::Charge> {
        self.root
    }

    fn len(&self) -> usize {
        self.length
    }

    fn get_txid(&self) -> u64 {
        self.txid
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> CursorReadOps<K, V, M::Charge>
    for CursorWrite<K, V, M>
{
    fn get_root_ref(&self) -> &Node<K, V, M::Charge> {
        self.assert_operable();
        unsafe { &*(self.root) }
    }

    fn get_root(&self) -> *mut Node<K, V, M::Charge> {
        self.assert_operable();
        self.root
    }

    fn len(&self) -> usize {
        self.assert_operable();
        self.length
    }

    fn get_txid(&self) -> u64 {
        self.assert_operable();
        self.txid
    }
}

fn clone_and_insert<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>>(
    node: *mut Node<K, V, M::Charge>,
    txid: u64,
    k: K,
    v: V,
    last_seen: &mut M::Buffer,
    first_seen: &mut M::Buffer,
    funding: &mut M,
) -> CRInsertState<K, V, M::Charge> {
    /*
     * Let's talk about the magic of this function. Come, join
     * me around the [🔥🔥🔥]
     *
     * This function is the heart and soul of a copy on write
     * structure - as we progress to the leaf location where we
     * wish to perform an alteration, we clone (if required) all
     * nodes on the path. This way an abort (rollback) of the
     * commit simply is to drop the cursor, where the "new"
     * cloned values are only referenced. To commit, we only need
     * to replace the tree root in the parent structures as
     * the cloned path must by definition include the root, and
     * will contain references to nodes that did not need cloning,
     * thus keeping them alive.
     */

    if self_meta_shared!(node).is_leaf() {
        // NOTE: We have to match, rather than map here, as rust tries to
        // move k:v into both closures!

        // Leaf path
        match leaf_ref_shared!(node, K, V, M::Charge).req_clone(txid, funding) {
            Some(cnode) => {
                // println!();
                first_seen.push(cnode);
                // println!("ls push 5");
                last_seen.push(node);
                // Clone was required.
                let mref = leaf_ref!(cnode, K, V, M::Charge);
                // insert to the new node.
                match mref.insert_or_update(k, v, funding) {
                    LeafInsertState::Ok(res) => CRInsertState::Clone(res, cnode),
                    LeafInsertState::Split(rnode) => {
                        first_seen.push(rnode as *mut Node<K, V, M::Charge>);
                        // let rnode = Node::new_leaf_ins(txid, sk, sv);
                        CRInsertState::CloneSplit(cnode, rnode as *mut Node<K, V, M::Charge>)
                    }
                    LeafInsertState::RevSplit(lnode) => {
                        first_seen.push(lnode as *mut Node<K, V, M::Charge>);
                        CRInsertState::CloneRevSplit(cnode, lnode as *mut Node<K, V, M::Charge>)
                    }
                }
            }
            None => {
                // No clone required.
                // simply do the insert.
                let mref = leaf_ref!(node, K, V, M::Charge);
                match mref.insert_or_update(k, v, funding) {
                    LeafInsertState::Ok(res) => CRInsertState::NoClone(res),
                    LeafInsertState::Split(rnode) => {
                        // We split, but left is already part of the txn group, so lets
                        // just return what's new.
                        // let rnode = Node::new_leaf_ins(txid, sk, sv);
                        first_seen.push(rnode as *mut Node<K, V, M::Charge>);
                        CRInsertState::Split(rnode as *mut Node<K, V, M::Charge>)
                    }
                    LeafInsertState::RevSplit(lnode) => {
                        first_seen.push(lnode as *mut Node<K, V, M::Charge>);
                        CRInsertState::RevSplit(lnode as *mut Node<K, V, M::Charge>)
                    }
                }
            }
        } // end match
    } else {
        // Branch path
        // Decide if we need to clone - we do this as we descend due to a quirk in Arc
        // get_mut, because we don't have access to get_mut_unchecked (and this api may
        // never be stabilised anyway). When we change this to *mut + garbage lists we
        // could consider restoring the reactive behaviour that clones up, rather than
        // cloning down the path.
        //
        // NOTE: We have to match, rather than map here, as rust tries to
        // move k:v into both closures!
        match branch_ref_shared!(node, K, V, M::Charge).req_clone(txid, funding) {
            Some(cnode) => {
                first_seen.push(cnode);
                last_seen.push(node);
                // Not same txn, clone instead.
                let nmref = branch_ref!(cnode, K, V, M::Charge);
                let anode_idx = nmref.locate_node(&k);
                let anode = nmref.get_idx_unchecked(anode_idx);

                match clone_and_insert(anode, txid, k, v, last_seen, first_seen, funding) {
                    CRInsertState::Clone(res, lnode) => {
                        nmref.replace_by_idx(anode_idx, lnode);
                        // Pass back up that we cloned.
                        CRInsertState::Clone(res, cnode)
                    }
                    CRInsertState::CloneSplit(lnode, rnode) => {
                        // CloneSplit here, would have already updated lnode/rnode into the
                        // gc lists.
                        // Second, we update anode_idx node with our lnode as the new clone.
                        nmref.replace_by_idx(anode_idx, lnode);

                        // Third we insert rnode - perfect world it's at anode_idx + 1, but
                        // we use the normal insert routine for now.
                        match nmref.add_node(rnode, funding) {
                            BranchInsertState::Ok => CRInsertState::Clone(None, cnode),
                            BranchInsertState::Split(clnode, crnode) => {
                                // Create a new branch to hold these children.
                                let nrnode = Node::new_branch(txid, clnode, crnode, funding);
                                first_seen.push(nrnode as *mut Node<K, V, M::Charge>);
                                // Return it
                                CRInsertState::CloneSplit(
                                    cnode,
                                    nrnode as *mut Node<K, V, M::Charge>,
                                )
                            }
                        }
                    }
                    CRInsertState::CloneRevSplit(nnode, lnode) => {
                        nmref.replace_by_idx(anode_idx, nnode);
                        match nmref.add_node_left(lnode, anode_idx, funding) {
                            BranchInsertState::Ok => CRInsertState::Clone(None, cnode),
                            BranchInsertState::Split(clnode, crnode) => {
                                let nrnode = Node::new_branch(txid, clnode, crnode, funding);
                                first_seen.push(nrnode as *mut Node<K, V, M::Charge>);
                                CRInsertState::CloneSplit(
                                    cnode,
                                    nrnode as *mut Node<K, V, M::Charge>,
                                )
                            }
                        }
                    }
                    CRInsertState::NoClone(_res) => {
                        // If our descendant did not clone, then we don't have to either.
                        unreachable!("Should never be possible.");
                        // CRInsertState::NoClone(res)
                    }
                    CRInsertState::Split(_rnode) => {
                        // I think
                        unreachable!("This represents a corrupt tree state");
                    }
                    CRInsertState::RevSplit(_lnode) => {
                        unreachable!("This represents a corrupt tree state");
                    }
                } // end match
            } // end Some,
            None => {
                let nmref = branch_ref!(node, K, V, M::Charge);
                let anode_idx = nmref.locate_node(&k);
                let anode = nmref.get_idx_unchecked(anode_idx);

                match clone_and_insert(anode, txid, k, v, last_seen, first_seen, funding) {
                    CRInsertState::Clone(res, lnode) => {
                        nmref.replace_by_idx(anode_idx, lnode);
                        // We did not clone, and no further work needed.
                        CRInsertState::NoClone(res)
                    }
                    CRInsertState::NoClone(res) => {
                        // If our descendant did not clone, then we don't have to do any adjustments
                        // or further work.
                        CRInsertState::NoClone(res)
                    }
                    CRInsertState::Split(rnode) => {
                        match nmref.add_node(rnode, funding) {
                            // Similar to CloneSplit - we are either okay, and the insert was happy.
                            BranchInsertState::Ok => CRInsertState::NoClone(None),
                            // Or *we* split as well, and need to return a new sibling branch.
                            BranchInsertState::Split(clnode, crnode) => {
                                // Create a new branch to hold these children.
                                let nrnode = Node::new_branch(txid, clnode, crnode, funding);
                                first_seen.push(nrnode as *mut Node<K, V, M::Charge>);
                                // Return it
                                CRInsertState::Split(nrnode as *mut Node<K, V, M::Charge>)
                            }
                        }
                    }
                    CRInsertState::CloneSplit(lnode, rnode) => {
                        // work inplace.
                        // Second, we update anode_idx node with our lnode as the new clone.
                        nmref.replace_by_idx(anode_idx, lnode);

                        // Third we insert rnode - perfect world it's at anode_idx + 1, but
                        // we use the normal insert routine for now.
                        match nmref.add_node(rnode, funding) {
                            // Similar to CloneSplit - we are either okay, and the insert was happy.
                            BranchInsertState::Ok => CRInsertState::NoClone(None),
                            // Or *we* split as well, and need to return a new sibling branch.
                            BranchInsertState::Split(clnode, crnode) => {
                                // Create a new branch to hold these children.
                                let nrnode = Node::new_branch(txid, clnode, crnode, funding);
                                first_seen.push(nrnode as *mut Node<K, V, M::Charge>);
                                // Return it
                                CRInsertState::Split(nrnode as *mut Node<K, V, M::Charge>)
                            }
                        }
                    }
                    CRInsertState::RevSplit(lnode) => {
                        match nmref.add_node_left(lnode, anode_idx, funding) {
                            BranchInsertState::Ok => CRInsertState::NoClone(None),
                            BranchInsertState::Split(clnode, crnode) => {
                                let nrnode = Node::new_branch(txid, clnode, crnode, funding);
                                first_seen.push(nrnode as *mut Node<K, V, M::Charge>);
                                CRInsertState::Split(nrnode as *mut Node<K, V, M::Charge>)
                            }
                        }
                    }
                    CRInsertState::CloneRevSplit(nnode, lnode) => {
                        nmref.replace_by_idx(anode_idx, nnode);
                        match nmref.add_node_left(lnode, anode_idx, funding) {
                            BranchInsertState::Ok => CRInsertState::NoClone(None),
                            BranchInsertState::Split(clnode, crnode) => {
                                let nrnode = Node::new_branch(txid, clnode, crnode, funding);
                                first_seen.push(nrnode as *mut Node<K, V, M::Charge>);
                                CRInsertState::Split(nrnode as *mut Node<K, V, M::Charge>)
                            }
                        }
                    }
                } // end match
            }
        } // end match branch ref clone
    } // end if leaf
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> Debug for CursorRead<K, V, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CursorRead")
            .field("txid", &self.txid)
            .field("length", &self.length)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}
impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> Debug for CursorWrite<K, V, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CursorWrite")
            .field("txid", &self.txid)
            .field("length", &self.length)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

fn path_clone<K: Clone + Ord + Debug, V: Clone>(
    node: *mut Node<K, V>,
    txid: u64,
    k: &K,
    last_seen: &mut Vec<*mut Node<K, V>>,
    first_seen: &mut Vec<*mut Node<K, V>>,
) -> CRCloneState<K, V> {
    if unsafe { (*node).is_leaf() } {
        leaf_ref_shared!(node, K, V, Untracked)
            .req_clone(txid, &mut Untracked)
            .map(|cnode| {
                // Track memory
                last_seen.push(node);
                // println!("ls push 7 {:?}", node);
                first_seen.push(cnode);
                CRCloneState::Clone(cnode)
            })
            .unwrap_or(CRCloneState::NoClone)
    } else {
        // We are in a branch, so locate our descendent and prepare
        // to clone if needed.
        // println!("txid -> {:?} {:?}", node_txid, txid);
        let nmref = branch_ref_shared!(node, K, V, Untracked);
        let anode_idx = nmref.locate_node(k);
        let anode = nmref.get_idx_unchecked(anode_idx);
        match path_clone(anode, txid, k, last_seen, first_seen) {
            CRCloneState::Clone(cnode) => {
                // Do we need to clone?
                nmref
                    .req_clone(txid, &mut Untracked)
                    .map(|acnode| {
                        // We require to be cloned.
                        last_seen.push(node);
                        // println!("ls push 8");
                        first_seen.push(acnode);
                        let nmref = branch_ref!(acnode, K, V, Untracked);
                        nmref.replace_by_idx(anode_idx, cnode);
                        CRCloneState::Clone(acnode)
                    })
                    .unwrap_or_else(|| {
                        // This branch is already private to the same transaction.
                        let nmref = branch_ref!(node, K, V, Untracked);
                        nmref.replace_by_idx(anode_idx, cnode);
                        CRCloneState::NoClone
                    })
            }
            CRCloneState::NoClone => {
                // Did not clone, unwind.
                CRCloneState::NoClone
            }
        }
    }
}

fn path_get_mut_ref<'a, K, V>(node: *mut Node<K, V>, k: &K) -> Option<&'a mut V>
where
    K: Clone + Ord + Debug + 'a,
    V: Clone,
{
    if unsafe { &*node }.meta.is_leaf() {
        leaf_ref!(node, K, V, Untracked).get_mut_ref(k)
    } else {
        // This nmref binds the life of the reference ...
        let nmref = branch_ref!(node, K, V, Untracked);
        let anode_idx = nmref.locate_node(k);
        let anode = nmref.get_idx_unchecked(anode_idx);
        // That we get here. So we can't just return it, and we need to 'strip' the
        // lifetime so that it's bound to the lifetime of the outer node
        // rather than the nmref.
        let r: Option<*mut V> = path_get_mut_ref(anode, k).map(|v| v as *mut V);

        // I solemly swear I am up to no good.
        r.map(|v| unsafe { &mut *v as &mut V })
    }
}

/*
fn clone_and_split_off_trim_lt<K: Clone + Ord + Debug, V: Clone>(
    node: *mut Node<K, V>,
    txid: u64,
    k: &K,
    last_seen: &mut Vec<*mut Node<K, V>>,
    first_seen: &mut Vec<*mut Node<K, V>>,
) -> CRTrimState<K, V> {
    if self_meta!(node).is_leaf() {
        // No action, it's a leaf. Prune will do it.
        CRTrimState::Complete
    } else {
        branch_ref!(node, K, V, Untracked)
            .req_clone(txid, &mut Untracked)
            .map(|cnode| {
                let nmref = branch_ref!(cnode, K, V, Untracked);
                first_seen.push(cnode as *mut Node<K, V>);
                last_seen.push(node as *mut Node<K, V>);
                match nmref.trim_lt_key(k, last_seen, first_seen) {
                    BranchTrimState::Complete => CRTrimState::Clone(cnode),
                    BranchTrimState::Promote(pnode) => {
                        // We just cloned it but oh well, away you go ...
                        last_seen.push(cnode as *mut Node<K, V>);
                        CRTrimState::Promote(pnode)
                    }
                }
            })
            .unwrap_or_else(|| {
                let nmref = branch_ref!(node, K, V, Untracked);

                match nmref.trim_lt_key(k, last_seen, first_seen) {
                    BranchTrimState::Complete => CRTrimState::Complete,
                    BranchTrimState::Promote(pnode) => {
                        // We are about to remove our node, so mark it as the last time.
                        last_seen.push(node);
                        CRTrimState::Promote(pnode)
                    }
                }
            })
    }
}
*/

/*
fn clone_and_split_off_prune_lt<K: Clone + Ord + Debug, V: Clone>(
    node: &mut ABNode<K, V>,
    txid: usize,
    k: &K,
) -> CRPruneState<K, V> {
    if node.is_leaf() {
        // I think this should be do nothing, the up walk will clean.
        if node.txid == txid {
            let nmref = Arc::get_mut(node).unwrap().as_mut_leaf();
            match nmref.remove_lt(k) {
                LeafPruneState::Ok => CRPruneState::OkNoClone,
                LeafPruneState::Prune => CRPruneState::Prune,
            }
        } else {
            let mut cnode = node.req_clone(txid, &mut Untracked);
            let nmref = Arc::get_mut(&mut cnode).unwrap().as_mut_leaf();
            match nmref.remove_lt(k) {
                LeafPruneState::Ok => CRPruneState::OkClone(cnode),
                LeafPruneState::Prune => CRPruneState::ClonePrune(cnode),
            }
        }
    } else {
        if node.txid == txid {
            let nmref = Arc::get_mut(node).unwrap().as_mut_branch();
            let anode_idx = nmref.locate_node(&k);
            let anode = nmref.get_idx_unchecked(anode_idx);
            let result = clone_and_split_off_prune_lt(anode, txid, k);
            // println!("== clone_and_split_off_prune_lt --> {:?}", result);
            match result {
                CRPruneState::OkNoClone => {
                    match nmref.prune(anode_idx) {
                        Ok(_) => {
                            // Okay, the branch remains valid, return that we are okay, and
                            // no clone is needed.
                            CRPruneState::OkNoClone
                        }
                        Err(_) => CRPruneState::Prune,
                    }
                }
                CRPruneState::OkClone(clone) => {
                    // Our child cloned, so replace it.
                    nmref.replace_by_idx(anode_idx, clone);
                    // Check our node for anything else to be removed.
                    match nmref.prune(anode_idx) {
                        Ok(_) => {
                            // Okay, the branch remains valid, return that we are okay, and
                            // no clone is needed.
                            CRPruneState::OkNoClone
                        }
                        Err(_) => CRPruneState::Prune,
                    }
                }
                CRPruneState::Prune => {
                    match nmref.prune_decision(txid, anode_idx) {
                        Ok(_) => {
                            // Okay, the branch remains valid. Now we need to trim any
                            // excess if possible.
                            CRPruneState::OkNoClone
                        }
                        Err(_) => CRPruneState::Prune,
                    }
                }
                CRPruneState::ClonePrune(clone) => {
                    // Our child cloned, and intends to be removed.
                    nmref.replace_by_idx(anode_idx, clone);
                    // Now make the prune decision.
                    match nmref.prune_decision(txid, anode_idx) {
                        Ok(_) => {
                            // Okay, the branch remains valid. Now we need to trim any
                            // excess if possible.
                            CRPruneState::OkNoClone
                        }
                        Err(_) => CRPruneState::Prune,
                    }
                }
            }
        } else {
            let mut cnode = node.req_clone(txid, &mut Untracked);
            let nmref = Arc::get_mut(&mut cnode).unwrap().as_mut_branch();
            let anode_idx = nmref.locate_node(&k);
            let anode = nmref.get_idx_unchecked(anode_idx);
            let result = clone_and_split_off_prune_lt(anode, txid, k);
            // println!("!= clone_and_split_off_prune_lt --> {:?}", result);
            match result {
                CRPruneState::OkNoClone => {
                    // I think this is an impossible state - how can a child be in the
                    // txid if we are not?
                    unreachable!("Impossible tree state")
                }
                CRPruneState::OkClone(clone) => {
                    // Our child cloned, so replace it.
                    nmref.replace_by_idx(anode_idx, clone);
                    // Check our node for anything else to be removed.
                    match nmref.prune(anode_idx) {
                        Ok(_) => {
                            // Okay, the branch remains valid, return that we are okay.
                            CRPruneState::OkClone(cnode)
                        }
                        Err(_) => CRPruneState::ClonePrune(cnode),
                    }
                }
                CRPruneState::Prune => {
                    unimplemented!();
                }
                CRPruneState::ClonePrune(clone) => {
                    // Our child cloned, and intends to be removed.
                    nmref.replace_by_idx(anode_idx, clone);
                    // Now make the prune decision.
                    match nmref.prune_decision(txid, anode_idx) {
                        Ok(_) => {
                            // Okay, the branch remains valid. Now we need to trim any
                            // excess if possible.
                            CRPruneState::OkClone(cnode)
                        }
                        Err(_) => CRPruneState::ClonePrune(cnode),
                    }
                } // end clone prune
            } // end match result
        }
    }
}
*/

#[cfg(test)]
mod tests {
    use super::super::node::*;
    use super::super::states::*;
    use super::SuperBlock;
    use super::{CursorRead, CursorReadOps};
    use crate::internals::lincowcell::LinCowCellCapable;
    use rand::seq::SliceRandom;
    use std::mem;

    fn create_leaf_node(v: usize) -> *mut Node<usize, usize> {
        let node = Node::new_leaf(1, &mut Untracked);
        {
            let nmut: &mut Leaf<_, _> = leaf_ref!(node, usize, usize, Untracked);
            nmut.insert_or_update(v, v, &mut Untracked);
        }
        node as *mut Node<usize, usize>
    }

    fn create_leaf_node_full(vbase: usize) -> *mut Node<usize, usize> {
        assert!(vbase.is_multiple_of(10));
        let node = Node::new_leaf(1, &mut Untracked);
        {
            let nmut = leaf_ref!(node, usize, usize, Untracked);
            for idx in 0..L_CAPACITY {
                let v = vbase + idx;
                nmut.insert_or_update(v, v, &mut Untracked);
            }
            // println!("lnode full {:?} -> {:?}", vbase, nmut);
        }
        node as *mut Node<usize, usize>
    }

    fn create_branch_node_full(vbase: usize) -> *mut Node<usize, usize> {
        let l1 = create_leaf_node(vbase);
        let l2 = create_leaf_node(vbase + 10);
        let lbranch = Node::new_branch(1, l1, l2, &mut Untracked);
        let bref = branch_ref!(lbranch, usize, usize, Untracked);
        for i in 2..BV_CAPACITY {
            let l = create_leaf_node(vbase + (10 * i));
            let r = bref.add_node(l, &mut Untracked);
            match r {
                BranchInsertState::Ok => {}
                _ => debug_assert!(false),
            }
        }
        assert!(bref.count() == L_CAPACITY);
        lbranch as *mut Node<usize, usize>
    }

    #[test]
    fn test_bptree2_cursor_insert_leaf() {
        // First create the node + cursor
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        eprintln!("{:?}", wcurs);

        let prev_txid = wcurs.root_txid();
        eprintln!("prev_txid {:?}", prev_txid);

        // Now insert - the txid should be different.
        let r = wcurs.insert(1, 1);
        assert!(r.is_none());
        eprintln!("get_root_ref {:?}", wcurs.get_root_ref().meta.get_txid());
        let r1_txid = wcurs.root_txid();
        assert!(r1_txid == prev_txid + 1);

        // Now insert again - the txid should be the same.
        let r = wcurs.insert(2, 2);
        assert!(r.is_none());
        let r2_txid = wcurs.root_txid();
        assert!(r2_txid == r1_txid);
        // The clones worked as we wanted!
        assert!(wcurs.verify());
    }

    #[test]
    fn test_bptree2_cursor_insert_split_1() {
        // Given a leaf at max, insert such that:
        //
        // leaf
        //
        // leaf -> split leaf
        //
        //
        //      root
        //     /    \
        //  leaf    split leaf
        //
        // It's worth noting that this is testing the CloneSplit path
        // as leaf needs a clone AND to split to achieve the new root.

        let node = create_leaf_node_full(10);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());
        let prev_txid = wcurs.root_txid();

        let r = wcurs.insert(1, 1);
        assert!(r.is_none());
        let r1_txid = wcurs.root_txid();
        assert!(r1_txid == prev_txid + 1);
        assert!(wcurs.verify());
        // println!("{:?}", wcurs);
        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_split_2() {
        // Similar to split_1, but test the Split only path. This means
        // leaf needs to be below max to start, and we insert enough in-txn
        // to trigger a clone of leaf AND THEN to cause the split.
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        for v in 1..(L_CAPACITY + 1) {
            // println!("ITER v {}", v);
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
        }
        // println!("{:?}", wcurs);
        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_split_3() {
        //      root
        //     /    \
        //  leaf    split leaf
        //       ^
        //        \----- nnode
        //
        //  Check leaf split in between l/sl (new txn)
        let lnode = create_leaf_node_full(10);
        let rnode = create_leaf_node_full(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());

        assert!(wcurs.verify());
        // println!("{:?}", wcurs);

        let r = wcurs.insert(19, 19);
        assert!(r.is_none());
        assert!(wcurs.verify());
        // println!("{:?}", wcurs);

        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_split_4() {
        //      root
        //     /    \
        //  leaf    split leaf
        //                       ^
        //                        \----- nnode
        //
        //  Check leaf split of sl (new txn)
        //
        let lnode = create_leaf_node_full(10);
        let rnode = create_leaf_node_full(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        let r = wcurs.insert(29, 29);
        assert!(r.is_none());
        assert!(wcurs.verify());
        // println!("{:?}", wcurs);

        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_split_5() {
        //      root
        //     /    \
        //  leaf    split leaf
        //       ^
        //        \----- nnode
        //
        //  Check leaf split in between l/sl (same txn)
        //
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        // Now insert to trigger the needed actions.
        // Remember, we only need L_CAPACITY because there is already a
        // value in the leaf.
        for idx in 0..(L_CAPACITY) {
            let v = 10 + 1 + idx;
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
        }
        // println!("{:?}", wcurs);

        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_split_6() {
        //      root
        //     /    \
        //  leaf    split leaf
        //                       ^
        //                        \----- nnode
        //
        //  Check leaf split of sl (same txn)
        //
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        // Now insert to trigger the needed actions.
        // Remember, we only need L_CAPACITY because there is already a
        // value in the leaf.
        for idx in 0..(L_CAPACITY) {
            let v = 20 + 1 + idx;
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
        }
        // println!("{:?}", wcurs);

        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_split_7() {
        //      root
        //     /    \
        //  leaf    split leaf
        // Insert to leaf then split leaf such that root has cloned
        // in step 1, but doesn't need clone in 2.
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        let r = wcurs.insert(11, 11);
        assert!(r.is_none());
        assert!(wcurs.verify());

        let r = wcurs.insert(21, 21);
        assert!(r.is_none());
        assert!(wcurs.verify());

        // println!("{:?}", wcurs);

        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_split_8() {
        //      root
        //     /    \
        //  leaf    split leaf
        //        ^               ^
        //        \---- nnode 1    \----- nnode 2
        //
        //  Check double leaf split of sl (same txn). This is to
        // take the clonesplit path in the branch case where branch already
        // cloned.
        //
        let lnode = create_leaf_node_full(10);
        let rnode = create_leaf_node_full(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        let r = wcurs.insert(19, 19);
        assert!(r.is_none());
        assert!(wcurs.verify());

        let r = wcurs.insert(29, 29);
        assert!(r.is_none());
        assert!(wcurs.verify());

        // println!("{:?}", wcurs);

        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_stress_1() {
        // Insert ascending - we want to ensure the tree is a few levels deep
        // so we do this to a reasonable number.
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        for v in 1..(L_CAPACITY << 4) {
            // println!("ITER v {}", v);
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
        }
        // println!("{:?}", wcurs);
        // println!("DENSITY -> {:?}", wcurs.get_tree_density());
        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_stress_2() {
        // Insert descending
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        for v in (1..(L_CAPACITY << 4)).rev() {
            // println!("ITER v {}", v);
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
        }
        // println!("{:?}", wcurs);
        // println!("DENSITY -> {:?}", wcurs.get_tree_density());
        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_stress_3() {
        // Insert random
        let mut rng = rand::rng();
        let mut ins: Vec<usize> = (1..(L_CAPACITY << 4)).collect();
        ins.shuffle(&mut rng);

        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        for v in ins.into_iter() {
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
        }
        // println!("{:?}", wcurs);
        // println!("DENSITY -> {:?}", wcurs.get_tree_density());
        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    // Add transaction-ised versions.
    #[test]
    fn test_bptree2_cursor_insert_stress_4() {
        // Insert ascending - we want to ensure the tree is a few levels deep
        // so we do this to a reasonable number.
        let mut sb = unsafe { SuperBlock::new() };
        let mut rdr = sb.create_reader();

        for v in 1..(L_CAPACITY << 4) {
            let mut wcurs = sb.create_writer(());
            // println!("ITER v {}", v);
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());

            rdr = sb.pre_commit(wcurs, &rdr);
        }
        // println!("{:?}", node);
        // On shutdown, check we dropped all as needed.
        mem::drop(rdr);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_stress_5() {
        // Insert descending
        let mut sb = unsafe { SuperBlock::new() };
        let mut rdr = sb.create_reader();

        for v in (1..(L_CAPACITY << 4)).rev() {
            let mut wcurs = sb.create_writer(());
            // println!("ITER v {}", v);
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
            rdr = sb.pre_commit(wcurs, &rdr);
        }
        // println!("{:?}", node);
        // On shutdown, check we dropped all as needed.
        mem::drop(rdr);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_insert_stress_6() {
        // Insert random
        let mut rng = rand::rng();
        let mut ins: Vec<usize> = (1..(L_CAPACITY << 4)).collect();
        ins.shuffle(&mut rng);

        let mut sb = unsafe { SuperBlock::new() };
        let mut rdr = sb.create_reader();

        for v in ins.into_iter() {
            let mut wcurs = sb.create_writer(());
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
            rdr = sb.pre_commit(wcurs, &rdr);
        }
        // println!("{:?}", node);
        // On shutdown, check we dropped all as needed.
        mem::drop(rdr);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_search_1() {
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        for v in 1..(L_CAPACITY << 4) {
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            let r = wcurs.search(&v);
            assert!(r.unwrap() == &v);
        }

        for v in 1..(L_CAPACITY << 4) {
            let r = wcurs.search(&v);
            assert!(r.unwrap() == &v);
        }
        // On shutdown, check we dropped all as needed.
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_length_1() {
        // Check the length is consistent on operations.
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        for v in 1..(L_CAPACITY << 4) {
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
        }
        // println!("{} == {}", wcurs.len(), L_CAPACITY << 4);
        assert!(wcurs.len() == L_CAPACITY << 4);
    }

    #[test]
    fn test_bptree2_cursor_remove_01_p0() {
        // Check that a single value can be removed correctly without change.
        // Check that a missing value is removed as "None".
        // Check that emptying the root is ok.
        // BOTH of these need new txns to check clone, and then reuse txns.
        //
        //
        let lnode = create_leaf_node_full(0);
        let sb = SuperBlock::new_test(1, lnode);
        let mut wcurs = sb.create_writer(());
        // println!("{:?}", wcurs);

        for v in 0..L_CAPACITY {
            let x = wcurs.remove(&v);
            // println!("{:?}", wcurs);
            assert!(x == Some(v));
        }

        for v in 0..L_CAPACITY {
            let x = wcurs.remove(&v);
            assert!(x.is_none());
        }

        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_01_p1() {
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        let _ = wcurs.remove(&0);
        // println!("{:?}", wcurs);

        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_02() {
        // Given the tree:
        //
        //      root
        //     /    \
        //  leaf    split leaf
        //
        // Remove from "split leaf" and merge left. (new txn)
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let znode = create_leaf_node(0);
        let root = Node::new_branch(0, znode, lnode, &mut Untracked);
        // Prevent the tree shrinking.
        unsafe { (*root).add_node(rnode, &mut Untracked) };
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        // println!("{:?}", wcurs);
        assert!(wcurs.verify());

        wcurs.remove(&20);
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_03() {
        // Given the tree:
        //
        //      root
        //     /    \
        //  leaf    split leaf
        //
        // Remove from "leaf" and merge right (really left, but you know ...). (new txn)
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let znode = create_leaf_node(30);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        // Prevent the tree shrinking.
        unsafe { (*root).add_node(znode, &mut Untracked) };
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.remove(&10);
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_04p0() {
        // Given the tree:
        //
        //      root
        //     /    \
        //  leaf    split leaf
        //
        // Remove from "split leaf" and merge left. (leaf cloned already)
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let znode = create_leaf_node(0);
        let root = Node::new_branch(0, znode, lnode, &mut Untracked);
        // Prevent the tree shrinking.
        unsafe { (*root).add_node(rnode, &mut Untracked) };
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        // Setup sibling leaf to already be cloned.
        wcurs.path_clone(&10);
        assert!(wcurs.verify());

        wcurs.remove(&20);
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_04p1() {
        // Given the tree:
        //
        //      root
        //     /    \
        //  leaf    split leaf
        //
        // Remove from "split leaf" and merge left. (leaf cloned already)
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let znode = create_leaf_node(0);
        let root = Node::new_branch(0, znode, lnode, &mut Untracked);
        // Prevent the tree shrinking.
        unsafe { (*root).add_node(rnode, &mut Untracked) };
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        // Setup leaf to already be cloned.
        wcurs.path_clone(&20);
        assert!(wcurs.verify());

        wcurs.remove(&20);
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_05() {
        // Given the tree:
        //
        //      root
        //     /    \
        //  leaf    split leaf
        //
        // Remove from "leaf" and merge 'right'. (split leaf cloned already)
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node(20);
        let znode = create_leaf_node(30);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        // Prevent the tree shrinking.
        unsafe { (*root).add_node(znode, &mut Untracked) };
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        // Setup leaf to already be cloned.
        wcurs.path_clone(&20);

        wcurs.remove(&10);
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_06() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - 2node
        //   rbranch - 2node
        //   txn     - new
        //
        //   when remove from rbranch, mergc left to lbranch.
        //   should cause tree height reduction.
        let l1 = create_leaf_node(0);
        let l2 = create_leaf_node(10);
        let r1 = create_leaf_node(20);
        let r2 = create_leaf_node(30);
        let lbranch = Node::new_branch(0, l1, l2, &mut Untracked);
        let rbranch = Node::new_branch(0, r1, r2, &mut Untracked);
        let root: *mut Branch<usize, usize> =
            Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());

        assert!(wcurs.verify());

        wcurs.remove(&30);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_07() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - 2node
        //   rbranch - 2node
        //   txn     - new
        //
        //   when remove from lbranch, merge right to rbranch.
        //   should cause tree height reduction.
        let l1 = create_leaf_node(0);
        let l2 = create_leaf_node(10);
        let r1 = create_leaf_node(20);
        let r2 = create_leaf_node(30);
        let lbranch = Node::new_branch(0, l1, l2, &mut Untracked);
        let rbranch = Node::new_branch(0, r1, r2, &mut Untracked);
        let root: *mut Branch<usize, usize> =
            Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.remove(&10);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_08() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - full
        //   rbranch - 2node
        //   txn     - new
        //
        //   when remove from rbranch, borrow from lbranch
        //   will NOT reduce height
        let lbranch = create_branch_node_full(0);

        let r1 = create_leaf_node(80);
        let r2 = create_leaf_node(90);
        let rbranch = Node::new_branch(0, r1, r2, &mut Untracked);

        let root: *mut Branch<usize, usize> =
            Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.remove(&80);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_09() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - 2node
        //   rbranch - full
        //   txn     - new
        //
        //   when remove from lbranch, borrow from rbranch
        //   will NOT reduce height
        let l1 = create_leaf_node(0);
        let l2 = create_leaf_node(10);
        let lbranch = Node::new_branch(0, l1, l2, &mut Untracked);

        let rbranch = create_branch_node_full(100);

        let root: *mut Branch<usize, usize> =
            Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.remove(&10);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_10() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - 2node
        //   rbranch - 2node
        //   txn     - touch lbranch
        //
        //   when remove from rbranch, mergc left to lbranch.
        //   should cause tree height reduction.
        let l1 = create_leaf_node(0);
        let l2 = create_leaf_node(10);
        let r1 = create_leaf_node(20);
        let r2 = create_leaf_node(30);
        let lbranch = Node::new_branch(0, l1, l2, &mut Untracked);
        let rbranch = Node::new_branch(0, r1, r2, &mut Untracked);
        let root: *mut Branch<usize, usize> =
            Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());

        assert!(wcurs.verify());

        wcurs.path_clone(&0);
        wcurs.path_clone(&10);

        wcurs.remove(&30);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_11() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - 2node
        //   rbranch - 2node
        //   txn     - touch rbranch
        //
        //   when remove from lbranch, merge right to rbranch.
        //   should cause tree height reduction.
        let l1 = create_leaf_node(0);
        let l2 = create_leaf_node(10);
        let r1 = create_leaf_node(20);
        let r2 = create_leaf_node(30);
        let lbranch = Node::new_branch(0, l1, l2, &mut Untracked);
        let rbranch = Node::new_branch(0, r1, r2, &mut Untracked);
        let root: *mut Branch<usize, usize> =
            Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.path_clone(&20);
        wcurs.path_clone(&30);

        wcurs.remove(&0);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_12() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - full
        //   rbranch - 2node
        //   txn     - touch lbranch
        //
        //   when remove from rbranch, borrow from lbranch
        //   will NOT reduce height
        let lbranch = create_branch_node_full(0);

        let r1 = create_leaf_node(80);
        let r2 = create_leaf_node(90);
        let rbranch = Node::new_branch(0, r1, r2, &mut Untracked);

        let root = Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        // let count = BV_CAPACITY + 2;
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.path_clone(&0);
        wcurs.path_clone(&10);
        wcurs.path_clone(&20);

        wcurs.remove(&90);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_13() {
        // Given the tree:
        //
        //          root
        //        /      \
        //   lbranch     rbranch
        //     /    \     /    \
        //    l1    l2   r1    r2
        //
        //   conditions:
        //   lbranch - 2node
        //   rbranch - full
        //   txn     - touch rbranch
        //
        //   when remove from lbranch, borrow from rbranch
        //   will NOT reduce height
        let l1 = create_leaf_node(0);
        let l2 = create_leaf_node(10);
        let lbranch = Node::new_branch(0, l1, l2, &mut Untracked);

        let rbranch = create_branch_node_full(100);

        let root = Node::new_branch(0, lbranch as *mut _, rbranch as *mut _, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        for i in 0..BV_CAPACITY {
            let k = 100 + (10 * i);
            wcurs.path_clone(&k);
        }
        assert!(wcurs.verify());

        wcurs.remove(&10);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_14() {
        // Test leaf borrow left
        let lnode = create_leaf_node_full(10);
        let rnode = create_leaf_node(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.remove(&20);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_15() {
        // Test leaf borrow right.
        let lnode = create_leaf_node(10);
        let rnode = create_leaf_node_full(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let sb = SuperBlock::new_test(1, root as *mut Node<usize, usize>);
        let mut wcurs = sb.create_writer(());
        assert!(wcurs.verify());

        wcurs.remove(&10);

        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    fn tree_create_rand() -> (SuperBlock<usize, usize>, CursorRead<usize, usize>) {
        let mut rng = rand::rng();
        let mut ins: Vec<usize> = (1..(L_CAPACITY << 4)).collect();
        ins.shuffle(&mut rng);

        let mut sb = unsafe { SuperBlock::new() };
        let rdr = sb.create_reader();
        let mut wcurs = sb.create_writer(());

        for v in ins.into_iter() {
            let r = wcurs.insert(v, v);
            assert!(r.is_none());
            assert!(wcurs.verify());
        }
        let rdr = sb.pre_commit(wcurs, &rdr);
        (sb, rdr)
    }

    #[test]
    fn test_bptree2_cursor_remove_stress_1() {
        // Insert ascending - we want to ensure the tree is a few levels deep
        // so we do this to a reasonable number.
        let (mut sb, rdr) = tree_create_rand();
        let mut wcurs = sb.create_writer(());

        for v in 1..(L_CAPACITY << 4) {
            // println!("-- ITER v {}", v);
            let r = wcurs.remove(&v);
            assert!(r == Some(v));
            assert!(wcurs.verify());
        }
        // println!("{:?}", wcurs);
        let rdr2 = sb.pre_commit(wcurs, &rdr);
        // On shutdown, check we dropped all as needed.
        std::mem::drop(rdr2);
        std::mem::drop(rdr);
        std::mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_stress_2() {
        // Insert descending
        let (mut sb, rdr) = tree_create_rand();
        let mut wcurs = sb.create_writer(());

        for v in (1..(L_CAPACITY << 4)).rev() {
            // println!("ITER v {}", v);
            let r = wcurs.remove(&v);
            assert!(r == Some(v));
            assert!(wcurs.verify());
        }
        let rdr2 = sb.pre_commit(wcurs, &rdr);
        std::mem::drop(rdr2);
        std::mem::drop(rdr);
        std::mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_stress_3() {
        // Insert random
        let mut rng = rand::rng();
        let mut ins: Vec<usize> = (1..(L_CAPACITY << 4)).collect();
        ins.shuffle(&mut rng);

        let (mut sb, rdr) = tree_create_rand();
        let mut wcurs = sb.create_writer(());

        for v in ins.into_iter() {
            let r = wcurs.remove(&v);
            assert!(r == Some(v));
            assert!(wcurs.verify());
        }
        let rdr2 = sb.pre_commit(wcurs, &rdr);
        std::mem::drop(rdr2);
        std::mem::drop(rdr);
        std::mem::drop(sb);
        assert_released();
    }

    // Add transaction-ised versions.
    #[test]
    fn test_bptree2_cursor_remove_stress_4() {
        // Insert ascending - we want to ensure the tree is a few levels deep
        // so we do this to a reasonable number.
        let (mut sb, mut rdr) = tree_create_rand();

        for v in 1..(L_CAPACITY << 4) {
            let mut wcurs = sb.create_writer(());
            // println!("ITER v {}", v);
            let r = wcurs.remove(&v);
            assert!(r == Some(v));
            assert!(wcurs.verify());
            rdr = sb.pre_commit(wcurs, &rdr);
        }
        std::mem::drop(rdr);
        std::mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_stress_5() {
        // Insert descending
        let (mut sb, mut rdr) = tree_create_rand();

        for v in (1..(L_CAPACITY << 4)).rev() {
            let mut wcurs = sb.create_writer(());
            // println!("ITER v {}", v);
            let r = wcurs.remove(&v);
            assert!(r == Some(v));
            assert!(wcurs.verify());
            rdr = sb.pre_commit(wcurs, &rdr);
        }
        std::mem::drop(rdr);
        std::mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_remove_stress_6() {
        // Insert random
        let mut rng = rand::rng();
        let mut ins: Vec<usize> = (1..(L_CAPACITY << 4)).collect();
        ins.shuffle(&mut rng);

        let (mut sb, mut rdr) = tree_create_rand();

        for v in ins.into_iter() {
            let mut wcurs = sb.create_writer(());
            let r = wcurs.remove(&v);
            assert!(r == Some(v));
            assert!(wcurs.verify());
            rdr = sb.pre_commit(wcurs, &rdr);
        }
        std::mem::drop(rdr);
        std::mem::drop(sb);
        assert_released();
    }

    /*
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_bptree2_cursor_remove_stress_7() {
        // Insert random
        let mut rng = rand::rng();
        let mut ins: Vec<usize> = (1..10240).collect();

        let node: *mut Leaf<usize, usize> = Node::new_leaf(0, &mut Untracked);
        let mut wcurs = CursorWrite::new_test(1, node as *mut _);
        wcurs.extend(ins.iter().map(|v| (*v, *v)));

        ins.shuffle(&mut rng);

        let compacts = 0;

        for v in ins.into_iter() {
            let r = wcurs.remove(&v);
            assert!(r == Some(v));
            assert!(wcurs.verify());
            // let (l, m) = wcurs.tree_density();
            // if l > 0 && (m / l) > 1 {
            //     compacts += 1;
            // }
        }
        println!("compacts {:?}", compacts);
    }
    */

    // This is for setting up trees that are specialised for the split off tests.
    // This is because we can exercise a LOT of complex edge cases by bracketing
    // within this tree. It also works on both node sizes.
    //
    // This is a 16 node tree, with 4 branches and a root. We have 2 values per leaf to
    // allow some cases to be explored. We also need "gaps" between the values to allow other
    // cases.
    //
    // Effectively this means we can test by splitoff on the values:
    // for i in [0,100,200,300]:
    //     for j in [0, 10, 20, 30]:
    //         t1 = i + j
    //         t2 = i + j + 1
    //         t3 = i + j + 2
    //         t4 = i + j + 3
    //
    #[cfg(not(feature = "skinny"))]
    fn create_split_off_leaf(base: usize) -> *mut Node<usize, usize> {
        let l = Node::new_leaf(0, &mut Untracked);
        let lref = leaf_ref!(l, usize, usize, Untracked);
        lref.insert_or_update(base + 1, base + 1, &mut Untracked);
        lref.insert_or_update(base + 2, base + 2, &mut Untracked);
        l as *mut _
    }

    #[cfg(not(feature = "skinny"))]
    fn create_split_off_branch(base: usize) -> *mut Node<usize, usize> {
        // This is a helper for create_split_off_tree to make the sub-branches based
        // on a base.
        let l1 = create_split_off_leaf(base);
        let l2 = create_split_off_leaf(base + 10);
        let l3 = create_split_off_leaf(base + 20);
        let l4 = create_split_off_leaf(base + 30);

        let branch = Node::new_branch(0, l1, l2, &mut Untracked);
        let nref = branch_ref!(branch, usize, usize, Untracked);
        nref.add_node(l3, &mut Untracked);
        nref.add_node(l4, &mut Untracked);

        branch as *mut _
    }

    #[cfg(not(feature = "skinny"))]
    fn create_split_off_tree() -> *mut Node<usize, usize> {
        let b1 = create_split_off_branch(0);
        let b2 = create_split_off_branch(100);
        let b3 = create_split_off_branch(200);
        let b4 = create_split_off_branch(300);
        let root = Node::new_branch(0, b1, b2, &mut Untracked);
        let nref = branch_ref!(root, usize, usize, Untracked);
        nref.add_node(b3, &mut Untracked);
        nref.add_node(b4, &mut Untracked);

        root as *mut _
    }

    #[test]
    fn test_bptree2_cursor_split_off_lt_01() {
        // Make a tree with just a leaf
        // Do a split_off_lt.
        let node = create_leaf_node(0);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        wcurs.split_off_lt(&5);

        // Remember, all the cases of the remove_lte are already tested on
        // leaf.
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_split_off_lt_02() {
        // Make a tree with just a leaf
        // Do a split_off_lt.
        let node = create_leaf_node_full(10);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        wcurs.split_off_lt(&11);

        // Remember, all the cases of the remove_lte are already tested on
        // leaf.
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[test]
    fn test_bptree2_cursor_split_off_lt_03() {
        // Make a tree with just a leaf
        // Do a split_off_lt.
        let node = create_leaf_node_full(10);
        let sb = SuperBlock::new_test(1, node);
        let mut wcurs = sb.create_writer(());

        wcurs.path_clone(&11);
        wcurs.split_off_lt(&11);

        // Remember, all the cases of the remove_lte are already tested on
        // leaf.
        assert!(wcurs.verify());
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[cfg(not(feature = "skinny"))]
    fn run_split_off_test_clone(v: usize, _exp: usize) {
        // println!("RUNNING -> {:?}", v);
        let tree = create_split_off_tree();

        let sb = SuperBlock::new_test(1, tree);
        let mut wcurs = sb.create_writer(());
        // 0 is min, and not present, will cause no change.
        // clone everything
        let outer: [usize; 4] = [0, 100, 200, 300];
        let inner: [usize; 4] = [0, 10, 20, 30];
        for i in outer.iter() {
            for j in inner.iter() {
                wcurs.path_clone(&(i + j + 1));
            }
        }

        wcurs.split_off_lt(&v);
        assert!(wcurs.verify());
        if v > 0 {
            assert!(!wcurs.contains_key(&(v - 1)));
        }
        // assert!(wcurs.len() == exp);

        // println!("{:?}", wcurs);
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[cfg(not(feature = "skinny"))]
    fn run_split_off_test(v: usize, _exp: usize) {
        // println!("RUNNING -> {:?}", v);
        let tree = create_split_off_tree();
        // println!("START -> {:?}", tree);

        let sb = SuperBlock::new_test(1, tree);
        let mut wcurs = sb.create_writer(());
        // 0 is min, and not present, will cause no change.
        wcurs.split_off_lt(&v);
        assert!(wcurs.verify());
        if v > 0 {
            assert!(!wcurs.contains_key(&(v - 1)));
        }
        // assert!(wcurs.len() == exp);

        // println!("{:?}", wcurs);
        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    #[cfg(not(feature = "skinny"))]
    #[test]
    fn test_bptree2_cursor_split_off_lt_clone_stress() {
        // Can't proceed as the "fake" tree we make is invalid.
        let outer: [usize; 4] = [0, 100, 200, 300];
        let inner: [usize; 4] = [0, 10, 20, 30];
        for i in outer.iter() {
            for j in inner.iter() {
                run_split_off_test_clone(i + j, 32);
                run_split_off_test_clone(i + j + 1, 32);
                run_split_off_test_clone(i + j + 2, 32);
                run_split_off_test_clone(i + j + 3, 32);
            }
        }
    }

    #[cfg(not(feature = "skinny"))]
    #[test]
    fn test_bptree2_cursor_split_off_lt_stress() {
        let outer: [usize; 4] = [0, 100, 200, 300];
        let inner: [usize; 4] = [0, 10, 20, 30];
        for i in outer.iter() {
            for j in inner.iter() {
                run_split_off_test(i + j, 32);
                run_split_off_test(i + j + 1, 32);
                run_split_off_test(i + j + 2, 32);
                run_split_off_test(i + j + 3, 32);
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_bptree2_cursor_split_off_lt_random_stress() {
        let data: Vec<isize> = (0..1024).collect();

        for v in data.iter() {
            let node: *mut Leaf<isize, isize> = Node::new_leaf(0, &mut Untracked) as *mut _;
            let sb = SuperBlock::new_test(1, node as *mut Node<isize, isize>);
            let mut wcurs = sb.create_writer(());
            wcurs.extend(data.iter().map(|v| (*v, *v)));

            if v > &0 {
                assert!(wcurs.contains_key(&(v - 1)));
            }

            wcurs.split_off_lt(v);
            assert!(!wcurs.contains_key(&(v - 1)));
            if v < &1024 {
                assert!(wcurs.contains_key(v));
            }
            assert!(wcurs.verify());
            let contents: Vec<_> = wcurs.k_iter().collect();
            assert!(contents[0] == v);
            assert!(contents.len() as isize == (1024 - v));
        }
    }

    #[test]
    fn test_bptree_cursor_double_extend() {
        let node: *mut Leaf<isize, isize> = Node::new_leaf(0, &mut Untracked) as *mut _;
        let sb = SuperBlock::new_test(1, node as *mut Node<isize, isize>);
        let mut wcurs = sb.create_writer(());

        wcurs.extend([(0, 0), (1, 1), (2, 2), (3, 3)]);
        assert!(wcurs.len() == 4);
        assert!(wcurs.verify());

        wcurs.extend([(2, 2), (3, 3), (4, 4), (5, 5)]);
        assert!(wcurs.len() == 6);
        assert!(wcurs.verify());

        mem::drop(wcurs);
        mem::drop(sb);
        assert_released();
    }

    /*
    #[test]
    fn test_bptree_cursor_get_mut_ref_1() {
        // Test that we can clone a path (new txn)
        // Test that we don't re-clone.
        let lnode = create_leaf_node_full(10);
        let rnode = create_leaf_node_full(20);
        let root = Node::new_branch(0, lnode, rnode, &mut Untracked);
        let mut wcurs = CursorWrite::new(root, 0);
        assert!(wcurs.verify());

        let r1 = wcurs.get_mut_ref(&10);
        std::mem::drop(r1);
        let r1 = wcurs.get_mut_ref(&10);
        std::mem::drop(r1);
    }
    */
}

#[cfg(all(test, not(feature = "dhat-heap"), not(miri)))]
#[path = "cursor_allocation_tests.rs"]
mod allocation_tests;
