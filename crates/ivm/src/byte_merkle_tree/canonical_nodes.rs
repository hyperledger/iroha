//! One fixed canonical node array and its original execution/retention charges.

use crate::{
    VMError,
    cache_memory::{FixedAllocationValue, MemoryReservation},
    error::ExecutionDeferral,
    execution_memory::{ExecutionMemoryLease, ExecutionMemoryPlan},
};
use iroha_allocation::AllocationCharge;
use iroha_crypto::{HashOf, MerkleTree};
use std::{alloc::Layout, ops::Deref};

/// The backing is destroyed before either accounting owner is refunded.
pub(super) struct CanonicalNodes {
    tree: FixedAllocationValue<MerkleTree<[u8; 32]>>,
    _execution_charge: Option<AllocationCharge>,
    stale: bool,
}

impl CanonicalNodes {
    fn layout(leaves: usize) -> Result<Layout, VMError> {
        let bytes = MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(leaves)
            .map_err(|_| unavailable())?;
        Layout::from_size_align(bytes, std::mem::align_of::<Option<HashOf<[u8; 32]>>>())
            .map_err(|_| unavailable())
    }

    pub(super) fn memory_plan(leaves: usize) -> Result<ExecutionMemoryPlan, VMError> {
        let mut plan = ExecutionMemoryPlan::default();
        plan.include(Self::layout(leaves)?)
            .map_err(VMError::AllocationDeferred)?;
        Ok(plan)
    }

    pub(super) fn new(
        leaves: usize,
        zero_hash: [u8; 32],
        lease: Option<&mut ExecutionMemoryLease>,
    ) -> Result<Self, VMError> {
        Self::with_tree(leaves, lease, || {
            MerkleTree::try_from_repeated_hashed_leaf_sha256(leaves, zero_hash)
        })
    }
    pub(super) fn from_leaves(
        leaves: &[[u8; 32]],
        lease: Option<&mut ExecutionMemoryLease>,
    ) -> Result<Self, VMError> {
        Self::with_tree(leaves.len(), lease, || {
            MerkleTree::try_from_hashed_leaves_sha256(leaves)
        })
    }
    fn with_tree(
        leaves: usize,
        lease: Option<&mut ExecutionMemoryLease>,
        build: impl FnOnce() -> Result<MerkleTree<[u8; 32]>, iroha_crypto::MerkleError>,
    ) -> Result<Self, VMError> {
        let layout = Self::layout(leaves)?;
        let charge = lease
            .map(|lease| lease.split_allocation(layout).map_err(|_| unavailable()))
            .transpose()?;
        let reservation = MemoryReservation::active(layout.size());
        #[cfg(test)]
        if REFUSE_NEXT_ALLOCATION.with(|flag| flag.replace(false)) {
            return Err(unavailable());
        }
        let tree = build().map_err(|_| unavailable())?;
        // The canonical constructor makes the exact checked Vec request. Do not
        // publish an owner whose backing would exceed its original admission.
        if tree.allocated_bytes() != layout.size() {
            return Err(unavailable());
        }
        #[cfg(test)]
        ALLOCATIONS.set(ALLOCATIONS.get() + 1);
        Ok(Self {
            tree: FixedAllocationValue::from_pre_reserved(
                tree,
                reservation,
                MerkleTree::allocated_bytes,
            ),
            _execution_charge: charge,
            stale: false,
        })
    }

    pub(super) fn update_leaf_digest(&mut self, index: usize, digest: [u8; 32]) {
        assert!(
            self.is_current(),
            "incremental updates require current canonical nodes"
        );
        assert!(
            index < self.tree.leaf_count(),
            "canonical leaf index must be prevalidated"
        );
        self.tree.update_hashed_leaf_sha256(index, digest);
    }

    /// Install every leaf marked in `marked_words` and rehash each affected
    /// parent once per level, bit-identical to one path update per leaf.
    pub(super) fn update_marked_leaf_digests(&mut self, leaves: &[[u8; 32]], marked_words: &[u64]) {
        assert!(
            self.is_current(),
            "incremental updates require current canonical nodes"
        );
        self.tree
            .update_marked_hashed_leaves_sha256(leaves, marked_words)
            .expect("fixed canonical nodes and leaves have the same SHA-256 geometry");
    }

    pub(super) fn mark_stale(&mut self) {
        self.stale = true;
    }
    pub(super) fn is_current(&self) -> bool {
        !self.stale
    }
    pub(super) fn refresh(&mut self, leaves: &[[u8; 32]]) -> bool {
        if !self.stale {
            return false;
        }
        self.tree
            .rewrite_hashed_leaves_sha256(leaves)
            .expect("fixed canonical nodes and leaves have the same SHA-256 geometry");
        self.stale = false;
        true
    }
    pub(super) fn try_retain(&self) -> bool {
        self.tree.try_retain()
    }
    pub(super) fn make_active(&self) {
        self.tree.make_active();
    }
}
impl Deref for CanonicalNodes {
    type Target = MerkleTree<[u8; 32]>;
    fn deref(&self) -> &Self::Target {
        &self.tree
    }
}
fn unavailable() -> VMError {
    VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
}
#[cfg(test)]
thread_local! {
    pub(super) static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static REFUSE_NEXT_ALLOCATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
