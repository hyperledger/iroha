//! CPU register file: 256 general-purpose registers with optional privacy tags.
//!
//! The register file implements the full set of helpers required by the
//! specification, including lane-level accessors for vector registers.
//!
//! The original implementation exposed only 32 general purpose registers and a
//! separate set of vector registers.  The updated architecture requires a much
//! larger register file (256 entries) and associates a 1‑bit privacy tag with
//! each register when zero–knowledge mode is active.  Vector operations no
//! longer use a dedicated register file – instead groups of the general
//! registers are interpreted as vectors.  This module implements that design.
use crate::zk::{RegEvent, record_register_event};
use crate::{VMError, error::ExecutionDeferral, parallel::REGISTER_COUNT};
use iroha_allocation::{AllocationBudget, AllocationCharge};
use iroha_crypto::{CompactMerkleProof, Hash, HashOf, MerkleProof, MerkleTree};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::{
    alloc::Layout,
    sync::atomic::{AtomicBool, Ordering},
};
mod fixed_path;
pub use fixed_path::REGISTER_MERKLE_PATH_DEPTH;
pub struct Registers {
    /// 256 general purpose 64-bit registers. `r0` is hardwired to zero.
    gpr: [u64; 256],
    /// Privacy tags associated with each register. `false` denotes public data
    /// and `true` denotes private (secret) data.
    tags: [bool; 256],
    /// Merkle tree commitment to the register contents and tags (canonical type).
    tree: Mutex<crate::cache_memory::FixedAllocationValue<MerkleTree<[u8; 32]>>>,
    // Drop the node allocation above before refunding its original active charge.
    _tree_charge: Option<AllocationCharge>,
    /// Dirty flag to defer rebuilds until root/path are requested.
    dirty: AtomicBool,
}
impl Drop for Registers {
    fn drop(&mut self) {
        // Inline values belong to this file alone, even inside a shared outer
        // runtime template. No borrowed baseline is erased before final drop.
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.gpr);
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.tags);
    }
}

#[cfg(test)]
mod private_disposal_tests;

impl Clone for Registers {
    fn clone(&self) -> Self {
        let gpr = self.gpr;
        let tags = self.tags;
        let tree = if self.dirty.load(Ordering::Acquire) {
            crate::cache_memory::FixedAllocationValue::new(
                MerkleTree::from_hashed_leaves_sha256(register_leaf_digests(&gpr, &tags)),
                MerkleTree::allocated_bytes,
            )
        } else {
            self.tree.lock().clone()
        };
        Registers {
            gpr,
            tags,
            tree: Mutex::new(tree),
            _tree_charge: None,
            dirty: AtomicBool::new(false),
        }
    }
}
impl Registers {
    #[cfg(test)]
    pub(crate) fn disposal_spans_for_testing(&self) -> [(*const u8, usize); 2] {
        [
            (self.gpr.as_ptr().cast(), std::mem::size_of_val(&self.gpr)),
            (self.tags.as_ptr().cast(), std::mem::size_of_val(&self.tags)),
        ]
    }

    /// Conservatively cover the exact node clone request, including spare source capacity.
    pub(crate) fn runtime_template_memory_plan(
        &self,
    ) -> Result<crate::execution_memory::ExecutionMemoryPlan, VMError> {
        crate::execution_memory::ExecutionMemoryPlan::array::<u8>(
            self.tree.lock().allocated_bytes(),
        )
        .map_err(VMError::AllocationDeferred)
    }

    /// Copy the register file for a reusable runtime baseline with a fallible
    /// Merkle-node allocation. Dirty state stays dirty until its next root read.
    pub(crate) fn try_clone_for_runtime_template(&self) -> Result<Self, VMError> {
        let tree = self.tree.lock();
        let reservation = crate::cache_memory::MemoryReservation::active(tree.allocated_bytes());
        let copied_tree = tree
            .try_clone_allocation()
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable))?;
        Ok(Self {
            gpr: self.gpr,
            tags: self.tags,
            tree: Mutex::new(
                crate::cache_memory::FixedAllocationValue::from_pre_reserved(
                    copied_tree,
                    reservation,
                    MerkleTree::allocated_bytes,
                ),
            ),
            _tree_charge: None,
            dirty: AtomicBool::new(self.dirty.load(Ordering::Acquire)),
        })
    }

    pub(crate) fn try_retain(&self) -> bool {
        self.tree.lock().try_retain()
    }
    pub(crate) fn make_active(&self) {
        self.tree.lock().make_active();
    }
    #[inline]
    pub fn new() -> Self {
        Self::try_new().expect("register Merkle allocation requires local memory")
    }
    /// Construct the register file with its Merkle node charge reserved before allocation.
    ///
    /// # Errors
    /// Returns a local allocation deferral if the canonical register tree
    /// cannot be reserved. No guest gas or transaction validity is changed.
    #[inline]
    pub fn try_new() -> Result<Self, VMError> {
        Self::try_new_with_charge(None)
    }

    /// Prepay the complete initial Merkle-node backing from an active VM pool.
    /// The charge follows this register owner through resets and idle borrowing.
    pub(crate) fn try_new_with_memory_budget(budget: &AllocationBudget) -> Result<Self, VMError> {
        let layout = Self::initial_tree_layout()?;
        let mut reservation = budget
            .try_reserve(layout)
            .map_err(VMError::AllocationDeferred)?;
        let charge = reservation
            .try_split(layout)
            .expect("the original exact layout is prepaid");
        Self::try_new_with_charge(Some(charge))
    }

    pub(crate) fn initial_tree_allocation_bytes() -> Result<usize, VMError> {
        Self::initial_tree_layout().map(|layout| layout.size())
    }

    fn initial_tree_layout() -> Result<Layout, VMError> {
        let unavailable = || VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable);
        let bytes = MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(256)
            .map_err(|_| unavailable())?;
        Layout::from_size_align(bytes, std::mem::align_of::<Option<HashOf<[u8; 32]>>>())
            .map_err(|_| unavailable())
    }

    fn try_new_with_charge(tree_charge: Option<AllocationCharge>) -> Result<Self, VMError> {
        let gpr = [0u64; 256];
        let tags = [false; 256];
        let zero_leaf: [u8; 32] = {
            let b = [0u8; 9];
            Sha256::digest(b).into()
        };
        let unavailable = || VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable);
        let requested = Self::initial_tree_allocation_bytes()?;
        let reservation = crate::cache_memory::MemoryReservation::active(requested);
        let tree = crate::cache_memory::FixedAllocationValue::from_pre_reserved(
            MerkleTree::try_from_repeated_hashed_leaf_sha256(256, zero_leaf)
                .map_err(|_| unavailable())?,
            reservation,
            MerkleTree::allocated_bytes,
        );
        Ok(Registers {
            gpr,
            tags,
            tree: Mutex::new(tree),
            _tree_charge: tree_charge,
            dirty: AtomicBool::new(false),
        })
    }

    /// Restore zero registers while retaining the existing Merkle backing and charge.
    ///
    /// The retained nodes are rewritten lazily: the next root or path read
    /// rebuilds them from these values, so a reset nobody reads hashes nothing.
    pub(crate) fn reset_to_zero(&mut self) {
        self.gpr = [0; 256];
        self.tags = [false; 256];
        *self.dirty.get_mut() = true;
    }

    /// Restore a runtime baseline without replacing the worker's Merkle backing.
    ///
    /// Like [`Self::reset_to_zero`], the retained nodes are rebuilt only when a
    /// root or path is next read, yielding the template's canonical root.
    pub(crate) fn restore_from_template(&mut self, template: &Self) {
        self.gpr = template.gpr;
        self.tags = template.tags;
        *self.dirty.get_mut() = true;
    }
    /// Get the value of register `idx`.
    #[inline]
    pub fn get(&self, idx: usize) -> u64 {
        debug_assert!(idx < 256);
        let val = self.gpr[idx];
        record_register_event(|| {
            let (root, path) = self
                .merkle_root_and_path(idx)
                .expect("register access already validated the index");
            RegEvent::Read {
                index: idx,
                value: val,
                tag: self.tags[idx],
                path,
                root,
            }
        });
        val
    }
    /// Set the value of register `idx`. Writes to x0 are ignored (x0 is always 0).
    #[inline]
    pub fn set(&mut self, idx: usize, value: u64) {
        debug_assert!(idx < 256);
        if idx != 0 {
            self.gpr[idx] = value;
            // Exclusive access needs no atomic read-modify-write.
            let was_dirty = std::mem::replace(self.dirty.get_mut(), true);
            record_register_event(|| {
                if !was_dirty {
                    self.tree.get_mut().update_hashed_leaf_sha256(
                        idx,
                        register_leaf_digest(value, self.tags[idx]),
                    );
                    *self.dirty.get_mut() = false;
                }
                let (root, path) = self
                    .merkle_root_and_path(idx)
                    .expect("register access already validated the index");
                RegEvent::Write {
                    index: idx,
                    value,
                    tag: self.tags[idx],
                    path,
                    root,
                }
            });
        }
    }
    /// Get the privacy tag of register `idx`.
    #[inline]
    pub fn tag(&self, idx: usize) -> bool {
        debug_assert!(idx < 256);
        self.tags[idx]
    }
    /// Set the privacy tag of register `idx`. Writing to `r0` has no effect.
    #[inline]
    pub fn set_tag(&mut self, idx: usize, value: bool) {
        debug_assert!(idx < 256);
        if idx != 0 {
            self.tags[idx] = value;
            let was_dirty = std::mem::replace(self.dirty.get_mut(), true);
            record_register_event(|| {
                if !was_dirty {
                    self.tree
                        .get_mut()
                        .update_hashed_leaf_sha256(idx, register_leaf_digest(self.gpr[idx], value));
                    *self.dirty.get_mut() = false;
                }
                let (root, path) = self
                    .merkle_root_and_path(idx)
                    .expect("register access already validated the index");
                RegEvent::Write {
                    index: idx,
                    value: self.gpr[idx],
                    tag: value,
                    path,
                    root,
                }
            });
        }
    }
    /// Record a proof-bearing write for the current value of `idx` without
    /// mutating the register file.
    ///
    /// Host callbacks execute with register logging masked so unrelated VMs
    /// cannot inject events. The caller uses this after the callback to publish
    /// only net changes to the VM that actually resumed execution.
    pub(crate) fn record_write_proof(&self, idx: usize) {
        debug_assert!(idx < 256);
        if idx == 0 {
            return;
        }
        record_register_event(|| {
            let (root, path) = self
                .merkle_root_and_path(idx)
                .expect("register access already validated the index");
            RegEvent::Write {
                index: idx,
                value: self.gpr[idx],
                tag: self.tags[idx],
                path,
                root,
            }
        });
    }
    /// Zero every private register before clearing its privacy tag.
    ///
    /// Public registers are preserved so hosts may preload ordinary arguments
    /// before replacing a program. Zeroing first prevents logs and Merkle
    /// leaves from ever representing a secret value as public.
    pub(crate) fn scrub_private(&mut self) {
        for index in 1..self.tags.len() {
            if self.tags[index] {
                iroha_crypto::zeroize_value_for_confidential_discard(&mut self.gpr[index]);
                self.tags[index] = false;
                *self.dirty.get_mut() = true;
            }
        }
    }
    /// Return whether any general-purpose register is private-tagged.
    pub(crate) fn has_private(&self) -> bool {
        self.tags.iter().any(|tag| *tag)
    }
    /// Return a copy of all general-purpose registers.
    #[inline]
    pub fn snapshot(&self) -> [u64; 256] {
        self.gpr
    }
    /// Return a copy of all privacy tags.
    #[inline]
    pub fn snapshot_tags(&self) -> [bool; 256] {
        self.tags
    }
    /// Return the Merkle root of the register file.
    #[inline]
    pub fn merkle_root(&self) -> HashOf<MerkleTree<[u8; 32]>> {
        self.ensure_built_and_lock()
            .root()
            .expect("tree has at least one leaf")
    }
    /// Build a compact Merkle proof for the register at `idx`.
    ///
    /// Without truncation the returned root is the full register-tree root.
    /// When `depth_cap` truncates the path, the returned root commits only to
    /// that path fragment and is not a membership commitment.
    ///
    /// # Errors
    /// Returns [`VMError::RegisterOutOfBounds`] when `idx` is not a register index.
    #[inline]
    pub fn merkle_compact(
        &self,
        idx: usize,
        depth_cap: Option<usize>,
    ) -> Result<(CompactMerkleProof<[u8; 32]>, HashOf<MerkleTree<[u8; 32]>>), VMError> {
        let leaf_index = register_leaf_index(idx)?;
        let (root, path) = self.merkle_root_and_path(idx)?;
        let proof = crate::merkle_utils::make_compact_from_path_bytes(&path, leaf_index, depth_cap);
        let leaf_digest = register_leaf_digest(self.gpr[idx], self.tags[idx]);
        let leaf_hash = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf_digest));
        let siblings = proof.siblings().to_vec();
        let merkle_proof = MerkleProof::from_audit_path(proof.dirs(), siblings);
        // A depth cap commits only to this path fragment. It is deliberately
        // not treated as membership in the fixed 256-leaf register tree.
        let adj_root = if usize::from(proof.depth()) < path.len() {
            merkle_proof
                .compute_partial_root_sha256(&leaf_hash, usize::from(proof.depth()))
                .expect("proof height equals compact depth")
        } else {
            root
        };
        Ok((proof, adj_root))
    }
    #[inline]
    fn ensure_built_and_lock(
        &self,
    ) -> parking_lot::MutexGuard<'_, crate::cache_memory::FixedAllocationValue<MerkleTree<[u8; 32]>>>
    {
        let mut tree = self.tree.lock();
        if self.dirty.load(Ordering::Acquire) {
            tree.rewrite_hashed_leaves_sha256(&register_leaf_digests(&self.gpr, &self.tags))
                .expect("register tree has fixed SHA-256 geometry");
            self.dirty.store(false, Ordering::Release);
        }
        tree
    }
}
impl Default for Registers {
    fn default() -> Self {
        Self::new()
    }
}
#[inline]
fn register_leaf_digest(value: u64, tag: bool) -> [u8; 32] {
    #[cfg(test)]
    REGISTER_LEAF_DIGEST_COUNT.with(|count| count.set(count.get() + 1));
    let mut bytes = [0u8; 9];
    bytes[0] = if tag { 1 } else { 0 };
    bytes[1..].copy_from_slice(&value.to_le_bytes());
    Sha256::digest(bytes).into()
}
#[inline]
fn register_leaf_index(idx: usize) -> Result<u32, VMError> {
    if idx >= REGISTER_COUNT {
        return Err(VMError::RegisterOutOfBounds);
    }
    u32::try_from(idx).map_err(|_| VMError::RegisterOutOfBounds)
}
fn register_leaf_digests(gpr: &[u64; 256], tags: &[bool; 256]) -> [[u8; 32]; 256] {
    std::array::from_fn(|index| register_leaf_digest(gpr[index], tags[index]))
}
#[cfg(test)]
thread_local! {
    static REGISTER_LEAF_DIGEST_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
fn reset_register_leaf_digest_count() {
    REGISTER_LEAF_DIGEST_COUNT.with(|count| count.set(0));
}
#[cfg(test)]
fn register_leaf_digest_count() -> usize {
    REGISTER_LEAF_DIGEST_COUNT.with(std::cell::Cell::get)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn funded_tree_charge_survives_rebuild_reset_and_template_restore() {
        let bytes = Registers::initial_tree_allocation_bytes().unwrap();
        let insufficient = AllocationBudget::new(bytes - 1);
        assert!(matches!(
            Registers::try_new_with_memory_budget(&insufficient),
            Err(VMError::AllocationDeferred(
                iroha_allocation::AllocationRefusal::ExceedsLimit { .. }
            ))
        ));
        assert_eq!(insufficient.reserved_bytes(), 0);

        let budget = AllocationBudget::new(bytes);
        let mut worker = Registers::try_new_with_memory_budget(&budget).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes);
        assert!(matches!(
            Registers::try_new_with_memory_budget(&budget),
            Err(VMError::AllocationDeferred(
                iroha_allocation::AllocationRefusal::Capacity { .. }
            ))
        ));
        worker.set(7, 81);
        worker.set_tag(7, true);
        let changed_root = worker.merkle_root();
        assert_eq!(budget.reserved_bytes(), bytes);

        let mut baseline = Registers::try_new().unwrap();
        baseline.set(31, 0x1000);
        baseline.set_tag(31, true);
        worker.restore_from_template(&baseline);
        assert_eq!(worker.snapshot(), baseline.snapshot());
        assert_eq!(worker.snapshot_tags(), baseline.snapshot_tags());
        assert_eq!(worker.merkle_root(), baseline.merkle_root());
        assert_ne!(worker.merkle_root(), changed_root);
        assert_eq!(budget.reserved_bytes(), bytes);
        worker.reset_to_zero();
        assert_eq!(
            worker.merkle_root(),
            Registers::try_new().unwrap().merkle_root()
        );
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(worker);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn fallible_runtime_template_register_copy_preserves_values_tags_and_root() {
        let mut source = Registers::try_new().expect("bounded register tree");
        source.set(7, 81);
        source.set_tag(7, true);
        let copied = source
            .try_clone_for_runtime_template()
            .expect("bounded register snapshot");
        assert_eq!(copied.snapshot(), source.snapshot());
        assert_eq!(copied.snapshot_tags(), source.snapshot_tags());
        assert_eq!(copied.merkle_root(), source.merkle_root());
    }

    #[test]
    fn fallible_initial_register_tree_matches_canonical_root_and_capacity() {
        let regs = Registers::try_new().expect("initial register allocation fits test host");
        let zero_leaf: [u8; 32] = Sha256::digest([0_u8; 9]).into();
        let canonical = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(vec![zero_leaf; 256]);
        let tree = regs.tree.lock();
        assert_eq!(tree.root(), canonical.root());
        assert_eq!(tree.allocated_bytes(), canonical.allocated_bytes());
        assert_eq!(tree.leaf_count(), 256);
    }

    #[test]
    fn private_scrub_zeros_tagged_registers_and_preserves_public_values() {
        let mut regs = Registers::new();
        regs.set(2, 0xfeed_face_dead_beef);
        regs.set_tag(2, true);
        regs.set(200, 0x0123_4567_89ab_cdef);
        regs.set_tag(200, true);
        regs.set(7, 0x55aa);

        regs.scrub_private();

        assert_eq!(regs.get(2), 0);
        assert!(!regs.tag(2));
        assert_eq!(regs.get(200), 0);
        assert!(!regs.tag(200));
        assert_eq!(regs.get(7), 0x55aa);
        assert!(!regs.tag(7));
        assert!(!regs.has_private());
    }
    #[test]
    fn private_owner_scrub_does_not_emit_register_proofs() {
        let mut regs = Registers::new();
        regs.set(2, 91);
        regs.set_tag(2, true);
        regs.set(7, 55);
        let log = crate::zk::SharedRegLog::try_new(None).expect("test logger allocation");
        let guard = crate::zk::RegLoggerGuard::install(Some(log.clone()));
        regs.scrub_private();
        assert!(log.lock().as_slice().is_empty());
        drop(guard);
        let mut expected = Registers::new();
        expected.set(7, 55);
        assert_eq!(regs.merkle_root(), expected.merkle_root());
    }

    #[test]
    fn register_writes_defer_merkle_hashing_until_the_root_is_read() {
        let mut regs = Registers::new();
        reset_register_leaf_digest_count();
        for value in 1..=1_000_u64 {
            let index = (value as usize % 255) + 1;
            regs.set(index, value);
            regs.set_tag(index, value.is_multiple_of(2));
        }
        assert_eq!(register_leaf_digest_count(), 0);

        let first_root = regs.merkle_root();
        assert_eq!(register_leaf_digest_count(), 256);
        assert_eq!(regs.merkle_root(), first_root);
        assert_eq!(register_leaf_digest_count(), 256);
    }
    #[test]
    fn cloning_reuses_a_clean_tree_and_rebuilds_a_dirty_tree_once() {
        let mut regs = Registers::new();
        reset_register_leaf_digest_count();
        let clean = regs.clone();
        assert_eq!(register_leaf_digest_count(), 0);
        assert_eq!(clean.merkle_root(), regs.merkle_root());

        regs.set(7, 42);
        let dirty = regs.clone();
        assert_eq!(register_leaf_digest_count(), 256);
        assert_eq!(dirty.merkle_root(), regs.merkle_root());
        assert_eq!(register_leaf_digest_count(), 512);
    }
    #[test]
    fn logged_writes_update_only_the_changed_merkle_leaf() {
        let mut regs = Registers::new();
        let log = crate::zk::SharedRegLog::try_new(None).expect("test logger allocation");
        reset_register_leaf_digest_count();
        let guard = crate::zk::RegLoggerGuard::install(Some(log.clone()));
        let batch = crate::zk::RegEventBatch::begin(2).unwrap();

        regs.set(7, 42);
        assert_eq!(register_leaf_digest_count(), 1);
        let after_set = canonical_root_and_path(&regs, 7);

        reset_register_leaf_digest_count();
        regs.set_tag(7, true);
        assert_eq!(register_leaf_digest_count(), 1);
        let after_tag = canonical_root_and_path(&regs, 7);
        drop(batch);
        drop(guard);

        let log = log.lock();
        assert_eq!(log.as_slice().len(), 2);
        assert_logged_event_matches(&log.as_slice()[0], &after_set);
        assert_logged_event_matches(&log.as_slice()[1], &after_tag);
        assert_eq!(regs.merkle_root(), after_tag.0);
    }
    #[test]
    fn lazy_reset_and_template_restore_hash_nothing_until_a_root_is_read() {
        let mut template = Registers::new();
        template.set(9, 0x99);
        template.set_tag(9, true);
        let template_root = template.merkle_root();
        let zero_root = Registers::new().merkle_root();
        let mut worker = Registers::new();
        worker.set(3, 7);
        assert_ne!(worker.merkle_root(), zero_root);

        reset_register_leaf_digest_count();
        worker.reset_to_zero();
        worker.restore_from_template(&template);
        assert_eq!(register_leaf_digest_count(), 0);
        assert_eq!(worker.snapshot(), template.snapshot());
        assert_eq!(worker.snapshot_tags(), template.snapshot_tags());
        assert_eq!(worker.merkle_root(), template_root);
        assert_eq!(register_leaf_digest_count(), 256);

        worker.reset_to_zero();
        assert_eq!(register_leaf_digest_count(), 256);
        assert_eq!(worker.merkle_root(), zero_root);
        let (root, path) = worker.merkle_root_and_path(9).unwrap();
        let canonical = canonical_root_and_path(&worker, 9);
        assert_eq!(root, canonical.0);
        assert_eq!(path.as_slice(), canonical.1.as_slice());
    }

    #[test]
    fn logged_writes_after_a_lazy_restore_report_canonical_roots_and_paths() {
        let mut template = Registers::new();
        template.set(4, 44);
        let mut regs = Registers::new();
        regs.set(5, 55);
        let _ = regs.merkle_root();
        regs.restore_from_template(&template);
        let log = crate::zk::SharedRegLog::try_new(None).expect("test logger allocation");
        let guard = crate::zk::RegLoggerGuard::install(Some(log.clone()));
        let batch = crate::zk::RegEventBatch::begin(2).unwrap();

        regs.set(7, 42);
        let after_set = canonical_root_and_path(&regs, 7);
        regs.set_tag(7, true);
        let after_tag = canonical_root_and_path(&regs, 7);
        drop(batch);
        drop(guard);

        let log = log.lock();
        assert_eq!(log.as_slice().len(), 2);
        assert_logged_event_matches(&log.as_slice()[0], &after_set);
        assert_logged_event_matches(&log.as_slice()[1], &after_tag);
        assert_eq!(regs.merkle_root(), after_tag.0);
    }

    #[test]
    fn merkle_proof_apis_reject_out_of_range_indices_without_aliasing() {
        let regs = Registers::new();

        assert!(regs.merkle_path(REGISTER_COUNT - 1).is_ok());
        assert!(regs.merkle_root_and_path(REGISTER_COUNT - 1).is_ok());
        assert!(regs.merkle_compact(REGISTER_COUNT - 1, None).is_ok());

        let mut invalid = vec![REGISTER_COUNT, usize::MAX];
        #[cfg(target_pointer_width = "64")]
        invalid.push((u64::from(u32::MAX) + 1) as usize);

        for idx in invalid {
            assert!(matches!(
                regs.merkle_path(idx),
                Err(VMError::RegisterOutOfBounds)
            ));
            assert!(matches!(
                regs.merkle_root_and_path(idx),
                Err(VMError::RegisterOutOfBounds)
            ));
            assert!(matches!(
                regs.merkle_compact(idx, None),
                Err(VMError::RegisterOutOfBounds)
            ));
            assert!(matches!(
                crate::merkle_utils::registers_compact_bundle(&regs, idx, None),
                Err(VMError::RegisterOutOfBounds)
            ));
        }
    }

    fn canonical_root_and_path(
        regs: &Registers,
        idx: usize,
    ) -> (HashOf<MerkleTree<[u8; 32]>>, Vec<[u8; 32]>) {
        let canonical =
            MerkleTree::from_hashed_leaves_sha256(register_leaf_digests(&regs.gpr, &regs.tags));
        let root = canonical.root().expect("non-empty register tree");
        let path = canonical
            .get_proof(idx as u32)
            .expect("valid register index")
            .into_audit_path()
            .into_iter()
            .map(|entry| entry.map(|hash| *hash.as_ref()).unwrap_or([0; 32]))
            .collect::<Vec<_>>();
        (root, path)
    }

    fn assert_logged_event_matches(
        event: &RegEvent,
        expected: &(HashOf<MerkleTree<[u8; 32]>>, Vec<[u8; 32]>),
    ) {
        let (logged_root, logged_path) = match event {
            RegEvent::Read { root, path, .. } | RegEvent::Write { root, path, .. } => (root, path),
        };

        assert_eq!(logged_root, &expected.0);
        assert_eq!(logged_path.as_slice(), expected.1.as_slice());
    }
}
