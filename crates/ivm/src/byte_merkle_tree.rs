//! Canonical byte-chunk Merkle commitments with fixed leaf ownership.

#[cfg(any(target_os = "macos", feature = "cuda", test))]
mod acceleration_policy;
mod canonical_nodes;
mod cpu_leaves;
mod rehash;
#[cfg(any(target_os = "macos", feature = "cuda"))]
use acceleration_policy::ResolvedMerklePolicy;
use canonical_nodes::CanonicalNodes;

use crate::VMError;
use crate::execution_memory::{ExecutionBuffer, ExecutionMemoryLease, ExecutionMemoryPlan};
use iroha_crypto::{HashOf, MerkleProof, MerkleTree};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::ops::{Deref, DerefMut};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

/// One fixed leaf backing. Cold nested VMs keep their prepaid execution charge
/// attached to these digests through idle retention and cache eviction.
enum MerkleLeaves {
    Local(crate::cache_memory::OwnedAllocation<[u8; 32]>),
    Funded(ExecutionBuffer<[u8; 32]>),
}

impl From<crate::cache_memory::OwnedAllocation<[u8; 32]>> for MerkleLeaves {
    fn from(leaves: crate::cache_memory::OwnedAllocation<[u8; 32]>) -> Self {
        Self::Local(leaves)
    }
}

impl Deref for MerkleLeaves {
    type Target = [[u8; 32]];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Local(leaves) => leaves,
            Self::Funded(leaves) => leaves.as_slice(),
        }
    }
}

impl DerefMut for MerkleLeaves {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Local(leaves) => leaves,
            Self::Funded(leaves) => leaves.as_mut_slice(),
        }
    }
}

impl MerkleLeaves {
    #[cfg(any(feature = "cuda", test))]
    fn replace_equal_length(&mut self, digests: &[[u8; 32]]) -> bool {
        if self.len() != digests.len() {
            return false;
        }
        self.copy_from_slice(digests);
        true
    }

    fn try_retain(&self) -> bool {
        match self {
            Self::Local(leaves) => leaves.try_retain(),
            Self::Funded(leaves) => leaves.try_retain(),
        }
    }

    fn make_active(&self) {
        match self {
            Self::Local(leaves) => leaves.make_active(),
            Self::Funded(leaves) => leaves.activate(),
        }
    }
}
/// Merkle tree over fixed-size byte chunks, implemented as a thin adaptor over
/// the canonical `iroha_crypto::MerkleTree<[u8;32]>`.
///
/// - Leaves are SHA-256 of `chunk` bytes, with the final chunk zero-padded to
///   `chunk` length. Empty input yields the hash of `chunk` zero bytes.
/// - Inner nodes are SHA-256(left||right) with left-promotion when right is
///   absent.
/// - Canonical node storage is allocated once with the leaves. Updates reuse
///   its fixed geometry for incremental paths or a complete in-place rebuild.
pub struct ByteMerkleTree {
    chunk: usize,
    zero_hash: [u8; 32],
    leaves: Mutex<MerkleLeaves>,
    nodes: Mutex<CanonicalNodes>,
}
// Test-only observation counters; production exposes the same events via telemetry.
#[cfg(test)]
static MERKLE_REBUILDS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static MERKLE_INCREMENTAL_LEAF_UPDATES: AtomicU64 = AtomicU64::new(0);
/// Return cumulative completed canonical-node refreshes and incremental leaf updates.
/// Initial construction and independent template copies do not increment these counters.
#[cfg(test)]
pub fn merkle_update_counters() -> (u64, u64) {
    (
        MERKLE_REBUILDS.load(Ordering::Relaxed),
        MERKLE_INCREMENTAL_LEAF_UPDATES.load(Ordering::Relaxed),
    )
}
impl ByteMerkleTree {
    /// Fixed independent leaf and canonical-node backing demand.
    pub(crate) fn memory_plan(leaf_count: usize) -> Result<ExecutionMemoryPlan, VMError> {
        let leaf_count = leaf_count.max(1);
        let mut plan = ExecutionMemoryPlan::array::<[u8; 32]>(leaf_count)
            .map_err(VMError::AllocationDeferred)?;
        plan.include_child(CanonicalNodes::memory_plan(leaf_count)?)
            .map_err(VMError::AllocationDeferred)?;
        Ok(plan)
    }

    pub(crate) fn runtime_template_memory_plan(&self) -> Result<ExecutionMemoryPlan, VMError> {
        Self::memory_plan(self.leaf_count())
    }

    /// Copy leaves and canonical nodes from original prepaid credit when supplied.
    pub(crate) fn try_clone_for_runtime_template(
        &self,
        mut lease: Option<&mut ExecutionMemoryLease>,
    ) -> Result<Self, VMError> {
        let unavailable =
            || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
        // The same node-then-leaf lock order protects complete snapshots.
        let _nodes = self.nodes.lock();
        let leaves = self.leaves.lock();
        let copied_leaves = if let Some(lease) = lease.as_deref_mut() {
            let mut copied =
                ExecutionBuffer::new(leaves.len(), lease).map_err(|_| unavailable())?;
            copied.append(&leaves).map_err(|_| unavailable())?;
            MerkleLeaves::Funded(copied)
        } else {
            let mut copied =
                crate::cache_memory::OwnedAllocation::try_filled_copy(leaves.len(), [0; 32])?;
            copied.copy_from_slice(&leaves);
            MerkleLeaves::Local(copied)
        };
        let nodes = CanonicalNodes::from_leaves(&copied_leaves, lease)?;
        Ok(Self {
            chunk: self.chunk,
            zero_hash: self.zero_hash,
            leaves: Mutex::new(copied_leaves),
            nodes: Mutex::new(nodes),
        })
    }

    pub(crate) fn try_retain(&self) -> bool {
        let nodes = self.nodes.lock();
        nodes.try_retain() && self.leaves.lock().try_retain()
    }
    pub(crate) fn make_active(&self) {
        let nodes = self.nodes.lock();
        nodes.make_active();
        self.leaves.lock().make_active();
    }
    fn validate_chunk_size(chunk: usize) -> Result<(), VMError> {
        if !(1..=32).contains(&chunk) {
            return Err(VMError::MemoryOutOfBounds);
        }
        Ok(())
    }
    fn compute_zero_hash(chunk: usize) -> [u8; 32] {
        let buf = [0u8; 32];
        let digest = Sha256::digest(&buf[..chunk]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
    fn hash_chunk_padded(&self, data: &[u8]) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[..data.len()].copy_from_slice(data);
        if buf[..self.chunk].iter().all(|&b| b == 0) {
            return self.zero_hash;
        }
        // Accelerated one-block SHA-256 using our CPU/GPU paths.
        sha256_oneblock32(&buf[..self.chunk])
    }
    fn refresh_locked(&self, nodes: &mut CanonicalNodes) {
        if nodes.is_current() || !nodes.refresh(&self.leaves.lock()) {
            return;
        }
        #[cfg(test)]
        MERKLE_REBUILDS.fetch_add(1, Ordering::Relaxed);
        iroha_telemetry::metrics::global_or_default()
            .ivm_merkle_rebuild_total
            .inc();
    }

    #[cfg(any(all(target_os = "macos", feature = "metal"), feature = "cuda"))]
    pub(crate) fn from_leaf_digests(digests: &[[u8; 32]], chunk: usize) -> Result<Self, VMError> {
        let mut leaves =
            crate::cache_memory::OwnedAllocation::try_filled_copy(digests.len(), [0; 32])?;
        leaves.copy_from_slice(digests);
        let nodes = CanonicalNodes::from_leaves(&leaves, None)?;
        Ok(Self {
            chunk,
            zero_hash: Self::compute_zero_hash(chunk),
            leaves: Mutex::new(leaves.into()),
            nodes: Mutex::new(nodes),
        })
    }

    #[cfg(feature = "cuda")]
    fn install_leaf_digests(&self, digests: &[[u8; 32]]) -> bool {
        let mut nodes = self.nodes.lock();
        let mut leaves = self.leaves.lock();
        if !leaves.replace_equal_length(digests) {
            return false;
        }
        nodes.mark_stale();
        true
    }

    fn checked_leaf_index(&self, index: usize) -> Result<u32, VMError> {
        if index >= self.leaves.lock().len() {
            return Err(VMError::MemoryOutOfBounds);
        }
        u32::try_from(index).map_err(|_| VMError::MemoryOutOfBounds)
    }
    /// Construct a tree from raw bytes, padding the final chunk with zeros.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] unless `chunk` is in `1..=32`;
    /// local leaf-allocation refusal defers execution.
    pub fn from_bytes(data: &[u8], chunk: usize) -> Result<Self, VMError> {
        Self::from_bytes_hashed(data, chunk, false)
    }
    /// Construct fixed leaf and canonical node backing, hashing chunks in parallel.
    ///
    /// # Errors
    /// Returns a bounds error for invalid chunk geometry or a local allocation deferral.
    pub fn from_bytes_parallel(data: &[u8], chunk: usize) -> Result<Self, VMError> {
        Self::from_bytes_hashed(data, chunk, true)
    }
    /// Whether two trees have the same immutable leaf geometry.
    pub(crate) fn has_same_shape(&self, other: &ByteMerkleTree) -> bool {
        self.chunk == other.chunk && self.leaf_count() == other.leaf_count()
    }
    /// Byte width of one Merkle leaf.
    pub(crate) fn chunk_size(&self) -> usize {
        self.chunk
    }
    /// Restore marked leaves from a shape-compatible immutable template and
    /// update their canonical parents in place, without allocating reset scratch.
    pub(crate) fn reset_leaves_from(
        &mut self,
        other: &ByteMerkleTree,
        restored: &crate::memory::dirty_chunks::DirtyChunks,
    ) {
        assert!(
            self.has_same_shape(other),
            "Merkle template shape must be validated before dirty-leaf reset"
        );
        assert_eq!(
            restored.chunks(),
            self.leaf_count(),
            "restored-leaf geometry mismatch"
        );
        if restored.is_empty() {
            return;
        }
        let mut nodes = self.nodes.lock();
        let template = other.leaves.lock();
        let mut leaves = self.leaves.lock();
        for index in restored.iter() {
            leaves[index] = template[index];
        }
        // Ordinary commits leave nodes current. Preserve that property across
        // warm resets so the next invocation's first write/root does not rebuild
        // the entire image. Already stale nodes still need their full refresh.
        // Memory separately restores the template's pending dirty bitmap: its
        // uncommitted bytes must be hashed before publishing the restored root.
        if nodes.is_current() {
            nodes.update_marked_leaf_digests(&leaves, restored.words());
        }
    }
    /// Construct a tree from raw bytes using acceleration when beneficial.
    ///
    /// Metal selects complete construction costs for the exact public chunk
    /// and tail geometry against the actual qualified parallel CPU path.
    /// CUDA retains its independently qualified leaf attempt. Every refusal
    /// falls back to the same canonical parallel constructor.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] unless `chunk` is in `1..=32`.
    pub fn from_bytes_accel(data: &[u8], chunk: usize) -> Result<Self, VMError> {
        Self::validate_chunk_size(chunk)?;
        #[cfg(any(target_os = "macos", feature = "cuda"))]
        let leaves_count = data.len().div_ceil(chunk).max(1);
        #[cfg(any(target_os = "macos", feature = "cuda"))]
        let policy = ResolvedMerklePolicy::current();
        #[cfg(target_os = "macos")]
        if let Some(tree) = policy.try_metal(leaves_count, || {
            crate::vector::metal_tree_from_bytes_auto(data, chunk)
        }) {
            return Ok(tree);
        }
        // CUDA keeps generated padded chunks and complete output in owned host storage.
        #[cfg(feature = "cuda")]
        if let Some(output) = policy.try_cuda(leaves_count, || {
            crate::cuda::sha256_leaf_chunks_cuda_attempt(data, chunk, leaves_count)
        }) && output.len() == leaves_count
        {
            // HostOutput stays alive until both destination owners are complete.
            return Self::from_leaf_digests(output.as_slice(), chunk);
        }
        // CPU path (parallel when Rayon is enabled)
        Self::from_bytes_parallel(data, chunk)
    }
    /// Recompute all leaf digests from `data` using acceleration when available.
    /// On success, installs complete leaves; Metal also refreshes the retained
    /// canonical nodes under its original owner before returning.
    /// Returns true if acceleration was used, false otherwise (no changes made).
    pub(crate) fn recompute_all_leaves_accel(&self, data: &[u8]) -> bool {
        #[cfg(any(target_os = "macos", feature = "cuda"))]
        let leaves_count = self.leaf_count();
        #[cfg(any(target_os = "macos", feature = "cuda"))]
        let policy = ResolvedMerklePolicy::current();
        #[cfg(target_os = "macos")]
        if policy
            .try_metal(leaves_count, || {
                crate::vector::metal_rehash_tree_auto(self, data).then_some(())
            })
            .is_some()
        {
            return true;
        }
        #[cfg(feature = "cuda")]
        if let Some(output) = policy.try_cuda(leaves_count, || {
            crate::cuda::sha256_leaf_chunks_cuda_attempt(data, self.chunk, leaves_count)
        }) {
            // Validate exact geometry, then copy the full HostOutput while its
            // original allocation owner is still alive. Canonical nodes remain prepaid.
            return self.install_leaf_digests(output.as_slice());
        }
        #[cfg(not(any(target_os = "macos", feature = "cuda")))]
        let _ = data;
        false
    }
    /// Rehash every fixed leaf in place on the CPU. A large memory commit must
    /// keep the original prepaid backing instead of replacing the whole tree.
    pub(crate) fn recompute_all_leaves_parallel(&self, data: &[u8]) {
        self.rehash_parallel_in_context(data, crate::vector::Sha256Context::production());
    }
    /// Construct a zero-filled tree with at least one leaf.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] unless `chunk` is in `1..=32`.
    pub fn new(num_leaves: usize, chunk: usize) -> Result<Self, VMError> {
        Self::validate_chunk_size(chunk)?;
        let zero_hash = Self::compute_zero_hash(chunk);
        let leaves =
            crate::cache_memory::OwnedAllocation::try_filled_copy(num_leaves.max(1), zero_hash)?;
        let nodes = CanonicalNodes::new(num_leaves.max(1), zero_hash, None)?;
        Ok(ByteMerkleTree {
            chunk,
            zero_hash,
            leaves: Mutex::new(leaves.into()),
            nodes: Mutex::new(nodes),
        })
    }
    /// Construct fixed zero leaves from credit reserved before either guest
    /// image or leaf backing is allocated.
    pub(crate) fn new_funded(
        num_leaves: usize,
        chunk: usize,
        lease: &mut ExecutionMemoryLease,
    ) -> Result<Self, VMError> {
        Self::validate_chunk_size(chunk)?;
        let zero_hash = Self::compute_zero_hash(chunk);
        let leaf_count = num_leaves.max(1);
        let mut leaves = ExecutionBuffer::new(leaf_count, lease).map_err(|_| {
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
        })?;
        let zeros = [zero_hash; 128];
        while leaves.as_slice().len() < leaf_count {
            let remaining = leaf_count - leaves.as_slice().len();
            leaves
                .append(&zeros[..remaining.min(zeros.len())])
                .expect("fixed prepaid leaf backing has sufficient capacity");
        }
        let nodes = CanonicalNodes::new(leaf_count, zero_hash, Some(lease))?;
        Ok(Self {
            chunk,
            zero_hash,
            leaves: Mutex::new(MerkleLeaves::Funded(leaves)),
            nodes: Mutex::new(nodes),
        })
    }
    pub(crate) fn leaf_count(&self) -> usize {
        self.leaves.lock().len()
    }
    /// Return the canonical Merkle root as a typed hash.
    pub fn root_hash(&self) -> HashOf<MerkleTree<[u8; 32]>> {
        let mut nodes = self.nodes.lock();
        self.refresh_locked(&mut nodes);
        nodes.root().expect("tree has at least one leaf")
    }
    /// Retrieve the canonical Merkle proof for the leaf at `index`.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] when `index` is not an exact leaf index or cannot be
    /// represented by the canonical proof format.
    pub fn proof(&self, index: usize) -> Result<MerkleProof<[u8; 32]>, VMError> {
        let index = self.checked_leaf_index(index)?;
        let mut nodes = self.nodes.lock();
        self.refresh_locked(&mut nodes);
        nodes.get_proof(index).ok_or(VMError::MemoryOutOfBounds)
    }
    /// Combined helper returning both the root hash and the Merkle proof.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] when `index` is not an exact leaf index or cannot be
    /// represented by the canonical proof format.
    pub fn root_and_proof(
        &self,
        index: usize,
    ) -> Result<(HashOf<MerkleTree<[u8; 32]>>, MerkleProof<[u8; 32]>), VMError> {
        let index = self.checked_leaf_index(index)?;
        let mut nodes = self.nodes.lock();
        self.refresh_locked(&mut nodes);
        let root = nodes.root().expect("tree has at least one leaf");
        let proof = nodes.get_proof(index).ok_or(VMError::MemoryOutOfBounds)?;
        Ok((root, proof))
    }
    pub fn root(&self) -> [u8; 32] {
        let root = self.root_hash();
        *root.as_ref()
    }
    /// Update leaf at `index` with new chunk bytes.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] when `index` is not an exact leaf index or `data`
    /// is larger than the configured leaf width.
    pub fn update_leaf(&self, index: usize, data: &[u8]) -> Result<(), VMError> {
        if data.len() > self.chunk {
            return Err(VMError::MemoryOutOfBounds);
        }
        self.checked_leaf_index(index)?;
        let digest = self.hash_chunk_padded(data);
        let mut nodes = self.nodes.lock();
        self.leaves.lock()[index] = digest;
        if nodes.is_current() {
            nodes.update_leaf_digest(index, digest);
        }
        Ok(())
    }
    /// Authentication path for leaf at `index`.
    ///
    /// Ordering: returns siblings from leaf → root. Each entry is the sibling
    /// hash at the corresponding tree level (missing siblings encoded as all‑zero).
    /// Keep this convention in sync with canonical proof consumers and tests.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] when `index` is not an exact leaf index or cannot be
    /// represented by the canonical proof format.
    pub fn path(&self, index: usize) -> Result<Vec<[u8; 32]>, VMError> {
        let proof = self.proof(index)?;
        let path = proof
            .into_audit_path()
            .into_iter()
            .map(|opt| opt.map(|h| *h.as_ref()).unwrap_or([0u8; 32]))
            .collect::<Vec<_>>();
        if crate::dev_env::debug_compact_enabled() {
            eprintln!("[path] index={} depth={}", index, path.len());
        }
        Ok(path)
    }
    /// Rehash the original memory bitmap directly into fixed leaf backing.
    ///
    /// Sparse writes touch only their set bits; larger updates hash disjoint
    /// groups of 64 leaves in parallel. Current canonical nodes then rehash each
    /// dirty parent once per level, with the same nodes as one leaf-to-root path
    /// update per dirty leaf in ascending order. No index or digest vector is
    /// copied or allocated here.
    pub(crate) fn update_dirty_leaves_from_bytes(
        &mut self,
        data: &[u8],
        dirty: &crate::memory::dirty_chunks::DirtyChunks,
    ) {
        use rayon::prelude::*;

        // Root/proof refresh takes nodes then leaves; every mutation follows
        // the same order so a query cannot publish mismatched representations.
        let mut nodes = self.nodes.lock();
        let mut leaves = self.leaves.lock();
        assert_eq!(dirty.chunks(), leaves.len(), "dirty-leaf geometry mismatch");
        if dirty.is_empty() {
            return;
        }
        let chunk = self.chunk;
        let zero_hash = self.zero_hash;
        let context = crate::vector::Sha256Context::production();
        let digest =
            |index: usize| cpu_leaves::digest_leaf(data, index, chunk, zero_hash, context).0;
        if dirty.len() < 256 {
            for index in dirty.iter() {
                leaves[index] = digest(index);
            }
        } else {
            leaves
                .par_chunks_mut(64)
                .zip(dirty.words().par_iter())
                .enumerate()
                .for_each(|(word_index, (group, word))| {
                    let mut remaining = *word;
                    while remaining != 0 {
                        let offset = remaining.trailing_zeros() as usize;
                        remaining &= remaining - 1;
                        group[offset] = digest(word_index * 64 + offset);
                    }
                });
        }
        if nodes.is_current() {
            nodes.update_marked_leaf_digests(&leaves, dirty.words());
            let updated = dirty.len() as u64;
            #[cfg(test)]
            MERKLE_INCREMENTAL_LEAF_UPDATES.fetch_add(updated, Ordering::Relaxed);
            iroha_telemetry::metrics::global_or_default()
                .ivm_merkle_incremental_leaf_updates_total
                .inc_by(updated);
        }
    }
    /// Return both the Merkle root and the authentication path for `index`.
    /// Refreshes retained canonical nodes in place at most once.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] when `index` is not an exact leaf index or cannot be
    /// represented by the canonical proof format.
    pub fn root_and_path(
        &self,
        index: usize,
    ) -> Result<(HashOf<MerkleTree<[u8; 32]>>, Vec<[u8; 32]>), VMError> {
        let (root, proof) = self.root_and_proof(index)?;
        let path = proof
            .into_audit_path()
            .into_iter()
            .map(|opt| opt.map(|h| *h.as_ref()).unwrap_or([0u8; 32]))
            .collect();
        Ok((root, path))
    }
    /// Compute a Merkle root directly from raw bytes using acceleration for both leaf hashing
    /// and inner-node reduction when beneficial. Falls back to CPU for small trees or when
    /// accelerators are unavailable.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] unless `chunk` is in `1..=32`,
    /// or a local execution deferral when the canonical CPU backing is unavailable.
    pub fn root_from_bytes_accel(data: &[u8], chunk: usize) -> Result<[u8; 32], VMError> {
        Self::validate_chunk_size(chunk)?;
        #[cfg(any(target_os = "macos", feature = "cuda"))]
        let leaves_count = data.len().div_ceil(chunk).max(1);
        #[cfg(any(target_os = "macos", feature = "cuda"))]
        let policy = ResolvedMerklePolicy::current();
        // Operator policy admits an attempt; the native owner still qualifies
        // hardware and selects its complete public-geometry cost profile.
        #[cfg(target_os = "macos")]
        if let Some(root) = policy.try_metal(leaves_count, || {
            crate::vector::metal_root_from_bytes_auto(data, chunk)
        }) {
            let metrics = iroha_telemetry::metrics::global_or_default();
            metrics.merkle_root_gpu_total.inc();
            return Ok(root);
        }
        #[cfg(feature = "cuda")]
        if let Some(root) = policy.try_cuda(leaves_count, || {
            if crate::cuda_available() {
                crate::cuda::sha256_merkle_root_cuda(data, chunk)
            } else {
                None
            }
        }) {
            let metrics = iroha_telemetry::metrics::global_or_default();
            metrics.merkle_root_gpu_total.inc();
            return Ok(root);
        }
        // CPU fallback
        let canonical =
            MerkleTree::<[u8; 32]>::from_byte_chunks(data, chunk).map_err(|error| match error {
                iroha_crypto::MerkleError::AllocationUnavailable => VMError::ExecutionDeferred(
                    crate::error::ExecutionDeferral::AllocationUnavailable,
                ),
                _ => VMError::MemoryOutOfBounds,
            })?;
        let metrics = iroha_telemetry::metrics::global_or_default();
        metrics.merkle_root_cpu_total.inc();
        Ok(*canonical.root().expect("non-empty").as_ref())
    }
}
#[inline]
pub(crate) fn sha256_oneblock32(input: &[u8]) -> [u8; 32] {
    sha256_oneblock32_in_context(input, crate::vector::Sha256Context::production()).0
}

#[inline]
pub(crate) fn sha256_oneblock32_in_context(
    input: &[u8],
    context: crate::vector::Sha256Context,
) -> ([u8; 32], crate::vector::Sha256Observed) {
    debug_assert!(input.len() <= 32);
    // IV
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    // Build a single padded block (fits since input <= 55 bytes, here <= 32)
    let mut block = [0u8; 64];
    let len = input.len();
    block[..len].copy_from_slice(input);
    block[len] = 0x80;
    let bit_len_be = (len as u64 * 8).to_be_bytes();
    block[56..64].copy_from_slice(&bit_len_be);
    // Single blocks stay below the GPU launch floor. Preserve the original
    // caller's native/scalar policy and receipt bank on every Rayon worker.
    let observed = crate::vector::Sha256Observed::completed(context.compress(&mut state, &block));
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    (out, observed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationBudget;

    #[test]
    fn funded_leaves_keep_prepaid_owner_and_match_local_updates() {
        let plan = ByteMerkleTree::memory_plan(4).unwrap();
        let total_bytes = plan.requested_bytes();
        let budget = AllocationBudget::new(total_bytes);
        let mut lease = ExecutionMemoryLease::reserve(&budget, plan).unwrap();
        let funded = ByteMerkleTree::new_funded(4, 32, &mut lease).unwrap();
        drop(lease);
        assert_eq!(budget.reserved_bytes(), total_bytes);
        let local = ByteMerkleTree::new(4, 32).unwrap();
        assert_eq!(funded.root_hash(), local.root_hash());
        funded.update_leaf(2, &[0x5a; 32]).unwrap();
        local.update_leaf(2, &[0x5a; 32]).unwrap();
        assert_eq!(funded.root_hash(), local.root_hash());
        let digests = funded.leaves.lock().to_vec();
        assert!(funded.leaves.lock().replace_equal_length(&digests));
        assert!(!funded.leaves.lock().replace_equal_length(&digests[..3]));
        assert_eq!(budget.reserved_bytes(), total_bytes);
        let mut data = [0u8; 128];
        data[0] = 0x39;
        data[127] = 0xb7;
        funded.recompute_all_leaves_parallel(&data);
        local.recompute_all_leaves_parallel(&data);
        let expected = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32)
            .unwrap()
            .root()
            .unwrap();
        assert_eq!(funded.root_hash(), expected);
        assert_eq!(local.root_hash(), expected);
        assert_eq!(budget.reserved_bytes(), total_bytes);
        let cloned = funded.try_clone_for_runtime_template(None).unwrap();
        assert_eq!(cloned.root_hash(), funded.root_hash());
        assert_eq!(budget.reserved_bytes(), total_bytes);
        drop(funded);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(cloned.root_hash(), local.root_hash());
    }

    #[test]
    fn fallible_template_tree_copy_preserves_root_and_independent_leaves() {
        let source = ByteMerkleTree::new(3, 32).expect("bounded test tree");
        source.update_leaf(1, &[0x5a; 32]).expect("update source");
        let copied = source
            .try_clone_for_runtime_template(None)
            .expect("bounded tree copy");
        assert_eq!(copied.root_hash(), source.root_hash());
        copied.update_leaf(1, &[0x33; 32]).expect("update copy");
        assert_ne!(copied.root_hash(), source.root_hash());
    }

    #[test]
    fn constructor_defers_unrepresentable_leaf_storage() {
        assert!(matches!(
            ByteMerkleTree::new(usize::MAX, 32),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
    }
    #[test]
    fn sha256_oneblock32_matches_sha2() {
        for &len in &[0usize, 1, 7, 16, 31, 32] {
            let mut v = vec![0u8; len];
            for (i, b) in v.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(13).wrapping_add(5);
            }
            let ours = sha256_oneblock32(&v);
            let theirs = sha2::Sha256::digest(&v);
            assert_eq!(ours.as_slice(), &theirs[..]);
        }
    }
    #[test]
    fn root_from_bytes_accel_matches_canonical() {
        let samples: &[(&[u8], usize)] = &[
            (b"", 32),
            (b"a", 1),
            (b"hello world", 16),
            (&[0u8; 100], 32),
        ];
        for &(data, chunk) in samples {
            let accel = ByteMerkleTree::root_from_bytes_accel(data, chunk).unwrap();
            let canonical = iroha_crypto::MerkleTree::<[u8; 32]>::from_byte_chunks(data, chunk)
                .expect("valid chunk");
            let expected = *canonical.root().expect("non-empty").as_ref();
            assert_eq!(accel, expected);
        }
    }
    #[test]
    fn large_accelerated_merkle_paths_match_canonical() {
        let _serial = crate::vector::forced_simd_test_lock();
        let mut data = vec![0u8; 8_193 * 32];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        let canonical = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).unwrap();
        let expected = *canonical.root().unwrap().as_ref();
        assert_eq!(
            ByteMerkleTree::root_from_bytes_accel(&data, 32).unwrap(),
            expected
        );
        assert_eq!(
            ByteMerkleTree::from_bytes_accel(&data, 32).unwrap().root(),
            expected
        );
    }
    #[test]
    fn recompute_all_leaves_accel_small_tree_returns_false() {
        let data = b"small";
        let chunk = 32;
        let tree = ByteMerkleTree::from_bytes(data, chunk).unwrap();
        // Below GPU threshold; must return false (no acceleration used)
        assert!(!tree.recompute_all_leaves_accel(data));
    }
    #[test]
    fn reset_from_restores_state() {
        let data_a = vec![0u8; 96];
        let data_b = vec![1u8; 96];
        let source = ByteMerkleTree::from_bytes(&data_a, 32).unwrap();
        let other = ByteMerkleTree::from_bytes(&data_b, 32).unwrap();
        other.update_leaf(1, &[5u8; 32]).unwrap();
        let mut target = ByteMerkleTree::new(3, 32).unwrap();
        let mut restored = crate::memory::dirty_chunks::DirtyChunks::new(3, None).unwrap();
        restored.extend(0..3);
        target.reset_leaves_from(&other, &restored);
        assert_eq!(target.root(), other.root());
        target.reset_leaves_from(&source, &restored);
        assert_eq!(target.root(), source.root());
    }
    #[test]
    fn selected_leaf_reset_restores_template_without_tree_clone() {
        let template = ByteMerkleTree::from_bytes(&[0u8; 128], 32).unwrap();
        let mut worker = template.try_clone_for_runtime_template(None).unwrap();
        assert!(worker.has_same_shape(&template));
        assert_eq!(worker.chunk_size(), 32);
        assert!(!worker.has_same_shape(&ByteMerkleTree::new(4, 16).unwrap()));
        worker.update_leaf(1, &[0xAA; 32]).unwrap();
        worker.update_leaf(3, &[0x55; 32]).unwrap();
        assert_ne!(worker.root(), template.root());
        let mut restored = crate::memory::dirty_chunks::DirtyChunks::new(4, None).unwrap();
        restored.extend([3, 1, 3, 1]);
        worker.reset_leaves_from(&template, &restored);
        assert_eq!(worker.root(), template.root());
    }
}

#[cfg(test)]
mod dirty_bitmap_tests;

#[cfg(test)]
mod canonical_node_tests;

#[cfg(test)]
mod warm_reset_tests;
