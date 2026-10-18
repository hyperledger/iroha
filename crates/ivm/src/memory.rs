//! Region-based memory manager implementing the IVM memory model.
//!
//! The memory subsystem enforces permissions, alignment and region bounds for all loads and stores.
//! Heap allocation is supported and vector accesses are checked for 16‑byte alignment as required
//! by the specification. Memory is divided into disjoint regions:
//!
//! * **Code** – loaded at address `0x0000_0000` and marked read/execute only.
//! * **Heap** – starts at `0x0010_0000` and grows upward via `SYSCALL_ALLOC`.
//! * **Input** – read-only buffer beginning at `0x0020_0000` (64 KB).
//! * **Output** – read/write buffer beginning at `0x0021_0000`.
//! * **Stack** – starts at `0x0030_0000`; ABI V1 derives a deterministic
//!   64&nbsp;KiB–4&nbsp;MiB active limit from the invocation gas budget.
use crate::{
    byte_merkle_tree::ByteMerkleTree,
    error::{Perm, VMError},
    execution_memory::{ExecutionBuffer, ExecutionMemoryLease, ExecutionMemoryPlan},
    execution_memory_recorder::{
        DiagnosticInitialMemoryState, DiagnosticMemoryAccessKind, DiagnosticMemoryAccessRecorder,
    },
    merkle_utils::compute_memory_leaf_digest,
    stack_policy::IvmStackPolicy,
};
use iroha_allocation::AllocationBudget;
use iroha_crypto::{
    CompactMerkleProof, Hash, HashOf, MerkleProof, MerkleTree, MerkleTreeCommitment,
};
use likely_stable::{likely, unlikely};
use parking_lot::Mutex;
use std::{
    convert::TryInto,
    num::NonZeroU64,
    ops::{Deref, DerefMut},
    time::Instant,
};
pub(crate) mod dirty_chunks;
use dirty_chunks::DirtyChunks;
pub(crate) mod private_disposal;
mod private_scrub;
mod read_log;
use read_log::ReadLog;
pub use read_log::ReadLogSnapshot;
mod write_log;
use write_log::WriteLog;
pub use write_log::{WriteLogEntry, WriteLogSnapshot};

#[cfg(test)]
std::thread_local! {
    static REFUSE_NEXT_READ_TRACKING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Memory read range recorded for conflict detection in parallel execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessRange {
    pub addr: u64,
    pub len: u64,
}
/// Memory manager for the VM, with fixed regions for code, heap, and stack.
///
/// In accordance with the updated architecture the entire memory image is committed via a Merkle
/// tree. Writes mark ranges dirty and the [`root`] is recomputed lazily on `commit()` by hashing
/// only the modified chunks. This avoids re-hashing untouched memory while still enabling inclusion
/// paths to be produced after a commit. Zero‑knowledge mode can request inclusion paths for any
/// address.
pub struct Memory {
    /// Trusted stack/table ownership and actual byte initialization for compiled calls.
    pub(crate) call_frames: crate::call_frame::CallFrameMemory,
    stack_limit: u64,
    heap_alloc: u64,
    heap_limit: u64,
    heap_max_limit: u64,
    /// Whether any heap byte may differ from the zeroed program-load baseline.
    heap_contains_data: bool,
    code_length: u64,
    /// Append-only cursor for the OUTPUT region. Enforces append-only semantics.
    output_cursor: u64,
    /// Merkle root of the entire memory image. Updated when `commit()` is
    /// called to batch multiple writes together.
    root: HashOf<MerkleTree<[u8; 32]>>,
    tree: ByteMerkleTree,
    /// Flag indicating that memory contents have changed since the last commit.
    dirty: bool,
    /// Prepaid bitmap of Merkle leaves modified since the last commit.
    dirty_chunks: DirtyChunks,
    /// Leaf indices modified since the last runtime-template reset.
    ///
    /// Unlike `dirty_chunks`, this bitmap is not cleared by Merkle commits. It
    /// lets warm VM reuse restore only pages the guest actually changed.
    modified_chunks: DirtyChunks,
    /// Number of times a program loader established a new runtime baseline.
    template_generation: u64,
    /// Opaque identity of the runtime baseline that owns this memory image.
    ///
    /// Runtime-template snapshots preserve this identity.
    baseline_lineage: crate::cache_memory::SharedValue<()>,
    /// Addresses read during execution when access tracking is enabled.
    read_log: Mutex<ReadLog>,
    /// Log of writes performed during execution (byte-accurate).
    write_log: Mutex<WriteLog>,
    /// Attached only for one explicit local diagnostic run; never cloned into a template.
    diagnostic_access_recorder: Option<DiagnosticMemoryAccessRecorder>,
    // Release aggregate charges after every owned allocation above is destroyed.
    data: MemoryImage,
}

/// One fixed guest image with its original allocation owner attached.
/// Only Core's cold nested checkout uses the finite active pool so far.
enum MemoryImage {
    Local(crate::cache_memory::OwnedAllocation<u8>),
    Funded(ExecutionBuffer<u8>),
}

impl From<Vec<u8>> for MemoryImage {
    fn from(values: Vec<u8>) -> Self {
        Self::Local(values.into())
    }
}

impl MemoryImage {
    fn try_retain(&self) -> bool {
        match self {
            Self::Local(image) => image.try_retain(),
            Self::Funded(image) => image.try_retain(),
        }
    }

    fn mark_unmeasured(&mut self) {
        match self {
            Self::Local(image) => image.mark_unmeasured(),
            Self::Funded(image) => image.mark_unmeasured(),
        }
    }

    fn remeasure_fixed(&mut self) {
        match self {
            Self::Local(image) => image.remeasure_fixed(),
            Self::Funded(image) => image.remeasure_fixed(),
        }
    }
}

impl Deref for MemoryImage {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Local(image) => image,
            Self::Funded(image) => image.as_slice(),
        }
    }
}

impl DerefMut for MemoryImage {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Local(image) => image,
            Self::Funded(image) => image.as_mut_slice(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoryGeometry {
    pub(crate) bytes: usize,
    pub(crate) stack_limit: u64,
    pub(crate) heap_max_limit: u64,
    pub(crate) merkle_chunk_bytes: usize,
    pub(crate) merkle_leaves: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoryTemplateMismatch {
    pub(crate) current: MemoryGeometry,
    pub(crate) template: MemoryGeometry,
}
impl Memory {
    /// Original physical cell for the sealed native producer. This does not
    /// perform a guest read, grant access, charge gas or alter access logs.
    pub(crate) fn native_packet_cell(&self, address: u64) -> Option<[u8; 16]> {
        if !address.is_multiple_of(16) {
            return None;
        }
        let start = usize::try_from(address).ok()?;
        self.data
            .get(start..start.checked_add(16)?)?
            .try_into()
            .ok()
    }

    pub(crate) fn capture_diagnostic_initial_image(
        &self,
        recorder: &DiagnosticMemoryAccessRecorder,
    ) -> Result<(), VMError> {
        recorder.capture_initial_image(
            DiagnosticInitialMemoryState {
                image_bytes: self.data.len(),
                code_length: self.code_length,
                heap_allocated: self.heap_alloc,
                heap_limit: self.heap_limit,
                heap_max_limit: self.heap_max_limit,
                output_cursor: self.output_cursor,
                stack_limit: self.stack_limit,
            },
            &self.data,
        )
    }

    pub(crate) fn install_diagnostic_access_recorder(
        &mut self,
        recorder: DiagnosticMemoryAccessRecorder,
    ) -> Result<(), VMError> {
        if self.diagnostic_access_recorder.is_some() {
            return Err(VMError::HostUnavailable);
        }
        self.diagnostic_access_recorder = Some(recorder);
        Ok(())
    }

    pub(crate) fn clear_diagnostic_access_recorder(&mut self) {
        self.diagnostic_access_recorder = None;
    }

    pub(crate) fn diagnostic_step_ordinal(&self, ordinal: u64) {
        if let Some(recorder) = &self.diagnostic_access_recorder {
            recorder.set_step_ordinal(ordinal);
        }
    }

    pub(crate) fn diagnostic_classify_last_access(
        &self,
        addr: u64,
        len: u64,
        kind: DiagnosticMemoryAccessKind,
        private: bool,
    ) {
        if let Some(recorder) = &self.diagnostic_access_recorder {
            recorder.classify_last_access(addr, len, kind, private);
        }
    }

    /// Fund a complete loader's CODE/HEAP/OUTPUT byte rows before its first
    /// memory mutation. Ordinary execution has no recorder and no new limit.
    pub(crate) fn preflight_diagnostic_program_load(&self, code_len: usize) -> Result<(), VMError> {
        let Some(recorder) = &self.diagnostic_access_recorder else {
            return Ok(());
        };
        let heap_rows = if self.heap_contains_data || self.heap_alloc != 0 {
            Memory::HEAP_MAX_SIZE as usize
        } else {
            0
        };
        let output_start = Memory::OUTPUT_START as usize;
        let output_end = output_start + Memory::OUTPUT_SIZE as usize;
        let output_rows = if self.output_cursor != 0
            || self.data[output_start..output_end]
                .iter()
                .any(|byte| *byte != 0)
        {
            Memory::OUTPUT_SIZE as usize
        } else {
            0
        };
        let demand = heap_rows
            .checked_add(code_len.max(self.code_length as usize))
            .and_then(|rows| rows.checked_add(output_rows))
            .ok_or(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable,
            ))?;
        recorder.ensure_remaining(demand)
    }

    // Fixed storage and both access logs carry their own lifetime charges.
    // TODO: Complete original active-pool plans for read-log growth, hardware
    // and remaining snapshot scratch before claiming complete execution funding.
    pub(crate) fn prepare_for_cache(&mut self) -> bool {
        if !self.call_frames.compact_for_cache() {
            return false;
        }
        // The image never resizes; activation only marks it unmeasured while
        // guest code runs. After the template reset its exact size is known
        // again, so it must not block retention of the idle runtime.
        self.data.remeasure_fixed();
        true
    }
    pub(crate) fn try_retain(&self) -> bool {
        self.data.try_retain()
            && self.read_log.lock().try_retain()
            && self.write_log.lock().try_retain()
            && self.tree.try_retain()
            && self.dirty_chunks.try_retain()
            && self.modified_chunks.try_retain()
            && self.call_frames.try_retain()
            && self.baseline_lineage.try_retain()
    }
    pub(crate) fn activate_cache_accounting(&mut self) {
        self.data.mark_unmeasured();
        self.read_log.lock().make_active();
        self.write_log.lock().make_active();
        self.tree.make_active();
        self.dirty_chunks.make_active();
        self.modified_chunks.make_active();
        self.call_frames.make_active();
    }
    /// Alignment enforced for the ABI V1 guest stack top.
    pub const STACK_ALIGNMENT: u64 = IvmStackPolicy::V1.stack_alignment_bytes();
    /// Define static addresses for memory regions
    pub const HEAP_START: u64 = 0x0010_0000;
    /// Maximum heap size allowed (from HEAP_START up to INPUT_START).
    pub const HEAP_MAX_SIZE: u64 = Self::INPUT_START - Self::HEAP_START;
    /// Default heap limit exposed to guest programs.
    ///
    /// Kotodama contracts currently do not auto-grow the heap, so starting at
    /// the full pre-input window avoids spurious `OutOfMemory` traps for
    /// larger but still bounded contracts such as SoraSwap DLMM.
    pub const HEAP_SIZE: u64 = Self::HEAP_MAX_SIZE;
    pub const INPUT_START: u64 = 0x0020_0000;
    pub const INPUT_SIZE: u64 = 0x0001_0000; // 64 KB input
    pub const OUTPUT_START: u64 = Self::INPUT_START + Self::INPUT_SIZE;
    pub const OUTPUT_SIZE: u64 = 0x0000_8000; // 32 KB output
    pub const STACK_START: u64 = 0x0030_0000;
    /// Maximum logical stack size for ABI V1 guest programs.
    pub const STACK_SIZE: u64 = IvmStackPolicy::V1.maximum_stack_bytes();
    /// Minimum logical stack size for ABI V1 guest programs.
    pub const MIN_STACK_SIZE: u64 = IvmStackPolicy::V1.minimum_stack_bytes();
    /// Extra slop beyond the nominal stack end (kept zero to trap exactly at the limit).
    pub const STACK_SLOP: u64 = 0;
    /// Current stack limit (bytes) enforced for this memory instance.
    pub fn stack_limit(&self) -> u64 {
        self.stack_limit
    }
    /// Top-of-stack address (exclusive).
    pub fn stack_top(&self) -> u64 {
        Memory::STACK_START + self.stack_limit
    }
    /// Update only the modified Merkle leaves and recompute the root.
    fn recompute_dirty(&mut self) {
        let started_at = Instant::now();
        // Heuristic: if more than half the leaves are dirty, prefer a full
        // accelerated leaf recompute when available.
        let total_leaves = self.tree.leaf_count();
        let large_update = self.dirty_chunks.len() >= total_leaves.div_ceil(2);
        let dirty_count = self.dirty_chunks.len() as f64;
        let mut commit_path = "incremental";
        if large_update && self.tree.recompute_all_leaves_accel(&self.data) {
            self.root = self.tree.root_hash();
            self.dirty_chunks.clear();
            self.dirty = false;
            commit_path = "accel";
            let metrics = iroha_telemetry::metrics::global_or_default();
            metrics
                .ivm_memory_commit_ms
                .with_label_values(&[commit_path])
                .observe(started_at.elapsed().as_secs_f64() * 1_000.0);
            metrics
                .ivm_memory_commit_dirty_chunks
                .with_label_values(&[commit_path])
                .observe(dirty_count);
            return;
        }
        if large_update {
            self.tree.recompute_all_leaves_parallel(&self.data);
            commit_path = "full_rebuild";
        } else {
            self.tree
                .update_dirty_leaves_from_bytes(&self.data, &self.dirty_chunks);
        }
        self.root = self.tree.root_hash();
        self.dirty_chunks.clear();
        self.dirty = false;
        let metrics = iroha_telemetry::metrics::global_or_default();
        metrics
            .ivm_memory_commit_ms
            .with_label_values(&[commit_path])
            .observe(started_at.elapsed().as_secs_f64() * 1_000.0);
        metrics
            .ivm_memory_commit_dirty_chunks
            .with_label_values(&[commit_path])
            .observe(dirty_count);
    }
    /// Commit pending writes by hashing only the dirty chunks if the memory has
    /// been modified since the last commit.
    pub fn commit(&mut self) {
        if self.dirty {
            self.recompute_dirty();
        }
    }
    #[cfg(test)]
    pub(crate) fn dirty_for_testing(&self) -> bool {
        self.dirty
    }
    fn merkle_leaf_index(&self, addr: u64) -> Result<usize, VMError> {
        let addr = usize::try_from(addr).map_err(|_| VMError::MemoryOutOfBounds)?;
        if addr >= self.data.len() {
            return Err(VMError::MemoryOutOfBounds);
        }
        Ok(addr / 32)
    }
    /// Generate the Merkle authentication path for the 32-byte chunk containing `addr`.
    /// Pending writes are committed before sampling so the returned path matches the latest
    /// memory image.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] unless `addr` names an exact byte in this memory
    /// image. In particular, the exclusive end address is not rounded into the final tree leaf.
    pub fn merkle_path(&mut self, addr: u64) -> Result<Vec<[u8; 32]>, VMError> {
        let index = self.merkle_leaf_index(addr)?;
        self.commit();
        self.tree.path(index)
    }
    /// Return both the current Merkle root (typed `HashOf<MerkleTree<[u8; 32]>>`)
    /// and the authentication path for the 32-byte chunk containing `addr` in a single operation.
    /// Pending writes are committed first to keep the root/path in sync.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] unless `addr` names an exact byte in this memory
    /// image.
    pub fn merkle_root_and_path(
        &mut self,
        addr: u64,
    ) -> Result<(HashOf<MerkleTree<[u8; 32]>>, Vec<[u8; 32]>), VMError> {
        let index = self.merkle_leaf_index(addr)?;
        self.commit();
        self.tree.root_and_path(index)
    }
    /// Build a compact Merkle proof for the memory chunk containing `addr`.
    ///
    /// Pending writes are committed before construction. Without truncation the returned root is
    /// the full memory-tree root. When `depth_cap` truncates the path, the returned root commits
    /// only to that path fragment and is not a membership commitment.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] unless `addr` names an exact byte in this memory
    /// image.
    pub fn merkle_compact(
        &mut self,
        addr: u64,
        depth_cap: Option<usize>,
    ) -> Result<(CompactMerkleProof<[u8; 32]>, HashOf<MerkleTree<[u8; 32]>>), VMError> {
        let leaf_index = self.merkle_leaf_index(addr)?;
        let leaf_index = u32::try_from(leaf_index).map_err(|_| VMError::MemoryOutOfBounds)?;
        let (full_root, path) = self.merkle_root_and_path(addr)?;
        let mut depth = path.len().min(32);
        if let Some(cap) = depth_cap {
            depth = depth.min(cap);
        }
        let dirs = if depth == 32 {
            leaf_index
        } else {
            leaf_index & ((1u32 << depth) - 1)
        };
        let typed_siblings: Vec<Option<HashOf<[u8; 32]>>> = path
            .iter()
            .take(depth)
            .map(|b| {
                if *b == [0u8; 32] {
                    None
                } else {
                    Some(HashOf::from_untyped_unchecked(Hash::prehashed(*b)))
                }
            })
            .collect();
        let proof_for_root = MerkleProof::from_audit_path(dirs, typed_siblings.clone());
        let compact = CompactMerkleProof::from_parts(depth as u8, dirs, typed_siblings);
        let root: HashOf<MerkleTree<[u8; 32]>> = if depth < path.len() {
            let base = (addr / 32) * 32;
            let start = base as usize;
            let end = (start + 32).min(self.data.len());
            let mut chunk = [0u8; 32];
            chunk[..(end - start)].copy_from_slice(&self.data[start..end]);
            let leaf_digest = compute_memory_leaf_digest(&chunk);
            let leaf_hash =
                HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf_digest));
            proof_for_root
                .compute_partial_root_sha256(&leaf_hash, depth)
                .expect("proof height equals compact depth")
        } else {
            full_root
        };
        Ok((compact, root))
    }
    /// Return the current full-tree root and exact local memory geometry as one
    /// membership commitment.
    ///
    /// This commitment is authoritative only for this in-process [`Memory`]
    /// instance. Protocols transporting a root must authenticate the count
    /// alongside it rather than reconstructing a count from the proof depth.
    pub fn merkle_commitment(&mut self) -> MerkleTreeCommitment<[u8; 32]> {
        self.commit();
        let leaf_count = u64::try_from(self.tree.leaf_count())
            .ok()
            .and_then(NonZeroU64::new)
            .expect("memory tree always has a non-zero leaf count representable as u64");
        MerkleTreeCommitment::new(self.root, leaf_count)
    }
    /// Current typed Merkle root, recomputing pending dirty ranges if needed.
    ///
    /// This helper mirrors [`root`](Self::root) but keeps the method name used by callers that
    /// sample the root during execution (e.g., step logs). It forces a `commit()` so that in-flight
    /// writes are reflected in the returned digest.
    pub fn current_root(&mut self) -> HashOf<MerkleTree<[u8; 32]>> {
        self.commit();
        self.root
    }
    /// Return the current Merkle root of memory, recomputing it if any writes
    /// have occurred since the last call.
    pub fn root(&mut self) -> HashOf<MerkleTree<[u8; 32]>> {
        self.commit();
        self.root
    }
    fn update_merkle(&mut self, start: usize, len: usize) {
        const CHUNK: usize = 32;
        let end = start.saturating_add(len);
        let heap_start = Memory::HEAP_START as usize;
        let heap_end = heap_start + Memory::HEAP_MAX_SIZE as usize;
        if start < heap_end && end > heap_start {
            self.heap_contains_data = true;
        }
        let first = start / CHUNK;
        let last = end.div_ceil(CHUNK);
        for i in first..last {
            self.dirty_chunks.insert(i);
            self.modified_chunks.insert(i);
        }
        // Mark the tree as dirty so the root is recomputed lazily on the next
        // `commit()` or `root()` call.
        self.dirty = true;
    }
    /// Initialize an empty memory image with the canonical ABI V1 maximum stack.
    ///
    /// Code becomes executable only after a successful [`Self::load_code`].
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_stack_limit(IvmStackPolicy::V1.maximum_stack_bytes())
            .expect("the canonical ABI V1 memory geometry is valid")
    }
    /// Initialize memory with an explicit stack limit (bytes).
    ///
    /// This low-level constructor is used for runtime templates and focused
    /// memory tests. Production VMs derive its argument exclusively from the
    /// immutable ABI stack policy in `IvmConfig`.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] when `stack_limit` is outside the
    /// ABI V1 range, is not exactly aligned, or the resulting memory geometry
    /// is not representable on the host. Local allocation refusal defers execution.
    pub fn new_with_stack_limit(stack_limit: u64) -> Result<Self, VMError> {
        let total_size = Self::image_bytes_for_stack_limit(stack_limit)?;
        let data = crate::cache_memory::OwnedAllocation::try_zeroed(total_size).map_err(|_| {
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
        })?;
        Self::new_with_image(
            stack_limit,
            total_size,
            MemoryImage::Local(data),
            None,
            None,
        )
    }

    pub(crate) fn new_with_stack_limit_funded(
        stack_limit: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, VMError> {
        let total_size = Self::image_bytes_for_stack_limit(stack_limit)?;
        let unavailable =
            || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
        let leaf_count = total_size.div_ceil(32).max(1);
        let mut plan = ExecutionMemoryPlan::array::<u8>(total_size).map_err(|_| unavailable())?;
        plan.include_child(ByteMerkleTree::memory_plan(leaf_count)?)
            .map_err(|_| unavailable())?;
        for _ in 0..2 {
            plan.include_child(DirtyChunks::memory_plan(leaf_count)?)
                .map_err(VMError::AllocationDeferred)?;
        }
        let mut lease =
            ExecutionMemoryLease::reserve(budget, plan).map_err(VMError::AllocationDeferred)?;
        let image = ExecutionBuffer::zeroed(total_size, &mut lease).map_err(|_| unavailable())?;
        Self::new_with_image(
            stack_limit,
            total_size,
            MemoryImage::Funded(image),
            Some(&mut lease),
            Some(budget),
        )
    }

    pub(crate) fn image_bytes_for_stack_limit(stack_limit: u64) -> Result<usize, VMError> {
        if !(Self::MIN_STACK_SIZE..=Self::STACK_SIZE).contains(&stack_limit)
            || !stack_limit.is_multiple_of(Self::STACK_ALIGNMENT)
        {
            return Err(VMError::MemoryOutOfBounds);
        }
        let total_size = Memory::STACK_START
            .checked_add(stack_limit)
            .and_then(|size| size.checked_add(Memory::STACK_SLOP))
            .ok_or(VMError::MemoryOutOfBounds)?;
        usize::try_from(total_size).map_err(|_| VMError::MemoryOutOfBounds)
    }

    fn new_with_image(
        stack_limit: u64,
        total_size: usize,
        data: MemoryImage,
        mut lease: Option<&mut ExecutionMemoryLease>,
        active_budget: Option<&AllocationBudget>,
    ) -> Result<Self, VMError> {
        let leaf_count = total_size.div_ceil(32).max(1);
        let tree = match lease.as_deref_mut() {
            Some(lease) => ByteMerkleTree::new_funded(leaf_count, 32, lease)?,
            None => ByteMerkleTree::new(leaf_count, 32)?,
        };
        let dirty_chunks = DirtyChunks::new(leaf_count, lease.as_deref_mut())?;
        let modified_chunks = DirtyChunks::new(leaf_count, lease)?;
        let mut mem = Memory {
            call_frames: active_budget.map_or_else(
                crate::call_frame::CallFrameMemory::default,
                crate::call_frame::CallFrameMemory::with_memory_budget,
            ),
            data,
            stack_limit,
            heap_alloc: 0,
            heap_limit: Memory::HEAP_SIZE,
            heap_max_limit: Memory::HEAP_MAX_SIZE,
            heap_contains_data: false,
            code_length: 0,
            output_cursor: 0,
            root: HashOf::from_untyped_unchecked(Hash::prehashed([0u8; 32])),
            tree,
            dirty: false,
            dirty_chunks,
            modified_chunks,
            template_generation: 0,
            baseline_lineage: crate::cache_memory::SharedValue::new((), Some(0)),
            read_log: Mutex::new(
                active_budget.map_or_else(ReadLog::default, ReadLog::with_memory_budget),
            ),
            write_log: Mutex::new(
                active_budget.map_or_else(WriteLog::default, WriteLog::with_memory_budget),
            ),
            diagnostic_access_recorder: None,
        };
        // initialize root from zeroed memory
        mem.root = mem.tree.root_hash();
        mem.activate_cache_accounting();
        Ok(mem)
    }
    /// Preload data into the input region. Used by tests/host before execution.
    pub fn preload_input(&mut self, offset: u64, bytes: &[u8]) -> Result<(), VMError> {
        if offset > Memory::INPUT_SIZE {
            return Err(VMError::MemoryOutOfBounds);
        }
        let len = bytes.len() as u64;
        let end_off = offset.checked_add(len).ok_or(VMError::MemoryOutOfBounds)?;
        if end_off > Memory::INPUT_SIZE {
            return Err(VMError::MemoryOutOfBounds);
        }
        let start = (Memory::INPUT_START + offset) as usize;
        let end = start + bytes.len();
        if let Some(recorder) = &self.diagnostic_access_recorder {
            recorder.record_write(
                Memory::INPUT_START + offset,
                &self.data[start..end],
                bytes,
                DiagnosticMemoryAccessKind::HostInputWrite,
            )?;
        }
        self.data[start..end].copy_from_slice(bytes);
        self.update_merkle(start, bytes.len());
        Ok(())
    }
    /// Tiny INPUT allocator helper: write `bytes` at the next aligned offset pointed to by `cursor`.
    ///
    /// - `cursor` is an offset relative to `INPUT_START` that the caller maintains.
    /// - `align` must be a power of two; defaults to 8 in most callers.
    /// - Returns the absolute pointer to the beginning of the written bytes.
    pub fn input_write_aligned(
        &mut self,
        cursor: &mut u64,
        bytes: &[u8],
        align: u64,
    ) -> Result<u64, VMError> {
        if !align.is_power_of_two() {
            return Err(VMError::MemoryOutOfBounds);
        }
        let mask = align - 1;
        let off = cursor
            .checked_add(mask)
            .map(|value| value & !mask)
            .ok_or(VMError::MemoryOutOfBounds)?;
        let len = u64::try_from(bytes.len()).map_err(|_| VMError::MemoryOutOfBounds)?;
        let end = off.checked_add(len).ok_or(VMError::MemoryOutOfBounds)?;
        if end > Memory::INPUT_SIZE {
            return Err(VMError::MemoryOutOfBounds);
        }
        self.preload_input(off, bytes)?;
        *cursor = end;
        Memory::INPUT_START
            .checked_add(off)
            .ok_or(VMError::MemoryOutOfBounds)
    }
    #[inline]
    pub fn alloc(&mut self, size: u64) -> Result<u64, VMError> {
        let aligned = size
            .checked_add(7)
            .map(|v| v & !7)
            .ok_or(VMError::OutOfMemory)?;
        if aligned != 0 {
            let new_alloc = self
                .heap_alloc
                .checked_add(aligned)
                .ok_or(VMError::OutOfMemory)?;
            if unlikely(new_alloc > self.heap_limit) {
                return Err(VMError::OutOfMemory);
            }
            let addr = Memory::HEAP_START + self.heap_alloc;
            self.heap_alloc = new_alloc;
            Ok(addr)
        } else {
            Ok(Memory::HEAP_START + self.heap_alloc)
        }
    }
    /// Grow the heap by `additional` bytes, returning the new limit.
    pub fn grow_heap(&mut self, additional: u64) -> Result<u64, VMError> {
        let aligned = additional
            .checked_add(7)
            .map(|v| v & !7)
            .ok_or(VMError::OutOfMemory)?;
        if aligned == 0 {
            return Ok(self.heap_limit);
        }
        let new_limit = self
            .heap_limit
            .checked_add(aligned)
            .ok_or(VMError::OutOfMemory)?;
        if unlikely(new_limit > self.heap_max_limit) {
            return Err(VMError::OutOfMemory);
        }
        self.heap_limit = new_limit;
        Ok(self.heap_limit)
    }
    /// Current heap limit in bytes.
    pub fn heap_limit(&self) -> u64 {
        self.heap_limit
    }
    /// Per-instance ceiling for heap growth.
    pub fn heap_max_limit(&self) -> u64 {
        self.heap_max_limit
    }
    /// Number of heap bytes currently owned by successful allocations.
    pub(crate) fn heap_allocated_len(&self) -> u64 {
        self.heap_alloc
    }
    /// Override the active heap limit, keeping the already-allocated region valid.
    pub fn set_heap_limit(&mut self, limit: u64) -> Result<(), VMError> {
        if limit < self.heap_alloc || limit > self.heap_max_limit {
            return Err(VMError::OutOfMemory);
        }
        self.heap_limit = limit;
        Ok(())
    }
    /// Set the absolute per-instance heap ceiling and clamp the active limit to it.
    ///
    /// Unlike [`Self::set_heap_limit`], this limit cannot be bypassed by [`Self::grow_heap`]. Hosts
    /// use it to apply deterministic governance limits before guest execution.
    pub fn set_heap_max_limit(&mut self, limit: u64) -> Result<(), VMError> {
        if limit < self.heap_alloc || limit > Memory::HEAP_MAX_SIZE {
            return Err(VMError::OutOfMemory);
        }
        self.heap_max_limit = limit;
        self.heap_limit = self.heap_limit.min(limit);
        Ok(())
    }
    /// Clear all physical heap bytes before installing a different program.
    pub(crate) fn clear_program_heap(&mut self) -> Result<(), VMError> {
        if !self.heap_contains_data && self.heap_alloc == 0 {
            return Ok(());
        }
        let start = Memory::HEAP_START as usize;
        let end = start + Memory::HEAP_MAX_SIZE as usize;
        if let Some(recorder) = &self.diagnostic_access_recorder {
            recorder.record_zero_fill(
                Memory::HEAP_START,
                &self.data[start..end],
                DiagnosticMemoryAccessKind::HeapReset,
            )?;
        }
        self.data[start..end].fill(0);
        self.heap_alloc = 0;
        self.update_merkle(start, end - start);
        self.heap_contains_data = false;
        Ok(())
    }
    /// Update the code region length after loading a program.
    fn set_code_length(&mut self, code_size: u64) {
        self.code_length = code_size;
    }
    /// Return the current code length in bytes.
    pub fn code_len(&self) -> u64 {
        self.code_length
    }
    /// Copy out the code bytes currently loaded in the code region.
    pub fn read_code_bytes(&self) -> Vec<u8> {
        let len = self.code_length as usize;
        self.data[0..len].to_vec()
    }
    /// Load program bytes into the beginning of memory (code region).
    ///
    /// The complete request is validated before any bytes or metadata change.
    ///
    /// # Errors
    /// Returns [`VMError::MemoryOutOfBounds`] when the program overlaps the
    /// heap boundary or is not representable in the physical memory image.
    pub fn load_code(&mut self, code: &[u8]) -> Result<(), VMError> {
        let len = code.len();
        let code_region_end = usize::try_from(Memory::HEAP_START)
            .map_err(|_| VMError::MemoryOutOfBounds)?
            .min(self.data.len());
        if len > code_region_end {
            return Err(VMError::MemoryOutOfBounds);
        }
        let old_len = usize::try_from(self.code_length).map_err(|_| VMError::MemoryOutOfBounds)?;
        if old_len > code_region_end {
            return Err(VMError::MemoryOutOfBounds);
        }
        let modified_len = len.max(old_len);
        if let Some(recorder) = &self.diagnostic_access_recorder {
            recorder.record_code_install(&self.data[..modified_len], code)?;
        }
        self.call_frames.clear();
        self.data[0..len].copy_from_slice(code);
        if len < old_len {
            self.data[len..old_len].fill(0);
        }
        self.set_code_length(len as u64);
        if modified_len != 0 {
            self.update_merkle(0, modified_len);
        }
        Ok(())
    }
    /// Determine the permissions for the address range `[addr, addr + size)`.
    #[inline]
    fn region_perm(&self, addr: u64, size: u32) -> Option<Perm> {
        let end = addr.checked_add(size as u64)?;
        if end <= self.code_length {
            return Some(Perm::READ | Perm::EXECUTE);
        }
        if addr >= Memory::HEAP_START && end <= Memory::HEAP_START + self.heap_limit {
            return Some(Perm::READ | Perm::WRITE);
        }
        if addr >= Memory::INPUT_START && end <= Memory::INPUT_START + Memory::INPUT_SIZE {
            return Some(Perm::READ);
        }
        if addr >= Memory::OUTPUT_START && end <= Memory::OUTPUT_START + Memory::OUTPUT_SIZE {
            return Some(Perm::READ | Perm::WRITE);
        }
        let stack_end = Memory::STACK_START + self.stack_limit;
        if addr >= Memory::STACK_START && end <= stack_end {
            return Some(Perm::READ | Perm::WRITE);
        }
        if addr > stack_end && end <= stack_end + Memory::STACK_SLOP {
            return Some(Perm::READ | Perm::WRITE);
        }
        None
    }
    /// Check that an address range has the required permissions.
    #[inline]
    fn check_perm(&self, addr: u64, size: u32, required: Perm) -> Result<(), VMError> {
        self.call_frames
            .check_access(addr, u64::from(size), required)?;
        if let Some(perm) = self.region_perm(addr, size) {
            if likely(perm.contains(required)) {
                Ok(())
            } else {
                Err(VMError::MemoryAccessViolation {
                    addr: addr as u32,
                    perm: required,
                })
            }
        } else {
            Err(VMError::MemoryAccessViolation {
                addr: addr as u32,
                perm: required,
            })
        }
    }
    /// Load an 8-bit value from memory.
    #[inline]
    pub fn load_u8(&self, addr: u64) -> Result<u8, VMError> {
        self.check_perm(addr, 1, Perm::READ)?;
        self.record_read_range(addr, 1, DiagnosticMemoryAccessKind::Read)?;
        Ok(self.data[addr as usize])
    }
    /// Load a 32-bit value (little-endian) from memory.
    #[inline]
    pub fn load_u32(&self, addr: u64) -> Result<u32, VMError> {
        self.load_u32_with_kind(addr, DiagnosticMemoryAccessKind::Read)
    }

    /// Fetch a code word through the existing checked read path.
    ///
    /// The read-set behavior stays identical to `load_u32`; an attached local
    /// diagnostic bus identifies the transfer as an instruction fetch.
    pub(crate) fn load_instruction_u32(&self, addr: u64) -> Result<u32, VMError> {
        self.load_u32_with_kind(addr, DiagnosticMemoryAccessKind::InstructionFetch)
    }

    fn load_u32_with_kind(
        &self,
        addr: u64,
        kind: DiagnosticMemoryAccessKind,
    ) -> Result<u32, VMError> {
        if unlikely(!addr.is_multiple_of(4)) {
            return Err(VMError::MisalignedAccess { addr: addr as u32 });
        }
        self.check_perm(addr, 4, Perm::READ)?;
        let bytes: [u8; 4] = self.data[addr as usize..addr as usize + 4]
            .try_into()
            .unwrap();
        self.record_read_range(addr, 4, kind)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Record a prepared instruction against the loaded code image without
    /// changing the ordinary prepared path's read set.
    pub(crate) fn diagnostic_record_prepared_fetch(
        &self,
        pc: u64,
        instruction: u32,
    ) -> Result<(), VMError> {
        let Some(recorder) = &self.diagnostic_access_recorder else {
            return Ok(());
        };
        let end = pc.checked_add(4).ok_or(VMError::DecodeError)?;
        // The prepared-program owner already authenticates the instruction
        // boundary relative to its admitted executable origin. A variable-size
        // contract prefix can place that origin at any physical byte alignment.
        if end > self.code_length {
            return Err(VMError::DecodeError);
        }
        let start = usize::try_from(pc).map_err(|_| VMError::DecodeError)?;
        let bytes = self
            .data
            .get(start..start.checked_add(4).ok_or(VMError::DecodeError)?)
            .ok_or(VMError::DecodeError)?;
        if bytes != instruction.to_le_bytes() {
            return Err(VMError::DecodeError);
        }
        recorder.record_read(pc, bytes, DiagnosticMemoryAccessKind::InstructionFetch)
    }
    /// Load a 64-bit value from memory.
    #[inline]
    pub fn load_u64(&self, addr: u64) -> Result<u64, VMError> {
        if unlikely(!addr.is_multiple_of(8)) {
            return Err(VMError::MisalignedAccess { addr: addr as u32 });
        }
        self.check_perm(addr, 8, Perm::READ)?;
        self.record_read_range(addr, 8, DiagnosticMemoryAccessKind::Read)?;
        let bytes: [u8; 8] = self.data[addr as usize..addr as usize + 8]
            .try_into()
            .unwrap();
        Ok(u64::from_le_bytes(bytes))
    }
    /// Read an initialized result slot for the interpreter's trusted return transition.
    /// Guest reads remain forbidden while the result table is borrowed for writing.
    pub(crate) fn active_call_result(&self, index: usize) -> Result<(u64, u64), VMError> {
        let address = self.call_frames.active_result_word(index)?;
        if !self
            .region_perm(address, 8)
            .is_some_and(|perm| perm.contains(Perm::READ))
        {
            return Err(VMError::MemoryOutOfBounds);
        }
        let bytes = self.data[address as usize..address as usize + 8]
            .try_into()
            .map_err(|_| VMError::MemoryOutOfBounds)?;
        self.record_read_range(address, 8, DiagnosticMemoryAccessKind::CallResultRead)?;
        Ok((address, u64::from_le_bytes(bytes)))
    }
    /// Load a 128-bit value from memory (little endian).
    #[inline]
    pub fn load_u128(&self, addr: u64) -> Result<u128, VMError> {
        if unlikely(!addr.is_multiple_of(16)) {
            return Err(VMError::MisalignedAccess { addr: addr as u32 });
        }
        self.check_perm(addr, 16, Perm::READ)?;
        let bytes: [u8; 16] = self.data[addr as usize..addr as usize + 16]
            .try_into()
            .unwrap();
        self.record_read_range(addr, 16, DiagnosticMemoryAccessKind::Read)?;
        Ok(u128::from_le_bytes(bytes))
    }
    /// Copy `out.len()` bytes starting at `addr` into `out`.
    #[inline]
    pub fn load_bytes(&self, addr: u64, out: &mut [u8]) -> Result<(), VMError> {
        let len = u64::try_from(out.len()).map_err(|_| VMError::MemoryAccessViolation {
            addr: addr as u32,
            perm: Perm::READ,
        })?;
        let (start, end) = self.checked_region_bounds_for(addr, len, Perm::READ)?;
        self.record_read_range(addr, len, DiagnosticMemoryAccessKind::HostRead)?;
        out.copy_from_slice(&self.data[start..end]);
        Ok(())
    }
    /// Validate a complete host transfer range without reading or mutating guest memory.
    pub(crate) fn checked_region_bounds_for(
        &self,
        addr: u64,
        len: u64,
        required: Perm,
    ) -> Result<(usize, usize), VMError> {
        let violation = || VMError::MemoryAccessViolation {
            addr: addr as u32,
            perm: required,
        };
        let len_u32 = u32::try_from(len).map_err(|_| violation())?;
        self.check_perm(addr, len_u32, required)?;
        let start = usize::try_from(addr).map_err(|_| violation())?;
        let len_usize = usize::try_from(len).map_err(|_| VMError::MemoryAccessViolation {
            addr: addr as u32,
            perm: required,
        })?;
        let Some(end) = start.checked_add(len_usize) else {
            return Err(violation());
        };
        if end > self.data.len() {
            return Err(violation());
        }
        Ok((start, end))
    }
    fn checked_region_bounds(&self, addr: u64, len: u64) -> Result<(usize, usize), VMError> {
        self.checked_region_bounds_for(addr, len, Perm::READ)
    }
    /// Inspect `len` bytes without recording a guest-visible memory access.
    ///
    /// This is reserved for side-effect-free host quote preparation. Actual syscall execution must
    /// use [`Self::load_region`] so access tracing remains complete.
    #[inline]
    pub(crate) fn inspect_region(&self, addr: u64, len: u64) -> Result<&[u8], VMError> {
        let (start, end) = self.checked_region_bounds(addr, len)?;
        Ok(&self.data[start..end])
    }
    /// Load `len` bytes starting at `addr` and return a slice referencing the underlying memory.
    #[inline]
    pub fn load_region(&self, addr: u64, len: u64) -> Result<&[u8], VMError> {
        let (start, end) = self.checked_region_bounds(addr, len)?;
        self.record_read_range(addr, len, DiagnosticMemoryAccessKind::HostRead)?;
        Ok(&self.data[start..end])
    }
    /// Copy bytes from `bytes` into memory starting at `addr`.
    #[inline]
    pub fn store_bytes(&mut self, addr: u64, bytes: &[u8]) -> Result<(), VMError> {
        let len = u64::try_from(bytes.len()).map_err(|_| VMError::MemoryAccessViolation {
            addr: addr as u32,
            perm: Perm::WRITE,
        })?;
        let (start, end) = self.checked_region_bounds_for(addr, len, Perm::WRITE)?;
        let output_cursor = self.checked_output_append_cursor(addr, len)?;
        let tracking = self.prepare_write_tracking(addr, bytes)?;
        self.output_cursor = output_cursor;
        self.data[start..end].copy_from_slice(bytes);
        self.update_merkle(start, bytes.len());
        self.record_write(tracking);
        Ok(())
    }
    /// Store an 8-bit value into memory.
    #[inline]
    pub fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), VMError> {
        self.check_perm(addr, 1, Perm::WRITE)?;
        let output_cursor = self.checked_output_append_cursor(addr, 1)?;
        let tracking = self.prepare_write_tracking(addr, &[value])?;
        self.output_cursor = output_cursor;
        self.data[addr as usize] = value;
        self.update_merkle(addr as usize, 1);
        self.record_write(tracking);
        Ok(())
    }
    /// Store a 32-bit value (little-endian) into memory.
    #[inline]
    pub fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), VMError> {
        if unlikely(!addr.is_multiple_of(4)) {
            return Err(VMError::MisalignedAccess { addr: addr as u32 });
        }
        self.check_perm(addr, 4, Perm::WRITE)?;
        let output_cursor = self.checked_output_append_cursor(addr, 4)?;
        let bytes = value.to_le_bytes();
        let tracking = self.prepare_write_tracking(addr, &bytes)?;
        self.output_cursor = output_cursor;
        self.data[addr as usize..addr as usize + 4].copy_from_slice(&bytes);
        self.update_merkle(addr as usize, 4);
        self.record_write(tracking);
        Ok(())
    }
    /// Store a 64-bit value into memory.
    #[inline]
    pub fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), VMError> {
        if unlikely(!addr.is_multiple_of(8)) {
            return Err(VMError::MisalignedAccess { addr: addr as u32 });
        }
        self.check_perm(addr, 8, Perm::WRITE)?;
        let output_cursor = self.checked_output_append_cursor(addr, 8)?;
        let bytes = value.to_le_bytes();
        let tracking = self.prepare_write_tracking(addr, &bytes)?;
        self.output_cursor = output_cursor;
        self.data[addr as usize..addr as usize + 8].copy_from_slice(&bytes);
        self.record_write(tracking);
        self.update_merkle(addr as usize, 8);
        Ok(())
    }
    /// Store a 128-bit value into memory.
    #[inline]
    pub fn store_u128(&mut self, addr: u64, value: u128) -> Result<(), VMError> {
        if unlikely(!addr.is_multiple_of(16)) {
            return Err(VMError::MisalignedAccess { addr: addr as u32 });
        }
        self.check_perm(addr, 16, Perm::WRITE)?;
        let output_cursor = self.checked_output_append_cursor(addr, 16)?;
        let bytes = value.to_le_bytes();
        let tracking = self.prepare_write_tracking(addr, &bytes)?;
        self.output_cursor = output_cursor;
        self.data[addr as usize..addr as usize + 16].copy_from_slice(&bytes);
        self.update_merkle(addr as usize, 16);
        self.record_write(tracking);
        Ok(())
    }
    /// Obtain a slice of the entire output region without allocating.
    #[inline]
    pub fn read_output(&self) -> &[u8] {
        let start = Memory::OUTPUT_START as usize;
        let end = start + Memory::OUTPUT_SIZE as usize;
        &self.data[start..end]
    }
    /// Number of bytes in the append-only prefix written by the guest.
    #[inline]
    pub fn output_used_len(&self) -> u64 {
        self.output_cursor
    }
    /// Borrow only the append-only output prefix written by the guest.
    #[inline]
    pub fn read_output_used(&self) -> &[u8] {
        let start = Memory::OUTPUT_START as usize;
        let used = usize::try_from(self.output_cursor).unwrap_or(Memory::OUTPUT_SIZE as usize);
        &self.data[start..start.saturating_add(used)]
    }
    /// Clear the OUTPUT region and reset the append-only cursor.
    pub(crate) fn clear_output(&mut self) -> Result<(), VMError> {
        let start = Memory::OUTPUT_START as usize;
        let end = start + Memory::OUTPUT_SIZE as usize;
        if self.output_cursor == 0 && self.data[start..end].iter().all(|b| *b == 0) {
            return Ok(());
        }
        if let Some(recorder) = &self.diagnostic_access_recorder {
            recorder.record_zero_fill(
                Memory::OUTPUT_START,
                &self.data[start..end],
                DiagnosticMemoryAccessKind::OutputReset,
            )?;
        }
        self.data[start..end].fill(0);
        self.output_cursor = 0;
        self.update_merkle(start, end - start);
        Ok(())
    }
    /// Clear recorded access information.
    pub fn clear_tracking(&self) {
        self.with_read_log(ReadLog::clear);
        self.with_write_log(WriteLog::clear);
    }
    /// Detach an immutable, independently accounted snapshot of recorded reads.
    ///
    /// The snapshot holds no Memory lock across later loads or clears.
    ///
    /// # Errors
    /// Defers locally if original-pool credit or row allocation is unavailable.
    pub fn try_read_log_snapshot(&self) -> Result<ReadLogSnapshot, VMError> {
        self.with_read_log(|log| log.try_snapshot())
    }

    // Replacement and snapshot failures can refund original execution credit.
    // Waiter callbacks must run after the read-log mutex releases, even on unwind.
    fn with_read_log<R>(&self, operation: impl FnOnce(&mut ReadLog) -> R) -> R {
        match self.allocation_budget() {
            Some(budget) => {
                budget.with_deferred_refund_notifications(|_| operation(&mut self.read_log.lock()))
            }
            None => operation(&mut self.read_log.lock()),
        }
    }
    /// Detach an immutable, independently accounted snapshot of recorded writes.
    ///
    /// The snapshot owns its bytes and holds no Memory lock across later stores.
    ///
    /// # Errors
    /// Defers locally if snapshot row or payload storage cannot be allocated.
    pub fn try_write_log_snapshot(&self) -> Result<WriteLogSnapshot, VMError> {
        self.with_write_log(|log| log.try_snapshot())
    }

    // A charge refund may run a capacity-waiter callback. Keep every such
    // callback outside the write-log lock, including failure and unwind paths.
    fn with_write_log<R>(&self, operation: impl FnOnce(&mut WriteLog) -> R) -> R {
        match self.allocation_budget() {
            Some(budget) => {
                budget.with_deferred_refund_notifications(|_| operation(&mut self.write_log.lock()))
            }
            None => operation(&mut self.write_log.lock()),
        }
    }
    /// Ranges of memory that have been modified since the last commit.
    pub fn dirty_ranges(&self) -> Vec<(usize, usize)> {
        const CHUNK: usize = 32;
        let mut ranges = Vec::new();
        let mut start = None;
        let mut prev = 0;
        for idx in self.dirty_chunks.iter() {
            if let Some(s) = start {
                if idx == prev + 1 {
                    prev = idx;
                    continue;
                } else {
                    ranges.push((s * CHUNK, (prev + 1) * CHUNK));
                }
            }
            start = Some(idx);
            prev = idx;
        }
        if let Some(s) = start {
            ranges.push((s * CHUNK, (prev + 1) * CHUNK));
        }
        ranges
    }
    /// Mark the current bytes as an immutable runtime-template baseline.
    pub(crate) fn mark_template_clean(&mut self) {
        self.modified_chunks.clear();
        self.template_generation = self
            .template_generation
            .checked_add(1)
            .expect("IVM memory template generation exhausted");
        self.baseline_lineage = crate::cache_memory::SharedValue::new((), Some(0));
        self.clear_tracking();
    }
    /// Return the current runtime-template lifecycle generation.
    pub(crate) const fn template_generation(&self) -> u64 {
        self.template_generation
    }
    /// Whether this memory image descends from the same captured runtime baseline.
    pub(crate) fn shares_baseline_lineage(&self, other: &Self) -> bool {
        crate::cache_memory::SharedValue::ptr_eq(&self.baseline_lineage, &other.baseline_lineage)
    }

    /// The exact State pool survives every immutable template derived from this VM.
    pub(crate) fn allocation_budget(&self) -> Option<&AllocationBudget> {
        self.call_frames.allocation_budget()
    }

    /// Plan the clone's requested layouts before any snapshot allocation.
    ///
    /// Both dirty bitmaps reserve their complete geometry, independently of
    /// the current number of set bits. Vec copies use exact reserve, and fixed
    /// images, leaves and bitmaps use move-only funded buffers.
    /// The caller holds exclusive VM access until the clone is complete.
    pub(crate) fn runtime_template_memory_plan(&self) -> Result<ExecutionMemoryPlan, VMError> {
        let mut plan = ExecutionMemoryPlan::array::<u8>(self.data.len())
            .map_err(VMError::AllocationDeferred)?;
        plan.include_child(DirtyChunks::memory_plan(self.dirty_chunks.chunks())?)
            .map_err(VMError::AllocationDeferred)?;
        plan.include_child(DirtyChunks::memory_plan(self.modified_chunks.chunks())?)
            .map_err(VMError::AllocationDeferred)?;
        plan.include_child(self.read_log.lock().memory_plan()?)
            .map_err(VMError::AllocationDeferred)?;
        plan.include_child(self.write_log.lock().memory_plan()?)
            .map_err(VMError::AllocationDeferred)?;
        plan.include_child(self.tree.runtime_template_memory_plan()?)
            .map_err(VMError::AllocationDeferred)?;
        Ok(plan)
    }

    /// Copy a frame-inactive memory image, reserving each owned allocation
    /// before constructing it. The image can become a runtime baseline or a
    /// sequential block checkpoint.
    pub(crate) fn try_clone_for_runtime_template(
        &self,
        mut lease: Option<&mut ExecutionMemoryLease>,
    ) -> Result<Self, VMError> {
        let unavailable =
            || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
        if !self.call_frames.is_empty() {
            return Err(unavailable());
        }
        let data = if let Some(lease) = lease.as_deref_mut() {
            let mut copied =
                ExecutionBuffer::new(self.data.len(), lease).map_err(|_| unavailable())?;
            copied.append(&self.data).map_err(|_| unavailable())?;
            MemoryImage::Funded(copied)
        } else {
            let mut copied = crate::cache_memory::OwnedAllocation::try_zeroed(self.data.len())
                .map_err(|_| unavailable())?;
            copied.copy_from_slice(&self.data);
            MemoryImage::Local(copied)
        };
        let reads = self.with_read_log(|log| log.try_copy(lease.as_deref_mut()))?;
        let copied_writes = self.with_write_log(|log| log.try_copy(lease.as_deref_mut()))?;
        let mut copied = Self {
            // An empty frame stack has no nested owned buffers; retain its
            // scalar completed-result descriptor for exact runtime snapshots.
            call_frames: self.call_frames.copy_inactive(),
            data,
            stack_limit: self.stack_limit,
            heap_alloc: self.heap_alloc,
            heap_limit: self.heap_limit,
            heap_max_limit: self.heap_max_limit,
            heap_contains_data: self.heap_contains_data,
            code_length: self.code_length,
            output_cursor: self.output_cursor,
            root: self.root,
            tree: self
                .tree
                .try_clone_for_runtime_template(lease.as_deref_mut())?,
            dirty: self.dirty,
            dirty_chunks: self.dirty_chunks.try_copy(lease.as_deref_mut())?,
            modified_chunks: self.modified_chunks.try_copy(lease)?,
            template_generation: self.template_generation,
            baseline_lineage: self.baseline_lineage.clone(),
            read_log: Mutex::new(reads),
            write_log: Mutex::new(copied_writes),
            diagnostic_access_recorder: None,
        };
        if !copied.prepare_for_cache() {
            return Err(unavailable());
        }
        Ok(copied)
    }
    pub(crate) fn reset_from_template(
        &mut self,
        template: &Memory,
    ) -> Result<(), MemoryTemplateMismatch> {
        self.ensure_template_geometry(template)?;
        const CHUNK: usize = 32;
        let modified_chunks = &self.modified_chunks;
        let indices = || modified_chunks.iter();
        // Independent leaves commute. Streaming the same sources twice keeps
        // the memory and Merkle images aligned without allocating reset scratch.
        for index in indices() {
            let start = index.saturating_mul(CHUNK);
            if start >= self.data.len() {
                continue;
            }
            let end = (start + CHUNK).min(self.data.len());
            self.data[start..end].copy_from_slice(&template.data[start..end]);
        }
        self.tree.reset_leaves_from(&template.tree, indices());
        self.heap_alloc = template.heap_alloc;
        self.heap_limit = template.heap_limit;
        self.heap_max_limit = template.heap_max_limit;
        self.heap_contains_data = template.heap_contains_data;
        self.code_length = template.code_length;
        self.output_cursor = template.output_cursor;
        self.root = template.root;
        self.dirty = template.dirty;
        // Equal geometry already owns every bit; warm reset copies initialized
        // words without allocating or requesting more execution credit.
        self.dirty_chunks.copy_from(&template.dirty_chunks);
        self.modified_chunks.clear();
        self.call_frames
            .restore_inactive_from(&template.call_frames);
        self.clear_tracking();
        Ok(())
    }
    /// Validate that two images can use the same in-place reset geometry.
    pub(crate) fn ensure_template_geometry(
        &self,
        template: &Memory,
    ) -> Result<(), MemoryTemplateMismatch> {
        let current = self.geometry();
        let template = template.geometry();
        if current == template {
            Ok(())
        } else {
            Err(MemoryTemplateMismatch { current, template })
        }
    }
    fn geometry(&self) -> MemoryGeometry {
        MemoryGeometry {
            bytes: self.data.len(),
            stack_limit: self.stack_limit,
            heap_max_limit: self.heap_max_limit,
            merkle_chunk_bytes: self.tree.chunk_size(),
            merkle_leaves: self.tree.leaf_count(),
        }
    }
    fn record_read_range(
        &self,
        addr: u64,
        len: u64,
        kind: DiagnosticMemoryAccessKind,
    ) -> Result<(), VMError> {
        let unavailable =
            || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
        #[cfg(test)]
        if REFUSE_NEXT_READ_TRACKING.with(|refuse| refuse.replace(false)) {
            return Err(unavailable());
        }
        self.with_read_log(|reads| {
            let replacement = reads.prepare_growth()?;
            if let Some(recorder) = &self.diagnostic_access_recorder {
                let start = usize::try_from(addr).map_err(|_| unavailable())?;
                let len = usize::try_from(len).map_err(|_| unavailable())?;
                let end = start.checked_add(len).ok_or_else(unavailable)?;
                let bytes = self.data.get(start..end).ok_or_else(unavailable)?;
                recorder.record_read(addr, bytes, kind)?;
            }
            // Both logs accept the complete access before caller output changes.
            reads.record_prepared(replacement, AccessRange { addr, len });
            Ok(())
        })
    }
    fn prepare_write_tracking(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<WriteLogEntry, VMError> {
        let unavailable =
            || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
        let copied = self.with_exclusive_write_log(|log| log.prepare(addr, bytes))?;
        let start = usize::try_from(addr).map_err(|_| unavailable())?;
        let end = start.checked_add(bytes.len()).ok_or_else(unavailable)?;
        if let Some(recorder) = &self.diagnostic_access_recorder {
            let previous = self.data.get(start..end).ok_or_else(unavailable)?;
            recorder.record_write(addr, previous, bytes, DiagnosticMemoryAccessKind::Write)?;
        }
        Ok(copied)
    }

    fn record_write(&mut self, entry: WriteLogEntry) {
        self.call_frames
            .record_write(entry.address(), entry.bytes().len() as u64);
        // The prepared-capacity invariant normally makes this infallible. Keep
        // payload refunds deferred even if that invariant unwinds.
        self.with_exclusive_write_log(|log| log.record_prepared(entry));
    }

    /// Run a store's write-log step through `&mut Memory` without locking.
    ///
    /// Exclusive access already rules out every concurrent log user, so only
    /// the original pool's deferred refund scope remains: capacity-waiter
    /// callbacks still run after the operation, exactly as on the locked path.
    fn with_exclusive_write_log<R>(&mut self, operation: impl FnOnce(&mut WriteLog) -> R) -> R {
        let log = self.write_log.get_mut();
        match self.call_frames.allocation_budget() {
            Some(budget) => budget.with_deferred_refund_notifications(|_| operation(log)),
            None => operation(log),
        }
    }
    /// Overwrite just the code region with bytes from another Memory.
    pub fn overlay_code(&mut self, src: &Memory) -> Result<(), VMError> {
        let len = src.code_length as usize;
        self.load_code(&src.data[0..len])
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}
impl Memory {
    #[inline]
    fn checked_output_append_cursor(&self, addr: u64, len: u64) -> Result<u64, VMError> {
        // Only enforce within OUTPUT region; allow arbitrary writes elsewhere.
        let start = Memory::OUTPUT_START;
        let end = Memory::OUTPUT_START + Memory::OUTPUT_SIZE;
        let write_end = addr.saturating_add(len);
        if addr >= start && write_end <= end {
            // Convert absolute addr to offset within OUTPUT
            let off = addr - start;
            // Relaxed monotonic append: allow forward writes at or beyond the
            // current cursor; disallow rewinding into already-written region.
            if off < self.output_cursor {
                return Err(VMError::MemoryAccessViolation {
                    addr: addr as u32,
                    perm: Perm::WRITE,
                });
            }
            let new_end = off.saturating_add(len);
            return Ok(self.output_cursor.max(new_end));
        }
        Ok(self.output_cursor)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_utils::compute_memory_leaf_digest;
    use iroha_crypto::{Hash, HashOf, MerkleProof};

    #[test]
    fn funded_large_commit_keeps_leaf_owner_and_matches_local_root() {
        let stack_limit = Memory::MIN_STACK_SIZE;
        let image_bytes = Memory::image_bytes_for_stack_limit(stack_limit).unwrap();
        let leaf_bytes = image_bytes.div_ceil(32) * 32;
        let node_bytes =
            MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(image_bytes.div_ceil(32))
                .unwrap();
        let bitmap_bytes = 2 * image_bytes.div_ceil(32).div_ceil(64) * 8;
        let log_bytes = 4 * std::mem::size_of::<WriteLogEntry>() + 1;
        let budget =
            AllocationBudget::new(image_bytes + leaf_bytes + node_bytes + bitmap_bytes + log_bytes);
        let mut funded = Memory::new_with_stack_limit_funded(stack_limit, &budget).unwrap();
        let mut local = Memory::new_with_stack_limit(stack_limit).unwrap();
        funded.store_u8(Memory::STACK_START, 0xa5).unwrap();
        local.store_u8(Memory::STACK_START, 0xa5).unwrap();
        let leaf_count = funded.tree.leaf_count();
        funded.dirty_chunks.extend(0..=leaf_count / 2);
        funded.commit();
        local.commit();
        assert_eq!(funded.current_root(), local.current_root());
        assert_eq!(
            budget.reserved_bytes(),
            image_bytes + leaf_bytes + node_bytes + bitmap_bytes + log_bytes
        );
        drop(funded);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn funded_memory_passes_its_original_pool_to_root_frame_preparation() {
        use crate::call_frame::CallFrameShape;

        let frame_backing_bytes = crate::call_frame::frame_backing_bytes_for_test();
        let stack_limit = Memory::MIN_STACK_SIZE;
        let image_bytes = Memory::image_bytes_for_stack_limit(stack_limit).unwrap();
        let leaf_bytes = image_bytes.div_ceil(32) * 32;
        let node_bytes =
            MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(image_bytes.div_ceil(32))
                .unwrap();
        let bitmap_bytes = 2 * image_bytes.div_ceil(32).div_ceil(64) * 8;
        let base_bytes = image_bytes + leaf_bytes + node_bytes + bitmap_bytes;
        let budget = AllocationBudget::new(base_bytes);
        let mut memory = Memory::new_with_stack_limit_funded(stack_limit, &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), base_bytes);
        let callable = CallFrameShape {
            entry_pc: 0,
            frame_bytes: 128,
            argument_words: 1,
            result_words: 1,
        };
        let tables = crate::call_frame::CallTables {
            argument_base: Memory::HEAP_START,
            argument_words: 1,
            result_base: Memory::HEAP_START + 16,
            result_words: 1,
        };
        let top = Memory::STACK_START + 128;
        assert!(matches!(
            memory.call_frames.prepare_root(top, &callable, tables, top),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), base_bytes);
        budget.set_limit_bytes(base_bytes + frame_backing_bytes + 17);
        memory
            .call_frames
            .enter_root(top, &callable, tables, top)
            .unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            base_bytes + frame_backing_bytes + 17
        );
        memory.call_frames.clear();
        assert_eq!(budget.reserved_bytes(), base_bytes + frame_backing_bytes);
        assert!(memory.call_frames.compact_for_cache());
        assert_eq!(budget.reserved_bytes(), base_bytes);
        drop(memory);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn template_bitmap_plan_is_fixed_by_geometry_and_copies_exact_bits() {
        let mut source = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        let fixed_bytes = source
            .runtime_template_memory_plan()
            .unwrap()
            .requested_bytes();
        let bitmap_bytes = 2 * source.tree.leaf_count().div_ceil(64) * 8;
        assert_eq!(
            fixed_bytes,
            source.data.len()
                + source
                    .tree
                    .runtime_template_memory_plan()
                    .unwrap()
                    .requested_bytes()
                + bitmap_bytes
        );
        for entries in [0, 1, 3, 4, 7, 8, 14, 15, 28, 29, 63, 64, 65, 127, 128] {
            source.dirty_chunks.clear();
            source.modified_chunks.clear();
            source.dirty_chunks.extend((0..entries).rev());
            source.modified_chunks.extend(0..entries);
            assert_eq!(
                source
                    .runtime_template_memory_plan()
                    .unwrap()
                    .requested_bytes(),
                fixed_bytes
            );
            let mut copy = source.try_clone_for_runtime_template(None).unwrap();
            assert_eq!(copy.dirty_chunks, source.dirty_chunks);
            assert_eq!(copy.modified_chunks, source.modified_chunks);
            assert_ne!(
                copy.dirty_chunks.words().as_ptr(),
                source.dirty_chunks.words().as_ptr()
            );
            assert_ne!(
                copy.modified_chunks.words().as_ptr(),
                source.modified_chunks.words().as_ptr()
            );
            // Fixed owners carry their own charge; retained scratch must not charge them twice.
            assert!(copy.prepare_for_cache());
            assert!(copy.write_log.lock().is_empty());
        }
    }

    #[test]
    fn funded_bitmap_constructor_refusal_and_final_owner_keep_original_credit() {
        let stack_limit = Memory::MIN_STACK_SIZE;
        let image_bytes = Memory::image_bytes_for_stack_limit(stack_limit).unwrap();
        let leaf_count = image_bytes.div_ceil(32);
        let bitmap_bytes = 2 * leaf_count.div_ceil(64) * 8;
        let node_bytes =
            MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(leaf_count).unwrap();
        let total_bytes = image_bytes + leaf_count * 32 + node_bytes + bitmap_bytes;
        let budget = AllocationBudget::new(total_bytes - 1);
        assert!(matches!(
            Memory::new_with_stack_limit_funded(stack_limit, &budget),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(total_bytes);
        let mut memory = Memory::new_with_stack_limit_funded(stack_limit, &budget).unwrap();
        budget.set_limit_bytes(0);
        let dirty_words = memory.dirty_chunks.words().as_ptr();
        let modified_words = memory.modified_chunks.words().as_ptr();
        memory.preload_input(0, &[0xa5; 129]).unwrap();
        assert!(matches!(
            memory.store_u64(Memory::STACK_START, 0x1234),
            Err(VMError::AllocationDeferred(_))
        ));
        let log_bytes = 4 * std::mem::size_of::<WriteLogEntry>() + 8;
        budget.set_limit_bytes(total_bytes + log_bytes);
        memory.store_u64(Memory::STACK_START, 0x1234).unwrap();
        budget.set_limit_bytes(0);
        memory.commit();
        assert_eq!(memory.dirty_chunks.words().as_ptr(), dirty_words);
        assert_eq!(memory.modified_chunks.words().as_ptr(), modified_words);
        assert_eq!(budget.reserved_bytes(), total_bytes + log_bytes);
        let owner = std::sync::Arc::new(memory);
        let borrower = std::sync::Arc::clone(&owner);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), total_bytes + log_bytes);
        drop(borrower);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn exclusive_store_tracking_records_every_store_and_refunds_payloads_on_clear() {
        let budget = AllocationBudget::new(64 * 1024 * 1024);
        let mut memory =
            Memory::new_with_stack_limit_funded(Memory::MIN_STACK_SIZE, &budget).unwrap();
        let baseline = budget.reserved_bytes();
        memory.store_u8(Memory::OUTPUT_START, 1).unwrap();
        memory.store_u64(Memory::STACK_START, 0x0102).unwrap();
        memory.store_bytes(Memory::HEAP_START, &[7, 8, 9]).unwrap();
        let snapshot = memory.try_write_log_snapshot().unwrap();
        let rows: Vec<(u64, Vec<u8>)> = snapshot
            .iter()
            .map(|entry| (entry.address(), entry.bytes().to_vec()))
            .collect();
        assert_eq!(
            rows,
            vec![
                (Memory::OUTPUT_START, vec![1]),
                (Memory::STACK_START, 0x0102_u64.to_le_bytes().to_vec()),
                (Memory::HEAP_START, vec![7, 8, 9]),
            ]
        );
        drop(snapshot);
        let row_bytes = 4 * std::mem::size_of::<WriteLogEntry>();
        assert_eq!(budget.reserved_bytes(), baseline + row_bytes + 1 + 8 + 3);
        memory.clear_tracking();
        assert_eq!(budget.reserved_bytes(), baseline + row_bytes);
        drop(memory);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn write_log_row_and_payload_refusal_preserve_existing_store_state() {
        let mut memory = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        let budget = crate::cache_memory::TestMemoryBudget::new(64 * 1024);
        memory.write_log = Mutex::new(WriteLog::with_test_budget(&budget));
        for index in 0..4 {
            memory
                .store_u8(Memory::OUTPUT_START + index, index as u8)
                .unwrap();
        }
        let before = memory.try_write_log_snapshot().unwrap();
        let root = memory.root();
        crate::cache_memory::refuse_next_owned_vec_growth_for_test();
        assert!(matches!(
            memory.store_u8(Memory::OUTPUT_START + 4, 9),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(memory.current_root(), root);
        assert_eq!(memory.output_used_len(), 4);
        assert_eq!(memory.read_output_used(), &[0, 1, 2, 3]);
        assert_eq!(memory.try_write_log_snapshot().unwrap(), before);
        crate::cache_memory::refuse_next_owned_allocation_for_test();
        assert!(memory.store_u8(Memory::OUTPUT_START + 4, 9).is_err());
        assert_eq!(memory.current_root(), root);
        assert_eq!(memory.output_used_len(), 4);
        assert_eq!(memory.try_write_log_snapshot().unwrap(), before);
        memory.store_u8(Memory::OUTPUT_START + 4, 9).unwrap();
        assert_eq!(memory.read_output_used(), &[0, 1, 2, 3, 9]);
        assert_eq!(before.len(), 4);
        let charged = budget.stats().measured_resident_bytes();
        assert!(memory.prepare_for_cache());
        assert_eq!(budget.stats().measured_resident_bytes(), charged);
        memory.clear_tracking();
        assert_eq!(before[3].address(), Memory::OUTPUT_START + 3);
        assert_eq!(before[3].bytes(), &[3]);
        drop(memory);
        assert!(budget.stats().measured_resident_bytes() > 0);
        drop(before);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
    }

    #[test]
    fn guest_store_tracking_refusal_preserves_memory_cursor_and_log() {
        let mut memory = Memory::new();
        let initial_root = memory.current_root();
        let mut next = Memory::OUTPUT_START;
        crate::cache_memory::refuse_next_owned_allocation_for_test();
        assert!(matches!(
            memory.store_u8(next, 0x5a),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(memory.output_used_len(), 0);
        assert_eq!(memory.current_root(), initial_root);
        assert!(
            memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot")
                .is_empty()
        );
        memory.store_u8(next, 0x5a).unwrap();
        next += 1;

        crate::cache_memory::refuse_next_owned_allocation_for_test();
        assert!(matches!(
            memory.store_bytes(next, &[0xa5, 0xc3, 0x7e]),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(memory.output_used_len(), 1);
        assert_eq!(memory.read_output_used(), &[0x5a]);
        assert_eq!(
            memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot")
                .len(),
            1
        );
        memory.store_bytes(next, &[0xa5, 0xc3, 0x7e]).unwrap();
        next += 3;

        crate::cache_memory::refuse_next_owned_allocation_for_test();
        assert!(matches!(
            memory.store_u32(next, 0x1234_5678),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(memory.output_used_len(), 4);
        memory.store_u32(next, 0x1234_5678).unwrap();
        next += 4;

        crate::cache_memory::refuse_next_owned_allocation_for_test();
        assert!(matches!(
            memory.store_u64(next, 0x0102_0304_0506_0708),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(memory.output_used_len(), 8);
        memory.store_u64(next, 0x0102_0304_0506_0708).unwrap();
        next += 8;

        crate::cache_memory::refuse_next_owned_allocation_for_test();
        assert!(matches!(
            memory.store_u128(next, 0x1020_3040_5060_7080_90a0_b0c0_d0e0_f000),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(memory.output_used_len(), 16);
        memory
            .store_u128(next, 0x1020_3040_5060_7080_90a0_b0c0_d0e0_f000)
            .unwrap();
        assert_eq!(
            memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot")
                .len(),
            5
        );
        assert_eq!(memory.output_used_len(), 32);
    }

    #[test]
    fn invalid_output_rewind_precedes_tracking_allocation() {
        let mut memory = Memory::new();
        memory.store_u8(Memory::OUTPUT_START, 7).unwrap();
        crate::cache_memory::refuse_next_owned_allocation_for_test();
        assert!(matches!(
            memory.store_u8(Memory::OUTPUT_START, 8),
            Err(VMError::MemoryAccessViolation {
                perm: Perm::WRITE,
                ..
            })
        ));
        assert_eq!(memory.output_used_len(), 1);
        assert_eq!(memory.read_output_used(), &[7]);
        assert!(matches!(
            memory.store_u8(Memory::OUTPUT_START + 1, 8),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(memory.output_used_len(), 1);
    }

    #[test]
    fn guest_read_tracking_refusal_leaves_outputs_and_logs_unchanged() {
        let memory = Memory::new();
        let address = Memory::OUTPUT_START;
        let reads: [fn(&Memory) -> Result<(), VMError>; 5] = [
            |memory| memory.load_u8(Memory::OUTPUT_START).map(|_| ()),
            |memory| memory.load_u32(Memory::OUTPUT_START).map(|_| ()),
            |memory| memory.load_u64(Memory::OUTPUT_START).map(|_| ()),
            |memory| memory.load_u128(Memory::OUTPUT_START).map(|_| ()),
            |memory| memory.load_region(Memory::OUTPUT_START, 2).map(|_| ()),
        ];
        for read in reads {
            REFUSE_NEXT_READ_TRACKING.set(true);
            assert!(matches!(
                read(&memory),
                Err(VMError::ExecutionDeferred(
                    crate::error::ExecutionDeferral::AllocationUnavailable
                ))
            ));
            assert!(
                memory
                    .try_read_log_snapshot()
                    .expect("allocate read-log snapshot")
                    .is_empty()
            );
        }

        let mut output = [0xa5, 0xc3];
        REFUSE_NEXT_READ_TRACKING.set(true);
        assert!(matches!(
            memory.load_bytes(address, &mut output),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(output, [0xa5, 0xc3]);
        assert!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")
                .is_empty()
        );

        REFUSE_NEXT_READ_TRACKING.set(true);
        assert!(matches!(
            memory.load_u8(0),
            Err(VMError::MemoryAccessViolation {
                perm: Perm::READ,
                ..
            })
        ));
        assert!(matches!(
            memory.load_u8(address),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")
                .is_empty()
        );

        memory.load_bytes(address, &mut output).unwrap();
        assert_eq!(output, [0, 0]);
        assert_eq!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")[..],
            vec![AccessRange {
                addr: address,
                len: 2
            }]
        );
    }
    #[test]
    fn read_log_growth_refusal_preserves_accesses_and_retry() {
        let mut memory = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        let address = Memory::OUTPUT_START;
        memory.load_u8(address).unwrap();
        while {
            let reads = memory.read_log.lock();
            reads.len() < reads.capacity()
        } {
            memory.load_u8(address).unwrap();
        }
        let before = memory
            .try_read_log_snapshot()
            .expect("allocate read-log snapshot");
        assert!(memory.read_log.lock().capacity() > 0);
        assert!(memory.prepare_for_cache());
        assert!(memory.write_log.lock().is_empty());
        let before_root = memory.current_root();
        crate::cache_memory::refuse_next_owned_vec_growth_for_test();
        assert!(matches!(
            memory.load_u8(address),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot"),
            before
        );
        assert_eq!(memory.current_root(), before_root);
        memory.load_u8(address).unwrap();
        assert_eq!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")
                .len(),
            before.len() + 1
        );
    }
    #[test]
    fn fallible_template_memory_copy_preserves_bytes_root_and_lineage() {
        let mut source =
            Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).expect("bounded test memory");
        source
            .store_u64(Memory::STACK_START, 0x1234_5678)
            .expect("owned stack write");
        source.mark_template_clean();
        source
            .store_u64(Memory::STACK_START + 8, 0x9abc_def0)
            .expect("tracked stack write");
        assert!(!source.modified_chunks.is_empty());
        assert_eq!(
            (source.load_u64(Memory::STACK_START + 8)).expect("expected successful fixture result"),
            0x9abc_def0
        );
        let mut copied = source
            .try_clone_for_runtime_template(None)
            .expect("bounded template copy");
        assert!(copied.shares_baseline_lineage(&source));
        assert_ne!(copied.data.as_ptr(), source.data.as_ptr());
        assert_eq!(copied.modified_chunks, source.modified_chunks);
        assert_eq!(&**copied.read_log.lock(), &**source.read_log.lock());
        assert_eq!(*copied.write_log.lock(), *source.write_log.lock());
        assert_eq!(
            (copied.load_u64(Memory::STACK_START)).expect("expected successful fixture result"),
            0x1234_5678
        );
        assert_eq!(copied.root(), source.root());
    }

    #[test]
    fn reset_from_template_restores_runtime_regions() {
        let mut base = Memory::new();
        base.preload_input(0, &[1, 2, 3, 4])
            .expect("preload template input");
        base.set_heap_limit(Memory::HEAP_MAX_SIZE - 128)
            .expect("lower template heap limit");
        let mut worker = base
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        worker.alloc(32).expect("alloc");
        worker
            .store_u64(Memory::OUTPUT_START, 0xDEAD_BEEF_DEAD_BEEFu64)
            .expect("store output");
        worker.grow_heap(64).expect("grow heap");
        assert!(!worker.modified_chunks.is_empty());
        let _ = worker.root();
        assert!(worker.dirty_chunks.is_empty());
        assert!(
            !worker.modified_chunks.is_empty(),
            "Merkle commits must retain reset tracking"
        );
        assert_ne!(&worker.read_output()[..8], &base.read_output()[..8],);
        worker
            .reset_from_template(&base)
            .expect("worker and template geometries match");
        assert_eq!(worker.heap_alloc, base.heap_alloc);
        assert_eq!(worker.heap_limit(), base.heap_limit());
        assert_eq!(worker.code_len(), base.code_len());
        assert_eq!(worker.read_output(), base.read_output());
        assert!(worker.modified_chunks.is_empty());
        let mut worker_clone = worker
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        let mut base_clone = base
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        assert_eq!(worker_clone.root(), base_clone.root());
    }
    #[test]
    fn warm_reset_does_not_copy_unmodified_memory_chunks() {
        let base = Memory::new();
        let mut worker = base
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        let tracked_address = Memory::HEAP_START;
        worker
            .store_u8(tracked_address, 0xA5)
            .expect("write tracked heap byte");
        // Deliberately perturb a different chunk without going through a Memory
        // write API. This is a test-only probe: a whole-image reset would erase
        // it, while a dirty-chunk reset must leave it untouched.
        const MERKLE_LEAF_BYTES: usize = 32;
        let untracked_address = usize::try_from(Memory::HEAP_START).expect("heap start fits usize")
            + 2 * MERKLE_LEAF_BYTES;
        worker.data[untracked_address] = 0x5A;
        worker
            .reset_from_template(&base)
            .expect("worker and template geometries match");
        assert_eq!(
            worker.data[usize::try_from(tracked_address).expect("tracked address fits usize")],
            0,
            "tracked chunks must be restored from the template"
        );
        assert_eq!(
            worker.data[untracked_address], 0x5A,
            "warm reset must not copy the complete memory image"
        );
    }
    #[test]
    fn shorter_code_load_clears_prior_tail_and_matches_fresh_root() {
        let short = [0x11, 0x22, 0x33, 0x44];
        let mut historical = Memory::new();
        historical.load_code(&[0xA5; 65]).unwrap();
        historical.commit();
        historical.load_code(&short).unwrap();

        let mut fresh = Memory::new();
        fresh.load_code(&short).unwrap();

        assert_eq!(&historical.data[..short.len()], &short);
        assert!(
            historical.data[short.len()..65]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(historical.current_root(), fresh.current_root());

        let mut overlaid = Memory::new();
        overlaid.load_code(&[0x5A; 65]).unwrap();
        overlaid.overlay_code(&fresh).unwrap();
        assert!(overlaid.data[short.len()..65].iter().all(|byte| *byte == 0));
        assert_eq!(overlaid.current_root(), fresh.current_root());
    }
    #[test]
    fn code_load_enforces_the_exact_code_region_and_is_atomic() {
        let mut memory = Memory::new();
        assert_eq!(memory.code_len(), 0);
        assert!(matches!(
            memory.load_u8(0),
            Err(VMError::MemoryAccessViolation {
                perm: Perm::READ,
                ..
            })
        ));

        let boundary = usize::try_from(Memory::HEAP_START).unwrap();
        let valid = vec![0xA5; boundary];
        memory
            .load_code(&valid)
            .expect("the code region's full extent is valid");
        assert_eq!(memory.code_len(), Memory::HEAP_START);
        assert_eq!(
            (memory.load_u8(Memory::HEAP_START - 1)).expect("expected successful fixture result"),
            0xA5
        );

        let invalid = vec![0x5A; boundary + 1];
        assert!(matches!(
            memory.load_code(&invalid),
            Err(VMError::MemoryOutOfBounds)
        ));
        assert_eq!(memory.code_len(), Memory::HEAP_START);
        assert_eq!(
            (memory.load_u8(0)).expect("expected successful fixture result"),
            0xA5
        );
        assert_eq!(
            (memory.load_u8(Memory::HEAP_START - 1)).expect("expected successful fixture result"),
            0xA5
        );
    }
    #[test]
    fn program_heap_clear_scrubs_inactive_capacity_and_resets_allocator() {
        let mut memory = Memory::new();
        memory
            .store_u64(Memory::HEAP_START, 0x1111)
            .expect("write active heap");
        let later_address = Memory::HEAP_START + 0x20_000;
        memory
            .store_u64(later_address, 0x2222)
            .expect("write future inactive heap");
        assert_eq!(
            (memory.alloc(16)).expect("expected successful fixture result"),
            Memory::HEAP_START
        );
        memory
            .set_heap_max_limit(0x1_000)
            .expect("tighten heap authority above allocation");
        let mut pristine = Memory::new();
        pristine
            .set_heap_max_limit(0x1_000)
            .expect("match heap authority");

        memory.clear_program_heap().unwrap();

        assert_eq!(memory.heap_allocated_len(), 0);
        assert_eq!(memory.heap_limit(), pristine.heap_limit());
        assert_eq!(memory.heap_max_limit(), pristine.heap_max_limit());
        assert_eq!(memory.data[Memory::HEAP_START as usize], 0);
        assert_eq!(memory.data[later_address as usize], 0);
        assert_eq!(memory.current_root(), pristine.current_root());
        assert_eq!(
            (memory.alloc(8)).expect("expected successful fixture result"),
            Memory::HEAP_START
        );
    }
    #[test]
    fn runtime_template_geometry_mismatch_fails_without_replacing_memory() {
        let mut worker = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        let template =
            Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE + Memory::STACK_ALIGNMENT).unwrap();
        worker
            .store_u8(Memory::HEAP_START, 0xA5)
            .expect("dirty worker memory");
        assert_eq!(
            worker
                .load_u8(Memory::HEAP_START)
                .expect("read dirty worker memory"),
            0xA5
        );
        let worker_geometry = worker.geometry();
        let template_geometry = template.geometry();
        let worker_data = worker.data.to_vec();
        let worker_root = worker.root;
        let worker_dirty = worker.dirty;
        let worker_dirty_chunks = worker.dirty_chunks.try_copy(None).unwrap();
        let worker_modified_chunks = worker.modified_chunks.try_copy(None).unwrap();
        let worker_reads = worker
            .try_read_log_snapshot()
            .expect("allocate read-log snapshot");
        let worker_writes = worker
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot");
        let error = worker
            .reset_from_template(&template)
            .expect_err("different stack geometry must reject warm reset");
        assert_eq!(
            error,
            MemoryTemplateMismatch {
                current: worker_geometry,
                template: template_geometry,
            }
        );
        assert_eq!(worker.geometry(), worker_geometry);
        assert_eq!(&worker.data[..], &worker_data[..]);
        assert_eq!(worker.root, worker_root);
        assert_eq!(worker.dirty, worker_dirty);
        assert_eq!(worker.dirty_chunks, worker_dirty_chunks);
        assert_eq!(worker.modified_chunks, worker_modified_chunks);
        assert_eq!(
            worker
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot"),
            worker_reads
        );
        assert_eq!(
            worker
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot"),
            worker_writes
        );
    }
    #[test]
    fn warm_reset_copies_prepaid_dirty_bits_after_original_budget_shrinks() {
        let stack_limit = Memory::MIN_STACK_SIZE;
        let mut template = Memory::new_with_stack_limit(stack_limit).unwrap();
        template.store_u8(Memory::HEAP_START, 0xA5).unwrap();
        let image_bytes = Memory::image_bytes_for_stack_limit(stack_limit).unwrap();
        let leaf_count = image_bytes.div_ceil(32);
        let node_bytes =
            MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(leaf_count).unwrap();
        let total_bytes =
            image_bytes + leaf_count * 32 + node_bytes + 2 * leaf_count.div_ceil(64) * 8;
        let row_bytes = 4 * std::mem::size_of::<WriteLogEntry>();
        let read_bytes = 4 * std::mem::size_of::<AccessRange>();
        let budget = AllocationBudget::new(total_bytes + row_bytes + 1 + read_bytes);
        let mut worker = Memory::new_with_stack_limit_funded(stack_limit, &budget).unwrap();
        worker.store_u8(Memory::HEAP_START, 0xB6).unwrap();
        assert_eq!(
            (worker.load_u8(Memory::HEAP_START)).expect("expected successful fixture result"),
            0xB6
        );
        worker.commit();
        assert!(worker.dirty_chunks.is_empty());
        assert!(!template.dirty_chunks.is_empty());
        let dirty_words = worker.dirty_chunks.words().as_ptr();
        let modified_words = worker.modified_chunks.words().as_ptr();
        budget.set_limit_bytes(0);
        for _ in 0..2 {
            worker.reset_from_template(&template).unwrap();
            assert_eq!(worker.dirty_chunks, template.dirty_chunks);
            assert_eq!(
                (worker.load_u8(Memory::HEAP_START)).expect("expected successful fixture result"),
                0xA5
            );
            assert_eq!(worker.dirty_chunks.words().as_ptr(), dirty_words);
            assert_eq!(worker.modified_chunks.words().as_ptr(), modified_words);
            assert!(worker.modified_chunks.is_empty());
            assert_eq!(
                budget.reserved_bytes(),
                total_bytes + row_bytes + read_bytes
            );
        }
        assert_eq!(worker.root(), template.root());
        drop(worker);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn dirty_ranges_coalesce_across_bitmap_words_in_memory_order() {
        let mut memory = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        let start = Memory::HEAP_START;
        for leaf in [128, 64, 1, 63, 62, 0, 64] {
            memory.store_u8(start + leaf * 32, 0xa5).unwrap();
        }
        let start = start as usize;
        assert_eq!(
            memory.dirty_ranges(),
            [
                (start, start + 2 * 32),
                (start + 62 * 32, start + 65 * 32),
                (start + 128 * 32, start + 129 * 32),
            ]
        );
        assert_eq!(memory.dirty_chunks.len(), 6);
        memory.commit();
        assert!(memory.dirty_ranges().is_empty());
        assert_eq!(memory.modified_chunks.len(), 6);
    }
    #[test]
    fn commit_small_dirty_set_uses_incremental_merkle_update() {
        let mut mem = Memory::new();
        let baseline = mem.root();
        let (_, updates_before) = crate::byte_merkle_tree::merkle_update_counters();
        mem.store_u8(Memory::HEAP_START, 0xAA)
            .expect("store in heap");
        mem.store_u8(Memory::HEAP_START + 1, 0x55)
            .expect("store in same chunk");
        let updated = mem.root();
        assert_ne!(updated, baseline, "memory root should change after writes");
        let (_, updates_after) = crate::byte_merkle_tree::merkle_update_counters();
        assert!(
            updates_after >= updates_before.saturating_add(1),
            "same-chunk writes should produce one incremental leaf update"
        );
        assert_eq!(
            mem.dirty_chunks.len(),
            0,
            "commit should drain dirty chunks"
        );
    }
    #[test]
    fn commit_large_dirty_set_matches_full_rebuild_root() {
        let data = vec![0u8; 32 * 8];
        let tree = ByteMerkleTree::from_bytes(&data, 32).unwrap();
        let root = tree.root_hash();
        let mut mem = Memory {
            call_frames: crate::call_frame::CallFrameMemory::default(),
            data: data.into(),
            stack_limit: Memory::STACK_ALIGNMENT,
            heap_alloc: 0,
            heap_limit: Memory::HEAP_SIZE,
            heap_max_limit: Memory::HEAP_MAX_SIZE,
            heap_contains_data: false,
            code_length: 0,
            output_cursor: 0,
            root,
            tree,
            dirty: false,
            dirty_chunks: DirtyChunks::new(8, None).unwrap(),
            modified_chunks: DirtyChunks::new(8, None).unwrap(),
            template_generation: 0,
            baseline_lineage: crate::cache_memory::SharedValue::new((), Some(0)),
            read_log: Mutex::new(ReadLog::default()),
            write_log: Mutex::new(WriteLog::default()),
            diagnostic_access_recorder: None,
        };
        mem.data[0..32].fill(0xAA);
        mem.data[32..64].fill(0x55);
        mem.data[64..96].fill(0x11);
        mem.data[96..128].fill(0x22);
        mem.dirty_chunks.extend([0, 1, 2, 3]);
        mem.dirty = true;
        let updated = mem.root();
        let expected = MerkleTree::<[u8; 32]>::from_byte_chunks(&mem.data, 32)
            .expect("canonical tree")
            .root()
            .expect("root");
        assert_eq!(updated, expected);
        assert!(
            mem.dirty_chunks.is_empty(),
            "large commit should drain dirty chunks"
        );
    }
    #[test]
    fn large_commit_keeps_unaligned_memory_tree_shape() {
        let data = vec![0u8; 32 * 8 + 16];
        let tree = ByteMerkleTree::new(8, 32).unwrap();
        let root = tree.root_hash();
        let mut incremental = Memory {
            call_frames: crate::call_frame::CallFrameMemory::default(),
            data: data.clone().into(),
            stack_limit: Memory::STACK_ALIGNMENT,
            heap_alloc: 0,
            heap_limit: Memory::HEAP_SIZE,
            heap_max_limit: Memory::HEAP_MAX_SIZE,
            heap_contains_data: false,
            code_length: 0,
            output_cursor: 0,
            root,
            tree,
            dirty: false,
            dirty_chunks: DirtyChunks::new(8, None).unwrap(),
            modified_chunks: DirtyChunks::new(8, None).unwrap(),
            template_generation: 0,
            baseline_lineage: crate::cache_memory::SharedValue::new((), Some(0)),
            read_log: Mutex::new(ReadLog::default()),
            write_log: Mutex::new(WriteLog::default()),
            diagnostic_access_recorder: None,
        };
        let mut rebuilt = incremental
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        incremental.data[0..32].fill(0xAA);
        incremental.data[32..64].fill(0x55);
        incremental.dirty_chunks.extend([0, 1]);
        incremental.dirty = true;
        incremental.commit();
        incremental.data[64..96].fill(0x11);
        incremental.data[96..128].fill(0x22);
        incremental.dirty_chunks.extend([2, 3]);
        incremental.dirty = true;
        let incremental_root = incremental.root();
        rebuilt.data[0..32].fill(0xAA);
        rebuilt.data[32..64].fill(0x55);
        rebuilt.data[64..96].fill(0x11);
        rebuilt.data[96..128].fill(0x22);
        rebuilt.dirty_chunks.extend([0, 1, 2, 3]);
        rebuilt.dirty = true;
        let rebuilt_root = rebuilt.root();
        assert_eq!(rebuilt.tree.leaf_count(), 8);
        assert_eq!(rebuilt_root, incremental_root);
    }
    #[test]
    fn preload_input_out_of_bounds_fails() {
        let mut mem = Memory::new();
        // Offset equal to INPUT_SIZE should be rejected even for empty writes.
        assert!(matches!(
            mem.preload_input(Memory::INPUT_SIZE, &[1]),
            Err(VMError::MemoryOutOfBounds)
        ));
        // Writing past the end should also fail.
        assert!(matches!(
            mem.preload_input(Memory::INPUT_SIZE - 1, &[1, 2]),
            Err(VMError::MemoryOutOfBounds)
        ));
    }
    /// VM stage of the resource contract (`specs/zk_resource_contract.json`, groups
    /// `guest_memory` and `vm_handles`): the heap and the input window are inclusive at their
    /// bound, one byte over is refused, and neither can hold a ceiling-sized proof.
    #[test]
    fn guest_heap_and_input_window_accept_their_bound_and_refuse_one_over() {
        assert_eq!(Memory::HEAP_MAX_SIZE, 1024 * 1024);
        assert_eq!(
            Memory::HEAP_MAX_SIZE,
            Memory::INPUT_START - Memory::HEAP_START
        );
        assert_eq!(Memory::INPUT_SIZE, 64 * 1024);
        assert_eq!(Memory::OUTPUT_SIZE, 32 * 1024);
        // The input window holds exactly INPUT_SIZE bytes.
        let window = vec![0xA5; usize::try_from(Memory::INPUT_SIZE).unwrap()];
        let mut mem = Memory::new();
        mem.preload_input(0, &window).expect("a full input window");
        let mut over = window.clone();
        over.push(0xA5);
        assert!(matches!(
            mem.preload_input(0, &over),
            Err(VMError::MemoryOutOfBounds)
        ));
        assert!(matches!(
            mem.preload_input(1, &window),
            Err(VMError::MemoryOutOfBounds)
        ));
        // The heap holds exactly HEAP_MAX_SIZE bytes.
        let mut mem = Memory::new();
        assert_eq!(
            (mem.alloc(Memory::HEAP_MAX_SIZE)).expect("expected successful fixture result"),
            Memory::HEAP_START
        );
        assert!(matches!(mem.alloc(1), Err(VMError::OutOfMemory)));
        assert!(matches!(mem.grow_heap(1), Err(VMError::OutOfMemory)));
        let mut mem = Memory::new();
        assert!(matches!(
            mem.alloc(Memory::HEAP_MAX_SIZE + 1),
            Err(VMError::OutOfMemory)
        ));
        // A governed heap limit below the ABI maximum is enforced the same way and cannot
        // be raised above the ABI maximum or grown past by the guest.
        let mut mem = Memory::new();
        assert!(matches!(
            mem.set_heap_max_limit(Memory::HEAP_MAX_SIZE + 1),
            Err(VMError::OutOfMemory)
        ));
        mem.set_heap_max_limit(Memory::HEAP_MAX_SIZE)
            .expect("the ABI maximum itself");
        mem.set_heap_max_limit(4_096).expect("a governed limit");
        assert_eq!(
            (mem.alloc(4_096)).expect("expected successful fixture result"),
            Memory::HEAP_START
        );
        assert!(matches!(mem.alloc(8), Err(VMError::OutOfMemory)));
        assert!(matches!(mem.grow_heap(8), Err(VMError::OutOfMemory)));
        // No guest region, nor all of them together, holds a 9,437,184-byte proof: large
        // proofs reach a contract only through host-held attachment handles (I.2).
        const {
            assert!(
                Memory::HEAP_MAX_SIZE
                    + Memory::INPUT_SIZE
                    + Memory::OUTPUT_SIZE
                    + Memory::STACK_SIZE
                    < 9_437_184
            );
        }
    }
    #[test]
    fn input_write_aligned_rejects_invalid_alignment_and_overflow() {
        let mut mem = Memory::new();
        let baseline = mem.current_root();

        for align in [0, 3] {
            let mut cursor = 1;
            assert!(matches!(
                mem.input_write_aligned(&mut cursor, &[0xA5], align),
                Err(VMError::MemoryOutOfBounds)
            ));
            assert_eq!(cursor, 1, "failed allocation must preserve the cursor");
        }

        let mut cursor = u64::MAX;
        assert!(matches!(
            mem.input_write_aligned(&mut cursor, &[0xA5], 8),
            Err(VMError::MemoryOutOfBounds)
        ));
        assert_eq!(cursor, u64::MAX);
        assert_eq!(mem.current_root(), baseline, "failed writes must be atomic");
    }
    #[test]
    fn alloc_rejects_overflow_sizes() {
        let mut mem = Memory::new();
        assert!(matches!(mem.alloc(u64::MAX), Err(VMError::OutOfMemory)));
        // Heap cursor should remain unchanged after failure.
        assert_eq!(mem.heap_alloc, 0);
        let small = mem.alloc(16).expect("small allocation succeeds");
        assert_eq!(small, Memory::HEAP_START);
    }
    #[test]
    fn per_instance_heap_ceiling_cannot_be_bypassed_by_growth() {
        let mut mem = Memory::new();
        mem.set_heap_max_limit(64)
            .expect("install governed heap ceiling");
        assert_eq!(mem.heap_limit(), 64);
        assert_eq!(mem.heap_max_limit(), 64);
        assert_eq!(
            (mem.alloc(64)).expect("expected successful fixture result"),
            Memory::HEAP_START
        );
        assert!(matches!(mem.grow_heap(8), Err(VMError::OutOfMemory)));
        assert!(matches!(mem.alloc(1), Err(VMError::OutOfMemory)));
    }
    #[test]
    fn grow_heap_rejects_overflow() {
        let mut mem = Memory::new();
        mem.set_heap_limit(Memory::HEAP_MAX_SIZE - 64)
            .expect("lower heap limit before bounded grow");
        let original_limit = mem.heap_limit();
        assert!(matches!(mem.grow_heap(u64::MAX), Err(VMError::OutOfMemory)));
        assert_eq!(mem.heap_limit(), original_limit);
        // Growing within bounds still works.
        mem.grow_heap(32).expect("bounded grow succeeds");
        assert_eq!(mem.heap_limit(), original_limit + 32);
    }
    #[test]
    fn store_u128_respects_output_append_only() {
        let mut mem = Memory::new();
        let base = Memory::OUTPUT_START;
        mem.store_u128(base, 0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF)
            .expect("initial append succeeds");
        let err = mem.store_u128(base, 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF);
        assert!(matches!(err, Err(VMError::MemoryAccessViolation { .. })));
        mem.store_u128(base + 16, 0x1111_2222_3333_4444_5555_6666_7777_8888)
            .expect("append at cursor succeeds");
    }
    #[test]
    fn load_region_rejects_oversized_len() {
        let mem = Memory::new();
        let err = mem.load_region(Memory::HEAP_START, u64::from(u32::MAX) + 1);
        assert!(matches!(
            err,
            Err(VMError::MemoryAccessViolation {
                perm: Perm::READ,
                ..
            })
        ));
    }
    #[test]
    fn byte_slice_access_rejects_ranges_crossing_region_boundaries() {
        let mut mem = Memory::new();
        let final_heap_byte = Memory::HEAP_START + Memory::HEAP_MAX_SIZE - 1;
        let mut output = [0_u8; 2];
        assert!(matches!(
            mem.load_bytes(final_heap_byte, &mut output),
            Err(VMError::MemoryAccessViolation {
                perm: Perm::READ,
                ..
            })
        ));
        assert!(matches!(
            mem.store_bytes(final_heap_byte, &[1, 2]),
            Err(VMError::MemoryAccessViolation {
                perm: Perm::WRITE,
                ..
            })
        ));
    }
    #[test]
    fn quote_inspection_does_not_mutate_memory_access_tracking() {
        let mut mem = Memory::new();
        let address = mem.alloc(4).expect("allocate quote fixture");
        mem.store_bytes(address, &[1, 2, 3, 4])
            .expect("write quote fixture");
        mem.clear_tracking();
        assert_eq!(
            mem.inspect_region(address, 4).expect("inspect fixture"),
            &[1, 2, 3, 4]
        );
        assert!(
            mem.try_read_log_snapshot()
                .expect("allocate read-log snapshot")
                .is_empty()
        );
        mem.load_region(address, 4).expect("tracked load fixture");
        assert_eq!(
            mem.try_read_log_snapshot()
                .expect("allocate read-log snapshot")[..],
            vec![AccessRange {
                addr: address,
                len: 4
            }]
        );
    }
    #[test]
    fn canonical_stack_limit_boundary_is_enforced() {
        let mut mem = Memory::new();
        assert_eq!(mem.stack_limit(), IvmStackPolicy::V1.maximum_stack_bytes());
        let ok_addr = mem.stack_top() - 1;
        mem.store_u8(ok_addr, 1).expect("write within limit");
        let err = mem.store_u8(mem.stack_top(), 1);
        assert!(matches!(
            err,
            Err(VMError::MemoryAccessViolation {
                perm: Perm::WRITE,
                ..
            })
        ));
    }
    #[test]
    fn explicit_unaligned_stack_limit_is_rejected() {
        assert!(matches!(
            Memory::new_with_stack_limit(0x60a04),
            Err(VMError::MemoryOutOfBounds)
        ));
    }
    #[test]
    fn stack_constructor_enforces_v1_limits() {
        let minimum = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        assert_eq!(minimum.stack_limit(), Memory::MIN_STACK_SIZE);

        let maximum = Memory::new_with_stack_limit(Memory::STACK_SIZE).unwrap();
        assert_eq!(maximum.stack_limit(), Memory::STACK_SIZE);
        assert_eq!(
            maximum.stack_top(),
            Memory::STACK_START + Memory::STACK_SIZE
        );

        assert!(matches!(
            Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE - 1),
            Err(VMError::MemoryOutOfBounds)
        ));
        assert!(matches!(
            Memory::new_with_stack_limit(0),
            Err(VMError::MemoryOutOfBounds)
        ));
        assert!(matches!(
            Memory::new_with_stack_limit(Memory::STACK_SIZE + 1),
            Err(VMError::MemoryOutOfBounds)
        ));
        assert!(matches!(
            Memory::new_with_stack_limit(u64::MAX),
            Err(VMError::MemoryOutOfBounds)
        ));
    }
    #[test]
    fn memory_merkle_helpers_reject_the_exclusive_end_address() {
        let mut memory = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        let final_byte = memory.stack_top() - 1;
        assert!(memory.merkle_path(final_byte).is_ok());
        assert!(memory.merkle_root_and_path(final_byte).is_ok());
        assert!(memory.merkle_compact(final_byte, None).is_ok());

        for invalid in [memory.stack_top(), u64::MAX] {
            assert!(matches!(
                memory.merkle_path(invalid),
                Err(VMError::MemoryOutOfBounds)
            ));
            assert!(matches!(
                memory.merkle_root_and_path(invalid),
                Err(VMError::MemoryOutOfBounds)
            ));
            assert!(matches!(
                memory.merkle_compact(invalid, None),
                Err(VMError::MemoryOutOfBounds)
            ));
        }
    }
    #[test]
    fn current_root_recomputes_dirty_state() {
        let mut mem = Memory::new();
        let baseline = mem.current_root();
        let addr = Memory::HEAP_START;
        mem.store_u64(addr, 0xCAFEBABE_DEADBEEF).unwrap();
        mem.store_u32(addr + 32, 0xA5A5_5A5A).unwrap();
        let mut clone = mem
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        let expected = clone.root();
        let observed = mem.current_root();
        assert_ne!(observed, baseline);
        assert_eq!(observed, expected);
        assert!(mem.dirty_ranges().is_empty());
    }
    #[test]
    fn merkle_path_without_explicit_commit_reflects_writes() {
        let mut mem = Memory::new();
        let addr = Memory::HEAP_START + 96;
        mem.store_u64(addr, 0xFEED_FACE_DEAD_BEEFu64).unwrap();
        let mut reference = mem
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        let path = mem.merkle_path(addr).unwrap();
        let root = mem.current_root();
        let expected_path = reference.merkle_path(addr).unwrap();
        let expected_root = reference.current_root();
        assert_eq!(root, expected_root);
        assert_eq!(path, expected_path);
    }
    #[test]
    fn merkle_compact_without_explicit_commit_matches_path() {
        let mut mem = Memory::new();
        let addr = Memory::HEAP_START + 160;
        mem.store_u32(addr, 0x1357_9BDF).unwrap();
        let mut reference = mem
            .try_clone_for_runtime_template(None)
            .expect("bounded test memory copy");
        let (proof, root) = mem.merkle_compact(addr, Some(12)).unwrap();
        let depth = proof.depth() as usize;
        assert_eq!(proof.siblings().len(), depth);
        assert_ne!(
            proof.dirs(),
            (addr / 32) as u32,
            "depth-capped proof must use only its encoded direction bits"
        );
        let (expected_root, expected_path) = reference.merkle_root_and_path(addr).unwrap();
        let mut chunk = [0u8; 32];
        reference
            .load_bytes((addr / 32) * 32, &mut chunk)
            .expect("load chunk");
        let leaf_digest = compute_memory_leaf_digest(&chunk);
        let leaf_hash = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf_digest));
        let partial_proof = MerkleProof::from_audit_path(
            proof.dirs(),
            expected_path
                .iter()
                .take(depth)
                .map(|b| {
                    if *b == [0u8; 32] {
                        None
                    } else {
                        Some(HashOf::from_untyped_unchecked(Hash::prehashed(*b)))
                    }
                })
                .collect(),
        );
        let expected_compact_root = if depth < expected_path.len() {
            partial_proof
                .compute_partial_root_sha256(&leaf_hash, depth)
                .expect("proof height equals compact depth")
        } else {
            expected_root
        };
        assert_eq!(root, expected_compact_root);
        assert!(depth <= expected_path.len());
        for (i, sibling) in proof.siblings().iter().enumerate() {
            if i >= depth {
                break;
            }
            let sib_bytes = sibling
                .as_ref()
                .map(|hash| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(hash.as_ref());
                    arr
                })
                .unwrap_or([0u8; 32]);
            assert_eq!(sib_bytes, expected_path[i]);
        }
    }
}
