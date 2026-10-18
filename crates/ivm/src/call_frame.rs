//! Runtime ownership and byte-initialization checks for the sole V1 table-call convention.
//!
//! Call metadata fixes the sizes before entering a function. A callee owns only its stack frame,
//! borrows its argument table for reading, and borrows a separate caller result table for writing.
//! A returned count never substitutes for evidence that every result byte was actually written.

use crate::{
    Memory, VMError,
    error::Perm,
    execution_memory::{ExecutionBuffer, ExecutionMemoryLease, ExecutionMemoryPlan},
};
use iroha_allocation::AllocationBudget;
use ivm_abi::call::{CALL_WORD_BYTES_V1, MAX_CALL_FRAME_BYTES_V1, MAX_CALL_WORDS_V1};
use std::ops::{Deref, DerefMut};

/// Derived shape from a fully validated immutable callable schema.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CallFrameShape {
    pub(crate) entry_pc: u64,
    pub(crate) frame_bytes: u32,
    pub(crate) argument_words: usize,
    pub(crate) result_words: usize,
}

impl CallFrameShape {
    fn validate(&self) -> bool {
        self.entry_pc.is_multiple_of(4)
            && self.frame_bytes.is_multiple_of(16)
            && self.frame_bytes <= MAX_CALL_FRAME_BYTES_V1
            && self.argument_words <= MAX_CALL_WORDS_V1
            && (1..=MAX_CALL_WORDS_V1).contains(&self.result_words)
    }
}

#[cfg(test)]
thread_local! {
    static REFUSE_NEXT_BITMAP_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Region {
    start: u64,
    end: u64,
}
impl Region {
    fn new(start: u64, bytes: u64) -> Result<Self, VMError> {
        // Per-access path: build the error only on overflow.
        match start.checked_add(bytes) {
            Some(end) => Ok(Self { start, end }),
            None => Err(VMError::MemoryOutOfBounds),
        }
    }
    fn table(start: u64, words: u64) -> Result<Self, VMError> {
        if words > MAX_CALL_WORDS_V1 as u64 || (words == 0 && start != 0) {
            return Err(VMError::AssertionFailed);
        }
        if !start.is_multiple_of(CALL_WORD_BYTES_V1 as u64) {
            return Err(VMError::MisalignedAccess { addr: start as u32 });
        }
        Self::new(start, words * CALL_WORD_BYTES_V1 as u64)
    }
    fn contains(self, other: Self) -> bool {
        other.start >= self.start && other.end <= self.end
    }
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
    fn empty(self) -> bool {
        self.start == self.end
    }
}

/// One bit per byte, so narrow and overlapping stores cannot counterfeit initialized words.
struct InitializedRegion {
    region: Region,
    bits: BitmapStorage,
}

/// Bitmap bytes keep the active pool charge until their actual backing is freed.
enum BitmapStorage {
    Local(crate::cache_memory::OwnedAllocation<u8>),
    Funded(ExecutionBuffer<u8>),
}

impl BitmapStorage {
    fn try_retain(&self) -> bool {
        match self {
            Self::Local(bits) => bits.try_retain(),
            Self::Funded(bits) => bits.try_retain(),
        }
    }

    fn make_active(&self) {
        match self {
            Self::Local(bits) => bits.make_active(),
            Self::Funded(bits) => bits.activate(),
        }
    }
}

impl Deref for BitmapStorage {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Local(bits) => bits,
            Self::Funded(bits) => bits.as_slice(),
        }
    }
}

impl DerefMut for BitmapStorage {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Local(bits) => bits,
            Self::Funded(bits) => bits.as_mut_slice(),
        }
    }
}
impl InitializedRegion {
    fn bitmap_bytes(region: Region) -> Result<usize, VMError> {
        let bytes =
            usize::try_from(region.end - region.start).map_err(|_| VMError::MemoryOutOfBounds)?;
        Ok(bytes.div_ceil(8))
    }

    fn new(region: Region, lease: Option<&mut ExecutionMemoryLease>) -> Result<Self, VMError> {
        let bytes = Self::bitmap_bytes(region)?;
        // Physical allocator refusal abandons this local attempt. Guest address
        // and frame bounds above remain deterministic faults.
        #[cfg(test)]
        if REFUSE_NEXT_BITMAP_FOR_TEST.with(|refuse| refuse.replace(false)) {
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable,
            ));
        }
        let unavailable =
            || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
        let bits = match lease {
            Some(lease) => BitmapStorage::Funded(
                ExecutionBuffer::zeroed(bytes, lease).map_err(|_| unavailable())?,
            ),
            None => BitmapStorage::Local(
                crate::cache_memory::OwnedAllocation::try_zeroed(bytes)
                    .map_err(|_| unavailable())?,
            ),
        };
        Ok(Self { region, bits })
    }
    fn initialized(&self, range: Region) -> bool {
        self.region.contains(range)
            && bitmap_spans(self.offsets(range)).all(|(byte, mask)| self.bits[byte] & mask == mask)
    }
    fn record_write(&mut self, range: Region) {
        debug_assert!(self.region.contains(range));
        for (byte, mask) in bitmap_spans(self.offsets(range)) {
            self.bits[byte] |= mask;
        }
    }
    /// Bit offsets of a contained range, relative to this region's first byte.
    fn offsets(&self, range: Region) -> std::ops::Range<usize> {
        (range.start - self.region.start) as usize..(range.end - self.region.start) as usize
    }
}

/// Cover the bit offsets `bits` with one `(byte index, mask)` per touched
/// bitmap byte, so word-sized accesses test or set whole bytes at once instead
/// of one bit per guest byte.
fn bitmap_spans(bits: std::ops::Range<usize>) -> impl Iterator<Item = (usize, u8)> {
    let mut next = bits.start;
    std::iter::from_fn(move || {
        if next >= bits.end {
            return None;
        }
        let shift = next % 8;
        let width = (8 - shift).min(bits.end - next);
        let mask = (u8::MAX >> (8 - width)) << shift;
        let span = (next / 8, mask);
        next += width;
        Some(span)
    })
}

struct Frame {
    stack: InitializedRegion,
    arguments: Region,
    results: InitializedRegion,
    entry_stack_pointer: u64,
    entry_pc: u64,
}

#[cfg(test)]
/// Exact frame slot layout for cross-module pool-accounting tests.
pub(crate) const fn frame_backing_bytes_for_test() -> usize {
    std::mem::size_of::<Frame>()
}

#[derive(Clone, Copy)]
struct FrameDescriptor {
    stack: Region,
    arguments: Region,
    results: Region,
    entry_stack_pointer: u64,
    entry_pc: u64,
}

/// Fully allocated frame authority awaiting a single allocation-free install.
pub(crate) struct PreparedCallFrame(Frame);

/// Caller-owned table descriptors captured before entering a V1 callable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CallTables {
    pub(crate) argument_base: u64,
    pub(crate) argument_words: u64,
    pub(crate) result_base: u64,
    pub(crate) result_words: u64,
}

/// Standalone execution retains local accounting; State execution funds each backing.
enum FrameStack {
    Local(crate::cache_memory::OwnedVec<Frame>),
    Funded {
        budget: AllocationBudget,
        backing: Option<ExecutionBuffer<Frame>>,
    },
}

impl Default for FrameStack {
    fn default() -> Self {
        Self::Local(crate::cache_memory::OwnedVec::default())
    }
}

impl FrameStack {
    fn with_memory_budget(budget: &AllocationBudget) -> Self {
        Self::Funded {
            budget: budget.clone(),
            backing: None,
        }
    }

    fn copy_inactive(&self) -> Self {
        match self {
            Self::Local(_) => Self::default(),
            Self::Funded { budget, .. } => Self::with_memory_budget(budget),
        }
    }

    fn try_reserve_one(&mut self) -> Result<(), VMError> {
        match self {
            Self::Local(values) => values.try_reserve_one().map_err(|_| {
                VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
            }),
            Self::Funded { budget, backing } => {
                let capacity = backing.as_ref().map_or(0, ExecutionBuffer::capacity);
                if backing
                    .as_ref()
                    .is_some_and(|owner| owner.as_slice().len() < capacity)
                {
                    return Ok(());
                }
                let capacity = capacity
                    .saturating_mul(2)
                    .clamp(1, crate::limits::MAX_CONTRACT_CALL_DEPTH + 1);
                if backing
                    .as_ref()
                    .is_some_and(|owner| owner.as_slice().len() == capacity)
                {
                    return Err(VMError::AssertionFailed);
                }
                let plan = ExecutionMemoryPlan::array::<Frame>(capacity)
                    .map_err(VMError::AllocationDeferred)?;
                let mut lease = ExecutionMemoryLease::reserve(budget, plan)
                    .map_err(VMError::AllocationDeferred)?;
                let mut replacement = ExecutionBuffer::new(capacity, &mut lease).map_err(|_| {
                    VMError::ExecutionDeferred(
                        crate::error::ExecutionDeferral::AllocationUnavailable,
                    )
                })?;
                if let Some(previous) = backing.as_mut() {
                    // The new backing and its charge are complete before moving
                    // any live Frame. Old and new charges overlap until the old
                    // allocation is actually deallocated after this transfer.
                    for frame in previous.drain_all() {
                        replacement.push_reserved(frame);
                    }
                }
                // Publish the complete replacement before releasing the old
                // charge: a refund callback may unwind during that release.
                let previous = backing.replace(replacement);
                drop(previous);
                Ok(())
            }
        }
    }

    fn insert_reserved(&mut self, index: usize, frame: Frame) {
        match self {
            Self::Local(values) => values.insert_reserved(index, frame),
            Self::Funded { backing, .. } => {
                let values = backing.as_mut().expect("frame backing was reserved");
                assert_eq!(index, values.as_slice().len());
                values.push_reserved(frame);
            }
        }
    }

    fn pop(&mut self) -> Option<Frame> {
        match self {
            Self::Local(values) => values.pop(),
            Self::Funded { backing, .. } => backing.as_mut().and_then(ExecutionBuffer::pop),
        }
    }

    fn clear(&mut self) {
        match self {
            Self::Local(values) => values.clear(),
            Self::Funded { backing, .. } => {
                if let Some(owner) = backing {
                    owner.truncate(0);
                }
            }
        }
    }

    fn clear_and_shrink(&mut self) {
        match self {
            Self::Local(values) => values.clear_and_shrink(),
            Self::Funded { backing, .. } => *backing = None,
        }
    }

    fn try_retain(&self) -> bool {
        match self {
            Self::Local(values) => values.try_retain(),
            Self::Funded { backing, .. } => {
                backing.as_ref().is_none_or(ExecutionBuffer::try_retain)
            }
        }
    }

    fn make_active(&self) {
        match self {
            Self::Local(values) => values.make_active(),
            Self::Funded { backing, .. } => {
                if let Some(owner) = backing {
                    owner.activate();
                }
            }
        }
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        match self {
            Self::Local(values) => values.capacity(),
            Self::Funded { backing, .. } => backing.as_ref().map_or(0, ExecutionBuffer::capacity),
        }
    }
}

impl Deref for FrameStack {
    type Target = [Frame];

    fn deref(&self) -> &[Frame] {
        match self {
            Self::Local(values) => values,
            Self::Funded { backing, .. } => backing.as_ref().map_or(&[], ExecutionBuffer::as_slice),
        }
    }
}

impl DerefMut for FrameStack {
    fn deref_mut(&mut self) -> &mut [Frame] {
        match self {
            Self::Local(values) => values,
            Self::Funded { backing, .. } => backing
                .as_mut()
                .map_or(&mut [], ExecutionBuffer::as_mut_slice),
        }
    }
}

/// Trusted per-invocation call ownership. Empty state is used by standalone opcode programs.
#[derive(Default)]
pub(crate) struct CallFrameMemory {
    frames: FrameStack,
    completed: Option<Region>,
    active_budget: Option<AllocationBudget>,
}
impl CallFrameMemory {
    /// Keep the exact active VM pool available for root and nested frame preparation.
    pub(crate) fn with_memory_budget(budget: &AllocationBudget) -> Self {
        Self {
            frames: FrameStack::with_memory_budget(budget),
            active_budget: Some(budget.clone()),
            ..Self::default()
        }
    }

    /// Original State allocation pool; equal limits cannot replace its provenance.
    pub(crate) fn allocation_budget(&self) -> Option<&AllocationBudget> {
        self.active_budget.as_ref()
    }

    /// Whether no callee still owns a live stack or result table.
    pub(crate) fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Copy only inactive completion metadata; spare frame capacity stays with its owner.
    pub(crate) fn copy_inactive(&self) -> Self {
        assert!(
            self.frames.is_empty(),
            "active call frames cannot be copied"
        );
        Self {
            frames: self.frames.copy_inactive(),
            completed: self.completed,
            active_budget: self.active_budget.clone(),
        }
    }

    /// Restore inactive completion metadata without allocating during memory reset.
    pub(crate) fn restore_inactive_from(&mut self, template: &Self) {
        assert!(
            template.frames.is_empty(),
            "active call frames cannot be a template"
        );
        self.frames.clear();
        self.completed = template.completed;
    }

    /// Enter a root frame after the host has initialized and validated its argument table.
    #[cfg(test)]
    pub(crate) fn enter_root(
        &mut self,
        stack_pointer: u64,
        callable: &CallFrameShape,
        tables: CallTables,
        stack_top: u64,
    ) -> Result<(), VMError> {
        let prepared = self.prepare_root(stack_pointer, callable, tables, stack_top)?;
        self.enter_prepared_root(prepared);
        Ok(())
    }

    /// Prepare a root frame and reserve its vector slot before call gas is debited.
    pub(crate) fn prepare_root(
        &mut self,
        stack_pointer: u64,
        callable: &CallFrameShape,
        tables: CallTables,
        stack_top: u64,
    ) -> Result<PreparedCallFrame, VMError> {
        if !self.frames.is_empty() {
            return Err(VMError::AssertionFailed);
        }
        let descriptor = Self::descriptor(stack_pointer, callable, tables, stack_top)?;
        if descriptor.stack.overlaps(descriptor.arguments)
            || descriptor.stack.overlaps(descriptor.results)
        {
            return Err(VMError::AssertionFailed);
        }
        let frame = self.frame(descriptor)?;
        self.reserve_frame_slot()?;
        Ok(PreparedCallFrame(frame))
    }

    /// Install a prepared root after all gas and typed-word checks pass.
    pub(crate) fn enter_prepared_root(&mut self, prepared: PreparedCallFrame) {
        self.completed = None;
        self.push_prepared(prepared);
    }

    /// Enter a child only if both disjoint tables belong to the immediate caller's live frame.
    #[cfg(test)]
    pub(crate) fn enter_child(
        &mut self,
        stack_pointer: u64,
        callable: &CallFrameShape,
        tables: CallTables,
        stack_top: u64,
    ) -> Result<(), VMError> {
        let prepared = self.prepare_child(stack_pointer, callable, tables, stack_top)?;
        self.enter_prepared_child(prepared);
        Ok(())
    }

    /// Prepare nested frame authority without changing the active caller.
    pub(crate) fn prepare_child(
        &mut self,
        stack_pointer: u64,
        callable: &CallFrameShape,
        tables: CallTables,
        stack_top: u64,
    ) -> Result<PreparedCallFrame, VMError> {
        let parent = self.frames.last().ok_or(VMError::AssertionFailed)?;
        if stack_pointer != parent.stack.region.start {
            return Err(VMError::AssertionFailed);
        }
        let descriptor = Self::descriptor(stack_pointer, callable, tables, stack_top)?;
        if (!descriptor.arguments.empty() && !parent.stack.initialized(descriptor.arguments))
            || (!descriptor.results.empty() && !parent.stack.region.contains(descriptor.results))
        {
            return Err(VMError::AssertionFailed);
        }
        let frame = self.frame(descriptor)?;
        self.reserve_frame_slot()?;
        Ok(PreparedCallFrame(frame))
    }

    /// Install a prepared child after all call checks finish.
    pub(crate) fn enter_prepared_child(&mut self, prepared: PreparedCallFrame) {
        self.push_prepared(prepared);
    }

    fn descriptor(
        stack_pointer: u64,
        callable: &CallFrameShape,
        tables: CallTables,
        stack_top: u64,
    ) -> Result<FrameDescriptor, VMError> {
        let frame_bytes = callable.frame_bytes;
        if !callable.validate()
            || tables.argument_words != callable.argument_words as u64
            || tables.result_words != callable.result_words as u64
            || frame_bytes > MAX_CALL_FRAME_BYTES_V1
            || !frame_bytes.is_multiple_of(CALL_WORD_BYTES_V1 as u32)
            || !stack_pointer.is_multiple_of(CALL_WORD_BYTES_V1 as u64)
            || stack_pointer > stack_top
        {
            return Err(VMError::AssertionFailed);
        }
        let start = stack_pointer
            .checked_sub(u64::from(frame_bytes))
            .filter(|start| *start >= Memory::STACK_START)
            .ok_or(VMError::MemoryOutOfBounds)?;
        let arguments = Region::table(tables.argument_base, tables.argument_words)?;
        let results = Region::table(tables.result_base, tables.result_words)?;
        if arguments.overlaps(results) {
            return Err(VMError::AssertionFailed);
        }
        Ok(FrameDescriptor {
            stack: Region::new(start, u64::from(frame_bytes))?,
            arguments,
            results,
            entry_stack_pointer: stack_pointer,
            entry_pc: callable.entry_pc,
        })
    }

    fn frame(&self, descriptor: FrameDescriptor) -> Result<Frame, VMError> {
        let FrameDescriptor {
            stack,
            arguments,
            results,
            entry_stack_pointer,
            entry_pc,
        } = descriptor;
        // Both bitmaps are prepaid as one child demand before either backing
        // allocation. A refused nested call never waits on the parent or
        // changes its initialized bytes, gas, or frame authority.
        let mut lease = self
            .active_budget
            .as_ref()
            .map(|budget| {
                let mut plan =
                    ExecutionMemoryPlan::array::<u8>(InitializedRegion::bitmap_bytes(stack)?)
                        .map_err(|_| VMError::MemoryOutOfBounds)?;
                plan.include_child(
                    ExecutionMemoryPlan::array::<u8>(InitializedRegion::bitmap_bytes(results)?)
                        .map_err(|_| VMError::MemoryOutOfBounds)?,
                )
                .map_err(|_| VMError::MemoryOutOfBounds)?;
                ExecutionMemoryLease::reserve(budget, plan).map_err(VMError::AllocationDeferred)
            })
            .transpose()?;
        let stack = InitializedRegion::new(stack, lease.as_mut())?;
        let results = InitializedRegion::new(results, lease.as_mut())?;
        Ok(Frame {
            stack,
            arguments,
            results,
            entry_stack_pointer,
            entry_pc,
        })
    }
    fn reserve_frame_slot(&mut self) -> Result<(), VMError> {
        self.frames.try_reserve_one()
    }

    fn push_prepared(&mut self, prepared: PreparedCallFrame) {
        self.frames.insert_reserved(self.frames.len(), prepared.0);
    }

    #[cfg(test)]
    pub(crate) fn refuse_next_bitmap_for_testing() {
        REFUSE_NEXT_BITMAP_FOR_TEST.with(|refuse| refuse.set(true));
    }

    /// Check ownership before any memory operation; reads also require initialized bytes.
    ///
    /// Standalone programs have no frames, so every guest access returns inline.
    #[inline]
    pub(crate) fn check_access(
        &self,
        address: u64,
        bytes: u64,
        permission: Perm,
    ) -> Result<(), VMError> {
        if self.frames.is_empty() {
            return Ok(());
        }
        self.check_frame_access(address, bytes, permission)
    }

    fn check_frame_access(
        &self,
        address: u64,
        bytes: u64,
        permission: Perm,
    ) -> Result<(), VMError> {
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let range = Region::new(address, bytes)?;
        if bytes == 0 {
            return Ok(());
        }
        let read = permission.contains(Perm::READ);
        let write = permission.contains(Perm::WRITE);
        let permitted = if frame.stack.region.contains(range) {
            !read || frame.stack.initialized(range)
        } else if frame.arguments.contains(range) {
            read && !write
        } else if frame.results.region.contains(range) {
            write && !read
        } else {
            // All other stack bytes, partially overlapping tables, and ancestor tables are
            // inaccessible. Ordinary heap/input/output permissions remain the Memory owner's job.
            // Every ancestor is scanned: the check must not trust how a frame was installed.
            address < Memory::STACK_START
                && !self.frames.iter().any(|ancestor| {
                    ancestor.arguments.overlaps(range)
                        || ancestor.results.region.overlaps(range)
                        || ancestor.stack.region.overlaps(range)
                })
                && range.end <= Memory::STACK_START
        };
        if permitted {
            Ok(())
        } else {
            Err(VMError::MemoryAccessViolation {
                addr: address as u32,
                perm: permission,
            })
        }
    }

    /// Record only successful writes, after the memory owner accepted the entire operation.
    #[inline]
    pub(crate) fn record_write(&mut self, address: u64, bytes: u64) {
        if self.frames.is_empty() {
            return;
        }
        self.record_frame_write(address, bytes);
    }

    fn record_frame_write(&mut self, address: u64, bytes: u64) {
        let Some(frame) = self.frames.last_mut() else {
            return;
        };
        let Ok(range) = Region::new(address, bytes) else {
            return;
        };
        if frame.stack.region.contains(range) {
            frame.stack.record_write(range);
        } else if frame.results.region.contains(range) {
            frame.results.record_write(range);
        }
    }

    /// Finish after trusted return-PC and typed word checks. Failure leaves the frame intact.
    pub(crate) fn finish(
        &mut self,
        stack_pointer: u64,
        result_base: u64,
        initialized_words: u64,
    ) -> Result<(), VMError> {
        let frame = self.frames.last().ok_or(VMError::AssertionFailed)?;
        let returned = Region::table(result_base, initialized_words)?;
        if stack_pointer != frame.entry_stack_pointer
            || returned != frame.results.region
            || !frame.results.initialized(returned)
        {
            return Err(VMError::AssertionFailed);
        }
        self.frames.pop();
        if let Some(parent) = self.frames.last_mut() {
            if !returned.empty() {
                parent.stack.record_write(returned);
            }
        } else {
            self.completed = Some(returned);
        }
        Ok(())
    }

    /// Borrow actual active descriptor values for the sealed native packet owner.
    pub(crate) fn native_packet_descriptor(&self) -> Option<[u64; 8]> {
        self.frames.last().map(|frame| {
            [
                frame.stack.region.start,
                frame.stack.region.end,
                frame.arguments.start,
                frame.arguments.end,
                frame.results.region.start,
                frame.results.region.end,
                frame.entry_stack_pointer,
                frame.entry_pc,
            ]
        })
    }

    /// Actual initialized bits for an absolute aligned cell, without allocating.
    pub(crate) fn native_packet_initialized(&self, address: u64) -> u16 {
        let Some(frame) = self.frames.last() else {
            return 0;
        };
        (0..16).fold(0, |mask, byte| {
            let Some(start) = address.checked_add(byte) else {
                return mask;
            };
            let Ok(one) = Region::new(start, 1) else {
                return mask;
            };
            mask | (u16::from(frame.stack.initialized(one) || frame.results.initialized(one))
                << byte)
        })
    }

    /// Authenticated active function root, unaffected by guest control-register writes.
    pub(crate) fn entry_pc(&self) -> Result<u64, VMError> {
        self.frames
            .last()
            .map(|frame| frame.entry_pc)
            .ok_or(VMError::AssertionFailed)
    }

    pub(crate) fn try_retain(&self) -> bool {
        self.frames.try_retain()
            && self
                .frames
                .iter()
                .all(|frame| frame.stack.bits.try_retain() && frame.results.bits.try_retain())
    }
    pub(crate) fn make_active(&self) {
        self.frames.make_active();
        for frame in self.frames.iter() {
            frame.stack.bits.make_active();
            frame.results.bits.make_active();
        }
    }
    pub(crate) fn compact_for_cache(&mut self) -> bool {
        if !self.frames.is_empty() {
            return false;
        }
        self.frames.clear_and_shrink();
        true
    }

    /// Drop all authority and initialization on a new invocation, reset, or error unwind.
    pub(crate) fn clear(&mut self) {
        self.frames.clear();
        self.completed = None;
    }

    /// Return the validated word count only after a successful root return.
    pub(crate) fn completed_word_count(&self) -> Result<usize, VMError> {
        let table = self.completed.ok_or(VMError::AssertionFailed)?;
        Ok(((table.end - table.start) / CALL_WORD_BYTES_V1 as u64) as usize)
    }

    /// Resolve an initialized active result word for trusted return validation.
    pub(crate) fn active_result_word(&self, index: usize) -> Result<u64, VMError> {
        let frame = self.frames.last().ok_or(VMError::AssertionFailed)?;
        let address = Self::word_address(frame.results.region, index)?;
        let range = Region::new(address, CALL_WORD_BYTES_V1 as u64)?;
        if !frame.results.initialized(range) {
            return Err(VMError::AssertionFailed);
        }
        Ok(address)
    }

    /// Resolve a successful root result without trusting mutable guest descriptor registers.
    pub(crate) fn completed_result_word(&self, index: usize) -> Result<u64, VMError> {
        Self::word_address(self.completed.ok_or(VMError::AssertionFailed)?, index)
    }

    fn word_address(table: Region, index: usize) -> Result<u64, VMError> {
        let offset = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(CALL_WORD_BYTES_V1 as u64))
            .ok_or(VMError::MemoryOutOfBounds)?;
        let address = table
            .start
            .checked_add(offset)
            .ok_or(VMError::MemoryOutOfBounds)?;
        if !table.contains(Region::new(address, CALL_WORD_BYTES_V1 as u64)?) {
            return Err(VMError::MemoryOutOfBounds);
        }
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const TOP: u64 = Memory::STACK_START + 4096;
    const ARG: u64 = Memory::HEAP_START;
    const RESULT: u64 = Memory::HEAP_START + 16;
    const FRAME_BACKING_BYTES: usize = std::mem::size_of::<Frame>();
    fn tables(
        argument_base: u64,
        argument_words: u64,
        result_base: u64,
        result_words: u64,
    ) -> CallTables {
        CallTables {
            argument_base,
            argument_words,
            result_base,
            result_words,
        }
    }
    fn callable(bytes: u32) -> CallFrameShape {
        CallFrameShape {
            entry_pc: 0,
            frame_bytes: bytes,
            argument_words: 1,
            result_words: 1,
        }
    }
    fn root() -> CallFrameMemory {
        let mut frames = CallFrameMemory::default();
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        frames
    }
    #[test]
    fn byte_mask_initialization_matches_a_per_byte_reference() {
        let base = Memory::STACK_START + 64;
        let length = 45_u64;
        let mut region = InitializedRegion::new(Region::new(base, length).unwrap(), None).unwrap();
        let mut reference = vec![false; length as usize];
        let ranges = [
            (0, 0),
            (3, 1),
            (8, 8),
            (5, 6),
            (17, 13),
            (40, 5),
            (0, 3),
            (44, 1),
        ];
        let probe = |region: &InitializedRegion, reference: &[bool]| {
            for start in 0..=length {
                for end in start..=length {
                    let range = Region::new(base + start, end - start).unwrap();
                    let expected = reference[start as usize..end as usize]
                        .iter()
                        .all(|bit| *bit);
                    assert_eq!(region.initialized(range), expected, "{start}..{end}");
                }
            }
            // Ranges outside the region are never initialized, even if empty.
            assert!(!region.initialized(Region::new(base - 1, 1).unwrap()));
            assert!(!region.initialized(Region::new(base + length, 1).unwrap()));
        };
        probe(&region, &reference);
        for (start, bytes) in ranges {
            region.record_write(Region::new(base + start, bytes).unwrap());
            reference[start as usize..(start + bytes) as usize].fill(true);
            let expected: Vec<u8> = reference
                .chunks(8)
                .map(|chunk| {
                    chunk
                        .iter()
                        .enumerate()
                        .fold(0, |mask, (bit, set)| mask | (u8::from(*set) << bit))
                })
                .collect();
            assert_eq!(&region.bits[..], &expected[..]);
            probe(&region, &reference);
        }
    }

    #[test]
    fn below_stack_accesses_reject_ancestor_tables_at_any_depth() {
        let mut frames = root();
        let mut parent_stack = TOP - 128;
        for _ in 0..3 {
            // Each callee's tables sit inside its caller's stack frame.
            let argument = parent_stack + 32;
            let result = parent_stack + 48;
            frames.record_write(argument, 8);
            frames
                .enter_child(
                    parent_stack,
                    &callable(64),
                    tables(argument, 1, result, 1),
                    TOP,
                )
                .unwrap();
            parent_stack -= 64;
        }
        assert_eq!(frames.frames.len(), 4);
        let denied = |frames: &CallFrameMemory, address: u64, bytes: u64, perm: Perm| {
            matches!(
                frames.check_access(address, bytes, perm),
                Err(VMError::MemoryAccessViolation { .. })
            )
        };
        for perm in [Perm::READ, Perm::WRITE, Perm::READ | Perm::WRITE] {
            // The root's heap tables stay inaccessible from every nested frame.
            assert!(denied(&frames, ARG, 8, perm));
            assert!(denied(&frames, RESULT, 8, perm));
            assert!(denied(&frames, ARG + 4, 8, perm));
            // Other heap bytes and ranges below the stack are the Memory owner's job.
            frames
                .check_access(Memory::HEAP_START + 64, 16, perm)
                .unwrap();
            frames
                .check_access(Memory::STACK_START - 8, 8, perm)
                .unwrap();
            // Straddling the stack base, or touching any ancestor frame, is denied.
            assert!(denied(&frames, Memory::STACK_START - 4, 8, perm));
            assert!(denied(&frames, TOP - 64, 8, perm));
            assert!(denied(&frames, TOP - 160, 8, perm));
        }
    }

    #[test]
    fn only_live_frames_prevent_runtime_baseline_capture() {
        let mut frames = CallFrameMemory::default();
        assert!(frames.is_empty());
        frames = root();
        assert!(!frames.is_empty());
        frames.clear();
        assert!(frames.is_empty());
    }

    #[test]
    fn inactive_completion_copy_and_restore_do_not_copy_frame_capacity() {
        let mut source = root();
        source.record_write(RESULT, 8);
        source.finish(TOP, RESULT, 1).unwrap();
        assert!(source.is_empty());
        assert!(source.frames.capacity() > 0);
        let copied = source.copy_inactive();
        assert_eq!(copied.frames.capacity(), 0);
        assert_eq!(copied.completed_word_count().unwrap(), 1);
        let mut destination = root();
        destination.restore_inactive_from(&source);
        assert!(destination.is_empty());
        assert_eq!(destination.completed_word_count().unwrap(), 1);
        source.clear();
        assert_eq!(copied.completed_word_count().unwrap(), 1);
    }

    #[test]
    fn bitmap_refusal_leaves_root_authority_uninstalled_and_retry_succeeds() {
        let mut frames = CallFrameMemory::default();
        CallFrameMemory::refuse_next_bitmap_for_testing();
        assert!(matches!(
            frames.prepare_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert!(frames.is_empty());
        assert!(frames.completed_word_count().is_err());
        let prepared = frames
            .prepare_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        frames.enter_prepared_root(prepared);
        assert!(!frames.is_empty());
    }

    #[test]
    fn bitmap_refusal_preserves_parent_frame_and_initialized_arguments() {
        let mut frames = root();
        let argument = TOP - 32;
        let result = TOP - 16;
        frames.record_write(argument, 8);
        CallFrameMemory::refuse_next_bitmap_for_testing();
        assert!(matches!(
            frames.prepare_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            ),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(frames.frames.len(), 1);
        frames.check_access(argument, 8, Perm::READ).unwrap();
        let prepared = frames
            .prepare_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            )
            .unwrap();
        frames.enter_prepared_child(prepared);
        assert_eq!(frames.frames.len(), 2);
    }

    #[test]
    fn funded_frame_backings_and_bitmaps_keep_exact_charges_until_owner_drops() {
        let budget = AllocationBudget::new(3 * FRAME_BACKING_BYTES + 26);
        let mut frames = CallFrameMemory::with_memory_budget(&budget);
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        // Root stack (128 / 8), one result word (8 / 8), one Frame slot.
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES + 17);
        let argument = TOP - 32;
        let result = TOP - 16;
        frames.record_write(argument, 8);
        frames
            .enter_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            )
            .unwrap();
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES + 26);
        frames.record_write(result, 8);
        frames.finish(TOP - 128, result, 1).unwrap();
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES + 17);
        budget.set_limit_bytes(0);
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES + 17);
        frames.clear();
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES);
        assert!(frames.compact_for_cache());
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn funded_frame_refusal_precedes_allocation_and_preserves_parent_authority() {
        let budget = AllocationBudget::new(FRAME_BACKING_BYTES + 16);
        let mut frames = CallFrameMemory::with_memory_budget(&budget);
        assert!(matches!(
            frames.prepare_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(frames.is_empty());
        budget.set_limit_bytes(FRAME_BACKING_BYTES + 17);
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        let argument = TOP - 32;
        let result = TOP - 16;
        frames.record_write(argument, 8);
        assert!(matches!(
            frames.prepare_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            ),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES + 17);
        assert_eq!(frames.frames.len(), 1);
        frames.check_access(argument, 8, Perm::READ).unwrap();
        budget.set_limit_bytes(3 * FRAME_BACKING_BYTES + 26);
        let prepared = frames
            .prepare_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            )
            .unwrap();
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES + 26);
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES + 17);
        drop(frames);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn funded_frame_growth_refusal_preserves_parent_and_refunds_child() {
        let budget = AllocationBudget::new(FRAME_BACKING_BYTES + 17);
        let mut frames = CallFrameMemory::with_memory_budget(&budget);
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        let argument = TOP - 32;
        let result = TOP - 16;
        frames.record_write(argument, 8);
        // The child bitmaps fit, but the replacement vector must coexist with
        // its live one-slot backing during the move.
        budget.set_limit_bytes(3 * FRAME_BACKING_BYTES + 25);
        assert!(matches!(
            frames.prepare_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            ),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(frames.frames.len(), 1);
        frames.check_access(argument, 8, Perm::READ).unwrap();
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES + 17);
        budget.set_limit_bytes(3 * FRAME_BACKING_BYTES + 26);
        let prepared = frames
            .prepare_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            )
            .unwrap();
        frames.enter_prepared_child(prepared);
        assert_eq!(frames.frames.len(), 2);
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES + 26);
        frames.record_write(result, 8);
        frames.finish(TOP - 128, result, 1).unwrap();
        frames.check_access(result, 8, Perm::READ).unwrap();
    }

    #[test]
    fn borrowed_funded_frame_backing_refunds_on_final_owner_release() {
        let budget = AllocationBudget::new(FRAME_BACKING_BYTES + 17);
        let mut frames = CallFrameMemory::with_memory_budget(&budget);
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        frames.clear();
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES);
        let owner = Arc::new(frames);
        let borrower = Arc::clone(&owner);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES);
        drop(borrower);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn funded_frame_allocator_refusal_and_unwind_refund_only_live_backings() {
        let budget = AllocationBudget::new(FRAME_BACKING_BYTES + 17);
        let mut frames = CallFrameMemory::with_memory_budget(&budget);
        CallFrameMemory::refuse_next_bitmap_for_testing();
        assert!(matches!(
            frames.prepare_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _frames = frames;
            panic!("abandon a funded frame");
        }));
        assert!(unwind.is_err());
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn inactive_frame_copy_preserves_original_active_pool_identity() {
        let budget = AllocationBudget::new(2 * FRAME_BACKING_BYTES + 17);
        let mut source = CallFrameMemory::with_memory_budget(&budget);
        source
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        source.record_write(RESULT, 8);
        source.finish(TOP, RESULT, 1).unwrap();
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES);
        let mut copy = source.copy_inactive();
        copy.enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        assert_eq!(budget.reserved_bytes(), 2 * FRAME_BACKING_BYTES + 17);
        drop(source);
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES + 17);
        drop(copy);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn malformed_nested_descriptor_is_rejected_before_pool_admission() {
        let budget = AllocationBudget::new(FRAME_BACKING_BYTES + 17);
        let mut frames = CallFrameMemory::with_memory_budget(&budget);
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES + 17);
        // The caller has not initialized this argument. Guest invalidity is
        // deterministic even when the local pool cannot admit a child.
        assert!(matches!(
            frames.prepare_child(
                TOP - 128,
                &callable(64),
                tables(TOP - 32, 1, TOP - 16, 1),
                TOP,
            ),
            Err(VMError::AssertionFailed)
        ));
        assert_eq!(budget.reserved_bytes(), FRAME_BACKING_BYTES + 17);
        drop(frames);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn table_descriptors_reject_counts_alignment_aliases_and_overflow() {
        assert!(Region::table(8, MAX_CALL_WORDS_V1 as u64).is_ok());
        assert!(Region::table(8, MAX_CALL_WORDS_V1 as u64 + 1).is_err());
        assert!(Region::table(1, 1).is_err());
        assert!(Region::table(8, 0).is_err());
        assert!(Region::table(u64::MAX - 7, 1).is_err());
        assert!(
            CallFrameMemory::default()
                .enter_root(TOP, &callable(128), tables(ARG, 1, ARG, 1), TOP)
                .is_err()
        );
    }
    #[test]
    fn result_count_cannot_replace_actual_byte_initialization() {
        let mut frames = root();
        assert!(frames.finish(TOP, RESULT, 1).is_err());
        frames.record_write(RESULT, 7);
        assert!(frames.finish(TOP, RESULT, 1).is_err());
        frames.record_write(RESULT + 7, 1);
        assert!(frames.finish(TOP, RESULT + 8, 1).is_err());
        assert!(frames.finish(TOP - 8, RESULT, 1).is_err());
        frames.finish(TOP, RESULT, 1).unwrap();
    }
    #[test]
    fn stack_initialization_and_table_permissions_cover_partial_accesses() {
        let mut frames = root();
        assert!(frames.check_access(TOP - 8, 8, Perm::READ).is_err());
        frames.record_write(TOP - 8, 8);
        frames.check_access(TOP - 8, 8, Perm::READ).unwrap();
        frames.check_access(ARG, 8, Perm::READ).unwrap();
        assert!(frames.check_access(ARG, 8, Perm::WRITE).is_err());
        assert!(frames.check_access(RESULT, 8, Perm::READ).is_err());
        frames.check_access(RESULT, 8, Perm::WRITE).unwrap();
        assert!(frames.check_access(RESULT - 1, 2, Perm::WRITE).is_err());
        assert!(frames.check_access(TOP - 136, 8, Perm::READ).is_err());
    }
    #[test]
    fn nested_tables_belong_to_immediate_caller_and_each_call_requires_fresh_writes() {
        let mut frames = root();
        let argument = TOP - 32;
        let result = TOP - 16;
        assert!(
            frames
                .enter_child(
                    TOP - 128,
                    &callable(64),
                    tables(argument, 1, result, 1),
                    TOP
                )
                .is_err()
        );
        frames.record_write(argument, 8);
        assert!(
            frames
                .enter_child(
                    TOP - 128,
                    &callable(64),
                    tables(argument, 1, RESULT, 1),
                    TOP
                )
                .is_err()
        );
        frames
            .enter_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            )
            .unwrap();
        assert!(frames.check_access(TOP - 8, 8, Perm::WRITE).is_err());
        assert!(frames.check_access(ARG, 8, Perm::READ).is_err());
        frames.record_write(result, 8);
        frames.finish(TOP - 128, result, 1).unwrap();
        frames.check_access(result, 8, Perm::READ).unwrap();
        frames
            .enter_child(
                TOP - 128,
                &callable(64),
                tables(argument, 1, result, 1),
                TOP,
            )
            .unwrap();
        assert!(frames.finish(TOP - 128, result, 1).is_err());
        frames.clear();
        frames
            .enter_root(TOP, &callable(128), tables(ARG, 1, RESULT, 1), TOP)
            .unwrap();
        assert!(frames.finish(TOP, RESULT, 1).is_err());
    }
}

#[cfg(test)]
#[path = "call_frame/ownership_summary_tests.rs"]
mod ownership_summary_tests;

#[cfg(test)]
#[path = "call_frame/initialization_transition_tests.rs"]
mod initialization_transition_tests;

#[cfg(test)]
#[path = "call_frame/native_equation_fixture_tests.rs"]
pub(crate) mod native_equation_fixture_tests;
