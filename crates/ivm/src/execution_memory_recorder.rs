//! Prepaid, ordered local snapshots of successful memory transfers.
//!
//! This diagnostic bus is deliberately outside transaction and proof admission.
//! It observes checked loads/stores, instruction fetches, host INPUT writes,
//! and the CODE/HEAP/OUTPUT changes made by program loading. It does not
//! witness code predecode preparation, quote-only inspections, infallible output
//! borrows, nested VM memories, or the full host/state relation. An opt-in,
//! prepaid initial image captures the bytes after program loading or a
//! template/block reset, before this VM's next interpreter step. It is not a
//! relation between the earlier loader/reset and that image.
//! Rows may contain private bytes. Final-owner drop volatile-erases retained byte
//! values and the initialized image; caller copies
//! and stack temporaries are not a production private-witness custody boundary.

use std::sync::Arc;

use iroha_allocation::AllocationBudget;
use parking_lot::Mutex;

use crate::{
    Memory, VMError,
    error::ExecutionDeferral,
    execution_memory::{ExecutionBuffer, ExecutionMemoryLease, ExecutionMemoryPlan},
};

mod private_disposal;
mod private_scrub;

/// Which successful checked memory API produced a byte row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticMemoryAccessKind {
    /// A fetched code word, including execution from a prepared program.
    InstructionFetch,
    /// A checked scalar load.
    Read,
    /// A checked byte-slice or region load, including host transfers.
    HostRead,
    /// A trusted result-table load during a call return.
    CallResultRead,
    /// A guest or host store through the checked write APIs.
    Write,
    /// A host write to the INPUT region.
    HostInputWrite,
    /// Code bytes replaced by a program loader.
    CodeInstall,
    /// Heap bytes zeroed by a program loader.
    HeapReset,
    /// Output bytes zeroed by a program loader.
    OutputReset,
    /// Private bytes zeroed by the exclusive owner before a lifecycle transition.
    PrivateReset,
}

/// Known privacy classification at the access boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticMemoryPrivacyTag {
    /// The VM knows this byte is public.
    Public,
    /// The VM knows this byte is private.
    Private,
    /// Memory alone cannot classify this byte at this boundary.
    Unknown,
}

/// One byte of a successful memory transfer, in exact observed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticMemoryAccess {
    /// `None` identifies work before the first interpreter instruction.
    pub step_ordinal: Option<u64>,
    /// Monotone ordinal for a checked memory operation.
    pub access_ordinal: u64,
    /// Offset within that operation.
    pub byte_offset: u32,
    /// Absolute memory address.
    pub address: u64,
    /// Byte before the access.
    pub before: u8,
    /// Byte after the access; equal to `before` for reads.
    pub after: u8,
    /// Checked API category.
    pub kind: DiagnosticMemoryAccessKind,
    /// Privacy classification where the VM has supplied it; for writes this
    /// describes the new byte, not necessarily the overwritten byte.
    pub privacy_tag: DiagnosticMemoryPrivacyTag,
}

/// Public geometry and cursors paired with one complete local pre-run byte image.
///
/// The image itself can contain private bytes and is exposed only through a
/// borrowed, local diagnostic inspection closure. Call-frame ownership, memory
/// privacy labels, and host state are not represented by this record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticInitialMemoryState {
    /// Exact number of bytes in the physical VM image.
    pub image_bytes: usize,
    /// Number of executable code bytes already loaded.
    pub code_length: u64,
    /// Heap bytes allocated before this run.
    pub heap_allocated: u64,
    /// Current heap allocation limit.
    pub heap_limit: u64,
    /// Absolute heap allocation ceiling.
    pub heap_max_limit: u64,
    /// Append-only OUTPUT cursor before this run.
    pub output_cursor: u64,
    /// Active stack size in bytes.
    pub stack_limit: u64,
}

struct RecorderInner {
    rows: ExecutionBuffer<DiagnosticMemoryAccess>,
    initial_image: Option<ExecutionBuffer<u8>>,
    initial_image_capacity: Option<usize>,
    initial_state: Option<DiagnosticInitialMemoryState>,
    capacity: usize,
    started: bool,
    step_ordinal: Option<u64>,
    next_access_ordinal: u64,
    default_tag: DiagnosticMemoryPrivacyTag,
}

/// Shared local handle retained by an attached `Memory` during one diagnostic run.
///
/// Every byte row is allocated before execution; an exhausted recorder defers
/// the explicit diagnostic run before the corresponding checked memory access.
/// Ordinary VM execution never attaches this handle.
pub struct DiagnosticMemoryAccessRecorder {
    inner: Arc<Mutex<RecorderInner>>,
}

impl DiagnosticMemoryAccessRecorder {
    /// Reserve the exact byte-row capacity before running the VM.
    ///
    /// # Errors
    /// Returns a local execution deferral if the finite budget or allocator
    /// cannot fund the requested backing.
    pub fn try_new(capacity: usize, budget: &AllocationBudget) -> Result<Self, VMError> {
        Self::try_new_inner(capacity, None, budget)
    }

    /// Reserve both ordered access rows and one complete initial memory image.
    ///
    /// `image_bytes` must equal the VM's physical memory length at run time;
    /// [`Memory::stack_top`] provides that length for the canonical V1 layout.
    /// The image is copied before instruction execution, without allocating or
    /// logging private bytes. The recorder remains diagnostic and cannot admit
    /// a proof-backed transaction.
    ///
    /// # Errors
    /// Refuses invalid image bounds or an unfunded exact backing before the run.
    pub fn try_new_with_initial_image(
        capacity: usize,
        image_bytes: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, VMError> {
        Self::try_new_inner(capacity, Some(image_bytes), budget)
    }

    pub(crate) fn allocation_plan(
        capacity: usize,
        image_bytes: Option<usize>,
    ) -> Result<ExecutionMemoryPlan, VMError> {
        if let Some(image_bytes) = image_bytes {
            let maximum = usize::try_from(Memory::STACK_START + Memory::STACK_SIZE)
                .map_err(|_| VMError::MemoryOutOfBounds)?;
            if image_bytes == 0 || image_bytes > maximum {
                return Err(VMError::MemoryOutOfBounds);
            }
        }
        let unavailable = || VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable);
        let mut plan = ExecutionMemoryPlan::array::<DiagnosticMemoryAccess>(capacity)
            .map_err(|_| unavailable())?;
        if let Some(image_bytes) = image_bytes {
            plan.include_child(
                ExecutionMemoryPlan::array::<u8>(image_bytes).map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?;
        }
        Ok(plan)
    }

    fn try_new_inner(
        capacity: usize,
        image_bytes: Option<usize>,
        budget: &AllocationBudget,
    ) -> Result<Self, VMError> {
        let plan = Self::allocation_plan(capacity, image_bytes)?;
        let mut lease = ExecutionMemoryLease::reserve(budget, plan)
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity))?;
        Self::try_new_from_lease(capacity, image_bytes, &mut lease)
    }

    pub(crate) fn try_new_from_lease(
        capacity: usize,
        image_bytes: Option<usize>,
        lease: &mut ExecutionMemoryLease,
    ) -> Result<Self, VMError> {
        Self::allocation_plan(capacity, image_bytes)?;
        let unavailable = || VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable);
        let rows = ExecutionBuffer::new(capacity, lease).map_err(|_| unavailable())?;
        let initial_image = image_bytes
            .map(|len| ExecutionBuffer::new(len, lease).map_err(|_| unavailable()))
            .transpose()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(RecorderInner {
                rows,
                initial_image,
                initial_image_capacity: image_bytes,
                initial_state: None,
                capacity,
                started: false,
                step_ordinal: None,
                next_access_ordinal: 0,
                default_tag: DiagnosticMemoryPrivacyTag::Unknown,
            })),
        })
    }

    /// Borrow the complete pre-run image without allocating a second copy.
    ///
    /// `None` means the recorder was constructed without image capacity or has
    /// not captured a run. The closure must keep private bytes in local
    /// diagnostic custody and must not call back into this recorder.
    pub fn with_initial_image<R>(
        &self,
        inspect: impl FnOnce(Option<(&DiagnosticInitialMemoryState, &[u8])>) -> R,
    ) -> R {
        let inner = self.inner.lock();
        inspect(
            inner
                .initial_state
                .as_ref()
                .zip(inner.initial_image.as_ref().map(ExecutionBuffer::as_slice)),
        )
    }

    /// Inspect retained rows without making a second allocation or copy.
    ///
    /// The closure must keep private bytes in local diagnostic custody and must
    /// not call back into this recorder or its attached `Memory`.
    pub fn with_records<R>(&self, inspect: impl FnOnce(&[DiagnosticMemoryAccess]) -> R) -> R {
        let inner = self.inner.lock();
        inspect(inner.rows.as_slice())
    }

    /// Number of retained byte rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().rows.as_slice().len()
    }

    /// Whether there are no retained byte rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn shared(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    pub(crate) fn begin_run(&self, zk_mode: bool) -> Result<(), VMError> {
        let mut inner = self.inner.lock();
        if inner.started {
            return Err(VMError::HostUnavailable);
        }
        inner.started = true;
        inner.default_tag = if zk_mode {
            DiagnosticMemoryPrivacyTag::Unknown
        } else {
            DiagnosticMemoryPrivacyTag::Public
        };
        Ok(())
    }

    pub(crate) fn capture_initial_image(
        &self,
        state: DiagnosticInitialMemoryState,
        bytes: &[u8],
    ) -> Result<(), VMError> {
        let mut inner = self.inner.lock();
        let Some(capacity) = inner.initial_image_capacity else {
            return Ok(());
        };
        if !inner.started
            || inner.initial_state.is_some()
            || state.image_bytes != bytes.len()
            || bytes.len() != capacity
        {
            return Err(VMError::HostUnavailable);
        }
        let image = inner
            .initial_image
            .as_mut()
            .ok_or(VMError::HostUnavailable)?;
        if !image.as_slice().is_empty() {
            return Err(VMError::HostUnavailable);
        }
        image
            .append(bytes)
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable))?;
        inner.initial_state = Some(state);
        Ok(())
    }

    pub(crate) fn set_step_ordinal(&self, ordinal: u64) {
        self.inner.lock().step_ordinal = Some(ordinal);
    }

    pub(crate) fn ensure_remaining(&self, additional: usize) -> Result<(), VMError> {
        let inner = self.inner.lock();
        if additional > inner.capacity.saturating_sub(inner.rows.as_slice().len()) {
            return Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity,
            ));
        }
        Ok(())
    }

    pub(crate) fn record_read(
        &self,
        address: u64,
        bytes: &[u8],
        kind: DiagnosticMemoryAccessKind,
    ) -> Result<(), VMError> {
        self.record_with(address, bytes, kind, |offset| bytes[offset])
    }

    pub(crate) fn record_write(
        &self,
        address: u64,
        before: &[u8],
        after: &[u8],
        kind: DiagnosticMemoryAccessKind,
    ) -> Result<(), VMError> {
        if before.len() != after.len() {
            return Err(VMError::HostUnavailable);
        }
        self.record_with(address, before, kind, |offset| after[offset])
    }

    pub(crate) fn record_code_install(&self, before: &[u8], code: &[u8]) -> Result<(), VMError> {
        if code.len() > before.len() {
            return Err(VMError::HostUnavailable);
        }
        self.record_with(
            0,
            before,
            DiagnosticMemoryAccessKind::CodeInstall,
            |offset| code.get(offset).copied().unwrap_or(0),
        )
    }

    pub(crate) fn record_zero_fill(
        &self,
        address: u64,
        before: &[u8],
        kind: DiagnosticMemoryAccessKind,
    ) -> Result<(), VMError> {
        self.record_with(address, before, kind, |_| 0)
    }

    fn record_with(
        &self,
        address: u64,
        before: &[u8],
        kind: DiagnosticMemoryAccessKind,
        mut after: impl FnMut(usize) -> u8,
    ) -> Result<(), VMError> {
        let mut inner = self.inner.lock();
        if !inner.started {
            return Err(VMError::HostUnavailable);
        }
        let remaining = inner.capacity.saturating_sub(inner.rows.as_slice().len());
        if before.len() > remaining {
            return Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity,
            ));
        }
        u32::try_from(before.len()).map_err(|_| VMError::HostUnavailable)?;
        let span = u64::try_from(before.len()).map_err(|_| VMError::HostUnavailable)?;
        address.checked_add(span).ok_or(VMError::HostUnavailable)?;
        let ordinal = inner.next_access_ordinal;
        inner.next_access_ordinal = ordinal.checked_add(1).ok_or(VMError::HostUnavailable)?;
        for (offset, &old) in before.iter().enumerate() {
            let byte_offset = u32::try_from(offset).map_err(|_| VMError::HostUnavailable)?;
            let byte_address = address
                .checked_add(offset as u64)
                .ok_or(VMError::HostUnavailable)?;
            let row = DiagnosticMemoryAccess {
                step_ordinal: inner.step_ordinal,
                access_ordinal: ordinal,
                byte_offset,
                address: byte_address,
                before: old,
                after: after(offset),
                kind,
                privacy_tag: if matches!(
                    kind,
                    DiagnosticMemoryAccessKind::InstructionFetch
                        | DiagnosticMemoryAccessKind::HostInputWrite
                        | DiagnosticMemoryAccessKind::CodeInstall
                        | DiagnosticMemoryAccessKind::HeapReset
                        | DiagnosticMemoryAccessKind::OutputReset
                ) {
                    DiagnosticMemoryPrivacyTag::Public
                } else {
                    inner.default_tag
                },
            };
            inner.rows.append(&[row]).map_err(|_| {
                VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
            })?;
        }
        Ok(())
    }

    pub(crate) fn classify_last_access(
        &self,
        address: u64,
        len: u64,
        kind: DiagnosticMemoryAccessKind,
        private: bool,
    ) {
        let mut inner = self.inner.lock();
        let Some(last) = inner.next_access_ordinal.checked_sub(1) else {
            return;
        };
        let Ok(len) = usize::try_from(len) else {
            return;
        };
        let rows = inner.rows.as_mut_slice();
        let Some(tail) = rows.len().checked_sub(len) else {
            return;
        };
        if !rows[tail..].iter().enumerate().all(|(offset, row)| {
            row.access_ordinal == last
                && row.kind == kind
                && row.address == address.saturating_add(offset as u64)
        }) {
            return;
        }
        let tag = if private {
            DiagnosticMemoryPrivacyTag::Private
        } else {
            DiagnosticMemoryPrivacyTag::Public
        };
        for row in &mut rows[tail..] {
            row.privacy_tag = tag;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IVM, Memory, decoder,
        encoding::wide,
        execution_step_recorder::{DiagnosticStepRecord, DiagnosticStepRecorder},
        host::DefaultHost,
        instruction,
        metadata::ProgramMetadata,
    };

    fn budget_for_rows(capacity: usize) -> AllocationBudget {
        AllocationBudget::new(capacity * std::mem::size_of::<DiagnosticMemoryAccess>())
    }

    fn budget_for_initial_image(rows: usize, image_bytes: usize) -> AllocationBudget {
        AllocationBudget::new(rows * std::mem::size_of::<DiagnosticMemoryAccess>() + image_bytes)
    }

    #[test]
    fn pre_run_image_captures_loaded_code_input_heap_and_output_without_log_rows() {
        let halt = wide::encode_halt();
        let mut vm = IVM::new(100);
        vm.load_code(&halt.to_le_bytes()).unwrap();
        vm.memory.preload_input(3, &[0x91, 0x92]).unwrap();
        vm.memory.store_u8(Memory::HEAP_START + 7, 0xa7).unwrap();
        vm.memory.store_u8(Memory::OUTPUT_START, 0xb8).unwrap();
        let image_bytes = usize::try_from(vm.memory.stack_top()).unwrap();
        let budget = budget_for_initial_image(4, image_bytes);
        let accesses =
            DiagnosticMemoryAccessRecorder::try_new_with_initial_image(4, image_bytes, &budget)
                .unwrap();
        let step_budget = AllocationBudget::new(std::mem::size_of::<DiagnosticStepRecord>());
        let mut steps = DiagnosticStepRecorder::try_new(1, &step_budget).unwrap();
        accesses.with_initial_image(|image| assert!(image.is_none()));
        vm.run_with_host_diagnostic_steps_and_memory(
            &mut DefaultHost::default(),
            &mut steps,
            &accesses,
        )
        .unwrap();
        assert_eq!(accesses.len(), 4, "the image is separate from access rows");
        accesses.with_initial_image(|image| {
            let (state, bytes) = image.expect("captured initial image");
            assert_eq!(state.image_bytes, image_bytes);
            assert_eq!(state.code_length, 4);
            assert_eq!(state.stack_limit, vm.memory.stack_limit());
            assert_eq!(state.heap_allocated, 0);
            assert_eq!(state.output_cursor, 1);
            assert_eq!(bytes.len(), image_bytes);
            assert_eq!(&bytes[..4], &halt.to_le_bytes());
            assert_eq!(
                &bytes[(Memory::INPUT_START + 3) as usize..(Memory::INPUT_START + 5) as usize],
                &[0x91, 0x92]
            );
            assert_eq!(bytes[(Memory::HEAP_START + 7) as usize], 0xa7);
            assert_eq!(bytes[Memory::OUTPUT_START as usize], 0xb8);
            assert_eq!(bytes[Memory::STACK_START as usize], 0);
        });
        assert_eq!(
            budget.reserved_bytes(),
            image_bytes + 4 * std::mem::size_of::<DiagnosticMemoryAccess>()
        );
        drop(accesses);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_template_reset_is_reflected_in_the_next_initial_image() {
        let halt = wide::encode_halt();
        let mut program = ProgramMetadata::default().encode();
        program.extend_from_slice(&halt.to_le_bytes());
        let mut vm = IVM::new(100);
        vm.load_program(&program).unwrap();
        let template = vm.try_runtime_template().unwrap();
        vm.memory.preload_input(0, &[0xd1]).unwrap();
        vm.memory.store_u8(Memory::HEAP_START, 0xe2).unwrap();
        vm.reset_from_runtime_template(&template).unwrap();
        let image_bytes = usize::try_from(vm.memory.stack_top()).unwrap();
        let budget = budget_for_initial_image(4, image_bytes);
        let accesses =
            DiagnosticMemoryAccessRecorder::try_new_with_initial_image(4, image_bytes, &budget)
                .unwrap();
        let step_budget = AllocationBudget::new(std::mem::size_of::<DiagnosticStepRecord>());
        let mut steps = DiagnosticStepRecorder::try_new(1, &step_budget).unwrap();
        vm.run_with_host_diagnostic_steps_and_memory(
            &mut DefaultHost::default(),
            &mut steps,
            &accesses,
        )
        .unwrap();
        accesses.with_initial_image(|image| {
            let (state, bytes) = image.expect("post-template initial image");
            assert_eq!(state.code_length, 4);
            assert_eq!(&bytes[..4], &halt.to_le_bytes());
            assert_eq!(bytes[Memory::INPUT_START as usize], 0);
            assert_eq!(bytes[Memory::HEAP_START as usize], 0);
        });
    }

    #[test]
    fn image_geometry_or_budget_refusal_precedes_vm_execution() {
        let mut vm = IVM::new(100);
        vm.load_code(&wide::encode_halt().to_le_bytes()).unwrap();
        let image_bytes = usize::try_from(vm.memory.stack_top()).unwrap();
        assert_eq!(
            DiagnosticMemoryAccessRecorder::try_new_with_initial_image(
                4,
                image_bytes,
                &budget_for_initial_image(4, image_bytes - 1),
            )
            .err(),
            Some(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            )),
        );
        assert_eq!(
            DiagnosticMemoryAccessRecorder::try_new_with_initial_image(
                4,
                usize::MAX,
                &budget_for_initial_image(4, 0),
            )
            .err(),
            Some(VMError::MemoryOutOfBounds),
        );
        let budget = budget_for_initial_image(4, image_bytes - 1);
        let accesses =
            DiagnosticMemoryAccessRecorder::try_new_with_initial_image(4, image_bytes - 1, &budget)
                .unwrap();
        let step_budget = AllocationBudget::new(std::mem::size_of::<DiagnosticStepRecord>());
        let mut steps = DiagnosticStepRecorder::try_new(1, &step_budget).unwrap();
        assert_eq!(
            vm.run_with_host_diagnostic_steps_and_memory(
                &mut DefaultHost::default(),
                &mut steps,
                &accesses,
            ),
            Err(VMError::HostUnavailable),
        );
        assert!(steps.records().is_empty());
        assert!(accesses.is_empty());
        accesses.with_initial_image(|image| assert!(image.is_none()));
        assert_eq!(vm.pc(), 0);
        assert_eq!(vm.remaining_gas(), 100);
    }

    #[test]
    fn checked_guest_and_host_transfers_have_ordered_pre_post_bytes() {
        let budget = budget_for_rows(9);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(9, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        let mut memory = Memory::new();
        memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();
        memory.diagnostic_step_ordinal(4);
        memory
            .store_bytes(Memory::HEAP_START, &[0x12, 0x34])
            .unwrap();
        assert_eq!(memory.load_u8(Memory::HEAP_START).unwrap(), 0x12);
        let mut copied = [0; 2];
        memory.load_bytes(Memory::HEAP_START, &mut copied).unwrap();
        assert_eq!(copied, [0x12, 0x34]);
        assert_eq!(
            memory.load_region(Memory::HEAP_START, 2).unwrap(),
            &[0x12, 0x34]
        );
        memory.preload_input(0, &[0x9a, 0xbc]).unwrap();
        recorder.with_records(|rows| {
            assert_eq!(rows.len(), 9);
            assert_eq!(rows[0].step_ordinal, Some(4));
            assert_eq!(rows[0].access_ordinal, 0);
            assert_eq!(rows[0].address, Memory::HEAP_START);
            assert_eq!((rows[0].before, rows[0].after), (0, 0x12));
            assert_eq!(rows[1].byte_offset, 1);
            assert_eq!(rows[1].access_ordinal, 0);
            assert_eq!(rows[2].access_ordinal, 1);
            assert_eq!((rows[2].before, rows[2].after), (0x12, 0x12));
            assert_eq!(rows[3].kind, DiagnosticMemoryAccessKind::HostRead);
            assert_eq!(rows[5].kind, DiagnosticMemoryAccessKind::HostRead);
            assert_eq!(rows[7].kind, DiagnosticMemoryAccessKind::HostInputWrite);
            assert_eq!(rows[7].address, Memory::INPUT_START);
            assert_eq!(rows[8].after, 0xbc);
            assert!(
                rows.iter()
                    .all(|row| row.privacy_tag == DiagnosticMemoryPrivacyTag::Public)
            );
        });
        memory.clear_diagnostic_access_recorder();
        drop(recorder);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn diagnostic_capacity_refuses_before_output_mutation() {
        let budget = budget_for_rows(1);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(1, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        let mut memory = Memory::new();
        memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();
        assert_eq!(
            memory.store_bytes(Memory::OUTPUT_START, &[0xaa, 0xbb]),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        assert_eq!(memory.output_used_len(), 0);
        assert!(
            memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot")
                .is_empty()
        );
        assert!(recorder.is_empty());
        memory.store_u8(Memory::OUTPUT_START, 0xcc).unwrap();
        assert_eq!(memory.output_used_len(), 1);
        recorder.with_records(|rows| assert_eq!(rows[0].after, 0xcc));
        let mut input_cursor = 0;
        assert_eq!(
            memory.input_write_aligned(&mut input_cursor, &[0xdd], 8),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        assert_eq!(input_cursor, 0);
        memory.clear_diagnostic_access_recorder();
        assert_eq!(memory.load_u8(Memory::INPUT_START).unwrap(), 0);
    }

    #[test]
    fn diagnostic_read_capacity_refuses_before_destination_copy() {
        let budget = budget_for_rows(0);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(0, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        let mut memory = Memory::new();
        memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();
        let mut output = [0xa5];
        assert_eq!(
            memory.load_bytes(Memory::HEAP_START, &mut output),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        assert_eq!(output, [0xa5]);
        assert!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")
                .is_empty()
        );
    }

    #[test]
    fn privacy_label_requires_explicit_vm_classification_in_zk_mode() {
        let budget = budget_for_rows(2);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(2, &budget).unwrap();
        recorder.begin_run(true).unwrap();
        recorder
            .record_write(
                Memory::STACK_START,
                &[0],
                &[0xa5],
                DiagnosticMemoryAccessKind::Write,
            )
            .unwrap();
        recorder.with_records(|rows| {
            assert_eq!(rows[0].privacy_tag, DiagnosticMemoryPrivacyTag::Unknown)
        });
        recorder.classify_last_access(
            Memory::STACK_START,
            1,
            DiagnosticMemoryAccessKind::Write,
            true,
        );
        recorder.with_records(|rows| {
            assert_eq!(rows[0].privacy_tag, DiagnosticMemoryPrivacyTag::Private)
        });
        assert_eq!(recorder.begin_run(true), Err(VMError::HostUnavailable));
    }

    #[test]
    fn public_vm_load_wrappers_classify_zk_memory_rows() {
        let budget = budget_for_rows(31);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(31, &budget).unwrap();
        recorder.begin_run(true).unwrap();
        let mut vm = IVM::new(100);
        vm.set_zk_mode(true)
            .expect("private lifecycle cleanup succeeds");
        vm.memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();
        assert_eq!(vm.load_u32(Memory::HEAP_START).unwrap(), 0);
        assert_eq!(vm.load_u64(Memory::HEAP_START + 8).unwrap(), 0);
        assert_eq!(vm.load_u128(Memory::HEAP_START + 16).unwrap(), 0);
        let mut bytes = [0xff; 2];
        vm.load_bytes(Memory::HEAP_START + 32, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 2]);
        assert_eq!(vm.memory.load_u8(Memory::HEAP_START + 40).unwrap(), 0);
        recorder.with_records(|rows| {
            assert_eq!(rows.len(), 31);
            assert!(
                rows[..30]
                    .iter()
                    .all(|row| row.privacy_tag == DiagnosticMemoryPrivacyTag::Public)
            );
            assert_eq!(rows[30].privacy_tag, DiagnosticMemoryPrivacyTag::Unknown);
        });
    }

    #[test]
    fn code_replacement_records_old_bytes_new_bytes_and_cleared_tail() {
        let mut memory = Memory::new();
        memory.load_code(&[1, 2, 3, 4]).unwrap();
        let budget = budget_for_rows(4);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(4, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();
        memory.load_code(&[9, 8]).unwrap();
        assert_eq!(memory.read_code_bytes(), &[9, 8]);
        recorder.with_records(|rows| {
            assert_eq!(rows.len(), 4);
            assert!(
                rows.iter()
                    .all(|row| row.kind == DiagnosticMemoryAccessKind::CodeInstall)
            );
            assert_eq!((rows[0].before, rows[0].after), (1, 9));
            assert_eq!((rows[1].before, rows[1].after), (2, 8));
            assert_eq!((rows[2].before, rows[2].after), (3, 0));
            assert_eq!((rows[3].before, rows[3].after), (4, 0));
        });
    }

    #[test]
    fn loader_preflight_refuses_before_any_code_heap_or_output_mutation() {
        let mut vm = IVM::new(100);
        vm.load_code(&[1, 2, 3, 4]).unwrap();
        vm.memory.store_u8(Memory::HEAP_START, 0xa5).unwrap();
        vm.memory.store_u8(Memory::OUTPUT_START, 0x5a).unwrap();
        let budget = budget_for_rows(0);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(0, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        vm.memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();
        assert_eq!(
            vm.memory.clear_program_heap(),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        assert_eq!(
            vm.memory.clear_output(),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        assert_eq!(
            vm.load_code(&[9, 8]),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        vm.memory.clear_diagnostic_access_recorder();
        assert_eq!(vm.memory.read_code_bytes(), &[1, 2, 3, 4]);
        assert_eq!(vm.memory.load_u8(Memory::HEAP_START).unwrap(), 0xa5);
        assert_eq!(vm.memory.read_output_used(), &[0x5a]);
    }

    #[test]
    fn output_reset_records_full_cleared_region_once() {
        let mut memory = Memory::new();
        memory.store_u8(Memory::OUTPUT_START, 0x7e).unwrap();
        let capacity = Memory::OUTPUT_SIZE as usize;
        let budget = budget_for_rows(capacity);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(capacity, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();
        memory.clear_output().unwrap();
        assert_eq!(memory.output_used_len(), 0);
        recorder.with_records(|rows| {
            assert_eq!(rows.len(), capacity);
            assert_eq!(rows[0].kind, DiagnosticMemoryAccessKind::OutputReset);
            assert_eq!((rows[0].before, rows[0].after), (0x7e, 0));
            assert_eq!(
                rows[capacity - 1].address,
                Memory::OUTPUT_START + Memory::OUTPUT_SIZE - 1
            );
            assert_eq!(rows[capacity - 1].after, 0);
        });
    }

    #[test]
    fn interpreter_steps_and_memory_byte_rows_share_ordinals() {
        let mut code = Vec::new();
        code.extend_from_slice(
            &wide::encode_store(instruction::wide::memory::STORE64, 1, 2, 0).to_le_bytes(),
        );
        code.extend_from_slice(
            &wide::encode_load(instruction::wide::memory::LOAD64, 3, 1, 0).to_le_bytes(),
        );
        code.extend_from_slice(&wide::encode_halt().to_le_bytes());
        let step_budget = AllocationBudget::new(3 * std::mem::size_of::<DiagnosticStepRecord>());
        let mut steps = DiagnosticStepRecorder::try_new(3, &step_budget).unwrap();
        let access_budget = budget_for_rows(64);
        let accesses = DiagnosticMemoryAccessRecorder::try_new(64, &access_budget).unwrap();
        let mut vm = IVM::new(100);
        vm.load_code(&code).unwrap();
        vm.set_register(1, Memory::HEAP_START);
        vm.set_register(2, 0x0102_0304_0506_0708);
        let mut host = DefaultHost::default();
        vm.run_with_host_diagnostic_steps_and_memory(&mut host, &mut steps, &accesses)
            .unwrap();
        assert_eq!(steps.records().len(), 3);
        accesses.with_records(|rows| {
            let write = rows
                .iter()
                .filter(|row| {
                    row.kind == DiagnosticMemoryAccessKind::Write
                        && row.address >= Memory::HEAP_START
                        && row.address < Memory::HEAP_START + 8
                })
                .collect::<Vec<_>>();
            assert_eq!(write.len(), 8);
            assert!(write.iter().all(|row| row.step_ordinal == Some(0)));
            assert_eq!(write[0].before, 0);
            assert_eq!(write[0].after, 0x08);
            let read = rows
                .iter()
                .filter(|row| {
                    row.kind == DiagnosticMemoryAccessKind::Read
                        && row.address >= Memory::HEAP_START
                        && row.address < Memory::HEAP_START + 8
                })
                .collect::<Vec<_>>();
            assert_eq!(read.len(), 8);
            assert!(read.iter().all(|row| row.step_ordinal == Some(1)));
            assert_eq!(read[0].before, 0x08);
            assert_eq!(read[0].before, read[0].after);
            assert!(
                rows.windows(2)
                    .all(|pair| pair[0].access_ordinal <= pair[1].access_ordinal)
            );
        });
        let recorded = accesses.len();
        assert_eq!(
            vm.memory.load_u64(Memory::HEAP_START).unwrap(),
            0x0102_0304_0506_0708
        );
        assert_eq!(accesses.len(), recorded);
    }

    #[test]
    fn prepared_execution_fetches_match_loaded_public_code_bytes() {
        let first = wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 0, 7);
        let halt = wide::encode_halt();
        let mut program = ProgramMetadata::default().encode();
        program.extend_from_slice(&first.to_le_bytes());
        program.extend_from_slice(&halt.to_le_bytes());

        let mut vm = IVM::new(100);
        vm.load_program(&program).unwrap();
        let step_budget = AllocationBudget::new(2 * std::mem::size_of::<DiagnosticStepRecord>());
        let mut steps = DiagnosticStepRecorder::try_new(2, &step_budget).unwrap();
        let access_budget = budget_for_rows(8);
        let accesses = DiagnosticMemoryAccessRecorder::try_new(8, &access_budget).unwrap();
        vm.run_with_host_diagnostic_steps_and_memory(
            &mut DefaultHost::default(),
            &mut steps,
            &accesses,
        )
        .unwrap();

        assert_eq!(steps.records().len(), 2);
        accesses.with_records(|rows| {
            assert_eq!(rows.len(), 8);
            for (step, word) in [first, halt].into_iter().enumerate() {
                let fetched = &rows[step * 4..(step + 1) * 4];
                assert_eq!(steps.records()[step].instruction, Some(word));
                assert_eq!(fetched[0].address, steps.records()[step].before.pc);
                assert!(fetched.iter().enumerate().all(|(byte, row)| {
                    row.step_ordinal == Some(step as u64)
                        && row.access_ordinal == step as u64
                        && row.byte_offset == byte as u32
                        && row.before == word.to_le_bytes()[byte]
                        && row.after == row.before
                        && row.kind == DiagnosticMemoryAccessKind::InstructionFetch
                        && row.privacy_tag == DiagnosticMemoryPrivacyTag::Public
                }));
            }
        });
    }

    #[test]
    fn prepared_fetch_capacity_refuses_before_opcode_gas_or_register_change() {
        let mut program = ProgramMetadata::default().encode();
        program.extend_from_slice(&wide::encode_halt().to_le_bytes());
        let mut vm = IVM::new(100);
        vm.load_program(&program).unwrap();
        let step_budget = AllocationBudget::new(std::mem::size_of::<DiagnosticStepRecord>());
        let mut steps = DiagnosticStepRecorder::try_new(1, &step_budget).unwrap();
        let access_budget = budget_for_rows(3);
        let accesses = DiagnosticMemoryAccessRecorder::try_new(3, &access_budget).unwrap();

        assert_eq!(
            vm.run_with_host_diagnostic_steps_and_memory(
                &mut DefaultHost::default(),
                &mut steps,
                &accesses,
            ),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        assert!(accesses.is_empty());
        assert_eq!(steps.records().len(), 1);
        assert_eq!(steps.records()[0].before, steps.records()[0].after);
    }

    #[test]
    fn diagnostic_prepared_fetch_rejects_stale_word_without_retaining_rows() {
        let mut memory = Memory::new();
        memory.load_code(&[1, 2, 3, 4]).unwrap();
        let budget = budget_for_rows(4);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(4, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();

        assert_eq!(
            memory.diagnostic_record_prepared_fetch(0, u32::from_le_bytes([9, 2, 3, 4])),
            Err(VMError::DecodeError)
        );
        assert!(recorder.is_empty());
        memory
            .diagnostic_record_prepared_fetch(0, u32::from_le_bytes([1, 2, 3, 4]))
            .unwrap();
        recorder.with_records(|rows| {
            assert_eq!(rows.len(), 4);
            assert!(rows.iter().all(|row| {
                row.kind == DiagnosticMemoryAccessKind::InstructionFetch
                    && row.privacy_tag == DiagnosticMemoryPrivacyTag::Public
            }));
        });
    }

    #[test]
    fn admitted_prepared_fetch_preserves_every_physical_alignment_and_refuses_false_bytes() {
        use crate::execution_diagnostics::DiagnosticExecutionRecorders;
        let interface = crate::metadata::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            callables: vec![ivm_abi::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 512,
                arguments: ivm_abi::call::CallSchemaV1::empty(),
                results: ivm_abi::call::CallSchemaV1::unit(),
            }],
            seiyaku_name: "DiagnosticAlignment".to_owned(),
            compiler_fingerprint: "memory-diagnostics-test".to_owned(),
            abi_hash: crate::syscalls::compute_abi_hash(crate::SyscallPolicy::AbiV1),
            features_bitmap: crate::CONTRACT_FEATURE_BIT_ZK,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![crate::metadata::EmbeddedEntrypointDescriptor {
                name: "main".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization:
                    iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let instructions = [
            wide::encode_store(instruction::wide::memory::STORE64, 12, 0, 0),
            wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 12, 0),
            wide::encode_ri(instruction::wide::arithmetic::ADDI, 11, 0, 1),
            wide::encode_rr(instruction::wide::control::JALR, 0, 1, 0),
        ];
        for alignment in 0..4 {
            let prefix = (1..=32)
                .map(|length| {
                    let mut interface = interface.clone();
                    interface.compiler_fingerprint = "x".repeat(length);
                    interface.encode_section()
                })
                .find(|prefix| prefix.len() % 4 == alignment)
                .expect("canonical contract prefix covers all physical alignments");
            let mut bytes = ProgramMetadata {
                mode: crate::metadata::mode::ZK,
                max_cycles: 64,
                ..ProgramMetadata::default()
            }
            .encode();
            bytes.extend_from_slice(&prefix);
            bytes.extend(instructions.into_iter().flat_map(u32::to_le_bytes));
            let contract = crate::prepare_contract(Arc::<[u8]>::from(bytes)).unwrap();
            let first_pc = contract.instruction_entry_pc();
            assert_eq!(first_pc % 4, alignment as u64);
            assert!(contract.is_instruction_boundary(0));
            let first_word = u32::from_le_bytes(
                contract.artifact()[contract.code_offset()..contract.code_offset() + 4]
                    .try_into()
                    .unwrap(),
            );
            let mut vm = IVM::new(10_000);
            vm.load_prepared(&contract).unwrap();
            vm.memory.clear_tracking();
            let budget = budget_for_rows(4);
            let accesses = DiagnosticMemoryAccessRecorder::try_new(4, &budget).unwrap();
            accesses.begin_run(true).unwrap();
            vm.memory
                .install_diagnostic_access_recorder(accesses.shared())
                .unwrap();
            for (pc, word) in [
                (first_pc, first_word ^ 1),
                (vm.memory.code_len() - 3, first_word),
                (u64::MAX - 2, first_word),
            ] {
                assert_eq!(
                    vm.memory.diagnostic_record_prepared_fetch(pc, word),
                    Err(VMError::DecodeError)
                );
                assert!(accesses.is_empty());
                assert!(vm.memory.try_read_log_snapshot().unwrap().is_empty());
            }
            vm.memory
                .diagnostic_record_prepared_fetch(first_pc, first_word)
                .unwrap();
            accesses.with_records(|rows| {
                assert_eq!(rows.len(), 4);
                for (byte, row) in rows.iter().enumerate() {
                    assert_eq!(row.address, first_pc + byte as u64);
                    assert_eq!(row.byte_offset, byte as u32);
                    assert_eq!(
                        (row.before, row.after),
                        (
                            first_word.to_le_bytes()[byte],
                            first_word.to_le_bytes()[byte]
                        )
                    );
                    assert_eq!(row.kind, DiagnosticMemoryAccessKind::InstructionFetch);
                    assert_eq!(row.privacy_tag, DiagnosticMemoryPrivacyTag::Public);
                }
            });
            assert!(vm.memory.try_read_log_snapshot().unwrap().is_empty());
            vm.memory.clear_diagnostic_access_recorder();

            let plan = DiagnosticExecutionRecorders::allocation_plan(32, 512, None).unwrap();
            let budget = AllocationBudget::new(plan.requested_bytes());
            let mut recorders =
                DiagnosticExecutionRecorders::try_new(32, 512, None, &budget).unwrap();
            vm.run_with_host_diagnostic_steps_and_memory(
                &mut DefaultHost::default(),
                &mut recorders.steps,
                &recorders.memory_accesses,
            )
            .unwrap();
            assert_eq!(vm.public_call_result_word(0), Ok(0));
            assert_eq!(recorders.steps.records()[0].before.pc, first_pc);
            recorders.memory_accesses.with_records(|rows| {
                let fetched = rows
                    .iter()
                    .filter(|row| row.kind == DiagnosticMemoryAccessKind::InstructionFetch)
                    .collect::<Vec<_>>();
                assert_eq!(fetched.len(), recorders.steps.records().len() * 4);
                for (step, bytes) in recorders
                    .steps
                    .records()
                    .iter()
                    .zip(fetched.chunks_exact(4))
                {
                    assert!(contract.is_instruction_boundary(step.before.pc - first_pc));
                    let instruction = step.instruction.unwrap().to_le_bytes();
                    for (byte, row) in bytes.iter().enumerate() {
                        assert_eq!(row.address, step.before.pc + byte as u64);
                        assert_eq!(
                            (row.before, row.after),
                            (instruction[byte], instruction[byte])
                        );
                    }
                }
            });
        }
    }

    #[test]
    fn unprepared_decoder_keeps_read_set_and_labels_fetch() {
        let mut memory = Memory::new();
        let word = wide::encode_halt();
        memory.load_code(&word.to_le_bytes()).unwrap();
        let budget = budget_for_rows(4);
        let recorder = DiagnosticMemoryAccessRecorder::try_new(4, &budget).unwrap();
        recorder.begin_run(false).unwrap();
        memory
            .install_diagnostic_access_recorder(recorder.shared())
            .unwrap();

        assert_eq!(decoder::decode(&memory, 0), Ok(word));
        assert_eq!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")
                .len(),
            1
        );
        assert_eq!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")[0]
                .addr,
            0
        );
        assert_eq!(
            memory
                .try_read_log_snapshot()
                .expect("allocate read-log snapshot")[0]
                .len,
            4
        );
        recorder.with_records(|rows| {
            assert_eq!(rows.len(), 4);
            assert!(rows.iter().enumerate().all(|(offset, row)| {
                row.kind == DiagnosticMemoryAccessKind::InstructionFetch
                    && row.privacy_tag == DiagnosticMemoryPrivacyTag::Public
                    && row.before == word.to_le_bytes()[offset]
            }));
        });
    }
}
