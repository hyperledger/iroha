//! Fallible independent VM snapshots with retained allocation ownership.
//!
//! Mutable memory, trace and diagnostic buffers are copied only after reserving
//! their storage. Immutable admitted programs remain shared between snapshots.

use super::{IVM, diagnostic::TrapSnapshot};
#[cfg(test)]
use super::{
    REFUSE_DIAGNOSTIC_SNAPSHOT_FOR_TEST, REFUSE_TRACE_SNAPSHOT_FOR_TEST,
    REFUSE_WORKER_SNAPSHOT_FOR_TEST,
};
use crate::{
    contract_return_stack::ContractReturnStack,
    error::VMError,
    memory::Memory,
    metadata::{
        EmbeddedContractDebugInfoV1, EmbeddedFunctionBudgetReportV1, EmbeddedSourceLocation,
        EmbeddedSourceMapEntryV1,
    },
    private_memory_ranges::PrivateMemoryRanges,
    registers::Registers,
    zk::{self, DeltaTraceLog},
};

struct SnapshotTraceCopies {
    constraints: zk::ConstraintLog,
    mem_log: zk::MemLog,
    reg_log: zk::RegLog,
    trace_log: DeltaTraceLog,
    step_log: zk::StepLog,
    pc_trace: zk::PcTraceLog,
    delta_trace: DeltaTraceLog,
    contract_return_stack: ContractReturnStack,
    contract_debug: Option<EmbeddedContractDebugInfoV1>,
    last_diagnostic: Option<TrapSnapshot>,
}
impl SnapshotTraceCopies {
    fn try_new(
        vm: &IVM,
        reg_log: &zk::RegLog,
        scope: Option<&iroha_allocation::AllocationScope<'_>>,
    ) -> Result<Self, VMError> {
        let trace_storage = vm.try_clone_trace_storage(scope)?;
        let mut copied = Self {
            constraints: vm.constraints.try_clone_allocation()?,
            mem_log: vm.mem_log.try_clone_allocation()?,
            reg_log: reg_log.try_clone_allocation(scope)?,
            trace_log: trace_storage.cycles,
            step_log: vm.step_log.try_clone_allocation()?,
            pc_trace: trace_storage.pcs,
            delta_trace: trace_storage.runtime,
            contract_return_stack: vm.contract_return_stack.try_copy_exact()?,
            contract_debug: None,
            last_diagnostic: None,
        };
        #[cfg(test)]
        if REFUSE_DIAGNOSTIC_SNAPSHOT_FOR_TEST.with(std::cell::Cell::get) {
            return Err(allocation_unavailable());
        }
        copied.contract_debug = vm
            .contract_debug
            .as_ref()
            .map(try_clone_contract_debug)
            .transpose()?;
        // The copied source index resolves against this snapshot's copied debug owner.
        copied.last_diagnostic = vm.last_diagnostic;
        Ok(copied)
    }
    fn allocated_bytes(&self) -> Result<usize, VMError> {
        trace_allocation_bytes(
            &self.constraints,
            &self.mem_log,
            self.contract_debug.as_ref(),
        )
    }
}
fn trace_allocation_bytes(
    constraints: &zk::ConstraintLog,
    mem_log: &zk::MemLog,
    contract_debug: Option<&EmbeddedContractDebugInfoV1>,
) -> Result<usize, VMError> {
    let unavailable =
        || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
    let mut total = 0usize;
    for bytes in [
        constraints.allocated_bytes()?,
        mem_log.allocated_bytes()?,
        contract_debug.map_or(Ok(0), contract_debug_allocation_bytes)?,
    ] {
        total = total.checked_add(bytes).ok_or_else(unavailable)?;
    }
    (total <= isize::MAX as usize)
        .then_some(total)
        .ok_or_else(unavailable)
}
fn allocation_unavailable() -> VMError {
    VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
}
pub(super) fn checked_allocation_bytes(total: &mut usize, bytes: usize) -> Result<(), VMError> {
    *total = total
        .checked_add(bytes)
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or_else(allocation_unavailable)?;
    Ok(())
}
fn vector_allocation_bytes<T>(values: &Vec<T>) -> Result<usize, VMError> {
    values
        .capacity()
        .checked_mul(std::mem::size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or_else(allocation_unavailable)
}
fn try_clone_string(value: &str) -> Result<String, VMError> {
    if value.len() > isize::MAX as usize {
        return Err(allocation_unavailable());
    }
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| allocation_unavailable())?;
    copied.push_str(value);
    Ok(copied)
}
fn try_clone_source_location(
    source: &EmbeddedSourceLocation,
) -> Result<EmbeddedSourceLocation, VMError> {
    Ok(EmbeddedSourceLocation {
        source_path: source
            .source_path
            .as_deref()
            .map(try_clone_string)
            .transpose()?,
        source_id: source.source_id,
        byte_start: source.byte_start,
        byte_end: source.byte_end,
        line: source.line,
        column: source.column,
    })
}
fn try_clone_contract_debug(
    debug: &EmbeddedContractDebugInfoV1,
) -> Result<EmbeddedContractDebugInfoV1, VMError> {
    let _ = debug
        .source_map
        .len()
        .checked_mul(std::mem::size_of::<EmbeddedSourceMapEntryV1>())
        .ok_or_else(allocation_unavailable)?;
    let _ = debug
        .budget_report
        .len()
        .checked_mul(std::mem::size_of::<EmbeddedFunctionBudgetReportV1>())
        .ok_or_else(allocation_unavailable)?;
    let mut source_map = Vec::new();
    source_map
        .try_reserve_exact(debug.source_map.len())
        .map_err(|_| allocation_unavailable())?;
    for entry in &debug.source_map {
        source_map.push(EmbeddedSourceMapEntryV1 {
            function_name: try_clone_string(&entry.function_name)?,
            pc_start: entry.pc_start,
            pc_end: entry.pc_end,
            source: try_clone_source_location(&entry.source)?,
        });
    }
    let mut budget_report = Vec::new();
    budget_report
        .try_reserve_exact(debug.budget_report.len())
        .map_err(|_| allocation_unavailable())?;
    for entry in &debug.budget_report {
        budget_report.push(EmbeddedFunctionBudgetReportV1 {
            function_name: try_clone_string(&entry.function_name)?,
            pc_start: entry.pc_start,
            pc_end: entry.pc_end,
            bytecode_bytes: entry.bytecode_bytes,
            bytecode_words: entry.bytecode_words,
            frame_bytes: entry.frame_bytes,
            jump_span_words: entry.jump_span_words,
            jump_range_risk: entry.jump_range_risk,
            source: entry
                .source
                .as_ref()
                .map(try_clone_source_location)
                .transpose()?,
        });
    }
    Ok(EmbeddedContractDebugInfoV1 {
        source_map,
        budget_report,
    })
}
pub(super) fn contract_debug_allocation_bytes(
    debug: &EmbeddedContractDebugInfoV1,
) -> Result<usize, VMError> {
    let mut total = 0;
    checked_allocation_bytes(&mut total, vector_allocation_bytes(&debug.source_map)?)?;
    checked_allocation_bytes(&mut total, vector_allocation_bytes(&debug.budget_report)?)?;
    for entry in &debug.source_map {
        checked_allocation_bytes(&mut total, entry.function_name.capacity())?;
        if let Some(path) = &entry.source.source_path {
            checked_allocation_bytes(&mut total, path.capacity())?;
        }
    }
    for entry in &debug.budget_report {
        checked_allocation_bytes(&mut total, entry.function_name.capacity())?;
        if let Some(path) = entry
            .source
            .as_ref()
            .and_then(|source| source.source_path.as_ref())
        {
            checked_allocation_bytes(&mut total, path.capacity())?;
        }
    }
    Ok(total)
}
impl IVM {
    fn clone_with_owned_snapshot(
        &self,
        registers: Registers,
        memory: Memory,
        private_memory_bytes: PrivateMemoryRanges,
        cache_reservation: crate::cache_memory::MemoryReservation,
        mut traces: SnapshotTraceCopies,
    ) -> Result<Self, VMError> {
        let reg_log = zk::SharedRegLog::try_from_owned_rows(
            std::mem::replace(
                &mut traces.reg_log,
                zk::RegLog::new(self.memory.allocation_budget()),
            ),
            self.memory.allocation_budget(),
        )?;
        Ok(Self {
            cache_reservation,
            registers,
            memory,
            private_memory_bytes,
            pc: self.pc,
            host: None,
            gas_limit: self.gas_limit,
            gas_remaining: self.remaining_gas(),
            // A clone is an independent VM, not a continuation of an active
            // host call, so fold any transient reserve into ordinary gas.
            syscall_gas_reserve: 0,
            staged_syscall: None,
            last_staged_syscall: None,
            argument_decode_prepaid_gas: None,
            captured_root_tables: None,
            cycles: self.cycles,
            active_cycle_budget: self.active_cycle_budget.clone(),
            halted: self.halted,
            constraint_failed: self.constraint_failed,
            contract_abort_error: self.contract_abort_error.clone(),
            constraints: traces.constraints,
            mem_log: traces.mem_log,
            reg_log: Some(reg_log),
            host_trace_log_detached: false,
            host_trace_invocation_log: None,
            proof_state_epoch: self.proof_state_epoch,
            trace_log: traces.trace_log,
            step_log: traces.step_log,
            trace_mode: self.trace_mode,
            pc_trace: traces.pc_trace,
            delta_trace: traces.delta_trace,
            vector_enabled: self.vector_enabled,
            max_vector_lanes: self.max_vector_lanes,
            vector_length: self.vector_length,
            max_cycles: self.max_cycles,
            metadata: self.metadata.clone(),
            code_hash: self.code_hash,
            contract_interface: self.contract_interface.clone(),
            call_layouts: self.call_layouts.clone(),
            contract_debug: traces.contract_debug,
            literal_table: self.literal_table.clone(),
            predecoded: self.predecoded.clone(),
            prepared: self.prepared.clone(),
            prepared_required: self.prepared_required,
            allow_koto_test_syscalls: self.allow_koto_test_syscalls,
            strict_return_integrity: self.strict_return_integrity,
            contract_return_stack: traces.contract_return_stack,
            contract_outer_return_pc: self.contract_outer_return_pc,
            // A snapshot never adopts another invocation's native producer custody.
            native_packets: None,
            #[cfg(test)]
            predecoded_misses: 0,
            #[cfg(test)]
            program_parse_attempts: 0,
            #[cfg(test)]
            prepared_loads: 0,
            scheduler_limits: self.scheduler_limits,
            zk_mode: self.zk_mode,
            zk_trace_enabled: self.zk_trace_enabled,
            entrypoint_pc: self.entrypoint_pc,
            program_prefix_len: self.program_prefix_len,
            last_diagnostic: traces.last_diagnostic,
            pc_alignment: self.pc_alignment,
            input_bump_next: self.input_bump_next,
            acceleration_policy: self.acceleration_policy,
            hardware_capabilities: self.hardware_capabilities,
        })
    }

    /// Copy the independent memory, register, and trace images before any
    /// host observes the snapshot. Immutable decoded program owners remain shared.
    pub(crate) fn try_clone_snapshot(&self) -> Result<Self, VMError> {
        // A partially copied funded root owner may retire while copying the
        // mutex-protected register log. Keep original-pool callbacks outside
        // that physical guard on success, refusal and unwind.
        match self.memory.allocation_budget() {
            Some(budget) => budget.with_deferred_refund_notifications(|scope| {
                self.try_clone_snapshot_inner(Some(scope))
            }),
            None => self.try_clone_snapshot_inner(None),
        }
    }

    fn try_clone_snapshot_inner(
        &self,
        scope: Option<&iroha_allocation::AllocationScope<'_>>,
    ) -> Result<Self, VMError> {
        #[cfg(test)]
        if REFUSE_WORKER_SNAPSHOT_FOR_TEST.with(std::cell::Cell::get) {
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable,
            ));
        }
        let memory = self.memory.try_clone_for_runtime_template(None)?;
        let registers = self.registers.try_clone_for_runtime_template()?;
        let private_memory_bytes = self.private_memory_bytes.try_clone()?;
        #[cfg(test)]
        let unavailable =
            || VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable);
        let empty = zk::RegLog::new(self.memory.allocation_budget());
        let reg_log = self.reg_log.as_ref().map(zk::SharedRegLog::lock);
        let reg_log_value = reg_log.as_deref().unwrap_or(&empty);
        let trace_bytes = trace_allocation_bytes(
            &self.constraints,
            &self.mem_log,
            self.contract_debug.as_ref(),
        )?;
        let reserved_bytes = trace_bytes;
        let mut reservation =
            crate::cache_memory::MemoryReservation::active_unmeasured(reserved_bytes);
        #[cfg(test)]
        if REFUSE_TRACE_SNAPSHOT_FOR_TEST.with(std::cell::Cell::get) {
            return Err(unavailable());
        }
        let traces = SnapshotTraceCopies::try_new(self, reg_log_value, scope)?;
        drop(reg_log);
        let actual_bytes = traces.allocated_bytes()?;
        reservation.set_known_bytes(actual_bytes);
        reservation.mark_unmeasured();
        self.clone_with_owned_snapshot(registers, memory, private_memory_bytes, reservation, traces)
    }
}
