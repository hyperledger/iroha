//! Original-funded runtime and completed-cycle observations admitted before effects.
//!
//! Local trace-owner mismatches defer execution without becoming transaction
//! rejections. Existing ZK host-isolation errors keep PrivacyViolation precedence.
//! The run owner begins before root preparation, records the initial observation
//! before fetch, and admits each next observation before the preceding instruction
//! changes registers. It finishes on every result, including the unwind branch.

#[cfg(test)]
use super::zk;
use super::{IVM, TraceMode, VMError, completed_instruction_cycles};
use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationScope};

mod change_counts;

/// Move-only identity for one invocation's admitted observation policy.
///
/// This stores no private state and owns no caller-supplied row counts. A host
/// changing the trace mode or resetting/reloading this VM invalidates the token,
/// including when formal ZK tracing is disabled. Never repair that mismatch by
/// allocating a replacement observation after the host's effects.
pub(super) struct InvocationTrace {
    epoch: u64,
    mode: TraceMode,
    cycles: bool,
    /// Collection policy of the thread-local invocation scope at admission.
    ///
    /// The run installs that scope before admission and keeps it until the
    /// token finishes, so its policy cannot change in between; reusing it keeps
    /// the per-step ownership checks free of TLS lookups. Without a scope the
    /// VM's current configuration is consulted, as `zk_trace_collection_enabled`
    /// does.
    scoped_collection: Option<bool>,
    original: Option<AllocationBudget>,
}
impl InvocationTrace {
    fn collection_enabled(&self, vm: &IVM) -> bool {
        self.scoped_collection
            .unwrap_or(vm.zk_mode && vm.zk_trace_enabled)
    }
    fn owns(&self, vm: &IVM) -> bool {
        self.epoch == vm.proof_state_epoch
            && self.mode == vm.trace_mode
            && self.cycles == (self.collection_enabled(vm) && vm.max_cycles != 0)
            && match (&self.original, vm.memory.allocation_budget()) {
                (Some(original), Some(current)) => original.same_pool(current),
                (None, None) => true,
                _ => false,
            }
    }
    fn check(&self, vm: &IVM) -> Result<(), VMError> {
        self.owns(vm)
            .then_some(())
            .ok_or(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::TraceOwnerUnavailable,
            ))
    }
    fn discard_unobserved(&self, vm: &mut IVM) {
        // A newer/replaced invocation owns any new pending quota. Existing
        // lifecycle operations already scrub the invalidated original logs.
        if self.owns(vm) {
            vm.trace_log.discard_unobserved();
            vm.delta_trace.discard_unobserved();
        }
    }
}

/// Borrowed preparation custody; refusal or unwind cancels only unused spans.
///
/// No storage is refunded here. Original allocation scopes and their mutable
/// log borrows finish before this guard retires; cancellation only clears the
/// inline pending quota. The enclosing invocation owns the panic boundary.
struct TracePreparation<'vm, 'invocation> {
    vm: &'vm mut IVM,
    invocation: &'invocation InvocationTrace,
    armed: bool,
}
impl Drop for TracePreparation<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            self.invocation.discard_unobserved(self.vm);
        }
    }
}

#[cfg(test)]
pub(super) struct TraceStorageCopies {
    pub(super) cycles: zk::DeltaTraceLog,
    pub(super) runtime: zk::DeltaTraceLog,
    pub(super) pcs: zk::PcTraceLog,
}

impl IVM {
    fn with_trace_scope<T>(
        &mut self,
        operation: impl FnOnce(&mut Self, Option<&AllocationScope<'_>>) -> Result<T, VMError>,
    ) -> Result<T, VMError> {
        // Clone the original budget handle, never its limits or an independent
        // pool. All replacements and partial copies retire inside this scope;
        // callbacks occur only after mutable log borrows have ended.
        match self.memory.allocation_budget().cloned() {
            Some(original) => {
                original.with_deferred_refund_notifications(|scope| operation(self, Some(scope)))
            }
            None => operation(self, None),
        }
    }

    /// Check lifecycle custody before any reset or program-load effects.
    pub(super) fn check_trace_storage_owner(&self) -> Result<(), VMError> {
        match self.memory.allocation_budget() {
            Some(original) => original
                .with_deferred_refund_notifications(|scope| self.validate_trace_scope(Some(scope))),
            None => self.validate_trace_scope(None),
        }
    }

    fn validate_trace_scope(&self, scope: Option<&AllocationScope<'_>>) -> Result<(), VMError> {
        // Check all three before reset/copy/preparation mutates any one owner.
        self.trace_log.validate_scope(scope)?;
        self.delta_trace.validate_scope(scope)?;
        self.pc_trace.validate_scope(scope)
    }

    /// Admit the initial pre-fetch record before root arguments or host effects.
    ///
    /// Capture after `clear_zk_trace_logs` advances the invocation epoch, and
    /// before cycle/halt resets or `begin_root_call` argument preparation. The
    /// root boundary must not clear these logs or advance the epoch again.
    /// The caller has already scrubbed the preceding invocation. Beginning is
    /// otherwise observational: no registers, gas, cycles or guest memory change.
    pub(super) fn begin_trace_invocation(&mut self) -> Result<InvocationTrace, VMError> {
        let mut invocation = InvocationTrace {
            epoch: self.proof_state_epoch,
            mode: self.trace_mode,
            cycles: false,
            scoped_collection: crate::zk::scoped_reg_logger_enabled(),
            original: self.memory.allocation_budget().cloned(),
        };
        invocation.cycles = invocation.collection_enabled(self) && self.max_cycles != 0;
        self.with_trace_scope(|vm, scope| {
            vm.validate_trace_scope(scope)?;
            match invocation.mode {
                TraceMode::Off => Ok(()),
                TraceMode::PcOnly => vm.pc_trace.prepare(1, scope),
                TraceMode::DeltaRegisters => vm.delta_trace.prepare_batch(1, 256, 0, scope),
            }
        })?;
        Ok(invocation)
    }

    /// Publish the already-admitted initial or preceding-instruction observation.
    pub(super) fn record_trace_prefetch(
        &mut self,
        invocation: &InvocationTrace,
    ) -> Result<(), VMError> {
        invocation.check(self)?;
        match invocation.mode {
            TraceMode::Off => {}
            TraceMode::PcOnly => self.pc_trace.record_reserved(self.pc),
            TraceMode::DeltaRegisters => self.delta_trace.record_reserved(
                self.pc,
                self.registers.snapshot(),
                self.registers.snapshot_tags(),
            ),
        }
        Ok(())
    }

    /// Admit completed cycles and the next pre-fetch row, then all later preflight.
    ///
    /// `tail_preflight` admits register rows, syscall shells, shared cycles and
    /// native capture before the caller debits opcode gas or performs effects.
    /// A refused/panicking tail cancels unobserved credit without losing earlier
    /// observations. Nested host callbacks do not own or finish this batch.
    pub(super) fn prepare_trace_instruction<T>(
        &mut self,
        invocation: &InvocationTrace,
        instruction: u32,
        tail_preflight: impl FnOnce(&mut Self) -> Result<T, VMError>,
    ) -> Result<T, VMError> {
        invocation.check(self)?;
        if !invocation.cycles && invocation.mode == TraceMode::Off {
            // Ordinary execution has no trace backing to admit or cancel. Do
            // not clone an allocation owner, enter a refund scope, or classify
            // destinations on this hot path. Tail errors (including the
            // earlier ZK privacy check) and panics propagate unchanged.
            let output = tail_preflight(self)?;
            invocation.check(self)?;
            return Ok(output);
        }
        let changes = if invocation.cycles || invocation.mode == TraceMode::DeltaRegisters {
            change_counts::instruction(instruction, self.vector_length)?
        } else {
            0
        };
        let cycles = if invocation.cycles {
            completed_instruction_cycles(crate::instruction::wide::opcode(instruction))
        } else {
            0
        };
        let mut preparation = TracePreparation {
            vm: self,
            invocation,
            armed: true,
        };
        preparation.vm.with_trace_scope(|vm, scope| {
            vm.validate_trace_scope(scope)?;
            if invocation.cycles {
                let rows = usize::try_from(cycles).map_err(|_| overflow())?;
                vm.step_log.prepare_cycles(cycles)?;
                vm.trace_log.prepare_batch(rows, changes, 0, scope)?;
            }
            match invocation.mode {
                TraceMode::Off => {}
                TraceMode::PcOnly => vm.pc_trace.prepare(1, scope)?,
                TraceMode::DeltaRegisters => {
                    vm.delta_trace.prepare_batch(1, changes, 0, scope)?;
                }
            }
            Ok(())
        })?;
        let output = tail_preflight(preparation.vm)?;
        // No tail may replace the prepaid owner's trace policy and then
        // authorize guest effects under a stale token. A host isolation error
        // has already propagated above, retaining ZK PrivacyViolation precedence.
        invocation.check(preparation.vm)?;
        preparation.armed = false;
        Ok(output)
    }

    /// Admit payable padding only after the final instruction's cycles flushed.
    ///
    /// The caller keeps the existing unpayable-padding OOG path, without calling
    /// this method or attempting to allocate. Padding never consumes the unused
    /// next-pre-fetch runtime record reserved by the terminal instruction.
    pub(super) fn prepare_trace_padding(
        &mut self,
        invocation: &InvocationTrace,
        additional: u64,
    ) -> Result<(), VMError> {
        invocation.check(self)?;
        if !invocation.cycles || additional == 0 {
            return Ok(());
        }
        let mut preparation = TracePreparation {
            vm: self,
            invocation,
            armed: true,
        };
        preparation.vm.with_trace_scope(|vm, scope| {
            vm.validate_trace_scope(scope)?;
            let rows = usize::try_from(additional).map_err(|_| overflow())?;
            vm.step_log.prepare_cycles(additional)?;
            vm.trace_log.prepare_batch(rows, 0, 0, scope)
        })?;
        preparation.armed = false;
        Ok(())
    }

    /// Flush only completed, pre-admitted cycles after delayed native finish.
    pub(super) fn publish_trace_cycles(
        &mut self,
        invocation: &InvocationTrace,
        last_logged_cycle: &mut u64,
    ) -> Result<(), VMError> {
        invocation.check(self)?;
        if !invocation.cycles {
            return Ok(());
        }
        while *last_logged_cycle < self.cycles {
            self.trace_log.record_reserved(
                self.pc,
                self.registers.snapshot(),
                self.registers.snapshot_tags(),
            );
            self.step_log.record_reserved(
                self.pc,
                self.registers.merkle_root(),
                self.memory.current_root(),
            );
            *last_logged_cycle += 1;
        }
        Ok(())
    }

    /// Finish on success, refusal or unwind without erasing initialized history.
    pub(super) fn finish_trace_invocation(&mut self, invocation: InvocationTrace) {
        invocation.discard_unobserved(self);
    }

    /// Retire all delta/PC backing while keeping each original allocation owner.
    pub(super) fn reset_trace_storage(&mut self) -> Result<(), VMError> {
        self.with_trace_scope(|vm, scope| {
            vm.validate_trace_scope(scope)?;
            vm.trace_log.reset(scope)?;
            vm.delta_trace.reset(scope)?;
            vm.pc_trace.reset(scope)
        })
    }

    /// Independently fund all capacities and pending credit inside snapshot scope.
    ///
    /// Snapshot aggregate byte accounting must exclude these three owners. The
    /// caller holds the original deferred-refund scope outside its register-log
    /// mutex, so partial copies retire before any release callback is delivered.
    #[cfg(test)]
    pub(super) fn try_clone_trace_storage(
        &self,
        scope: Option<&AllocationScope<'_>>,
    ) -> Result<TraceStorageCopies, VMError> {
        self.validate_trace_scope(scope)?;
        Ok(TraceStorageCopies {
            cycles: self.trace_log.try_clone_allocation(scope)?,
            runtime: self.delta_trace.try_clone_allocation(scope)?,
            pcs: self.pc_trace.try_clone_allocation(scope)?,
        })
    }
}

fn overflow() -> VMError {
    VMError::AllocationDeferred(AllocationRefusal::DemandOverflow)
}

#[cfg(test)]
mod runtime_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod cycle_tests;
