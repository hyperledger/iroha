//! Prepaid local snapshots of interpreter step boundaries.
//!
//! These rows are diagnostic material for developing a complete execution AIR.
//! They do not authenticate memory, host syscalls, code fetch, or state effects,
//! and cannot authorize proof-backed transactions. A caller must keep the
//! recorder local because register snapshots can contain private values.
//! Dropping the recorder volatile-erases its retained register values and tags, but
//! `Copy` snapshots and
//! append temporaries can leave transient copies. This is not a private-witness
//! cleanup or custody boundary for production proving.

use crate::{
    VMError,
    error::{ExecutionDeferral, VmTrapKind},
    execution_memory::{ExecutionBuffer, ExecutionMemoryLease, ExecutionMemoryPlan},
};
use iroha_allocation::AllocationBudget;

mod private_disposal;

/// Complete register and control snapshot at one interpreter boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticStepState {
    /// Program counter at this boundary.
    pub pc: u64,
    /// Unreserved gas still available at this boundary.
    pub gas_remaining: u64,
    /// Completed architectural cycles.
    pub cycles: u64,
    /// Logical vector length, independent of physical hardware.
    pub vector_length: usize,
    /// Whether a terminal instruction has completed.
    pub halted: bool,
    /// Whether a ZK assertion has failed.
    pub constraint_failed: bool,
    /// All architectural register values, including the hardwired zero register.
    pub registers: [u64; 256],
    /// Privacy tags corresponding to `registers`.
    pub tags: [bool; 256],
}

impl Default for DiagnosticStepState {
    fn default() -> Self {
        Self {
            pc: 0,
            gas_remaining: 0,
            cycles: 0,
            vector_length: 0,
            halted: false,
            constraint_failed: false,
            registers: [0; 256],
            tags: [false; 256],
        }
    }
}

/// Outcome of one attempted instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticStepOutcome {
    /// The instruction completed and its successor boundary was captured.
    Completed,
    /// The attempt trapped before it completed.
    Trapped(VmTrapKind),
}

/// One attempted instruction with exact local before/after register snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticStepRecord {
    /// Fetched word, absent if instruction fetch itself failed.
    pub instruction: Option<u32>,
    /// Wide opcode decoded from `instruction`, when fetch succeeded.
    pub opcode: Option<u8>,
    /// Base instruction debit, excluding staged and reserved host work.
    pub opcode_gas: Option<u64>,
    /// State just before fetch and gas admission.
    pub before: DiagnosticStepState,
    /// State after completion or at the trap boundary.
    pub after: DiagnosticStepState,
    /// Whether this attempt completed.
    pub outcome: DiagnosticStepOutcome,
}

impl DiagnosticStepRecord {
    /// Iterate net register and tag changes without allocating a second trace.
    pub fn changed_registers(
        &self,
    ) -> impl Iterator<Item = (usize, (u64, bool), (u64, bool))> + '_ {
        (0..self.before.registers.len()).filter_map(|index| {
            let before = (self.before.registers[index], self.before.tags[index]);
            let after = (self.after.registers[index], self.after.tags[index]);
            (before != after).then_some((index, before, after))
        })
    }
}

/// Final local outcome, including padding performed after the last instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticRunEnd {
    /// Final interpreter state after padding and return checks.
    pub state: DiagnosticStepState,
    /// Number of ZK padding cycles after the last instruction.
    pub padding_cycles: u64,
    /// Local completion or trap category.
    pub outcome: Result<(), VmTrapKind>,
}

/// One in-flight step. Its prestate is cleared if execution unwinds.
pub(crate) struct PendingDiagnosticStep {
    instruction: Option<u32>,
    opcode_gas: Option<u64>,
    before: DiagnosticStepState,
}

impl PendingDiagnosticStep {
    /// Fill the fetched word and priced base opcode after successful fetch.
    pub(crate) fn fetched(&mut self, instruction: u32) {
        self.instruction = Some(instruction);
    }

    /// Fill the priced base opcode after cost derivation.
    pub(crate) fn priced(&mut self, gas: u64) {
        self.opcode_gas = Some(gas);
    }
}

/// Fixed-capacity, prepaid local recorder for one VM invocation.
///
/// The buffer is allocated before execution. Reaching its cap produces a local
/// execution deferral before the next instruction; it cannot alter ordinary
/// consensus execution because only the explicit diagnostic run uses it.
/// Drop volatile-erases retained register values and tags; callers must not treat it as a secure
/// private-witness container because copied rows and stack temporaries remain.
pub struct DiagnosticStepRecorder {
    records: ExecutionBuffer<DiagnosticStepRecord>,
    capacity: usize,
    end: Option<DiagnosticRunEnd>,
}

impl DiagnosticStepRecorder {
    pub(crate) fn allocation_plan(capacity: usize) -> Result<ExecutionMemoryPlan, VMError> {
        ExecutionMemoryPlan::array::<DiagnosticStepRecord>(capacity)
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable))
    }

    pub(crate) fn try_new_from_lease(
        capacity: usize,
        lease: &mut ExecutionMemoryLease,
    ) -> Result<Self, VMError> {
        let records = ExecutionBuffer::new(capacity, lease)
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable))?;
        Ok(Self {
            records,
            capacity,
            end: None,
        })
    }

    /// Reserve and allocate the entire requested row capacity before execution.
    ///
    /// # Errors
    /// Returns a local deferral if the finite budget or physical allocator
    /// cannot fund the exact row backing.
    pub fn try_new(capacity: usize, budget: &AllocationBudget) -> Result<Self, VMError> {
        let plan = Self::allocation_plan(capacity)?;
        let mut lease = ExecutionMemoryLease::reserve(budget, plan)
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity))?;
        Self::try_new_from_lease(capacity, &mut lease)
    }

    /// Borrow the initialized local rows.
    #[must_use]
    pub fn records(&self) -> &[DiagnosticStepRecord] {
        self.records.as_slice()
    }

    /// Borrow the final local outcome, if the run returned normally.
    #[must_use]
    pub fn end(&self) -> Option<&DiagnosticRunEnd> {
        self.end.as_ref()
    }

    /// Reject reuse of a recorder whose prior invocation may retain private data.
    pub(crate) fn begin_run(&self) -> Result<(), VMError> {
        if !self.records().is_empty() || self.end.is_some() {
            return Err(VMError::HostUnavailable);
        }
        Ok(())
    }

    /// Check capacity before an instruction can mutate VM or host state.
    pub(crate) fn begin_step(
        &self,
        mut before: DiagnosticStepState,
    ) -> Result<PendingDiagnosticStep, VMError> {
        if self.records().len() >= self.capacity {
            before.scrub();
            return Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity,
            ));
        }
        let pending = PendingDiagnosticStep {
            instruction: None,
            opcode_gas: None,
            before,
        };
        before.scrub();
        Ok(pending)
    }

    /// Complete the already funded row; this never grows its allocation.
    pub(crate) fn finish_step(
        &mut self,
        pending: PendingDiagnosticStep,
        mut after: DiagnosticStepState,
        outcome: DiagnosticStepOutcome,
    ) -> Result<(), VMError> {
        let mut records = [DiagnosticStepRecord {
            instruction: pending.instruction,
            opcode: pending.instruction.map(|word| (word >> 24) as u8),
            opcode_gas: pending.opcode_gas,
            before: pending.before,
            after,
            outcome,
        }];
        after.scrub();
        let result = self
            .records
            .append(&records)
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable));
        records[0].scrub();
        result
    }

    /// Record a terminal boundary without adding a trace row.
    pub(crate) fn finish_run(&mut self, mut end: DiagnosticRunEnd) {
        if let Some(previous) = &mut self.end {
            previous.state.scrub();
        }
        self.end = Some(end);
        end.state.scrub();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IVM, encoding, host::DefaultHost, instruction};

    fn budget_for_rows(count: usize) -> AllocationBudget {
        AllocationBudget::new(count * std::mem::size_of::<DiagnosticStepRecord>())
    }

    fn add_then_halt() -> (u32, Vec<u8>) {
        let add = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 7, 0, 9);
        let mut bytes = add.to_le_bytes().to_vec();
        bytes.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
        (add, bytes)
    }

    #[test]
    fn completed_rows_capture_exact_pre_post_register_tag_and_gas_boundaries() {
        let (add, code) = add_then_halt();
        let budget = budget_for_rows(2);
        let mut recorder = DiagnosticStepRecorder::try_new(2, &budget).unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            2 * std::mem::size_of::<DiagnosticStepRecord>()
        );
        let mut vm = IVM::new(100);
        vm.load_code(&code).unwrap();
        let mut host = DefaultHost::default();
        vm.run_with_host_diagnostic_steps(&mut host, &mut recorder)
            .unwrap();
        let rows = recorder.records();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].instruction, Some(add));
        assert_eq!(rows[0].opcode, Some(instruction::wide::arithmetic::ADDI));
        assert_eq!(rows[0].outcome, DiagnosticStepOutcome::Completed);
        assert_eq!(rows[0].before.pc, 0);
        assert_eq!(rows[0].after.pc, 4);
        assert_eq!(rows[0].before.cycles, 0);
        assert_eq!(rows[0].after.cycles, 1);
        assert_eq!(
            rows[0].before.gas_remaining - rows[0].after.gas_remaining,
            rows[0].opcode_gas.unwrap()
        );
        assert_eq!(
            rows[0].changed_registers().collect::<Vec<_>>(),
            vec![(7, (0, false), (9, false))]
        );
        assert_eq!(rows[1].before, rows[0].after);
        assert!(rows[1].after.halted);
        assert_eq!(rows[1].after.pc, 8);
        assert_eq!(recorder.end().unwrap().padding_cycles, 0);
        assert!(matches!(recorder.end().unwrap().outcome, Ok(())));
        assert_eq!(recorder.end().unwrap().state, rows[1].after);
        assert!(matches!(
            recorder.begin_run(),
            Err(VMError::HostUnavailable)
        ));
        drop(recorder);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn attempted_out_of_gas_is_a_trap_row_without_a_guest_mutation() {
        let (add, code) = add_then_halt();
        let budget = budget_for_rows(1);
        let mut recorder = DiagnosticStepRecorder::try_new(1, &budget).unwrap();
        let mut vm = IVM::new(0);
        vm.load_code(&code).unwrap();
        let mut host = DefaultHost::default();
        assert!(matches!(
            vm.run_with_host_diagnostic_steps(&mut host, &mut recorder),
            Err(VMError::OutOfGas)
        ));
        let row = &recorder.records()[0];
        assert_eq!(row.instruction, Some(add));
        assert_eq!(
            row.outcome,
            DiagnosticStepOutcome::Trapped(VmTrapKind::OutOfGas)
        );
        assert_eq!(row.before, row.after);
        assert_eq!(recorder.end().unwrap().outcome, Err(VmTrapKind::OutOfGas));
    }

    #[test]
    fn recorder_capacity_defers_before_next_instruction_and_preserves_previous_row() {
        let (_, code) = add_then_halt();
        let budget = budget_for_rows(1);
        let mut recorder = DiagnosticStepRecorder::try_new(1, &budget).unwrap();
        let mut vm = IVM::new(100);
        vm.load_code(&code).unwrap();
        let mut host = DefaultHost::default();
        assert!(
            matches!(vm.run_with_host_diagnostic_steps(&mut host, &mut recorder), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        );
        assert_eq!(recorder.records().len(), 1);
        assert_eq!(recorder.records()[0].after.registers[7], 9);
        assert_eq!(recorder.records()[0].after.pc, 4);
        assert_eq!(recorder.end().unwrap().outcome, Err(VmTrapKind::Other));
        let too_small = AllocationBudget::new(std::mem::size_of::<DiagnosticStepRecord>() - 1);
        assert!(matches!(
            DiagnosticStepRecorder::try_new(1, &too_small),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            ))
        ));
        assert_eq!(too_small.reserved_bytes(), 0);
    }

    #[test]
    fn diagnostic_mutations_change_records_but_do_not_prove_execution() {
        let before = DiagnosticStepState::default();
        let mut after = before;
        after.pc = 4;
        after.registers[7] = 9;
        after.tags[7] = true;
        let baseline = DiagnosticStepRecord {
            instruction: Some(0x0102_0304),
            opcode: Some(1),
            opcode_gas: Some(3),
            before,
            after,
            outcome: DiagnosticStepOutcome::Completed,
        };
        assert_eq!(
            baseline.changed_registers().collect::<Vec<_>>(),
            vec![(7, (0, false), (9, true))]
        );
        let mut changed = baseline;
        changed.instruction = Some(0x0502_0304);
        assert_ne!(changed, baseline);
        changed = baseline;
        changed.opcode_gas = Some(4);
        assert_ne!(changed, baseline);
        changed = baseline;
        changed.after.pc = 8;
        assert_ne!(changed, baseline);
        changed = baseline;
        changed.after.tags[7] = false;
        assert_ne!(changed, baseline);
        changed = baseline;
        changed.outcome = DiagnosticStepOutcome::Trapped(VmTrapKind::Other);
        assert_ne!(changed, baseline);
    }
}
