//! Observe retained diagnostic register fields at their actual backing deallocation.

use super::super::*;
use crate::memory::private_disposal::tests::{
    assert_erased_and_freed, budget, original_credit_at_free, serial, watch, watch_second_span,
};
use std::alloc::Layout;

fn state(value: u64) -> DiagnosticStepState {
    DiagnosticStepState {
        registers: [value; 256],
        tags: [true; 256],
        ..DiagnosticStepState::default()
    }
}

struct RestoreLimit<'a>(&'a AllocationBudget, usize);
impl Drop for RestoreLimit<'_> {
    fn drop(&mut self) {
        self.0.set_limit_bytes(self.1);
    }
}

#[test]
fn prepaid_step_rows_erase_every_initialized_register_span_before_original_refund() {
    let _serial = serial();
    let budget = budget();
    assert_eq!(budget.reserved_bytes(), 0);
    let plan = DiagnosticStepRecorder::allocation_plan(3).unwrap();
    // Observe each before/after span in both initialized rows in separate real
    // destructions. The third prepaid row is uninitialized and is never read.
    for row_index in 0..2 {
        for before in [true, false] {
            let mut parent = ExecutionMemoryLease::reserve(budget, plan).unwrap();
            let restore = RestoreLimit(budget, budget.limit_bytes());
            budget.set_limit_bytes(0);
            let mut recorder = DiagnosticStepRecorder::try_new_from_lease(3, &mut parent).unwrap();
            assert_eq!(parent.remaining_bytes(), 0);
            drop(parent);
            for index in 0..2 {
                let pending = recorder.begin_step(state(0xA5 + index)).unwrap();
                recorder
                    .finish_step(
                        pending,
                        state(0xB6 + index),
                        DiagnosticStepOutcome::Completed,
                    )
                    .unwrap();
            }
            assert_eq!(recorder.records().len(), 2);
            assert_eq!(budget.reserved_bytes(), plan.requested_bytes());
            let base = recorder.records().as_ptr().cast::<u8>();
            let record = &recorder.records()[row_index];
            let target = if before {
                &record.before
            } else {
                &record.after
            };
            assert!(target.registers.iter().all(|value| *value != 0));
            assert!(target.tags.iter().all(|value| *value));
            let _watch = watch(
                base,
                Layout::array::<DiagnosticStepRecord>(3).unwrap(),
                target.registers.as_ptr() as usize - base as usize,
                std::mem::size_of_val(&target.registers),
            );
            watch_second_span(
                target.tags.as_ptr() as usize - base as usize,
                std::mem::size_of_val(&target.tags),
            );
            drop(recorder);
            assert_erased_and_freed();
            assert_eq!(original_credit_at_free(), plan.requested_bytes());
            assert_eq!(budget.reserved_bytes(), 0);
            drop(restore);
        }
    }
}

#[test]
fn pending_step_erases_its_original_box_during_unwind() {
    let _serial = serial();
    let budget = AllocationBudget::new(std::mem::size_of::<DiagnosticStepRecord>());
    let recorder = DiagnosticStepRecorder::try_new(1, &budget).unwrap();
    let pending = Box::new(recorder.begin_step(state(0xCAFE)).unwrap());
    let base = (&raw const *pending).cast::<u8>();
    let _watch = watch(
        base,
        Layout::new::<PendingDiagnosticStep>(),
        pending.before.registers.as_ptr() as usize - base as usize,
        std::mem::size_of_val(&pending.before.registers),
    );
    watch_second_span(
        pending.before.tags.as_ptr() as usize - base as usize,
        std::mem::size_of_val(&pending.before.tags),
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _pending = pending;
        panic!("unwind pending diagnostic step");
    }));
    assert!(result.is_err());
    assert_erased_and_freed();
    assert!(recorder.records().is_empty());
}

#[test]
fn replaced_terminal_snapshot_is_retained_then_erased_in_its_original_box() {
    let _serial = serial();
    let budget = AllocationBudget::new(0);
    let mut recorder = Box::new(DiagnosticStepRecorder::try_new(0, &budget).unwrap());
    for value in [0xD7, 0xE8] {
        recorder.finish_run(DiagnosticRunEnd {
            state: state(value),
            padding_cycles: 3,
            outcome: Ok(()),
        });
        assert_eq!(recorder.end().unwrap().state.registers, [value; 256]);
        assert_eq!(recorder.end().unwrap().state.tags, [true; 256]);
        assert!(matches!(recorder.end().unwrap().outcome, Ok(())));
    }
    let base = (&raw const *recorder).cast::<u8>();
    let end = recorder.end().unwrap();
    let _watch = watch(
        base,
        Layout::new::<DiagnosticStepRecorder>(),
        end.state.registers.as_ptr() as usize - base as usize,
        std::mem::size_of_val(&end.state.registers),
    );
    watch_second_span(
        end.state.tags.as_ptr() as usize - base as usize,
        std::mem::size_of_val(&end.state.tags),
    );
    drop(recorder);
    assert_erased_and_freed();
}

#[test]
fn refused_step_completion_preserves_published_rows_and_original_credit() {
    let bytes = std::mem::size_of::<DiagnosticStepRecord>();
    let budget = AllocationBudget::new(bytes);
    let mut recorder = DiagnosticStepRecorder::try_new(1, &budget).unwrap();
    let first = recorder.begin_step(state(11)).unwrap();
    let stale = recorder.begin_step(state(22)).unwrap();
    recorder
        .finish_step(first, state(33), DiagnosticStepOutcome::Completed)
        .unwrap();
    let expected = recorder.records()[0];
    assert!(
        matches!(recorder.finish_step(stale, state(44), DiagnosticStepOutcome::Completed), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
            ExecutionDeferral::AllocationUnavailable
        ))
    );
    assert!(matches!(
        recorder.begin_step(state(55)),
        Err(VMError::ExecutionDeferred(
            ExecutionDeferral::ActiveMemoryCapacity
        ))
    ));
    assert_eq!(recorder.records(), &[expected]);
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(recorder);
    assert_eq!(budget.reserved_bytes(), 0);
}
