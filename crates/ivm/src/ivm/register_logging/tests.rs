//! Real VM logger admission, detached custody and final TLS release regressions.

use super::*;
use crate::{ProgramMetadata, cache_memory, error::ExecutionDeferral, host::DefaultHost};
use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

const LIMIT: usize = 128 * 1024 * 1024;

fn loaded(budget: &AllocationBudget) -> IVM {
    let mut vm = IVM::try_new_with_memory_budget(10_000, budget).unwrap();
    let mut program = ProgramMetadata::default().encode();
    program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
    vm.load_program(&program).unwrap();
    vm
}

fn seed_log(vm: &mut IVM) -> zk::SharedRegLog {
    let owner = vm.proof_register_log_handle().unwrap();
    let _scope = zk::RegLoggerGuard::install(Some(owner.clone()));
    let _batch = zk::RegEventBatch::begin(1).unwrap();
    vm.registers.set(7, 41);
    assert!(!owner.lock().as_slice().is_empty());
    owner
}

#[test]
fn funded_vm_shell_stays_charged_until_its_final_external_logger_drops() {
    let budget = AllocationBudget::new(LIMIT);
    let vm = loaded(&budget);
    let borrowed = vm.proof_register_log_handle().unwrap();
    assert!(borrowed.belongs_to(&budget));
    drop(vm);
    assert_eq!(
        budget.reserved_bytes(),
        zk::SharedRegLog::allocation_layout().size()
    );
    drop(borrowed);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_logger_admission_refusal_leaves_the_whole_run_unchanged() {
    let budget = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&budget);
    let previous = seed_log(&mut vm);
    vm.memory.preload_input(0, &[1, 2, 3, 4]).unwrap();
    vm.input_bump_next = 8;
    vm.cycles = 19;
    vm.halted = true;
    budget
        .with_deferred_refund_notifications(|scope| vm.pc_trace.prepare(1, Some(scope)))
        .unwrap();
    vm.pc_trace.record_reserved(7);
    let before = vm.execution_summary();
    let previous_events = previous.lock().as_slice().to_vec();
    let baseline = budget.reserved_bytes();
    let shell = zk::SharedRegLog::allocation_layout().size();
    budget.set_limit_bytes(baseline + shell - 1);
    assert!(matches!(vm.run_with_host(&mut DefaultHost::default()),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == shell));
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(vm.execution_summary(), before);
    assert_eq!(vm.input_bump_next, 8);
    assert_eq!(
        vm.memory
            .inspect_region(crate::Memory::INPUT_START, 4)
            .unwrap(),
        &[1, 2, 3, 4]
    );
    assert_eq!(previous.lock().as_slice(), previous_events);
    assert!(zk::SharedRegLog::ptr_eq(
        &previous,
        &vm.proof_register_log_handle().unwrap()
    ));
    budget.set_limit_bytes(LIMIT);
    cache_memory::with_refused_shared_allocation_for_test(|| {
        assert!(matches!(
            vm.run_with_host(&mut DefaultHost::default()),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::AllocationUnavailable
            ))
        ));
    });
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(vm.execution_summary(), before);
    assert_eq!(previous.lock().as_slice(), previous_events);
    vm.run_with_host(&mut DefaultHost::default()).unwrap();
    assert!(
        previous.lock().as_slice().is_empty(),
        "admitted invocation scrubs prior private values"
    );
    assert!(!zk::SharedRegLog::ptr_eq(
        &previous,
        &vm.proof_register_log_handle().unwrap()
    ));
    drop(vm);
    // Scrubbing removes initialized events, not the previous borrower's
    // already admitted row backing. Its final handle still owns both charges.
    assert_eq!(
        budget.reserved_bytes(),
        shell + previous.lock().capacity() * std::mem::size_of::<zk::RegEvent>()
    );
    drop(previous);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn detached_invalid_vm_severs_foreign_loggers_without_allocating_or_scrubbing_them() {
    let budget = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&budget);
    let invocation = seed_log(&mut vm);
    let detached = zk::SharedRegLog::try_new(Some(&budget)).unwrap();
    vm.reg_log = Some(detached.clone());
    vm.host_trace_log_detached = true;
    vm.host_trace_invocation_log = Some(invocation.clone());
    let events = invocation.lock().as_slice().to_vec();
    let baseline = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    cache_memory::with_refused_shared_allocation_for_test(|| {
        assert!(matches!(
            vm.run_with_host(&mut DefaultHost::default()),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::LocalInvariantViolation
            ))
        ));
        assert!(vm.reg_log.is_none());
        assert!(vm.host_trace_invocation_log.is_none());
        assert!(!vm.host_trace_log_detached);
        // The failure path never attempted even an untracked replacement shell.
        assert!(matches!(
            zk::SharedRegLog::try_new(None),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::AllocationUnavailable
            ))
        ));
    });
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(invocation.lock().as_slice(), events);
    assert_eq!(vm.execution_summary().register_log_len, 0);
    assert!(matches!(
        vm.run_with_host(&mut DefaultHost::default()),
        Err(VMError::AllocationDeferred(_))
    ));
    drop(vm);
    assert_eq!(
        budget.reserved_bytes(),
        2 * zk::SharedRegLog::allocation_layout().size() + 4 * std::mem::size_of::<zk::RegEvent>()
    );
    drop((invocation, detached));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn idle_runtime_eviction_does_not_refund_its_borrowed_logger() {
    let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
        capacity: 64,
        max_bytes: 64 * 1024 * 1024,
        max_decoded_ops: 0,
    });
    let budget = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&budget);
    let template = vm.try_runtime_template().unwrap();
    vm.reset_from_runtime_template(&template).unwrap();
    assert!(vm.try_retain_cache_allocations());
    let borrowed = vm.proof_register_log_handle().unwrap();
    let original = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(budget.reserved_bytes(), original);
    assert!(zk::SharedRegLog::ptr_eq(
        &borrowed,
        &vm.proof_register_log_handle().unwrap()
    ));
    vm.activate_cached_runtime();
    drop(vm);
    drop(template);
    assert_eq!(
        budget.reserved_bytes(),
        zk::SharedRegLog::allocation_layout().size()
    );
    drop(borrowed);
    assert_eq!(budget.reserved_bytes(), 0);
}

struct ReenterTls(AtomicUsize);
impl Wake for ReenterTls {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        assert_eq!(zk::scoped_reg_logger_enabled(), None);
        let _nested = zk::RegLoggerGuard::install(None);
        assert_eq!(zk::scoped_reg_logger_enabled(), Some(false));
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn assert_final_tls_release_reenters(unwind: bool) {
    let shell = zk::SharedRegLog::allocation_layout().size();
    let registration_bytes = ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(shell + registration_bytes);
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let logger = zk::SharedRegLog::try_new(Some(&budget)).unwrap();
    let guard = zk::RegLoggerGuard::install(Some(logger));
    let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
    else {
        panic!("full original pool");
    };
    let callback = Arc::new(ReenterTls(AtomicUsize::new(0)));
    let waker = Waker::from(callback.clone());
    let mut context = Context::from_waker(&waker);
    let mut wait = release.wait_for_release(&mut registration);
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Pending);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = guard;
        if unwind {
            panic!("test logger scope unwind");
        }
    }));
    assert_eq!(outcome.is_err(), unwind);
    assert_eq!(callback.0.load(Ordering::SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), registration_bytes);
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Ready(()));
    drop(wait);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn final_tls_refund_can_reenter_after_normal_scope_exit() {
    assert_final_tls_release_reenters(false);
}
#[test]
fn final_tls_refund_can_reenter_after_scope_unwind() {
    assert_final_tls_release_reenters(true);
}
