//! Original logger identity, nested quotas and callbacks at actual row growth.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
use iroha_crypto::{Hash, HashOf};
use std::{alloc::Layout, mem::size_of};

const ROW: usize = size_of::<RegEvent>();

fn event(value: u64) -> RegEvent {
    RegEvent::Read {
        index: 5,
        value,
        tag: false,
        path: [[0x5a; 32]; crate::REGISTER_MERKLE_PATH_DEPTH],
        root: HashOf::from_untyped_unchecked(Hash::new(value.to_le_bytes())),
    }
}
fn publish(value: u64) {
    record_register_event(|| event(value));
}
fn remaining() -> Option<usize> {
    LOGGER.with(
        |slot| match slot.borrow().state.as_ref().map(|state| &state.quota) {
            Some(Quota::Ready { remaining, .. }) => Some(*remaining),
            _ => None,
        },
    )
}
fn row_count(log: &SharedRegLog) -> usize {
    log.lock().as_slice().len()
}
fn fresh(rows: usize) -> (AllocationBudget, SharedRegLog) {
    let original = AllocationBudget::new(SharedRegLog::allocation_layout().size() + rows * ROW);
    let log = SharedRegLog::try_new(Some(&original)).unwrap();
    (original, log)
}

#[test]
fn nested_batches_partition_only_original_credit_and_return_unused_rows() {
    let (original, log) = fresh(6);
    let scope = RegLoggerGuard::install(Some(log.clone()));
    let baseline = original.reserved_bytes();
    let batch = RegEventBatch::begin(6).unwrap();
    assert_eq!(original.reserved_bytes(), baseline + 6 * ROW);
    original.set_limit_bytes(0);
    publish(1);
    assert_eq!(remaining(), Some(5));
    {
        let _child = RegEventBatch::begin(3).unwrap();
        assert_eq!(remaining(), Some(3));
        publish(2);
        {
            let _grandchild = RegEventBatch::begin(2).unwrap();
            publish(3);
        }
        assert_eq!(remaining(), Some(1));
    }
    assert_eq!(remaining(), Some(3));
    for value in 4..=6 {
        publish(value);
    }
    assert_eq!(remaining(), Some(0));
    assert_eq!(row_count(&log), 6);
    assert_eq!(original.peak_reserved_bytes(), baseline + 6 * ROW);
    drop(batch);
    assert_eq!(remaining(), None);
    drop(scope);
    drop(log);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn masks_and_same_identity_installs_move_the_quota_without_fresh_admission() {
    let (original, log) = fresh(6);
    let _scope = RegLoggerGuard::install(Some(log.clone()));
    let _batch = RegEventBatch::begin(6).unwrap();
    original.set_limit_bytes(0);
    publish(1);
    {
        let _mask = RegLoggerGuard::mask();
        assert_eq!(scoped_reg_logger_enabled(), Some(true));
        assert!(SharedRegLog::ptr_eq(&scoped_reg_logger().unwrap(), &log));
        assert!(event_reg_logger().is_none());
        let _ignored = RegEventBatch::begin(usize::MAX).unwrap();
        record_register_event(|| panic!("masked builder must not run"));
        assert_eq!(remaining(), Some(5));
        {
            let _same = RegLoggerGuard::install(Some(log.clone()));
            let _child = RegEventBatch::begin(2).unwrap();
            publish(2);
        }
        assert_eq!(remaining(), Some(4));
        assert!(event_reg_logger().is_none());
    }
    assert_eq!(remaining(), Some(4));
    assert!(SharedRegLog::ptr_eq(&event_reg_logger().unwrap(), &log));
    {
        let _off = RegLoggerGuard::install(None);
        assert_eq!(scoped_reg_logger_enabled(), Some(false));
        assert!(remaining().is_none());
        let _ignored = RegEventBatch::begin(usize::MAX).unwrap();
        record_register_event(|| panic!("untraced nested VM must not emit"));
    }
    assert_eq!(remaining(), Some(4));
    assert_eq!(row_count(&log), 2);
}

#[test]
fn different_invocation_cannot_consume_or_refund_the_suspended_parent() {
    let (original, parent) = fresh(4);
    let (child_pool, child) = fresh(4);
    let _parent_scope = RegLoggerGuard::install(Some(parent.clone()));
    let _parent_batch = RegEventBatch::begin(4).unwrap();
    publish(1);
    original.set_limit_bytes(0);
    {
        let _child_scope = RegLoggerGuard::install(Some(child.clone()));
        assert_eq!(remaining(), None);
        let _child_batch = RegEventBatch::begin(4).unwrap();
        publish(2);
        publish(3);
        assert_eq!(remaining(), Some(2));
    }
    assert_eq!(remaining(), Some(3));
    assert_eq!(row_count(&parent), 1);
    assert_eq!(row_count(&child), 2);
    drop(child);
    assert_eq!(child_pool.reserved_bytes(), 0);
    publish(4);
    assert_eq!(remaining(), Some(2));
}

#[test]
fn outer_refusal_and_nested_exhaustion_publish_no_new_credit_or_event() {
    let (original, log) = fresh(0);
    let _scope = RegLoggerGuard::install(Some(log.clone()));
    let baseline = original.reserved_bytes();
    assert!(matches!(
        RegEventBatch::begin(4),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(remaining(), None);
    assert_eq!(row_count(&log), 0);
    assert_eq!(original.reserved_bytes(), baseline);
    original.set_limit_bytes(baseline + 4 * ROW);
    let _batch = RegEventBatch::begin(1).unwrap();
    assert!(matches!(
        RegEventBatch::begin(2),
        Err(VMError::HostUnavailable)
    ));
    assert_eq!(remaining(), Some(1));
    publish(1);
    let overrun = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record_register_event(|| panic!("quota refusal must precede event construction"));
    }));
    assert!(overrun.is_err());
    assert_eq!(remaining(), Some(0));
    assert_eq!(row_count(&log), 1);
}

#[test]
fn pending_instruction_retains_the_delayed_native_finish_observation() {
    let (original, log) = fresh(5);
    let _scope = RegLoggerGuard::install(Some(log.clone()));
    let mut pending = Some(RegEventBatch::begin(5).unwrap());
    for value in 0..4 {
        publish(value);
    }
    original.set_limit_bytes(0);
    {
        let _host_mask = RegLoggerGuard::mask();
        record_register_event(|| panic!("callback cannot consume delayed finish credit"));
    }
    assert_eq!(remaining(), Some(1));
    // The real run-loop integration performs native_finish_step at the next
    // loop head, then retires this batch before starting the next instruction.
    publish(4);
    drop(pending.take());
    assert_eq!(row_count(&log), 5);
    assert_eq!(remaining(), None);
    assert!(matches!(
        RegEventBatch::begin(1),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(row_count(&log), 5);
}

#[test]
fn unwind_restores_parent_identity_credit_and_final_original_ownership() {
    let (original, log) = fresh(8);
    let scope = RegLoggerGuard::install(Some(log.clone()));
    let batch = RegEventBatch::begin(8).unwrap();
    publish(1);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _mask = RegLoggerGuard::mask();
        let _same = RegLoggerGuard::install(Some(log.clone()));
        let _child = RegEventBatch::begin(3).unwrap();
        publish(2);
        panic!("nested callback unwind");
    }));
    assert!(panic.is_err());
    assert_eq!(remaining(), Some(6));
    assert!(SharedRegLog::ptr_eq(&event_reg_logger().unwrap(), &log));
    drop(batch);
    drop(scope);
    assert_eq!(scoped_reg_logger_enabled(), None);
    drop(log);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn original_refusal_and_copy_panic_clear_preparing_after_owned_growth_unwinds() {
    let (original, log) = fresh(12);
    let _scope = RegLoggerGuard::install(Some(log.clone()));
    {
        let _batch = RegEventBatch::begin(4).unwrap();
        for value in 0..4 {
            publish(value);
        }
    }
    let baseline = original.reserved_bytes();
    original.set_limit_bytes(baseline + 8 * ROW - 1);
    let Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { release, .. })) =
        RegEventBatch::begin(1)
    else {
        panic!("complete replacement demand must retain its original refusal");
    };
    let Err(AllocationRefusal::Capacity {
        release: original_release,
        ..
    }) = original.try_reserve(Layout::array::<RegEvent>(8).unwrap())
    else {
        panic!("the original pool still owns the same refusal");
    };
    assert_eq!(release, original_release);
    assert_eq!(remaining(), None);
    assert_eq!(row_count(&log), 4);
    original.set_limit_bytes(baseline + 8 * ROW);
    super::super::register_events::PANIC_AFTER_COPY.set(true);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _batch = RegEventBatch::begin(1).unwrap();
    }));
    assert!(panic.is_err());
    assert_eq!(original.reserved_bytes(), baseline);
    assert_eq!(remaining(), None);
    assert_eq!(row_count(&log), 4);
    // A new outer admission succeeds; no stale Preparing marker or lock remains.
    let _retry = RegEventBatch::begin(1).unwrap();
    publish(5);
    assert_eq!(row_count(&log), 5);
}

#[test]
fn allocation_refund_reenters_without_logger_mutex_or_tls_borrow_and_cannot_mint_credit() {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };
    let registration_bytes = ReleaseRegistration::allocation_layout().size();
    let original = AllocationBudget::new(
        SharedRegLog::allocation_layout().size() + 12 * ROW + registration_bytes,
    );
    let mut registration = ReleaseRegistration::from_reservation(
        &mut original
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let log = SharedRegLog::try_new(Some(&original)).unwrap();
    let scope = RegLoggerGuard::install(Some(log.clone()));
    {
        let _batch = RegEventBatch::begin(4).unwrap();
        for value in 0..4 {
            publish(value);
        }
    }
    let Err(AllocationRefusal::Capacity { release, .. }) =
        original.try_reserve(Layout::array::<RegEvent>(9).unwrap())
    else {
        panic!("original row capacity pressure");
    };
    struct Reenter {
        log: SharedRegLog,
        independent: SharedRegLog,
        calls: AtomicUsize,
    }
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            assert!(SharedRegLog::ptr_eq(
                &scoped_reg_logger().unwrap(),
                &self.log
            ));
            assert_eq!(row_count(&self.log), 4);
            {
                let _same = RegLoggerGuard::install(Some(self.log.clone()));
                assert!(matches!(
                    RegEventBatch::begin(1),
                    Err(VMError::HostUnavailable)
                ));
            }
            {
                let _independent = RegLoggerGuard::install(Some(self.independent.clone()));
                let _owned = RegEventBatch::begin(1).unwrap();
                publish(99);
            }
            assert!(matches!(
                RegEventBatch::begin(1),
                Err(VMError::HostUnavailable)
            ));
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }
    let (independent_pool, independent) = fresh(4);
    let callback = Arc::new(Reenter {
        log: log.clone(),
        independent,
        calls: AtomicUsize::new(0),
    });
    let waker = Waker::from(callback.clone());
    let mut context = Context::from_waker(&waker);
    let mut wait = release.wait_for_release(&mut registration);
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Pending);
    let batch = RegEventBatch::begin(1).unwrap();
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(remaining(), Some(1));
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Ready(()));
    publish(5);
    drop(batch);
    drop(wait);
    drop(waker);
    drop(callback);
    assert_eq!(independent_pool.reserved_bytes(), 0);
    drop(scope);
    drop(log);
    drop(registration);
    assert_eq!(original.reserved_bytes(), 0);
}

fn counted_on_this_thread() -> usize {
    THREAD_EVENT_SCOPES.with(std::cell::Cell::get)
}

#[test]
fn only_event_capable_scopes_are_counted_and_every_exit_releases_them() {
    let (_original, log) = fresh(2);
    assert_eq!(counted_on_this_thread(), 0);
    {
        let _off = RegLoggerGuard::install(None);
        let _mask = RegLoggerGuard::mask();
        assert_eq!(counted_on_this_thread(), 0);
    }
    let outer = RegLoggerGuard::install(Some(log.clone()));
    assert_eq!(counted_on_this_thread(), 1);
    assert!(!no_event_scopes());
    {
        // A masked invocation keeps its count; TLS alone suppresses emission.
        let _mask = RegLoggerGuard::mask();
        assert_eq!(counted_on_this_thread(), 1);
        assert!(event_reg_logger().is_none());
        let _same = RegLoggerGuard::install(Some(log.clone()));
        assert_eq!(counted_on_this_thread(), 2);
    }
    assert_eq!(counted_on_this_thread(), 1);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _nested = RegLoggerGuard::install(Some(log.clone()));
        assert_eq!(counted_on_this_thread(), 2);
        panic!("unwind through a counted scope");
    }));
    assert!(unwound.is_err());
    assert_eq!(counted_on_this_thread(), 1);
    assert!(SharedRegLog::ptr_eq(&event_reg_logger().unwrap(), &log));
    drop(outer);
    assert_eq!(counted_on_this_thread(), 0);
}

#[test]
fn another_threads_scope_only_disables_the_fast_path_here() {
    let (_original, log) = fresh(1);
    let (installed_tx, installed_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _scope = RegLoggerGuard::install(Some(log));
        installed_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    installed_rx.recv().unwrap();
    // The process-wide count is live, so this thread takes the exact TLS
    // fallback, which finds no scope of its own and emits nothing.
    assert!(!no_event_scopes());
    assert_eq!(counted_on_this_thread(), 0);
    assert!(event_reg_logger().is_none());
    assert_eq!(scoped_reg_logger_enabled(), None);
    let batch = RegEventBatch::begin(usize::MAX).unwrap();
    record_register_event(|| panic!("a foreign scope must not enable this thread"));
    drop(batch);
    release_tx.send(()).unwrap();
    holder.join().unwrap();
}
