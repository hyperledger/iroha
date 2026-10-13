use super::*;
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::atomic::AtomicUsize,
    task::{Context, Wake, Waker},
};

thread_local! {
    static UNWIND_AFTER_FENCE: Cell<Option<usize>> = const { Cell::new(None) };
}

// Test-only unwind after acquiring an original fence, not a runtime policy switch.
pub(super) fn fence_boundary(stage: usize) {
    if UNWIND_AFTER_FENCE.with(|fault| {
        if fault.get() == Some(stage) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        std::panic::resume_unwind(Box::new("original recovery capacity fence unwind"));
    }
}

struct Probe {
    kura: Arc<Kura>,
    initialized: Option<bool>,
    calls: AtomicUsize,
    premature: AtomicUsize,
    reentered: AtomicUsize,
}

impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Inspect final accounting before reentry is allowed to refresh caches.
        let accounting_final = self.initialized.is_none_or(|initialized| {
            self.kura.disk_usage_initialized.load(Ordering::Acquire) == initialized
                && self
                    .kura
                    .disk_usage_total_initialized
                    .load(Ordering::Acquire)
                    == initialized
                && (initialized
                    || !self
                        .kura
                        .durable_budget_snapshot_valid
                        .load(Ordering::Acquire))
        });
        let physical_free = self
            .kura
            .publication_fences_for_test()
            .iter()
            .all(|(_, lock)| lock.try_lock().is_some());
        let store_free = self.kura.block_store.try_lock().is_some();
        if accounting_final && physical_free && store_free {
            let result = self.kura.try_publication_lease();
            if matches!(result, Err(KuraPublicationPreparationError::Busy { .. })) {
                self.premature.fetch_add(1, Ordering::SeqCst);
            } else {
                self.reentered.fetch_add(1, Ordering::SeqCst);
            }
            drop(result);
        } else {
            self.premature.fetch_add(1, Ordering::SeqCst);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn observe_original_release<T>(
    kura: &Arc<Kura>,
    fence: usize,
    initialized: Option<bool>,
    run: impl FnOnce() -> T,
) -> T {
    let budget = kura.transaction_history_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let original = kura.publication_fences_for_test()[fence]
        .1
        .observe_release();
    let mut wait = original.wait_for_release(&mut registration);
    let probe = Arc::new(Probe {
        kura: Arc::clone(kura),
        initialized,
        calls: AtomicUsize::new(0),
        premature: AtomicUsize::new(0),
        reentered: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(kura.publication_fences_for_test()[(fence + 1) % 4].1.lock());
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        0,
        "unrelated physical release"
    );
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let result = run();
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "one original physical release"
    );
    assert_eq!(
        probe.premature.load(Ordering::SeqCst),
        0,
        "original capacity recovery notice must follow all fences and final accounting"
    );
    assert_eq!(probe.reentered.load(Ordering::SeqCst), 1);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    drop(wait);
    assert!(registration.belongs_to(&budget));
    let reserved = budget.reserved_bytes();
    let charge = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    assert!(reserved >= charge);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), reserved - charge);
    result
}

fn assert_usage(kura: &Kura) {
    let (used, total) = kura.kura_disk_usage_bytes_with_total().unwrap();
    assert_eq!(kura.disk_usage.load(Ordering::Acquire), used);
    assert_eq!(kura.disk_usage_total.load(Ordering::Acquire), total);
    assert!(kura.disk_usage_initialized.load(Ordering::Acquire));
    assert!(kura.disk_usage_total_initialized.load(Ordering::Acquire));
}

#[test]
fn original_capacity_recovery_success_notifies_after_final_accounting() {
    for complete in [false, true] {
        let kura = Kura::blank_kura_for_testing();
        kura.disk_usage_initialized.store(false, Ordering::Release);
        kura.disk_usage_total_initialized
            .store(false, Ordering::Release);
        observe_original_release(&kura, 3, Some(true), || {
            kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(complete)
        })
        .unwrap();
        assert_usage(&kura);
        assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
    }
}

#[test]
fn original_capacity_restore_success_notifies_after_final_accounting() {
    let kura = Kura::blank_kura_for_testing();
    observe_original_release(&kura, 3, Some(true), || {
        kura.finish_restored_lane_segments_with_geometry(&LaneConfig::default())
    })
    .unwrap();
    assert_usage(&kura);
    assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
}

#[test]
fn original_capacity_recovery_capacity_refusal_notifies_after_invalidation() {
    let mut kura = Kura::blank_kura_for_testing();
    let used = kura.kura_total_disk_usage_bytes().unwrap();
    assert!(
        used > 1,
        "real canonical marker and geometry custody count against capacity"
    );
    let limit = used - 1;
    Arc::get_mut(&mut kura)
        .expect("fresh sole Kura owner")
        .max_disk_usage_bytes = limit;
    let result = observe_original_release(&kura, 3, Some(false), || {
        kura.finish_restored_lane_segments_with_geometry(&LaneConfig::default())
    });
    assert!(matches!(result, Err(Error::StorageBudgetExceeded {
        limit: actual_limit, used: actual_used, required
    }) if actual_limit == limit && actual_used == used && required == used));
    assert_eq!(kura.kura_total_disk_usage_bytes().unwrap(), used);
    assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
    Arc::get_mut(&mut kura)
        .expect("callback releases its Kura owner")
        .max_disk_usage_bytes = used;
    kura.finish_restored_lane_segments_with_geometry(&LaneConfig::default())
        .unwrap();
    assert_usage(&kura);
}

#[test]
fn original_capacity_recovery_prune_refusal_notifies_after_invalidation() {
    let kura = Kura::blank_kura_for_testing();
    kura.prune_recovery_required.store(true, Ordering::Release);
    let result = observe_original_release(&kura, 0, Some(false), || {
        let result =
            kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(true);
        kura.prune_recovery_required.store(false, Ordering::Release);
        result
    });
    assert!(matches!(result, Err(Error::PruneRecoveryRequired)));
    kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(true)
        .unwrap();
    assert_usage(&kura);
}

#[test]
fn original_capacity_recovery_canonical_refusal_notifies_after_invalidation() {
    let kura = Kura::blank_kura_for_testing();
    let path = Kura::canonical_storage_path(&kura.store_root).join(INDEX_FILE_NAME);
    let original = std::fs::read(&path).unwrap();
    assert!(original.is_empty());
    std::fs::write(&path, [1]).unwrap();
    kura.invalidate_durable_budget_snapshot();
    let result = observe_original_release(&kura, 1, Some(false), || {
        kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(true)
    });
    assert!(matches!(result, Err(Error::IO(ref error, ref actual_path))
        if error.kind() == ErrorKind::InvalidData && actual_path == &path
        && error.to_string() == "block index journal has a partial trailing entry"));
    assert_eq!(std::fs::read(&path).unwrap(), [1]);
    std::fs::write(&path, original).unwrap();
    kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(true)
        .unwrap();
    assert_usage(&kura);
}

#[test]
fn original_capacity_recovery_accounting_refusal_notifies_after_invalidation() {
    let kura = Kura::blank_kura_for_testing();
    let path = kura.store_root.join("retired").join("lane_geometry");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"retained recovery evidence").unwrap();
    let result = observe_original_release(&kura, 3, Some(false), || {
        kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(false)
    });
    assert!(matches!(result, Err(Error::IO(ref error, ref actual_path))
        if error.kind() == ErrorKind::InvalidData && actual_path == &path
        && error.to_string() == "Kura retained geometry root must be a non-symlink directory"));
    assert_eq!(std::fs::read(&path).unwrap(), b"retained recovery evidence");
    std::fs::remove_file(&path).unwrap();
    kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(false)
        .unwrap();
    assert_usage(&kura);
}

#[test]
fn original_capacity_recovery_unwind_notifies_after_each_acquired_prefix() {
    for stage in 1..=4 {
        let kura = Kura::blank_kura_for_testing();
        observe_original_release(&kura, stage - 1, None, || {
            UNWIND_AFTER_FENCE.with(|fault| fault.set(Some(stage)));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(true)
            }));
            UNWIND_AFTER_FENCE.with(|fault| fault.set(None));
            let error = result.expect_err("unwind after original acquired capacity fence");
            assert_eq!(
                error.downcast_ref::<&'static str>(),
                Some(&"original recovery capacity fence unwind")
            );
        });
        kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(true)
            .unwrap();
        assert_usage(&kura);
        assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
    }
}
