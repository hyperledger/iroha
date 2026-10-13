use super::*;
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

thread_local! {
    static UNWIND_AFTER_FENCE: Cell<Option<usize>> = const { Cell::new(None) };
}

// A test-only acquired-prefix unwind; Fast startup still follows actual configuration.
pub(in crate::kura) fn fence_boundary(stage: usize) {
    if UNWIND_AFTER_FENCE.with(|fault| {
        if fault.get() == Some(stage) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        std::panic::resume_unwind(Box::new("original snapshot boundary fence unwind"));
    }
}

struct Probe {
    kura: Arc<Kura>,
    calls: AtomicUsize,
    blocked: AtomicUsize,
    reentered: AtomicUsize,
}
impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let fences_free = self
            .kura
            .publication_fences_for_test()
            .iter()
            .all(|(_, fence)| fence.try_lock().is_some());
        let store_free = self.kura.block_store.try_lock().is_some();
        if fences_free && store_free {
            let result = self.kura.try_publication_lease();
            if matches!(result, Err(KuraPublicationPreparationError::Busy { .. })) {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            } else {
                self.reentered.fetch_add(1, Ordering::SeqCst);
            }
            drop(result);
        } else {
            self.blocked.fetch_add(1, Ordering::SeqCst);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn observe_original_release<T>(kura: &Arc<Kura>, fence: usize, run: impl FnOnce() -> T) -> T {
    let budget = kura.transaction_history_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let original = kura.publication_fences_for_test()[fence]
        .1
        .observe_release();
    let mut wait = original.wait_for_release(&mut registration);
    let probe = Arc::new(Probe {
        kura: Arc::clone(kura),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
        reentered: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(kura.publication_fences_for_test()[3].1.lock());
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
        probe.blocked.load(Ordering::SeqCst),
        0,
        "original snapshot boundary notice must wait for all storage fences"
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

fn strict_fixture(count: usize) -> (TempDir, KuraConfig, Arc<Kura>, Vec<HashOf<BlockHeader>>) {
    let directory = TempDir::new().unwrap();
    let config = kura_config_for_dir(&directory, BLOCKS_IN_MEMORY);
    let (kura, BlockCount(initial)) =
        test_kura_with_default_lane_markers(&config, &RuntimeLaneConfig::default());
    assert_eq!(initial, 0);
    // The established generator retains original native execution and certificates.
    let hashes = if count == 0 {
        Vec::new()
    } else {
        store_dummy_blocks(&kura, count)
    };
    assert!(!kura.emergency_fast_startup_enabled());
    (directory, config, kura, hashes)
}

fn fast_fixture(count: usize) -> (TempDir, Arc<Kura>, Vec<HashOf<BlockHeader>>) {
    let (directory, mut config, strict, hashes) = strict_fixture(count);
    drop(strict);
    let before = snapshot_regular_test_tree(directory.path());
    config.init_mode = InitMode::Fast;
    let (kura, BlockCount(reopened)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .unwrap();
    assert_eq!(reopened, count);
    assert!(kura.emergency_fast_startup_enabled());
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
    assert_eq!(snapshot_regular_test_tree(directory.path()), before);
    (directory, kura, hashes)
}

#[test]
fn original_snapshot_boundary_empty_notifies_after_storage_fences() {
    let (directory, kura, _) = fast_fixture(0);
    let before = snapshot_regular_test_tree(directory.path());
    for requested in [0, 1] {
        let boundary = observe_original_release(&kura, 1, || {
            kura.emergency_fast_snapshot_boundary(requested)
        })
        .unwrap();
        assert_eq!(boundary, (0, None));
    }
    assert_eq!(snapshot_regular_test_tree(directory.path()), before);
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
}

#[test]
fn original_snapshot_boundary_native_hash_notifies_after_storage_fences() {
    let (directory, kura, hashes) = fast_fixture(1);
    let before = snapshot_regular_test_tree(directory.path());
    for requested in [0, 1, 2] {
        let boundary = observe_original_release(&kura, 1, || {
            kura.emergency_fast_snapshot_boundary(requested)
        })
        .unwrap();
        assert_eq!(
            boundary,
            (
                1,
                if requested == 1 {
                    Some(hashes[0])
                } else {
                    None
                }
            )
        );
    }
    assert_eq!(snapshot_regular_test_tree(directory.path()), before);
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
}

#[test]
fn original_snapshot_mapping_empty_notifies_after_storage_fences() {
    let (directory, kura, _) = fast_fixture(0);
    let before = snapshot_regular_test_tree(directory.path());
    let mapping =
        observe_original_release(&kura, 1, || kura.emergency_fast_snapshot_hash_mapping(0))
            .unwrap();
    assert!(mapping.is_none());
    assert_eq!(snapshot_regular_test_tree(directory.path()), before);
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
}

#[test]
fn original_snapshot_mapping_native_bytes_notifies_after_storage_fences() {
    let (directory, kura, hashes) = fast_fixture(1);
    let before = snapshot_regular_test_tree(directory.path());
    let mapping =
        observe_original_release(&kura, 1, || kura.emergency_fast_snapshot_hash_mapping(1))
            .unwrap()
            .unwrap();
    assert_eq!(mapping.len(), Hash::LENGTH);
    assert_eq!(mapping.as_slice(), hashes[0].as_ref());
    assert_eq!(snapshot_regular_test_tree(directory.path()), before);
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
}

#[test]
fn original_snapshot_mapping_height_refusal_retains_exact_journals() {
    let (directory, kura, _) = fast_fixture(1);
    let before = snapshot_regular_test_tree(directory.path());
    for requested in [0, 2] {
        let result = observe_original_release(&kura, 1, || {
            kura.emergency_fast_snapshot_hash_mapping(requested)
        });
        assert!(matches!(result, Err(Error::HashesFileHeightMismatch)));
    }
    assert_eq!(snapshot_regular_test_tree(directory.path()), before);
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
}

#[test]
fn original_snapshot_corrupt_journal_refusal_retains_exact_error_and_bytes() {
    for mapping in [false, true] {
        let (directory, kura, _) = fast_fixture(1);
        let index_path = kura
            .block_store
            .lock()
            .path_to_blockchain
            .join(INDEX_FILE_NAME);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&index_path)
            .unwrap()
            .write_all(&[0xA5])
            .unwrap();
        let before = snapshot_regular_test_tree(directory.path());
        let result = observe_original_release(&kura, 1, || {
            if mapping {
                kura.emergency_fast_snapshot_hash_mapping(1).map(|_| ())
            } else {
                kura.emergency_fast_snapshot_boundary(1).map(|_| ())
            }
        });
        assert!(matches!(result, Err(Error::IO(error, path))
            if error.kind() == ErrorKind::InvalidData && path == index_path
            && error.to_string() == "block index journal has a partial trailing entry"));
        assert_eq!(snapshot_regular_test_tree(directory.path()), before);
        assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
    }
}

#[test]
fn original_snapshot_partial_refusals_preserve_storage_and_mode_errors() {
    let (directory, _, strict, _) = strict_fixture(0);
    let before = snapshot_regular_test_tree(directory.path());
    let budget = strict.transaction_history_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let original = strict.publication_fences_for_test()[0].1.observe_release();
    let mut wait = original.wait_for_release(&mut registration);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    for (mapping, expected) in [
        (
            false,
            "emergency Fast snapshot boundary requested after Strict startup",
        ),
        (
            true,
            "emergency Fast hash mapping requested after Strict startup",
        ),
    ] {
        let result = if mapping {
            strict.emergency_fast_snapshot_hash_mapping(0).map(|_| ())
        } else {
            strict.emergency_fast_snapshot_boundary(0).map(|_| ())
        };
        assert!(matches!(result, Err(Error::IO(error, path))
            if error.kind() == ErrorKind::InvalidInput && path == *strict.active_blocks_dir.lock()
            && error.to_string() == expected));
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    drop(wait);
    drop(registration);
    assert_eq!(snapshot_regular_test_tree(directory.path()), before);
    drop(strict);
    for mapping in [false, true] {
        for stage in 1..=2 {
            let (directory, kura, _) = fast_fixture(0);
            let before = snapshot_regular_test_tree(directory.path());
            let flag = if stage == 1 {
                &kura.prune_recovery_required
            } else {
                &kura.canonical_storage_poisoned
            };
            flag.store(true, Ordering::Release);
            let result = observe_original_release(&kura, stage - 1, || {
                let result = if mapping {
                    kura.emergency_fast_snapshot_hash_mapping(0).map(|_| ())
                } else {
                    kura.emergency_fast_snapshot_boundary(0).map(|_| ())
                };
                flag.store(false, Ordering::Release);
                result
            });
            if stage == 1 {
                assert!(matches!(result, Err(Error::PruneRecoveryRequired)));
            } else {
                assert!(matches!(result, Err(Error::CanonicalStoragePoisoned)));
            }
            assert_eq!(snapshot_regular_test_tree(directory.path()), before);
        }
    }
}

#[test]
fn original_snapshot_unwind_notifies_after_each_acquired_prefix() {
    for mapping in [false, true] {
        for stage in 1..=3 {
            let (directory, kura, _) = fast_fixture(0);
            let before = snapshot_regular_test_tree(directory.path());
            let fence = if stage == 1 { 0 } else { 1 };
            observe_original_release(&kura, fence, || {
                UNWIND_AFTER_FENCE.with(|fault| fault.set(Some(stage)));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if mapping {
                        kura.emergency_fast_snapshot_hash_mapping(0).map(|_| ())
                    } else {
                        kura.emergency_fast_snapshot_boundary(0).map(|_| ())
                    }
                }));
                UNWIND_AFTER_FENCE.with(|fault| fault.set(None));
                let error = result.expect_err("unwind after original acquired snapshot fence");
                assert_eq!(
                    error.downcast_ref::<&'static str>(),
                    Some(&"original snapshot boundary fence unwind")
                );
            });
            assert_eq!(snapshot_regular_test_tree(directory.path()), before);
            assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
        }
    }
}
