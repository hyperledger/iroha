use super::*;
use crate::kura::KuraPublicationPreparationError;
use std::{
    cell::Cell,
    collections::BTreeMap,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
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

// Test-only unwind after an original acquired fence, never a runtime policy switch.
pub(super) fn fence_boundary(stage: usize) {
    if UNWIND_AFTER_FENCE.with(|fault| {
        if fault.get() == Some(stage) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        std::panic::resume_unwind(Box::new("original FASTPQ artifact fence unwind"));
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
        let physical_free = self
            .kura
            .publication_fences_for_test()
            .iter()
            .all(|(_, lock)| lock.try_lock().is_some());
        let store_free = self.kura.block_store.try_lock().is_some();
        if physical_free && store_free {
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
        probe.blocked.load(Ordering::SeqCst),
        0,
        "original FASTPQ artifact notice must wait for every storage fence"
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

fn fixture(count: usize) -> Arc<Kura> {
    let mut kura = Kura::blank_kura_for_testing();
    Arc::get_mut(&mut kura)
        .expect("fresh sole artifact owner")
        .fastpq_artifact_policy = KuraFastpqArtifactPolicy {
        max_artifact_bytes: NonZeroUsize::new(64).unwrap(),
        max_artifacts: NonZeroUsize::new(count).unwrap(),
        max_total_bytes: NonZeroU64::new(256).unwrap(),
    };
    kura
}

fn inventory(kura: &Kura) -> BTreeMap<PathBuf, Vec<u8>> {
    let directory = kura.store_root.join(DIRECTORY);
    if !directory.exists() {
        return BTreeMap::new();
    }
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

fn path(kura: &Kura, reference: FastpqStoredArtifactReference) -> PathBuf {
    kura.store_root.join(DIRECTORY).join(reference.file_name())
}

fn assert_invalid(error: &Error, path: &Path, message: &str) {
    assert!(matches!(error, Error::IO(source, actual)
        if source.kind() == ErrorKind::InvalidData && actual == path && source.to_string() == message));
}

#[test]
fn original_artifact_persist_success_notifies_after_storage_fences() {
    let kura = fixture(4);
    let bytes = b"opaque original artifact";
    let receipt =
        observe_original_release(&kura, 3, || kura.persist_fastpq_artifact(bytes)).unwrap();
    assert!(receipt.is_from(&kura));
    assert_eq!(
        receipt.reference(),
        FastpqStoredArtifactReference::for_bytes(bytes)
    );
    assert_eq!(
        kura.read_fastpq_artifact(receipt.reference()).unwrap(),
        bytes
    );
    assert_eq!(
        inventory(&kura),
        BTreeMap::from([(path(&kura, receipt.reference()), bytes.to_vec())])
    );
}

#[test]
fn original_artifact_exact_retry_notifies_after_storage_fences() {
    let kura = fixture(1);
    let bytes = b"opaque original artifact";
    let first = kura.persist_fastpq_artifact(bytes).unwrap();
    let before = inventory(&kura);
    let repeated =
        observe_original_release(&kura, 3, || kura.persist_fastpq_artifact(bytes)).unwrap();
    assert_eq!(repeated.reference(), first.reference());
    assert!(repeated.is_from(&kura));
    assert_eq!(inventory(&kura), before);
}

#[test]
fn original_artifact_quota_refusal_notifies_after_storage_fences() {
    let kura = fixture(1);
    let _receipt = kura.persist_fastpq_artifact(b"retained").unwrap();
    let before = inventory(&kura);
    let reference = FastpqStoredArtifactReference::for_bytes(b"additional");
    let result = observe_original_release(&kura, 3, || kura.persist_fastpq_artifact(b"additional"));
    assert_invalid(
        &result.unwrap_err(),
        &path(&kura, reference),
        "FASTPQ artifact storage quota exhausted",
    );
    assert_eq!(inventory(&kura), before);
}

#[test]
fn original_artifact_content_conflict_notifies_after_storage_fences() {
    let kura = fixture(4);
    let receipt = kura.persist_fastpq_artifact(b"original").unwrap();
    let path = path(&kura, receipt.reference());
    std::fs::write(&path, b"modified").unwrap();
    let before = inventory(&kura);
    let result = observe_original_release(&kura, 3, || kura.persist_fastpq_artifact(b"original"));
    assert_invalid(
        &result.unwrap_err(),
        &path,
        "FASTPQ content address contains different bytes",
    );
    assert_eq!(inventory(&kura), before);
}

#[test]
fn original_artifact_read_success_notifies_after_storage_fences() {
    let kura = fixture(4);
    let bytes = b"opaque original artifact";
    let receipt = kura.persist_fastpq_artifact(bytes).unwrap();
    let before = inventory(&kura);
    let read =
        observe_original_release(&kura, 3, || kura.read_fastpq_artifact(receipt.reference()))
            .unwrap();
    assert_eq!(read, bytes);
    assert_eq!(inventory(&kura), before);
}

#[test]
fn original_artifact_read_refusals_retain_exact_errors_and_bytes() {
    for absent in [true, false] {
        let kura = fixture(4);
        let receipt = kura.persist_fastpq_artifact(b"original").unwrap();
        let reference = if absent {
            FastpqStoredArtifactReference::for_bytes(b"absent")
        } else {
            std::fs::write(path(&kura, receipt.reference()), b"modified").unwrap();
            receipt.reference()
        };
        let before = inventory(&kura);
        let result = observe_original_release(&kura, 3, || kura.read_fastpq_artifact(reference));
        assert_invalid(
            &result.unwrap_err(),
            &path(&kura, reference),
            if absent {
                "FASTPQ artifact reference is absent"
            } else {
                "FASTPQ artifact content or exact length differs from reference"
            },
        );
        assert_eq!(inventory(&kura), before);
    }
}

#[test]
fn original_artifact_partial_refusals_retain_exact_storage_errors() {
    for read in [false, true] {
        for stage in 1..=2 {
            let kura = fixture(4);
            let receipt = kura.persist_fastpq_artifact(b"original").unwrap();
            let before = inventory(&kura);
            let flag = if stage == 1 {
                &kura.prune_recovery_required
            } else {
                &kura.canonical_storage_poisoned
            };
            flag.store(true, Ordering::Release);
            let result = observe_original_release(&kura, stage - 1, || {
                let result = if read {
                    kura.read_fastpq_artifact(receipt.reference()).map(|_| ())
                } else {
                    kura.persist_fastpq_artifact(b"original").map(|_| ())
                };
                flag.store(false, Ordering::Release);
                result
            });
            if stage == 1 {
                assert!(matches!(result, Err(Error::PruneRecoveryRequired)));
            } else {
                assert!(matches!(result, Err(Error::CanonicalStoragePoisoned)));
            }
            assert_eq!(inventory(&kura), before);
            assert_eq!(
                kura.read_fastpq_artifact(receipt.reference()).unwrap(),
                b"original"
            );
        }
    }
}

#[test]
fn original_artifact_unwind_notifies_after_each_acquired_prefix() {
    for read in [false, true] {
        for stage in 1..=if read { 3 } else { 4 } {
            let kura = fixture(4);
            let receipt = kura.persist_fastpq_artifact(b"original").unwrap();
            let before = inventory(&kura);
            let fence = if read && stage == 3 { 3 } else { stage - 1 };
            observe_original_release(&kura, fence, || {
                UNWIND_AFTER_FENCE.with(|fault| fault.set(Some(stage)));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if read {
                        kura.read_fastpq_artifact(receipt.reference()).map(|_| ())
                    } else {
                        kura.persist_fastpq_artifact(b"original").map(|_| ())
                    }
                }));
                UNWIND_AFTER_FENCE.with(|fault| fault.set(None));
                let error = result.expect_err("unwind after original acquired artifact fence");
                assert_eq!(
                    error.downcast_ref::<&'static str>(),
                    Some(&"original FASTPQ artifact fence unwind")
                );
            });
            assert_eq!(inventory(&kura), before);
            assert_eq!(
                kura.read_fastpq_artifact(receipt.reference()).unwrap(),
                b"original"
            );
        }
    }
}
