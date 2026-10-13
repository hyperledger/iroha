use super::*;
use resource_inventory::Unavailable;
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::atomic::AtomicUsize,
    task::{Context, Wake, Waker},
};

thread_local! {
    static UNWIND_AFTER_FENCE: Cell<Option<usize>> = const { Cell::new(None) };
    static POISON_AFTER_PRUNE: Cell<bool> = const { Cell::new(false) };
}

// The actual startup/re-audit operation still owns all policy and filesystem work.
pub(super) fn fence_boundary(kura: &Kura, stage: usize) {
    if stage == 1 && POISON_AFTER_PRUNE.with(|fault| fault.replace(false)) {
        kura.canonical_storage_poisoned
            .store(true, Ordering::Release);
    }
    if UNWIND_AFTER_FENCE.with(|fault| {
        if fault.get() == Some(stage) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        std::panic::resume_unwind(Box::new("original inventory acquired fence unwind"));
    }
}

type Components = Vec<(
    ResourceFamily,
    std::result::Result<ResourceUsage, Unavailable>,
)>;

fn components(kura: &Kura) -> Components {
    PHYSICAL_RESOURCE_FAMILIES
        .iter()
        .map(|family| {
            (
                *family,
                kura.resource_inventory.component_usage_for_tests(*family),
            )
        })
        .collect()
}

fn unavailable(reason: Unavailable) -> Components {
    PHYSICAL_RESOURCE_FAMILIES
        .iter()
        .map(|family| (*family, Err(reason)))
        .collect()
}

struct Probe {
    kura: Arc<Kura>,
    expected: Components,
    calls: AtomicUsize,
    premature: AtomicUsize,
    reentered: AtomicUsize,
}
impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        // Observe completed publication/invalidation before reentry can alter anything.
        let accounting_final = components(&self.kura) == self.expected;
        let fences_free = self
            .kura
            .publication_fences_for_test()
            .iter()
            .all(|(_, fence)| fence.try_lock().is_some());
        let store_free = self.kura.block_store.try_lock().is_some();
        if accounting_final && fences_free && store_free {
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
    expected: Components,
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
        expected,
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
    drop(kura.publication_fences_for_test()[2].1.lock());
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        0,
        "unrelated physical source release"
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
        "one original inventory source release"
    );
    assert_eq!(
        probe.premature.load(Ordering::SeqCst),
        0,
        "original inventory notice must follow all fences and final family accounting"
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

fn fixture() -> Arc<Kura> {
    let kura = Kura::blank_kura_for_testing();
    assert!(!kura.emergency_fast_startup_enabled());
    assert!(kura.physical_resource_reconciliation_allowed());
    kura.reconcile_physical_resource_inventory().unwrap();
    assert!(components(&kura).iter().all(|(_, usage)| usage.is_ok()));
    kura
}

fn canonical_bytes(kura: &Kura) -> Vec<Vec<u8>> {
    let root = Kura::canonical_storage_path(&kura.store_root);
    [DATA_FILE_NAME, INDEX_FILE_NAME, HASHES_FILE_NAME]
        .iter()
        .map(|name| std::fs::read(root.join(name)).unwrap())
        .collect()
}

fn observed(kura: &Kura) -> Components {
    let counts = kura
        .physical_resource_scope()
        .unwrap()
        .observe(kura.evidence_resource_limits())
        .unwrap();
    PHYSICAL_RESOURCE_FAMILIES
        .iter()
        .map(|family| (*family, Ok(counts[*family as usize])))
        .collect()
}

#[test]
fn original_inventory_absent_artifacts_publish_before_source_notice() {
    let kura = fixture();
    let expected = observed(&kura);
    let bytes = canonical_bytes(&kura);
    assert!(
        !kura
            .store_root
            .join(fastpq_artifact_store::DIRECTORY)
            .exists()
    );
    kura.resource_inventory
        .invalidate(physical_resource_mask(), Unavailable::Interrupted);
    observe_original_release(&kura, 3, expected.clone(), || {
        kura.reconcile_physical_resource_inventory()
    })
    .unwrap();
    assert_eq!(components(&kura), expected);
    assert_eq!(canonical_bytes(&kura), bytes);
    assert!(
        !kura
            .store_root
            .join(fastpq_artifact_store::DIRECTORY)
            .exists()
    );
}

#[test]
fn original_inventory_retained_artifacts_publish_exact_counts_before_notice() {
    let kura = fixture();
    let payload = b"original retained FASTPQ custody";
    let reference = kura.persist_fastpq_artifact(payload).unwrap().reference();
    let path = kura
        .store_root
        .join(fastpq_artifact_store::DIRECTORY)
        .join(format!("{}.norito", hex::encode(reference.digest())));
    let expected = observed(&kura);
    let bytes = canonical_bytes(&kura);
    kura.resource_inventory
        .invalidate(physical_resource_mask(), Unavailable::Interrupted);
    observe_original_release(&kura, 3, expected.clone(), || {
        kura.reconcile_physical_resource_inventory()
    })
    .unwrap();
    assert_eq!(components(&kura), expected);
    assert_eq!(std::fs::read(path).unwrap(), payload);
    assert_eq!(kura.read_fastpq_artifact(reference).unwrap(), payload);
    assert_eq!(canonical_bytes(&kura), bytes);
}

#[test]
fn original_inventory_artifact_refusal_invalidates_every_family_before_notice() {
    let kura = fixture();
    let reference = kura
        .persist_fastpq_artifact(b"original artifact")
        .unwrap()
        .reference();
    let directory = kura.store_root.join(fastpq_artifact_store::DIRECTORY);
    let retained = directory.join(format!("{}.norito", hex::encode(reference.digest())));
    let unexpected = directory.join("unregistered-artifact");
    std::fs::write(&unexpected, b"retain rejected bytes").unwrap();
    let bytes = canonical_bytes(&kura);
    assert_eq!(
        observe_original_release(&kura, 3, unavailable(Unavailable::InvalidInventory), || {
            kura.reconcile_physical_resource_inventory()
        }),
        Err(Unavailable::InvalidInventory)
    );
    assert_eq!(
        components(&kura),
        unavailable(Unavailable::InvalidInventory)
    );
    assert_eq!(std::fs::read(&retained).unwrap(), b"original artifact");
    assert_eq!(
        std::fs::read(&unexpected).unwrap(),
        b"retain rejected bytes"
    );
    assert_eq!(canonical_bytes(&kura), bytes);
    std::fs::remove_file(unexpected).unwrap();
    kura.reconcile_physical_resource_inventory().unwrap();
    assert_eq!(
        kura.read_fastpq_artifact(reference).unwrap(),
        b"original artifact"
    );
}

#[test]
fn original_inventory_tree_refusal_invalidates_every_family_before_notice() {
    let kura = fixture();
    let path = kura.active_blocks_dir.lock().join("unregistered.index");
    std::fs::write(&path, [0_u8; 3]).unwrap();
    let bytes = canonical_bytes(&kura);
    assert_eq!(
        observe_original_release(&kura, 3, unavailable(Unavailable::OwnerMismatch), || {
            kura.reconcile_physical_resource_inventory()
        }),
        Err(Unavailable::OwnerMismatch)
    );
    assert_eq!(components(&kura), unavailable(Unavailable::OwnerMismatch));
    assert_eq!(std::fs::read(&path).unwrap(), [0; 3]);
    assert_eq!(canonical_bytes(&kura), bytes);
    std::fs::remove_file(path).unwrap();
    kura.reconcile_physical_resource_inventory().unwrap();
    assert_eq!(components(&kura), observed(&kura));
}

#[test]
fn original_inventory_busy_owner_refusal_invalidates_before_prefix_notice() {
    let kura = fixture();
    let original = components(&kura);
    let bytes = canonical_bytes(&kura);
    let owner = kura
        .resource_inventory
        .begin(ResourceFamily::ResidentQueue.mask())
        .unwrap();
    assert_eq!(
        observe_original_release(&kura, 1, unavailable(Unavailable::Busy), || kura
            .reconcile_physical_resource_inventory()),
        Err(Unavailable::Busy)
    );
    assert_eq!(components(&kura), unavailable(Unavailable::Busy));
    assert_eq!(canonical_bytes(&kura), bytes);
    drop(owner);
    kura.reconcile_physical_resource_inventory().unwrap();
    assert_eq!(components(&kura), original);
}

#[test]
fn original_inventory_acquired_prefix_refusal_invalidates_before_notice() {
    let kura = fixture();
    let bytes = canonical_bytes(&kura);
    let original = components(&kura);
    POISON_AFTER_PRUNE.with(|fault| fault.set(true));
    let result = observe_original_release(&kura, 1, unavailable(Unavailable::Unregistered), || {
        kura.reconcile_physical_resource_inventory()
    });
    POISON_AFTER_PRUNE.with(|fault| fault.set(false));
    assert_eq!(result, Err(Unavailable::Unregistered));
    assert_eq!(components(&kura), unavailable(Unavailable::Unregistered));
    assert_eq!(canonical_bytes(&kura), bytes);
    kura.canonical_storage_poisoned
        .store(false, Ordering::Release);
    kura.reconcile_physical_resource_inventory().unwrap();
    assert_eq!(components(&kura), original);
}

#[test]
fn original_inventory_unwind_notifies_after_each_acquired_prefix() {
    for (stage, fence) in [(1, 0), (2, 1), (3, 3)] {
        let kura = fixture();
        let bytes = canonical_bytes(&kura);
        let expected = components(&kura);
        observe_original_release(&kura, fence, expected.clone(), || {
            UNWIND_AFTER_FENCE.with(|fault| fault.set(Some(stage)));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                kura.reconcile_physical_resource_inventory()
            }));
            UNWIND_AFTER_FENCE.with(|fault| fault.set(None));
            let error = result.expect_err("unwind after original acquired inventory fence");
            assert_eq!(
                error.downcast_ref::<&'static str>(),
                Some(&"original inventory acquired fence unwind")
            );
        });
        assert_eq!(components(&kura), expected);
        assert_eq!(canonical_bytes(&kura), bytes);
        kura.reconcile_physical_resource_inventory().unwrap();
        assert_eq!(components(&kura), expected);
    }
}
