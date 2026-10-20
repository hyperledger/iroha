use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
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

// Test-only unwind after a real acquired fence, never a production policy switch.
pub(super) fn fence_boundary(stage: usize) {
    if UNWIND_AFTER_FENCE.with(|fault| {
        if fault.get() == Some(stage) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        std::panic::resume_unwind(Box::new("original native frame fence unwind"));
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
            // Acquire the real aggregate on the default test stack. A poisoned
            // store still refuses, but no sibling physical fence may remain Busy.
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
    drop(kura.sidecar_lock.lock());
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
        "original native frame notice must wait for every storage fence"
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

fn fixture(evicted: bool) -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    if evicted {
        let wire = chain.committed(2).block().encode_wire().unwrap();
        let mut store = chain.kura().block_store.lock();
        store.write_da_block_bytes(2, &wire).unwrap();
        store
            .write_block_index(1, EVICTED_BLOCK_START, wire.len() as u64)
            .unwrap();
        store.publish_commit_marker(2).unwrap();
    }
    chain
}

#[test]
fn original_native_frame_metadata_success_notifies_after_storage_fences() {
    for evicted in [false, true] {
        let chain = fixture(evicted);
        let original = chain.committed(2);
        let wire = original.block().encode_wire().unwrap();
        let source = observe_original_release(chain.kura(), 1, || {
            chain.kura().native_frame_read(2, original.block_hash())
        })
        .unwrap()
        .unwrap();
        assert_eq!(source.wire_len(), wire.len() as u64);
        let budget = iroha_allocation::AllocationBudget::new(wire.len());
        let length = source.wire_len();
        let bytes = source.read(length, &budget).unwrap().unwrap();
        assert_eq!(bytes.as_slice(), wire);
        assert!(bytes.belongs_to(&budget));
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_native_frame_metadata_absence_notifies_after_storage_fences() {
    let chain = fixture(false);
    let result = observe_original_release(chain.kura(), 1, || {
        chain
            .kura()
            .native_frame_read(3, chain.committed(2).block_hash())
    });
    assert!(result.unwrap().is_none());
    assert_eq!(chain.kura().exact_durable_blocks_count().unwrap(), 2);
}

#[test]
fn original_native_frame_metadata_refusal_notifies_after_storage_fences() {
    let chain = fixture(false);
    let original = chain.committed(2);
    let result = observe_original_release(chain.kura(), 1, || {
        chain
            .kura()
            .native_frame_read(2, chain.committed(1).block_hash())
    });
    assert!(matches!(
        result,
        Err(Error::CanonicalBlockWireMismatch { height: 2 })
    ));
    let source = chain
        .kura()
        .native_frame_read(2, original.block_hash())
        .unwrap()
        .unwrap();
    assert_eq!(
        source.wire_len(),
        original.block().encode_wire().unwrap().len() as u64
    );
}

#[test]
fn original_native_frame_body_success_notifies_after_storage_fences() {
    for evicted in [false, true] {
        let chain = fixture(evicted);
        let original = chain.committed(2);
        let wire = original.block().encode_wire().unwrap();
        let mut source = chain
            .kura()
            .native_frame_read(2, original.block_hash())
            .unwrap()
            .unwrap();
        let budget = iroha_allocation::AllocationBudget::new(wire.len());
        let bytes = observe_original_release(chain.kura(), 1, || {
            source.read_original(source.wire_len(), &budget)
        })
        .unwrap()
        .unwrap();
        assert_eq!(bytes.as_slice(), wire);
        assert!(bytes.belongs_to(&budget));
        assert_eq!(budget.reserved_bytes(), wire.len());
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_native_frame_body_refusal_notifies_after_storage_fences() {
    for evicted in [false, true] {
        let chain = fixture(evicted);
        let original = chain.committed(2);
        let wire = original.block().encode_wire().unwrap();
        let mut source = chain
            .kura()
            .native_frame_read(2, original.block_hash())
            .unwrap()
            .unwrap();
        let budget = iroha_allocation::AllocationBudget::new(wire.len());
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let result = observe_original_release(chain.kura(), 1, || {
            source.read_original(source.wire_len(), &budget)
        });
        assert!(matches!(
            result,
            Err(Error::NativeFrameAllocation(
                iroha_allocation::ChargedBufferError::Admission(_)
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 1);
        drop(occupied);
        let bytes = source
            .read_original(source.wire_len(), &budget)
            .unwrap()
            .unwrap();
        assert_eq!(bytes.as_slice(), wire);
        assert!(bytes.belongs_to(&budget));
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_native_frame_partial_refusals_retain_exact_storage_errors() {
    for body_read in [false, true] {
        for stage in 1..=2 {
            let chain = fixture(false);
            let original = chain.committed(2);
            let mut source = chain
                .kura()
                .native_frame_read(2, original.block_hash())
                .unwrap()
                .unwrap();
            let budget = iroha_allocation::AllocationBudget::new(
                usize::try_from(source.wire_len()).unwrap(),
            );
            let flag = if stage == 1 {
                &chain.kura().prune_recovery_required
            } else {
                &chain.kura().canonical_storage_poisoned
            };
            flag.store(true, Ordering::Release);
            let result = observe_original_release(chain.kura(), stage - 1, || {
                let result = if body_read {
                    source.read_original(source.wire_len(), &budget).map(|_| ())
                } else {
                    chain
                        .kura()
                        .native_frame_read(2, original.block_hash())
                        .map(|_| ())
                };
                flag.store(false, Ordering::Release);
                result
            });
            if stage == 1 {
                assert!(matches!(result, Err(Error::PruneRecoveryRequired)));
            } else {
                assert!(matches!(result, Err(Error::CanonicalStoragePoisoned)));
            }
            assert_eq!(budget.reserved_bytes(), 0);
            assert_eq!(chain.kura().exact_durable_blocks_count().unwrap(), 2);
        }
    }
}

#[test]
fn original_native_frame_unwind_notifies_after_each_acquired_prefix() {
    for body_read in [false, true] {
        for stage in 1..=2 {
            let chain = fixture(false);
            let original = chain.committed(2);
            let mut source = chain
                .kura()
                .native_frame_read(2, original.block_hash())
                .unwrap()
                .unwrap();
            let budget = iroha_allocation::AllocationBudget::new(
                usize::try_from(source.wire_len()).unwrap(),
            );
            observe_original_release(chain.kura(), stage - 1, || {
                UNWIND_AFTER_FENCE.with(|fault| fault.set(Some(stage)));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if body_read {
                        source.read_original(source.wire_len(), &budget).map(|_| ())
                    } else {
                        chain
                            .kura()
                            .native_frame_read(2, original.block_hash())
                            .map(|_| ())
                    }
                }));
                UNWIND_AFTER_FENCE.with(|fault| fault.set(None));
                let error = result.expect_err("unwind after the original acquired frame fence");
                assert_eq!(
                    error.downcast_ref::<&'static str>(),
                    Some(&"original native frame fence unwind")
                );
            });
            assert_eq!(budget.reserved_bytes(), 0);
            let bytes = source
                .read_original(source.wire_len(), &budget)
                .unwrap()
                .unwrap();
            assert_eq!(bytes.as_slice(), original.block().encode_wire().unwrap());
            drop(bytes);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}
