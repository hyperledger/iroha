//! Actual original membership generations, finite credits and snapshot refusals.
use super::*;
use std::{
    future::Future,
    task::{Context, Waker},
};

fn key(n: u64) -> Key {
    HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(n.to_le_bytes()))
}
fn height(n: usize) -> Value {
    NonZeroUsize::new(n).unwrap()
}
fn commit(owner: &TransactionsStorage, at: usize, keys: &[Key], replacement: bool) {
    let mut pending = Some(owner.prepare_next_block(replacement).unwrap());
    let mut block = owner.attach_prepared(&mut pending).unwrap();
    block.insert_block(keys.iter().copied().collect(), height(at));
    block.commit().unwrap();
}
fn owner() -> TransactionsStorage {
    TransactionsStorage::try_new(AllocationBudget::new(4 * 1024 * 1024)).unwrap()
}

#[test]
fn initial_native_tree_and_identity_have_one_exact_finite_admission() {
    let calibration = owner();
    let minimum = calibration.budget.reserved_bytes();
    assert!(minimum > Identity::layout().size());
    let short = AllocationBudget::new(minimum - 1);
    assert!(
        matches!(TransactionsStorage::try_new(short.clone()), Err(MembershipAdmissionError::Capacity(
        AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes }
    )) if requested_bytes == minimum && limit_bytes == minimum - 1)
    );
    assert_eq!(short.reserved_bytes(), 0);
    let observer_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let exact = AllocationBudget::new(minimum + observer_bytes);
    let mut release_registration_0 = crate::unit_test_support::release_registration(&exact);
    let occupied = exact.try_reserve_bytes(1).unwrap();
    let refused = TransactionsStorage::try_new(exact.clone());
    let release = match refused {
        Err(MembershipAdmissionError::Capacity(AllocationRefusal::Capacity {
            requested_bytes,
            release,
            ..
        })) => {
            assert_eq!(requested_bytes, minimum);
            release
        }
        _ => panic!("both notification controls and initial tree require one original admission"),
    };
    assert_eq!(
        exact.reserved_bytes(),
        observer_bytes + 1,
        "no partial owner survives refusal"
    );
    let mut wait = release.wait_for_release(&mut release_registration_0);
    assert!(
        std::pin::Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(occupied);
    assert!(
        std::pin::Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    let storage = TransactionsStorage::try_new(exact.clone()).unwrap();
    assert_eq!(exact.reserved_bytes(), minimum + observer_bytes);
    drop(storage);
    assert_eq!(exact.reserved_bytes(), observer_bytes);
    drop(wait);
    drop(release_registration_0);
    assert_eq!(exact.reserved_bytes(), 0);
}

#[test]
fn independent_history_release_controls_stay_funded_through_last_observation() {
    let pool = AllocationBudget::new(1024 * 1024);
    let storage = TransactionsStorage::try_new(pool.clone()).unwrap();
    let observation = storage.history_release_wait();
    let retained = observation.clone();
    let logical = storage.released.observe();
    let retained_logical = logical.clone();
    assert_ne!(observation, logical);
    assert!(pool.reserved_bytes() > release_control_layout().size() * 2);
    drop(storage);
    assert_eq!(pool.reserved_bytes(), release_control_layout().size() * 2);
    drop(logical);
    assert_eq!(pool.reserved_bytes(), release_control_layout().size() * 2);
    drop(retained_logical);
    assert_eq!(pool.reserved_bytes(), release_control_layout().size());
    drop(observation);
    assert_eq!(pool.reserved_bytes(), release_control_layout().size());
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn physical_history_busy_ignores_logical_cleanup_and_retries_actual_release() {
    let storage = owner();
    let mut logical_registration = crate::unit_test_support::release_registration(&storage.budget);
    let physical_registrations: [_; 3] =
        std::array::from_fn(|_| crate::unit_test_support::release_registration(&storage.budget));
    commit(&storage, 1, &[key(1)], false);
    let reserved = storage.budget.reserved_bytes();
    let blocker = storage
        .history_released
        .guard(storage.blocks.try_acquire_writer().unwrap());
    let mut waits = Vec::new();
    for mut physical_registration in physical_registrations {
        let mut logical = std::pin::pin!(
            storage
                .released
                .observe()
                .wait_for_release(&mut logical_registration)
        );
        let error = match storage.prepare_next_block(false) {
            Err(error) => error,
            Ok(_) => panic!("actual physical writer remains held"),
        };
        let MembershipAdmissionError::Busy(source) = error else {
            panic!("physical contention retains its original source")
        };
        assert_eq!(source, storage.history_release_wait());
        assert!(
            logical
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready(),
            "the unsuccessful operation actually released its logical writer"
        );
        assert!(
            physical_registration
                .poll_wait(&source, &mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(storage.released.guard(storage.write_lock.lock()));
        let foreign = AllocationBudget::new(1);
        drop(foreign.try_reserve_bytes(1).unwrap());
        assert!(
            physical_registration
                .poll_wait(&source, &mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(storage.budget.reserved_bytes(), reserved);
        assert_eq!(storage.latest_height(), 1);
        waits.push((source, physical_registration));
    }
    drop(blocker);
    for (wait, mut registration) in waits {
        assert!(
            registration
                .poll_wait(&wait, &mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }
    let mut original = Some(storage.prepare_next_block(false).unwrap());
    let mut block = storage.attach_prepared(&mut original).unwrap();
    block.insert_block([key(2)].into_iter().collect(), height(2));
    block.commit().unwrap();
    assert_eq!(storage.view().get(&key(1)), Some(height(1)));
    assert_eq!(storage.view().get(&key(2)), Some(height(2)));
}

#[test]
fn physical_admission_notifies_after_logical_unlock_on_success_refusal_and_unwind() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::task::Wake;
    struct Probe {
        storage: Arc<TransactionsStorage>,
        wakes: AtomicUsize,
        held: AtomicBool,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.held.fetch_or(
                self.storage.write_lock.try_lock().is_none()
                    || self.storage.pending.try_lock().is_none()
                    || self.storage.blocks.try_acquire_writer().is_none(),
                SeqCst,
            );
            self.wakes.fetch_add(1, SeqCst);
        }
    }
    for outcome in 0..3 {
        let storage = Arc::new(owner());
        let mut release_registration_0 =
            crate::unit_test_support::release_registration(&storage.budget);
        let probe = Arc::new(Probe {
            storage: Arc::clone(&storage),
            wakes: AtomicUsize::new(0),
            held: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let source = storage.history_release_wait();
        let mut wait = std::pin::pin!(source.clone().wait_for_release(&mut release_registration_0));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        match outcome {
            0 => {
                let original = storage.prepare_next_block(false).unwrap();
                drop(original);
            }
            1 => {
                let occupied = storage
                    .budget
                    .try_reserve_bytes(
                        storage.budget.limit_bytes() - storage.budget.reserved_bytes(),
                    )
                    .unwrap();
                assert!(matches!(
                    storage.prepare_next_block(false),
                    Err(MembershipAdmissionError::Capacity(
                        AllocationRefusal::Capacity { .. }
                    ))
                ));
                assert_eq!(probe.wakes.load(SeqCst), 1);
                drop(occupied);
            }
            _ => {
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut physical_releases = storage.history_released.deferred_batch();
                    let _logical = storage.released.guard(storage.write_lock.lock());
                    let _pending = storage.pending.lock();
                    let _ = storage.try_history_writer(&mut physical_releases, |_, _| -> Result<Policy, MembershipAdmissionError> {
                        panic!("actual admission callback while physical and logical writers are held")
                    });
                })).is_err());
                assert!(storage.blocks.is_poisoned());
                assert!(source.is_poisoned());
            }
        }
        assert_eq!(probe.wakes.load(SeqCst), 1);
        assert!(!probe.held.load(SeqCst));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
        );
    }
}

#[test]
fn empty_successor_retains_exact_cursor_and_identity_layouts() {
    let storage = owner();
    let before = storage.budget.reserved_bytes();
    let mut cursor_bytes = None;
    assert!(matches!(
        storage
            .blocks
            .try_write_admitted_with_footprint(|_, additional| {
                cursor_bytes = Some(additional.bytes());
                Err::<Policy, _>(())
            }),
        Err(MapAdmissionError::Refused(()))
    ));
    let demand = std::alloc::Layout::array::<Key>(0).unwrap().size()
        + Identity::layout().size()
        + cursor_bytes.unwrap();
    let prepared = storage.prepare_next_block(false).unwrap();
    assert!(prepared.batch.as_ref().unwrap().as_slice().is_empty());
    assert_eq!(storage.budget.reserved_bytes(), before + demand);
    drop(prepared);
    assert_eq!(storage.budget.reserved_bytes(), before);
}

#[test]
fn initial_successor_reserves_batch_identity_and_cursor_before_work() {
    let storage = owner();
    let mut release_registration_0 =
        crate::unit_test_support::release_registration(&storage.budget);
    let keys: Vec<_> = (0..64).map(key).collect();
    commit(&storage, 1, &keys, false);
    let initial = storage.budget.reserved_bytes();
    let original_tip = storage.latest_block.load_full().unwrap();
    let original_identity = storage.write_lock.lock().clone();
    let mut cursor_bytes = None;
    assert!(matches!(
        storage
            .blocks
            .try_write_admitted_with_footprint(|_, additional| {
                cursor_bytes = Some(additional.bytes());
                Err::<Policy, _>(())
            }),
        Err(MapAdmissionError::Refused(()))
    ));
    let demand = std::alloc::Layout::array::<Key>(keys.len()).unwrap().size()
        + Identity::layout().size()
        + cursor_bytes.unwrap();
    assert!(demand > 0);
    assert!(demand <= storage.budget.limit_bytes() - initial);
    let blocker = storage
        .budget
        .try_reserve_bytes(storage.budget.limit_bytes() - initial - (demand - 1))
        .unwrap();
    let reserved_bytes = storage.budget.reserved_bytes();
    let release = match storage.prepare_next_block(false) {
        Err(MembershipAdmissionError::Capacity(AllocationRefusal::Capacity {
            requested_bytes,
            release,
            ..
        })) => {
            assert_eq!(requested_bytes, demand);
            release
        }
        _ => panic!("original batch, identity and cursor require one admission"),
    };
    assert_eq!(storage.budget.reserved_bytes(), reserved_bytes);
    {
        let pending = storage.pending.lock();
        let pending = pending.as_ref().expect("original refusal stays pending");
        assert!(Identity::ptr_eq(&pending.predecessor, &original_identity));
        assert!(Tip::ptr_eq(pending.latest.as_ref().unwrap(), &original_tip));
        assert!(pending.batch.is_none());
        assert!(pending.next_identity.is_none());
        assert!(pending.work.is_none());
        assert_eq!(pending.next, 0);
    }
    let mut future = std::pin::pin!(release.wait_for_release(&mut release_registration_0));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    drop(blocker);
    assert!(future.as_mut().poll(&mut context).is_ready());
    let ready = storage.prepare_next_block(false).unwrap();
    assert!(Identity::ptr_eq(&ready.predecessor, &original_identity));
    assert!(Tip::ptr_eq(ready.latest.as_ref().unwrap(), &original_tip));
    assert!(ready.batch.is_some() && ready.next_identity.is_some() && ready.work.is_some());
    assert_eq!(ready.next, keys.len());
    assert!(
        storage.blocks.read().is_empty(),
        "private promotion remains hidden"
    );
    drop(ready);
    assert_eq!(storage.budget.reserved_bytes(), initial);
}

#[test]
fn capacity_retry_keeps_original_batch_identity_and_private_predecessor() {
    let storage = owner();
    let mut release_registration_0 =
        crate::unit_test_support::release_registration(&storage.budget);
    let keys: Vec<_> = (0..64).map(key).collect();
    commit(&storage, 1, &keys, false);
    let mut cursor_demand = None;
    assert!(matches!(
        storage.blocks.try_write_admitted(|d| {
            cursor_demand = Some(d.bytes());
            Err::<Policy, _>(())
        }),
        Err(MapAdmissionError::Refused(()))
    ));
    let allowance = std::alloc::Layout::array::<Key>(keys.len()).unwrap().size()
        + Identity::layout().size()
        + cursor_demand.unwrap();
    let blocker = storage
        .budget
        .try_reserve_bytes(
            storage.budget.limit_bytes() - storage.budget.reserved_bytes() - allowance,
        )
        .unwrap();
    let wait = match storage.prepare_next_block(false) {
        Err(MembershipAdmissionError::Capacity(AllocationRefusal::Capacity {
            release, ..
        })) => release,
        _ => panic!("first tree edit exceeds remaining original credits"),
    };
    let (batch, identity, base, reserved) = {
        let pending = storage.pending.lock();
        let p = pending.as_ref().unwrap();
        assert_eq!(p.next, 0);
        (
            p.batch.as_ref().unwrap().as_slice().as_ptr(),
            p.next_identity.as_ref().unwrap().clone(),
            p.work.as_ref().unwrap().predecessor().retain(),
            storage.budget.reserved_bytes(),
        )
    };
    assert!(matches!(
        storage.prepare_next_block(false),
        Err(MembershipAdmissionError::Capacity(_))
    ));
    assert_eq!(storage.budget.reserved_bytes(), reserved);
    assert_eq!(storage.view().get(&keys[0]), Some(height(1)));
    let mut future = std::pin::pin!(wait.wait_for_release(&mut release_registration_0));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    drop(blocker);
    assert!(future.as_mut().poll(&mut context).is_ready());
    let ready = storage.prepare_next_block(false).unwrap();
    assert_eq!(ready.batch.as_ref().unwrap().as_slice().as_ptr(), batch);
    assert!(Identity::ptr_eq(
        ready.next_identity.as_ref().unwrap(),
        &identity
    ));
    assert!(base.matches(&ready.work.as_ref().unwrap().predecessor()));
    assert_eq!(ready.next, keys.len());
    assert!(
        storage.blocks.read().is_empty(),
        "private promotion never publishes during retry"
    );
    let mut pending = Some(ready);
    let mut block = storage.attach_prepared(&mut pending).unwrap();
    block.insert_block(BTreeSet::from([key(100)]), height(2));
    block.commit().unwrap();
    assert_eq!(storage.blocks.read().len(), keys.len());
}

#[test]
fn frozen_reader_clone_keeps_earlier_values_after_duplicate_promotions() {
    let storage = owner();
    commit(&storage, 1, &[key(1)], false);
    commit(&storage, 2, &[key(2)], false);
    let old = storage.view();
    let old_clone = old.clone();
    commit(&storage, 3, &[key(1)], false);
    commit(&storage, 4, &[key(3)], false);
    assert_eq!(storage.view().get(&key(1)), Some(height(3)));
    for reader in [&old, &old_clone] {
        assert_eq!(reader.get(&key(1)), Some(height(1)));
        assert_eq!(reader.get(&key(2)), Some(height(2)));
        assert_eq!(reader.get(&key(3)), None);
    }
}

#[test]
fn replacement_preserves_original_history_and_old_readers() {
    let storage = owner();
    commit(&storage, 1, &[key(1), key(2)], false);
    commit(&storage, 2, &[key(1), key(3)], false);
    let old = storage.view();
    commit(&storage, 2, &[key(4)], true);
    assert_eq!(old.get(&key(1)), Some(height(2)));
    assert_eq!(old.get(&key(3)), Some(height(2)));
    assert_eq!(storage.view().get(&key(1)), Some(height(1)));
    assert_eq!(storage.view().get(&key(3)), None);
    commit(&storage, 3, &[key(5)], false);
    assert_eq!(storage.view().get(&key(4)), Some(height(2)));
}

#[test]
fn original_reader_and_journal_credits_refund_only_after_last_custody() {
    let pool = AllocationBudget::new(4 * 1024 * 1024);
    let storage = TransactionsStorage::try_new(pool.clone()).unwrap();
    commit(&storage, 1, &[key(1)], false);
    commit(&storage, 2, &[key(2)], false);
    let old = storage.view();
    let mut block = storage.block();
    block.insert_block(BTreeSet::from([key(3)]), height(3));
    let journal = block.prepare_commit().unwrap().detach();
    let retained = pool.reserved_bytes();
    drop(journal);
    assert!(pool.reserved_bytes() < retained);
    commit(&storage, 3, &[key(4)], false);
    let retained = pool.reserved_bytes();
    drop(old);
    assert!(pool.reserved_bytes() < retained);
    drop(storage);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn restored_equal_bytes_are_a_foreign_original_family_and_identity() {
    let storage = owner();
    commit(&storage, 1, &[key(1)], false);
    let bytes = json::to_json(&storage).unwrap();
    let restored =
        TransactionsStorage::from_json_with_budget(&bytes, storage.budget.clone()).unwrap();
    let mut original = Some(storage.prepare_next_block(false).unwrap());
    assert!(matches!(
        restored.attach_prepared(&mut original),
        Err(MembershipAdmissionError::Changed(_))
    ));
    assert!(original.is_some());
    let mut block = storage.attach_prepared(&mut original).unwrap();
    block.insert_block(BTreeSet::from([key(2)]), height(2));
    block.commit().unwrap();
    assert_eq!(restored.view().get(&key(2)), None);
}

#[test]
fn restore_capacity_is_typed_and_refunds_before_retrying_same_bytes() {
    let source = owner();
    commit(&source, 1, &[key(1)], false);
    commit(&source, 2, &[key(2)], false);
    let bytes = json::to_json(&source).unwrap();
    let pool = AllocationBudget::new(4 * 1024 * 1024);
    let mut release_registration_0 = crate::unit_test_support::release_registration(&pool);
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let refusal = match TransactionsStorage::from_json_with_budget(&bytes, pool.clone()) {
        Err(MembershipRestoreError::Admission(MembershipAdmissionError::Capacity(
            AllocationRefusal::Capacity { release, .. },
        ))) => release,
        _ => panic!("history capacity cannot become a JSON/replay fallback error"),
    };
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    let mut future = refusal.wait_for_release(&mut release_registration_0);
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        std::pin::Pin::new(&mut future)
            .poll(&mut context)
            .is_pending()
    );
    drop(blocker);
    assert!(
        std::pin::Pin::new(&mut future)
            .poll(&mut context)
            .is_ready()
    );
    let restored = TransactionsStorage::from_json_with_budget(&bytes, pool.clone()).unwrap();
    assert_eq!(json::to_json(&restored).unwrap(), bytes);
    drop(restored);
    assert_eq!(
        pool.reserved_bytes(),
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size()
    );
    drop(future);
    drop(release_registration_0);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn unfundable_successor_is_permanent_before_batch_or_identity_allocation() {
    let calibration = owner();
    let mut required = None;
    assert!(matches!(
        calibration
            .blocks
            .try_write_admitted_with_footprint(|existing, additional| {
                required = Some(
                    existing.bytes()
                        + additional.bytes()
                        + Identity::layout().size() * 2
                        + release_control_layout().size() * 2,
                );
                Err::<Policy, _>(())
            }),
        Err(MapAdmissionError::Refused(()))
    ));
    let limit = required.unwrap();
    let storage = TransactionsStorage::try_new(AllocationBudget::new(limit - 1)).unwrap();
    let before = storage.budget.reserved_bytes();
    assert!(
        matches!(storage.prepare_next_block(false), Err(MembershipAdmissionError::Capacity(
        AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes }
    )) if requested_bytes == limit && limit_bytes == limit - 1)
    );
    assert_eq!(storage.budget.reserved_bytes(), before);
    let pending = storage.pending.lock();
    let pending = pending.as_ref().unwrap();
    assert!(pending.batch.is_none() && pending.next_identity.is_none() && pending.work.is_none());
    let exact = TransactionsStorage::try_new(AllocationBudget::new(limit)).unwrap();
    let next = exact.prepare_next_block(false).unwrap();
    assert!(next.work.is_some());
}

#[test]
fn checked_out_preparation_is_exclusive_and_abort_wakes_after_clearing_loan() {
    for unwind in [false, true] {
        let storage = owner();
        let mut release_registration_0 =
            crate::unit_test_support::release_registration(&storage.budget);
        let original = storage.prepare_next_block(false).unwrap();
        let identity = original.predecessor.clone();
        let reserved = storage.budget.reserved_bytes();
        let wait = match storage.prepare_next_block(false) {
            Err(MembershipAdmissionError::Busy(wait)) => wait,
            _ => panic!("one original preparation is checked out"),
        };
        assert_eq!(storage.budget.reserved_bytes(), reserved);
        let mut future = std::pin::pin!(wait.wait_for_release(&mut release_registration_0));
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        if unwind {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _original = original;
                    panic!("ordinary caller abort");
                }))
                .is_err()
            );
        } else {
            drop(original);
        }
        assert!(!identity.loaned.load(Ordering::Acquire));
        assert!(future.as_mut().poll(&mut context).is_ready());
        assert!(storage.prepare_next_block(false).is_ok());
    }
}

#[test]
fn physical_busy_return_resumes_exact_original_cursor_batch_and_identity() {
    let storage = owner();
    let mut release_registration_0 =
        crate::unit_test_support::release_registration(&storage.budget);
    commit(&storage, 1, &[key(1), key(2)], false);
    let ready = storage.prepare_next_block(false).unwrap();
    let batch = ready.batch.as_ref().unwrap().as_slice().as_ptr();
    let identity = ready.next_identity.as_ref().unwrap().clone();
    let predecessor = ready.baseline.as_ref().unwrap().clone();
    let mut ready = Some(ready);
    let mut block = storage.attach_prepared(&mut ready).unwrap();
    block.insert_block(BTreeSet::from([key(3)]), height(2));
    let mut field = super::super::block::TransactionsBlockField::new(block);
    field.try_prepare_publication().unwrap();
    let held = storage
        .history_released
        .guard(storage.blocks.try_acquire_writer().unwrap());
    let wait = match field.try_prepare_physical() {
        Err(TransactionsBlockError::MembershipAdmission(MembershipAdmissionError::Busy(wait))) => {
            wait
        }
        _ => panic!("actual native writer is held"),
    };
    let original = field.recover_preparation();
    assert_eq!(original.batch.as_ref().unwrap().as_slice().as_ptr(), batch);
    assert!(Identity::ptr_eq(
        original.next_identity.as_ref().unwrap(),
        &identity
    ));
    assert!(predecessor.matches(&original.work.as_ref().unwrap().predecessor()));
    field.release_writers();
    drop(field);
    drop(held);
    let mut future = std::pin::pin!(wait.wait_for_release(&mut release_registration_0));
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    storage.retain_preparation(original);
    let before = storage.budget.reserved_bytes();
    let resumed = storage.prepare_next_block(false).unwrap();
    assert_eq!(
        storage.budget.reserved_bytes(),
        before,
        "no second native cursor or charged batch"
    );
    assert_eq!(resumed.batch.as_ref().unwrap().as_slice().as_ptr(), batch);
    assert!(Identity::ptr_eq(
        resumed.next_identity.as_ref().unwrap(),
        &identity
    ));
    assert!(predecessor.matches(&resumed.work.as_ref().unwrap().predecessor()));
    let mut resumed = Some(resumed);
    let mut block = storage.attach_prepared(&mut resumed).unwrap();
    block.insert_block(BTreeSet::from([key(3)]), height(2));
    block.commit().unwrap();
    assert_eq!(storage.view().get(&key(1)), Some(height(1)));
    assert_eq!(storage.view().get(&key(3)), Some(height(2)));
}

#[test]
fn native_physical_retry_and_unrelated_unwind_preserve_original_generation() {
    let storage = owner();
    commit(&storage, 1, &[key(1)], false);
    let mut block = storage.block();
    block.insert_block(BTreeSet::from([key(2)]), height(2));
    let mut field = super::super::block::TransactionsBlockField::new(block);
    field.try_prepare_publication().unwrap();
    assert_eq!(
        storage.view().get(&key(1)),
        Some(height(1)),
        "logical preparation owns no reader lock"
    );
    let held = storage
        .history_released
        .guard(storage.blocks.try_acquire_writer().unwrap());
    assert!(matches!(
        field.try_prepare_physical(),
        Err(TransactionsBlockError::MembershipAdmission(
            MembershipAdmissionError::Busy(_)
        ))
    ));
    drop(held);
    field.try_prepare_physical().unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _original = field;
            panic!("unrelated outer caller panic before publication");
        }))
        .is_err()
    );
    assert_eq!(storage.view().get(&key(2)), None);
    commit(&storage, 2, &[key(3)], false);
    assert_eq!(storage.view().get(&key(3)), Some(height(2)));
}

#[test]
fn stale_return_cannot_displace_a_new_generation_preparation() {
    let storage = owner();
    let mut stale = storage.prepare_next_block(false).unwrap();
    // Semantic detached journals release the preparation loan while retaining
    // their exact native successor; this test retains the old successor directly.
    drop(stale.release_loan());
    commit(&storage, 1, &[key(1)], false);
    let current = storage.prepare_next_block(false).unwrap();
    let identity = current.next_identity.as_ref().unwrap().clone();
    storage.retain_preparation(current);
    storage.retain_preparation(stale);
    let next = storage.prepare_next_block(false).unwrap();
    assert!(Identity::ptr_eq(
        next.next_identity.as_ref().unwrap(),
        &identity
    ));
    assert!(next.predecessor.loaned.load(Ordering::Acquire));
}

#[test]
fn sequence_exhaustion_refuses_before_any_successor_allocation() {
    let storage = owner();
    storage
        .publication_sequence
        .store(u64::MAX - 1, Ordering::Release);
    let before = storage.budget.reserved_bytes();
    assert!(matches!(
        storage.prepare_next_block(false),
        Err(MembershipAdmissionError::Planning(PlanningError::Overflow))
    ));
    assert_eq!(storage.budget.reserved_bytes(), before);
    assert!(storage.pending.lock().is_none());
    assert!(!storage.write_lock.lock().loaned.load(Ordering::Acquire));
}

#[test]
fn original_kura_pool_refuses_before_world_or_either_start_stage() {
    let state = crate::state::State::new_with_pre_genesis_nexus_for_testing(
        crate::state::World::default(),
        iroha_config::parameters::actual::Nexus::default(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    let pool = state.kura.transaction_history_budget();
    assert_eq!(
        pool.reserved_bytes(),
        state.transactions.budget.reserved_bytes()
    );
    let occupied = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let world = state.world.block();
    let header =
        iroha_data_model::block::BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 1, 0);
    let result = state.block_with_owned_start_stages(
        header,
        |_| -> Result<(), ()> { panic!("pristine stage ran before membership admission") },
        |_, ()| -> Result<(), ()> { panic!("after-start ran before membership admission") },
    );
    assert!(matches!(
        result,
        Err(crate::state::StateBlockStartError::Membership(
            MembershipAdmissionError::Capacity(AllocationRefusal::Capacity { .. })
        ))
    ));
    drop(result);
    drop(world);
    drop(occupied);
    let block = state.try_block(header).unwrap();
    assert!(block.start_of_block_effects_applied);
    drop(block);
    assert_eq!(state.committed_height(), 0);
}

thread_local! {
    static PANIC_BEFORE_ADVANCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn panic_before_advance() {
    PANIC_BEFORE_ADVANCE.with(|armed| {
        assert!(!armed.replace(false), "controlled original advance unwind");
    });
}

#[test]
fn retired_pending_notice_outlives_both_preparation_locks_on_unwind() {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    struct ObserveLocks {
        storage: Arc<TransactionsStorage>,
        wakes: AtomicUsize,
        blocked: AtomicBool,
    }
    impl std::task::Wake for ObserveLocks {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            if self.storage.write_lock.try_lock().is_none()
                || self.storage.pending.try_lock().is_none()
            {
                self.blocked.store(true, Ordering::SeqCst);
            }
        }
    }
    for unwind in [false, true] {
        let storage = Arc::new(owner());
        let mut release_registration_0 =
            crate::unit_test_support::release_registration(&storage.budget);
        let mut original = storage.prepare_next_block(false).unwrap();
        drop(original.release_loan());
        // Current production returns drain these notices. Deliberately retain
        // an actual acquired guard's release to exercise the slot's stated
        // retirement guarantee, including its unwind boundary.
        assert!(
            storage
                .released
                .guard(storage.write_lock.lock())
                .try_release_into(&mut original.attachment_releases, drop)
                .is_ok()
        );
        *storage.pending.lock() = Some(original);
        let wait = storage.released.observe();
        let observe = Arc::new(ObserveLocks {
            storage: Arc::clone(&storage),
            wakes: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&observe));
        let mut future = std::pin::pin!(wait.wait_for_release(&mut release_registration_0));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        PANIC_BEFORE_ADVANCE.with(|armed| armed.set(unwind));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            storage.prepare_next_block(true)
        }));
        assert_eq!(result.is_err(), unwind);
        drop(result);
        assert!(observe.wakes.load(Ordering::SeqCst) > 0);
        assert!(!observe.blocked.load(Ordering::SeqCst));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
        );
        assert!(storage.write_lock.try_lock().is_some());
        assert!(storage.pending.try_lock().is_some());
        assert!(storage.prepare_next_block(true).is_ok());
    }
}

#[test]
fn original_identity_retirement_observer_is_lazy_and_never_retains_its_owner() {
    let pool = AllocationBudget::new(1024 * 1024);
    let identity = new_identity(&pool).unwrap();
    assert!(identity.retirement_observer.get().is_none());
    let first = identity.observe_retirement_for_tests();
    let second = identity.observe_retirement_for_tests();
    assert!(std::sync::Weak::ptr_eq(&first, &second));
    assert_eq!(
        first.strong_count(),
        1,
        "only the actual payload owns the marker"
    );
    assert!(!identity.loaned.load(Ordering::Acquire));
    let retained = identity.clone();
    let charged = pool.reserved_bytes();
    drop(identity);
    assert_eq!(pool.reserved_bytes(), charged);
    assert!(first.upgrade().is_some());
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(first.upgrade().is_none());
    assert!(second.upgrade().is_none());
}

#[test]
fn attached_publication_busy_retry_retains_original_cursor_charge_and_release_sources() {
    let storage = owner();
    commit(&storage, 1, &[key(1), key(2)], false);
    let mut pending = Some(storage.prepare_next_block(false).unwrap());
    let mut block = storage.attach_prepared(&mut pending).unwrap();
    block.insert_block([key(3)].into_iter().collect(), height(2));
    let mut field = TransactionsBlockField::new(block);
    field.try_prepare_publication().unwrap();
    let reserved = storage.budget.reserved_bytes();
    for _ in 0..3 {
        let blocker = storage
            .history_released
            .guard(storage.blocks.acquire_writer());
        let Err(TransactionsBlockError::MembershipAdmission(MembershipAdmissionError::Busy(_))) =
            field.try_prepare_physical()
        else {
            panic!("actual original history writer must refuse physical admission");
        };
        field.release_physical_for_retry();
        assert_eq!(storage.budget.reserved_bytes(), reserved);
        assert_eq!(storage.latest_height(), 1);
        drop(blocker);
    }
    field.try_prepare_physical().unwrap();
    // Recover a successfully acquired prefix too: no normal retry may leave it locked.
    field.release_physical_for_retry();
    assert!(storage.blocks.try_acquire_writer().is_some());
    assert_eq!(storage.budget.reserved_bytes(), reserved);
    field.try_prepare_physical().unwrap();
    field.publish_prepared();
    drop(field);
    assert_eq!(storage.latest_height(), 2);
    assert_eq!(storage.view().get(&key(1)), Some(height(1)));
    assert_eq!(storage.view().get(&key(3)), Some(height(2)));
}
