//! Original membership capture, refusal and native notification custody.

use super::capture::MembershipCapturePhase;
use super::*;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Wake, Waker},
};

struct Probe {
    first: Arc<TransactionsStorage>,
    second: Arc<TransactionsStorage>,
    calls: AtomicUsize,
    busy: AtomicUsize,
    panic_after_probe: AtomicBool,
}

impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        // Actual mutex probes: no assertion, blocking, allocation or
        // synthesized release inside a callback that may unwind.
        let first_busy = self.first.write_lock.try_lock().is_none();
        let second_busy = self.second.write_lock.try_lock().is_none();
        self.busy.fetch_add(
            usize::from(first_busy) + usize::from(second_busy),
            Ordering::SeqCst,
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic_after_probe.swap(false, Ordering::SeqCst),
            "injected membership wake panic after physical probes"
        )
    }
}

fn probe(first: &Arc<TransactionsStorage>, second: &Arc<TransactionsStorage>) -> Arc<Probe> {
    Arc::new(Probe {
        first: Arc::clone(first),
        second: Arc::clone(second),
        calls: AtomicUsize::new(0),
        busy: AtomicUsize::new(0),
        panic_after_probe: AtomicBool::new(false),
    })
}

fn register(
    wait: iroha_allocation::release::ReleaseWait,
    probe: &Arc<Probe>,
    mut registration: iroha_allocation::release::ReleaseRegistration,
) -> (
    iroha_allocation::release::ReleaseWait,
    iroha_allocation::release::ReleaseRegistration,
) {
    let waker = Waker::from(Arc::clone(probe));
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(&waker))
            .is_pending()
    );
    (wait, registration)
}

fn assert_released(
    pending: &mut (
        iroha_allocation::release::ReleaseWait,
        iroha_allocation::release::ReleaseRegistration,
    ),
    probe: &Probe,
) {
    assert!(
        pending
            .1
            .poll_wait(&pending.0, &mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.busy.load(Ordering::SeqCst), 0);
}

struct Pair<'a> {
    first: Option<TransactionsCaptureSlot<'a>>,
    second: Option<TransactionsCaptureSlot<'a>>,
}
impl Drop for Pair<'_> {
    fn drop(&mut self) {
        if let Some(first) = self.first.as_mut() {
            first.release();
        }
        if let Some(second) = self.second.as_mut() {
            second.release();
        }
    }
}

fn key(tag: u8) -> Key {
    HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed(
        [tag; iroha_crypto::Hash::LENGTH],
    ))
}
fn height(value: usize) -> Value {
    NonZeroUsize::new(value).unwrap()
}
fn seeded(tag: u8) -> Arc<TransactionsStorage> {
    let storage = Arc::new(TransactionsStorage::new());
    let mut original = storage.block();
    original.insert_block(BTreeSet::from([key(tag)]), height(1));
    original.commit().unwrap();
    storage
}
fn staged(storage: &TransactionsStorage, replace: bool, tag: u8) -> TransactionsBlock<'_> {
    let mut block = if replace {
        storage.block_and_revert()
    } else {
        storage.block()
    };
    block.insert_block(
        BTreeSet::from([key(tag)]),
        height(if replace { 1 } else { 2 }),
    );
    block
}

#[test]
fn membership_capture_retains_original_ordinary_and_replacement_journals_and_releases() {
    for replace in [false, true] {
        let first = seeded(2);
        let second = seeded(4);
        let release_registration_0 = crate::unit_test_support::release_registration(&first.budget);
        let release_registration_1 = crate::unit_test_support::release_registration(&second.budget);
        let first_tip = first.latest_block.load_full().unwrap();
        let second_tip = second.latest_block.load_full().unwrap();
        let first_identity = (*first.write_lock.lock()).clone();
        let second_identity = (*second.write_lock.lock()).clone();
        let first_block = staged(&first, replace, 6);
        let second_block = staged(&second, replace, 8);
        let first_payload = tip_weak_for_tests(first_block.current_block.as_ref().unwrap());
        let second_payload = tip_weak_for_tests(second_block.current_block.as_ref().unwrap());
        let mut pair = Pair {
            first: Some(first_block.capture_slot()),
            second: Some(second_block.capture_slot()),
        };
        let first_probe = probe(&first, &second);
        let second_probe = probe(&first, &second);
        let mut first_wait = register(
            first.released.observe(),
            &first_probe,
            release_registration_0,
        );
        let mut second_wait = register(
            second.released.observe(),
            &second_probe,
            release_registration_1,
        );
        pair.first.as_mut().unwrap().try_prepare().unwrap();
        let first_next = match &pair.first.as_ref().unwrap().phase {
            MembershipCapturePhase::Prepared(prepared) => {
                match (&prepared.publication, replace) {
                    (MembershipPublication::Replace { current }, true) => {
                        assert_eq!(tip_ptr(current), first_payload.as_ptr());
                    }
                    (
                        MembershipPublication::Advance {
                            _previous: previous,
                            current,
                        },
                        false,
                    ) => {
                        assert!(Tip::ptr_eq(previous.as_ref().unwrap(), &first_tip));
                        assert_eq!(tip_ptr(current), first_payload.as_ptr());
                    }
                    _ => panic!("exact original membership action"),
                }
                std::ptr::from_ref(&*prepared.next_identity)
            }
            _ => panic!("original preparation remains in caller slot"),
        };
        pair.first.as_mut().unwrap().try_capture().unwrap();
        assert_eq!(first_probe.calls.load(Ordering::SeqCst), 0);
        assert!(first.write_lock.try_lock().is_some());
        assert!(second.write_lock.try_lock().is_none());
        pair.second.as_mut().unwrap().try_capture().unwrap();
        let (first_journal, first_release) = pair.first.take().unwrap().into_detached();
        let (second_journal, second_release) = pair.second.take().unwrap().into_detached();
        assert_eq!(first_probe.calls.load(Ordering::SeqCst), 0);
        assert_eq!(second_probe.calls.load(Ordering::SeqCst), 0);
        assert_eq!(first_journal.revert, replace);
        assert_eq!(second_journal.revert, replace);
        assert_eq!(
            std::ptr::from_ref(&*first_journal.next_identity),
            first_next
        );
        assert!(Identity::ptr_eq(
            &first_journal.predecessor_identity,
            &first_identity
        ));
        assert!(Identity::ptr_eq(
            &second_journal.predecessor_identity,
            &second_identity
        ));
        assert!(Tip::ptr_eq(
            first_journal.predecessor.as_ref().unwrap(),
            &first_tip
        ));
        assert!(Tip::ptr_eq(
            second_journal.predecessor.as_ref().unwrap(),
            &second_tip
        ));
        assert_eq!(tip_ptr(&first_journal.current), first_payload.as_ptr());
        assert_eq!(tip_ptr(&second_journal.current), second_payload.as_ptr());
        assert!(Tip::ptr_eq(
            &first.latest_block.load_full().unwrap(),
            &first_tip
        ));
        assert!(Tip::ptr_eq(
            &second.latest_block.load_full().unwrap(),
            &second_tip
        ));
        drop((first_release, second_release));
        assert_released(&mut first_wait, &first_probe);
        assert_released(&mut second_wait, &second_probe);
        // Original journals, not copied test images, remain alive
        // through all callback, identity and physical-unlock checks.
        drop((first_journal, second_journal));
        assert!(first_payload.upgrade().is_none());
        assert!(second_payload.upgrade().is_none());
    }
}

#[test]
fn membership_capture_real_refusal_keeps_original_writer_until_joint_release() {
    for wrong_height in [false, true] {
        let first = seeded(2);
        let second = seeded(4);
        let release_registration_0 = crate::unit_test_support::release_registration(&first.budget);
        let release_registration_1 = crate::unit_test_support::release_registration(&second.budget);
        let first_tip = first.latest_block.load_full().unwrap();
        let second_tip = second.latest_block.load_full().unwrap();
        let first_block = staged(&first, false, 6);
        let first_payload = tip_weak_for_tests(first_block.current_block.as_ref().unwrap());
        let mut second_block = second.block();
        if wrong_height {
            second_block.insert_block(BTreeSet::from([key(8)]), height(3));
        }
        let mut pair = Pair {
            first: Some(first_block.capture_slot()),
            second: Some(second_block.capture_slot()),
        };
        let first_probe = probe(&first, &second);
        let second_probe = probe(&first, &second);
        let mut first_wait = register(
            first.released.observe(),
            &first_probe,
            release_registration_0,
        );
        let mut second_wait = register(
            second.released.observe(),
            &second_probe,
            release_registration_1,
        );
        pair.first.as_mut().unwrap().try_prepare().unwrap();
        let error = pair.second.as_mut().unwrap().try_prepare().unwrap_err();
        assert!(if wrong_height {
            matches!(
                error,
                TransactionsBlockError::HeightMismatch {
                    expected_current_height: 2,
                    actual_current_height: 3
                }
            )
        } else {
            matches!(error, TransactionsBlockError::MissingInsertBlock)
        });
        assert!(first.write_lock.try_lock().is_none());
        assert!(second.write_lock.try_lock().is_none());
        assert!(first_payload.upgrade().is_some());
        assert_eq!(first_probe.calls.load(Ordering::SeqCst), 0);
        assert_eq!(second_probe.calls.load(Ordering::SeqCst), 0);
        drop(pair);
        assert_released(&mut first_wait, &first_probe);
        assert_released(&mut second_wait, &second_probe);
        assert!(first_payload.upgrade().is_none());
        assert!(Tip::ptr_eq(
            &first.latest_block.load_full().unwrap(),
            &first_tip
        ));
        assert!(Tip::ptr_eq(
            &second.latest_block.load_full().unwrap(),
            &second_tip
        ));
        staged(&second, false, 8).commit().unwrap();
        assert_eq!(second.view().get(&key(8)), Some(height(2)));
    }
}

#[test]
fn membership_capture_outer_unwind_releases_prepared_or_captured_and_attached_sibling() {
    for capture_first in [false, true] {
        let first = seeded(2);
        let second = seeded(4);
        let release_registration_0 = crate::unit_test_support::release_registration(&first.budget);
        let release_registration_1 = crate::unit_test_support::release_registration(&second.budget);
        let first_probe = probe(&first, &second);
        let second_probe = probe(&first, &second);
        let first_observation = first.released.observe();
        let second_observation = second.released.observe();
        let mut first_wait = register(
            first_observation.clone(),
            &first_probe,
            release_registration_0,
        );
        let mut second_wait = register(
            second_observation.clone(),
            &second_probe,
            release_registration_1,
        );
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut pair = Pair {
                first: Some(staged(&first, false, 6).capture_slot()),
                second: Some(staged(&second, false, 8).capture_slot()),
            };
            if capture_first {
                pair.first.as_mut().unwrap().try_capture().unwrap();
            } else {
                pair.first.as_mut().unwrap().try_prepare().unwrap();
            }
            // Represents a later caller/callee unwind while original
            // membership siblings remain in the caller's aggregate.
            panic!("injected later capture failure");
        }));
        assert!(result.is_err());
        assert_released(&mut first_wait, &first_probe);
        assert_released(&mut second_wait, &second_probe);
        assert!(!first_observation.is_poisoned());
        assert!(!second_observation.is_poisoned());
        assert_eq!(first.view().get(&key(6)), None);
        assert_eq!(second.view().get(&key(8)), None);
        assert!(first.write_lock.try_lock().is_some());
        assert!(second.write_lock.try_lock().is_some());
    }
}

#[test]
fn membership_terminal_release_rejects_read_mutation_preparation_and_publication() {
    let storage = seeded(2);
    let tip = storage.latest_block.load_full().unwrap();
    let mut block = staged(&storage, false, 6);
    block.release_writers();
    assert!(storage.write_lock.try_lock().is_some());
    assert!(catch_unwind(AssertUnwindSafe(|| block.get(&key(6)))).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(
            || block.insert_block(BTreeSet::from([key(6)]), height(2))
        ))
        .is_err()
    );
    assert!(catch_unwind(AssertUnwindSafe(|| block.prepare_commit())).is_err());
    let mut prepared = staged(&storage, false, 8).prepare_commit().unwrap();
    prepared.block.release_writers();
    assert!(catch_unwind(AssertUnwindSafe(|| prepared.publish())).is_err());
    assert!(Tip::ptr_eq(
        &storage.latest_block.load_full().unwrap(),
        &tip
    ));
    assert!(storage.blocks.read().is_empty());
    let mut slot = staged(&storage, false, 10).capture_slot();
    slot.try_prepare().unwrap();
    slot.release();
    assert!(catch_unwind(AssertUnwindSafe(|| slot.try_capture())).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| slot.into_prepared())).is_err());
    let mut slot = staged(&storage, false, 12).capture_slot();
    slot.try_capture().unwrap();
    slot.release();
    assert!(catch_unwind(AssertUnwindSafe(|| slot.into_detached())).is_err());
    assert!(Tip::ptr_eq(
        &storage.latest_block.load_full().unwrap(),
        &tip
    ));
}

#[test]
fn membership_capture_wake_panic_keeps_other_original_release_healthy() {
    let first = seeded(2);
    let second = seeded(4);
    let release_registration_0 = crate::unit_test_support::release_registration(&first.budget);
    let release_registration_1 = crate::unit_test_support::release_registration(&second.budget);
    let first_probe = probe(&first, &second);
    let second_probe = probe(&first, &second);
    first_probe.panic_after_probe.store(true, Ordering::SeqCst);
    let first_observation = first.released.observe();
    let second_observation = second.released.observe();
    let mut first_wait = register(
        first_observation.clone(),
        &first_probe,
        release_registration_0,
    );
    let mut second_wait = register(
        second_observation.clone(),
        &second_probe,
        release_registration_1,
    );
    let result = catch_unwind(AssertUnwindSafe(|| {
        let pair = Pair {
            first: Some(staged(&first, false, 6).capture_slot()),
            second: Some(staged(&second, false, 8).capture_slot()),
        };
        drop(pair);
    }));
    assert!(result.is_err());
    assert_released(&mut first_wait, &first_probe);
    assert_released(&mut second_wait, &second_probe);
    assert!(!first_observation.is_poisoned());
    assert!(!second_observation.is_poisoned());
    assert_eq!(first.view().get(&key(6)), None);
    assert_eq!(second.view().get(&key(8)), None);
}

struct PublicationPair<'a> {
    first: TransactionsBlockField<'a>,
    second: TransactionsBlockField<'a>,
}
impl Drop for PublicationPair<'_> {
    fn drop(&mut self) {
        self.first.release_writers();
        self.second.release_writers();
    }
}

#[test]
fn membership_attached_publication_retains_original_actions_and_defers_both_wakes() {
    for replace in [false, true] {
        let first = seeded(2);
        let second = seeded(4);
        let release_registration_0 = crate::unit_test_support::release_registration(&first.budget);
        let release_registration_1 = crate::unit_test_support::release_registration(&second.budget);
        let first_original_identity = (*first.write_lock.lock()).clone();
        let original_tip = first.latest_block.load_full().unwrap();
        let first_block = staged(&first, replace, 6);
        let mut expected_json = String::new();
        JsonSerializeTrait::json_serialize(&first_block, &mut expected_json);
        let expected_bounded_json = json::to_json_bounded(&first_block, usize::MAX);
        let staged_pointer = tip_ptr(first_block.current_block.as_ref().unwrap());
        let mut pair = PublicationPair {
            first: TransactionsBlockField::new(first_block),
            second: TransactionsBlockField::new(staged(&second, replace, 8)),
        };
        let mut actual_json = String::new();
        JsonSerializeTrait::json_serialize(&pair.first, &mut actual_json);
        assert_eq!(actual_json, expected_json);
        // The original manual serializer does not certify bounded output.
        // Forward that exact refusal instead of fabricating a checked path.
        assert_eq!(
            expected_bounded_json,
            Err(json::BoundedJsonError::Unsupported)
        );
        assert_eq!(
            json::to_json_bounded(&pair.first, usize::MAX),
            expected_bounded_json
        );
        assert_eq!(
            pair.first.get(&key(6)),
            Some(height(if replace { 1 } else { 2 }))
        );
        let first_probe = probe(&first, &second);
        let second_probe = probe(&first, &second);
        let mut first_wait = register(
            first.released.observe(),
            &first_probe,
            release_registration_0,
        );
        let mut second_wait = register(
            second.released.observe(),
            &second_probe,
            release_registration_1,
        );
        pair.first.try_prepare_publication().unwrap();
        pair.first.try_prepare_physical().unwrap();
        pair.second.try_prepare_publication().unwrap();
        pair.second.try_prepare_physical().unwrap();
        let next = match &pair.first.slot.phase {
            MembershipCapturePhase::Prepared(prepared) => (prepared.next_identity).clone(),
            _ => panic!("original admitted membership"),
        };
        pair.first.publish_prepared();
        assert!(first.write_lock.try_lock().is_some());
        assert!(second.write_lock.try_lock().is_none());
        assert_eq!(first_probe.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            tip_ptr(&first.latest_block.load_full().unwrap()),
            staged_pointer
        );
        assert!(Identity::ptr_eq(&first.write_lock.lock(), &next));
        match &pair.first.slot.phase {
            MembershipCapturePhase::Published(prepared) => {
                assert!(Identity::ptr_eq(
                    &prepared.next_identity,
                    &first_original_identity
                ));
                assert!(Tip::ptr_eq(
                    prepared.retired_tip.as_ref().unwrap(),
                    &original_tip
                ));
                assert!(prepared.published && prepared.publication_started);
            }
            _ => panic!("original published membership retained"),
        }
        // Borrowed execution and repeated publication reject before removing
        // the already published owner or its original deferred release.
        assert!(catch_unwind(AssertUnwindSafe(|| pair.first.get(&key(6)))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| pair.first.publish_prepared())).is_err());
        assert_eq!(first_probe.calls.load(Ordering::SeqCst), 0);
        pair.second.publish_prepared();
        assert_eq!(second_probe.calls.load(Ordering::SeqCst), 0);
        drop(pair);
        assert_released(&mut first_wait, &first_probe);
        assert_released(&mut second_wait, &second_probe);
        assert_eq!(
            first.view().get(&key(6)),
            Some(height(if replace { 1 } else { 2 }))
        );
        assert_eq!(
            first.view().get(&key(2)),
            if replace { None } else { Some(height(1)) }
        );
    }
}

#[test]
fn membership_attached_refusal_and_panic_keep_original_sibling_until_joint_drop() {
    for failure in 0..3 {
        let first = seeded(2);
        let second = seeded(4);
        let release_registration_0 = crate::unit_test_support::release_registration(&first.budget);
        let release_registration_1 = crate::unit_test_support::release_registration(&second.budget);
        let first_tip = first.latest_block.load_full().unwrap();
        let second_tip = second.latest_block.load_full().unwrap();
        let mut second_block = second.block();
        if failure == 1 {
            second_block.insert_block(BTreeSet::from([key(8)]), height(3));
        }
        let first_probe = probe(&first, &second);
        let second_probe = probe(&first, &second);
        let mut first_wait = register(
            first.released.observe(),
            &first_probe,
            release_registration_0,
        );
        let mut second_wait = register(
            second.released.observe(),
            &second_probe,
            release_registration_1,
        );
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut pair = PublicationPair {
                first: TransactionsBlockField::new(staged(&first, false, 6)),
                second: TransactionsBlockField::new(second_block),
            };
            pair.first.try_prepare_publication().unwrap();
            pair.first.try_prepare_physical().unwrap();
            if failure == 2 {
                // Real one-shot API refusal: the first action is published,
                // then a later field rejects publication without preparation.
                pair.first.publish_prepared();
                pair.second.publish_prepared();
                unreachable!("unprepared membership publication must panic");
            }
            let error = pair.second.try_prepare_publication().unwrap_err();
            assert!(matches!(
                (failure, error),
                (0, TransactionsBlockError::MissingInsertBlock)
                    | (
                        1,
                        TransactionsBlockError::HeightMismatch {
                            expected_current_height: 2,
                            actual_current_height: 3
                        }
                    )
            ));
            assert!(first.write_lock.try_lock().is_none());
            assert!(second.write_lock.try_lock().is_none());
            assert_eq!(first_probe.calls.load(Ordering::SeqCst), 0);
            assert_eq!(second_probe.calls.load(Ordering::SeqCst), 0);
            // Failed preparation is terminal, retaining both actual writers.
            assert!(
                catch_unwind(AssertUnwindSafe(|| pair.second.try_prepare_publication())).is_err()
            );
        }));
        assert_eq!(result.is_err(), failure == 2);
        assert_released(&mut first_wait, &first_probe);
        assert_released(&mut second_wait, &second_probe);
        if failure != 2 {
            assert!(Tip::ptr_eq(
                &first.latest_block.load_full().unwrap(),
                &first_tip
            ));
        } else {
            assert_eq!(first.view().get(&key(6)), Some(height(2)));
        }
        assert!(Tip::ptr_eq(
            &second.latest_block.load_full().unwrap(),
            &second_tip
        ));
        // Native membership uses the original non-poisoning mutex on unwind.
        staged(&second, false, 8).commit().unwrap();
        assert_eq!(second.view().get(&key(8)), Some(height(2)));
    }
}

#[test]
fn membership_attached_execution_transfer_and_repeated_commit_preserve_identity() {
    let storage = seeded(2);
    let original_identity = (*storage.write_lock.lock()).clone();
    let original_tip = storage.latest_block.load_full().unwrap();
    let mut block = TransactionsBlockField::new(storage.block());
    block.insert_block(BTreeSet::from([key(2)]), height(1));
    let original_staged = tip_ptr(block.current_block.as_ref().unwrap());
    let block = block.into_executing();
    assert_eq!(
        tip_ptr(block.current_block.as_ref().unwrap()),
        original_staged
    );
    let capture = TransactionsBlockField::new(block).into_capture();
    let mut capture = capture;
    capture.try_prepare().unwrap();
    capture.publish_prepared();
    assert!(Identity::ptr_eq(
        &storage.write_lock.lock(),
        &original_identity
    ));
    assert!(Tip::ptr_eq(
        &storage.latest_block.load_full().unwrap(),
        &original_tip
    ));
    assert!(catch_unwind(AssertUnwindSafe(|| capture.try_capture())).is_err());
    capture.release();
    assert!(catch_unwind(AssertUnwindSafe(|| capture.publish_prepared())).is_err());
    drop(capture);
    assert_eq!(storage.view().get(&key(2)), Some(height(1)));
}

#[test]
fn inline_membership_freeze_releases_logical_writer_and_retries_exact_original() {
    for replace in [false, true] {
        let storage = seeded(71);
        let mut original = TransactionsBlockField::new(if replace {
            storage.block_and_revert()
        } else {
            storage.block()
        });
        let next = if replace { height(1) } else { height(2) };
        original.insert_block_with_single_tx(key(72), next);
        let pointer = tip_ptr(original.current_block.as_ref().unwrap());
        let expected = json::to_json(&original).unwrap();
        let reserved = storage.budget.reserved_bytes();
        original.try_prepare_publication().unwrap();
        original.finish_freeze().unwrap();
        assert!(
            storage.write_lock.try_lock().is_some(),
            "actual membership mutex released"
        );
        assert_eq!(original.get(&key(72)), Some(next));
        assert_eq!(json::to_json(&original).unwrap(), expected);
        assert_eq!(storage.budget.reserved_bytes(), reserved);
        original.retire_frozen_cleanup();
        storage.budget.set_limit_bytes(0);
        for _ in 0..3 {
            let blocker = storage.released.guard(storage.write_lock.lock());
            original.install_frozen_publication(&storage);
            assert!(matches!(
                original.try_prepare_frozen_publication(),
                Err(mv::PublicationPreparationError::Busy(_))
            ));
            original.recover_installed_frozen_publication();
            let MembershipCapturePhase::Captured(journal) = &original.slot.phase else {
                panic!("exact frozen original")
            };
            assert_eq!(tip_ptr(&journal.current), pointer);
            assert_eq!(original.get(&key(72)), Some(next));
            assert_eq!(json::to_json(&original).unwrap(), expected);
            drop(blocker);
            original.retire_frozen_cleanup();
        }
        original.install_frozen_publication(&storage);
        original.try_prepare_frozen_publication().unwrap();
        original.publish_prepared();
        drop(original);
        assert_eq!(storage.view().get(&key(72)), Some(next));
    }
}
