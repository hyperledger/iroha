//! Retained membership acquisition, original retry and aggregate release custody.

use super::{detached_publication::DetachedTransactionsPublicationSlot, *};
use mv::PublicationPreparationError;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Wake, Waker},
};

struct Probe {
    targets: [Arc<TransactionsStorage>; 2],
    wakes: AtomicUsize,
    installations: AtomicUsize,
    busy: AtomicUsize,
}
impl Probe {
    fn inspect(&self) {
        for target in &self.targets {
            self.busy.fetch_add(
                usize::from(target.write_lock.try_lock().is_none()),
                Ordering::SeqCst,
            );
        }
    }
}
impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.inspect();
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}
struct Installation(Arc<Probe>);
impl Drop for Installation {
    fn drop(&mut self) {
        self.0.inspect();
        self.0.installations.fetch_add(1, Ordering::SeqCst);
    }
}
struct Pair<'a> {
    first: DetachedTransactionsPublicationSlot<'a, Installation>,
    second: DetachedTransactionsPublicationSlot<'a, Installation>,
}
impl Drop for Pair<'_> {
    fn drop(&mut self) {
        self.first.release_writers();
        self.second.release_writers();
    }
}
fn key(tag: u8) -> Key {
    HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([tag; 32]))
}
fn stage(target: &TransactionsStorage, replace: bool, tag: u8) -> DetachedTransactionsBlock {
    let mut block = if replace {
        target.block_and_revert()
    } else {
        target.block()
    };
    block.insert_block(
        BTreeSet::from([key(tag)]),
        NonZeroUsize::new(if replace { 1 } else { 2 }).unwrap(),
    );
    block.prepare_commit().unwrap().detach()
}
fn targets() -> [Arc<TransactionsStorage>; 2] {
    std::array::from_fn(|i| {
        let target = Arc::new(TransactionsStorage::new());
        let mut block = target.block();
        block.insert_block(
            BTreeSet::from([key(u8::try_from(i).expect("fixture value fits u8"))]),
            NonZeroUsize::new(1).unwrap(),
        );
        block.commit().unwrap();
        target
    })
}
fn probe(targets: &[Arc<TransactionsStorage>; 2]) -> Arc<Probe> {
    Arc::new(Probe {
        targets: targets.clone(),
        wakes: AtomicUsize::new(0),
        installations: AtomicUsize::new(0),
        busy: AtomicUsize::new(0),
    })
}
fn register(
    target: &TransactionsStorage,
    probe: &Arc<Probe>,
    mut registration: iroha_allocation::release::ReleaseRegistration,
) -> (
    iroha_allocation::release::ReleaseWait,
    iroha_allocation::release::ReleaseRegistration,
) {
    let wait = target.released.observe();
    let waker = Waker::from(Arc::clone(probe));
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(&waker))
            .is_pending()
    );
    (wait, registration)
}
fn assert_ready(
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
    assert_eq!(probe.busy.load(Ordering::SeqCst), 0);
}
fn pair(targets: &[Arc<TransactionsStorage>; 2], replace: bool) -> Pair<'_> {
    Pair {
        first: stage(&targets[0], replace, 7).publication_slot(&targets[0]),
        second: stage(&targets[1], replace, 9).publication_slot(&targets[1]),
    }
}

#[test]
fn detached_membership_slots_retain_actual_preflight_on_refusal_and_caught_panic() {
    for replace in [false, true] {
        for panics in [false, true] {
            let targets = targets();
            let release_registration_0 =
                crate::unit_test_support::release_registration(&targets[0].budget);
            let release_registration_1 =
                crate::unit_test_support::release_registration(&targets[1].budget);
            let mut pair = pair(&targets, replace);
            let first_probe = probe(&targets);
            let second_probe = probe(&targets);
            let mut first_wait = register(&targets[0], &first_probe, release_registration_0);
            let mut second_wait = register(&targets[1], &second_probe, release_registration_1);
            pair.first
                .try_prepare(|_, _| Ok::<_, ()>(Installation(Arc::clone(&first_probe))))
                .unwrap();
            let result = catch_unwind(AssertUnwindSafe(|| {
                pair.second.try_prepare(|_, target| {
                    assert!(target.write_lock.try_lock().is_some());
                    assert_eq!(second_probe.wakes.load(Ordering::SeqCst), 0);
                    assert!(!panics, "admission cut after the real advisory release");
                    Err::<Installation, _>("capacity")
                })
            }));
            if panics {
                assert!(result.is_err());
                assert!(catch_unwind(AssertUnwindSafe(|| pair.second.recover_original())).is_err());
            } else {
                assert!(matches!(
                    result.unwrap(),
                    Err(PublicationPreparationError::Admission("capacity"))
                ));
            }
            assert!(
                catch_unwind(AssertUnwindSafe(|| pair.second.try_prepare(|_, _| Ok::<
                    _,
                    (),
                >(
                    Installation(Arc::clone(&second_probe))
                ))))
                .is_err()
            );
            assert!(targets[0].write_lock.try_lock().is_none());
            assert_eq!(first_probe.wakes.load(Ordering::SeqCst), 0);
            assert_eq!(second_probe.wakes.load(Ordering::SeqCst), 0);
            drop(pair);
            assert_ready(&mut first_wait, &first_probe);
            assert_ready(&mut second_wait, &second_probe);
            assert_eq!(first_probe.installations.load(Ordering::SeqCst), 1);
            assert_eq!(second_probe.installations.load(Ordering::SeqCst), 0);
            assert_eq!(targets[0].latest_height(), 1);
            assert_eq!(targets[1].latest_height(), 1);
        }
    }
}

#[test]
fn detached_membership_slots_outer_unwind_releases_all_original_writers_before_cleanup() {
    let targets = targets();
    let release_registration_0 = crate::unit_test_support::release_registration(&targets[0].budget);
    let release_registration_1 = crate::unit_test_support::release_registration(&targets[1].budget);
    let first_probe = probe(&targets);
    let second_probe = probe(&targets);
    let mut waits = None;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut pair = pair(&targets, false);
        waits = Some((
            register(&targets[0], &first_probe, release_registration_0),
            register(&targets[1], &second_probe, release_registration_1),
        ));
        pair.first
            .try_prepare(|_, _| Ok::<_, ()>(Installation(Arc::clone(&first_probe))))
            .unwrap();
        pair.second
            .try_prepare(|_, _| -> Result<Installation, ()> {
                panic!("second admission unwind");
            })
            .unwrap();
    }));
    assert!(result.is_err());
    let (mut first_wait, mut second_wait) = waits.unwrap();
    assert_ready(&mut first_wait, &first_probe);
    assert_ready(&mut second_wait, &second_probe);
    assert_eq!(first_probe.installations.load(Ordering::SeqCst), 1);
}

#[test]
fn detached_membership_slots_recover_exact_original_action_and_identity() {
    for replace in [false, true] {
        for refuses in [false, true] {
            let targets = targets();
            let journal = stage(&targets[0], replace, 7);
            let current = tip_ptr(&journal.current);
            let predecessor = tip_ptr(journal.predecessor.as_ref().unwrap());
            let identity = std::ptr::from_ref(&*journal.predecessor_identity);
            let next = std::ptr::from_ref(&*journal.next_identity);
            let mut slot = journal.publication_slot::<()>(&targets[0]);
            let result = slot.try_prepare(|_, _| if refuses { Err("capacity") } else { Ok(()) });
            assert_eq!(result.is_err(), refuses);
            let original = slot.recover_original();
            assert_eq!(tip_ptr(&original.current), current);
            assert_eq!(tip_ptr(original.predecessor.as_ref().unwrap()), predecessor);
            assert_eq!(
                std::ptr::from_ref(&*original.predecessor_identity),
                identity
            );
            assert_eq!(std::ptr::from_ref(&*original.next_identity), next);
            match (&original.publication, replace) {
                (MembershipPublication::Replace { current: row }, true) => {
                    assert_eq!(tip_ptr(row), current)
                }
                (
                    MembershipPublication::Advance {
                        _previous: previous,
                        current: row,
                    },
                    false,
                ) => {
                    assert_eq!(tip_ptr(row), current);
                    assert_eq!(tip_ptr(previous.as_ref().unwrap()), predecessor);
                }
                _ => panic!("original pre-admitted action"),
            }
            assert!(catch_unwind(AssertUnwindSafe(|| slot.recover_original())).is_err());
            drop(slot);
            let mut retry = original.publication_slot::<()>(&targets[0]);
            retry.try_prepare(|_, _| Ok::<_, ()>(())).unwrap();
            retry.into_prepared().publish();
            assert_eq!(
                tip_ptr(&targets[0].latest_block.load_full().unwrap()),
                current
            );
            assert_eq!(std::ptr::from_ref(&**targets[0].write_lock.lock()), next);
            assert_eq!(
                targets[0].view().get(&key(7)),
                NonZeroUsize::new(if replace { 1 } else { 2 })
            );
        }
    }
}

#[test]
fn detached_membership_slots_late_changed_retains_actual_acquisition_and_installation() {
    let targets = targets();
    let release_registration_0 = crate::unit_test_support::release_registration(&targets[1].budget);
    let mut pair = pair(&targets, false);
    let first_probe = probe(&targets);
    let second_probe = probe(&targets);
    pair.first
        .try_prepare(|_, _| Ok::<_, ()>(Installation(Arc::clone(&first_probe))))
        .unwrap();
    let mut competitor_retirement = None;
    let mut second_wait = None;
    let error = pair
        .second
        .try_prepare(|_, target| {
            let mut replacement = target.block_and_revert();
            replacement.insert_block(BTreeSet::from([key(11)]), NonZeroUsize::new(1).unwrap());
            competitor_retirement = Some(replacement.prepare_commit().unwrap().publish());
            // This observes the next actual acquisition, after the unrelated commit.
            second_wait = Some(register(target, &second_probe, release_registration_0));
            Ok::<_, ()>(Installation(Arc::clone(&second_probe)))
        })
        .unwrap_err();
    assert!(matches!(error, PublicationPreparationError::Changed));
    assert!(
        targets[1].write_lock.try_lock().is_none(),
        "the stale final guard stays in the slot"
    );
    let original = pair.second.recover_original();
    assert_eq!(original.staged_membership().1, &BTreeSet::from([key(9)]));
    assert!(targets[1].write_lock.try_lock().is_some());
    assert_eq!(second_probe.wakes.load(Ordering::SeqCst), 0);
    assert_eq!(second_probe.installations.load(Ordering::SeqCst), 0);
    drop(pair);
    assert_ready(second_wait.as_mut().unwrap(), &second_probe);
    assert_eq!(second_probe.installations.load(Ordering::SeqCst), 1);
    drop(competitor_retirement);
}

#[test]
fn detached_membership_slots_busy_has_no_fabricated_release_and_late_busy_keeps_admission() {
    for late in [false, true] {
        let targets = targets();
        let release_registration_0 =
            crate::unit_test_support::release_registration(&targets[1].budget);
        let mut pair = pair(&targets, false);
        let first_probe = probe(&targets);
        let second_probe = probe(&targets);
        pair.first
            .try_prepare(|_, _| Ok::<_, ()>(Installation(Arc::clone(&first_probe))))
            .unwrap();
        let mut competitor = if late { None } else { Some(targets[1].block()) };
        let mut wait = register(&targets[1], &second_probe, release_registration_0);
        let error = pair
            .second
            .try_prepare(|_, _| {
                assert!(late, "early Busy cannot admit");
                competitor = Some(targets[1].block());
                Ok::<_, ()>(Installation(Arc::clone(&second_probe)))
            })
            .unwrap_err();
        assert!(matches!(error, PublicationPreparationError::Busy(_)));
        let _original = pair.second.recover_original();
        assert_eq!(second_probe.wakes.load(Ordering::SeqCst), 0);
        // The competitor belongs to the enclosing owner too: physically retire
        // it before any participant's retained callback or admission destructor.
        competitor.as_mut().unwrap().release_writers();
        pair.first.release_writers();
        pair.second.release_writers();
        drop(pair);
        if late {
            assert_ready(&mut wait, &second_probe);
            assert_eq!(second_probe.installations.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(second_probe.wakes.load(Ordering::SeqCst), 0);
            assert_eq!(second_probe.installations.load(Ordering::SeqCst), 0);
        }
        drop(competitor);
        assert_ready(&mut wait, &second_probe);
    }
}

#[test]
fn detached_membership_slots_terminal_release_revokes_original_and_prepared_authority() {
    for prepare in [false, true] {
        let targets = targets();
        let mut slot = stage(&targets[0], false, 7).publication_slot::<()>(&targets[0]);
        if prepare {
            slot.try_prepare(|_, _| Ok::<_, ()>(())).unwrap();
        }
        slot.release_writers();
        slot.release_writers();
        assert!(targets[0].write_lock.try_lock().is_some());
        assert!(catch_unwind(AssertUnwindSafe(|| slot.recover_original())).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| slot.try_prepare(|_, _| Ok::<_, ()>(())))).is_err()
        );
        assert!(catch_unwind(AssertUnwindSafe(|| slot.into_prepared())).is_err());
        assert_eq!(targets[0].latest_height(), 1);
    }
}

#[test]
fn detached_membership_slots_completed_abort_and_publish_retain_preflight_with_retirement() {
    for publish in [false, true] {
        let targets = targets();
        let release_registration_0 =
            crate::unit_test_support::release_registration(&targets[0].budget);
        let journal = stage(&targets[0], false, 7);
        let probe = probe(&targets);
        let mut slot = journal.publication_slot(&targets[0]);
        let mut wait = register(&targets[0], &probe, release_registration_0);
        slot.try_prepare(|_, _| Ok::<_, ()>(Installation(Arc::clone(&probe))))
            .unwrap();
        let prepared = slot.into_prepared();
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
        if publish {
            let retirement = prepared.publish();
            assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
            assert_eq!(probe.installations.load(Ordering::SeqCst), 0);
            drop(retirement);
        } else {
            let (_original, retirement) = prepared.abort();
            assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
            assert_eq!(probe.installations.load(Ordering::SeqCst), 0);
            drop(retirement);
        }
        assert_ready(&mut wait, &probe);
        assert_eq!(probe.installations.load(Ordering::SeqCst), 1);
    }
}
