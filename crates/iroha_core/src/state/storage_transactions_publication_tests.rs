//! Exact membership publication, refusal custody and installation lifetime.

use super::*;
use mv::PublicationPreparationError;

fn key(n: u8) -> Key {
    HashOf::from_untyped_unchecked(iroha_crypto::Hash::new([n]))
}

fn stage<'storage>(
    storage: &'storage TransactionsStorage,
    at: usize,
    keys: &[u8],
) -> TransactionsBlock<'storage> {
    let mut block = storage.block();
    block.insert_block(
        keys.iter().copied().map(key).collect(),
        NonZeroUsize::new(at).unwrap(),
    );
    block
}

fn prepare(
    detached: DetachedTransactionsBlock,
    storage: &TransactionsStorage,
) -> PreparedDetachedTransactionsBlock<'_, ()> {
    detached
        .try_prepare_publication(storage, |_, _| Ok::<_, &'static str>(()))
        .unwrap_or_else(|(_, error, _)| panic!("publication preparation: {error:?}"))
}

#[test]
fn publication_and_abort_keep_original_membership_allocation_and_history() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[1, 2]).commit().unwrap();
    let old_view = storage.view();
    let prepared = stage(&storage, 2, &[2, 3]).prepare_commit().unwrap();
    let expected = norito::json::to_json(&prepared).unwrap();
    let journal = prepared.detach();
    let pointer = std::ptr::from_ref(journal.staged_membership().1);
    let prepared = prepare(journal, &storage);
    assert!(storage.write_lock.try_lock().is_none());
    assert_eq!(storage.latest_height(), 1);
    // The prepared publication owns the active writer. Observe its old cut
    // through the reader retained before preparation, not a new blocking read.
    assert_eq!(old_view.get(&key(3)), None);
    let journal = prepared.abort().0;
    assert_eq!(std::ptr::from_ref(journal.staged_membership().1), pointer);
    assert_eq!(
        journal.observe_predecessor(&storage),
        MembershipPredecessorStatus::Current
    );
    prepare(journal, &storage).publish();
    assert_eq!(norito::json::to_json(&storage).unwrap(), expected);
    assert_eq!(storage.view().get(&key(1)), NonZeroUsize::new(1));
    assert_eq!(storage.view().get(&key(2)), NonZeroUsize::new(2));
    assert_eq!(old_view.get(&key(2)), NonZeroUsize::new(1));
    assert_eq!(old_view.get(&key(3)), None);
}

#[test]
fn repeat_does_not_promote_the_tip_and_replacement_recovers_older_membership() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[1, 2]).commit().unwrap();
    stage(&storage, 2, &[2, 3]).commit().unwrap();
    let next = stage(&storage, 3, &[4]).prepare_commit().unwrap().detach();
    prepare(
        stage(&storage, 2, &[2, 3])
            .prepare_commit()
            .unwrap()
            .detach(),
        &storage,
    )
    .publish();
    assert_eq!(
        next.observe_predecessor(&storage),
        MembershipPredecessorStatus::Current
    );
    let mut replacement = storage.block_and_revert();
    replacement.insert_block(BTreeSet::from([key(4)]), NonZeroUsize::new(2).unwrap());
    let replacement = replacement.prepare_commit().unwrap();
    let expected = norito::json::to_json(&replacement).unwrap();
    prepare(replacement.detach(), &storage).publish();
    assert_eq!(norito::json::to_json(&storage).unwrap(), expected);
    assert_eq!(storage.view().get(&key(2)), NonZeroUsize::new(1));
    assert_eq!(storage.view().get(&key(3)), None);
    assert_eq!(
        next.observe_predecessor(&storage),
        MembershipPredecessorStatus::Changed
    );
}

#[test]
fn busy_and_refused_installation_return_the_original_journal_for_retry() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[1]).commit().unwrap();
    let journal = stage(&storage, 2, &[2]).prepare_commit().unwrap().detach();
    let pointer = std::ptr::from_ref(journal.staged_membership().1);
    let writer = storage.block();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&storage, |_, _| -> Result<(), &str> {
            panic!("busy observation must not attempt installation admission")
        })
        .err()
        .expect("busy writer");
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    drop(writer);
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&storage, |_, target| {
            assert!(
                target.write_lock.try_lock().is_some(),
                "admission precedes writer ownership"
            );
            Err::<(), _>("capacity")
        })
        .err()
        .expect("admission refusal");
    assert!(matches!(
        error,
        PublicationPreparationError::Admission("capacity")
    ));
    assert_eq!(std::ptr::from_ref(journal.staged_membership().1), pointer);
    assert_eq!(storage.latest_height(), 1);
    prepare(journal, &storage).publish();
    assert_eq!(storage.view().get(&key(2)), NonZeroUsize::new(2));
}

#[test]
fn membership_abort_detach_and_commit_signal_the_exact_busy_writer() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Waker},
    };
    for finish in 0..5 {
        let storage = TransactionsStorage::new();
        let mut release_slot_0 = crate::unit_test_support::release_registration(&storage.budget);
        stage(&storage, 1, &[1]).commit().unwrap();
        let journal = stage(&storage, 2, &[2]).prepare_commit().unwrap().detach();
        let pointer = std::ptr::from_ref(journal.staged_membership().1);
        let competitor = stage(&storage, 2, &[3]).prepare_commit().unwrap();
        let (journal, error, _cleanup) = journal
            .try_prepare_publication(&storage, |_, _| Ok::<_, ()>(()))
            .err()
            .expect("membership writer");
        let PublicationPreparationError::Busy(wait) = error else {
            panic!("writer wait");
        };
        let mut wait = wait.wait_for_release(&mut release_slot_0);
        let mut context = Context::from_waker(Waker::noop());
        if finish % 2 == 0 {
            assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
        }
        match finish {
            0 => drop(competitor),
            1 => {
                competitor.detach();
            }
            2 => {
                drop(prepare(competitor.detach(), &storage));
            }
            3 => {
                prepare(competitor.detach(), &storage).abort();
            }
            _ => drop(competitor.publish()),
        }
        assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
        assert_eq!(std::ptr::from_ref(journal.staged_membership().1), pointer);
        let retry = journal.try_prepare_publication(&storage, |_, _| Ok::<_, ()>(()));
        if finish == 4 {
            assert!(matches!(
                retry.err().unwrap().1,
                PublicationPreparationError::Changed
            ));
        } else {
            assert_eq!(storage.latest_height(), 1, "wake needs no commit");
            assert!(retry.is_ok());
        }
    }
}

#[test]
fn foreign_owner_and_an_admission_race_cannot_rebind_the_journal() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[1]).commit().unwrap();
    let restored: TransactionsStorage =
        norito::json::from_str(&norito::json::to_json(&storage).unwrap()).unwrap();
    let journal = stage(&storage, 2, &[2]).prepare_commit().unwrap().detach();
    let pointer = std::ptr::from_ref(journal.staged_membership().1);
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&restored, |_, _| -> Result<(), &str> {
            panic!("foreign identity must be rejected before admission")
        })
        .err()
        .expect("foreign owner");
    assert!(matches!(error, PublicationPreparationError::Changed));
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&storage, |_, target| {
            // Equal bytes after two real replacements still represent a new cut.
            for value in [3, 1] {
                let mut replacement = target.block_and_revert();
                replacement
                    .insert_block(BTreeSet::from([key(value)]), NonZeroUsize::new(1).unwrap());
                replacement.commit().unwrap();
            }
            Ok::<_, &str>(())
        })
        .err()
        .expect("predecessor changed during admission");
    assert!(matches!(error, PublicationPreparationError::Changed));
    assert_eq!(std::ptr::from_ref(journal.staged_membership().1), pointer);
    assert_eq!(storage.view().get(&key(1)), NonZeroUsize::new(1));
    assert_eq!(storage.view().get(&key(2)), None);
    assert!(storage.write_lock.try_lock().is_some());
}

struct Installation<'a> {
    storage: &'a TransactionsStorage,
    releases: &'a std::cell::Cell<usize>,
}

impl Drop for Installation<'_> {
    fn drop(&mut self) {
        assert!(
            self.storage.write_lock.try_lock().is_some(),
            "release admission after writer"
        );
        self.releases.set(self.releases.get() + 1);
    }
}

#[test]
fn installation_outlives_writer_on_drop_abort_and_publication() {
    let storage = TransactionsStorage::new();
    let releases = std::cell::Cell::new(0);
    let detached = || stage(&storage, 1, &[1]).prepare_commit().unwrap().detach();
    let admit = |_: &DetachedTransactionsBlock, _: &TransactionsStorage| {
        Ok::<_, &str>(Installation {
            storage: &storage,
            releases: &releases,
        })
    };
    let prepared = detached()
        .try_prepare_publication(&storage, admit)
        .unwrap_or_else(|_| panic!("prepare"));
    drop(prepared);
    assert_eq!(releases.get(), 1);
    assert_eq!(storage.latest_height(), 0);
    let journal = detached()
        .try_prepare_publication(&storage, admit)
        .unwrap_or_else(|_| panic!("prepare"))
        .abort()
        .0;
    assert_eq!(releases.get(), 2);
    let guard = journal
        .try_prepare_publication(&storage, admit)
        .unwrap_or_else(|_| panic!("prepare"))
        .publish();
    assert_eq!(
        releases.get(),
        2,
        "aggregate owner retains installation admission"
    );
    assert_eq!(storage.latest_height(), 1);
    drop(guard);
    assert_eq!(releases.get(), 3);
}

#[test]
fn membership_publication_retains_original_cleanup_until_outer_unlock() {
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
    };
    struct Reenter {
        storage: Arc<TransactionsStorage>,
        outer: Arc<crate::publication_lock::PublicationMutex>,
        observed: AtomicUsize,
    }
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            let _outer = self
                .outer
                .try_lock_or_wait()
                .expect("outer commit fence released");
            let _writer = self
                .storage
                .write_lock
                .try_lock()
                .expect("membership writer released");
            assert_eq!(self.storage.view().get(&key(2)), NonZeroUsize::new(2));
            self.observed.fetch_add(1, Ordering::SeqCst);
        }
    }
    for detached in [false, true] {
        for unwind in [false, true] {
            let storage = Arc::new(TransactionsStorage::new());
            let mut release_slot_0 =
                crate::unit_test_support::release_registration(&storage.budget);
            stage(&storage, 1, &[1]).commit().unwrap();
            let tip = tip_weak_for_tests(storage.latest_block.load().as_ref().unwrap());
            let identity = storage.write_lock.lock().observe_retirement_for_tests();
            let prepared = stage(&storage, 2, &[2]).prepare_commit().unwrap();
            // Detachment also releases its writer: observe only the final owner.
            let publish: Box<dyn FnOnce() -> Box<dyn std::any::Any> + '_> = if detached {
                let prepared = prepare(prepared.detach(), &storage);
                Box::new(move || Box::new(prepared.publish()))
            } else {
                Box::new(move || Box::new(prepared.publish()))
            };
            let outer = Arc::new(crate::publication_lock::PublicationMutex::default());
            let outer_guard = outer.lock();
            let mut pending = Box::pin(
                storage
                    .released
                    .observe()
                    .wait_for_release(&mut release_slot_0),
            );
            let probe = Arc::new(Reenter {
                storage: Arc::clone(&storage),
                outer: Arc::clone(&outer),
                observed: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            assert!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let retirement = publish();
            assert!(storage.write_lock.try_lock().is_some());
            assert_eq!(probe.observed.load(Ordering::SeqCst), 0);
            assert!(
                tip.upgrade().is_some(),
                "original published tip is still retained"
            );
            assert!(
                identity.upgrade().is_some(),
                "original predecessor identity is still retained"
            );
            if unwind {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let _retirement = retirement;
                        let _outer = outer_guard;
                        panic!("enclosing completion unwind");
                    }))
                    .is_err()
                );
            } else {
                drop(outer_guard);
                drop(retirement);
            }
            assert_eq!(probe.observed.load(Ordering::SeqCst), 1);
            assert!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
            assert!(tip.upgrade().is_none());
            assert!(identity.upgrade().is_none());
        }
    }
}
