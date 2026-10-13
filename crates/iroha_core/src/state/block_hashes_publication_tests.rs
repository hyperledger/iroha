//! Hash publication preserves exact allocations and refuses stale predecessors.

use super::*;
use mv::PublicationPreparationError;

fn hash(n: u8) -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(Hash::new([n]))
}

fn detached(owner: &BlockHashes, replace: bool, appends: &[u8]) -> DetachedBlockHashes {
    let mut block = if replace {
        owner.block_and_revert()
    } else {
        owner.block()
    };
    for &value in appends {
        block.push(hash(value));
    }
    block.detach()
}

fn prepare(journal: DetachedBlockHashes, owner: &BlockHashes) -> PreparedBlockHashes<'_, ()> {
    journal
        .try_prepare_publication(owner, |_, _| Ok::<_, &str>(()))
        .unwrap_or_else(|(_, error, _)| panic!("hash publication preparation: {error:?}"))
}

#[test]
fn publication_moves_the_original_generation_and_matches_direct_commit() {
    for (replace, appends) in [
        (false, vec![3, 4]),
        (true, vec![3]),
        (true, vec![]),
        (false, vec![]),
    ] {
        let owner = BlockHashes::new(vec![hash(1), hash(2)]);
        let direct = BlockHashes::new(vec![hash(1), hash(2)]);
        let mut direct_block = if replace {
            direct.block_and_revert()
        } else {
            direct.block()
        };
        for &value in &appends {
            direct_block.push(hash(value));
        }
        direct_block.commit();
        let journal = detached(&owner, replace, &appends);
        let pointer = journal.get(0).map(std::ptr::from_ref);
        let old = detached(&owner, false, &[]);
        let prepared = prepare(journal, &owner);
        assert!(owner.try_view().is_err());
        assert_eq!(owner.committed_height(), 2);
        prepared.publish();
        let view = owner.view();
        assert_eq!(
            view.get(0).map(std::ptr::from_ref),
            pointer,
            "publication must move, not copy, the original chain"
        );
        assert_eq!(
            &view.iter().copied().collect::<Vec<_>>(),
            &direct.view().iter().copied().collect::<Vec<_>>()
        );
        assert_eq!(owner.committed_height(), direct.committed_height());
        drop(view);
        assert!(
            !old.matches_current(&owner),
            "even untouched hash publication rotates identity"
        );
    }
}

#[test]
fn abort_and_drop_leave_the_exact_original_cut_available() {
    let owner = BlockHashes::new(vec![hash(1), hash(2)]);
    let journal = detached(&owner, true, &[3]);
    let visible = journal.get(0).map(std::ptr::from_ref);
    let pending = journal.pending().get(0).map(std::ptr::from_ref);
    let journal = prepare(journal, &owner).abort().0;
    assert_eq!(journal.get(0).map(std::ptr::from_ref), visible);
    assert_eq!(journal.pending().get(0).map(std::ptr::from_ref), pending);
    assert_eq!(journal.prefix(), &[hash(1)]);
    assert!(journal.matches_current(&owner));
    drop(prepare(journal, &owner));
    assert_eq!(
        &owner.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1), hash(2)]
    );
    assert_eq!(owner.committed_height(), 2);
    prepare(detached(&owner, true, &[4]), &owner).publish();
    assert_eq!(
        &owner.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1), hash(4)]
    );
}

#[test]
fn readers_writers_and_installation_refusal_preserve_retry_custody() {
    let owner = BlockHashes::new(vec![hash(1)]);
    let journal = detached(&owner, false, &[2]);
    let pointer = journal.get(0).map(std::ptr::from_ref);
    let writer = prepare(detached(&owner, false, &[]), &owner);
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&owner, |_, _| -> Result<(), &str> {
            panic!("busy writer is observed before admission")
        })
        .err()
        .expect("busy writer");
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    drop(writer);
    let reader = owner.view();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&owner, |_, target| {
            assert!(
                target.writer_available(),
                "installation precedes write ownership"
            );
            Err::<(), _>("capacity")
        })
        .err()
        .expect("installation refusal");
    assert!(matches!(
        error,
        PublicationPreparationError::Admission("capacity")
    ));
    assert_eq!(journal.get(0).map(std::ptr::from_ref), pointer);
    assert_eq!(
        &owner.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1)]
    );
    prepare(journal, &owner).publish();
    assert_eq!(reader.iter().copied().collect::<Vec<_>>(), [hash(1)]);
    assert_eq!(
        &owner.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1), hash(2)]
    );
}

#[test]
fn retained_readers_and_private_blocks_never_veto_publication() {
    let owner = BlockHashes::new(vec![hash(1)]);
    let reader = owner.view();
    let mut private = owner.block();
    private.push(hash(3));
    let journal = detached(&owner, false, &[2]);
    prepare(journal, &owner).publish();
    assert!(reader.iter().copied().eq([hash(1)]));
    assert!(private.iter().copied().eq([hash(1), hash(3)]));
    assert!(!private.detach().matches_current(&owner));
    assert!(owner.view().iter().copied().eq([hash(1), hash(2)]));
}

#[test]
fn hash_prepared_writer_release_before_wait_registration_is_not_lost() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Waker},
    };
    for finish in 0..3 {
        let owner = BlockHashes::new(vec![hash(1)]);
        let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
        let first = detached(&owner, false, &[2]);
        let second = detached(&owner, false, &[3]);
        let prepared = prepare(first, &owner);
        let (second, error, _cleanup) = second
            .try_prepare_publication(&owner, |_, _| Ok::<_, ()>(()))
            .err()
            .expect("writer excludes observation");
        let PublicationPreparationError::Busy(wait) = error else {
            panic!("writer wait");
        };
        match finish {
            0 => drop(prepared),
            1 => {
                prepared.abort();
            }
            _ => {
                prepared.publish();
            }
        }
        let mut wait = wait.wait_for_release(&mut release_slot_0);
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        let retry = second.try_prepare_publication(&owner, |_, _| Ok::<_, ()>(()));
        if finish == 2 {
            assert!(matches!(
                retry.err().unwrap().1,
                PublicationPreparationError::Changed
            ));
        } else {
            assert!(retry.is_ok());
        }
    }
}

#[test]
fn caught_reader_panic_does_not_poison_publication() {
    let owner = BlockHashes::new(vec![hash(1)]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _reader = owner.view();
            panic!("read-only request failed");
        }))
        .is_err()
    );
    let reader = owner.view();
    prepare(detached(&owner, false, &[2]), &owner).publish();
    assert!(reader.iter().copied().eq([hash(1)]));
    assert!(owner.view().iter().copied().eq([hash(1), hash(2)]));
}

#[test]
fn equal_bytes_in_another_owner_or_after_aba_never_authorize_publication() {
    let owner = BlockHashes::new(vec![hash(1)]);
    let foreign = BlockHashes::new(vec![hash(1)]);
    let journal = detached(&owner, false, &[2]);
    let pointer = journal.get(0).map(std::ptr::from_ref);
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&foreign, |_, _| -> Result<(), &str> {
            panic!("reject foreign owner before admission")
        })
        .err()
        .expect("foreign owner");
    assert!(matches!(error, PublicationPreparationError::Changed));
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&owner, |_, target| {
            for value in [3, 1] {
                let mut block = target.block_and_revert();
                block.push(hash(value));
                block.commit();
            }
            Ok::<_, &str>(())
        })
        .err()
        .expect("changed during admission");
    assert!(matches!(error, PublicationPreparationError::Changed));
    assert_eq!(journal.get(0).map(std::ptr::from_ref), pointer);
    assert_eq!(
        &owner.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1)]
    );
    assert_eq!(owner.committed_height(), 1);
    assert!(owner.writer_available());
}

struct Installation<'a> {
    owner: &'a BlockHashes,
    releases: &'a std::cell::Cell<usize>,
}

impl Drop for Installation<'_> {
    fn drop(&mut self) {
        assert!(
            self.owner.writer_available(),
            "writer releases before installation admission"
        );
        self.releases.set(self.releases.get() + 1);
    }
}

#[test]
fn installation_is_retained_until_after_drop_abort_or_aggregate_publication() {
    let owner = BlockHashes::new(vec![hash(1)]);
    let releases = std::cell::Cell::new(0);
    let admit = |_: &DetachedBlockHashes, _: &BlockHashes| {
        Ok::<_, &str>(Installation {
            owner: &owner,
            releases: &releases,
        })
    };
    let prepare = |journal: DetachedBlockHashes| {
        journal
            .try_prepare_publication(&owner, admit)
            .unwrap_or_else(|_| panic!("prepare"))
    };
    drop(prepare(detached(&owner, false, &[2])));
    assert_eq!(releases.get(), 1);
    let journal = prepare(detached(&owner, false, &[2])).abort().0;
    assert_eq!(releases.get(), 2);
    assert_eq!(
        &owner.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1)]
    );
    let admission = prepare(journal).publish();
    assert_eq!(releases.get(), 2);
    assert_eq!(
        &owner.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1), hash(2)]
    );
    drop(admission);
    assert_eq!(releases.get(), 3);
}

#[test]
fn late_hash_refusal_releases_prepared_membership_before_exact_retry() {
    use crate::state::storage_transactions::{TransactionsReadOnly, TransactionsStorage};
    let hashes = BlockHashes::new(vec![hash(1)]);
    let membership = TransactionsStorage::new();
    let entrypoint = HashOf::from_untyped_unchecked(Hash::new(b"publication membership"));
    let mut block = membership.block();
    block.insert_block(
        std::collections::BTreeSet::from([entrypoint]),
        NonZeroUsize::new(1).unwrap(),
    );
    let journal = block.prepare_commit().unwrap().detach();
    let admitted = journal
        .try_prepare_publication(&membership, |_, _| Ok::<_, &str>(()))
        .unwrap_or_else(|_| panic!("membership prepare"));
    let hash_journal = detached(&hashes, false, &[2]);
    let blocker = prepare(detached(&hashes, false, &[]), &hashes);
    let (hash_journal, error, _cleanup) = hash_journal
        .try_prepare_publication(&hashes, |_, _| Ok::<_, &str>(()))
        .err()
        .expect("late busy hash component");
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    let journal = admitted.abort().0;
    assert_eq!(membership.view().get(&entrypoint), None);
    assert_eq!(hashes.committed_height(), 1);
    drop(blocker);
    let admitted = journal
        .try_prepare_publication(&membership, |_, _| Ok::<_, &str>(()))
        .unwrap_or_else(|_| panic!("membership retry"));
    let hash_admitted = prepare(hash_journal, &hashes);
    admitted.publish();
    hash_admitted.publish();
    assert_eq!(membership.view().get(&entrypoint), NonZeroUsize::new(1));
    assert_eq!(
        &hashes.view().iter().copied().collect::<Vec<_>>(),
        &[hash(1), hash(2)]
    );
}

#[test]
fn changed_after_admission_signals_the_writer_released_during_refusal() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Waker},
    };
    let owner = BlockHashes::new(vec![hash(1)]);
    let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
    let journal = detached(&owner, false, &[2]);
    let mut observation = None;
    let (_, error, _cleanup) = journal
        .try_prepare_publication(&owner, |_, target| {
            target.block().commit();
            observation = Some(target.released.observe());
            Ok::<_, ()>(())
        })
        .err()
        .expect("changed base");
    assert!(matches!(error, PublicationPreparationError::Changed));
    let mut wait = observation.unwrap().wait_for_release(&mut release_slot_0);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(_cleanup);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert!(owner.writer_available());
}

#[test]
fn advisory_predecessor_observation_notifies_only_successful_acquisition() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Waker},
    };
    let owner = BlockHashes::new(vec![hash(1)]);
    let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
    let mut release_slot_1 = crate::unit_test_support::release_registration(&owner.budget);
    let mut release_slot_2 = crate::unit_test_support::release_registration(&owner.budget);
    let journal = detached(&owner, false, &[2]);
    let mut released = owner
        .map()
        .unwrap()
        .observe_reader_release()
        .wait_for_release(&mut release_slot_0);
    let mut writer_released = owner
        .released
        .observe()
        .wait_for_release(&mut release_slot_1);
    assert!(journal.matches_current(&owner));
    assert!(
        Pin::new(&mut released)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert!(
        Pin::new(&mut writer_released)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let prepared = prepare(detached(&owner, false, &[]), &owner);
    let mut blocked = owner
        .map()
        .unwrap()
        .observe_reader_release()
        .wait_for_release(&mut release_slot_2);
    assert!(!journal.matches_current(&owner));
    assert!(
        Pin::new(&mut blocked)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(prepared);
    assert!(
        Pin::new(&mut blocked)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
}

#[test]
fn hash_reader_refusal_waits_on_the_original_reader_mutex() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Waker},
    };
    let owner = BlockHashes::new(vec![hash(1)]);
    let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
    let journal = detached(&owner, false, &[2]);
    let held = prepare(detached(&owner, false, &[]), &owner);
    let expected = owner.map().unwrap().observe_reader_release();
    let writer_release = owner.released.observe();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&owner, |_, _| -> Result<(), ()> {
            panic!("reader contention precedes admission");
        })
        .err()
        .expect("active reader mutex is held");
    let PublicationPreparationError::Busy(wait) = error else {
        panic!("original blocker required");
    };
    assert_eq!(wait, expected);
    assert_ne!(wait, writer_release);
    let mut wait = wait.wait_for_release(&mut release_slot_0);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let (first, retirement) = held.abort();
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(retirement);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    drop(first);
    prepare(journal, &owner).publish();
    assert!(owner.view().iter().copied().eq([hash(1), hash(2)]));
}

#[test]
fn stale_hash_refusal_retains_release_and_installation_until_outer_unlock() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };
    struct Probe {
        hashes: Arc<BlockHashes>,
        outer: Arc<crate::publication_lock::PublicationMutex>,
        wakes: AtomicUsize,
        refunds: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            assert!(
                self.outer.try_lock_or_wait().is_ok(),
                "outer fence remains held"
            );
            assert!(
                self.hashes.writer_available(),
                "original hash writer remains held"
            );
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Installation(Arc<Probe>);
    impl Drop for Installation {
        fn drop(&mut self) {
            assert!(self.0.outer.try_lock_or_wait().is_ok());
            assert!(self.0.hashes.writer_available());
            self.0.refunds.fetch_add(1, Ordering::SeqCst);
        }
    }
    for unwind in [false, true] {
        let owner = Arc::new(BlockHashes::new(vec![hash(1)]));
        let mut registration = crate::unit_test_support::release_registration(&owner.budget);
        let outer = Arc::new(crate::publication_lock::PublicationMutex::default());
        let guard = outer.lock();
        let probe = Arc::new(Probe {
            hashes: Arc::clone(&owner),
            outer: Arc::clone(&outer),
            wakes: AtomicUsize::new(0),
            refunds: AtomicUsize::new(0),
        });
        let journal = detached(&owner, false, &[2]);
        let pointer = journal.get(0).map(std::ptr::from_ref);
        let mut wait = None;
        let (journal, error, cleanup) = journal
            .try_prepare_publication(&owner, |_, target| {
                target.block().commit();
                let observation = target.released.observe();
                let waker = Waker::from(Arc::clone(&probe));
                assert!(
                    registration
                        .poll_wait(&observation, &mut Context::from_waker(&waker))
                        .is_pending()
                );
                wait = Some(observation);
                Ok::<_, ()>(Installation(Arc::clone(&probe)))
            })
            .err()
            .expect("actual stale predecessor");
        assert_eq!(error, PublicationPreparationError::Changed);
        assert_eq!(journal.get(0).map(std::ptr::from_ref), pointer);
        assert!(owner.writer_available());
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(probe.refunds.load(Ordering::SeqCst), 0);
        if unwind {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _cleanup = cleanup;
                    let _outer = guard;
                    panic!("abandon retained hash refusal");
                }))
                .is_err()
            );
        } else {
            drop(guard);
            drop(cleanup);
        }
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(probe.refunds.load(Ordering::SeqCst), 1);
        assert!(
            registration
                .poll_wait(&wait.unwrap(), &mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }
}

#[path = "retained_hash_slot_tests.rs"]
mod retained_hash_slot_tests;
