//! Publication identity contention must not block detached preparation.

use super::*;

#[test]
fn cell_identity_contention_retains_original_journal_without_admission() {
    let target = crate::cell::Cell::new(String::from("before"));
    let mut block = target.block();
    *block = String::from("after");
    let journal = block
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("detach original journal"));
    let original = journal.touched_value().unwrap().after.as_ptr();
    let identity = target.publication.lock_version();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&target, |_, _| -> Result<(), ()> {
            panic!("busy identity observation must precede admission")
        })
        .err()
        .expect("identity lock is busy");
    drop(_cleanup);
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    assert_eq!(journal.touched_value().unwrap().after.as_ptr(), original);
    drop(identity);
    journal
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("retry same cell journal"))
        .publish();
    assert_eq!(&**target.view(), "after");
}

#[test]
fn storage_identity_contention_retains_original_journal_without_admission() {
    let target: crate::storage::Storage<u64, String> =
        [(1, String::from("before"))].into_iter().collect();
    let mut block = target.block();
    block.insert(1, String::from("after"));
    let journal = block
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("detach original journal"));
    let original = journal
        .touched_entries()
        .next()
        .unwrap()
        .after
        .unwrap()
        .as_ptr();
    let identity = target.publication.lock_version();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&target, |_, _| -> Result<(), ()> {
            panic!("busy identity observation must precede admission")
        })
        .err()
        .expect("identity lock is busy");
    drop(_cleanup);
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    assert_eq!(
        journal
            .touched_entries()
            .next()
            .unwrap()
            .after
            .unwrap()
            .as_ptr(),
        original
    );
    drop(identity);
    journal
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("retry same storage journal"))
        .publish();
    assert_eq!(target.view().get(&1).map(String::as_str), Some("after"));
}

struct CellIdentityAdmission<'a> {
    target: &'a crate::cell::Cell<String>,
    _identity: crate::ReleaseGuard<'a, std::sync::MutexGuard<'a, Identity<Version>>>,
}
impl Drop for CellIdentityAdmission<'_> {
    fn drop(&mut self) {
        assert!(
            self.target.revert.try_write().is_some(),
            "undo writer precedes admission release"
        );
        assert!(
            self.target.blocks.try_write().is_some(),
            "current writer precedes admission release"
        );
    }
}

#[test]
fn cell_identity_contention_after_admission_releases_both_writers_before_guard() {
    let target = crate::cell::Cell::new(String::from("before"));
    let mut block = target.block();
    *block = String::from("after");
    let journal = block
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("detach original journal"));
    let original = journal.touched_value().unwrap().after.as_ptr();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&target, |_, _| {
            Ok::<_, ()>(CellIdentityAdmission {
                target: &target,
                _identity: target.publication.lock_version(),
            })
        })
        .err()
        .expect("identity changed to busy after admission");
    drop(_cleanup);
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    assert_eq!(journal.touched_value().unwrap().after.as_ptr(), original);
    assert_eq!(&**target.view(), "before");
    assert!(journal.matches_current(&target));
    journal
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("retry after identity contention"))
        .publish();
}

struct StorageIdentityAdmission<'a> {
    target: &'a crate::storage::Storage<u64, String>,
    _identity: crate::ReleaseGuard<'a, std::sync::MutexGuard<'a, Identity<Version>>>,
}
impl Drop for StorageIdentityAdmission<'_> {
    fn drop(&mut self) {
        assert!(self.target.revert.try_write().is_some());
        assert!(self.target.blocks.try_write().is_some());
        assert!(self.target.revert.try_read().is_ok());
        assert!(self.target.blocks.try_read().is_ok());
    }
}

#[test]
fn storage_identity_contention_after_admission_releases_both_writers_before_guard() {
    let target: crate::storage::Storage<u64, String> =
        [(1, String::from("before"))].into_iter().collect();
    let mut block = target.block();
    block.insert(1, String::from("after"));
    let journal = block
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("detach original journal"));
    let original = journal
        .touched_entries()
        .next()
        .unwrap()
        .after
        .unwrap()
        .as_ptr();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&target, |_, _| {
            Ok::<_, ()>(StorageIdentityAdmission {
                target: &target,
                _identity: target.publication.lock_version(),
            })
        })
        .err()
        .expect("identity changed to busy after admission");
    drop(_cleanup);
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    assert_eq!(
        journal
            .touched_entries()
            .next()
            .unwrap()
            .after
            .unwrap()
            .as_ptr(),
        original
    );
    assert_eq!(target.view().get(&1).map(String::as_str), Some("before"));
    assert!(journal.matches_current(&target));
    journal
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("retry after identity contention"))
        .publish();
}

#[test]
fn poisoned_publication_is_a_local_failure_instead_of_endless_busy_retry() {
    let target = crate::cell::Cell::new(String::from("before"));
    let mut block = target.block();
    *block = String::from("after");
    let journal = block
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("detach original journal"));
    let original = journal.touched_value().unwrap().after.as_ptr();
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _identity = target.publication.lock_version();
        panic!("simulate failed joint publication");
    }));
    assert!(poisoned.is_err());
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&target, |_, _| -> Result<(), ()> {
            panic!("poisoned publication must not acquire installation resources")
        })
        .err()
        .expect("poisoned identity");
    drop(_cleanup);
    assert_eq!(error, PublicationPreparationError::Poisoned);
    assert_eq!(journal.touched_value().unwrap().after.as_ptr(), original);
    assert_eq!(&**target.view(), "before");
}

#[test]
fn busy_identity_wait_is_signaled_after_the_actual_metadata_guard_releases() {
    let release_budget = iroha_allocation::AllocationBudget::new(
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut release_registration_1 = crate::release_test_support::registration(&release_budget);

    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Waker},
    };
    let target = crate::cell::Cell::new(10_u64);
    let journal = target.block().try_detach(|_| Ok::<_, ()>(())).unwrap();
    let identity = target.publication.lock_version();
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("metadata busy");
    drop(_cleanup);
    let PublicationPreparationError::Busy(wait) = error else {
        panic!("metadata wait");
    };
    let mut wait = wait.wait_for_release(&mut release_registration_1);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    drop(identity);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
    assert!(
        journal
            .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
            .is_ok()
    );
}

#[test]
fn funded_identity_refund_observes_unlocked_publication_even_on_release_unwind() {
    use iroha_allocation::{AllocationBudget, AllocationRefusal};
    use std::{
        future::Future,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering::SeqCst},
        },
        task::{Context, Wake, Waker},
    };
    struct Probe {
        owner: Arc<super::Publication>,
        wakes: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            assert!(
                !matches!(
                    self.owner.version.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ),
                "identity refund ran under the publication lock"
            );
            self.wakes.fetch_add(1, SeqCst);
        }
    }
    for unwind in [false, true] {
        let initial = super::Publication::allocation_demand().unwrap().bytes();
        let successor = super::NextPublication::allocation_demand().unwrap().bytes();
        let registration_bytes =
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
        let budget = AllocationBudget::new(initial + successor + registration_bytes);
        let mut registration = crate::release_test_support::registration(&budget);
        let owner = Arc::new(
            super::Publication::try_from_original(&mut budget.try_reserve_bytes(initial).unwrap())
                .unwrap(),
        );
        let next = super::NextPublication::try_from_charge(
            budget
                .try_reserve_bytes(successor)
                .unwrap()
                .try_split(super::NextPublication::allocation_layout())
                .unwrap(),
        )
        .unwrap();
        let probe = Arc::new(Probe {
            owner: Arc::clone(&owner),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
        else {
            panic!("original identity pool must be full");
        };
        let mut wait = release.wait_for_release(&mut registration);
        assert!(
            std::pin::Pin::new(&mut wait)
                .poll(&mut context)
                .is_pending()
        );
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            owner.publish_retaining(
                next,
                || (),
                |()| {
                    assert_eq!(probe.wakes.load(SeqCst), 0);
                    assert!(!unwind, "release interruption");
                },
            )
        }));
        assert_eq!(outcome.is_err(), unwind);
        assert_eq!(probe.wakes.load(SeqCst), 1);
        assert!(std::pin::Pin::new(&mut wait).poll(&mut context).is_ready());
        assert_eq!(budget.reserved_bytes(), initial + registration_bytes);
        drop(wait);
        drop((waker, probe, owner));
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn cell_refusal_retains_original_notifications_and_admission_through_enclosing_fence() {
    let release_budget = iroha_allocation::AllocationBudget::new(
        3 * iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut release_registration_1 = crate::release_test_support::registration(&release_budget);
    let mut release_registration_2 = crate::release_test_support::registration(&release_budget);
    let mut release_registration_3 = crate::release_test_support::registration(&release_budget);

    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    struct Reenter {
        target: Arc<crate::cell::Cell<u64>>,
        fence: Arc<Mutex<()>>,
        wakes: AtomicUsize,
    }
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            assert!(
                self.fence.try_lock().is_ok(),
                "enclosing fence precedes callbacks"
            );
            assert!(
                self.target.blocks.try_write().is_some(),
                "current writer released"
            );
            assert!(
                self.target.revert.try_write().is_some(),
                "undo writer released"
            );
            assert!(
                self.target.publication.version.try_lock().is_ok(),
                "identity released"
            );
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Installation {
        fence: Arc<Mutex<()>>,
        refunds: Arc<AtomicUsize>,
    }
    impl Drop for Installation {
        fn drop(&mut self) {
            assert!(
                self.fence.try_lock().is_ok(),
                "enclosing fence precedes admission refund"
            );
            self.refunds.fetch_add(1, Ordering::SeqCst);
        }
    }
    // Refusal before admission, after the first writer, and after both physical
    // writers/readers but a changed publication identity. Every cut returns the
    // original journal, with no callback or admission refund before outer release.
    for cut in 0..3 {
        let target = Arc::new(crate::cell::Cell::new(10));
        let mut block = target.block();
        *block = 20;
        let journal = block
            .try_detach(|_| Ok::<_, ()>(()))
            .unwrap_or_else(|_| panic!("detach"));
        let fence = Arc::new(Mutex::new(()));
        let held = fence.lock().unwrap();
        let busy = (cut == 1).then(|| target.blocks.write());
        let callbacks = Arc::new(Reenter {
            target: Arc::clone(&target),
            fence: Arc::clone(&fence),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&callbacks));
        let mut cx = Context::from_waker(&waker);
        let mut waits = [
            (
                target.publication.released.observe(),
                &mut release_registration_1,
            ),
            (
                target.blocks_released.observe(),
                &mut release_registration_2,
            ),
            (
                target.revert_released.observe(),
                &mut release_registration_3,
            ),
        ]
        .map(|(wait, registration)| wait.wait_for_release(registration));
        for wait in &mut waits {
            assert!(Pin::new(wait).poll(&mut cx).is_pending());
        }
        let refunds = Arc::new(AtomicUsize::new(0));
        let (journal, error, cleanup) = journal
            .try_prepare_publication(&target, |_, _| {
                if cut == 0 {
                    return Err("capacity");
                }
                if cut == 2 {
                    // Race only the identity after its first successful observation.
                    // This raw fixture lock emits no unrelated production notification.
                    *target.publication.version.lock().unwrap() = NextPublication::new().0;
                }
                Ok(Installation {
                    fence: Arc::clone(&fence),
                    refunds: Arc::clone(&refunds),
                })
            })
            .err()
            .expect("requested acquisition cut");
        match cut {
            0 => assert!(matches!(
                error,
                PublicationPreparationError::Admission("capacity")
            )),
            1 => assert!(matches!(error, PublicationPreparationError::Busy(_))),
            2 => assert_eq!(error, PublicationPreparationError::Changed),
            _ => unreachable!(),
        }
        assert_eq!(callbacks.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(refunds.load(Ordering::SeqCst), 0);
        for wait in &mut waits {
            assert!(Pin::new(wait).poll(&mut cx).is_pending());
        }
        assert_eq!(*journal.touched_value().unwrap().after, 20);
        assert_eq!(*target.view(), 10);
        drop(busy);
        drop(held);
        drop(cleanup);
        assert_eq!(callbacks.wakes.load(Ordering::SeqCst), [1, 2, 3][cut]);
        assert_eq!(refunds.load(Ordering::SeqCst), usize::from(cut != 0));
        assert!(Pin::new(&mut waits[0]).poll(&mut cx).is_ready());
        assert_eq!(
            Pin::new(&mut waits[1]).poll(&mut cx).is_ready(),
            cut == 2,
            "never signal a writer this attempt did not acquire"
        );
        assert_eq!(Pin::new(&mut waits[2]).poll(&mut cx).is_ready(), cut != 0);
    }
}

#[test]
fn storage_refusal_retains_original_notifications_and_admission_through_enclosing_fence() {
    let release_budget = iroha_allocation::AllocationBudget::new(
        5 * iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut release_registration_1 = crate::release_test_support::registration(&release_budget);
    let mut release_registration_2 = crate::release_test_support::registration(&release_budget);
    let mut release_registration_3 = crate::release_test_support::registration(&release_budget);
    let mut release_registration_4 = crate::release_test_support::registration(&release_budget);
    let mut release_registration_5 = crate::release_test_support::registration(&release_budget);

    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    struct Reenter {
        target: Arc<crate::storage::Storage<u64, u64>>,
        fence: Arc<Mutex<()>>,
        wakes: AtomicUsize,
    }
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            assert!(
                self.fence.try_lock().is_ok(),
                "enclosing fence precedes callbacks"
            );
            assert!(
                self.target.blocks.try_write().is_some(),
                "current writer released"
            );
            assert!(
                self.target.revert.try_write().is_some(),
                "undo writer released"
            );
            assert!(
                self.target.publication.version.try_lock().is_ok(),
                "identity released"
            );
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Installation {
        fence: Arc<Mutex<()>>,
        refunds: Arc<AtomicUsize>,
    }
    impl Drop for Installation {
        fn drop(&mut self) {
            assert!(
                self.fence.try_lock().is_ok(),
                "enclosing fence precedes admission refund"
            );
            self.refunds.fetch_add(1, Ordering::SeqCst);
        }
    }
    // Refusal before admission, after the first writer, and after both physical
    // writers/readers but a changed publication identity. Every cut returns the
    // original journal, with no callback or admission refund before outer release.
    for cut in 0..3 {
        let target = Arc::new(
            [(1, 10)]
                .into_iter()
                .collect::<crate::storage::Storage<_, _>>(),
        );
        let mut block = target.block();
        block.insert(1, 20);
        let journal = block
            .try_detach(|_| Ok::<_, ()>(()))
            .unwrap_or_else(|_| panic!("detach"));
        let before = target.view();
        let fence = Arc::new(Mutex::new(()));
        let held = fence.lock().unwrap();
        let busy = (cut == 1).then(|| target.blocks.write());
        let callbacks = Arc::new(Reenter {
            target: Arc::clone(&target),
            fence: Arc::clone(&fence),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&callbacks));
        let mut cx = Context::from_waker(&waker);
        let mut waits = [
            (
                target.publication.released.observe(),
                &mut release_registration_1,
            ),
            (
                target.blocks_released.observe(),
                &mut release_registration_2,
            ),
            (
                target.revert_released.observe(),
                &mut release_registration_3,
            ),
            (
                target.blocks.observe_reader_release(),
                &mut release_registration_4,
            ),
            (
                target.revert.observe_reader_release(),
                &mut release_registration_5,
            ),
        ]
        .map(|(wait, registration)| wait.wait_for_release(registration));
        for wait in &mut waits {
            assert!(Pin::new(wait).poll(&mut cx).is_pending());
        }
        let refunds = Arc::new(AtomicUsize::new(0));
        let (journal, error, cleanup) = journal
            .try_prepare_publication(&target, |_, _| {
                if cut == 0 {
                    return Err("capacity");
                }
                if cut == 2 {
                    // Race only the identity after its first successful observation.
                    // This raw fixture lock emits no unrelated production notification.
                    *target.publication.version.lock().unwrap() = NextPublication::new().0;
                }
                Ok(Installation {
                    fence: Arc::clone(&fence),
                    refunds: Arc::clone(&refunds),
                })
            })
            .err()
            .expect("requested acquisition cut");
        match cut {
            0 => assert!(matches!(
                error,
                PublicationPreparationError::Admission("capacity")
            )),
            1 => assert!(matches!(error, PublicationPreparationError::Busy(_))),
            2 => assert_eq!(error, PublicationPreparationError::Changed),
            _ => unreachable!(),
        }
        assert_eq!(callbacks.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(refunds.load(Ordering::SeqCst), 0);
        for wait in &mut waits {
            assert!(Pin::new(wait).poll(&mut cx).is_pending());
        }
        assert_eq!(journal.touched_entries().next().unwrap().after, Some(&20));
        assert_eq!(before.get(&1), Some(&10));
        drop(busy);
        drop(held);
        drop(cleanup);
        assert_eq!(callbacks.wakes.load(Ordering::SeqCst), [1, 2, 5][cut]);
        assert_eq!(refunds.load(Ordering::SeqCst), usize::from(cut != 0));
        assert!(Pin::new(&mut waits[0]).poll(&mut cx).is_ready());
        assert_eq!(
            Pin::new(&mut waits[1]).poll(&mut cx).is_ready(),
            cut == 2,
            "never signal a writer this attempt did not acquire"
        );
        assert_eq!(Pin::new(&mut waits[2]).poll(&mut cx).is_ready(), cut != 0);
        drop(waits);
        assert_eq!(target.view().get(&1), Some(&10));
    }
}
