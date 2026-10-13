//! Complete trigger publication and exact retry after late component refusal.

use super::super::publication::SetPublicationError;
use super::*;
use mv::PublicationPreparationError;

fn contract_touch_pointer<Admission>(
    journal: &DetachedSet<Admission>,
) -> *const HashOf<IvmBytecode> {
    std::ptr::from_ref(
        journal
            .contracts()
            .touched_entries()
            .next()
            .expect("actual contract touch")
            .key,
    )
}

fn prepare_trigger_publication<Admission>(
    journal: DetachedSet<Admission>,
    target: &Set,
) -> super::super::publication::PreparedSet<'_, Admission, ()> {
    journal
        .try_prepare_publication(target, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("trigger publication: {error:?}"))
}

#[test]
fn complete_trigger_publication_matches_all_ten_direct_current_and_undo_images() {
    let set = seeded_set();
    let direct = seeded_set();
    let before = images(&set);
    let mut original = set.block();
    let mut reference = direct.block();
    mutate_all(&mut original);
    mutate_all(&mut reference);
    reference.commit();
    let journal = capture(original);
    let pointer = contract_touch_pointer(&journal);
    let prepared = prepare_trigger_publication(journal, &set);
    let journal = prepared.abort().0;
    assert_eq!(
        images(&set),
        before,
        "preparation and abort publish no component"
    );
    assert_eq!(contract_touch_pointer(&journal), pointer);
    assert!(journal.matches_current(&set));
    assert_all_writers_released(&set);
    prepare_trigger_publication(journal, &set).publish();
    assert_eq!(images(&set), images(&direct));
    assert_all_writers_released(&set);
}

#[test]
fn complete_trigger_replacement_restores_untouched_discarded_tip_owners() {
    for touched in [false, true] {
        let set = seeded_set();
        let direct = seeded_set();
        for target in [&set, &direct] {
            let mut block = target.block();
            mutate_all(&mut block);
            block.commit();
        }
        let mut candidate = set.block_and_revert();
        let mut reference = direct.block_and_revert();
        if touched {
            for block in [&mut candidate, &mut reference] {
                let mut tx = block.transaction();
                assert!(tx.remove(&id("call_a")));
                register_call(&mut tx, "replacement");
                tx.apply();
            }
        }
        reference.commit();
        prepare_trigger_publication(capture(candidate), &set).publish();
        assert_eq!(images(&set), images(&direct));
        set.block_and_revert().commit();
        direct.block_and_revert().commit();
        assert_eq!(
            images(&set),
            images(&direct),
            "replacement preserves real undo for later rollback"
        );
    }
}

#[test]
fn busy_at_each_trigger_component_returns_all_original_journals_and_releases_earlier_writers() {
    let set = seeded_set();
    let before = images(&set);
    let mut block = set.block();
    mutate_all(&mut block);
    let mut journal = capture(block);
    let pointer = contract_touch_pointer(&journal);
    macro_rules! busy {
        ($field:ident) => {{
            let busy = set.$field.block();
            let (returned, error, cleanup) = journal
                .try_prepare_publication(&set, |_, _| Ok::<_, ()>(()))
                .err()
                .expect("busy component");
            drop(cleanup);
            assert!(
                matches!(
                    error,
                    SetPublicationError::Component {
                        field: stringify!($field),
                        cause: PublicationPreparationError::Busy(_),
                    }
                ),
                "{error:?}"
            );
            drop(busy);
            returned
        }};
    }
    for component in 0..10 {
        journal = match component {
            0 => busy!(data_triggers),
            1 => busy!(pipeline_triggers),
            2 => busy!(time_triggers),
            3 => busy!(by_call_triggers),
            4 => busy!(ids),
            5 => busy!(active_data_trigger_ids),
            6 => busy!(active_pipeline_trigger_ids),
            7 => busy!(active_time_trigger_ids),
            8 => busy!(active_by_call_trigger_ids),
            _ => busy!(contracts),
        };
        assert_eq!(contract_touch_pointer(&journal), pointer);
        assert_eq!(images(&set), before);
        assert!(journal.matches_current(&set));
        assert_all_writers_released(&set);
    }
    prepare_trigger_publication(journal, &set).publish();
    assert_ne!(images(&set), before);
}

#[test]
fn trigger_installation_refusal_and_late_identity_change_keep_every_original_delta() {
    let set = seeded_set();
    let mut block = set.block();
    mutate_all(&mut block);
    let journal = capture(block);
    let pointer = contract_touch_pointer(&journal);
    let (journal, error, cleanup) = journal
        .try_prepare_publication(&set, |_, _| {
            assert_all_writers_released(&set);
            Err::<(), _>("capacity")
        })
        .err()
        .expect("resource refusal");
    drop(cleanup);
    assert!(matches!(error, SetPublicationError::Admission("capacity")));
    let installation_released = Arc::new(AtomicBool::new(false));
    let (journal, error, cleanup) = journal
        .try_prepare_publication(&set, |_, target| {
            target.contracts.block().commit();
            Ok::<_, ()>(TriggerInstallation {
                set: Arc::clone(&set),
                released: Arc::clone(&installation_released),
            })
        })
        .err()
        .expect("late changed component");
    drop(cleanup);
    assert!(matches!(
        error,
        SetPublicationError::Component {
            field: "contracts",
            cause: PublicationPreparationError::Changed,
        }
    ));
    assert_eq!(contract_touch_pointer(&journal), pointer);
    assert_all_writers_released(&set);
    assert!(installation_released.load(Ordering::SeqCst));
    assert!(!journal.matches_current(&set));
    assert!(journal.data_triggers().matches_current(&set.data_triggers));
}

struct TriggerInstallation {
    set: Arc<Set>,
    released: Arc<AtomicBool>,
}
impl Drop for TriggerInstallation {
    fn drop(&mut self) {
        assert_all_writers_released(&self.set);
        self.released.store(true, Ordering::SeqCst);
    }
}

#[test]
fn trigger_resource_guards_outlive_all_writers_on_drop_abort_and_publication() {
    for action in 0..3 {
        let set = seeded_set();
        let before = images(&set);
        let capture_released = Arc::new(AtomicBool::new(false));
        let installation_released = Arc::new(AtomicBool::new(false));
        let mut original = set.block();
        mutate_all(&mut original);
        let journal = original
            .try_detach(|_| Ok::<_, ()>(Reservation(Arc::clone(&capture_released))))
            .unwrap();
        let prepared = journal
            .try_prepare_publication(&set, |_, _| {
                Ok::<_, ()>(TriggerInstallation {
                    set: Arc::clone(&set),
                    released: Arc::clone(&installation_released),
                })
            })
            .unwrap_or_else(|_| panic!("prepare complete trigger publication"));
        match action {
            0 => drop(prepared),
            1 => {
                let journal = prepared.abort().0;
                assert!(!capture_released.load(Ordering::SeqCst));
                assert!(installation_released.load(Ordering::SeqCst));
                assert!(journal.matches_current(&set));
                drop(journal);
            }
            _ => {
                let guards = prepared.publish();
                assert!(!capture_released.load(Ordering::SeqCst));
                assert!(!installation_released.load(Ordering::SeqCst));
                assert_ne!(images(&set), before);
                drop(guards);
            }
        }
        assert!(capture_released.load(Ordering::SeqCst));
        assert!(installation_released.load(Ordering::SeqCst));
        if action != 2 {
            assert_eq!(images(&set), before);
        }
        assert_all_writers_released(&set);
    }
}

#[test]
fn trigger_abandonment_releases_every_component_before_callbacks_and_capacity() {
    use std::{
        future::Future,
        pin::Pin,
        sync::Mutex,
        task::{Context, Wake, Waker},
    };

    struct Capacity(Arc<AtomicUsize>, usize);
    impl Drop for Capacity {
        fn drop(&mut self) {
            self.0.fetch_or(self.1, Ordering::SeqCst);
        }
    }
    struct Reenter {
        target: Arc<Set>,
        journals: Mutex<Option<DetachedSet<()>>>,
        released: Arc<AtomicUsize>,
        checks: AtomicUsize,
        failures: AtomicUsize,
        wakes: AtomicUsize,
        unwind: bool,
    }
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            if self.released.load(Ordering::SeqCst) != 0 {
                self.failures.fetch_add(1, Ordering::SeqCst);
            }
            let journals = self
                .journals
                .lock()
                .unwrap()
                .take()
                .expect("one original wake");
            // Probe each original component independently: a poisoned earlier
            // component must not hide a later sibling whose lock is still held.
            macro_rules! check {
                ($field:ident) => {{
                    match journals
                        .$field
                        .try_prepare_publication(&self.target.$field, |_, _| Ok::<_, ()>(()))
                    {
                        Ok(prepared) => drop(prepared.abort()),
                        Err((_, PublicationPreparationError::Poisoned, _)) if self.unwind => {}
                        Err(_) => {
                            self.failures.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    self.checks.fetch_add(1, Ordering::SeqCst);
                }};
            }
            check!(data_triggers);
            check!(pipeline_triggers);
            check!(time_triggers);
            check!(by_call_triggers);
            check!(ids);
            check!(active_data_trigger_ids);
            check!(active_pipeline_trigger_ids);
            check!(active_time_trigger_ids);
            check!(active_by_call_trigger_ids);
            check!(contracts);
        }
    }

    for unwind in [false, true] {
        for component in 0..10 {
            let waiter_budget = iroha_allocation::AllocationBudget::new(
                iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
            );
            let mut registration = crate::unit_test_support::release_registration(&waiter_budget);
            let released = Arc::new(AtomicUsize::new(0));
            let target = seeded_set();
            let before = images(&target);
            let watcher = capture(target.block());
            let reentry = capture(target.block());
            let mut block = target.block();
            mutate_all(&mut block);
            let journal = block
                .try_detach(|_| Ok::<_, ()>(Capacity(Arc::clone(&released), 1)))
                .unwrap();
            let prepared = journal
                .try_prepare_publication(&target, |_, _| {
                    Ok::<_, ()>(Capacity(Arc::clone(&released), 2))
                })
                .unwrap_or_else(|_| panic!("prepare original aggregate"));
            macro_rules! observe {
                ($field:ident) => {{
                    let (_, error, cleanup) = watcher
                        .$field
                        .try_prepare_publication(&target.$field, |_, _| Ok::<_, ()>(()))
                        .err()
                        .expect("original prepared component held");
                    drop(cleanup);
                    let PublicationPreparationError::Busy(wait) = error else {
                        panic!("expected original prepared identity contention");
                    };
                    wait.wait_for_release(&mut registration)
                }};
            }
            let mut wait = match component {
                0 => observe!(data_triggers),
                1 => observe!(pipeline_triggers),
                2 => observe!(time_triggers),
                3 => observe!(by_call_triggers),
                4 => observe!(ids),
                5 => observe!(active_data_trigger_ids),
                6 => observe!(active_pipeline_trigger_ids),
                7 => observe!(active_time_trigger_ids),
                8 => observe!(active_by_call_trigger_ids),
                9 => observe!(contracts),
                _ => unreachable!(),
            };
            let callback = Arc::new(Reenter {
                target: Arc::clone(&target),
                journals: Mutex::new(Some(reentry)),
                released: Arc::clone(&released),
                checks: AtomicUsize::new(0),
                failures: AtomicUsize::new(0),
                wakes: AtomicUsize::new(0),
                unwind,
            });
            let waker = Waker::from(Arc::clone(&callback));
            assert!(
                Pin::new(&mut wait)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            if unwind {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _original = prepared;
                    panic!("abandon original aggregate during unwind");
                }));
                assert!(result.is_err());
            } else {
                drop(prepared);
                assert_eq!(images(&target), before);
            }
            assert_eq!(
                callback.wakes.load(Ordering::SeqCst),
                1,
                "component {component}, unwind {unwind}"
            );
            assert_eq!(callback.checks.load(Ordering::SeqCst), 10);
            assert_eq!(
                callback.failures.load(Ordering::SeqCst),
                0,
                "component {component}, unwind {unwind}"
            );
            assert_eq!(released.load(Ordering::SeqCst), 3);
            assert!(
                Pin::new(&mut wait)
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
        }
    }
}

#[path = "set_publication_slot_tests.rs"]
mod slot_tests;
