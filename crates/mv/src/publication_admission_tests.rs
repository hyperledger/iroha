//! Exact original publication controls retain admission through release observers.

use super::*;
use iroha_allocation::AllocationBudget;

#[test]
fn complete_initial_publication_admission_includes_original_release_control() {
    let identities = Identity::<Owner>::layout().size() + Identity::<Version>::layout().size();
    let notification = ReleaseNotification::allocation_layout::<AllocationCharge>().size();
    let required = Publication::allocation_demand().unwrap().bytes();
    assert_eq!(required, identities + notification);
    let budget = AllocationBudget::new(required - 1);
    assert!(budget.try_reserve_bytes(required).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(required);
    let mut original = budget.try_reserve_bytes(required).unwrap();
    // Construction only splits the already admitted complete owner. It never
    // silently acquires more capacity after another participant takes a writer.
    budget.set_limit_bytes(0);
    let publication = Publication::try_from_original(&mut original).unwrap();
    assert_eq!(budget.reserved_bytes(), required);
    drop(publication);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_publication_observers_keep_their_exact_charge_after_identity_destruction() {
    let required = Publication::allocation_demand().unwrap().bytes();
    let notification = ReleaseNotification::allocation_layout::<AllocationCharge>().size();
    let budget = AllocationBudget::new(required);
    let foreign = AllocationBudget::new(required);
    let foreign_publication =
        Publication::try_from_original(&mut foreign.try_reserve_bytes(required).unwrap()).unwrap();
    let publication =
        Publication::try_from_original(&mut budget.try_reserve_bytes(required).unwrap()).unwrap();
    let identity = publication.capture();
    let original = publication.released.observe();
    let retained = original.clone();
    assert_ne!(
        original,
        foreign_publication.released.observe(),
        "equal release sequence is not source identity"
    );
    drop(publication);
    assert_eq!(budget.reserved_bytes(), required);
    assert_eq!(foreign.reserved_bytes(), required);
    drop(identity);
    assert_eq!(budget.reserved_bytes(), notification);
    drop(original);
    assert_eq!(budget.reserved_bytes(), notification);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), required);
    drop(foreign_publication);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn charged_identity_busy_release_unlocks_before_signal_and_retains_original_control() {
    let required = Publication::allocation_demand().unwrap().bytes();
    let notification = ReleaseNotification::allocation_layout::<AllocationCharge>().size();
    let budget = AllocationBudget::new(required);
    let publication =
        Publication::try_from_original(&mut budget.try_reserve_bytes(required).unwrap()).unwrap();
    let identity = publication.capture();
    let writer = publication.lock_version();
    let wait = match identity.try_prepare_current::<()>(&publication) {
        Err((PublicationPreparationError::Busy(wait), None)) => wait,
        _ => panic!("actual identity mutex contention must retain its original release"),
    };
    assert_eq!(wait, publication.released.observe());
    let ((), deferred) = writer.release_deferred(drop);
    assert!(
        publication.version.try_lock().is_ok(),
        "physical lock is already free"
    );
    assert_eq!(
        wait,
        publication.released.observe(),
        "no notification before aggregate cleanup"
    );
    drop(deferred);
    assert_ne!(
        wait,
        publication.released.observe(),
        "the actual release advances this source"
    );
    drop(identity);
    drop(publication);
    assert_eq!(budget.reserved_bytes(), notification);
    drop(wait);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pending_publication_waiter_keeps_original_control_until_cancelled() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Waker},
    };

    let required = Publication::allocation_demand().unwrap().bytes();
    let notification = ReleaseNotification::allocation_layout::<AllocationCharge>().size();
    let registration_bytes =
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(required + registration_bytes);
    let mut registration = crate::release_test_support::registration(&budget);
    let publication =
        Publication::try_from_original(&mut budget.try_reserve_bytes(required).unwrap()).unwrap();
    let mut future = publication
        .released
        .observe()
        .wait_for_release(&mut registration);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut future).poll(&mut context).is_pending());
    // Both controls remain charged until their respective owners are released.
    drop(publication);
    assert_eq!(budget.reserved_bytes(), notification + registration_bytes);
    drop(future);
    assert_eq!(budget.reserved_bytes(), registration_bytes);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn all_original_publication_constructors_initialize_cold_observation_mutexes() {
    use crate::allocation_test_support::without_allocations;
    let required = Publication::allocation_demand().unwrap().bytes();
    let budget = AllocationBudget::new(2 * required);
    let mut reservation = budget.try_reserve_bytes(required).unwrap();
    let sources = [
        Publication::new(),
        Publication::try_from_original(&mut budget.try_reserve_bytes(required).unwrap()).unwrap(),
        Publication::try_from_original(&mut reservation).unwrap(),
    ];
    assert_eq!(reservation.remaining_bytes(), 0);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                for source in &sources {
                    let first = without_allocations(|| source.try_capture_reads(|| true).unwrap());
                    without_allocations(|| {
                        assert!(first.same_as(&source.try_capture_reads(|| true).unwrap()));
                        drop(first);
                    });
                }
            })
            .join()
            .unwrap();
    });
    drop(sources);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
}
