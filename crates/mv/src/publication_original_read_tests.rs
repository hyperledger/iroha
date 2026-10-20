//! Exact original publication waiter for coherent committed pair capture.

use super::*;
use crate::allocation_test_support::without_allocations;
use crate::cell::{Cell, CommittedCellReadError};
use iroha_allocation::AllocationBudget;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

#[test]
fn every_initial_publication_supports_a_cold_allocation_free_observation() {
    let required = Publication::allocation_demand().unwrap().bytes();
    for constructor in 0..3 {
        let budget = AllocationBudget::new(required);
        let publication = match constructor {
            0 => Publication::new(),
            1 => Publication::try_from_original(&mut budget.try_reserve_bytes(required).unwrap())
                .unwrap(),
            2 => {
                let mut reservation = budget.try_reserve_bytes(required).unwrap();
                Publication::try_from_original(&mut reservation).unwrap()
            }
            _ => unreachable!(),
        };
        // No preceding capture or writer may warm this original mutex. Both
        // successful observation and refusal must work after construction alone.
        let identity = without_allocations(|| publication.try_capture_reads(|| true).unwrap());
        without_allocations(|| {
            assert!(matches!(
                publication.try_capture_reads(|| false),
                Err(PublicationPreparationError::Changed)
            ));
        });
        assert_eq!(
            budget.reserved_bytes(),
            if constructor == 0 { 0 } else { required }
        );
        drop(identity);
        drop(publication);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_publication_contention_retains_its_real_release_source() {
    let release_budget = iroha_allocation::AllocationBudget::new(
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut release_registration_1 = crate::release_test_support::registration(&release_budget);

    let cell = Cell::new(1_u64);
    let expected = cell.publication.released.observe();
    let guard = cell.publication.lock_version();
    let error = cell
        .try_committed_view()
        .err()
        .expect("actual publication lock");
    assert_eq!(
        error,
        CommittedCellReadError::Publication(PublicationPreparationError::Busy(expected.clone()))
    );
    let mut wait = expected.wait_for_release(&mut release_registration_1);
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Pending);
    drop(guard);
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Ready(()));
    assert!(cell.try_committed_view().is_ok());
}
