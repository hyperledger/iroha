//! Actual finalized-reader refusals across the pin signer's read boundaries.

use super::*;
use crate::musubi_publication_service::finality::tests::{ReaderFixture, reader_fixture};
use iroha_allocation::{
    AllocationBudget, AllocationRefusal, AllocationReservation, release::ReleaseRegistration,
};
use iroha_config::parameters::actual::Queue as QueueConfig;
use iroha_crypto::Algorithm;
use iroha_musubi_service::MusubiPublicationServiceBackendErrorV1;
use std::{
    future::Future as _,
    pin::Pin,
    task::{Context, Waker},
};

struct ClosedClock {
    calls: usize,
}
impl MusubiPublicationServiceClockV1 for ClosedClock {
    fn current_time_ms(&mut self) -> Result<u64, MusubiPublicationServiceBackendErrorV1> {
        self.calls += 1;
        Err(MusubiPublicationServiceBackendErrorV1::Permanent)
    }
}

fn signer(fixture: &ReaderFixture) -> MusubiPublicationPinTransactionSignerV1 {
    let key_pair = KeyPair::from_seed(vec![0xD1; 32], Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let (events, _) = tokio::sync::broadcast::channel(1);
    MusubiPublicationPinTransactionSignerV1 {
        network_id: fixture.query.network_id,
        policy: MusubiPublicationPaidPinPolicy {
            storage_class: StorageClass::Hot,
            retention_horizon_secs: 30 * 24 * 60 * 60,
            transaction_authority: authority.clone(),
        },
        authority,
        key_pair,
        state: Arc::clone(&fixture.state),
        queue: Arc::new(Queue::from_config(QueueConfig::default(), events)),
        finalized_reader: fixture.reader.clone(),
    }
}

fn exhaust_original_budget(
    budget: &AllocationBudget,
) -> (AllocationReservation, ReleaseRegistration) {
    let mut prepaid = budget
        .try_reserve(ReleaseRegistration::allocation_layout())
        .expect("admit original retry registration before exhausting the pool");
    let registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
    drop(prepaid);
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .expect("retain all remaining original State capacity");
    (held, registration)
}

fn require_original_release(
    error: MusubiPublicationPinSigningErrorV1,
    budget: &AllocationBudget,
    held: AllocationReservation,
    mut registration: ReleaseRegistration,
) {
    let MusubiPublicationPinSigningErrorV1::Deferred(original) = error else {
        panic!("original capacity refusal was lost: {error:?}");
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        panic!("original pool release observation was lost: {original:?}");
    };
    assert!(registration.belongs_to(budget));
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    let other_budget = AllocationBudget::new(1);
    drop(other_budget.try_reserve_bytes(1).unwrap());
    assert!(
        Pin::new(&mut wait).poll(&mut context).is_pending(),
        "a different pool cannot release this original refusal"
    );
    drop(held);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
}

#[test]
fn original_state_capacity_refuses_before_clock_or_signing_and_preserves_retry_owner() {
    let fixture = reader_fixture();
    let signer = signer(&fixture);
    let budget = fixture.state.query_view().execution_budget();
    let (held, registration) = exhaust_original_budget(&budget);
    let mut clock = ClosedClock { calls: 0 };
    let error = signer
        .prepare_finalized_archive(&fixture.query, &mut clock, 200_000)
        .expect_err("original State capacity is occupied");
    assert_eq!(clock.calls, 0, "refuse before clock, fees or signing");
    require_original_release(error, &budget, held, registration);
    assert!(
        matches!(
            signer.prepare_finalized_archive(&fixture.query, &mut clock, 200_000),
            Err(MusubiPublicationPinSigningErrorV1::Clock)
        ),
        "retry of the same source passes native finality after its original refund"
    );
    assert_eq!(clock.calls, 1);
}

#[test]
fn final_recheck_retains_original_capacity_refusal_and_retries_the_exact_source() {
    let fixture = reader_fixture();
    let signer = signer(&fixture);
    signer.recheck_finalized_archive(&fixture.query).unwrap();
    let budget = fixture.state.query_view().execution_budget();
    let (held, registration) = exhaust_original_budget(&budget);
    let error = signer
        .recheck_finalized_archive(&fixture.query)
        .expect_err("final recheck cannot erase original capacity refusal");
    require_original_release(error, &budget, held, registration);
    signer.recheck_finalized_archive(&fixture.query).unwrap();
}

#[test]
fn captured_view_conversion_preserves_the_complete_original_refusal() {
    let fixture = reader_fixture();
    let view = fixture.state.query_view();
    let budget = view.execution_budget();
    let (held, registration) = exhaust_original_budget(&budget);
    let original = fixture
        .reader
        .read_current_archive_in_view(&fixture.query, &view)
        .expect_err("the captured view uses the same original pool");
    let MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Deferred(ref expected) = original
    else {
        panic!("expected original capacity refusal: {original:?}");
    };
    let expected_reason = expected.reason();
    let expected_allocation = expected.allocation_refusal().cloned();
    let converted = MusubiPublicationPinSigningErrorV1::from(original);
    let MusubiPublicationPinSigningErrorV1::Deferred(retained) = &converted else {
        panic!("conversion must retain the sole original refusal");
    };
    assert_eq!(retained.reason(), expected_reason);
    assert_eq!(retained.allocation_refusal(), expected_allocation.as_ref());
    require_original_release(converted, &budget, held, registration);
    assert_eq!(
        fixture
            .reader
            .read_current_archive_in_view(&fixture.query, &view)
            .unwrap(),
        fixture.archive
    );
}

#[test]
fn initial_and_final_reads_distinguish_locally_future_evidence_from_invalid_finality() {
    let fixture = reader_fixture();
    let signer = signer(&fixture);
    for future_revision in [false, true] {
        let mut future = fixture.query.clone();
        if future_revision {
            future.snapshot.index_revision += 1;
        } else {
            future.snapshot.finalized_height += 1;
        }
        let mut clock = ClosedClock { calls: 0 };
        assert!(matches!(
            signer.prepare_finalized_archive(&future, &mut clock, 200_000),
            Err(MusubiPublicationPinSigningErrorV1::LocallyAhead)
        ));
        assert_eq!(clock.calls, 0);
        assert!(matches!(
            signer.recheck_finalized_archive(&future),
            Err(MusubiPublicationPinSigningErrorV1::LocallyAhead)
        ));
    }
    let mut substituted = fixture.query.clone();
    substituted.snapshot.finalized_block_hash = [0xD2; 32];
    let mut clock = ClosedClock { calls: 0 };
    assert!(matches!(
        signer.prepare_finalized_archive(&substituted, &mut clock, 200_000),
        Err(MusubiPublicationPinSigningErrorV1::Finality)
    ));
    assert_eq!(clock.calls, 0);
    assert!(matches!(
        signer.recheck_finalized_archive(&substituted),
        Err(MusubiPublicationPinSigningErrorV1::Finality)
    ));
}
