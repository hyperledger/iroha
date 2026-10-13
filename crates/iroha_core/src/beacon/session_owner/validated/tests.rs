//! Authenticated shared graph custody, exact preflight and original prepaid retries.

use super::*;
use crate::{
    beacon::{fixtures::*, global_threshold_beacon_roster_hash_v1},
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_allocation::release::ReleaseRegistration;
use std::task::{Context, Waker};

fn fixture(seats: u16) -> AdaptiveBeaconFixture {
    let mut session = adaptive_dkg_session_fixture();
    session.committee_size = seats;
    session.threshold = (seats - 1) / 3 + 1;
    let keys = adaptive_fixture_signing_keys(seats);
    session.roster_hash = global_threshold_beacon_roster_hash_v1(
        &keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>(),
    );
    adaptive_beacon_fixture_for_session_and_keys(session, &keys, &fixture_budget())
}

#[test]
fn sealed_minimum_and_maximum_graphs_share_exact_custody_without_clone_allocations() {
    for seats in [4, 31] {
        let fixture = fixture(seats);
        let source = fixture.session.record();
        let demand = SessionDemand::new(source, &fixture.binding).unwrap();
        let total = demand.total;
        let retained = total - demand.scratch.bytes;
        let pool = AllocationBudget::new(total);
        let bytes = norito::to_bytes(source).unwrap();
        let count = Demand::for_session(source).unwrap().charges + 4; // ledger, shared control, two scratch buffers
        let mut captured = None;
        assert_eq!(
            allocations_during(|| {
                captured = Some(
                    ValidatedGlobalThresholdBeaconSessionV1::admit(source, &fixture.binding, &pool)
                        .unwrap(),
                );
            }),
            count,
            "all verification and retained storage is concrete original-pool backing"
        );
        let captured = captured.unwrap();
        assert!(captured.belongs_to(&pool));
        assert_eq!(captured.retained_allocation_bytes(), retained);
        assert_eq!(
            pool.reserved_bytes(),
            retained,
            "both verification buffers have retired"
        );
        super::super::tests::check_allocations(source, captured.record());
        assert_eq!(norito::to_bytes(&captured).unwrap(), bytes);
        assert_eq!(captured.transcript(), fixture.session.transcript());
        let mut last = None;
        assert_eq!(
            allocations_during(|| {
                last = Some(captured.clone());
            }),
            0
        );
        let last = last.unwrap();
        assert!(last.ptr_eq(&captured));
        assert!(core::ptr::eq(last.record(), captured.record()));
        assert_eq!(pool.reserved_bytes(), retained);
        drop(captured);
        assert_eq!(
            pool.reserved_bytes(),
            retained,
            "a surviving reader owns every original charge"
        );
        assert_eq!(last.record(), source);
        drop(last);
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(norito::to_bytes(source).unwrap(), bytes);
    }
}

#[test]
fn prepaid_session_shortage_and_foreign_source_refuse_before_any_physical_allocation() {
    let fixture = fixture(4);
    let source = fixture.session.record();
    let total = SessionDemand::new(source, &fixture.binding).unwrap().total;
    let pool = AllocationBudget::new(total + 23);
    let mut short = pool.try_reserve_bytes(total - 1).unwrap();
    let mut outcome = None;
    assert_eq!(
        allocations_during(|| {
            outcome = Some(ValidatedGlobalThresholdBeaconSessionV1::admit_prepaid(
                source,
                &fixture.binding,
                &pool,
                &mut short,
            ));
        }),
        0,
        "the complete plan must be admitted before any constructed child owner"
    );
    assert!(
        matches!(outcome.take().unwrap(), Err(GlobalThresholdBeaconSessionError::Reservation(InsufficientReservation { requested_bytes, remaining_bytes })) if requested_bytes == total && remaining_bytes == total - 1)
    );
    assert_eq!(short.remaining_bytes(), total - 1);
    assert_eq!(pool.reserved_bytes(), total - 1);
    drop(short);
    let foreign = AllocationBudget::new(total);
    let mut original = foreign.try_reserve_bytes(total).unwrap();
    assert_eq!(
        allocations_during(|| {
            outcome = Some(ValidatedGlobalThresholdBeaconSessionV1::admit_prepaid(
                source,
                &fixture.binding,
                &pool,
                &mut original,
            ));
        }),
        0
    );
    let foreign_error = outcome.unwrap().unwrap_err();
    assert!(matches!(
        &foreign_error,
        GlobalThresholdBeaconSessionError::ForeignReservation
    ));
    let crate::execution_attempt::ExecutionAttemptError::Deferred(invariant) =
        foreign_error.into_execution_attempt()
    else {
        panic!("an impossible original custody mismatch cannot become a signed rejection")
    };
    assert_eq!(
        invariant.reason(),
        ivm::error::ExecutionDeferral::LocalInvariantViolation
    );
    assert!(
        invariant.allocation_refusal().is_none(),
        "foreign custody has no invented allocation source"
    );
    assert_eq!(original.remaining_bytes(), total);
    assert_eq!(foreign.reserved_bytes(), total);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(original);
    assert_eq!(foreign.reserved_bytes(), 0);

    let mut original = pool.try_reserve_bytes(total + 23).unwrap();
    pool.set_limit_bytes(1); // already owned credit remains authoritative after local policy changes
    let sealed = ValidatedGlobalThresholdBeaconSessionV1::admit_prepaid(
        source,
        &fixture.binding,
        &pool,
        &mut original,
    )
    .unwrap();
    assert!(sealed.belongs_to(&pool));
    assert_eq!(original.remaining_bytes(), 23);
    assert_eq!(
        pool.reserved_bytes(),
        sealed.retained_allocation_bytes() + 23
    );
    drop(original);
    assert_eq!(pool.reserved_bytes(), sealed.retained_allocation_bytes());
    drop(sealed);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn complete_sealed_admission_preserves_capacity_source_and_physical_refusal_custody() {
    let fixture = fixture(4);
    let source = fixture.session.record();
    let plan = SessionDemand::new(source, &fixture.binding).unwrap();
    let total = plan.total;
    let floor = ReleaseRegistration::allocation_layout().size();
    let pool = AllocationBudget::new(total + floor);
    let mut registration = crate::unit_test_support::release_registration(&pool);
    let blocker = pool.try_reserve_bytes(1).unwrap();
    let expected = pool.try_reserve_bytes(total).unwrap_err();
    let mut outcome = None;
    assert_eq!(
        allocations_during(|| {
            outcome = Some(ValidatedGlobalThresholdBeaconSessionV1::admit(
                source,
                &fixture.binding,
                &pool,
            ));
        }),
        0
    );
    let Err(GlobalThresholdBeaconSessionError::Admission(actual)) = outcome.unwrap() else {
        panic!("retain actual original refusal")
    };
    assert_eq!(actual, expected);
    let AllocationRefusal::Capacity { release, .. } = actual else {
        panic!("held source is observable")
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    drop(blocker);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    registration.cancel();
    let sealed =
        ValidatedGlobalThresholdBeaconSessionV1::admit(source, &fixture.binding, &pool).unwrap();
    assert_eq!(sealed.record(), source);
    drop(sealed);
    drop(registration);
    assert_eq!(pool.reserved_bytes(), 0);

    for layout in [
        ChargedShared::<RetainedPayload<Payload>>::allocation_layout(),
        Layout::array::<u8>(plan.scratch.preimage).unwrap(),
        Layout::array::<ValidatedDealerCommitment<BeaconPurpose>>(plan.scratch.dealers).unwrap(),
    ] {
        let pool = AllocationBudget::new(total + 23);
        let mut original = pool.try_reserve_bytes(total + 23).unwrap();
        let (result, refused) = refuse_one_layout_during(layout, || {
            ValidatedGlobalThresholdBeaconSessionV1::admit_prepaid(
                source,
                &fixture.binding,
                &pool,
                &mut original,
            )
        });
        assert!(
            refused,
            "actual original shell/scratch layout was reached: {layout:?}"
        );
        let error = result.expect_err("physical refusal cannot authenticate a session");
        assert!(matches!(
            error,
            GlobalThresholdBeaconSessionError::Shared(PrepaidSharedError::Allocator { .. })
                | GlobalThresholdBeaconSessionError::Buffer(PrepaidBufferError::Allocation(
                    iroha_allocation::ChargedBufferError::Allocator { .. }
                ))
        ));
        assert_eq!(
            pool.reserved_bytes(),
            original.remaining_bytes(),
            "constructed and refused child credits retired to their original pool"
        );
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
        let retry = ValidatedGlobalThresholdBeaconSessionV1::admit(source, &fixture.binding, &pool)
            .unwrap();
        assert_eq!(retry.record(), source);
        drop(retry);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn shared_authenticated_session_rechecks_every_current_external_binding() {
    let fixture = fixture(4);
    let original = fixture.session;
    let reader = original.clone();
    assert!(reader.ptr_eq(&original));
    let mut changed = fixture.binding;
    changed.network_id = beacon_fixture_network_id(0xe1);
    assert_eq!(
        reader.check_binding(&changed),
        Err(GlobalThresholdBeaconError::NetworkMismatch)
    );
    changed = fixture.binding;
    changed.session_id[0] ^= 1;
    assert_eq!(
        reader.check_binding(&changed),
        Err(GlobalThresholdBeaconError::SessionMismatch)
    );
    changed = fixture.binding;
    changed.roster_hash[0] ^= 1;
    assert_eq!(
        reader.check_binding(&changed),
        Err(GlobalThresholdBeaconError::RosterMismatch)
    );
    changed = fixture.binding;
    changed.transcript_hash[0] ^= 1;
    assert_eq!(
        reader.check_binding(&changed),
        Err(GlobalThresholdBeaconError::TranscriptMismatch)
    );
    assert_eq!(
        allocations_during(|| reader.check_binding(&fixture.binding).unwrap()),
        0
    );
    assert!(reader.ptr_eq(&original));
}
