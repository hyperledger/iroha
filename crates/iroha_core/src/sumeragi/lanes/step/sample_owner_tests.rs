//! Exact autoscale suffix custody, rollback and actual World publication.
use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::sumeragi_lanes::{SumeragiLaneAutoscale, SumeragiLaneSamples};

fn sample(height: u64) -> SumeragiLaneSample {
    SumeragiLaneSample {
        height,
        time_ms: height * 1000,
        transactions: height,
        lanes: 1,
    }
}
fn demand(count: usize) -> usize {
    count * std::mem::size_of::<SumeragiLaneSample>() + SumeragiLaneSamples::control_layout().size()
}
fn policy(window: u32) -> SumeragiLanePolicy {
    SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 4,
        max_merge_blocks: 8,
        stall_window: 10,
        lane_params: SumeragiParameters::default(),
        fixed: vec![],
        routes: vec![],
        autoscale: Some(SumeragiLaneAutoscale {
            min_lane: LaneId::new(16),
            max_lane_exclusive: LaneId::new(20),
            dataspace: DataSpaceId::new(0),
            committee_size: 4,
            per_lane_target_tps: 10,
            window,
            scale_out_permille: 800,
            scale_in_permille: 200,
            cooldown: 3,
        }),
    }
}
fn state(pool: &AllocationBudget) -> SumeragiLaneState {
    SumeragiLaneState {
        samples: SumeragiLaneSamples::try_from(vec![sample(1), sample(2), sample(3)])
            .unwrap()
            .admit(pool)
            .unwrap(),
        ..SumeragiLaneState::default()
    }
}
fn input() -> LaneStepInput {
    LaneStepInput {
        executed: [(LaneId::SINGLE, 7)].into_iter().collect(),
        ..LaneStepInput::default()
    }
}
#[test]
fn sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix() {
    let pool = AllocationBudget::new(demand(3));
    let mut value = state(&pool);
    let original = value.clone();
    let pointer = value.samples.as_ptr();
    pool.set_limit_bytes(demand(3) + demand(2) - 1);
    let original_refusal = pool.try_reserve_bytes(demand(2)).unwrap_err();
    assert_eq!(
        record_sample(&mut value, Some(&policy(1)), &input(), 5, 5000, &pool),
        Err(LaneStepError::Deferred(original_refusal.clone().into()))
    );
    let iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ref release,
    } = original_refusal
    else {
        panic!("actual sample suffix retains the original capacity owner");
    };
    assert_eq!(requested_bytes, demand(2));
    assert_eq!(reserved_bytes, demand(3));
    assert_eq!(limit_bytes, demand(3) + demand(2) - 1);
    let wait_pool = AllocationBudget::new(1 << 10);
    let mut registration = crate::unit_test_support::release_registration(&wait_pool);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert_eq!(
        registration.poll_wait(release, &mut context),
        std::task::Poll::Pending
    );
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert_eq!(
        registration.poll_wait(release, &mut context),
        std::task::Poll::Pending
    );
    assert_eq!(value, original);
    assert_eq!(value.samples.as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), demand(3));
    pool.set_limit_bytes(demand(3) + demand(2));
    assert_eq!(
        registration.poll_wait(release, &mut context),
        std::task::Poll::Ready(()),
        "growth of this original finite pool notifies its capacity waiter"
    );
    record_sample(&mut value, Some(&policy(1)), &input(), 5, 5000, &pool).unwrap();
    assert_eq!(
        value.samples.as_slice(),
        &[
            sample(3),
            SumeragiLaneSample {
                height: 5,
                time_ms: 5000,
                transactions: 7,
                lanes: 1
            }
        ]
    );
    assert!(value.samples.admitted_to(&pool));
    assert_eq!(pool.reserved_bytes(), demand(3) + demand(2));
    drop(value);
    assert_eq!(pool.reserved_bytes(), demand(3));
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(registration);
    assert_eq!(wait_pool.reserved_bytes(), 0);
}
#[test]
fn sample_finalizer_borrowed_lane_selection_preserves_boundaries_and_saturation() {
    let pool = AllocationBudget::new(1 << 20);
    let mut value = state(&pool);
    let policy = policy(u32::MAX);
    for (lane, active_from, closing) in [
        (2, 1, None),
        (16, 1, None),
        (17, 6, None),
        (18, 1, Some(5)),
        (19, 4, None),
    ] {
        let mut record = create(
            &mut value,
            &policy,
            &NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([5; 32]),
            )),
            LaneId::new(lane),
            DataSpaceId::new(0),
            vec![],
            1,
        );
        record.active_from = active_from;
        record.closing = closing;
        value.upsert(record);
    }
    let input = LaneStepInput {
        executed: [
            (0, u64::MAX - 2),
            (16, 2),
            (19, 4),
            (17, 9),
            (18, 9),
            (2, 9),
        ]
        .into_iter()
        .map(|(lane, count)| (LaneId::new(lane), count))
        .collect(),
        ..LaneStepInput::default()
    };
    // Independently reconstruct the previous temporary-Vec selection.
    let elastic = value
        .lanes
        .iter()
        .filter(|record| policy.is_elastic(record.lane) && record.admits_anchor(5))
        .map(|record| record.lane)
        .collect::<Vec<_>>();
    let transactions = input
        .executed
        .iter()
        .filter(|(lane, _)| lane.as_u32() == 0 || elastic.contains(lane))
        .map(|(_, count)| *count)
        .fold(0, u64::saturating_add);
    record_sample(&mut value, Some(&policy), &input, 5, 5000, &pool).unwrap();
    assert_eq!(
        value.samples.len(),
        4,
        "large positive policy window admits only actual rows"
    );
    assert_eq!(value.samples[3].transactions, transactions);
    assert_eq!(transactions, u64::MAX);
    assert_eq!(
        value.samples[3].lanes,
        u32::try_from(elastic.len() + 1).unwrap()
    );
    assert_eq!(value.samples[3].lanes, 3);
    assert!(policy.validate().is_ok());
    let mut invalid = policy.clone();
    invalid.autoscale.as_mut().unwrap().window = 0;
    assert!(
        invalid.validate().is_err(),
        "zero-window policy remains invalid"
    );
    let retained = value.samples.clone();
    let bytes = pool.reserved_bytes();
    pool.set_limit_bytes(0);
    record_sample(&mut value, None, &input, 6, 6000, &pool).unwrap();
    assert!(value.samples.is_empty());
    assert_eq!(
        pool.reserved_bytes(),
        bytes,
        "retained reader still owns exact backing"
    );
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn sample_finalizer_foreign_pool_requires_recovery_without_source_or_refund_changes() {
    let pool = AllocationBudget::new(demand(3));
    let mut value = state(&pool);
    let original = value.clone();
    let pointer = value.samples.as_ptr();
    let foreign = AllocationBudget::new(demand(4));
    let error =
        record_sample(&mut value, Some(&policy(8)), &input(), 5, 5000, &foreign).unwrap_err();
    let LaneStepError::Deferred(defect) = error else {
        panic!("foreign original sample custody cannot become a retryable pool shortage");
    };
    assert_eq!(
        defect.reason(),
        ivm::error::ExecutionDeferral::LocalInvariantViolation
    );
    assert!(defect.allocation_refusal().is_none());
    assert_eq!(value, original);
    assert_eq!(value.samples.as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), demand(3));
    assert_eq!(foreign.reserved_bytes(), 0);
    drop(value);
    assert_eq!(pool.reserved_bytes(), demand(3));
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn sample_finalizer_exceeds_limit_retains_exact_requested_suffix_demand() {
    let pool = AllocationBudget::new(demand(1) - 1);
    let mut value = SumeragiLaneState::default();
    let original = value.clone();
    let expected = pool.try_reserve_bytes(demand(1)).unwrap_err();
    assert!(
        matches!(expected, iroha_allocation::AllocationRefusal::ExceedsLimit {
        requested_bytes, limit_bytes,
    } if requested_bytes == demand(1) && limit_bytes == demand(1) - 1)
    );
    assert_eq!(
        record_sample(&mut value, Some(&policy(8)), &input(), 5, 5000, &pool),
        Err(LaneStepError::Deferred(expected.into()))
    );
    assert_eq!(value, original);
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(demand(1));
    record_sample(&mut value, Some(&policy(8)), &input(), 5, 5000, &pool).unwrap();
    assert_eq!(
        value.samples.as_slice(),
        &[SumeragiLaneSample {
            height: 5,
            time_ms: 5000,
            transactions: 7,
            lanes: 1,
        }]
    );
    assert!(value.samples.admitted_to(&pool));
    assert_eq!(pool.reserved_bytes(), demand(1));
    drop(value);
    assert_eq!(pool.reserved_bytes(), 0);
}
