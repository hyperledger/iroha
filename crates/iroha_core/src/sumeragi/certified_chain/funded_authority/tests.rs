//! Original native-parent authority graph ownership and shared-verifier integration.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    test_allocations::{allocations_during, refuse_one_layout_during},
};

fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    chain
}
fn scheduled(parent: &CommittedBlock) -> &schedule::ScheduledConfig {
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("genuine executed parent authorizes its successor")
    };
    scheduled
}
fn demand(scheduled: &schedule::ScheduledConfig) -> usize {
    config_demand(&scheduled.epoch.committee).unwrap()
        + FundedBlsCommittee::allocation_demand(&scheduled.epoch.committee).unwrap()
}

#[test]
fn native_funded_authority_borrows_original_epoch_and_one_exact_configuration_graph() {
    // Retain fixture publication generations before they can become reclaimable;
    // unrelated EBR collection must not change the original pool's measured baseline.
    let _epoch = crossbeam_epoch::pin();
    let chain = chain();
    let parent = chain.committed(2);
    let current = chain.committed(3);
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let source_budget = view.execution_budget();
    let baseline = source_budget.reserved_bytes();
    let slot = scheduled(&parent);
    let original_keys: Vec<_> = slot
        .epoch
        .committee
        .iter()
        .map(|member| {
            member
                .validator
                .public_key()
                .borrowed_parts()
                .unwrap()
                .1
                .as_ptr()
        })
        .collect();
    let authority =
        state_certificate::executed_successor_authority(&parent, &current, &source_budget).unwrap();
    assert!(std::ptr::eq(authority.material, &slot.epoch));
    assert!(authority.belongs_to(&source_budget));
    assert_eq!(source_budget.reserved_bytes(), baseline + demand(slot));
    let projected = authority.projection();
    assert!(std::ptr::eq(
        projected.committee,
        &authority.config().committee
    ));
    assert!(std::ptr::eq(projected.material, &slot.epoch));
    assert_eq!(authority.config(), &slot.height_config().unwrap());
    for ((source, copied), original_pointer) in slot
        .epoch
        .committee
        .iter()
        .zip(authority.config().committee.members())
        .zip(original_keys)
    {
        let bytes = source.validator.public_key().borrowed_parts().unwrap().1;
        assert_eq!(bytes, copied.as_bytes());
        assert_eq!(bytes.as_ptr(), original_pointer);
        assert_ne!(copied.as_bytes().as_ptr(), original_pointer);
    }
    let result = reader
        .verification_context()
        .prepare_certificate_with_scratch_admission(
            &current,
            authority.projection(),
            Some(authority.config()),
            None,
            &mut state_certificate::query_scratch_admission,
        )
        .unwrap();
    assert_eq!(result.verification, QcVerification::Verified);
    verify_boundary_source(&current, &parent, authority.projection()).unwrap();
    assert_eq!(source_budget.reserved_bytes(), baseline + demand(slot));
    eprintln!(
        "native funded authority inline bytes: {}",
        std::mem::size_of::<FundedExecutionAuthority<'_>>()
    );
    drop(authority);
    assert_eq!(source_budget.reserved_bytes(), baseline);
}

#[test]
fn native_funded_authority_partial_key_array_epoch_and_completion_unwinds_refund_exactly() {
    // Retain fixture publication generations before they can become reclaimable;
    // unrelated EBR collection must not change the original pool's measured baseline.
    let _epoch = crossbeam_epoch::pin();
    let chain = chain();
    let parent = chain.committed(2);
    let current = chain.committed(3);
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let original = (parent.id(), current.id());
    for stage in [
        ConstructionStage::Key(0),
        ConstructionStage::Key(3),
        ConstructionStage::Committee,
        ConstructionStage::Epoch,
        ConstructionStage::Complete,
    ] {
        UNWIND_AT.with(|point| point.set(Some(stage)));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state_certificate::executed_successor_authority(&parent, &current, &budget)
        }));
        assert!(
            result.is_err(),
            "the actual production checkpoint must be reached: {stage:?}"
        );
        assert_eq!(UNWIND_AT.with(std::cell::Cell::get), None);
        assert_eq!(
            budget.reserved_bytes(),
            baseline,
            "partial payloads retire before exact original refund: {stage:?}"
        );
        assert_eq!((parent.id(), current.id()), original);
        let retry =
            state_certificate::executed_successor_authority(&parent, &current, &budget).unwrap();
        assert!(retry.belongs_to(&budget));
        assert_eq!(
            budget.reserved_bytes(),
            baseline + demand(scheduled(&parent))
        );
        drop(retry);
        assert_eq!(budget.reserved_bytes(), baseline);
    }
}

#[test]
fn exact_core_key_allocator_refusal_retires_partial_graph_and_preserves_original_prepaid_remainder()
{
    // Retain fixture publication generations before they can become reclaimable;
    // unrelated EBR collection must not change the original pool's measured baseline.
    let _epoch = crossbeam_epoch::pin();
    let chain = chain();
    let parent = chain.committed(2);
    let slot = scheduled(&parent);
    let (epoch, params) = slot
        .core_parameters_with_validation(&mut EpochValidationScope::new())
        .unwrap();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let bytes = config_demand(&slot.epoch.committee).unwrap();
    let mut original = budget.try_reserve_bytes(bytes).unwrap();
    let refused_layout = Layout::array::<u8>(48).unwrap();
    let (result, refused) = refuse_one_layout_during(refused_layout, || {
        FundedHeightConfig::from_reservation(slot, epoch, params, &mut original)
    });
    assert!(
        refused,
        "the genuine first raw BLS key uses the selected physical layout"
    );
    let error = result
        .err()
        .expect("the selected physical allocation refused");
    assert!(matches!(
        &error,
        CommitteeAdmissionError::Buffer(PrepaidBufferError::Allocation(
            ChargedBufferError::Allocator {
                requested_bytes: 48
            }
        ))
    ));
    assert!(matches!(
        admission_error(3, error),
        VerificationReadError::Deferred(original)
            if original.reason() == ivm::error::ExecutionDeferral::AllocationUnavailable
                && original.allocation_refusal().is_none()
    ));
    assert_eq!(
        budget.reserved_bytes(),
        baseline + original.remaining_bytes()
    );
    drop(original);
    assert_eq!(budget.reserved_bytes(), baseline);
    let mut original = budget.try_reserve_bytes(bytes).unwrap();
    let mut completed = None;
    let count = allocations_during(|| {
        completed =
            Some(FundedHeightConfig::from_reservation(slot, epoch, params, &mut original).unwrap());
    });
    assert_eq!(
        count,
        slot.epoch.committee.len() + 2,
        "one raw allocation per core key, the sole key array, and one epoch box"
    );
    assert_eq!(original.remaining_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), baseline + bytes);
    drop(completed);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn native_funded_authority_preserves_structural_rejection_before_capacity_and_exact_original_fields()
 {
    // Retain fixture publication generations before they can become reclaimable;
    // unrelated EBR collection must not change the original pool's measured baseline.
    let _epoch = crossbeam_epoch::pin();
    let chain = chain();
    let parent = chain.committed(2);
    let original = scheduled(&parent);
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut cases = Vec::new();
    let mut changed = original.clone();
    changed.height = 0;
    cases.push(changed);
    let mut changed = original.clone();
    changed.epoch.leader_seed = [0; 32];
    cases.push(changed);
    let mut changed = original.clone();
    changed.epoch.committee[3].proof_of_possession[0] ^= 1;
    cases.push(changed);
    let mut changed = original.clone();
    changed.epoch.committee.swap(0, 1);
    cases.push(changed);
    let mut changed = original.clone();
    changed.params.payload_retry_interval_ms = 0;
    cases.push(changed);
    let expected: Vec<_> = cases
        .iter()
        .map(|candidate| candidate.height_config().unwrap_err().to_string())
        .collect();
    let blocked = budget
        .try_reserve_bytes(budget.limit_bytes() - baseline)
        .unwrap();
    for (candidate, expected) in cases.iter().zip(expected) {
        let result = FundedExecutionAuthority::admit(candidate, 3, &budget);
        assert!(
            matches!(result, Err(VerificationReadError::Source(ChainReadError::Committee { height: 3, reason })) if reason == expected)
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    }
    drop(blocked);
    let authority = FundedExecutionAuthority::admit(original, 3, &budget).unwrap();
    assert!(std::ptr::eq(
        authority.projection().material,
        &original.epoch
    ));
    drop(authority);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn native_authority_prepaid_custody_errors_require_recovery() {
    use crate::sumeragi::{
        driver::traits::PublicationError, executor::classify_parent_service_deferral_for_test,
    };
    use iroha_allocation::InsufficientReservation;
    use ivm::error::ExecutionDeferral;

    let short = InsufficientReservation {
        requested_bytes: 49,
        remaining_bytes: 48,
    };
    for error in [
        CommitteeAdmissionError::ForeignPool,
        CommitteeAdmissionError::Reservation(short),
        CommitteeAdmissionError::Buffer(PrepaidBufferError::Reservation(short)),
        CommitteeAdmissionError::KeyAllocation(PublicKeyAllocationError::ForeignPool),
        CommitteeAdmissionError::KeyAllocation(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::DemandOverflow,
        )),
        CommitteeAdmissionError::KeyAllocation(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::LayoutMismatch {
                expected: Layout::array::<u8>(49).unwrap(),
                actual: Layout::array::<u8>(48).unwrap(),
            },
        )),
        CommitteeAdmissionError::KeyAllocation(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::LayoutMismatch {
                expected: Layout::from_size_align(48, 1).unwrap(),
                actual: Layout::from_size_align(48, 8).unwrap(),
            },
        )),
    ] {
        let VerificationReadError::Deferred(classified) = admission_error(3, error) else {
            panic!("prepaid authority custody failure is local, never source rejection")
        };
        assert_eq!(
            classified.reason(),
            ExecutionDeferral::LocalInvariantViolation,
            "prepaid authority custody violations must require recovery"
        );
        assert_eq!(classified.allocation_refusal(), None);
        assert!(
            matches!(
                classify_parent_service_deferral_for_test(classified),
                PublicationError::RecoveryRequired(_)
            ),
            "native parent service must require recovery for prepaid custody violations"
        );
    }
}

#[test]
fn native_authority_admission_keeps_original_release_and_policy_refusals() {
    use crate::sumeragi::{
        driver::traits::PublicationError, executor::classify_parent_service_deferral_for_test,
    };
    use iroha_allocation::release::ReleaseRegistration;
    use ivm::error::ExecutionDeferral;
    use std::task::{Context, Waker};

    let waiter_bytes = ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(waiter_bytes + 17);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget.try_reserve_bytes(17).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let AllocationRefusal::Capacity { release, .. } = &original else {
        panic!("the genuine occupied original pool must produce a capacity observation")
    };
    let mut task = Context::from_waker(Waker::noop());
    for error in [
        CommitteeAdmissionError::Admission(original.clone()),
        CommitteeAdmissionError::Buffer(PrepaidBufferError::Allocation(
            ChargedBufferError::Admission(original.clone()),
        )),
    ] {
        let VerificationReadError::Deferred(classified) = admission_error(3, error) else {
            panic!("original authority admission remains a local refusal")
        };
        assert_eq!(classified.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        assert_eq!(classified.allocation_refusal(), Some(&original));
        let Some(AllocationRefusal::Capacity {
            release: carried, ..
        }) = classified.allocation_refusal()
        else {
            unreachable!("the exact original capacity observation is retained")
        };
        assert_eq!(carried, release);
        assert!(registration.poll_wait(carried, &mut task).is_pending());
        let PublicationError::Deferred(returned) =
            classify_parent_service_deferral_for_test(classified)
        else {
            panic!("the actual parent-service boundary must retain original admission")
        };
        assert_eq!(returned.allocation_refusal(), Some(&original));
        assert_eq!(returned.release_wait(), Some(release));
        assert!(registration.poll_wait(release, &mut task).is_pending());
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    }
    let other = AllocationBudget::new(17);
    drop(other.try_reserve_bytes(17).unwrap());
    assert!(registration.poll_wait(release, &mut task).is_pending());
    drop(occupied);
    assert!(registration.poll_wait(release, &mut task).is_ready());
    let retry = budget.try_reserve_bytes(1).unwrap();
    assert!(retry.belongs_to(&budget));
    drop(retry);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);

    for original in [
        AllocationRefusal::DemandOverflow,
        AllocationRefusal::ExceedsLimit {
            requested_bytes: 18,
            limit_bytes: 17,
        },
    ] {
        for error in [
            CommitteeAdmissionError::Admission(original.clone()),
            CommitteeAdmissionError::Buffer(PrepaidBufferError::Allocation(
                ChargedBufferError::Admission(original.clone()),
            )),
        ] {
            let VerificationReadError::Deferred(classified) = admission_error(3, error) else {
                panic!("original admission policy refusal must remain local")
            };
            assert_eq!(classified.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert_eq!(classified.allocation_refusal(), Some(&original));
            if original == AllocationRefusal::DemandOverflow {
                // No release or larger configured pool can repair an overflowing demand.
                let diagnostic = classified.to_string();
                assert_eq!(
                    classify_parent_service_deferral_for_test(classified),
                    PublicationError::RecoveryRequired(diagnostic),
                    "the actual parent-service boundary must retain terminal overflow"
                );
                continue;
            }
            let PublicationError::Deferred(returned) =
                classify_parent_service_deferral_for_test(classified)
            else {
                panic!("the actual parent-service boundary must retain original policy refusal")
            };
            assert_eq!(returned.allocation_refusal(), Some(&original));
            assert_eq!(returned.release_wait(), None);
        }
    }
}

#[test]
fn native_authority_allocator_refusals_preserve_unavailability_without_pool_release() {
    use crate::sumeragi::{
        driver::traits::PublicationError, executor::classify_parent_service_deferral_for_test,
    };
    use ivm::error::ExecutionDeferral;

    for error in [
        CommitteeAdmissionError::Buffer(PrepaidBufferError::Allocation(
            ChargedBufferError::Allocator {
                requested_bytes: 48,
            },
        )),
        CommitteeAdmissionError::KeyAllocation(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::Allocator {
                layout: Layout::array::<u8>(49).unwrap(),
            },
        )),
    ] {
        let VerificationReadError::Deferred(classified) = admission_error(3, error) else {
            panic!("physical allocator refusal is local, never source rejection")
        };
        assert_eq!(
            classified.reason(),
            ExecutionDeferral::AllocationUnavailable
        );
        assert_eq!(classified.allocation_refusal(), None);
        let PublicationError::Deferred(returned) =
            classify_parent_service_deferral_for_test(classified.clone())
        else {
            panic!("the actual parent-service boundary must retain allocator unavailability")
        };
        assert_eq!(returned.execution(), Some(&classified));
        assert_eq!(returned.allocation_refusal(), None);
        assert_eq!(returned.release_wait(), None);
    }
}
