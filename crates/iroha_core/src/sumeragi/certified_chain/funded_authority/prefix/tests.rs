//! Exact original prefix material, authority graph and sharing controls.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use std::{
    future::Future as _,
    pin::Pin,
    task::{Context, Waker},
};

fn fixture() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain
}
fn scheduled(parent: &CommittedBlock) -> &schedule::ScheduledConfig {
    let schedule::ScheduledSlot::Ready(slot) = &parent.commitment().schedule.next else {
        panic!("genuine successor")
    };
    slot
}

#[test]
fn exact_prefix_authority_retains_material_config_and_pairing_through_last_reader() {
    let chain = fixture();
    let parent = chain.committed(1);
    let source = scheduled(&parent);
    let bytes = FundedPrefixAuthority::demand(&source.epoch).unwrap();
    let budget = AllocationBudget::new(bytes);
    let mut validation = EpochValidationScope::new();
    let authority = FundedPrefixAuthority::admit(source, 2, &mut validation, &budget).unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        bytes,
        "HC958 prefix authority is charged to the captured original pool"
    );
    assert!(
        authority.belongs_to(&budget) && FundedPrefixAuthority::belongs_to(&authority, &budget)
    );
    assert_eq!(authority.material, source.epoch);
    assert_eq!(authority.config(), &source.height_config().unwrap());
    let material = authority.material.committee.as_ptr();
    let keys = authority.config().committee.members().as_ptr();
    let mut reader = None;
    let allocations = allocations_during(|| reader = Some(authority.clone()));
    assert_eq!(allocations, 0);
    let reader = reader.unwrap();
    drop(authority);
    assert_eq!(reader.material.committee.as_ptr(), material);
    assert_eq!(reader.config().committee.members().as_ptr(), keys);
    assert_eq!(budget.reserved_bytes(), bytes);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let moved = reader;
        assert_eq!(moved.material.committee.as_ptr(), material);
        panic!("controlled complete prefix authority unwind");
    }));
    assert!(result.is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prefix_authority_capacity_refusal_preserves_original_release_and_borrowed_source() {
    let chain = fixture();
    let parent = chain.committed(1);
    let source = scheduled(&parent);
    let bytes = FundedPrefixAuthority::allocation_bytes(&source.epoch).unwrap();
    let registration_bytes =
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(bytes + registration_bytes);
    let mut original_registration = budget.try_reserve_bytes(registration_bytes).unwrap();
    let mut registration = iroha_allocation::release::ReleaseRegistration::from_reservation(
        &mut original_registration,
    )
    .unwrap();
    drop(original_registration);
    let occupied = budget.try_reserve_bytes(bytes).unwrap();
    let source_pointer = source.epoch.committee.as_ptr();
    let mut validation = EpochValidationScope::new();
    validation.core_epoch(&source.epoch).unwrap();
    let mut refusal = None;
    let allocations = allocations_during(|| {
        refusal = Some(FundedPrefixAuthority::admit(
            source,
            2,
            &mut validation,
            &budget,
        ));
    });
    assert_eq!(
        allocations, 0,
        "capacity refusal creates no candidate graph"
    );
    let ExecutionAttemptError::Deferred(original) = refusal.unwrap().err().unwrap() else {
        panic!("original capacity refusal")
    };
    assert!(original.allocator_refusal().is_none());
    let Some(AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    }) = original.allocation_refusal()
    else {
        panic!("original release observation retained")
    };
    assert_eq!(*requested_bytes, bytes);
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    let foreign = AllocationBudget::new(bytes);
    drop(foreign.try_reserve_bytes(bytes).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    assert_eq!(source.epoch.committee.as_ptr(), source_pointer);
    drop(occupied);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    drop(wait);
    let retry = FundedPrefixAuthority::admit(source, 2, &mut validation, &budget).unwrap();
    assert!(retry.belongs_to(&budget));
    assert_eq!(retry.material, source.epoch);
    assert_eq!(retry.config(), &source.height_config().unwrap());
    drop(retry);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn foreign_prefix_authority_reservation_is_rejected_before_partition() {
    let chain = fixture();
    let parent = chain.committed(1);
    let source = scheduled(&parent);
    let bytes = FundedPrefixAuthority::demand(&source.epoch).unwrap();
    let budget = AllocationBudget::new(bytes);
    let foreign = AllocationBudget::new(bytes);
    let mut original = budget.try_reserve_bytes(bytes).unwrap();
    let (epoch, params) = source
        .core_parameters_with_validation(&mut EpochValidationScope::new())
        .unwrap();
    let result =
        FundedPrefixAuthority::from_reservation(source, epoch, params, 2, &foreign, &mut original);
    assert!(result.is_err());
    assert_eq!(
        original.remaining_bytes(),
        bytes,
        "prefix authority rejects a foreign pool before partition"
    );
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn prefix_authority_each_physical_layout_refuses_without_capacity_wait_and_retries() {
    let chain = fixture();
    let parent = chain.committed(1);
    let source = scheduled(&parent);
    let bytes = FundedPrefixAuthority::demand(&source.epoch).unwrap();
    let budget = AllocationBudget::new(bytes);
    // Warm only the bounded exact-value validation workspace, never graph storage.
    let mut validation = EpochValidationScope::new();
    validation.core_epoch(&source.epoch).unwrap();
    let layouts = [
        Layout::array::<ValidatorCommitteeMemberV1>(source.epoch.committee.len()).unwrap(),
        source.epoch.committee[0]
            .validator
            .public_key()
            .retained_allocation_layout(),
        Layout::array::<u8>(96).unwrap(),
        Layout::array::<PublicKey>(source.epoch.committee.len()).unwrap(),
        Layout::array::<u8>(48).unwrap(),
        Layout::new::<EpochConfig>(),
        Layout::from_size_align(
            iroha_crypto::bls::consensus::ConsensusAggregateScratch::<()>::backing_bytes(),
            8,
        )
        .unwrap(),
        FundedBlsCommittee::credential_allocation_layout(source.epoch.committee.len()).unwrap(),
        ChargedShared::<FundedPrefixAuthority>::allocation_layout(),
    ];
    for layout in layouts {
        let (result, refused) = refuse_one_layout_during(layout, || {
            FundedPrefixAuthority::admit(source, 2, &mut validation, &budget)
        });
        assert!(refused, "real original allocation {layout:?}");
        let ExecutionAttemptError::Deferred(error) = result.err().expect("physical refusal") else {
            panic!("allocator refusal must be local")
        };
        assert_eq!(
            error.reason(),
            ivm::error::ExecutionDeferral::AllocationUnavailable
        );
        assert!(error.allocation_refusal().is_none());
        assert!(error.allocator_refusal().is_some());
        assert_original_allocator_layout(&error, layout);
        assert_eq!(budget.reserved_bytes(), 0);
        let retry = FundedPrefixAuthority::admit(source, 2, &mut validation, &budget).unwrap();
        assert_eq!(retry.material, source.epoch);
        drop(retry);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

fn assert_original_allocator_layout(
    error: &crate::execution_attempt::ExecutionDeferred,
    layout: Layout,
) {
    let original = error.allocator_refusal().expect("original physical cause");
    let actual = original
        .vec_reserve_error()
        .map(|(_, actual)| actual)
        .or_else(|| match original.buffer_from_charge_error() {
            Some(ChargedBufferFromChargeError::Allocator { layout }) => Some(*layout),
            _ => None,
        });
    if let Some(actual) = actual {
        assert_eq!(
            actual, layout,
            "the exact original allocator layout survives"
        );
        return;
    }
    let requested = match original.buffer_error() {
        Some(ChargedBufferError::Allocator { requested_bytes }) => Some(*requested_bytes),
        _ => match original.shared_error() {
            Some(iroha_allocation::PrepaidSharedError::Allocator { requested_bytes }) => {
                Some(*requested_bytes)
            }
            _ => None,
        },
    };
    assert_eq!(
        requested,
        Some(layout.size()),
        "the original allocator demand survives without a capacity wait"
    );
}

#[test]
fn prefix_authority_exact_layout_census_has_no_unowned_backing() {
    let chain = fixture();
    let parent = chain.committed(1);
    let source = scheduled(&parent);
    let bytes = FundedPrefixAuthority::demand(&source.epoch).unwrap();
    let count = source.epoch.committee.len();
    let nested = source
        .epoch
        .committee
        .iter()
        .map(|member| {
            let key = member.validator.public_key();
            key.retained_allocation_layout().size() * 2
                + Layout::array::<u8>(member.proof_of_possession.len())
                    .unwrap()
                    .size()
                + Layout::array::<u8>(key.borrowed_parts().unwrap().1.len())
                    .unwrap()
                    .size()
        })
        .sum::<usize>();
    let roots = Layout::array::<ValidatorCommitteeMemberV1>(count)
        .unwrap()
        .size()
        + Layout::array::<PublicKey>(count).unwrap().size()
        + Layout::new::<EpochConfig>().size()
        + iroha_crypto::bls::consensus::ConsensusAggregateScratch::<()>::backing_bytes()
        + FundedBlsCommittee::credential_allocation_layout(count)
            .unwrap()
            .size()
        + ChargedShared::<FundedPrefixAuthority>::allocation_layout().size();
    assert_eq!(bytes, roots + nested);
    let budget = AllocationBudget::new(bytes);
    let mut validation = EpochValidationScope::new();
    validation.core_epoch(&source.epoch).unwrap();
    let mut owner = None;
    let count_allocations = allocations_during(|| {
        owner = Some(FundedPrefixAuthority::admit(source, 2, &mut validation, &budget).unwrap());
    });
    assert_eq!(
        count_allocations,
        6 + 4 * count,
        "six graph backings and material key/proof, config key and credential key per member"
    );
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn fresh_prefix_epoch_validation_has_no_heap_scratch() {
    let chain = fixture();
    let parent = chain.committed(1);
    let source = scheduled(&parent);
    let committee = source.epoch.committee.as_ptr();
    let original = norito::encode_canonical(&source.epoch).unwrap();
    let mut result = None;
    let allocations = allocations_during(|| result = Some(source.epoch.validate()));
    result.unwrap().unwrap();
    assert_eq!(
        allocations, 0,
        "complete native epoch validation borrows its graph"
    );

    let mut result = None;
    let allocations = allocations_during(|| result = Some(source.epoch.context_id()));
    let context = result.unwrap().unwrap();
    assert_eq!(
        allocations, 0,
        "complete epoch identity streams without heap scratch"
    );

    let mut validation = EpochValidationScope::new();
    let mut result = None;
    let allocations = allocations_during(|| result = Some(validation.core_epoch(&source.epoch)));
    let epoch = result.unwrap().unwrap();
    assert_eq!(epoch.id.context.0, context);
    assert_eq!(
        allocations, 0,
        "a fresh epoch scope stores only its inline snapshot"
    );

    let mut validation = EpochValidationScope::new();
    let mut result = None;
    let allocations = allocations_during(|| {
        result = Some(source.core_parameters_with_validation(&mut validation));
    });
    let (actual_epoch, params) = result.unwrap().unwrap();
    assert_eq!(actual_epoch, epoch);
    assert_eq!(params, source.params.to_core());
    assert_eq!(
        allocations, 0,
        "fresh prefix core parameters create no heap scratch"
    );
    assert_eq!(source.epoch.committee.as_ptr(), committee);
    assert_eq!(norito::encode_canonical(&source.epoch).unwrap(), original);
}

#[test]
fn prefix_authority_every_nested_member_allocation_refuses_and_retries_original_pool() {
    let chain = fixture();
    let parent = chain.committed(1);
    let source = scheduled(&parent);
    let bytes = FundedPrefixAuthority::demand(&source.epoch).unwrap();
    let budget = AllocationBudget::new(bytes);
    let source_pointer = source.epoch.committee.as_ptr();
    let source_members: Vec<_> = source
        .epoch
        .committee
        .iter()
        .map(|member| {
            (
                member
                    .validator
                    .public_key()
                    .borrowed_parts()
                    .unwrap()
                    .1
                    .as_ptr(),
                member.proof_of_possession.as_ptr(),
            )
        })
        .collect();
    let mut validation = EpochValidationScope::new();
    validation.core_epoch(&source.epoch).unwrap();
    for (index, member) in source.epoch.committee.iter().enumerate() {
        let retained_key = member.validator.public_key().retained_allocation_layout();
        let layouts = [
            retained_key,
            Layout::array::<u8>(member.proof_of_possession.len()).unwrap(),
            Layout::array::<u8>(
                member
                    .validator
                    .public_key()
                    .borrowed_parts()
                    .unwrap()
                    .1
                    .len(),
            )
            .unwrap(),
            retained_key,
        ];
        for (stage, layout) in layouts.into_iter().enumerate() {
            let result = match stage {
                0 | 1 => {
                    let stage = if stage == 0 {
                        MaterialAllocation::Key(index)
                    } else {
                        MaterialAllocation::Proof(index)
                    };
                    REFUSE_MATERIAL_AT.with(|selected| selected.set(Some(stage)));
                    let result = FundedPrefixAuthority::admit(source, 2, &mut validation, &budget);
                    assert!(REFUSE_MATERIAL_AT.with(|selected| selected.take().is_none()));
                    result
                }
                2 => {
                    super::super::REFUSE_CONFIG_KEY_AT.with(|selected| selected.set(Some(index)));
                    let result = FundedPrefixAuthority::admit(source, 2, &mut validation, &budget);
                    assert!(
                        super::super::REFUSE_CONFIG_KEY_AT
                            .with(|selected| selected.take().is_none())
                    );
                    result
                }
                3 => {
                    let (result, reached) =
                        crate::sumeragi::crypto::funded::refuse_key_allocation_at(index, || {
                            FundedPrefixAuthority::admit(source, 2, &mut validation, &budget)
                        });
                    assert!(reached, "credential key index {index} was allocated");
                    result
                }
                _ => unreachable!("four nested member allocations"),
            };
            let ExecutionAttemptError::Deferred(error) = result.err().expect("physical refusal")
            else {
                panic!("physical allocator failure remains local")
            };
            assert_eq!(
                error.reason(),
                ivm::error::ExecutionDeferral::AllocationUnavailable
            );
            assert!(
                error.allocation_refusal().is_none(),
                "physical failure creates no capacity-release wait"
            );
            assert_original_allocator_layout(&error, layout);
            assert_eq!(
                budget.reserved_bytes(),
                0,
                "partial candidate retires for member {index}, stage {stage}"
            );
            assert_eq!(source.epoch.committee.as_ptr(), source_pointer);
            for (member, pointers) in source.epoch.committee.iter().zip(&source_members) {
                assert_eq!(
                    member
                        .validator
                        .public_key()
                        .borrowed_parts()
                        .unwrap()
                        .1
                        .as_ptr(),
                    pointers.0
                );
                assert_eq!(member.proof_of_possession.as_ptr(), pointers.1);
            }
            let retry = FundedPrefixAuthority::admit(source, 2, &mut validation, &budget).unwrap();
            assert!(retry.belongs_to(&budget));
            assert_eq!(retry.material, source.epoch);
            assert_eq!(budget.reserved_bytes(), bytes);
            drop(retry);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}
