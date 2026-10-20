//! Actual finite-pool and physical allocator refusals over authenticated native sources.

use super::*;
use crate::{
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_allocation::AllocationRefusal;
use std::task::{Context, Waker};

fn fixture() -> (CertifiedTestChain, SignedBlock, ParentServicePreparation) {
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    let mut proposal = chain.proposal(Some(4_000), Vec::new());
    let pool = chain.state().ivm_execution_budget();
    admit_parent_service_fixture(&mut proposal, &pool).unwrap();
    let mut original = ParentServicePreparation::default();
    {
        let view = chain.state().view();
        original.prepare(&view, 3).unwrap();
        original.offered_qc.prepare(&proposal, &pool).unwrap();
        let (parent, current, authority, _, context) = original.inputs();
        verify_parent_service_relation(
            parent,
            current,
            original.offered_qc.get(&proposal, &pool).unwrap(),
            authority,
            context,
        )
        .unwrap();
    }
    (chain, proposal, original)
}

fn deferred(error: ParentServiceError) -> ExecutionDeferred {
    let ParentServiceError::Deferred(original) = error else {
        panic!("must preserve the original local allocation refusal: {error}")
    };
    original
}

#[test]
fn original_signer_late_capacity_retains_prefix_waiter_and_same_pool_retry() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, proposal, original) = fixture();
    let pool = chain.state().ivm_execution_budget();
    let view = chain.state().view();
    let (parent, current, _, _, _) = original.inputs();
    let qc = original.offered_qc.get(&proposal, &pool).unwrap();
    let indices: Vec<_> = qc.signers.ones().map(|index| index as usize).collect();
    assert_eq!(indices.len(), 3);
    let committee = &current.commitment().schedule.current.committee;
    let outer = Layout::array::<ChargedPublicKey>(indices.len())
        .unwrap()
        .size();
    let root = ChargedShared::<Keys>::allocation_layout().size();
    let first_key = committee[indices[0]]
        .validator
        .public_key()
        .retained_allocation_layout()
        .size();
    let second_layout = committee[indices[1]]
        .validator
        .public_key()
        .retained_allocation_layout();
    let demand = outer
        + root
        + indices
            .iter()
            .map(|index| {
                committee[*index]
                    .validator
                    .public_key()
                    .retained_allocation_layout()
                    .size()
            })
            .sum::<usize>();
    let mut registration = crate::unit_test_support::release_registration(&pool);
    let baseline = pool.reserved_bytes();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - baseline - outer - root - first_key)
        .unwrap();
    let mut pending = ParentServiceSignersPreparation::default();
    let first = deferred(
        pending
            .prepare(&view, &proposal, parent, current, qc)
            .unwrap_err(),
    );
    assert_eq!(
        pool.reserved_bytes(),
        pool.limit_bytes(),
        "signer refusal must retain every original charge and completed key prefix"
    );
    let expected = pool
        .try_reserve(second_layout)
        .err()
        .expect("original pool is full");
    assert_eq!(first.allocation_refusal(), Some(&expected));
    assert!(
        matches!(&expected, AllocationRefusal::Capacity {requested_bytes, reserved_bytes, limit_bytes, ..}
        if *requested_bytes == second_layout.size() && *reserved_bytes == pool.limit_bytes() && *limit_bytes == pool.limit_bytes())
    );
    let pointers = pending.retained_pointers();
    assert!(pointers.0 != 0 && pointers.1 != 0 && pointers.2 != 0);
    assert_eq!(
        pending
            .construction
            .as_ref()
            .unwrap()
            .keys
            .as_ref()
            .unwrap()
            .as_slice()
            .len(),
        1
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    let AllocationRefusal::Capacity { release, .. } = &expected else {
        unreachable!()
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(registration.poll_wait(release, &mut context).is_pending());
    let second = deferred(
        pending
            .prepare(&view, &proposal, parent, current, qc)
            .unwrap_err(),
    );
    assert_eq!(second.allocation_refusal(), Some(&expected));
    assert_eq!(pending.retained_pointers(), pointers);
    assert!(registration.poll_wait(release, &mut context).is_pending());
    assert!(pending.get(&view, &proposal, parent, current, qc).is_err());
    drop(blocker);
    assert!(registration.poll_wait(release, &mut context).is_ready());
    registration.cancel();
    assert_eq!(pool.reserved_bytes(), baseline + outer + root + first_key);
    pending
        .prepare(&view, &proposal, parent, current, qc)
        .unwrap();
    assert_eq!(pending.retained_pointers(), pointers);
    assert_eq!(pool.reserved_bytes(), baseline + demand);
    let mut held = None;
    assert_eq!(
        allocations_during(|| {
            let first = pending.get(&view, &proposal, parent, current, qc).unwrap();
            let second = pending.get(&view, &proposal, parent, current, qc).unwrap();
            assert!(ChargedShared::ptr_eq(&first.0, &second.0));
            held = Some((first, second));
        }),
        0,
        "completed lends must not clone or reallocate signer keys"
    );
    let (first, second) = held.unwrap();
    assert!(
        first.keys().eq(indices
            .iter()
            .map(|index| committee[*index].validator.public_key()))
    );
    drop(pending);
    assert_eq!(pool.reserved_bytes(), baseline + demand);
    drop(first);
    assert_eq!(pool.reserved_bytes(), baseline + demand);
    drop(second);
    assert_eq!(pool.reserved_bytes(), baseline);
}

#[test]
fn original_signer_physical_array_root_and_later_key_refusals_keep_exact_charges() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, proposal, original) = fixture();
    let pool = chain.state().ivm_execution_budget();
    let view = chain.state().view();
    let (parent, current, _, _, _) = original.inputs();
    let qc = original.offered_qc.get(&proposal, &pool).unwrap();
    let indices: Vec<_> = qc.signers.ones().map(|index| index as usize).collect();
    let committee = &current.commitment().schedule.current.committee;
    let array = Layout::array::<ChargedPublicKey>(indices.len()).unwrap();
    let root = ChargedShared::<Keys>::allocation_layout();
    let key = committee[indices[0]]
        .validator
        .public_key()
        .retained_allocation_layout();
    let baseline = pool.reserved_bytes();
    assert_eq!(
        committee[indices[1]]
            .validator
            .public_key()
            .retained_allocation_layout(),
        key
    );
    for (step, layout) in [array, root, key, key].into_iter().enumerate() {
        let mut pending = ParentServiceSignersPreparation::default();
        if step == 3 {
            let blocker = pool
                .try_reserve_bytes(
                    pool.limit_bytes() - baseline - array.size() - root.size() - key.size(),
                )
                .unwrap();
            assert!(matches!(
                deferred(
                    pending
                        .prepare(&view, &proposal, parent, current, qc)
                        .unwrap_err()
                )
                .allocation_refusal(),
                Some(AllocationRefusal::Capacity { .. })
            ));
            assert_eq!(
                pending
                    .construction
                    .as_ref()
                    .unwrap()
                    .keys
                    .as_ref()
                    .unwrap()
                    .as_slice()
                    .len(),
                1
            );
            drop(blocker);
        }
        let before = pending.retained_pointers();
        let (result, denied) = refuse_one_layout_during(layout, || {
            pending.prepare(&view, &proposal, parent, current, qc)
        });
        assert!(
            denied,
            "actual requested destination allocation must be reached"
        );
        let cause = deferred(result.unwrap_err());
        let expected = if step == 1 {
            AllocatorRefusal::try_from(SharedFromChargeError::Allocator { layout }).unwrap()
        } else {
            AllocatorRefusal::try_from(ChargedBufferFromChargeError::Allocator { layout }).unwrap()
        };
        let assert_original_cause = |cause: &ExecutionDeferred| {
            let actual = cause
                .allocator_refusal()
                .expect("original physical allocator cause");
            assert_eq!(
                actual.buffer_from_charge_error(),
                expected.buffer_from_charge_error()
            );
            assert_eq!(
                actual.shared_from_charge_error(),
                expected.shared_from_charge_error()
            );
            assert!(cause.allocation_refusal().is_none());
        };
        assert_original_cause(&cause);
        assert_eq!(
            pool.reserved_bytes(),
            baseline
                + array.size()
                + root.size()
                + match step {
                    2 => key.size(),
                    3 => 2 * key.size(),
                    _ => 0,
                }
        );
        if step == 3 {
            assert_eq!(pending.retained_pointers(), before);
        }
        let retained = pending.retained_pointers();
        let (retry, denied) = refuse_one_layout_during(layout, || {
            pending.prepare(&view, &proposal, parent, current, qc)
        });
        assert!(denied);
        assert_original_cause(&deferred(retry.unwrap_err()));
        assert_eq!(pending.retained_pointers(), retained);
        pending
            .prepare(&view, &proposal, parent, current, qc)
            .unwrap();
        assert!(pending.get(&view, &proposal, parent, current, qc).is_ok());
        drop(pending);
        assert_eq!(pool.reserved_bytes(), baseline);
    }
}

#[test]
fn original_signer_lend_refuses_same_wire_source_pool_cut_and_selection_substitution() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, proposal, original) = fixture();
    let pool = chain.state().ivm_execution_budget();
    let view = chain.state().view();
    let (parent, current, _, _, _) = original.inputs();
    let qc = original.offered_qc.get(&proposal, &pool).unwrap();
    let mut pending = ParentServiceSignersPreparation::default();
    pending
        .prepare(&view, &proposal, parent, current, qc)
        .unwrap();
    let pointers = pending.retained_pointers();
    let mut replacement = proposal.clone();
    let mut effects = proposal.npos_consensus_effects().unwrap().clone();
    effects.parent_service_commit_qc = Some(
        iroha_data_model::consensus::NposParentServiceCommitQc::from_untrusted(
            effects
                .parent_service_commit_qc
                .as_ref()
                .unwrap()
                .as_slice()
                .to_vec(),
        ),
    );
    replacement.set_npos_consensus_effects(Some(effects));
    admit_parent_service_fixture(&mut replacement, &pool).unwrap();
    assert_eq!(
        replacement.encode_wire().unwrap(),
        proposal.encode_wire().unwrap()
    );
    assert!(
        matches!(
            pending.prepare(&view, &replacement, parent, current, qc),
            Err(ParentServiceError::Source(_))
        ),
        "same-wire signer source substitution must refuse the retained original owner"
    );
    assert!(matches!(
        pending.get(&view, &replacement, parent, current, qc),
        Err(ParentServiceError::Source(_))
    ));
    let (other, _, _) = fixture();
    assert!(!other.state().ivm_execution_budget().same_pool(&pool));
    assert!(matches!(
        pending.get(&other.state().view(), &proposal, parent, current, qc),
        Err(ParentServiceError::Source(_))
    ));
    assert!(matches!(
        pending.get(&view, &proposal, current, parent, qc),
        Err(ParentServiceError::Source(_))
    ));
    let mut changed = qc.clone();
    changed.signers = iroha_sumeragi::types::Bitmap::new(4);
    assert!(matches!(
        pending.get(&view, &proposal, parent, current, &changed),
        Err(ParentServiceError::Source(_))
    ));
    assert_eq!(pending.retained_pointers(), pointers);
    assert!(pending.get(&view, &proposal, parent, current, qc).is_ok());
}
