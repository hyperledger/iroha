//! Typed semantic-QC refusal, explicit fixture admission and immutable source controls.
use super::*;
use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

fn fixture() -> (CertifiedTestChain, SignedBlock) {
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    let mut proposal = chain.proposal(Some(4_000), Vec::new());
    let mut effects = proposal.npos_consensus_effects().unwrap().clone();
    let input = effects
        .parent_service_commit_qc
        .as_ref()
        .unwrap()
        .as_slice()
        .to_vec();
    effects.parent_service_commit_qc =
        Some(iroha_data_model::consensus::NposParentServiceCommitQc::from_untrusted(input));
    proposal.set_npos_consensus_effects(Some(effects));
    (chain, proposal)
}

#[test]
fn semantic_qc_requires_original_admitted_source_and_rejects_same_wire_substitution() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, mut proposal) = fixture();
    let pool = chain.state().ivm_execution_budget();
    let mut pending = ParentServiceQcPreparation::default();
    let before = pool.reserved_bytes();
    assert!(matches!(
        pending.prepare(&proposal, &pool),
        Err(ParentServiceError::Source(_))
    ));
    assert_eq!(pool.reserved_bytes(), before);
    assert_eq!(pending.retained_pointers(), (0, 0));
    let mut replacement = proposal.clone();
    admit_parent_service_fixture(&mut proposal, &pool).unwrap();
    admit_parent_service_fixture(&mut replacement, &pool).unwrap();
    assert_eq!(
        proposal.encode_wire().unwrap(),
        replacement.encode_wire().unwrap()
    );
    let baseline = pool.reserved_bytes();
    pending.prepare(&proposal, &pool).unwrap();
    let pointers = pending.retained_pointers();
    assert!(pointers.0 != 0 && pointers.1 != 0);
    let bytes = pool.reserved_bytes();
    assert!(matches!(
        pending.prepare(&replacement, &pool),
        Err(ParentServiceError::Source(_))
    ));
    assert!(matches!(
        pending.get(&replacement, &pool),
        Err(ParentServiceError::Source(_))
    ));
    let foreign = AllocationBudget::new(pool.limit_bytes());
    assert!(matches!(
        pending.prepare(&proposal, &foreign),
        Err(ParentServiceError::Source(_))
    ));
    assert!(matches!(
        pending.get(&proposal, &foreign),
        Err(ParentServiceError::Source(_))
    ));
    assert_eq!(pool.reserved_bytes(), bytes);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(pending.retained_pointers(), pointers);
    pending.prepare(&proposal, &pool).unwrap();
    let qc = pending.get(&proposal, &pool).unwrap();
    assert_eq!(
        norito::encode_canonical(qc).unwrap(),
        proposal
            .npos_consensus_effects()
            .unwrap()
            .parent_service_commit_qc
            .as_ref()
            .unwrap()
            .as_slice()
    );
    drop(pending);
    assert_eq!(pool.reserved_bytes(), baseline);
}

#[test]
fn semantic_qc_error_transport_retains_exact_original_capacity_and_allocator_fields() {
    use iroha_allocation::{
        AllocationRefusal, ChargedBufferFromChargeError, SharedFromChargeError,
    };
    let pool = AllocationBudget::new(128);
    let blocker = pool.try_reserve_bytes(128).unwrap();
    let original = pool.try_reserve_bytes(8).unwrap_err();
    assert!(matches!(
        &original,
        AllocationRefusal::Capacity {
            requested_bytes: 8,
            reserved_bytes: 128,
            limit_bytes: 128,
            ..
        }
    ));
    let expected = original.clone();
    let ParentServiceError::Deferred(actual) = custody_error(QcCustodyError::Admission(original))
    else {
        panic!("original capacity transport")
    };
    assert_eq!(
        actual.allocation_refusal(),
        Some(&expected),
        "parent-service semantic QC must preserve the original capacity cause"
    );
    let transported =
        crate::execution_attempt::ExecutionDeferred::try_from_vm_error(actual.into_vm_error())
            .unwrap();
    assert_eq!(transported.allocation_refusal(), Some(&expected));
    let layout = std::alloc::Layout::from_size_align(17, 8).unwrap();
    let ParentServiceError::Deferred(actual) =
        custody_error(QcCustodyError::Decode(PreparedDecodeError::Destination(
            QcFieldError::BitmapBacking(ChargedBufferFromChargeError::Allocator { layout }),
        )))
    else {
        panic!("original bitmap allocator transport")
    };
    assert_eq!(
        actual
            .allocator_refusal()
            .unwrap()
            .buffer_from_charge_error(),
        Some(&ChargedBufferFromChargeError::Allocator { layout })
    );
    let ParentServiceError::Deferred(actual) = custody_error(QcCustodyError::ControlBacking(
        SharedFromChargeError::Allocator { layout },
    )) else {
        panic!("original control allocator transport")
    };
    assert_eq!(
        actual
            .allocator_refusal()
            .unwrap()
            .shared_from_charge_error(),
        Some(&SharedFromChargeError::Allocator { layout })
    );
    let ParentServiceError::Deferred(actual) = custody_error(QcCustodyError::LedgerBacking(
        ChargedBufferFromChargeError::Allocator { layout },
    )) else {
        panic!("original ledger allocator transport")
    };
    assert_eq!(
        actual
            .allocator_refusal()
            .unwrap()
            .buffer_from_charge_error(),
        Some(&ChargedBufferFromChargeError::Allocator { layout })
    );
    assert!(matches!(
        custody_error(QcCustodyError::Source),
        ParentServiceError::Source(_)
    ));
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), 0);
}

/// Only a model projection fixture; genuine lane authority is covered by the lane-store test.
fn projected_fixture() -> (CertifiedTestChain, SignedBlock, SignedBlock) {
    let (chain, mut original) = fixture();
    let mut context = original.execution_context().unwrap().clone();
    context
        .lane_merge
        .get_or_insert(iroha_data_model::sumeragi_lanes::SumeragiLaneMergeSection {
            merges: Vec::new(),
            time_floor_ms: 0,
            merged_count: 0,
        });
    original.set_execution_context(Some(context));
    admit_parent_service_fixture(&mut original, &chain.state().ivm_execution_budget()).unwrap();
    let input = original.external_entrypoints_slice()[0].clone();
    let context = original.execution_context().unwrap().external[0].clone();
    let expanded = original
        .clone()
        .with_merged_entrypoints(vec![input], vec![context])
        .unwrap();
    assert_ne!(original.hash(), expanded.hash());
    (chain, original, expanded)
}

#[test]
fn semantic_qc_projected_lend_preserves_original_source_pool_and_proposal_checks() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, original, expanded) = projected_fixture();
    let pool = chain.state().ivm_execution_budget();
    let foreign = AllocationBudget::new(pool.limit_bytes());
    for first in [&original, &expanded] {
        let mut pending = ParentServiceQcPreparation::default();
        pending.prepare(first, &pool).unwrap();
        let pointers = pending.retained_pointers();
        assert_ne!(pointers.0, 0);
        assert_ne!(pointers.1, 0);
        let reserved = pool.reserved_bytes();
        pending.prepare(&expanded, &pool).unwrap();
        pending.get(&expanded, &pool).unwrap();
        pending.get(&original, &pool).unwrap();
        assert!(matches!(
            pending.prepare(&expanded, &foreign),
            Err(ParentServiceError::Source(_))
        ));
        assert!(matches!(
            pending.get(&expanded, &foreign),
            Err(ParentServiceError::Source(_))
        ));
        let mut changed = expanded.clone();
        let mut context = changed.execution_context().unwrap().clone();
        context.lane_merge.as_mut().unwrap().time_floor_ms += 1;
        changed.set_execution_context(Some(context));
        assert!(matches!(
            pending.prepare(&changed, &pool),
            Err(ParentServiceError::Source(_))
        ));
        assert!(matches!(
            pending.get(&changed, &pool),
            Err(ParentServiceError::Source(_))
        ));
        assert_eq!(pending.retained_pointers(), pointers);
        assert_eq!(pool.reserved_bytes(), reserved);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}

#[test]
fn semantic_qc_projection_refusal_retains_first_input_before_any_rebinding() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, original, mut malformed) = projected_fixture();
    let pool = chain.state().ivm_execution_budget();
    let mut context = malformed.execution_context().unwrap().clone();
    context.lane_merge.as_mut().unwrap().merged_count = u32::MAX;
    malformed.set_execution_context(Some(context));
    let first_hash = malformed.hash();
    let first_source = malformed
        .npos_consensus_effects()
        .unwrap()
        .parent_service_commit_qc
        .as_ref()
        .unwrap()
        .admitted_source()
        .unwrap();
    let mut replacement = malformed.clone();
    let mut effects = replacement.npos_consensus_effects().unwrap().clone();
    effects.parent_service_commit_qc = Some(
        iroha_data_model::consensus::NposParentServiceCommitQc::from_untrusted(
            first_source.as_slice().to_vec(),
        ),
    );
    replacement.set_npos_consensus_effects(Some(effects));
    admit_parent_service_fixture(&mut replacement, &pool).unwrap();
    assert_eq!(replacement.hash(), first_hash);
    let mut pending = ParentServiceQcPreparation::default();
    let reserved = pool.reserved_bytes();
    assert!(matches!(
        pending.prepare(&malformed, &pool),
        Err(ParentServiceError::Invalid(_))
    ));
    let captured = pending.original.as_ref().unwrap();
    assert!(matches!(captured.0, ProposalIdentity::Captured(hash) if hash == first_hash));
    assert!(ChargedShared::ptr_eq(&captured.1, first_source));
    assert!(captured.2.same_pool(&pool));
    assert!(pending.pending.is_none() && pending.complete.is_none());
    let pointers = pending.retained_pointers();
    assert_eq!(pointers, (first_source.as_slice().as_ptr().addr(), 0));
    // All substitutions refuse before trying the still-malformed projection.
    assert!(matches!(
        pending.prepare(&original, &pool),
        Err(ParentServiceError::Source(_))
    ));
    assert!(matches!(
        pending.prepare(&replacement, &pool),
        Err(ParentServiceError::Source(_))
    ));
    let foreign = AllocationBudget::new(pool.limit_bytes());
    assert!(matches!(
        pending.prepare(&malformed, &foreign),
        Err(ParentServiceError::Source(_))
    ));
    assert!(matches!(
        pending.prepare(&malformed, &pool),
        Err(ParentServiceError::Invalid(_))
    ));
    assert_eq!(pending.retained_pointers(), pointers);
    assert_eq!(pool.reserved_bytes(), reserved);
    assert_eq!(foreign.reserved_bytes(), 0);
}
