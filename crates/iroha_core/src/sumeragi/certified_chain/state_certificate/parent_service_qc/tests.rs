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
