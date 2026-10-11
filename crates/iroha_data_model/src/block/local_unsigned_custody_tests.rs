//! Local empty-leaf admission retains canonical bytes and the original physical pool.
//! These structural fixtures do not establish block authority or complete child funding.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal};

fn original_unsigned() -> SignedBlock {
    let mut block = output_test_support::proposal(1);
    // Structural local-construction fixture only; production never erases signatures here.
    block.signatures = BlockSignatures::default();
    assert!(block.is_resultless_proposal());
    assert_eq!(block.signatures().len(), 0);
    block
}

#[test]
fn local_unsigned_signature_admission_preserves_wire_children_and_exact_control() {
    let mut block = original_unsigned();
    let wire = block.encode_wire().unwrap();
    let header = block.header();
    let children = block.external_entrypoints_slice().as_ptr();
    let pool = AllocationBudget::new(BlockSignatures::allocation_layout().size());
    block
        .prepare_local_unsigned_signature_custody(&pool)
        .unwrap();
    assert!(block.signatures_admitted_to(&pool));
    assert_eq!(block.header(), header);
    assert_eq!(block.external_entrypoints_slice().as_ptr(), children);
    assert_eq!(block.encode_wire().unwrap(), wire);
    assert!(block.matches_resultless_proposal_wire(&wire).unwrap());
    assert_eq!(
        pool.reserved_bytes(),
        BlockSignatures::allocation_layout().size()
    );
    // Clone only the actual immutable leaf, never the SignedBlock or its payload DTOs.
    let leaf = block.signatures.clone();
    assert!(BlockSignatures::ptr_eq(&leaf, &block.signatures));
    assert!(leaf.admitted_to(&pool));
    block
        .prepare_local_unsigned_signature_custody(&pool)
        .unwrap();
    assert!(BlockSignatures::ptr_eq(&leaf, &block.signatures));
    assert_eq!(
        pool.reserved_bytes(),
        BlockSignatures::allocation_layout().size()
    );
    drop(block);
    assert_eq!(
        pool.reserved_bytes(),
        BlockSignatures::allocation_layout().size()
    );
    drop(leaf);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn local_unsigned_signature_admission_short_limit_keeps_original_and_retries() {
    let mut block = original_unsigned();
    let wire = block.encode_wire().unwrap();
    let children = block.external_entrypoints_slice().as_ptr();
    let demand = BlockSignatures::allocation_layout().size();
    let pool = AllocationBudget::new(demand - 1);
    let error = block
        .prepare_local_unsigned_signature_custody(&pool)
        .unwrap_err();
    assert!(
        matches!(error, BlockSignatureCustodyError::ControlAdmission(
        AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes }
    ) if requested_bytes == demand && limit_bytes == demand - 1)
    );
    assert!(!block.signatures_admitted_to(&pool));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(block.external_entrypoints_slice().as_ptr(), children);
    assert_eq!(block.encode_wire().unwrap(), wire);
    // A same-pool operator policy change is explicit; it does not replace the original input.
    pool.set_limit_bytes(demand);
    block
        .prepare_local_unsigned_signature_custody(&pool)
        .unwrap();
    assert!(block.signatures_admitted_to(&pool));
    assert_eq!(block.external_entrypoints_slice().as_ptr(), children);
    assert_eq!(block.encode_wire().unwrap(), wire);
    drop(block);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn local_unsigned_signature_admission_rejects_foreign_pool_without_replacing_leaf() {
    let mut block = original_unsigned();
    let demand = BlockSignatures::allocation_layout().size();
    let pool = AllocationBudget::new(demand);
    let foreign = AllocationBudget::new(demand);
    block
        .prepare_local_unsigned_signature_custody(&pool)
        .unwrap();
    let leaf = block.signatures.clone();
    let wire = block.encode_wire().unwrap();
    assert!(matches!(
        block.prepare_local_unsigned_signature_custody(&foreign),
        Err(BlockSignatureCustodyError::ForeignPool)
    ));
    assert!(BlockSignatures::ptr_eq(&leaf, &block.signatures));
    assert_eq!(block.encode_wire().unwrap(), wire);
    assert!(block.signatures_admitted_to(&pool));
    assert!(!block.signatures_admitted_to(&foreign));
    assert_eq!(pool.reserved_bytes(), demand);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn local_unsigned_signature_admission_cannot_erase_signed_or_executed_profile() {
    let pool = AllocationBudget::new(1 << 20);
    let mut signed = output_test_support::proposal(1);
    assert_eq!(signed.signatures().len(), 1);
    let wire = signed.encode_wire().unwrap();
    let children = signed.external_entrypoints_slice().as_ptr();
    assert!(matches!(
        signed.prepare_local_unsigned_signature_custody(&pool),
        Err(BlockSignatureCustodyError::UnsignedProfile)
    ));
    assert_eq!(signed.external_entrypoints_slice().as_ptr(), children);
    assert_eq!(signed.signatures().len(), 1);
    assert_eq!(signed.encode_wire().unwrap(), wire);
    let mut executed = original_unsigned();
    output_test_support::install_network(&mut executed, vec![Ok(vec![])]).unwrap();
    let wire = executed.encode_wire().unwrap();
    let children = executed.external_entrypoints_slice().as_ptr();
    assert!(!executed.is_resultless_proposal());
    assert!(matches!(
        executed.prepare_local_unsigned_signature_custody(&pool),
        Err(BlockSignatureCustodyError::UnsignedProfile)
    ));
    assert_eq!(executed.external_entrypoints_slice().as_ptr(), children);
    assert_eq!(executed.encode_wire().unwrap(), wire);
    assert_eq!(pool.reserved_bytes(), 0);
}
