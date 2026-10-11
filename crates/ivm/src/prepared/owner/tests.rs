//! Prepared shell credit is attached to its actual original shared owner.

use super::*;
use crate::prepared::{PreparedContract, PreparedContractParts};
use iroha_allocation::AllocationRefusal;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

fn fixture() -> PreparedContract {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            r#"seiyaku PreparedOwners { permission Run;
            kotoage fn zebra() authorize(Run) {}
            kotoage fn alpha() authorize(Run) {}
        }"#,
        )
        .expect("compile actual artifact");
    crate::prepare_contract(Arc::from(artifact)).expect("admit actual artifact")
}

// Keep this cut's new owners isolated: all pre-existing children are diagnostic
// owners borrowed from an independently admitted fixture.
fn parts(prepared: &PreparedContract) -> PreparedContractParts {
    PreparedContractParts {
        artifact: prepared.shared_artifact(),
        metadata: prepared.metadata().clone(),
        manifest: prepared.manifest().clone(),
        header_len: prepared.header_len(),
        code_offset: prepared.code_offset(),
        code_hash: prepared.code_hash(),
        contract_interface: prepared.shared_contract_interface(),
        literal_table: prepared.literal_table().clone(),
        decoded: prepared.decoded().clone(),
        prepared_program: prepared.prepared_program().clone(),
        control_flow: prepared.inner.control_flow.clone(),
    }
}

#[test]
fn shell_reserves_before_physical_allocation_and_refunds_unused_unwind() {
    let bytes = ChargedShared::<PreparedContractInner>::allocation_layout().size();
    let budget = AllocationBudget::new(0);
    assert!(
        matches!(PreparedShell::reserve(Some(&budget)), Err(VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit { requested_bytes, .. })) if requested_bytes == bytes)
    );
    assert_eq!(budget.peak_reserved_bytes(), 0);
    budget.set_limit_bytes(bytes);
    let occupied = budget.try_reserve_bytes(bytes).unwrap();
    assert!(matches!(
        PreparedShell::reserve(Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    drop(occupied);
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let (shell, retention) = PreparedShell::reserve(Some(&budget)).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes);
        let _owners = (shell, retention);
        panic!("preparation abandoned before initialization");
    }));
    assert!(panic.is_err());
    assert_eq!(budget.reserved_bytes(), 0);
    let original = PreparedShell::reserve(Some(&budget)).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn shell_and_index_hold_original_credit_until_final_borrower_after_shrink() {
    let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    let source = fixture();
    let shell_bytes = ChargedShared::<PreparedContractInner>::allocation_layout().size();
    let index_bytes = std::mem::size_of::<crate::prepared::entrypoints::EntrypointIndex>()
        * source.contract_interface().entrypoints.len();
    let budget = AllocationBudget::new(1024 * 1024);
    let owner = PreparedContract::from_parts(parts(&source), Some(&budget)).unwrap();
    assert_eq!(budget.reserved_bytes(), shell_bytes + index_bytes);
    assert!(
        budget.peak_reserved_bytes() > budget.reserved_bytes(),
        "scratch releases before publication"
    );
    let PreparedOwner::Funded(control) = &owner.inner else {
        panic!("production shell must be funded")
    };
    assert!(control.belongs_to(&budget));
    assert!(!control.belongs_to(&AllocationBudget::new(budget.limit_bytes())));
    assert!(
        !owner.try_retain_allocations(),
        "zero retention must keep this execution cold"
    );
    let borrower = owner.clone();
    assert!(PreparedContract::ptr_eq(&owner, &borrower));
    assert!(!PreparedContract::ptr_eq(&owner, &source));
    drop(owner);
    budget.set_limit_bytes(0);
    for name in ["alpha", "zebra"] {
        assert_eq!(borrower.entrypoint_pc(name), source.entrypoint_pc(name));
        assert_eq!(
            borrower.entrypoint_descriptor(name),
            source.entrypoint_descriptor(name)
        );
        assert_eq!(
            borrower.entrypoint_requires_private_inputs(name),
            Some(false)
        );
    }
    assert_eq!(budget.reserved_bytes(), shell_bytes + index_bytes);
    let panic = catch_unwind(AssertUnwindSafe(move || {
        let _final_owner = borrower;
        panic!("borrowed execution unwinds");
    }));
    assert!(panic.is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn preparation_refunds_shell_after_index_refusal_then_retries_same_parts() {
    let source = fixture();
    let shell_bytes = ChargedShared::<PreparedContractInner>::allocation_layout().size();
    let budget = AllocationBudget::new(shell_bytes);
    assert!(matches!(
        PreparedContract::from_parts(parts(&source), Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(budget.peak_reserved_bytes(), shell_bytes);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(1024 * 1024);
    let owner = PreparedContract::from_parts(parts(&source), Some(&budget)).unwrap();
    assert_eq!(owner.code_hash(), source.code_hash());
    assert_eq!(
        owner.entrypoint_descriptor("zebra"),
        source.entrypoint_descriptor("zebra")
    );
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_funded_preparation_keeps_shell_and_index_through_concurrent_final_release() {
    let source = fixture();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let owner = crate::prepare_contract_with_memory_budget(source.artifact(), &budget).unwrap();
    let charged = budget.reserved_bytes();
    assert!(charged > ChargedShared::<PreparedContractInner>::allocation_layout().size());
    let other = owner.clone();
    assert_eq!(
        budget.reserved_bytes(),
        charged,
        "cloning cannot charge shared storage twice"
    );
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            drop(other);
        });
        barrier.wait();
        drop(owner);
    });
    assert_eq!(budget.reserved_bytes(), 0);
}
