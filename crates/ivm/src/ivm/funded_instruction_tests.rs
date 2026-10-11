//! State-owned instruction arrays never borrow diagnostic or foreign-pool credit.

use super::*;

const LIMIT: usize = 128 * 1024 * 1024;

fn artifact() -> Vec<u8> {
    kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Funded { view fn main() authorize(anyone) -> bool { true } }")
        .unwrap()
}

#[test]
fn funded_generic_loading_cannot_borrow_a_warm_diagnostic_cache() {
    let mut program = ProgramMetadata::default().encode();
    program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
    let mut diagnostic = IVM::new(100);
    diagnostic.load_program(&program).unwrap();
    let budget = AllocationBudget::new(LIMIT);
    let mut funded = IVM::try_new_with_memory_budget(100, &budget).unwrap();
    let original = budget.reserved_bytes();
    budget.set_limit_bytes(original);
    assert!(matches!(
        funded.load_program(&program),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), original);
    budget.set_limit_bytes(LIMIT);
    funded.load_program(&program).unwrap();
    let decoded = funded.predecoded.as_ref().unwrap().clone();
    let prepared = funded.prepared.as_ref().unwrap().clone();
    assert!(decoded.belongs_to(&budget));
    assert!(prepared.belongs_to(&budget));
    assert!(!crate::cache_memory::SharedAllocation::ptr_eq(
        &decoded,
        diagnostic.predecoded.as_ref().unwrap(),
    ));
    funded.run().unwrap();
    diagnostic.run().unwrap();
    assert_eq!(funded.remaining_gas(), diagnostic.remaining_gas());
    drop(funded);
    assert!(budget.reserved_bytes() > 0);
    drop((decoded, prepared));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prepared_loading_rebinds_foreign_arrays_to_the_actual_vm_pool() {
    let artifact = artifact();
    let first = AllocationBudget::new(LIMIT);
    let contract = crate::prepare_contract_with_memory_budget(&artifact, &first).unwrap();
    assert!(contract.decoded().belongs_to(&first));
    assert!(contract.prepared_program().belongs_to(&first));
    let first_charge = first.reserved_bytes();
    let second = AllocationBudget::new(LIMIT);
    let mut vm = IVM::try_new_with_memory_budget(100, &second).unwrap();
    let original = second.reserved_bytes();
    second.set_limit_bytes(original);
    assert!(matches!(
        vm.load_prepared(&contract),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(second.reserved_bytes(), original);
    assert_eq!(first.reserved_bytes(), first_charge);
    second.set_limit_bytes(LIMIT);
    vm.load_prepared(&contract).unwrap();
    assert!(vm.predecoded.as_ref().unwrap().belongs_to(&second));
    assert!(vm.prepared.as_ref().unwrap().belongs_to(&second));
    assert!(!crate::cache_memory::SharedAllocation::ptr_eq(
        vm.predecoded.as_ref().unwrap(),
        contract.decoded(),
    ));
    assert_eq!(
        vm.predecoded.as_ref().unwrap().as_ref(),
        contract.decoded().as_ref()
    );
    drop(contract);
    assert_eq!(first.reserved_bytes(), 0);
    drop(vm);
    assert_eq!(second.reserved_bytes(), 0);
}

#[test]
fn same_pool_preparation_and_template_keep_one_charge_until_final_borrower() {
    let budget = AllocationBudget::new(LIMIT);
    let contract = crate::prepare_contract_with_memory_budget(&artifact(), &budget).unwrap();
    let mut vm = IVM::try_new_with_memory_budget(100, &budget).unwrap();
    vm.load_prepared(&contract).unwrap();
    assert!(crate::cache_memory::SharedAllocation::ptr_eq(
        vm.predecoded.as_ref().unwrap(),
        contract.decoded(),
    ));
    let decoded = vm.predecoded.as_ref().unwrap().clone();
    let prepared = vm.prepared.as_ref().unwrap().clone();
    let instruction_bytes = decoded.allocation_bytes() + prepared.ops.allocation_bytes();
    let template = vm.try_runtime_template().unwrap();
    let before = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(budget.reserved_bytes(), before);
    drop(contract);
    drop(vm);
    assert!(budget.reserved_bytes() > 0);
    drop(template);
    assert_eq!(budget.reserved_bytes(), instruction_bytes);
    drop((decoded, prepared));
    assert_eq!(budget.reserved_bytes(), 0);
}
