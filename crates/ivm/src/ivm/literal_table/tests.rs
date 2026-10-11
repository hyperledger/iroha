//! Original-pool literal allocation, rebinding and final-owner reclamation.

use super::*;
use crate::{
    IVM,
    metadata::{LITERAL_SECTION_MAGIC, LiteralKindV1, ProgramMetadata, encode_literal_descriptor},
};
use iroha_allocation::AllocationRefusal;

fn program() -> Vec<u8> {
    let mut bytes = ProgramMetadata::default().encode();
    let mut pointer = (crate::pointer_abi::PointerType::Blob as u16)
        .to_be_bytes()
        .to_vec();
    pointer.push(1);
    pointer.extend_from_slice(&0_u32.to_be_bytes());
    pointer.extend_from_slice(iroha_crypto::Hash::new([]).as_ref());
    bytes.extend_from_slice(&LITERAL_SECTION_MAGIC);
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&(pointer.len() as u32 + 8).to_le_bytes());
    bytes.extend_from_slice(
        &encode_literal_descriptor(LiteralKindV1::PointerTlv, 32)
            .unwrap()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &encode_literal_descriptor(LiteralKindV1::I64, 32 + pointer.len() as u64)
            .unwrap()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&pointer);
    bytes.extend_from_slice(&i64::MIN.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
    bytes
}
fn decode(bytes: &[u8], budget: Option<&AllocationBudget>) -> Result<DecodedLiteralTable, VMError> {
    let parsed = ProgramMetadata::parse(bytes)?;
    decode_literal_table(
        bytes,
        parsed.header_len,
        parsed.literal_section,
        SyscallPolicy::AbiV1,
        budget,
    )
}
fn bytes(table: &DecodedLiteralTable) -> usize {
    table
        .entries
        .as_ref()
        .map_or(0, SharedAllocation::allocation_bytes)
        + table
            .pointer_starts
            .as_ref()
            .map_or(0, SharedAllocation::allocation_bytes)
}

#[test]
fn literal_arrays_refuse_original_pool_and_retry_without_payload_copies() {
    let program = program();
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        decode(&program, Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    budget.set_limit_bytes(4096);
    let table = decode(&program, Some(&budget)).unwrap();
    let exact = bytes(&table);
    assert_eq!(budget.reserved_bytes(), exact);
    assert_eq!(
        table.entries(),
        &[
            DecodedLiteral::Pointer(32),
            DecodedLiteral::I64(i64::MIN as u64)
        ]
    );
    assert_eq!(table.pointer_starts(), &[32]);
    assert_eq!(table.entries(), decode(&program, None).unwrap().entries());
    assert!(table.entries.as_ref().unwrap().belongs_to(&budget));
    assert!(table.pointer_starts.as_ref().unwrap().belongs_to(&budget));
    drop(table);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(exact);
    let occupied = budget.try_reserve_bytes(exact).unwrap();
    assert!(matches!(
        decode(&program, Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), exact);
    drop(occupied);
    drop(decode(&program, Some(&budget)).unwrap());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn second_array_refusal_and_foreign_rebind_leave_original_owners_intact() {
    let program = program();
    let first = AllocationBudget::new(4096);
    let original = decode(&program, Some(&first)).unwrap();
    let total = bytes(&original);
    let second = AllocationBudget::new(total - 1);
    for result in [
        decode(&program, Some(&second)),
        original.for_budget(&second),
    ] {
        assert!(matches!(
            result,
            Err(VMError::AllocationDeferred(
                AllocationRefusal::Capacity { .. }
            ))
        ));
        assert_eq!(second.reserved_bytes(), 0);
        assert_eq!(first.reserved_bytes(), total);
    }
    second.set_limit_bytes(total);
    let rebound = original.for_budget(&second).unwrap();
    assert!(!SharedAllocation::ptr_eq(
        original.entries.as_ref().unwrap(),
        rebound.entries.as_ref().unwrap()
    ));
    assert!(rebound.entries.as_ref().unwrap().belongs_to(&second));
    assert!(rebound.pointer_starts.as_ref().unwrap().belongs_to(&second));
    assert_eq!(rebound.entries(), original.entries());
    drop(original);
    assert_eq!(first.reserved_bytes(), 0);
    assert_eq!(second.reserved_bytes(), total);
    drop(rebound);
    assert_eq!(second.reserved_bytes(), 0);
}

#[test]
fn zero_retention_and_pool_shrink_keep_independent_final_owner_credit() {
    let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    let budget = AllocationBudget::new(4096);
    let table = decode(&program(), Some(&budget)).unwrap();
    assert!(!table.try_retain());
    let shared = table.for_budget(&budget).unwrap();
    assert!(SharedAllocation::ptr_eq(
        table.entries.as_ref().unwrap(),
        shared.entries.as_ref().unwrap()
    ));
    let pointers = shared.pointer_starts.clone().unwrap();
    let total = bytes(&table);
    budget.set_limit_bytes(0);
    drop(table);
    assert_eq!(budget.reserved_bytes(), total);
    drop(shared);
    assert_eq!(budget.reserved_bytes(), pointers.allocation_bytes());
    drop(pointers);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn empty_literals_need_no_execution_or_retention_control_owner() {
    let budget = AllocationBudget::new(0);
    let empty = decode(&ProgramMetadata::default().encode(), Some(&budget)).unwrap();
    assert!(empty.entries.is_none());
    assert!(empty.pointer_starts.is_none());
    assert_eq!(bytes(&empty.for_budget(&budget).unwrap()), 0);
    assert_eq!(budget.peak_reserved_bytes(), 0);
    assert!(DecodedLiteralTable::empty().entries.is_none());
}

#[test]
fn generic_runtime_and_snapshot_keep_literal_credit_through_warm_reset() {
    let budget = AllocationBudget::new(128 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(100, &budget).unwrap();
    let base = budget.reserved_bytes();
    budget.set_limit_bytes(base);
    assert!(matches!(
        vm.load_program(&program()),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), base);
    assert!(vm.literal_table.entries.is_none());
    budget.set_limit_bytes(128 * 1024 * 1024);
    vm.load_program(&program()).unwrap();
    let table = vm.literal_table.clone();
    assert!(table.entries.as_ref().unwrap().belongs_to(&budget));
    let snapshot = vm.try_clone_snapshot().unwrap();
    assert!(SharedAllocation::ptr_eq(
        table.entries.as_ref().unwrap(),
        snapshot.literal_table.entries.as_ref().unwrap()
    ));
    let template = vm.try_runtime_template().unwrap();
    let before = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(budget.reserved_bytes(), before);
    assert!(SharedAllocation::ptr_eq(
        table.entries.as_ref().unwrap(),
        vm.literal_table.entries.as_ref().unwrap()
    ));
    drop(vm);
    drop(template);
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), bytes(&table));
    drop(table);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prepared_loading_shares_original_literals_and_rebinds_foreign_pool() {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Literals { view fn main() authorize(anyone) -> int { 701 } }")
        .unwrap();
    let first = AllocationBudget::new(128 * 1024 * 1024);
    let contract = crate::prepare_contract_with_memory_budget(&artifact, &first).unwrap();
    assert!(!contract.literal_table().entries().is_empty());
    let mut same = IVM::try_new_with_memory_budget(100, &first).unwrap();
    same.load_prepared(&contract).unwrap();
    assert!(SharedAllocation::ptr_eq(
        same.literal_table.entries.as_ref().unwrap(),
        contract.literal_table().entries.as_ref().unwrap()
    ));
    let second = AllocationBudget::new(128 * 1024 * 1024);
    let mut foreign = IVM::try_new_with_memory_budget(100, &second).unwrap();
    let base = second.reserved_bytes();
    second.set_limit_bytes(base);
    assert!(matches!(
        foreign.load_prepared(&contract),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(second.reserved_bytes(), base);
    assert!(foreign.literal_table.entries.is_none());
    second.set_limit_bytes(128 * 1024 * 1024);
    foreign.load_prepared(&contract).unwrap();
    assert!(
        foreign
            .literal_table
            .entries
            .as_ref()
            .unwrap()
            .belongs_to(&second)
    );
    assert!(
        foreign
            .literal_table
            .pointer_starts
            .as_ref()
            .unwrap()
            .belongs_to(&second)
    );
    assert!(!SharedAllocation::ptr_eq(
        foreign.literal_table.entries.as_ref().unwrap(),
        contract.literal_table().entries.as_ref().unwrap()
    ));
    assert_eq!(
        foreign.literal_table.entries(),
        same.literal_table.entries()
    );
    drop(same);
    drop(contract);
    assert_eq!(first.reserved_bytes(), 0);
    drop(foreign);
    assert_eq!(second.reserved_bytes(), 0);
}
