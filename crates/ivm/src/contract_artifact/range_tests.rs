//! Original artifact range custody and single canonical admission-pass regressions.

use super::*;
use crate::{IVM, ProgramMetadata, VMError};
use iroha_allocation::AllocationBudget;
use norito::core::{DecodeLimits, with_decode_limits_measured, with_decode_limits_scope};

fn artifact() -> Vec<u8> {
    kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku RangeAdmission { view fn main() authorize(anyone) {} }")
        .expect("canonical compiled Unit entrypoint")
}

fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

fn one_admission(artifact: &[u8]) -> (VerifiedContractArtifact, DecodeLimits) {
    let (verified, usage) =
        with_decode_limits_measured(limits(usize::MAX), || verify_contract_artifact(artifact));
    assert!(usage.total_allocated_bytes() > 0);
    (verified.unwrap(), limits(usage.total_allocated_bytes()))
}

#[test]
fn funded_preparation_reuses_the_single_admitted_cntr_decode() {
    let bytes = artifact();
    let (verified, allowance) = one_admission(&bytes);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let prepared = with_decode_limits_scope(allowance, || {
        prepare_contract_with_memory_budget(&bytes, &budget)
    })
    .expect("one shared admission decode suffices for native preparation");
    // Retention normalization can fail cold under this exact allowance. This
    // checks removal of duplicate admission, not complete CNTR allocation funding.
    assert_eq!(prepared.code_hash(), verified.code_hash);
    assert_eq!(prepared.code_offset(), verified.code_offset);
    assert_eq!(prepared.header_len(), verified.header_len);
    assert_eq!(prepared.contract_interface(), &verified.contract_interface);
    assert_eq!(prepared.manifest(), &verified.manifest);
    assert_eq!(prepared.artifact(), bytes);
    let retained = prepared.clone();
    let charged = budget.reserved_bytes();
    assert!(charged > 0);
    budget.set_limit_bytes(0);
    drop(prepared);
    drop(bytes);
    assert_eq!(retained.contract_interface(), &verified.contract_interface);
    assert_eq!(retained.code_hash(), verified.code_hash);
    assert_eq!(budget.reserved_bytes(), charged);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn mutable_loader_routes_cntr_without_preliminary_owned_decode() {
    let bytes = artifact();
    let (verified, allowance) = one_admission(&bytes);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(100_000, &budget).unwrap();
    with_decode_limits_scope(allowance, || vm.load_program(&bytes))
        .expect("the loader dispatches from a borrowed fixed header");
    assert_eq!(vm.contract_interface(), Some(&verified.contract_interface));
    assert_eq!(vm.code_hash(), *verified.code_hash.as_ref());
    assert_eq!(vm.pc(), (verified.code_offset - verified.header_len) as u64);
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn canonical_cntr_refusal_keeps_existing_vm_state_and_retries_without_reclassification() {
    let bytes = artifact();
    let original = bytes.clone();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(91_337, &budget).unwrap();
    vm.set_register(7, 701);
    let before = (
        vm.pc(),
        vm.code_hash(),
        vm.remaining_gas(),
        budget.reserved_bytes(),
    );
    let error = with_decode_limits_scope(limits(0), || vm.load_program(&bytes)).unwrap_err();
    assert_eq!(
        error,
        VMError::ExecutionDeferred(crate::error::ExecutionDeferral::ActiveMemoryCapacity)
    );
    assert_eq!(
        (
            vm.pc(),
            vm.code_hash(),
            vm.remaining_gas(),
            budget.reserved_bytes()
        ),
        before
    );
    assert_eq!(vm.register(7), 701);
    assert!(vm.contract_interface().is_none());
    vm.load_program(&bytes)
        .expect("unchanged input retries after the enclosing scope ends");
    assert!(vm.contract_interface().is_some());
    assert_eq!(bytes, original);
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_pool_refusal_precedes_preparation_and_same_artifact_retries() {
    let bytes = artifact();
    let original = bytes.clone();
    let budget = AllocationBudget::new(0);
    let error = prepare_contract_with_memory_budget(&bytes, &budget)
        .err()
        .expect("original instruction funding refuses");
    assert!(matches!(
        error.into_vm_error(),
        VMError::AllocationDeferred(_)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(16 * 1024 * 1024);
    let prepared = prepare_contract_with_memory_budget(&bytes, &budget).unwrap();
    assert_eq!(prepared.artifact(), original);
    assert_eq!(bytes, original);
    assert!(budget.reserved_bytes() > 0);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn malformed_cntr_and_production_dbg1_never_take_the_generic_path() {
    let bytes = artifact();
    let budget = AllocationBudget::new(0);
    let mut malformed = bytes.clone();
    let start = crate::metadata::HEADER_SIZE;
    malformed[start + 4..start + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        prepare_contract_with_memory_budget(&malformed, &budget)
            .err()
            .unwrap()
            .into_vm_error(),
        VMError::InvalidMetadata
    );
    assert_eq!(
        IVM::validate_program(&malformed),
        Err(VMError::InvalidMetadata)
    );
    let parsed = ProgramMetadata::parse(&bytes).unwrap();
    let debug_offset = parsed
        .literal_section
        .map_or(parsed.code_offset, |section| section.start);
    let mut debug = bytes[..debug_offset].to_vec();
    debug.extend(
        crate::metadata::EmbeddedContractDebugInfoV1 {
            source_map: Vec::new(),
            budget_report: Vec::new(),
        }
        .encode_section(),
    );
    if let Some(literals) = parsed.literal_section {
        // Literal descriptors are relative to LTLB. Keep their original bytes
        // and data, but recompute the trailing alignment after inserting DBG1.
        let literal_start = debug.len();
        debug.extend_from_slice(&bytes[literals.start..literals.data_end]);
        let post_pad = (4 - ((debug.len() - parsed.header_len) % 4)) % 4;
        debug[literal_start + 8..literal_start + 12]
            .copy_from_slice(&(post_pad as u32).to_le_bytes());
        debug.resize(debug.len() + post_pad, 0);
    }
    debug.extend_from_slice(&bytes[parsed.code_offset..]);
    let debug_parsed = ProgramMetadata::parse(&debug)
        .expect("the debug fixture must reach production envelope policy");
    assert!(debug_parsed.contract_interface.is_some());
    assert!(debug_parsed.contract_debug.is_some());
    assert_eq!(
        &debug[debug_parsed.code_offset..],
        &bytes[parsed.code_offset..]
    );
    if let Some(original) = parsed.literal_section {
        let retained = debug_parsed.literal_section.unwrap();
        assert_eq!(retained.count, original.count);
        assert_eq!(
            &debug[retained.entries_start..retained.data_end],
            &bytes[original.entries_start..original.data_end]
        );
    }
    let error = prepare_contract_with_memory_budget(&debug, &budget)
        .err()
        .unwrap();
    assert!(error.to_string().contains("DBG1"));
    assert_eq!(error.into_vm_error(), VMError::InvalidMetadata);
    assert_eq!(IVM::validate_program(&debug), Err(VMError::InvalidMetadata));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_literal_ranges_preserve_original_index_order_and_backing() {
    use crate::{
        ivm::DecodedLiteral,
        metadata::{LiteralDirectory, ValidatedLiteral},
    };
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            r#"seiyaku RangeLiteral { permission ReadLiteral;
            kotoage fn run() authorize(ReadLiteral) -> Name {
                return Name::parse("indexed_literal");
            }
        }"#,
        )
        .unwrap();
    let parsed = ProgramMetadata::parse(&bytes).unwrap();
    let verified = verify_contract_artifact(&bytes).unwrap();
    assert!(parsed.literal_section.is_some());
    assert_eq!(verified.literal_section(), parsed.literal_section);
    let directory = LiteralDirectory::validate(
        &bytes,
        verified.header_len,
        verified.literal_section(),
        SyscallPolicy::AbiV1,
    )
    .unwrap();
    let expected = directory
        .iter()
        .map(|literal| match literal {
            ValidatedLiteral::Pointer { address, .. } => DecodedLiteral::Pointer(address),
            ValidatedLiteral::I64(bits) => DecodedLiteral::I64(bits),
        })
        .collect::<Vec<_>>();
    assert!(!expected.is_empty());
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let prepared = prepare_contract_with_memory_budget(&bytes, &budget).unwrap();
    assert_eq!(prepared.literal_table().entries(), expected);
    assert_eq!(prepared.artifact(), bytes);
    assert_eq!(prepared.code_offset(), verified.code_offset);
    assert_eq!(
        prepared.entrypoint_pc("run"),
        Some(prepared.instruction_entry_pc() + verified.contract_interface.entrypoints[0].entry_pc)
    );
    drop(bytes);
    assert_eq!(prepared.literal_table().entries(), expected);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
}
