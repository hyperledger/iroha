//! Operational read refusals survive TLV, crypto, numeric and loader consumers.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal};

fn funded() -> (IVM, AllocationBudget) {
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let vm = IVM::try_new_with_memory_budget(1_000_000, &budget).unwrap();
    (vm, budget)
}

fn exhaust_at_read(vm: &IVM, budget: &AllocationBudget, header_succeeds: bool) {
    if header_succeeds {
        for _ in 0..3 {
            vm.memory.load_u8(Memory::OUTPUT_START).unwrap();
        }
    }
    budget.set_limit_bytes(budget.reserved_bytes());
}

fn assert_operational<T>(result: Result<T, VMError>) {
    match result {
        Err(VMError::AllocationDeferred(_)) => {}
        Err(error) => panic!("expected the original allocation refusal, received {error:?}"),
        Ok(_) => panic!("resource exhaustion must defer before publishing a result"),
    }
}

// A cold loader now owns decoded/prepared operations and callable layouts.
// Observe their complete original-pool footprint using an empty INPUT control:
// its cursor scan performs exactly three reads and retains four AccessRange
// slots. This keeps the refusal tests at the read boundary rather than failing
// earlier at an unrelated program-owner allocation.
fn cold_program_owner_bytes(load: impl Fn(&mut IVM) -> Result<(), VMError>) -> usize {
    let (mut control, original) = funded();
    let construction = original.reserved_bytes();
    load(&mut control).unwrap();
    let loaded = original.reserved_bytes();
    // A successful load clears logical accesses at the clean-template cut,
    // retaining their physical backing. Prove its exact four-row capacity
    // without admitting another allocation before subtracting that footprint.
    original.set_limit_bytes(loaded);
    for _ in 0..4 {
        control.memory.load_u8(Memory::OUTPUT_START).unwrap();
    }
    assert_read_capacity_refusal(control.memory.load_u8(Memory::OUTPUT_START), 8, &original);
    assert_eq!(original.reserved_bytes(), loaded);
    let owners = loaded - construction - 4 * std::mem::size_of::<crate::AccessRange>();
    drop(control);
    assert_eq!(original.reserved_bytes(), 0);
    owners
}

fn assert_read_capacity_refusal<T>(
    result: Result<T, VMError>,
    rows: usize,
    original: &AllocationBudget,
) {
    let Err(VMError::AllocationDeferred(AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    })) = result
    else {
        panic!("expected original read-row capacity refusal");
    };
    assert_eq!(
        requested_bytes,
        rows * std::mem::size_of::<crate::AccessRange>()
    );
    let Err(AllocationRefusal::Capacity {
        release: expected, ..
    }) = original.try_reserve_bytes(requested_bytes)
    else {
        panic!("same original pool remains exhausted");
    };
    assert_eq!(release, expected);
}

#[test]
fn public_and_input_only_tlv_decoders_preserve_header_and_envelope_refusals() {
    for input_only in [false, true] {
        for header_succeeds in [false, true] {
            let (mut vm, budget) = funded();
            let tlv = empty_blob_tlv();
            vm.memory.preload_input(0, &tlv).unwrap();
            exhaust_at_read(&vm, &budget, header_succeeds);
            let occupied = budget.reserved_bytes();
            if input_only {
                assert_operational(vm.memory.validate_tlv(Memory::INPUT_START));
            } else {
                assert_operational(vm.validate_tlv(Memory::INPUT_START));
            }
            assert_eq!(budget.reserved_bytes(), occupied);
            // An invalid address retains its deterministic decoder fault.
            assert_eq!(
                vm.validate_tlv(u64::MAX).err().unwrap(),
                VMError::NoritoInvalid
            );
            budget.set_limit_bytes(occupied + 8 * std::mem::size_of::<crate::AccessRange>());
            assert!(
                vm.validate_tlv(Memory::INPUT_START)
                    .unwrap()
                    .payload
                    .is_empty()
            );
        }
    }
}

#[test]
fn private_tlv_snapshot_preserves_header_and_complete_envelope_refusals() {
    for header_succeeds in [false, true] {
        let (mut vm, budget) = funded();
        vm.zk_mode = true;
        let tlv =
            ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from(17)).unwrap();
        let address = vm.alloc_host_private_tlv(&tlv).unwrap();
        exhaust_at_read(&vm, &budget, header_succeeds);
        let occupied = budget.reserved_bytes();
        assert_operational(vm.snapshot_private_tlv(address, tlv.len()));
        assert_eq!(budget.reserved_bytes(), occupied);
        budget.set_limit_bytes(occupied + 8 * std::mem::size_of::<crate::AccessRange>());
        assert_eq!(vm.snapshot_private_tlv(address, tlv.len()).unwrap(), tlv);
        assert_eq!(
            vm.validate_tlv(address).err().unwrap(),
            VMError::PrivacyViolation
        );
    }
}

#[test]
fn staged_numeric_envelope_reads_keep_operational_errors_and_fault_semantics() {
    let integer = iroha_primitives::bigint::BigInt::from(17);
    let envelope = ivm_abi::numeric_tlv::encode_int(&integer).unwrap();
    for header_succeeds in [false, true] {
        let (mut vm, budget) = funded();
        vm.memory.preload_input(0, &envelope).unwrap();
        vm.set_register(10, Memory::INPUT_START);
        vm.set_register(11, Memory::INPUT_START);
        vm.set_register(14, crate::numeric::NUMERIC_FAILURE_TRAP);
        let mut host = crate::host::DefaultHost::new();
        let prepared_log = vm.prepare_host_register_log().unwrap();
        exhaust_at_read(&vm, &budget, header_succeeds);
        let occupied = budget.reserved_bytes();
        assert_operational(vm.execute_staged_syscall(
            &mut host,
            crate::syscalls::SYSCALL_INT_ADD,
            &prepared_log,
        ));
        assert_eq!(vm.register(10), Memory::INPUT_START);
        assert_eq!(budget.reserved_bytes(), occupied);
        budget.set_limit_bytes(occupied + 24 * std::mem::size_of::<crate::AccessRange>());
        vm.execute_staged_syscall(&mut host, crate::syscalls::SYSCALL_INT_ADD, &prepared_log)
            .unwrap();
        let value = vm.validate_tlv(vm.register(10)).unwrap();
        assert_eq!(
            iroha_primitives::numeric_abi::IntValueV1::decode_frame(value.payload)
                .unwrap()
                .into_int(),
            iroha_primitives::bigint::BigInt::from(34)
        );
        vm.set_register(10, u64::MAX);
        assert_eq!(
            vm.execute_staged_syscall(&mut host, crate::syscalls::SYSCALL_INT_ADD, &prepared_log),
            Err(VMError::PointerAbiFault(
                crate::numeric::PointerAbiFaultV1::InvalidAddress
            ))
        );
    }
}

#[test]
fn signature_opcodes_never_publish_false_on_preflight_or_validation_read_refusal() {
    let row_bytes = std::mem::size_of::<crate::AccessRange>();
    for opcode in [
        instruction::wide::crypto::ED25519VERIFY,
        instruction::wide::crypto::ECDSAVERIFY,
        instruction::wide::crypto::DILITHIUMVERIFY,
    ] {
        for prior_reads in [0, 3] {
            let (mut vm, budget) = funded();
            let tlv = empty_blob_tlv();
            vm.memory.preload_input(0, &tlv).unwrap();
            let instruction = crate::encoding::wide::encode_rr(opcode, 12, 10, 11);
            let program = [instruction, crate::encoding::wide::encode_halt()]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            vm.load_code(&program).unwrap();
            for register in [10, 11, 12] {
                vm.set_register(register, Memory::INPUT_START);
            }
            // Keep the preceding invocation owner alive so run's mandatory
            // replacement shell cannot refund credit intended for read rows.
            let previous_log = vm.proof_register_log_handle().unwrap();
            let shell = zk::SharedRegLog::allocation_layout().size();
            let base = budget.reserved_bytes();
            for _ in 0..prior_reads {
                vm.memory.load_u8(Memory::OUTPUT_START).unwrap();
            }
            budget.set_limit_bytes(base + shell + 4 * row_bytes);
            assert_read_capacity_refusal(vm.run(), 8, &budget);
            assert_eq!(
                vm.register(12),
                Memory::INPUT_START,
                "no verification decision published"
            );
            assert_eq!(vm.pc, 0);
            assert_eq!(budget.reserved_bytes(), base + shell + 4 * row_bytes);
            drop(previous_log);
            assert_eq!(budget.reserved_bytes(), base + 4 * row_bytes);
            // A separate adequately funded attempt retains the existing false
            // result for malformed public signature/key payloads.
            let mut ordinary = quiet_vm(1_000_000);
            ordinary.memory.preload_input(0, &tlv).unwrap();
            ordinary.load_code(&program).unwrap();
            for register in [10, 11, 12] {
                ordinary.set_register(register, Memory::INPUT_START);
            }
            ordinary.run().unwrap();
            assert_eq!(ordinary.register(12), 0);
            drop(vm);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn input_cursor_refusal_does_not_publish_a_partial_prefix_or_overwrite_preloaded_tlvs() {
    let row = std::mem::size_of::<crate::AccessRange>();
    let tlv = empty_blob_tlv();
    let stride = (tlv.len() as u64).next_multiple_of(8);
    for completed_reads in 0..7 {
        let (mut vm, budget) = funded();
        vm.memory.preload_input(0, &tlv).unwrap();
        vm.memory.preload_input(stride, &tlv).unwrap();
        // Place the upcoming scan's refusal at each header/payload/hash boundary
        // and at the first header after the two valid preloaded envelopes.
        let capacity = if completed_reads <= 4 { 4 } else { 8 };
        let prior = capacity - completed_reads;
        let establish = if capacity == 4 { 1 } else { 5 };
        for _ in 0..establish {
            vm.memory.load_u8(Memory::OUTPUT_START).unwrap();
        }
        vm.memory.clear_tracking();
        for _ in 0..prior {
            vm.memory.load_u8(Memory::OUTPUT_START).unwrap();
        }
        let occupied = budget.reserved_bytes();
        budget.set_limit_bytes(occupied);
        vm.input_bump_next = 17;
        assert_operational(vm.recompute_input_bump_from_memory());
        assert_eq!(vm.input_bump_next, 17);
        assert_eq!(budget.reserved_bytes(), occupied);
        assert_eq!(
            vm.memory
                .inspect_region(Memory::INPUT_START, tlv.len() as u64)
                .unwrap(),
            tlv
        );
        assert_eq!(
            vm.memory
                .inspect_region(Memory::INPUT_START + stride, tlv.len() as u64)
                .unwrap(),
            tlv
        );
        budget.set_limit_bytes(occupied + 64 * row);
        vm.recompute_input_bump_from_memory().unwrap();
        assert_eq!(vm.input_bump_next, 2 * stride);
        let next = vm.alloc_input_tlv(&tlv).unwrap();
        assert_eq!(next, Memory::INPUT_START + 2 * stride);
        assert_eq!(
            vm.memory
                .inspect_region(Memory::INPUT_START, tlv.len() as u64)
                .unwrap(),
            tlv
        );
    }
}

#[test]
fn program_loader_returns_cursor_scan_refusal_and_succeeds_after_resource_retry() {
    let compiled = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku ReadLoader { view fn main() authorize(anyone) { () } }")
        .unwrap();
    let contract = crate::prepare_contract(Arc::<[u8]>::from(compiled)).unwrap();
    let mut raw = ProgramMetadata::default().encode();
    raw.extend_from_slice(&crate::encoding::encode_halt().to_le_bytes());
    for prepared in [false, true] {
        let load = |vm: &mut IVM| {
            if prepared {
                vm.load_prepared(&contract)
            } else {
                vm.load_program(&raw)
            }
        };
        let program_owners = cold_program_owner_bytes(load);
        let (mut vm, budget) = funded();
        let tlv = empty_blob_tlv();
        vm.memory.preload_input(0, &tlv).unwrap();
        let generation = vm.memory.template_generation();
        let loaded_without_reads = budget.reserved_bytes() + program_owners;
        budget.set_limit_bytes(loaded_without_reads);
        vm.input_bump_next = 17;
        assert_read_capacity_refusal(load(&mut vm), 4, &budget);
        assert_eq!(budget.reserved_bytes(), loaded_without_reads);
        assert_eq!(vm.input_bump_next, 17);
        assert_eq!(
            vm.memory.template_generation(),
            generation,
            "failed load publishes no clean template baseline"
        );
        assert_eq!(
            vm.memory
                .inspect_region(Memory::INPUT_START, tlv.len() as u64)
                .unwrap(),
            tlv
        );
        // A direct caller must discard this unfinished attempt or explicitly
        // retry loading. No old-program rollback or run-after-error is claimed.
        budget.set_limit_bytes(
            // Retry temporarily owns both the unfinished image and its new
            // original-funded program owners, then the 4-to-8 read-row growth.
            budget.reserved_bytes()
                + program_owners
                + 12 * std::mem::size_of::<crate::AccessRange>(),
        );
        load(&mut vm).unwrap();
        let mut control = quiet_vm(1_000_000);
        control.memory.preload_input(0, &tlv).unwrap();
        load(&mut control).unwrap();
        assert_eq!(vm.code_hash(), control.code_hash());
        assert_eq!(vm.pc, control.pc);
        assert_eq!(vm.program_prefix_len, control.program_prefix_len);
        assert_eq!(vm.strict_return_integrity, control.strict_return_integrity);
        assert_eq!(vm.input_bump_next, control.input_bump_next);
        assert_eq!(vm.memory.template_generation(), generation + 1);
        assert_eq!(vm.memory.current_root(), control.memory.current_root());
        let next = vm.alloc_input_tlv(&tlv).unwrap();
        assert_eq!(
            next,
            Memory::INPUT_START + (tlv.len() as u64).next_multiple_of(8)
        );
        assert_eq!(next, control.alloc_input_tlv(&tlv).unwrap());
        budget.set_limit_bytes(64 * 1024 * 1024);
        if prepared {
            vm.select_entrypoint("main").unwrap();
            control.select_entrypoint("main").unwrap();
        }
        vm.run().unwrap();
        control.run().unwrap();
        assert_eq!(vm.remaining_gas(), control.remaining_gas());
        assert_eq!(vm.memory.current_root(), control.memory.current_root());
        assert_eq!(
            vm.call_result_word_count(),
            control.call_result_word_count()
        );
        if prepared {
            assert_eq!(
                vm.public_call_result_word(0),
                control.public_call_result_word(0)
            );
        }
        drop(vm);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn failed_cold_prepared_load_drops_its_original_pool_before_fresh_owner_retry() {
    let compiled = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku ColdReadLoader { view fn main() authorize(anyone) { () } }")
        .unwrap();
    let contract = crate::prepare_contract(Arc::<[u8]>::from(compiled)).unwrap();
    let program_owners = cold_program_owner_bytes(|vm| vm.load_prepared(&contract));
    let (probe, budget) = funded();
    let construction = budget.reserved_bytes();
    drop(probe);
    assert_eq!(budget.reserved_bytes(), 0);
    let load_cold = || -> Result<IVM, VMError> {
        let mut vm = IVM::try_new_with_memory_budget(1_000_000, &budget)?;
        vm.memory.preload_input(0, &empty_blob_tlv())?;
        vm.load_prepared(&contract)?;
        Ok(vm)
    };
    budget.set_limit_bytes(construction + program_owners);
    let Err(VMError::AllocationDeferred(AllocationRefusal::Capacity {
        requested_bytes, ..
    })) = load_cold()
    else {
        panic!("cold load must reach its first cursor read before refusal");
    };
    assert_eq!(
        requested_bytes,
        4 * std::mem::size_of::<crate::AccessRange>()
    );
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "no unfinished VM can enter a cache lease on failed load"
    );
    budget.set_limit_bytes(
        construction + program_owners + 12 * std::mem::size_of::<crate::AccessRange>(),
    );
    let vm = load_cold().unwrap();
    assert_eq!(vm.memory.template_generation(), 1);
    assert_eq!(
        vm.input_bump_next,
        (empty_blob_tlv().len() as u64).next_multiple_of(8)
    );
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn batch_signature_opcode_keeps_both_output_registers_on_read_refusal() {
    let row = std::mem::size_of::<crate::AccessRange>();
    for prior_reads in [1, 3] {
        let (mut vm, budget) = funded();
        let tlv = empty_blob_tlv();
        vm.memory.preload_input(0, &tlv).unwrap();
        let instruction = crate::encoding::wide::encode_rr(
            instruction::wide::crypto::ED25519BATCHVERIFY,
            12,
            10,
            11,
        );
        let program = [instruction, crate::encoding::wide::encode_halt()]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        vm.load_code(&program).unwrap();
        vm.set_register(10, Memory::INPUT_START);
        vm.set_register(11, 91);
        vm.set_register(12, 92);
        for _ in 0..prior_reads {
            vm.memory.load_u8(Memory::OUTPUT_START).unwrap();
        }
        let occupied = budget.reserved_bytes();
        budget.set_limit_bytes(occupied);
        assert_operational(vm.run());
        assert_eq!(vm.register(11), 91);
        assert_eq!(vm.register(12), 92);
        assert_eq!(vm.pc, 0);
        assert_eq!(budget.reserved_bytes(), occupied);
        // Reinitializing an attempt with sufficient credit keeps the existing
        // malformed-public-request result and failure-index convention.
        budget.set_limit_bytes(occupied + 12 * row);
        vm.load_code(&program).unwrap();
        vm.set_gas_limit(1_000_000);
        vm.run().unwrap();
        assert_eq!(vm.register(11), 0);
        assert_eq!(vm.register(12), 0);
    }
}
