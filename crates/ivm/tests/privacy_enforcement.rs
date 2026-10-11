//! Privacy-tag enforcement tests for ZK execution.
mod common;
use iroha_crypto::Hash;
use iroha_primitives::numeric::{Numeric, Quantity};
use ivm::{
    IVM, Memory, ProgramMetadata, VMError, encoding,
    host::{DefaultHost, IVMHost},
    instruction,
    pointer_abi::PointerType,
    syscalls,
};
use ivm_abi::private_input::PrivateInputRecordV1;
use std::{any::Any, cell::Cell};
fn meta_with_mode(mode: u8) -> ProgramMetadata {
    ProgramMetadata {
        mode,
        max_cycles: 2,
        ..ProgramMetadata::default()
    }
}
fn raw_zk_program(words: &[u32]) -> Vec<u8> {
    let mut program = ProgramMetadata {
        mode: ivm::ivm_mode::ZK,
        max_cycles: 32,
        ..ProgramMetadata::default()
    }
    .encode();
    for word in words {
        program.extend_from_slice(&word.to_le_bytes());
    }
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    program
}
const CONTINUATION_PC: u64 = 8;
fn private_store_then(target: u32) -> Vec<u8> {
    raw_zk_program(&[
        encoding::wide::encode_store(instruction::wide::memory::STORE64, 1, 2, 0),
        encoding::wide::encode_halt(),
        target,
    ])
}
fn scall(number: u32) -> u32 {
    encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(number).expect("test syscall fits compact SCALL"),
    )
}
fn int_private_host(values: &[u64]) -> DefaultHost {
    let records = values
        .iter()
        .map(|value| ivm::private_input::int_record((*value).into()).unwrap())
        .collect();
    DefaultHost::with_private_inputs(records).unwrap()
}
fn typed_private_host(records: Vec<PrivateInputRecordV1>) -> DefaultHost {
    DefaultHost::with_private_inputs(records).expect("construct bounded typed private-input host")
}
fn blob_tlv(payload: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    envelope.extend_from_slice(&(PointerType::Blob as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test TLV payload fits u32")
            .to_be_bytes(),
    );
    envelope.extend_from_slice(payload);
    let hash: [u8; Hash::LENGTH] = Hash::new(payload).into();
    envelope.extend_from_slice(&hash);
    envelope
}
fn mark_one_private_stack_byte(vm: &mut IVM, address: u64) {
    let word_address = address & !7;
    let byte_offset = usize::try_from(address - word_address).expect("word byte offset");
    let bytes: [u8; 8] = vm
        .memory
        .load_region(word_address, 8)
        .expect("load public stack word before retagging")
        .try_into()
        .expect("fixed stack word");
    vm.set_register(1, word_address);
    vm.set_register(2, u64::from_le_bytes(bytes));
    vm.registers.set_tag(2, true);
    vm.run().expect("store private stack word");
    if byte_offset != 0 {
        vm.store_bytes(word_address, &bytes[..byte_offset])
            .expect("restore public bytes before the selected byte");
    }
    if byte_offset + 1 < bytes.len() {
        vm.store_bytes(address + 1, &bytes[byte_offset + 1..])
            .expect("restore public bytes after the selected byte");
    }
    vm.set_program_counter(CONTINUATION_PC)
        .expect("select target after private-store fixture");
}
fn vm_with_private_stack_word() -> IVM {
    let program = private_store_then(encoding::wide::encode_load(
        instruction::wide::memory::LOAD64,
        3,
        1,
        0,
    ));
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program)
        .expect("load canonical private stack fixture");
    vm.set_register(1, Memory::STACK_START);
    vm.set_register(2, 0xCAFE_BABE_DEAD_BEEF);
    vm.registers.set_tag(2, true);
    vm.run().expect("store canonical private stack word");
    vm
}
#[test]
fn branch_on_private_fails() {
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&raw_zk_program(&[encoding::wide::encode_branch(
        instruction::wide::control::BEQ,
        1,
        2,
        1,
    )]))
    .expect("load private branch fixture");
    vm.set_register(1, 5);
    vm.registers.set_tag(1, true);
    vm.set_register(2, 5);
    vm.registers.set_tag(2, false);
    let res = vm.run();
    assert!(matches!(res, Err(VMError::PrivacyViolation)));
}
#[test]
fn escrow_and_merkle_host_boundaries_reject_private_secondary_arguments() {
    for (syscall, private_register) in [
        (syscalls::SYSCALL_ESCROW_OPEN_OFFER, 11),
        (syscalls::SYSCALL_ESCROW_RESOLVE_DISPUTE, 12),
        (syscalls::SYSCALL_GET_MERKLE_PATH, 11),
    ] {
        let mut vm = IVM::new(10_000);
        vm.load_program(&raw_zk_program(&[scall(syscall)]))
            .expect("load ZK syscall fixture");
        vm.set_host(DefaultHost::new());
        vm.set_register(private_register, 7);
        vm.registers.set_tag(private_register, true);
        assert_eq!(
            vm.run(),
            Err(VMError::PrivacyViolation),
            "syscall {syscall:#x} accepted private r{private_register} across the public host boundary"
        );
    }
}
#[test]
fn load_private_address_fails() {
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&raw_zk_program(&[encoding::wide::encode_load(
        instruction::wide::memory::LOAD64,
        2,
        1,
        0,
    )]))
    .expect("load private-address fixture");
    vm.set_register(1, Memory::HEAP_START);
    vm.registers.set_tag(1, true);
    let res = vm.run();
    assert!(matches!(res, Err(VMError::PrivacyViolation)));
}
#[test]
fn wide_shift_mismatched_tags_fails() {
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&raw_zk_program(&[encoding::wide::encode_rr(
        instruction::wide::arithmetic::SLL,
        3,
        1,
        2,
    )]))
    .expect("load private shift fixture");
    vm.set_register(1, 1);
    vm.set_register(2, 2);
    vm.registers.set_tag(1, true);
    vm.registers.set_tag(2, false);
    let err = vm.run();
    assert!(matches!(err, Err(VMError::PrivacyViolation)));
}
#[test]
fn sha256block_private_address_fails() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK | ivm::ivm_mode::VECTOR).encode();
    let sha = encoding::wide::encode_rr(instruction::wide::crypto::SHA256BLOCK, 0, 1, 0);
    program.extend_from_slice(&sha.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(1, Memory::HEAP_START);
    vm.registers.set_tag(1, true);
    let err = vm.run().unwrap_err();
    assert!(matches!(err, VMError::PrivacyViolation));
}
#[test]
fn sha3block_private_address_fails() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK).encode();
    let sha3 = encoding::wide::encode_rr(instruction::wide::crypto::SHA3BLOCK, 4, 10, 11);
    program.extend_from_slice(&sha3.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(10, Memory::HEAP_START);
    vm.set_register(11, Memory::HEAP_START);
    vm.set_register(4, Memory::HEAP_START);
    vm.registers.set_tag(10, true);
    let err = vm.run().unwrap_err();
    assert!(matches!(err, VMError::PrivacyViolation));
}
#[test]
fn wide_add_mismatched_tags_fails() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK).encode();
    let add = encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2);
    program.extend_from_slice(&add.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(1, 10);
    vm.set_register(2, 20);
    vm.registers.set_tag(1, true);
    vm.registers.set_tag(2, false);
    let err = vm.run().unwrap_err();
    assert!(matches!(err, VMError::PrivacyViolation));
}
#[test]
fn wide_add_propagates_secret_tag() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK).encode();
    let add = encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2);
    program.extend_from_slice(&add.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(1, 10);
    vm.set_register(2, 20);
    vm.registers.set_tag(1, true);
    vm.registers.set_tag(2, true);
    vm.run().unwrap();
    assert_eq!(vm.register(3), 30);
    assert!(vm.registers.tag(3));
}
#[test]
fn value_dependent_arithmetic_traps_reject_private_operands_before_reading_values() {
    for opcode in [
        instruction::wide::arithmetic::DIV,
        instruction::wide::arithmetic::DIVU,
        instruction::wide::arithmetic::REM,
        instruction::wide::arithmetic::REMU,
        instruction::wide::arithmetic::DIV_CEIL,
    ] {
        let mut expected_remaining = None;
        for (numerator, denominator) in
            [(12_u64, 3_u64), (12, 0), (i64::MIN as u64, (-1_i64) as u64)]
        {
            let program = raw_zk_program(&[encoding::wide::encode_rr(opcode, 3, 1, 2)]);
            let mut vm = IVM::new(10_000);
            vm.load_program(&program)
                .expect("load private trap fixture");
            vm.set_register(1, numerator);
            vm.set_register(2, denominator);
            vm.registers.set_tag(1, true);
            vm.registers.set_tag(2, true);
            assert_eq!(
                vm.run(),
                Err(VMError::PrivacyViolation),
                "opcode {opcode:#x} exposed a private value-dependent outcome for {numerator}/{denominator}"
            );
            let remaining = vm.remaining_gas();
            if let Some(expected) = expected_remaining {
                assert_eq!(remaining, expected, "opcode {opcode:#x} leaked through gas");
            } else {
                expected_remaining = Some(remaining);
            }
        }
    }
    for value in [0_u64, 7, i64::MIN as u64] {
        let program = raw_zk_program(&[encoding::wide::encode_rr(
            instruction::wide::arithmetic::ABS,
            3,
            1,
            0,
        )]);
        let mut vm = IVM::new(10_000);
        vm.load_program(&program).expect("load private abs fixture");
        vm.set_register(1, value);
        vm.registers.set_tag(1, true);
        assert_eq!(vm.run(), Err(VMError::PrivacyViolation));
    }
}
#[test]
fn zk_assertions_reject_private_predicates_independent_of_truth_value() {
    for word in [
        encoding::wide::encode_rr(instruction::wide::zk::ASSERT, 0, 1, 0),
        encoding::wide::encode_ri(instruction::wide::zk::ASSERT_RANGE, 0, 1, 1),
    ] {
        let mut expected_remaining = None;
        for value in [0_u64, 1] {
            let mut vm = IVM::new(10_000);
            vm.load_program(&raw_zk_program(&[word]))
                .expect("load private assertion fixture");
            vm.set_register(1, value);
            vm.registers.set_tag(1, true);
            assert_eq!(vm.run(), Err(VMError::PrivacyViolation));
            let remaining = vm.remaining_gas();
            if let Some(expected) = expected_remaining {
                assert_eq!(remaining, expected, "private assertion leaked through gas");
            } else {
                expected_remaining = Some(remaining);
            }
        }
    }
    let mut expected_remaining = None;
    for (left, right) in [(7_u64, 7_u64), (7, 8)] {
        let word = encoding::wide::encode_rr(instruction::wide::zk::ASSERT_EQ, 0, 1, 2);
        let mut vm = IVM::new(10_000);
        vm.load_program(&raw_zk_program(&[word]))
            .expect("load private equality assertion fixture");
        vm.set_register(1, left);
        vm.set_register(2, right);
        vm.registers.set_tag(1, true);
        vm.registers.set_tag(2, true);
        assert_eq!(vm.run(), Err(VMError::PrivacyViolation));
        let remaining = vm.remaining_gas();
        if let Some(expected) = expected_remaining {
            assert_eq!(remaining, expected, "private equality leaked through gas");
        } else {
            expected_remaining = Some(remaining);
        }
    }
}
#[test]
fn wide_addi_propagates_tag() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK).encode();
    let addi = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 3, 1, 7);
    program.extend_from_slice(&addi.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(1, 10);
    vm.registers.set_tag(1, true);
    vm.run().unwrap();
    assert_eq!(vm.register(3), 17);
    assert!(vm.registers.tag(3));
}
#[test]
fn wide_cmov_secret_condition_fails() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK).encode();
    let cmov = encoding::wide::encode_rr(instruction::wide::arithmetic::CMOV, 3, 1, 2);
    program.extend_from_slice(&cmov.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(1, 42);
    vm.set_register(2, 1);
    vm.registers.set_tag(2, true);
    let err = vm.run().unwrap_err();
    assert!(matches!(err, VMError::PrivacyViolation));
}
#[test]
fn wide_jal_clears_tag() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK).encode();
    let jal = encoding::wide::encode_jump(instruction::wide::control::JAL, 5, 1);
    program.extend_from_slice(&jal.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.registers.set_tag(5, true);
    vm.run().unwrap();
    assert!(!vm.registers.tag(5));
}
#[test]
fn wide_jalr_secret_target_fails() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK).encode();
    let jalr = encoding::wide::encode_ri(instruction::wide::control::JALR, 5, 1, 0);
    program.extend_from_slice(&jalr.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(1, 0);
    vm.registers.set_tag(1, true);
    let err = vm.run().unwrap_err();
    assert!(matches!(err, VMError::PrivacyViolation));
}
#[test]
fn wide_aesenc_mismatched_tags_fails() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK | ivm::ivm_mode::VECTOR).encode();
    let aes = encoding::wide::encode_rr(instruction::wide::crypto::AESENC, 20, 10, 12);
    program.extend_from_slice(&aes.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(10, 0);
    vm.set_register(11, 0);
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    vm.registers.set_tag(10, true);
    vm.registers.set_tag(11, true);
    vm.registers.set_tag(12, false);
    vm.registers.set_tag(13, false);
    let err = vm.run().unwrap_err();
    assert!(matches!(err, VMError::PrivacyViolation));
}
#[test]
fn wide_aesdec_propagates_tag() {
    let mut program = meta_with_mode(ivm::ivm_mode::ZK | ivm::ivm_mode::VECTOR).encode();
    let aes = encoding::wide::encode_rr(instruction::wide::crypto::AESDEC, 20, 10, 12);
    program.extend_from_slice(&aes.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).unwrap();
    vm.set_register(10, 0);
    vm.set_register(11, 0);
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    vm.registers.set_tag(10, true);
    vm.registers.set_tag(11, true);
    vm.registers.set_tag(12, true);
    vm.registers.set_tag(13, true);
    vm.registers.set_tag(20, false);
    vm.registers.set_tag(21, false);
    vm.run().unwrap();
    assert!(vm.registers.tag(20));
    assert!(vm.registers.tag(21));
}
#[test]
fn private_input_syscall_marks_result_private() {
    let program = raw_zk_program(&[scall(syscalls::SYSCALL_GET_PRIVATE_INPUT)]);
    let mut vm = IVM::new(10_000);
    vm.set_host(int_private_host(&[42]));
    vm.load_program(&program).unwrap();
    vm.set_register(10, 0);
    vm.run().expect("private input should load");
    assert!(
        vm.register(10) >= Memory::HEAP_START,
        "typed private input must remain an opaque heap pointer"
    );
    assert!(vm.registers.tag(10));
}
#[test]
fn private_input_syscall_requires_zk_execution_mode() {
    let mut program = ProgramMetadata {
        max_cycles: 32,
        ..ProgramMetadata::default()
    }
    .encode();
    program.extend_from_slice(&scall(syscalls::SYSCALL_GET_PRIVATE_INPUT).to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000);
    vm.set_host(int_private_host(&[42]));
    vm.load_program(&program).expect("load non-ZK program");
    vm.set_register(10, 0);
    let error = vm
        .run()
        .expect_err("non-ZK execution must not consume private input");
    assert!(matches!(error, VMError::PrivacyViolation));
    assert_eq!(vm.register(10), 0);
    assert!(!vm.registers.tag(10));
}
#[test]
fn successful_hosts_cannot_declassify_unwritten_output_registers() {
    struct PartialOutputHost;
    impl IVMHost for PartialOutputHost {
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
            match number {
                syscalls::SYSCALL_CURRENT_TIME_MS => {
                    assert_eq!(vm.register(10), 0);
                    assert!(!vm.registers.tag(10));
                }
                syscalls::SYSCALL_VERIFY_PROOF => {
                    assert_eq!(vm.register(10), 123, "declared input must be preserved");
                    assert!(!vm.registers.tag(10));
                    assert_eq!(vm.register(11), 0, "output-only r11 must be sanitized");
                    assert!(!vm.registers.tag(11));
                }
                _ => panic!("unexpected syscall {number:#x}"),
            }
            Ok(0)
        }
        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            if number == syscalls::SYSCALL_CURRENT_TIME_MS {
                assert_eq!(vm.register(10), 0);
                assert!(!vm.registers.tag(10));
            }
            if number == syscalls::SYSCALL_VERIFY_PROOF {
                assert_eq!(vm.register(11), 0);
                assert!(!vm.registers.tag(11));
                vm.set_register(10, 1);
            }
            Ok(0)
        }
        fn as_any(&mut self) -> &mut dyn Any
        where
            Self: 'static,
        {
            self
        }
    }
    let mut no_write = IVM::new(10_000);
    no_write
        .load_program(&raw_zk_program(&[scall(syscalls::SYSCALL_CURRENT_TIME_MS)]))
        .expect("load output-only syscall fixture");
    no_write.set_host(PartialOutputHost);
    no_write.set_register(10, 0xDEAD_BEEF);
    no_write.registers.set_tag(10, true);
    no_write.run().expect("no-write host returns success");
    assert_eq!(no_write.register(10), 0);
    assert!(!no_write.registers.tag(10));
    let mut partial_write = IVM::new(10_000);
    partial_write
        .load_program(&raw_zk_program(&[scall(syscalls::SYSCALL_VERIFY_PROOF)]))
        .expect("load partial-output syscall fixture");
    partial_write.set_host(PartialOutputHost);
    partial_write.set_register(10, 123);
    partial_write.set_register(11, 0xA5A5_A5A5);
    partial_write.registers.set_tag(11, true);
    partial_write
        .run()
        .expect("partial-write host returns success");
    assert_eq!(partial_write.register(10), 1);
    assert_eq!(partial_write.register(11), 0);
    assert!(!partial_write.registers.tag(10));
    assert!(!partial_write.registers.tag(11));
}
#[test]
fn output_sanitization_restores_registers_when_prepare_or_quote_fails() {
    struct PrepareFailureHost;
    impl IVMHost for PrepareFailureHost {
        fn prepare_syscall(&self, _number: u32, vm: &IVM) -> Result<u64, VMError> {
            assert_eq!(vm.register(10), 0);
            assert!(!vm.registers.tag(10));
            Err(VMError::DecodeError)
        }
        fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
            panic!("failed preparation must not execute the host")
        }
        fn as_any(&mut self) -> &mut dyn Any
        where
            Self: 'static,
        {
            self
        }
    }
    struct UnaffordableHost;
    impl IVMHost for UnaffordableHost {
        fn prepare_syscall(&self, _number: u32, vm: &IVM) -> Result<u64, VMError> {
            assert_eq!(vm.register(10), 0);
            assert!(!vm.registers.tag(10));
            Ok(1_000_000)
        }
        fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
            panic!("unaffordable quote must not execute the host")
        }
        fn as_any(&mut self) -> &mut dyn Any
        where
            Self: 'static,
        {
            self
        }
    }
    fn assert_restored(host: impl IVMHost + Send + Sync + 'static, expected: VMError) {
        let mut vm = IVM::new(10_000);
        vm.load_program(&raw_zk_program(&[scall(syscalls::SYSCALL_CURRENT_TIME_MS)]))
            .expect("load restoration fixture");
        vm.set_host(host);
        vm.set_register(10, 0xC0FF_EE);
        vm.registers.set_tag(10, true);
        assert_eq!(vm.run(), Err(expected));
        assert_eq!(vm.register(10), 0xC0FF_EE);
        assert!(vm.registers.tag(10));
    }
    assert_restored(PrepareFailureHost, VMError::DecodeError);
    assert_restored(UnaffordableHost, VMError::OutOfGas);
}
#[test]
fn host_cannot_return_a_private_tag_through_an_ordinary_public_output() {
    struct PrivateOutputHost;
    impl IVMHost for PrivateOutputHost {
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            Ok(0)
        }
        fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            vm.set_register(10, 7);
            vm.registers.set_tag(10, true);
            Ok(0)
        }
        fn as_any(&mut self) -> &mut dyn Any
        where
            Self: 'static,
        {
            self
        }
    }
    let mut vm = IVM::new(10_000);
    vm.load_program(&raw_zk_program(&[scall(syscalls::SYSCALL_CURRENT_TIME_MS)]))
        .expect("load private host-output fixture");
    vm.set_host(PrivateOutputHost);
    assert_eq!(vm.run(), Err(VMError::PrivacyViolation));
    assert!(vm.registers.tag(10), "the VM must not launder the host tag");
}
#[test]
fn private_input_cannot_flow_directly_to_public_syscall_sinks() {
    for sink in [
        syscalls::SYSCALL_DEBUG_PRINT,
        syscalls::SYSCALL_INPUT_PUBLISH_TLV,
    ] {
        let program = raw_zk_program(&[scall(syscalls::SYSCALL_GET_PRIVATE_INPUT), scall(sink)]);
        let mut vm = IVM::new(10_000);
        vm.set_host(int_private_host(&[42]));
        vm.load_program(&program).unwrap();
        vm.set_register(10, 0);
        let error = vm
            .run()
            .expect_err("private public-sink argument must trap");
        assert!(matches!(error, VMError::PrivacyViolation), "sink {sink:#x}");
    }
}
#[test]
fn valcom_declassifies_matching_private_operands() {
    let program = raw_zk_program(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 0, 0),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 11, 0, 0),
        scall(syscalls::SYSCALL_GET_PRIVATE_INPUT),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 10, 0),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 0, 1),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 11, 0, 0),
        scall(syscalls::SYSCALL_GET_PRIVATE_INPUT),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 11, 10, 0),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 1, 0),
        scall(syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM),
    ]);
    let mut vm = IVM::new(100_000);
    vm.set_host(int_private_host(&[7, 11]));
    vm.load_program(&program).unwrap();
    vm.run().expect("private commitment should run");
    let commitment = common::decode_int_word(&vm, vm.register(10));
    assert!(
        commitment.bit_len() > 64,
        "commitment must not be truncated"
    );
    assert!(!vm.registers.tag(10));
}
#[test]
fn compiled_secret_commitment_executes_end_to_end() {
    let source = r#"
        seiyaku Privacy { permission CreateCommitment;
            kotoage fn commitment() authorize(CreateCommitment) -> int {
                let Secret<int> value = crypto::private_input(0);
                let Secret<int> blinding = crypto::private_input(1);
                return crypto::valcom(left: value, right: blinding);
            }
        }
    "#;
    let artifact = kotodama_lang::compiler::Compiler::new_with_options(
        kotodama_lang::compiler::CompilerOptions {
            force_zk: true,
            ..kotodama_lang::compiler::CompilerOptions::default()
        },
    )
    .compile_source(source)
    .expect("compile a source-level Secret<T> commitment");
    let metadata = ProgramMetadata::parse(&artifact).expect("parse compiled artifact");
    assert_ne!(
        metadata.metadata.mode & ivm::ivm_mode::ZK,
        0,
        "Secret<T> artifacts must bind ZK execution mode"
    );
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(int_private_host(&[7, 11]));
    vm.load_program(&artifact).expect("load compiled artifact");
    common::select_kotodama_entrypoint(&mut vm, &artifact, "commitment");
    vm.run().expect("execute approved commitment");
    assert_eq!(
        vm.call_result_word_count().expect("completed result table"),
        1
    );
    assert!(
        common::decode_int_return_word(&vm, 0).bit_len() > 64,
        "source commitment must retain the complete compressed point"
    );
    assert!(
        !vm.registers.tag(10),
        "the approved commitment must be the explicit declassification boundary"
    );
}
#[test]
fn typed_int_decimal_and_quantity_commitments_execute_and_bind_nominal_kind() {
    fn compile(kind: &str) -> Vec<u8> {
        let source = format!(
            r#"
                seiyaku Privacy {{ permission CreateCommitment;
                    kotoage fn commitment() authorize(CreateCommitment) -> int {{
                        let Secret<{kind}> value = crypto::private_input(0);
                        let Secret<{kind}> blinding = crypto::private_input(1);
                        return crypto::valcom(left: value, right: blinding);
                    }}
                }}
            "#
        );
        kotodama_lang::compiler::Compiler::new_with_options(
            kotodama_lang::compiler::CompilerOptions {
                force_zk: true,
                ..kotodama_lang::compiler::CompilerOptions::default()
            },
        )
        .compile_source(&source)
        .unwrap_or_else(|error| panic!("compile Secret<{kind}> commitment: {error}"))
    }
    let cases = [
        (
            "int",
            vec![
                ivm::private_input::int_record(7_u64.into()).unwrap(),
                ivm::private_input::int_record(11_u64.into()).unwrap(),
            ],
        ),
        (
            "decimal",
            vec![
                ivm::private_input::decimal_record("7".parse::<Numeric>().unwrap()).unwrap(),
                ivm::private_input::decimal_record("11".parse::<Numeric>().unwrap()).unwrap(),
            ],
        ),
        (
            "quantity",
            vec![
                ivm::private_input::quantity_record(Quantity::from(7_u32)).unwrap(),
                ivm::private_input::quantity_record(Quantity::from(11_u32)).unwrap(),
            ],
        ),
    ];
    let mut commitments = Vec::new();
    for (kind, records) in cases {
        let artifact = compile(kind);
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(typed_private_host(records));
        vm.load_program(&artifact)
            .unwrap_or_else(|error| panic!("load Secret<{kind}> artifact: {error}"));
        common::select_kotodama_entrypoint(&mut vm, &artifact, "commitment");
        vm.run()
            .unwrap_or_else(|error| panic!("execute Secret<{kind}> commitment: {error}"));
        assert_eq!(
            vm.call_result_word_count().expect("completed result table"),
            1
        );
        let commitment = common::decode_int_return_word(&vm, 0);
        assert!(
            commitment.bit_len() > 64,
            "Secret<{kind}> commitment was truncated"
        );
        assert!(!vm.registers.tag(10));
        commitments.push(commitment);
    }
    assert_ne!(commitments[0], commitments[1]);
    assert_ne!(commitments[0], commitments[2]);
    assert_ne!(commitments[1], commitments[2]);
    let decimal_artifact = compile("decimal");
    let mut wrong_kind = IVM::new(1_000_000);
    wrong_kind.set_host(int_private_host(&[7, 11]));
    wrong_kind
        .load_program(&decimal_artifact)
        .expect("load decimal commitment artifact");
    common::select_kotodama_entrypoint(&mut wrong_kind, &decimal_artifact, "commitment");
    assert_eq!(wrong_kind.run(), Err(VMError::NoritoInvalid));
    assert_eq!(
        wrong_kind.alloc_heap(1).expect("probe untouched heap"),
        Memory::HEAP_START,
        "wrong-kind rejection must occur before private or public allocation"
    );
}
#[test]
fn poseidon_opcodes_never_declassify_private_operands() {
    fn program_fetching_private_operands(operands: &[u8], word: u32) -> Vec<u8> {
        let mut words = Vec::with_capacity(operands.len() * 4 + 1);
        for (index, register) in operands.iter().copied().enumerate() {
            words.push(encoding::wide::encode_ri(
                instruction::wide::arithmetic::ADDI,
                10,
                0,
                i8::try_from(index).expect("small private-input index"),
            ));
            words.push(encoding::wide::encode_ri(
                instruction::wide::arithmetic::ADDI,
                11,
                0,
                0,
            ));
            words.push(scall(syscalls::SYSCALL_GET_PRIVATE_INPUT));
            words.push(encoding::wide::encode_ri(
                instruction::wide::arithmetic::ADDI,
                register,
                10,
                0,
            ));
        }
        words.push(word);
        raw_zk_program(&words)
    }
    for (label, word, operands) in [
        (
            "POSEIDON2",
            encoding::wide::encode_rr(instruction::wide::crypto::POSEIDON2, 3, 1, 2),
            vec![1, 2],
        ),
        (
            "POSEIDON6",
            encoding::wide::encode_poseidon6(3, 20),
            (20..26).collect(),
        ),
    ] {
        let program = program_fetching_private_operands(&operands, word);
        let mut all_private = IVM::new(100_000);
        all_private.set_host(int_private_host(&vec![7; operands.len()]));
        all_private.load_program(&program).unwrap();
        assert_eq!(
            all_private.run(),
            Err(VMError::PrivacyViolation),
            "{label} accepted all-private operands"
        );
        if operands.len() > 1 {
            let mixed_program = program_fetching_private_operands(&operands[..1], word);
            let mut mixed = IVM::new(100_000);
            mixed.set_host(int_private_host(&[11]));
            mixed.load_program(&mixed_program).unwrap();
            for (offset, register) in operands.iter().copied().enumerate().skip(1) {
                mixed.set_register(
                    usize::from(register),
                    11 + u64::try_from(offset).expect("small operand index"),
                );
            }
            assert_eq!(
                mixed.run(),
                Err(VMError::PrivacyViolation),
                "{label} accepted mixed-visibility operands"
            );
        }
    }
}
#[test]
fn zk_field_operations_propagate_private_tags_and_reject_mixed_visibility() {
    for opcode in [
        instruction::wide::zk::FADD,
        instruction::wide::zk::FSUB,
        instruction::wide::zk::FMUL,
    ] {
        let program = raw_zk_program(&[encoding::wide::encode_rr(opcode, 3, 1, 2)]);
        let mut private_vm = IVM::new(10_000);
        private_vm.load_program(&program).unwrap();
        private_vm.set_register(1, 7);
        private_vm.set_register(2, 11);
        private_vm.registers.set_tag(1, true);
        private_vm.registers.set_tag(2, true);
        private_vm
            .run()
            .unwrap_or_else(|error| panic!("private field opcode {opcode:#x} failed: {error}"));
        assert!(
            private_vm.registers.tag(3),
            "field opcode {opcode:#x} laundered a private result"
        );
        let mut mixed_vm = IVM::new(10_000);
        mixed_vm.load_program(&program).unwrap();
        mixed_vm.set_register(1, 7);
        mixed_vm.set_register(2, 11);
        mixed_vm.registers.set_tag(1, true);
        let error = mixed_vm.run().expect_err("mixed field operands must trap");
        assert!(matches!(error, VMError::PrivacyViolation));
    }
}
#[test]
fn zk_field_inverse_rejects_private_operand_independent_of_invertibility() {
    let mut expected_remaining = None;
    for value in [0_u64, 7] {
        let program = raw_zk_program(&[encoding::wide::encode_rr(
            instruction::wide::zk::FINV,
            3,
            1,
            0,
        )]);
        let mut vm = IVM::new(10_000);
        vm.load_program(&program).unwrap();
        vm.set_register(1, value);
        vm.registers.set_tag(1, true);
        assert_eq!(vm.run(), Err(VMError::PrivacyViolation));
        let remaining = vm.remaining_gas();
        if let Some(expected) = expected_remaining {
            assert_eq!(remaining, expected, "private inverse leaked through gas");
        } else {
            expected_remaining = Some(remaining);
        }
    }
}
#[test]
fn zk_field_results_cannot_reach_public_syscall_sinks() {
    let program = raw_zk_program(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 0, 0),
        scall(syscalls::SYSCALL_GET_PRIVATE_INPUT),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 10, 0),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 2, 10, 0),
        encoding::wide::encode_rr(instruction::wide::zk::FADD, 10, 1, 2),
        scall(syscalls::SYSCALL_DEBUG_PRINT),
    ]);
    let mut vm = IVM::new(10_000);
    vm.set_host(int_private_host(&[7]));
    vm.load_program(&program).unwrap();
    let error = vm
        .run()
        .expect_err("field-derived secret must not reach a public syscall");
    assert!(matches!(error, VMError::PrivacyViolation));
}
#[test]
fn private_stack_spill_cannot_launder_a_syscall_argument() {
    let program = raw_zk_program(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 0, 0),
        scall(syscalls::SYSCALL_GET_PRIVATE_INPUT),
        encoding::wide::encode_store(instruction::wide::memory::STORE64, 1, 10, 0),
        encoding::wide::encode_load(instruction::wide::memory::LOAD64, 10, 1, 0),
        scall(syscalls::SYSCALL_DEBUG_PRINT),
    ]);
    let mut vm = IVM::new(10_000);
    vm.set_host(int_private_host(&[42]));
    vm.load_program(&program).unwrap();
    vm.set_register(1, Memory::STACK_START);
    let error = vm
        .run()
        .expect_err("a stack roundtrip must preserve the private tag");
    assert!(matches!(error, VMError::PrivacyViolation));
    assert!(vm.registers.tag(10));
}
#[test]
fn private_stack_envelope_cannot_be_published_through_a_public_pointer() {
    let program = raw_zk_program(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 0, 0),
        scall(syscalls::SYSCALL_GET_PRIVATE_INPUT),
        encoding::wide::encode_store(instruction::wide::memory::STORE64, 1, 10, 8),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 1, 0),
        scall(syscalls::SYSCALL_INPUT_PUBLISH_TLV),
    ]);
    let mut vm = IVM::new(10_000);
    vm.set_host(int_private_host(&[42]));
    vm.load_program(&program).expect("load ZK program");
    let payload = [0_u8; 16];
    let mut envelope = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    envelope.extend_from_slice(&(PointerType::Blob as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&payload);
    let hash: [u8; Hash::LENGTH] = Hash::new(payload).into();
    envelope.extend_from_slice(&hash);
    vm.store_bytes(Memory::STACK_START, &envelope)
        .expect("seed public stack envelope");
    vm.set_register(1, Memory::STACK_START);
    let error = vm
        .run()
        .expect_err("private envelope bytes must not cross the public host boundary");
    assert!(matches!(error, VMError::PrivacyViolation));
    assert!(
        !vm.registers.tag(10),
        "the pointer register itself is public"
    );
}
#[test]
fn signature_opcodes_reject_private_tlv_header_payload_and_checksum_bytes() {
    for opcode in [
        instruction::wide::crypto::ED25519BATCHVERIFY,
        instruction::wide::crypto::ED25519VERIFY,
        instruction::wide::crypto::ECDSAVERIFY,
        instruction::wide::crypto::DILITHIUMVERIFY,
    ] {
        for private_offset in [0_u64, 7, 7 + 32] {
            let program = private_store_then(encoding::wide::encode_rr(opcode, 3, 1, 2));
            let mut vm = IVM::new(100_000);
            vm.load_program(&program)
                .expect("load signature privacy fixture");
            let pointer = Memory::STACK_START;
            let envelope = blob_tlv(&[0_u8; 32]);
            vm.store_bytes(pointer, &envelope)
                .expect("seed public signature TLV");
            mark_one_private_stack_byte(&mut vm, pointer + private_offset);
            for register in [1, 2, 3] {
                vm.set_register(register, pointer);
                vm.registers.set_tag(register, false);
            }
            assert_eq!(
                vm.run(),
                Err(VMError::PrivacyViolation),
                "signature opcode {opcode:#x} converted private TLV bytes at offset {private_offset} into a public verification result"
            );
        }
    }
}
#[test]
fn megabyte_public_tlv_privacy_preflight_checks_ranges_before_gas_debit() {
    struct ExpensivePrepareHost {
        prepares: Cell<u32>,
        calls: Cell<u32>,
    }
    impl IVMHost for ExpensivePrepareHost {
        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            self.prepares.set(self.prepares.get() + 1);
            Ok(1_000_000)
        }
        fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
            self.calls.set(self.calls.get() + 1);
            Ok(1_000_000)
        }
        fn as_any(&mut self) -> &mut dyn Any
        where
            Self: 'static,
        {
            self
        }
    }
    let run = |private_byte_offset: Option<usize>| {
        let program = private_store_then(scall(syscalls::SYSCALL_INPUT_PUBLISH_TLV));
        // Allocate the one-megabyte stack fixture independently of the low
        // execution budget, then apply the budget the assertion exercises.
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program).expect("load low-gas ZK syscall");
        let envelope = blob_tlv(&vec![0x5A; 1024 * 1024]);
        let pointer = Memory::STACK_START;
        vm.store_bytes(pointer, &envelope)
            .expect("store one-megabyte public stack TLV");
        if let Some(offset) = private_byte_offset {
            mark_one_private_stack_byte(
                &mut vm,
                pointer + u64::try_from(offset).expect("offset fits u64"),
            );
        } else {
            vm.set_program_counter(CONTINUATION_PC)
                .expect("skip private-store test prefix");
        }
        vm.set_register(10, pointer);
        vm.set_gas_limit(64);
        let mut host = ExpensivePrepareHost {
            prepares: Cell::new(0),
            calls: Cell::new(0),
        };
        let result = vm.run_with_host(&mut host);
        (
            result,
            host.prepares.get(),
            host.calls.get(),
            envelope.len(),
            vm.remaining_gas(),
        )
    };
    let (public_result, public_prepares, public_calls, envelope_len, public_gas) = run(None);
    assert_eq!(public_result, Err(VMError::OutOfGas));
    assert_eq!(public_prepares, 1);
    assert_eq!(public_calls, 0);
    let (unrelated_result, unrelated_prepares, unrelated_calls, _, unrelated_gas) =
        run(Some(envelope_len));
    assert_eq!(unrelated_result, Err(VMError::OutOfGas));
    assert_eq!(unrelated_prepares, 1);
    assert_eq!(unrelated_calls, 0);
    assert_eq!(unrelated_gas, public_gas);
    let overlapping_offset = 7 + 512 * 1024;
    let (overlap_result, overlap_prepares, overlap_calls, _, overlap_gas) =
        run(Some(overlapping_offset));
    assert_eq!(overlap_result, Err(VMError::PrivacyViolation));
    assert_eq!(overlap_prepares, 0);
    assert_eq!(overlap_calls, 0);
    assert_eq!(overlap_gas, public_gas);
    for boundary_offset in [0, envelope_len - 1] {
        let (boundary_result, boundary_prepares, boundary_calls, _, boundary_gas) =
            run(Some(boundary_offset));
        assert_eq!(boundary_result, Err(VMError::PrivacyViolation));
        assert_eq!(boundary_prepares, 0);
        assert_eq!(boundary_calls, 0);
        assert_eq!(boundary_gas, public_gas);
    }
}
#[test]
fn private_store_outside_the_stack_is_rejected() {
    for address in [
        Memory::HEAP_START,
        Memory::INPUT_START,
        Memory::OUTPUT_START,
    ] {
        let program = raw_zk_program(&[
            encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 0, 0),
            scall(syscalls::SYSCALL_GET_PRIVATE_INPUT),
            encoding::wide::encode_store(instruction::wide::memory::STORE64, 1, 10, 0),
        ]);
        let mut vm = IVM::new(10_000);
        vm.set_host(int_private_host(&[42]));
        vm.load_program(&program).unwrap();
        vm.set_register(1, address);
        let error = vm
            .run()
            .expect_err("private stores outside the stack must trap");
        assert!(matches!(error, VMError::PrivacyViolation));
    }
}
#[test]
fn partial_public_overwrite_does_not_declassify_a_private_stack_word() {
    let mut vm = vm_with_private_stack_word();
    vm.store_u32(Memory::STACK_START, 0).unwrap();
    let error = vm.run().expect_err("mixed-visibility words must trap");
    assert!(matches!(error, VMError::PrivacyViolation));
}
#[test]
fn complete_public_overwrite_clears_private_stack_range() {
    let mut vm = vm_with_private_stack_word();
    vm.store_u64(Memory::STACK_START, 7).unwrap();
    vm.run()
        .expect("complete public overwrite declassifies the whole word");
    assert_eq!(vm.register(3), 7);
    assert!(!vm.registers.tag(3));
}
#[test]
fn execution_summary_preserves_private_stack_ranges() {
    let mut vm = vm_with_private_stack_word();
    let _summary = vm.execution_summary();
    vm.run()
        .expect("execution summary must not discard privacy metadata");
    assert_eq!(vm.register(3), 0xCAFE_BABE_DEAD_BEEF);
    assert!(vm.registers.tag(3));
}
#[test]
fn reset_scrubs_private_stack_spills() {
    let mut vm = vm_with_private_stack_word();
    vm.reset().expect("private lifecycle cleanup succeeds");
    assert_eq!(vm.load_u64(Memory::STACK_START).unwrap(), 0);
}
#[test]
fn disabling_zk_mode_scrubs_private_stack_spills() {
    let mut vm = vm_with_private_stack_word();
    vm.set_register(7, 0x1234_5678);
    vm.set_zk_mode(false)
        .expect("private lifecycle cleanup succeeds");
    assert_eq!(vm.load_u64(Memory::STACK_START).unwrap(), 0);
    assert_eq!(vm.register(2), 0);
    assert!(!vm.registers.tag(2));
    assert_eq!(vm.register(7), 0x1234_5678);
    assert!(!vm.registers.tag(7));
}
#[test]
fn disabling_zk_mode_discards_private_trace_and_write_history() {
    const PRIVATE_VALUE: u64 = 0xCAFE_BABE_DEAD_BEEF;
    let mut vm = IVM::new(u64::MAX);
    vm.set_zk_trace_enabled(true);
    vm.set_trace_mode(ivm::TraceMode::DeltaRegisters);
    vm.load_program(&private_store_then(encoding::wide::encode_halt()))
        .expect("load private trace fixture");
    vm.set_register(1, Memory::STACK_START);
    vm.set_register(2, PRIVATE_VALUE);
    vm.registers.set_tag(2, true);
    vm.run().expect("record private trace fixture");

    assert!(
        common::diagnostic_snapshot(&vm)
            .states()
            .iter()
            .any(|state| state.gpr[2] == PRIVATE_VALUE)
    );
    assert!(
        common::diagnostic_snapshot(&vm)
            .register_events()
            .any(|event| event.value == PRIVATE_VALUE)
    );
    assert!(
        vm.memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot")
            .iter()
            .any(|entry| {
                entry
                    .bytes()
                    .windows(8)
                    .any(|bytes| bytes == PRIVATE_VALUE.to_le_bytes().as_slice())
            })
    );

    vm.set_zk_mode(false)
        .expect("private lifecycle cleanup succeeds");

    assert!(common::diagnostic_snapshot(&vm).states().is_empty());
    assert!(common::diagnostic_snapshot(&vm).register_event_count() == 0);
    assert!(vm.memory_log().is_empty());
    assert!(vm.delta_register_trace().is_empty());
    assert!(vm.step_log().is_empty());
    assert!(
        vm.memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot")
            .is_empty()
    );
}
#[test]
fn raw_code_load_scrubs_private_registers_and_preserves_public_arguments() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_zk_mode(true)
        .expect("private lifecycle cleanup succeeds");
    vm.set_register(2, 0xCAFE_BABE_DEAD_BEEF);
    vm.registers.set_tag(2, true);
    vm.set_register(7, 0x1234_5678);

    vm.load_code(&encoding::wide::encode_halt().to_le_bytes())
        .expect("replace the ZK program with raw public code");

    assert_eq!(vm.register(2), 0);
    assert!(!vm.registers.tag(2));
    assert_eq!(vm.register(7), 0x1234_5678);
    assert!(!vm.registers.tag(7));
}
#[test]
fn artifact_load_scrubs_private_registers_and_preserves_public_arguments() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_zk_mode(true)
        .expect("private lifecycle cleanup succeeds");
    vm.set_register(2, 0xCAFE_BABE_DEAD_BEEF);
    vm.registers.set_tag(2, true);
    vm.set_register(7, 0x1234_5678);
    let mut artifact = ProgramMetadata::default().encode();
    artifact.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());

    vm.load_program(&artifact)
        .expect("replace the ZK program with a public artifact");

    assert_eq!(vm.register(2), 0);
    assert!(!vm.registers.tag(2));
    assert_eq!(vm.register(7), 0x1234_5678);
    assert!(!vm.registers.tag(7));
}
#[test]
fn non_zk_run_rejects_injected_private_register_state() {
    let mut vm = IVM::new(u64::MAX);
    vm.load_code(&encoding::wide::encode_halt().to_le_bytes())
        .expect("load public code");
    vm.set_register(2, 0xCAFE_BABE_DEAD_BEEF);
    vm.registers.set_tag(2, true);

    assert_eq!(vm.run(), Err(VMError::PrivacyViolation));
}
#[test]
fn runtime_template_restores_private_stack_tags_with_their_bytes() {
    let mut vm = vm_with_private_stack_word();
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.set_zk_mode(false)
        .expect("private lifecycle cleanup succeeds");
    assert!(!vm.zk_mode_enabled());
    vm.reset_from_runtime_template(&template)
        .expect("private-memory template geometry must match");
    assert!(
        vm.zk_mode_enabled(),
        "a private template must restore its ZK execution mode"
    );
    vm.run().unwrap();
    assert_eq!(vm.register(3), 0xCAFE_BABE_DEAD_BEEF);
    assert!(vm.registers.tag(3));
    assert_eq!(vm.ensure_public_register(3), Err(VMError::PrivacyViolation));
}
