//! Admission and runtime rejection of retired or unassigned instruction words.
use crate::common;
use common::assemble;
use ivm::{IVM, VMError, encoding};
#[test]
fn classic_opcode_is_rejected() {
    // Classic RISC-V ADD encoding (rd=x0, rs1=x0, rs2=x0, funct3=0, funct7=0, opcode=0x33).
    let add_rv = 0x0000_0033u32;
    let halt = encoding::wide::encode_halt();
    let mut bytes = Vec::new();
    for word in [add_rv, halt] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let program = assemble(&bytes);
    let mut vm = IVM::new(1_000);
    let err = vm
        .load_program(&program)
        .expect_err("classic opcode must be rejected");
    assert!(matches!(err, VMError::InvalidOpcode(0x0033)));
}
#[test]
fn classic_opcode_runtime_rejected_after_manual_load() {
    // Write a classic ADD instruction directly into memory to bypass loader validation.
    let add_rv = 0x0000_0033u32;
    let halt = encoding::wide::encode_halt();
    let mut bytes = Vec::new();
    for word in [add_rv, halt] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let mut vm = IVM::new(1_000);
    vm.memory.load_code(&bytes).unwrap();
    vm.pc = 0;
    assert_eq!(vm.memory.load_u32(0).expect("load"), add_rv);
    let err = vm
        .run()
        .expect_err("classic opcode must trap during execution");
    assert!(matches!(err, VMError::InvalidOpcode(0x0033)));
}

#[test]
fn unassigned_crypto_slots_are_rejected_by_admission_and_runtime() {
    for opcode in 0x8B..=0x8F {
        let word = encoding::wide::encode_rr(opcode, 3, 1, 2);
        // InvalidOpcode identifies the rejected word's low 16 bits on both paths.
        let invalid_word = (word & 0xFFFF) as u16;
        let mut bytes = word.to_le_bytes().to_vec();
        bytes.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
        let program = assemble(&bytes);
        let mut admitted = IVM::new(1_000);
        assert!(
            match (
                &(admitted.load_program(&program)),
                &(VMError::InvalidOpcode(invalid_word))
            ) {
                (
                    Err(VMError::InvalidOpcode(actual_field_0)),
                    VMError::InvalidOpcode(expected_field_0),
                ) => actual_field_0 == expected_field_0,
                _ => false,
            },
            "unassigned opcode 0x{opcode:02x} passed artifact admission"
        );

        let mut raw = IVM::new(1_000);
        raw.memory.load_code(&bytes).unwrap();
        raw.pc = 0;
        assert!(
            match (&(raw.run()), &(VMError::InvalidOpcode(invalid_word))) {
                (
                    Err(VMError::InvalidOpcode(actual_field_0)),
                    VMError::InvalidOpcode(expected_field_0),
                ) => actual_field_0 == expected_field_0,
                _ => false,
            },
            "unassigned opcode 0x{opcode:02x} executed after manual loading"
        );
    }
}
