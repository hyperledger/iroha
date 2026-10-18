use crate::common;
use common::assemble;
use ivm::{IVM, encoding, instruction};
const HALT_WORD: u32 = encoding::wide::encode_halt();
fn assemble_words(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assemble(&bytes)
}
#[test]
fn test_shift_immediate_ops() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 4); // shift amount for SLL
    vm.set_register(6, 0xFFFF_FFFF_FFFF_FFFF);
    vm.set_register(7, 1); // shift amount for SRL
    vm.set_register(8, 1); // shift amount for SRA
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::SLL, 3, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::SRL, 4, 3, 7),
        encoding::wide::encode_rr(instruction::wide::arithmetic::SRA, 5, 6, 8),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("shift ops failed");
    assert_eq!(vm.register(3), 16);
    assert_eq!(vm.register(4), 8);
    assert_eq!(vm.register(5), 0xFFFF_FFFF_FFFF_FFFF);
}
#[test]
fn test_branch_signed_unsigned() {
    // Case 1: BLT should be taken (signed)
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, (-1i64) as u64);
    vm.set_register(2, 1);
    // Branch offset measured in 32-bit words; offset=2 skips one instruction (addi1).
    let prog = assemble_words(&[
        encoding::wide::encode_branch(instruction::wide::control::BLT, 1, 2, 2),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 3, 0, 1),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 3, 0, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("branch failed");
    let val = vm.register(3);
    assert_eq!(val, 2, "x3={val}, should be 2");
}
#[test]
fn test_not_and_bit_counts() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0x00FF00FF00FF00FF);
    // NOT x2,x1; CLZ x3,x1; CTZ x4,x1; POPCNT x5,x1
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::NOT, 2, 1, 0),
        encoding::wide::encode_rr(instruction::wide::arithmetic::CLZ, 3, 1, 0),
        encoding::wide::encode_rr(instruction::wide::arithmetic::CTZ, 4, 1, 0),
        encoding::wide::encode_rr(instruction::wide::arithmetic::POPCNT, 5, 1, 0),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("bit ops failed");
    assert_eq!(vm.register(2), !0x00FF00FF00FF00FFu64);
    assert_eq!(vm.register(3), 8); // leading zeros
    assert_eq!(vm.register(4), 0); // trailing zeros
    assert_eq!(vm.register(5), 32);
}
#[test]
fn test_rotate_ops() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0x01);
    vm.set_register(2, 0x10);
    let prog = assemble_words(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ROTL_IMM, 3, 1, 4),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ROTR_IMM, 4, 2, 4),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("rotate ops failed");
    assert_eq!(vm.register(3), 0x10);
    assert_eq!(vm.register(4), 0x01);
}
