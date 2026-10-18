//! Arithmetic instruction coverage and regression checks.
use crate::common;
use common::assemble;
use ivm::{IVM, VMError, encoding, instruction};
const HALT_WORD: u32 = encoding::wide::encode_halt();
#[test]
fn check_wide_add_opcode_is_valid() {
    assert!(instruction::wide::is_valid_opcode(
        instruction::wide::arithmetic::ADD
    ));
}
fn assemble_words(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assemble(&bytes)
}
#[test]
fn test_arithmetic_operations() {
    let mut vm = IVM::new(u64::MAX);
    // 1. Test ADD: 5 + 7 = 12
    vm.set_register(1, 5);
    vm.set_register(2, 7);
    // Program: ADD x3 = x1 + x2; HALT
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("ADD failed");
    assert_eq!(vm.register(3), 12);
    // 2. Test SUB: 5 - 10 = -5 (two's complement 0xFFFFFFFB)
    vm.set_register(1, 5);
    vm.set_register(2, 10);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::SUB, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("SUB failed");
    let result_sub = vm.register(3);
    assert_eq!(result_sub as i64, -5);
    // 3. Test MUL: 70000 * 70000 = 4_900_000_000
    vm.set_register(1, 70000);
    vm.set_register(2, 70000);
    // MUL x3,x1,x2; HALT (funct7=0x01)
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::MUL, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("MUL failed");
    let result_mul = vm.register(3);
    assert_eq!(result_mul, 4_900_000_000u64);
    // 4. Test DIV and division by zero handling.
    let div_word = encoding::wide::encode_rr(instruction::wide::arithmetic::DIV, 3, 1, 2);
    // 4a. 10 / 2 = 5
    vm.set_register(1, 10);
    vm.set_register(2, 2);
    let prog_tmp = assemble_words(&[div_word, HALT_WORD]);
    vm.load_program(&prog_tmp).unwrap();
    vm.run().expect("DIV failed");
    assert_eq!(vm.register(3), 5);
    // 4b. -10 / 2 = -5
    vm.set_register(1, (-10i64) as u64);
    vm.set_register(2, 2);
    let prog_tmp = assemble_words(&[div_word, HALT_WORD]);
    vm.load_program(&prog_tmp).unwrap();
    vm.run().expect("DIV negative failed");
    assert_eq!(vm.register(3) as i64, -5);
    // 4c. Division by zero triggers AssertionFailed
    vm.set_register(1, 10);
    vm.set_register(2, 0);
    let prog_tmp = assemble_words(&[div_word, HALT_WORD]);
    vm.load_program(&prog_tmp).unwrap();
    let result = vm.run();
    assert!(
        matches!(result, Err(VMError::AssertionFailed)),
        "Expected AssertionFailed on div by zero"
    );
    // 5. Test that x0 stays 0 (writes to x0 are ignored)
    vm.set_register(1, 42);
    vm.set_register(2, 1);
    // Program: ADD x0 = x1 + x2; HALT  (i.e., try to write to x0)
    let prog_tmp = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 0, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog_tmp).unwrap();
    vm.run().expect("Execution failed");
    assert_eq!(vm.register(0), 0, "x0 should remain 0");
    // 6. Integer square root: isqrt(81) = 9
    vm.set_register(1, 81);
    let prog_tmp = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::ISQRT, 3, 1, 0),
        HALT_WORD,
    ]);
    vm.load_program(&prog_tmp).unwrap();
    vm.run().expect("ISQRT failed");
    assert_eq!(vm.register(3), 9);
}
#[test]
fn math_helpers_min_max_abs_divceil_gcd_mean() {
    let mut vm = IVM::new(u64::MAX);
    // MIN/MAX
    vm.set_register(1, 10);
    vm.set_register(2, 20);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::MIN, 3, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::MAX, 4, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("min/max");
    assert_eq!(vm.register(3), 10);
    assert_eq!(vm.register(4), 20);
    // ABS (negative)
    vm.set_register(1, (-7i64) as u64);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::ABS, 3, 1, 0),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("abs");
    assert_eq!(vm.register(3), 7);
    // DIV_CEIL (-3,2) = -1
    vm.set_register(1, (-3i64) as u64);
    vm.set_register(2, 2);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::DIV_CEIL, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("div_ceil");
    assert_eq!(vm.register(3) as i64, -1);
    // DIV_CEIL rejects the only signed quotient that cannot fit in i64.
    vm.set_register(1, i64::MIN as u64);
    vm.set_register(2, (-1i64) as u64);
    vm.set_register(3, 0xCAFE_BABE_DEAD_BEEF);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::DIV_CEIL, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    assert!(matches!(vm.run(), Err(VMError::AssertionFailed)));
    assert_eq!(vm.register(3), 0xCAFE_BABE_DEAD_BEEF);
    // GCD(48, 18) = 6
    vm.set_register(1, 48);
    vm.set_register(2, 18);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::GCD, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("gcd");
    assert_eq!(vm.register(3), 6);
    // GCD(i64::MIN, 0) = 2^63 without overflow.
    vm.set_register(1, i64::MIN as u64);
    vm.set_register(2, 0);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::GCD, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("gcd min");
    assert_eq!(vm.register(3), 1u64 << 63);
    // MEAN floor((5 + 6)/2) = 5
    vm.set_register(1, 5);
    vm.set_register(2, 6);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::MEAN, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("mean");
    assert_eq!(vm.register(3), 5);
}
#[test]
fn test_bitwise_and_or_xor() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0x0F0F_0F0F_0F0F_0F0F);
    vm.set_register(2, 0x3333_3333_3333_3333);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::AND, 3, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::OR, 4, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::XOR, 5, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("bitwise ops failed");
    assert_eq!(vm.register(3), 0x0303_0303_0303_0303);
    assert_eq!(vm.register(4), 0x3F3F_3F3F_3F3F_3F3F);
    assert_eq!(vm.register(5), 0x3C3C_3C3C_3C3C_3C3C);
}
#[test]
fn test_shift_register_ops() {
    // Enable debug logging for invalid opcodes in case of regression (disabled in CI)
    // NOTE: on some restricted runners, setting env may be unsafe; skip it here.
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 4); // shift amount
    vm.set_register(3, 0x80);
    vm.set_register(4, (-8i64) as u64);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::SLL, 5, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::SRL, 6, 3, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::SRA, 7, 4, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("shift reg ops failed");
    assert_eq!(vm.register(5), 16);
    assert_eq!(vm.register(6), 0x8);
    assert_eq!(vm.register(7), 0xFFFF_FFFF_FFFF_FFFF);
}
#[test]
fn test_mulh_mulhu_divu_remu() {
    let mut vm = IVM::new(u64::MAX);
    // MULH signed high product
    vm.set_register(1, 0x1_0000_0000);
    vm.set_register(2, 0x2_0000_0000);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::MULH, 3, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::MULHU, 4, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::DIVU, 7, 5, 6),
        encoding::wide::encode_rr(instruction::wide::arithmetic::REMU, 8, 5, 6),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.set_register(5, 20);
    vm.set_register(6, 3);
    vm.run().expect("extended arithmetic ops failed");
    assert_eq!(vm.register(3), 2);
    assert_eq!(vm.register(4), 2);
    assert_eq!(vm.register(7), 6);
    assert_eq!(vm.register(8), 2);
}
