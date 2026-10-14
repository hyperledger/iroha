use crate::common;
use common::assemble_zk;
use ivm::{IVM, VMError, encoding, instruction, zk::MAX_CYCLES};
const HALT_WORD: u32 = encoding::wide::encode_halt();
fn encode_words(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
#[test]
fn test_assert_instruction() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    let instr = encoding::wide::encode_rr(instruction::wide::zk::ASSERT, 0, 1, 0);
    let prog = assemble_zk(&encode_words(&[instr, HALT_WORD]), 32);
    vm.load_program(&prog).unwrap();
    eprintln!("r1 before run = {}", vm.register(1));
    let res = vm.run();
    assert!(matches!(res, Err(VMError::AssertionFailed)));
    // Passing case
    let mut vm2 = IVM::new(u64::MAX);
    vm2.set_register(1, 0);
    let prog = assemble_zk(&encode_words(&[instr, HALT_WORD]), 32);
    vm2.load_program(&prog).unwrap();
    vm2.run().expect("assert should pass");
}
#[test]
fn test_assert_eq_instruction() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 5);
    vm.set_register(2, 5);
    let instr_eq = encoding::wide::encode_rr(instruction::wide::zk::ASSERT_EQ, 0, 1, 2);
    let code = encode_words(&[instr_eq, HALT_WORD]);
    let prog = assemble_zk(&code, 32);
    vm.load_program(&prog).unwrap();
    vm.run().expect("assert_eq should pass");
    // Failing case
    let mut vm2 = IVM::new(u64::MAX);
    vm2.set_register(1, 1);
    vm2.set_register(2, 2);
    let prog = assemble_zk(&code, 32);
    vm2.load_program(&prog).unwrap();
    eprintln!("r1={}, r2={} before run", vm2.register(1), vm2.register(2));
    let res = vm2.run();
    assert!(matches!(res, Err(VMError::AssertionFailed)));
}
#[test]
fn test_assert_zk_padding() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    let instr = encoding::wide::encode_rr(instruction::wide::zk::ASSERT, 0, 1, 0);
    let prog = assemble_zk(&encode_words(&[instr, HALT_WORD]), MAX_CYCLES);
    vm.load_program(&prog).unwrap();
    eprintln!("r1 before run = {}", vm.register(1));
    let res = vm.run();
    assert!(matches!(res, Err(VMError::AssertionFailed)));
    assert_eq!(vm.get_cycle_count(), MAX_CYCLES);
}
