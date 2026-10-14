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
fn test_slt_sltu() {
    let mut vm = IVM::new(u64::MAX);
    // SLT (signed)
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::SLT, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.set_register(1, (-5i64) as u64);
    vm.set_register(2, 4);
    vm.run().expect("SLT execution failed");
    assert_eq!(vm.register(3), 1);
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.load_program(&prog).unwrap();
    vm.set_register(1, 7);
    vm.set_register(2, 3);
    vm.run().expect("SLT execution failed");
    assert_eq!(vm.register(3), 0);
    // SLTU (unsigned)
    let prog_u = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::SLTU, 4, 1, 2),
        HALT_WORD,
    ]);
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.load_program(&prog_u).unwrap();
    vm.set_register(1, 5);
    vm.set_register(2, 7);
    vm.run().expect("SLTU execution failed");
    assert_eq!(vm.register(4), 1);
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.load_program(&prog_u).unwrap();
    vm.set_register(1, 9);
    vm.set_register(2, 3);
    vm.run().expect("SLTU execution failed");
    assert_eq!(vm.register(4), 0);
}
#[test]
fn test_sltu_immediate_emulation() {
    let mut vm = ivm::IVM::new(u64::MAX);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::SLTU, 3, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.set_register(1, 0);
    vm.set_register(2, 1);
    vm.run().expect("SLTU run");
    assert_eq!(vm.register(3), 1);
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.load_program(&prog).unwrap();
    vm.set_register(1, 2);
    vm.set_register(2, 1);
    vm.run().expect("SLTU run");
    assert_eq!(vm.register(3), 0);
}
#[test]
fn test_seq_sne_cmov() {
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_words(&[
        encoding::wide::encode_rr(instruction::wide::arithmetic::SEQ, 3, 1, 2),
        encoding::wide::encode_rr(instruction::wide::arithmetic::SNE, 4, 1, 2),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.set_register(1, 42);
    vm.set_register(2, 42);
    vm.run().expect("comparison ops failed");
    assert_eq!(vm.register(3), 1); // SEQ true
    assert_eq!(vm.register(4), 0); // SNE false
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.load_program(&prog).unwrap();
    vm.set_register(1, 10);
    vm.set_register(2, 7);
    vm.run().expect("comparison ops failed");
    assert_eq!(vm.register(3), 0);
    assert_eq!(vm.register(4), 1);
}
