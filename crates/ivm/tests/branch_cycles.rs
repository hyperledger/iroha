use ivm::{IVM, encoding, instruction};

use crate::common;
use common::assemble;

const HALT_WORD: u32 = encoding::wide::encode_halt();

fn assemble_words(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assemble(&bytes)
}

#[test]
fn conditional_branches_use_one_cycle_per_execution() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0);
    vm.set_register(2, 5);
    let program = assemble_words(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 1, 1),
        encoding::wide::encode_branch(instruction::wide::control::BLT, 1, 2, -1),
        HALT_WORD,
    ]);

    vm.load_program(&program).unwrap();
    vm.run().unwrap();

    assert_eq!(vm.register(1), 5);
    assert_eq!(vm.get_cycle_count(), 11);
}
