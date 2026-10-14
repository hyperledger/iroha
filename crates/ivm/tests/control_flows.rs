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
fn enc_branch(op: u8, rs1: u8, rs2: u8, offset_words: i8) -> u32 {
    encoding::wide::encode_branch(op, rs1, rs2, offset_words)
}
#[test]
fn test_jumps_and_branches() {
    // 1. Test JAL: jump forward and link
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 5);
    // Program:
    // JAL x2, +4   (skip next instruction, link = PC+4)
    // ADDI x1, x1, 1   (this should be skipped)
    // HALT
    let prog = assemble_words(&[
        encoding::wide::encode_jump(instruction::wide::control::JAL, 2, 2),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 1, 1),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("JAL execution failed");
    assert_eq!(vm.register(1), 5, "x1 should remain unchanged (skip addi)");
    assert_eq!(
        vm.register(2),
        0x00000004,
        "x2 should contain link address (4)"
    );
    // 2. Test JALR: jump to address in register and link
    let mut vm2 = IVM::new(u64::MAX);
    vm2.set_register(1, 1); // initial x1 = 1
    // We will jump to the HALT at the end via JALR
    // Program:
    // ADDI x3, x0, 1    (set x3 = 1)
    // JALR x2, x4, 0    (jump to address in x4, link = PC+4)
    // ADDI x3, x0, 2    (should be skipped if jump works)
    // HALT
    // We'll set x4 to point to HALT (offset 12 from start)
    vm2.set_register(4, 12);
    let prog = assemble_words(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 3, 0, 1),
        encoding::wide::encode_rr(instruction::wide::control::JR, 4, 0, 0),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 3, 0, 2),
        HALT_WORD,
    ]);
    vm2.load_program(&prog).unwrap();
    vm2.run().expect("JR execution failed");
    assert_eq!(
        vm2.register(3),
        1,
        "x3 should remain 1 (second addi skipped)"
    );
    assert_eq!(vm2.register(2), 0, "JR should not set link register");
    // 3. Test BEQ and BNE:
    // If x1 == x2, skip the increment; otherwise increment.
    let mut vm3 = IVM::new(u64::MAX);
    // Case A: x1 == x2
    vm3.set_register(1, 5);
    vm3.set_register(2, 5);
    // Program:
    // BEQ x1,x2,+8   (skip next addi if equal)
    // ADDI x1,x1,1
    // HALT
    let branch_prog = assemble_words(&[
        enc_branch(instruction::wide::control::BEQ, 1, 2, 2),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 1, 1),
        HALT_WORD,
    ]);
    vm3.load_program(&branch_prog.clone()).unwrap();
    vm3.run().expect("BEQ failed");
    assert_eq!(
        vm3.register(1),
        5,
        "x1 should remain 5 when equal (branch taken)"
    );
    // Case B: x1 != x2
    let mut vm4 = IVM::new(u64::MAX);
    vm4.set_register(1, 5);
    vm4.set_register(2, 6);
    vm4.load_program(&branch_prog.clone()).unwrap();
    vm4.run().expect("BEQ failed");
    assert_eq!(
        vm4.register(1),
        6,
        "x1 should increment to 6 when not equal (branch not taken)"
    );
    // 4. Test HALT returns Ok and stops execution
    let mut vm5 = IVM::new(u64::MAX);
    let prog = assemble_words(&[HALT_WORD]);
    vm5.load_program(&prog).unwrap();
    let res = vm5.run();
    assert!(res.is_ok(), "HALT should result in Ok(())");
}
#[test]
fn test_bge_and_bgeu() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, (-1i64) as u64);
    vm.set_register(2, (-5i64) as u64);
    let prog = assemble_words(&[
        enc_branch(instruction::wide::control::BGE, 1, 2, 2),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 1, 1),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("BGE failed");
    assert_eq!(vm.register(1) as i64, -1);
    let mut vm2 = IVM::new(u64::MAX);
    vm2.set_register(1, 1);
    vm2.set_register(2, u64::MAX);
    let prog = assemble_words(&[
        enc_branch(instruction::wide::control::BGEU, 1, 2, 2),
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 1, 1),
        HALT_WORD,
    ]);
    vm2.load_program(&prog).unwrap();
    vm2.run().expect("BGEU failed");
    assert_eq!(vm2.register(1), 2);
}
#[test]
fn test_backwards_branch_loop() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0);
    vm.set_register(2, 3);
    let prog = assemble_words(&[
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 1, 1),
        enc_branch(instruction::wide::control::BLT, 1, 2, -1),
        HALT_WORD,
    ]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("loop failed");
    assert_eq!(vm.register(1), 3);
}
