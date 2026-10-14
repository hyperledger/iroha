use crate::common;
use ivm::{IVM, encoding, instruction};
fn program_shift_ops() -> Vec<u8> {
    // Build: SLL x5 = x1 << x2; SRL x6 = x3 >> x2; SRA x7 = x4 >>> x2; HALT
    let sll = encoding::wide::encode_rr(instruction::wide::arithmetic::SLL, 5, 1, 2);
    let srl = encoding::wide::encode_rr(instruction::wide::arithmetic::SRL, 6, 3, 2);
    let sra = encoding::wide::encode_rr(instruction::wide::arithmetic::SRA, 7, 4, 2);
    let halt = encoding::wide::encode_halt();
    let mut code = Vec::new();
    code.extend_from_slice(&sll.to_le_bytes());
    code.extend_from_slice(&srl.to_le_bytes());
    code.extend_from_slice(&sra.to_le_bytes());
    code.extend_from_slice(&halt.to_le_bytes());
    common::assemble(&code)
}
#[test]
fn shift_ops_match_with_and_without_cycle_limit() {
    // Inputs
    let mut unbounded = IVM::new(10_000);
    unbounded.set_register(1, 1);
    unbounded.set_register(2, 4);
    unbounded.set_register(3, 0x80);
    unbounded.set_register(4, (-8i64) as u64);
    let prog = program_shift_ops();
    unbounded.load_program(&prog).unwrap();
    unbounded.run().unwrap();
    let r5 = unbounded.register(5);
    let r6 = unbounded.register(6);
    let r7 = unbounded.register(7);
    let mut bounded = IVM::new(10_000);
    bounded.set_register(1, 1);
    bounded.set_register(2, 4);
    bounded.set_register(3, 0x80);
    bounded.set_register(4, (-8i64) as u64);
    let mut bounded_prog = prog.clone();
    let max_cycles = 1024u64.to_le_bytes();
    bounded_prog[8..16].copy_from_slice(&max_cycles);
    bounded.load_program(&bounded_prog).unwrap();
    bounded.run().unwrap();
    assert_eq!(r5, bounded.register(5));
    assert_eq!(r6, bounded.register(6));
    assert_eq!(r7, bounded.register(7));
    // Basic value smoke check
    assert_eq!(r5, 16);
    assert_eq!(r6, 0x8);
    assert_eq!(r7, 0xFFFF_FFFF_FFFF_FFFF);
}
