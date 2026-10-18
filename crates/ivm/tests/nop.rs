use crate::common;
use common::assemble;
use ivm::{IVM, encoding, instruction};
#[test]
fn test_nop_instruction() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 42);
    let mut prog = Vec::new();
    // Wide NOP encoded as `ADDI x0, x0, 0` (32-bit) then HALT
    let nop = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 0, 0, 0);
    prog.extend_from_slice(&nop.to_le_bytes());
    prog.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("execution failed");
    // Register should remain unchanged
    assert_eq!(vm.register(1), 42);
    // Two cycles: NOP and HALT
    assert_eq!(vm.get_cycle_count(), 2);
}
