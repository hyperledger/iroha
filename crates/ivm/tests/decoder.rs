use crate::common;
use common::assemble;
use ivm::{IVM, VMError, encoding};
const HALT: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
#[test]
fn test_compressed_ebreak() {
    let mut vm = IVM::new(u64::MAX);
    let prog: [u8; 6] = [
        0x02, 0x90, // historic compressed ebreak (unsupported in wide mode)
        HALT[0], HALT[1], HALT[2], HALT[3],
    ];
    let prog = assemble(&prog);
    let err = vm.load_program(&prog).unwrap_err();
    assert!(matches!(err, VMError::MemoryAccessViolation { .. }));
}
#[test]
fn test_invalid_opcode() {
    let mut vm = IVM::new(u64::MAX);
    let prog: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
    let prog = assemble(&prog);
    match vm.load_program(&prog) {
        Err(VMError::InvalidOpcode(_)) => (),
        Ok(()) => {
            let res = vm.run();
            assert!(matches!(res, Err(VMError::InvalidOpcode(_))));
        }
        Err(err) => panic!("unexpected error: {err:?}"),
    }
}
#[test]
fn test_unknown_compressed_traps() {
    let mut vm = IVM::new(u64::MAX);
    let prog: [u8; 4] = [0x00, 0x01, 0x00, 0x00]; // invalid 16-bit opcode
    let prog = assemble(&prog);
    match vm.load_program(&prog) {
        Err(VMError::InvalidOpcode(_)) => (),
        Ok(()) => {
            let res = vm.run();
            assert!(matches!(res, Err(VMError::InvalidOpcode(_))));
        }
        Err(err) => panic!("unexpected error: {err:?}"),
    }
}
#[test]
fn test_ebreak_instruction() {
    let mut vm = IVM::new(u64::MAX);
    let prog: [u8; 8] = [
        0x73, 0x00, 0x10, 0x00, // ebreak
        HALT[0], HALT[1], HALT[2], HALT[3],
    ];
    let prog = assemble(&prog);
    let err = vm.load_program(&prog).unwrap_err();
    assert!(
        matches!(err, VMError::InvalidOpcode(_)),
        "expected compressed ebreak to be rejected"
    );
}
