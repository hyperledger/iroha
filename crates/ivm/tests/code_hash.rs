use crate::common;
use common::assemble;
use ivm::{IVM, encoding};
#[test]
fn test_program_code_hash() {
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let prog = assemble(&halt);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&prog).unwrap();
    let expected: [u8; 32] = ivm::contract_code_hash(&prog).into();
    assert_eq!(vm.code_hash(), expected);
    vm.run().unwrap();
    assert_eq!(vm.code_hash(), expected);
}
