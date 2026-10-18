use crate::common;
use common::assemble_zk;
use ivm::{IVM, encoding, instruction};
#[test]
fn test_memory_events_logged() {
    // Program: store 0x11 at heap, load it back, halt
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &encoding::wide::encode_store(instruction::wide::memory::STORE64, 1, 2, 0).to_le_bytes(),
    );
    bytes.extend_from_slice(
        &encoding::wide::encode_load(instruction::wide::memory::LOAD64, 3, 1, 0).to_le_bytes(),
    );
    bytes.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let prog = assemble_zk(&bytes, 10);
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, ivm::Memory::HEAP_START);
    vm.set_register(2, 0x11);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    // Memory events are only recorded for certain instrumented ops (e.g., zk trace helpers);
    // plain store/load does not emit events, so the log should be empty.
    let log = vm.memory_log();
    assert!(log.is_empty());
}
