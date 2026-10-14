//! IVM gas schedule wiring tests.

use iroha_core::smartcontracts::limits;
#[test]
fn ivm_gas_schedule_entries_match_ivm_table() {
    let entries = limits::ivm_gas_schedule_entries();
    assert_eq!(entries.len(), ivm::gas::SCHEDULE_OPCODES.len());
    for (entry, &opcode) in entries.iter().zip(ivm::gas::SCHEDULE_OPCODES) {
        assert_eq!(entry.opcode, opcode);
        let expected =
            ivm::gas::cost_of((opcode as u32) << 24).expect("scheduled opcode must have gas cost");
        assert_eq!(entry.cost, expected);
    }
}
#[test]
fn ivm_gas_schedule_hash_matches_ivm_hash() {
    assert_eq!(limits::ivm_gas_schedule_hash(), ivm::gas::schedule_hash());
}
