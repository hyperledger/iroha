//! Gas schedule determinism guardrails.
use hex_literal::hex;
#[test]
fn schedule_hash_matches_expected_digest() {
    let digest = ivm::gas::schedule_hash();
    // Blake2b-32 over the canonical opcode/host/numeric schedule descriptor,
    // with the LSB set per `iroha_crypto::Hash`.
    let expected = hex!("af5a27f5fc57ebfb9eae3c4f8a25091ce78d97ff7797dbc3b304a0091069731f");
    assert_eq!(digest.as_ref(), &expected);
}
#[test]
fn schedule_opcode_set_has_no_duplicates() {
    use std::collections::BTreeSet;
    let mut seen = BTreeSet::new();
    for &op in ivm::gas::SCHEDULE_OPCODES {
        assert!(seen.insert(op), "duplicate opcode 0x{op:02x} in schedule");
    }
}
