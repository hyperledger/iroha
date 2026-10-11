//! ABI hash tests ensure the hash is stable for the same policy.
use ivm::syscalls::compute_abi_hash;
#[path = "../../iroha_data_model/tests/fixtures/abi_v1_hash.rs"]
mod abi_v1_fixture;
use abi_v1_fixture::ABI_V1_HASH_GOLDEN;
#[test]
fn abi_hash_is_stable() {
    let h1 = compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    let h2 = compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    assert_eq!(h1, h2, "ABI hash must be stable for the same policy");
}
#[test]
fn abi_hash_matches_v1_golden() {
    let hash = compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    assert_eq!(hex::encode(hash), ABI_V1_HASH_GOLDEN);
    assert_eq!(hash, abi_v1_fixture::abi_v1_hash());
}
#[test]
fn abi_hash_has_valid_iroha_hash_marker() {
    let hash = compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    assert_eq!(
        hash[hash.len() - 1] & 1,
        1,
        "ABI hash must not be an invalid-surface diagnostic sentinel"
    );
}
#[test]
fn abi_v1_execute_instruction_advertises_only_the_submit_ballot_tag() {
    // specs/sccp.md §4.4: contracts record no SCCP messages, so the hashed 0xA0 surface names
    // the single operation tag `1=SubmitBallot` and nothing about `RecordSccpMessage`.
    let table = ivm::syscalls::render_syscalls_markdown_table();
    let rows: Vec<&str> = table
        .lines()
        .filter(|line| line.starts_with("| 0xA0 |"))
        .collect();
    assert_eq!(rows.len(), 1, "exactly one 0xA0 row: {rows:?}");
    assert!(
        rows[0].contains("r11=operation_tag(1=SubmitBallot) |"),
        "{}",
        rows[0]
    );
    assert!(!table.contains("RecordSccpMessage"));
}
