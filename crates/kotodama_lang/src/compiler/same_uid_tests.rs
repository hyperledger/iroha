//! Exact source labels and boolean type for a private native membership comparison.
use super::*;
const SOURCE: &str = r#"seiyaku SameUid {
    view fn same(AssetDefinitionId asset, AccountId source, AccountId destination) authorize(anyone) -> bool {
        ledger::asset::same_uid(asset_definition: asset, source: source, destination: destination)
    }
}"#;
#[test]
fn same_uid_read_compiles_in_views_and_effectful_entrypoints() {
    for source in [SOURCE.to_owned(), SOURCE.replace("view fn", "kotoage fn")] {
        let bytes = test_mode_compiler().compile_source(&source).unwrap();
        let parsed = ProgramMetadata::parse(&bytes).unwrap();
        let count = bytes[parsed.code_offset..]
            .chunks_exact(4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
            .filter(|w| {
                instruction::wide::opcode(*w) == instruction::wide::system::SYSTEM
                    && encoding::wide::decode_syscallx(*w) == syscalls::SYSCALL_ASSET_SAME_UID
            })
            .count();
        assert_eq!(count, 1);
    }
}
#[test]
fn same_uid_rejects_wrong_operand_types_missing_identity_and_nonboolean_result() {
    for (from, to) in [
        ("asset_definition: asset", "asset_definition: source"),
        ("source: source", "source: asset"),
        ("destination: destination", "destination: false"),
        (", destination: destination", ""),
        ("-> bool", "-> int"),
    ] {
        let source = SOURCE.replace(from, to);
        let parsed = parse(&source).unwrap();
        assert!(analyze(&parsed).is_err(), "{source}");
    }
}
