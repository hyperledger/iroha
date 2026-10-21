//! Scalar FI-link read compilation; native authority is checked by the host.
use super::*;
const SOURCE: &str = r#"seiyaku LinkRevision {
    view fn revision(AssetDefinitionId asset, AccountId wallet, AccountId fi) authorize(anyone) -> int {
        ledger::fi::link_revision(asset_definition: asset, account: wallet, expected_fi: fi)
    }
}"#;
#[test]
fn fi_link_revision_read_is_available_to_views_and_effectful_entrypoints() {
    for source in [SOURCE.to_owned(), SOURCE.replace("view fn", "kotoage fn")] {
        let bytes = test_mode_compiler().compile_source(&source).unwrap();
        let parsed = ProgramMetadata::parse(&bytes).unwrap();
        let count = bytes[parsed.code_offset..]
            .chunks_exact(4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
            .filter(|w| {
                instruction::wide::opcode(*w) == instruction::wide::system::SYSTEM
                    && encoding::wide::decode_syscallx(*w)
                        == syscalls::SYSCALL_ASSET_FI_LINK_REVISION
            })
            .count();
        assert_eq!(count, 1);
    }
}
#[test]
fn fi_link_revision_rejects_wrong_types_missing_fi_and_scalar_substitution() {
    for (from, to) in [
        ("asset_definition: asset", "asset_definition: wallet"),
        ("account: wallet", "account: asset"),
        ("expected_fi: fi", "expected_fi: true"),
        (", expected_fi: fi", ""),
        ("-> int", "-> AccountId"),
    ] {
        let source = SOURCE.replace(from, to);
        let parsed = parse(&source).unwrap();
        assert!(analyze(&parsed).is_err(), "{source}");
    }
}
