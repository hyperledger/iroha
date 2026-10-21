// Register after the coherent ICL1 checkpoint with the native quote surface.
use super::*;

const QUOTE_SOURCE: &str = r#"seiyaku HoldingPolicy {
    view fn quote(
        AssetDefinitionId asset_definition, AccountId account, quantity incoming
    ) authorize(anyone) -> AssetUidHoldingQuote {
        ledger::asset::uid_holding_quote(asset_definition, account, incoming)
    }
}"#;

#[test]
fn typed_uid_quote_compiles_as_one_native_read() {
    let bytes = test_mode_compiler()
        .compile_source(QUOTE_SOURCE)
        .expect("typed native quote compiles");
    let parsed = ProgramMetadata::parse(&bytes).unwrap();
    let quote_calls = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .filter(|word| {
            instruction::wide::opcode(*word) == instruction::wide::system::SYSTEM
                && encoding::wide::decode_syscallx(*word)
                    == syscalls::SYSCALL_ASSET_UID_HOLDING_QUOTE
        })
        .count();
    assert_eq!(quote_calls, 1);
}

#[test]
fn uid_quote_fields_keep_exact_value_types() {
    for (field, value_type) in [
        ("asset_definition_id", "AssetDefinitionId"),
        ("account_id", "AccountId"),
        ("policy_revision", "int"),
        ("beneficial_holdings", "quantity"),
        ("holding_limit", "Option<quantity>"),
        ("required_overflow", "quantity"),
    ] {
        let source = QUOTE_SOURCE.replace(
            "-> AssetUidHoldingQuote {\n        ledger::asset::uid_holding_quote(asset_definition, account, incoming)",
            &format!(
                "-> {value_type} {{\n        let quote = ledger::asset::uid_holding_quote(asset_definition, account, incoming);\n        quote.{field}"
            ),
        );
        test_mode_compiler()
            .compile_source(&source)
            .unwrap_or_else(|error| panic!("typed quote field {field}: {error:?}"));
    }
}

#[test]
fn uid_quote_rejects_wrong_identity_and_amount_types() {
    for arguments in [
        "account, account, incoming",
        "asset_definition, asset_definition, incoming",
        "asset_definition, account, true",
        "asset_definition, account",
    ] {
        let source = QUOTE_SOURCE.replace(
            "uid_holding_quote(asset_definition, account, incoming)",
            &format!("uid_holding_quote({arguments})"),
        );
        let parsed = parse(&source).expect("well-formed negative source");
        assert!(
            analyze(&parsed).is_err(),
            "invalid quote arguments admitted: {arguments}",
        );
    }
}

#[test]
fn uid_quote_does_not_expose_identity_roster_or_transfer_authority() {
    for field in ["uid", "accounts", "controller", "fi_account"] {
        let source = QUOTE_SOURCE.replace(
            "-> AssetUidHoldingQuote {\n        ledger::asset::uid_holding_quote(asset_definition, account, incoming)",
            &format!(
                "-> bytes {{\n        let quote = ledger::asset::uid_holding_quote(asset_definition, account, incoming);\n        quote.{field}"
            ),
        );
        let parsed = parse(&source).expect("well-formed negative source");
        assert!(
            analyze(&parsed).is_err(),
            "private or authority field unexpectedly exposed: {field}",
        );
    }
}
