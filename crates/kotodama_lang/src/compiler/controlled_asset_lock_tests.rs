use super::*;

const SOURCE: &str = r#"seiyaku ControlledLock {
    kotoage fn operate(
        bytes key, AccountId source, AccountId destination,
        AssetDefinitionId asset_definition, quantity amount, quantity remaining,
        int release_until_ms, int cancel_not_before_ms, int expires_at_ms
    ) authorize(anyone) {
        ledger::asset_lock::open(
            key, source, destination, asset_definition, amount,
            release_until_ms, cancel_not_before_ms, expires_at_ms
        );
        ledger::asset_lock::drawdown(key, amount, expected_remaining: remaining);
        ledger::asset_lock::cancel(key, expected_remaining: remaining);
        ledger::asset_lock::expire(key);
    }
}"#;

#[test]
fn typed_controlled_lock_calls_compile_to_four_distinct_effects() {
    let bytes = test_mode_compiler()
        .compile_source(SOURCE)
        .expect("typed lock operations compile");
    let parsed = ProgramMetadata::parse(&bytes).unwrap();
    let words = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>();
    for syscall in [
        syscalls::SYSCALL_ASSET_LOCK_OPEN,
        syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN,
        syscalls::SYSCALL_ASSET_LOCK_CANCEL,
        syscalls::SYSCALL_ASSET_LOCK_EXPIRE,
    ] {
        assert_eq!(
            words
                .iter()
                .filter(|word| {
                    instruction::wide::opcode(**word) == instruction::wide::system::SYSTEM
                        && encoding::wide::decode_syscallx(**word) == syscall
                })
                .count(),
            1,
            "each operation must emit exactly its own syscall"
        );
    }
}

#[test]
fn controlled_lock_open_rejects_wrong_quantity_and_deadline_types() {
    for (original, replacement) in [
        (
            "key, source, destination, asset_definition, amount,",
            "key, source, destination, asset_definition, amount: true,",
        ),
        (
            "release_until_ms, cancel_not_before_ms, expires_at_ms",
            "release_until_ms: true, cancel_not_before_ms, expires_at_ms",
        ),
    ] {
        let source = SOURCE.replace(original, replacement);
        let parsed = parse(&source).expect("well-formed negative source");
        assert!(
            analyze(&parsed).is_err(),
            "invalid typed lock call admitted"
        );
    }
}

#[test]
fn controlled_lock_effects_are_unavailable_to_views() {
    let source = SOURCE.replace("kotoage fn", "view fn");
    assert!(test_mode_compiler().compile_source(&source).is_err());
}

const CUSTODY_SOURCE: &str = r#"seiyaku CustodyReturn {
    kotoage fn open(
        bytes key, AccountId source, AccountId destination,
        AssetDefinitionId asset, quantity amount
    ) authorize(anyone) -> AccountId {
        let custody = ledger::asset_lock::open(
            key: key, source: source, destination: destination,
            asset_definition: asset, amount: amount,
            release_until_ms: 0, cancel_not_before_ms: 0, expires_at_ms: 0
        );
        custody
    }
}"#;

#[test]
fn controlled_lock_open_captures_typed_account_result() {
    test_mode_compiler()
        .compile_source(CUSTODY_SOURCE)
        .expect("open result can be captured and returned as an AccountId");
}

#[test]
fn controlled_lock_open_result_rejects_wrong_nominal_and_scalar_types() {
    for wrong in ["AssetDefinitionId", "quantity", "int", "bool", "bytes"] {
        let source = CUSTODY_SOURCE.replace("-> AccountId", &format!("-> {wrong}"));
        let parsed = parse(&source).expect("well-formed negative return type source");
        assert!(analyze(&parsed).is_err(), "custody accepted as {wrong}");
    }
}
