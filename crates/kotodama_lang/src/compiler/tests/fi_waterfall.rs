//! Compiler contract for native FI and controlled overflow settlement.
//!
//! TODO: Register with the compiler tests in the coordinated ABI candidate.
//! This staged file is uncompiled and does not qualify any native surface.

use super::*;

const CALLS: [&str; 4] = [
    "ledger::fi::transfer_linked(asset_definition: asset, account: wallet, amount: amount, policy_revision: policy_revision, link_revision: link_revision);",
    "ledger::asset_lock::drawdown_with_waterfall(key: key, amount: amount, expected_remaining: remaining, policy_revision: policy_revision, link_revision: link_revision);",
    "ledger::asset_lock::cancel_with_waterfall(key: key, expected_remaining: remaining, policy_revision: policy_revision, link_revision: link_revision);",
    "ledger::asset_lock::expire_with_waterfall(key: key, policy_revision: policy_revision, link_revision: link_revision);",
];

fn source(call: &str) -> String {
    format!(
        "seiyaku NativeSettlement {{ permission Settle; kotoage fn apply(\
         AssetDefinitionId asset, AccountId wallet, bytes key, quantity amount, \
         quantity remaining, int policy_revision, int link_revision\
         ) authorize(Settle) {{ {call} }} }}"
    )
}

#[test]
fn each_native_settlement_lowers_both_dynamic_revisions_as_checked_u64() {
    for (call, syscall) in CALLS.into_iter().zip([
        syscalls::SYSCALL_TRANSFER_TO_LINKED_FI,
        syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN_WATERFALL,
        syscalls::SYSCALL_ASSET_LOCK_CANCEL_WATERFALL,
        syscalls::SYSCALL_ASSET_LOCK_EXPIRE_WATERFALL,
    ]) {
        let program = test_mode_compiler()
            .compile_source(&source(call))
            .expect("typed native settlement compiles");
        let parsed = ProgramMetadata::parse(&program).unwrap();
        let calls: Vec<_> = program[parsed.code_offset..]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .filter(|word| instruction::wide::opcode(*word) == instruction::wide::system::SYSTEM)
            .map(encoding::wide::decode_syscallx)
            .collect();
        assert_eq!(calls.iter().filter(|number| **number == syscall).count(), 1);
        assert_eq!(
            calls
                .iter()
                .filter(|number| **number == syscalls::SYSCALL_INT_TO_U64)
                .count(),
            2,
            "each policy/link revision must be checked independently: {call}",
        );
    }
}

#[test]
fn each_settlement_accepts_full_u64_and_refuses_overflowing_literals() {
    for call in CALLS {
        for field in ["policy_revision", "link_revision"] {
            // Keep named argument labels intact; replace only value positions.
            let replace_value = |value: &str| {
                let original = format!("{field}: {field}");
                assert_eq!(call.matches(&original).count(), 1);
                call.replace(&original, &format!("{field}: {value}"))
            };
            test_mode_compiler()
                .compile_source(&source(&replace_value("18446744073709551615")))
                .expect("the full unsigned revision is supported");
            assert!(
                test_mode_compiler()
                    .compile_source(&source(&replace_value("18446744073709551616")))
                    .is_err(),
                "overflowing {field} must not reach the host: {call}",
            );
        }
    }
}

#[test]
fn each_settlement_is_effectful_and_keeps_revision_types_nominal() {
    for call in CALLS {
        let program = source(call);
        let view = program.replace("kotoage fn", "view fn");
        assert!(test_mode_compiler().compile_source(&view).is_err());
        for field in ["policy_revision", "link_revision"] {
            let wrong = program.replace(&format!("int {field}"), &format!("quantity {field}"));
            assert!(test_mode_compiler().compile_source(&wrong).is_err());
        }
    }
}
