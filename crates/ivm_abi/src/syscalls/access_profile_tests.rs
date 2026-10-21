//! Exact ABI-v1 helper, host-private, generic-program, AXT, and access-profile tests.
use super::*;
#[test]
fn koto_test_syscalls_are_host_private() {
    let private = [
        SYSCALL_KOTO_TEST_ACTOR_ACCOUNT,
        SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY,
        SYSCALL_KOTO_TEST_ACTOR_SIGN,
        SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS,
        SYSCALL_KOTO_TEST_EXPECT_REJECT_AS,
        SYSCALL_KOTO_TEST_ASSERT_FAILED,
        SYSCALL_KOTO_TEST_SET_BLOCK_HEIGHT,
        SYSCALL_KOTO_TEST_ADVANCE_BLOCKS,
        SYSCALL_KOTO_TEST_SET_TRANSACTION_TIME_MS,
        SYSCALL_KOTO_TEST_CALL_SITE,
    ];
    for syscall in private {
        assert!(is_koto_test_syscall(syscall));
        assert!(!is_syscall_allowed(crate::SyscallPolicy::AbiV1, syscall));
        assert!(syscall > u8::MAX as u32);
    }
}
#[test]
fn generic_program_syscall_profile_is_sorted_complete_and_fail_closed() {
    assert!(
        GENERIC_PROGRAM_DENIED_SYSCALLS_V1
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "ABI-bound denylist must remain strictly sorted"
    );
    assert_eq!(
        GENERIC_PROGRAM_DENIED_SYSCALLS_V1,
        &[
            SYSCALL_GRANT_CONTRACT_PERMISSION,
            SYSCALL_REVOKE_CONTRACT_PERMISSION,
            SYSCALL_DEACTIVATE_CONTRACT_INSTANCE,
            SYSCALL_REMOVE_SMART_CONTRACT_BYTES,
            SYSCALL_REGISTER_SMART_CONTRACT_CODE,
            SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
            SYSCALL_ACTIVATE_CONTRACT_INSTANCE,
            SYSCALL_STATE_GET,
            SYSCALL_STATE_SET,
            SYSCALL_STATE_DEL,
            SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
            SYSCALL_CALL_CONTRACT,
            SYSCALL_EMIT_CONTRACT_EVENT,
            SYSCALL_SYSVAR_CONTRACT_ADDRESS,
            SYSCALL_SYSVAR_ENTRYPOINT,
            SYSCALL_SYSVAR_CONTRACT_SUBJECT,
            SYSCALL_STATE_HAS,
            SYSCALL_STATE_LEN,
            SYSCALL_STATE_COUNT,
            SYSCALL_STATE_SCAN,
            SYSCALL_ASSET_LOCK_OPEN,
            SYSCALL_ASSET_LOCK_DRAWDOWN,
            SYSCALL_ASSET_LOCK_CANCEL,
            SYSCALL_ASSET_LOCK_EXPIRE,
            SYSCALL_ASSET_UID_HOLDING_QUOTE,
            SYSCALL_TRANSFER_TO_LINKED_FI,
            SYSCALL_ASSET_LOCK_DRAWDOWN_WATERFALL,
            SYSCALL_ASSET_LOCK_CANCEL_WATERFALL,
            SYSCALL_ASSET_LOCK_EXPIRE_WATERFALL,
            SYSCALL_ASSET_FI_LINK_REVISION,
            SYSCALL_ASSET_SAME_UID,
        ]
    );
    for &syscall in GENERIC_PROGRAM_DENIED_SYSCALLS_V1 {
        assert!(is_syscall_allowed(crate::SyscallPolicy::AbiV1, syscall));
        assert!(!is_generic_program_syscall_allowed(
            crate::SyscallPolicy::AbiV1,
            syscall
        ));
    }
    for syscall in [
        SYSCALL_REGISTER_DOMAIN,
        SYSCALL_INT_ADD,
        SYSCALL_SUBSCRIPTION_BILL,
        SYSCALL_SUBSCRIPTION_RECORD_USAGE,
        SYSCALL_AXT_BEGIN,
        SYSCALL_AXT_TOUCH,
        SYSCALL_AXT_COMMIT,
        SYSCALL_VERIFY_DS_PROOF,
        SYSCALL_AXT_STAGE_ANCHORED_SPEND,
    ] {
        assert!(is_generic_program_syscall_allowed(
            crate::SyscallPolicy::AbiV1,
            syscall
        ));
    }
    assert!(!is_generic_program_syscall_allowed(
        crate::SyscallPolicy::AbiV1,
        u32::MAX
    ));
}
#[test]
fn axt_syscall_classifier_is_exact() {
    for syscall in [
        SYSCALL_AXT_BEGIN,
        SYSCALL_AXT_TOUCH,
        SYSCALL_AXT_COMMIT,
        SYSCALL_VERIFY_DS_PROOF,
        SYSCALL_AXT_STAGE_ANCHORED_SPEND,
    ] {
        assert!(is_axt_syscall(syscall));
    }
    for syscall in [0xB4, SYSCALL_ESCROW_OPEN_OFFER, SYSCALL_STATE_GET, u32::MAX] {
        assert!(!is_axt_syscall(syscall));
    }
}
#[test]
fn syscall_access_classification_is_conservative() {
    assert_eq!(syscall_access(SYSCALL_STATE_GET), SyscallAccess::StateRead);
    assert_eq!(syscall_access(SYSCALL_STATE_SET), SyscallAccess::StateWrite);
    assert_eq!(
        syscall_access(SYSCALL_STATE_MAP_KEY_AT),
        SyscallAccess::None
    );
    assert_eq!(
        syscall_access(SYSCALL_STATE_VALUE_ENCODE),
        SyscallAccess::None
    );
    assert_eq!(
        syscall_access(SYSCALL_STATE_VALUE_DECODE),
        SyscallAccess::None
    );
    assert_eq!(
        syscall_access(SYSCALL_CORE_QUERY_GET),
        SyscallAccess::LedgerRead
    );
    assert_eq!(
        syscall_access(SYSCALL_CORE_QUERY_PAGE),
        SyscallAccess::LedgerRead
    );
    assert_eq!(
        syscall_access(SYSCALL_VRF_EPOCH_SEED),
        SyscallAccess::LedgerRead
    );
    assert_eq!(
        syscall_access(SYSCALL_TRANSFER_ASSET_SCOPED),
        SyscallAccess::LedgerWrite
    );
    assert_eq!(
        syscall_access(SYSCALL_CALL_CONTRACT),
        SyscallAccess::Dynamic
    );
    assert_eq!(syscall_access(SYSCALL_SHA256_HASH), SyscallAccess::None);
    assert_eq!(syscall_access(0x00ff_fffe), SyscallAccess::Dynamic);
    for number in abi_syscall_list() {
        assert!(
            syscall_name(*number).is_some(),
            "ABI syscall 0x{number:06x} lacks a registry name"
        );
    }
}
#[test]
fn gas_text_is_not_part_of_the_abi_surface_hash() {
    let canonical = &syscalls_doc_gen::DOCS[0];
    let changed_gas = SyscallDoc {
        number: canonical.number,
        args: canonical.args,
        ret: canonical.ret,
        gas: "a deliberately different gas schedule",
    };
    let canonical_surface =
        collect_abi_syscall_surface(&[canonical.number], std::slice::from_ref(canonical))
            .expect("single canonical row");
    let changed_surface = collect_abi_syscall_surface(&[canonical.number], &[changed_gas])
        .expect("single altered-gas row");
    assert_eq!(canonical_surface, changed_surface);
}

#[test]
fn controller_quote_and_settlements_have_exact_access_profiles() {
    assert_eq!(
        registered_syscall_access(SYSCALL_ASSET_UID_HOLDING_QUOTE),
        Some(SyscallAccess::LedgerRead),
    );
    for number in [
        SYSCALL_TRANSFER_TO_LINKED_FI,
        SYSCALL_ASSET_LOCK_DRAWDOWN_WATERFALL,
        SYSCALL_ASSET_LOCK_CANCEL_WATERFALL,
        SYSCALL_ASSET_LOCK_EXPIRE_WATERFALL,
    ] {
        assert_eq!(registered_syscall_access(number), Some(SyscallAccess::LedgerWrite));
    }
    let row = syscalls_doc_gen::DOCS.iter()
        .find(|row| row.number == SYSCALL_ASSET_UID_HOLDING_QUOTE)
        .expect("generated quote ABI row");
    assert_eq!(row.ret, "r10=owned public six-word AssetUidHoldingQuote heap table [asset_definition_id:&AssetDefinitionId, account_id:&AccountId, policy_revision:&Int(exact u64), beneficial_holdings:&Quantity, holding_limit:Option<Quantity> sum handle, required_overflow:&Quantity]");
}

#[test]
fn fi_link_revision_is_a_controller_only_scalar_ledger_read() {
    let number = SYSCALL_ASSET_FI_LINK_REVISION;
    assert_eq!(registered_syscall_access(number), Some(SyscallAccess::LedgerRead));
    assert!(is_syscall_allowed(crate::SyscallPolicy::AbiV1, number));
    assert!(!is_generic_program_syscall_allowed(crate::SyscallPolicy::AbiV1, number));
    let row = syscalls_doc_gen::DOCS.iter().find(|row| row.number == number)
        .expect("generated exact FI revision row");
    assert_eq!(row.args, "r10=&AssetDefinitionId, r11=&AccountId, r12=&AccountId(expected_fi); exact active link controller, enabled owner grant, expected-FI equality and current native FI/attestation revisions required");
    assert_eq!(row.ret, "r10=&Int(exact current nonzero u64 link revision); no FI identity or reference returned");
}

#[test]
fn same_uid_is_reader_granted_retail_only_boolean_ledger_read() {
    let number=SYSCALL_ASSET_SAME_UID;
    assert_eq!(registered_syscall_access(number),Some(SyscallAccess::LedgerRead));
    assert!(is_syscall_allowed(crate::SyscallPolicy::AbiV1,number));
    assert!(!is_generic_program_syscall_allowed(crate::SyscallPolicy::AbiV1,number));
    let row=syscalls_doc_gen::DOCS.iter().find(|row|row.number==number).expect("generated exact same-UID row");
    assert_eq!(row.args,"r10=&AssetDefinitionId, r11=&AccountId(source), r12=&AccountId(destination); exact active frame and current asset-owner reader grant; both exact native retail memberships/policies required, institutional or unknown operands fail");
    assert_eq!(row.ret,"r10=0|1 (bool); false only for two valid distinct retail UIDs; no UID or roster returned");
}

#[test]
fn controlled_lock_open_abi_returns_exact_custody_with_output_byte_metering() {
    let row = syscalls_doc_gen::DOCS
        .iter()
        .find(|row| row.number == SYSCALL_ASSET_LOCK_OPEN)
        .expect("generated controlled lock open row");
    assert_eq!(
        row.ret,
        "r10=&AccountId(protocol escrow custody derived from actual network, controller-scoped lock ID, and asset definition)"
    );
    assert_eq!(
        row.gas,
        "asset:gas/G_sci@ivm.core/v2 + bytes + 1 per complete encoded AccountId return TLV byte"
    );
}
