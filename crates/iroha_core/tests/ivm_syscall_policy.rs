//! Ensure `CoreHost` enforces syscall policy by `abi_version` header.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::cast_possible_truncation)]
use iroha_core::{governance::manifest::LaneManifestRegistry, smartcontracts::ivm::host::CoreHost};
use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use std::{num::NonZeroU64, sync::Arc};
fn program_with_scall(sys: u8) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, sys).to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 10_000,
        abi_version: 1,
    };
    let mut out = meta.encode();
    out.extend_from_slice(&code);
    out
}
fn unlisted_syscall_number() -> u8 {
    (0u8..=u8::MAX)
        .find(|number| {
            !ivm::syscalls::is_syscall_allowed(ivm::SyscallPolicy::AbiV1, u32::from(*number))
        })
        .expect("ABI v1 should leave at least one u8 syscall number unmapped")
}
fn fee_payment_with_gas_limit(limit: u64) -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(limit))
}
fn checked_random_ivm_admission_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked IVM admission transaction keypair")
}
fn install_current_lane_manifest_registry(state: &iroha_core::state::State) {
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
}
#[test]
fn ivm_admission_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_ivm_admission_keypair();
}
#[test]
fn deny_unlisted_syscall_in_current() {
    // Choose a syscall number that is not in the ABI v1 allowlist.
    let prog = program_with_scall(unlisted_syscall_number());
    let mut vm = IVM::new(u64::MAX);
    // Any authority is fine; it won't be used
    let authority = ALICE_ID.clone();
    vm.set_host(CoreHost::new(authority));
    let err = vm
        .load_program(&prog)
        .expect_err("strict program loading must reject an unknown syscall");
    assert!(
        matches!(err, ivm::VMError::UnknownSyscall(__actual_error_field) if __actual_error_field == (u32::from(unlisted_syscall_number())))
    );
}
#[test]
fn allow_forwarded_alloc_in_current() {
    // ALLOC is forwarded by CoreHost and should be permitted.
    let prog = program_with_scall(ivm_sys::SYSCALL_ALLOC as u8);
    let mut vm = IVM::new(u64::MAX);
    let authority = ALICE_ID.clone();
    vm.set_host(CoreHost::new(authority));
    vm.load_program(&prog).unwrap();
    // Set x10 = 16 for allocation size
    vm.set_register(10, 16);
    vm.run().expect("alloc should be allowed under policy");
}
#[test]
fn unknown_syscall_is_rejected_at_admission() {
    use iroha_core::{
        kura::Kura, query::store::LiveQueryStore, smartcontracts::ivm::cache::IvmCache,
        state::State, tx::AcceptedTransaction,
    };
    use iroha_data_model::{
        block::BlockHeader,
        executor::ValidationFail,
        prelude::{AssetDefinition, TransactionBuilder},
        transaction::error::TransactionRejectionReason,
    };
    use nonzero_ext::nonzero;
    use std::borrow::Cow;
    // Build a minimal world with a single authority account.
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_ivm_admission_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world =
        iroha_core::state::World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let chain: ChainId = "chain".parse().expect("chain id");
    let state = State::new_with_chain_for_testing(world, kura, query_handle, chain.clone());
    install_current_lane_manifest_registry(&state);
    let network_id = *state.network_id_ref();
    // Program calls an unknown syscall number before halting.
    let prog = program_with_scall(unlisted_syscall_number());
    let tx = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(1_000_000),
    )
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
    .sign(kp.private_key());
    // Validate the transaction in a block; ABI policy admission rejects it before execution.
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut ivm_cache = IvmCache::new();
    let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accepted,
        &mut ivm_cache,
        None,
    );
    let unknown_syscall = unlisted_syscall_number();
    match result {
        Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))) => {
            assert_eq!(
                message,
                format!("unknown syscall number 0x{unknown_syscall:02x} for abi_version 1"),
                "unknown syscalls must fail at the ABI policy boundary"
            );
        }
        other => panic!("expected strict ABI policy rejection for unknown syscall, got {other:?}"),
    }
}
