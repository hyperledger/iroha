//! Admission-time guard: reject IVM programs that invoke unknown syscalls under ABI v1.

use iroha_core::{
    governance::manifest::LaneManifestRegistry, kura::Kura, prelude::World,
    query::store::LiveQueryStore, smartcontracts::ivm::cache::IvmCache, state::State,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    ValidationFail,
    prelude::*,
    transaction::{Executable, TransactionBuilder, error::TransactionRejectionReason},
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use ivm::{ProgramMetadata, encoding, instruction};
use nonzero_ext::nonzero;
use std::{borrow::Cow, num::NonZeroU64, sync::Arc};
const TEST_GAS_LIMIT: u64 = 10_000;
fn checked_random_unknown_syscall_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked unknown syscall admission keypair")
}
#[test]
fn unknown_syscall_fixture_uses_checked_randomness() {
    let key_pair = checked_random_unknown_syscall_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::Ed25519);
}
fn fee_payment_with_gas_limit(limit: u64) -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(limit))
}
fn unlisted_syscall_number() -> u8 {
    (0u8..=u8::MAX)
        .find(|number| {
            !ivm::syscalls::is_syscall_allowed(ivm::SyscallPolicy::AbiV1, u32::from(*number))
        })
        .expect("ABI v1 should leave at least one u8 syscall number unmapped")
}
fn install_current_lane_manifest_registry(state: &State) {
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
}
#[test]
fn unknown_syscall_number_rejected_during_ivm_admission() {
    // Minimal world with a single authority account.
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_unknown_syscall_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let chain: ChainId = "chain".parse().unwrap();
    let state = State::new_with_chain_for_testing(world, kura, query_handle, chain.clone());
    install_current_lane_manifest_registry(&state);
    let network_id = *state.network_id_ref();
    // Build a tiny program with an unknown syscall followed by HALT.
    let unknown_syscall = unlisted_syscall_number();
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, unknown_syscall)
            .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 10,
        abi_version: 1,
    };
    let mut program = meta.encode();
    program.extend_from_slice(&code);
    // Submit the program; admission should fail before execution due to the unknown syscall.
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let tx = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(TEST_GAS_LIMIT),
    )
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
    .sign(kp.private_key());
    let mut ivm_cache = IvmCache::new();
    let accepted = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accepted,
        &mut ivm_cache,
        None,
    );
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
