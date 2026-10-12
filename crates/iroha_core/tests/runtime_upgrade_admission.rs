//! Admission coverage for runtime upgrade manifests under the v1-only policy.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::items_after_statements)]
use iroha_config::parameters::actual::RuntimeUpgradeProvenanceMode;
use iroha_core::smartcontracts::Execute; // bring trait for `.execute()` on ISIs
use iroha_core::{
    governance::manifest::LaneManifestRegistry,
    prelude::World,
    state::{State, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    isi::error::{InstructionExecutionError, InvalidParameterError},
    prelude::*,
    runtime::{RuntimeUpgradeRecord, RuntimeUpgradeStatus},
};
use iroha_executor_data_model::permission::governance::CanManageRuntimeUpgrades;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use ivm::ProgramMetadata;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::{borrow::Cow, collections::BTreeSet, num::NonZeroU64, sync::Arc};
const TEST_GAS_LIMIT: u64 = 1_000_000;
fn minimal_ivm_program(abi_version: u8) -> Vec<u8> {
    // Program: HALT (minimal body)
    let mut code = Vec::new();
    code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1,
        abi_version,
    };
    let mut out = meta.encode();
    out.extend_from_slice(&code);
    out
}
fn fee_payment_with_gas_limit(limit: u64) -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(limit))
}
fn new_account_in_domain(account_id: &AccountId) -> Account {
    Account::new(account_id.clone()).build(account_id)
}
fn checked_keypair() -> KeyPair {
    KeyPair::try_random().expect("runtime upgrade admission fixture key generation should succeed")
}
fn install_current_lane_manifest_registry(state: &State) {
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
}
#[test]
fn checked_keypair_preserves_default_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
}
#[test]
fn runtime_upgrade_rejects_non_v1_manifest() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    use iroha_data_model::prelude::Grant;
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx)
        .expect("grant permission");
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 2".to_string(),
        description: "Unsupported ABI version".to_string(),
        abi_version: 2,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 2,
        end_height: 10,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let manifest_bytes = manifest.canonical_bytes();
    let err = iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx)
        .expect_err("non runtime upgrade must be rejected");
    match err {
        InstructionExecutionError::InvariantViolation(msg) => {
            assert!(
                msg.contains("unsupported abi_version 2") && msg.contains("expected 1"),
                "unexpected msg: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn propose_runtime_upgrade_allows_v1_when_v1_active() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    use iroha_data_model::prelude::Grant;
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    let active_manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activated ABI v1".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 1,
        end_height: 5,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let active_id = active_manifest.id();
    stx1.world.runtime_upgrades_mut().insert(
        active_id,
        RuntimeUpgradeRecord {
            manifest: active_manifest,
            status: RuntimeUpgradeStatus::ActivatedAt(1),
            proposer: account_id.clone(),
            created_height: 1,
        },
    );
    stx1.apply();
    block1.commit_empty_block_for_testing().unwrap();
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Runtime upgrade without ABI bump".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 10,
        end_height: 20,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let id = manifest.id();
    let manifest_bytes = manifest.canonical_bytes();
    iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx2)
        .expect("v1 runtime upgrade should be accepted even with v1 active");
    stx2.world
        .runtime_upgrades()
        .get(&id)
        .expect("record persisted");
}
#[test]
fn propose_runtime_upgrade_rejects_non_matching_abi_hash() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx)
        .expect("grant permission");
    let mut manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: [0xAA; 32], // wrong hash: should be compute_abi_hash(AbiV1)
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 10,
        end_height: 20,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    // Deliberately scramble abi_hash while keeping other fields valid.
    manifest.abi_hash[0] ^= 0xFF;
    let manifest_bytes = manifest.canonical_bytes();
    let err = iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx)
        .expect_err("mismatched abi_hash must be rejected");
    assert!(matches!(
        err,
        InstructionExecutionError::InvariantViolation(_)
    ));
}
#[test]
fn propose_runtime_upgrade_rejects_incorrect_added_sets() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx)
        .expect("grant permission");
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        // No new syscalls/types exist in this build, so added_* must be empty.
        added_syscalls: vec![9000],
        added_pointer_types: vec![0x00FF],
        start_height: 10,
        end_height: 20,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let manifest_bytes = manifest.canonical_bytes();
    let err = iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx)
        .expect_err("incorrect added_* sets must be rejected");
    assert!(matches!(
        err,
        InstructionExecutionError::InvariantViolation(_)
    ));
}
#[test]
fn propose_runtime_upgrade_is_idempotent_for_identical_manifest() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx)
        .expect("grant permission");
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 10,
        end_height: 20,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let manifest_bytes = manifest.canonical_bytes();
    iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade {
        manifest_bytes: manifest_bytes.clone(),
    }
    .execute(&account_id, &mut stx)
    .expect("first proposal succeeds");
    // Replay the same proposal; should be treated as a no-op.
    iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx)
        .expect("replaying identical proposal is idempotent");
    let id = manifest.id();
    let rec = stx
        .world
        .runtime_upgrades()
        .get(&id)
        .expect("record persisted");
    assert_eq!(rec.manifest, manifest);
    assert!(matches!(
        rec.status,
        iroha_data_model::runtime::RuntimeUpgradeStatus::Proposed
    ));
}
#[test]
fn activate_runtime_upgrade_is_idempotent_at_start_height() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    // Block 1: grant permission and propose upgrade starting at height 5
    let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 5,
        end_height: 15,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let id = manifest.id();
    let manifest_bytes = manifest.canonical_bytes();
    iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx1)
        .expect("propose manifest");
    stx1.apply();
    block1.commit_empty_block_for_testing().unwrap();
    // Block 5: activate twice at the same height; the second invocation should be a no-op
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(5_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    iroha_data_model::isi::runtime_upgrade::ActivateRuntimeUpgrade { id }
        .execute(&account_id, &mut stx2)
        .expect("first activation succeeds");
    iroha_data_model::isi::runtime_upgrade::ActivateRuntimeUpgrade { id }
        .execute(&account_id, &mut stx2)
        .expect("second activation at same height is a no-op");
    let rec = stx2
        .world
        .runtime_upgrades()
        .get(&id)
        .expect("record present after activation");
    assert!(matches!(
        rec.status,
        iroha_data_model::runtime::RuntimeUpgradeStatus::ActivatedAt(5)
    ));
}
#[test]
fn activation_allows_v1_in_same_block() {
    use iroha_core::{
        smartcontracts::ivm::cache::IvmCache,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    // Execute against an original signed root; a height-shaped overlay alone is not one.
    let mut config = TestChainConfig::new(world, 0);
    config.chain_id = ChainId::from("chain");
    let chain = CertifiedTestChain::start(config).expect("signed runtime admission genesis");
    let state = chain.state();
    let network_id = *state.network_id_ref();
    install_current_lane_manifest_registry(state);
    let prog_current = minimal_ivm_program(1);
    // Block 2, after signed genesis: grant permission and propose upgrade [3, 10)
    let genesis_header = chain.genesis().header();
    assert_eq!(
        state.view().latest_block_hash(),
        Some(genesis_header.hash())
    );
    let proposal_time = genesis_header
        .creation_time_ms
        .checked_add(1)
        .expect("fixture time");
    let header1 = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        Some(genesis_header.hash()),
        None,
        proposal_time,
        0,
    );
    let proposal_header_hash = header1.hash();
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 3,
        end_height: 10,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let id = manifest.id();
    let manifest_bytes = manifest.canonical_bytes();
    iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx1)
        .expect("propose manifest");
    stx1.apply();
    block1.commit_empty_block_for_testing().unwrap();
    // Block 3: activate upgrade, then validate a v1 program in the same block
    let committed_proposal_hash = state.view().latest_block_hash();
    assert_eq!(committed_proposal_hash, Some(proposal_header_hash));
    let activation_time = proposal_time.checked_add(1).expect("fixture time");
    let header2 = iroha_data_model::block::BlockHeader::new(
        nonzero!(3_u64),
        committed_proposal_hash,
        None,
        activation_time,
        0,
    );
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    iroha_data_model::isi::runtime_upgrade::ActivateRuntimeUpgrade { id }
        .execute(&account_id, &mut stx2)
        .expect("activate upgrade at scheduled height");
    stx2.apply();
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(TEST_GAS_LIMIT),
    )
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog_current)))
    .sign(kp.private_key());
    let mut ivm_cache = IvmCache::new();
    let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block2,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(
        result.is_ok(),
        "program with ABI v1 should validate: {result:?}"
    );
}
#[test]
fn active_manifest_hash_mismatch_rejects_block_construction() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    use iroha_data_model::executor::IvmAdmissionError;
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    // Seed an activated upgrade record with an incorrect abi_hash.
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: [0x11; 32], // deliberately wrong
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 1,
        end_height: 5,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let id = manifest.id();
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world.runtime_upgrades_mut().insert(
        id,
        RuntimeUpgradeRecord {
            manifest: manifest.clone(),
            status: RuntimeUpgradeStatus::ActivatedAt(1),
            proposer: account_id.clone(),
            created_height: 1,
        },
    );
    stx.apply();
    block.commit_empty_block_for_testing().unwrap();
    // The next block must fail closed before any transaction can execute under
    // an ABI surface that differs from the local binary.
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    match state.try_block(header2) {
        Err(iroha_core::state::StateBlockStartError::Stage(
            IvmAdmissionError::ManifestAbiHashMismatch(info),
        )) => {
            assert_eq!(info.expected, Hash::prehashed(manifest.abi_hash));
        }
        Err(other) => panic!("Expected ManifestAbiHashMismatch, got {other:?}"),
        Ok(_) => panic!("tampered active ABI must prevent block construction"),
    }
}
#[test]
fn propose_runtime_upgrade_rejects_missing_provenance_when_required() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let mut state = State::new_for_testing(world, kura, query_handle);
    state.gov.runtime_upgrade_provenance.mode = RuntimeUpgradeProvenanceMode::Required;
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx)
        .expect("grant permission");
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 10,
        end_height: 20,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let manifest_bytes = manifest.canonical_bytes();
    let err = iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx)
        .expect_err("missing provenance must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
            assert!(
                msg.contains("runtime_upgrade_provenance:missing_provenance"),
                "unexpected msg: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn propose_runtime_upgrade_rejects_untrusted_signer() {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let trusted = checked_keypair();
    let untrusted = checked_keypair();
    let (pubkey, _) = trusted.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = new_account_in_domain(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let mut state = State::new_for_testing(world, kura, query_handle);
    state.gov.runtime_upgrade_provenance.mode = RuntimeUpgradeProvenanceMode::Required;
    state.gov.runtime_upgrade_provenance.signature_threshold = 1;
    state.gov.runtime_upgrade_provenance.trusted_signers =
        BTreeSet::from([trusted.public_key().clone()]);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm = Permission::from(CanManageRuntimeUpgrades);
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx)
        .expect("grant permission");
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "ABI version 1".to_string(),
        description: "Activate ABI version 1".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 10,
        end_height: 20,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    }
    .try_signed(&untrusted)
    .expect("sign the runtime upgrade manifest with the untrusted key");
    let manifest_bytes = manifest.canonical_bytes();
    let err = iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes }
        .execute(&account_id, &mut stx)
        .expect_err("untrusted signer must be rejected");
    match err {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
            assert!(
                msg.contains("runtime_upgrade_provenance:untrusted_signer"),
                "unexpected msg: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
