//! Admission-time rejection when on-chain manifest `abi_hash` mismatches node policy.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
use iroha_core::smartcontracts::Execute; // bring trait for `.execute()` on ISIs
use iroha_core::{
    governance::manifest::LaneManifestRegistry, prelude::World,
    smartcontracts::ivm::cache::IvmCache, state::State, tx::TransactionRejectionReason,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    executor::{IvmAdmissionError, ValidationFail},
    prelude::*,
    smart_contract::{ContractArtifactId, manifest},
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use ivm::{ProgramMetadata, encoding};
use nonzero_ext::nonzero;
use std::{borrow::Cow, num::NonZeroU64, sync::Arc};
const TEST_GAS_LIMIT: u64 = 1_000_000;
fn checked_random_ivm_manifest_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked IVM manifest keypair")
}
#[test]
fn ivm_manifest_fixture_uses_checked_randomness() {
    let key_pair = checked_random_ivm_manifest_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::Ed25519);
}
fn minimal_contract_interface() -> ivm::EmbeddedContractInterfaceV1 {
    ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: vec![iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 { name: "CanManageSmartContractCode".parse().unwrap(), scope: iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Chain { permission_name: "CanManageSmartContractCode".parse().unwrap() } }],
        callables: vec![ivm::call::EmbeddedCallableV1 {
            entry_pc: 0,
            frame_bytes: 0,
            arguments: ivm::call::CallSchemaV1::empty(),
            results: ivm::call::CallSchemaV1::unit(),
        }],
        seiyaku_name: "ManifestAdmissionFixture".to_owned(),
        compiler_fingerprint: "iroha-core-manifest-admission-test".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission("CanManageSmartContractCode".parse().unwrap()),
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    }
}
fn minimal_contract_artifact(abi_version: u8) -> (Vec<u8>, manifest::ContractManifest) {
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 4,
        abi_version,
    };
    let mut artifact = meta.encode();
    artifact.extend_from_slice(&minimal_contract_interface().encode_section());
    for instruction in [
        ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
        ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
    ] {
        artifact.extend_from_slice(&instruction.to_le_bytes());
    }
    let verified =
        ivm::verify_contract_artifact(&artifact).expect("canonical manifest test contract");
    (artifact, verified.manifest)
}
fn minimal_contract_artifact_with_syscall(abi_version: u8, syscall: u8) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(ivm::instruction::wide::system::SCALL, syscall).to_le_bytes(),
    );
    for instruction in [
        ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
        ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
    ] {
        code.extend_from_slice(&instruction.to_le_bytes());
    }
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 5,
        abi_version,
    };
    let mut out = meta.encode();
    out.extend_from_slice(&minimal_contract_interface().encode_section());
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
fn contract_entrypoint_metadata(entrypoint: &str) -> Metadata {
    let mut metadata = Metadata::default();
    metadata.insert(
        "contract_entrypoint"
            .parse()
            .expect("static contract entrypoint metadata key"),
        Json::new(entrypoint.to_owned()),
    );
    metadata
}
fn contract_dispatch_metadata(entrypoint: &str, contract_address: &ContractAddress) -> Metadata {
    let mut metadata = contract_entrypoint_metadata(entrypoint);
    metadata.insert(
        "contract_address"
            .parse()
            .expect("static contract address metadata key"),
        Json::new(contract_address.to_string()),
    );
    metadata
}
fn install_current_lane_manifest_registry(state: &State) {
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
}
// This component World/height overlay uses synthetic Global scope metadata.
// It does not apply signed genesis or establish an authenticated root or Network finality.
fn manifest_admission_root_parameter() -> iroha_data_model::parameter::Parameter {
    use iroha_data_model::{
        block::consensus::{SumeragiGenesisContextParameters, SumeragiRootScope},
        parameter::{
            Parameter,
            custom::CustomParameter,
            system::{
                ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
                consensus_metadata,
            },
        },
    };
    let context = SumeragiGenesisContextParameters::recommended();
    assert_eq!(context.root_scope, SumeragiRootScope::Global);
    let metadata = ConsensusHandshakeMetadata {
        mode: SumeragiConsensusMode::Permissioned,
        block_cadence_ms: NonZeroU64::new(1_000).unwrap(),
        wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
        consensus_fingerprint: ConsensusFingerprint::new([0xA5; 32]),
        sumeragi_context: context,
    };
    metadata
        .validate()
        .expect("valid global manifest fixture metadata");
    Parameter::Custom(CustomParameter::new(
        consensus_metadata::handshake_meta_id(),
        Json::new(metadata),
    ))
}
#[test]
fn ivm_manifest_mismatched_abi_hash_rejected_at_admission() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    use iroha_data_model::{
        permission,
        transaction::{Executable, TransactionBuilder},
    };
    // Build world with a domain and an authority account
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_ivm_manifest_keypair();
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
    // Prepare a minimal IVM program and its hashes
    let (prog, mut manifest) = minimal_contract_artifact(1);
    let code_hash = manifest
        .code_hash
        .expect("verified contract manifest must bind its artifact hash");
    let policy = ivm::SyscallPolicy::AbiV1;
    let correct_abi = ivm::syscalls::compute_abi_hash(policy);
    let mut wrong_abi = correct_abi;
    wrong_abi[0] ^= 0x5A; // flip a byte to make it wrong
    // Block 1: grant permission and register a manifest with wrong abi_hash under the code_hash
    let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    stx1.world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(manifest_admission_root_parameter());
    // Grant CanManageSmartContractCode to the authority
    let token = iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
    let perm: permission::Permission = token.into();
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    // Register manifest with wrong abi_hash
    manifest.abi_hash = Some(iroha_crypto::Hash::prehashed(wrong_abi));
    let manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &kp,
        )
        .expect("sign bounded fixture manifest");
    stx1.world.contract_manifests_mut_for_testing().insert(
        ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
        manifest,
    );
    stx1.apply();
    let _ = block1.commit_world_overlay_for_testing();
    // Block 2: submit the IVM program; admission should reject due to abi_hash mismatch
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(block2.world()),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    );
    let tx = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(TEST_GAS_LIMIT),
    )
    .with_metadata(contract_entrypoint_metadata("main"))
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
    .sign(kp.private_key());
    let mut ivm_cache = IvmCache::new();
    let accepted = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block2,
        accepted,
        &mut ivm_cache,
        None,
    );
    match result {
        Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
            IvmAdmissionError::ManifestAbiHashMismatch(info),
        ))) => {
            assert_eq!(info.expected, iroha_crypto::Hash::prehashed(wrong_abi));
            assert_eq!(info.actual, iroha_crypto::Hash::prehashed(correct_abi));
        }
        other => panic!(
            "abi_hash mismatch must be rejected at admission with structured error, got {other:?}"
        ),
    }
}
#[test]
fn ivm_manifest_matching_abi_hash_accepted_at_admission() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    use iroha_data_model::{
        permission,
        transaction::{Executable, TransactionBuilder},
    };
    // Build world with a domain and an authority account
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_ivm_manifest_keypair();
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
    // Prepare a minimal IVM program and its hashes
    let (prog, manifest) = minimal_contract_artifact(1);
    let code_hash = manifest
        .code_hash
        .expect("verified contract manifest must bind its artifact hash");
    let contract_address =
        ContractAddress::derive(&network_id, &account_id, 1, DataSpaceId::UNIVERSAL)
            .expect("derive manifest admission contract address");
    let policy = ivm::SyscallPolicy::AbiV1;
    let correct_abi = ivm::syscalls::compute_abi_hash(policy);
    // Block 1: grant permission and register a manifest with correct abi_hash under the code_hash
    let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    stx1.world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(manifest_admission_root_parameter());
    // Grant permission
    let token = iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
    let perm: permission::Permission = token.into();
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    // Register and activate the exact artifact in the synthetic scoped component
    // World so raw dispatch exercises the canonical local identity lookup.
    iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: prog.clone(),
    }
    .execute(&account_id, &mut stx1)
    .expect("register exact contract artifact");
    assert_eq!(
        manifest.abi_hash,
        Some(iroha_crypto::Hash::prehashed(correct_abi)),
        "verified contract manifest must bind the canonical ABI"
    );
    let manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &kp,
        )
        .expect("sign bounded fixture manifest");
    {
        let scoped_manifest = manifest;
        iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&account_id, &mut stx1)
    .expect("register exact contract manifest");
    Register::account(Account::new(contract_address.subject_id()))
        .execute(&account_id, &mut stx1)
        .expect("register non-signable contract-subject account");
    stx1.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), account_id.clone());
    iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&account_id, &mut stx1)
    .expect("activate manifest admission contract");
    stx1.apply();
    let _ = block1.commit_world_overlay_for_testing();
    // Block 2: submit the IVM program; admission should accept due to matching abi_hash
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(block2.world()),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    );
    let tx = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(TEST_GAS_LIMIT),
    )
    .with_metadata(contract_dispatch_metadata("main", &contract_address))
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
    .sign(kp.private_key());
    let mut ivm_cache = IvmCache::new();
    let accepted = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block2,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(
        result.is_ok(),
        "matching manifest abi_hash should allow admission, got {result:?}"
    );
}
#[test]
fn ivm_manifest_without_abi_hash_is_rejected_at_admission() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    use iroha_data_model::{
        permission,
        transaction::{Executable, TransactionBuilder},
    };
    // Build world with a domain and an authority account
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_ivm_manifest_keypair();
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
    // Prepare a minimal IVM program (v1) and its hashes
    let (prog, mut manifest) = minimal_contract_artifact(1);
    let code_hash = manifest
        .code_hash
        .expect("verified contract manifest must bind its artifact hash");
    // Block 1: grant permission and register a manifest with only code_hash (no abi_hash)
    let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    stx1.world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(manifest_admission_root_parameter());
    // Grant permission
    let token = iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
    let perm: permission::Permission = token.into();
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    // Register manifest with code_hash only
    manifest.abi_hash = None;
    let manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &kp,
        )
        .expect("sign bounded fixture manifest");
    stx1.world.contract_manifests_mut_for_testing().insert(
        ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
        manifest,
    );
    stx1.apply();
    let _ = block1.commit_world_overlay_for_testing();
    // Block 2: a present V1 manifest is incomplete without its ABI binding.
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(block2.world()),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    );
    let tx = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(TEST_GAS_LIMIT),
    )
    .with_metadata(contract_entrypoint_metadata("main"))
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
    .sign(kp.private_key());
    let mut ivm_cache = IvmCache::new();
    let accepted = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block2,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(
        matches!(
            result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::IvmAdmission(IvmAdmissionError::ManifestAbiHashMissing)
            ))
        ),
        "manifest with no abi_hash must fail closed, got {result:?}"
    );
}
#[test]
fn ivm_manifest_matching_abi_hash_v1_accepted_at_admission() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    use iroha_data_model::{
        permission,
        transaction::{Executable, TransactionBuilder},
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_ivm_manifest_keypair();
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
    let (prog, manifest) = minimal_contract_artifact(1);
    let code_hash = manifest
        .code_hash
        .expect("verified contract manifest must bind its artifact hash");
    let contract_address =
        ContractAddress::derive(&network_id, &account_id, 2, DataSpaceId::UNIVERSAL)
            .expect("derive manifest admission contract address");
    let abi_current = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    // Block 1: grant permission and register manifest with v1 abi_hash
    let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    stx1.world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(manifest_admission_root_parameter());
    let token = iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
    let perm: permission::Permission = token.into();
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: prog.clone(),
    }
    .execute(&account_id, &mut stx1)
    .expect("register exact V1 contract artifact");
    assert_eq!(
        manifest.abi_hash,
        Some(iroha_crypto::Hash::prehashed(abi_current)),
        "verified V1 contract manifest must bind the canonical ABI"
    );
    let manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &kp,
        )
        .expect("sign bounded fixture manifest");
    {
        let scoped_manifest = manifest;
        iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&account_id, &mut stx1)
    .expect("register exact V1 contract manifest");
    Register::account(Account::new(contract_address.subject_id()))
        .execute(&account_id, &mut stx1)
        .expect("register non-signable V1 contract-subject account");
    stx1.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), account_id.clone());
    iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&account_id, &mut stx1)
    .expect("activate V1 manifest admission contract");
    stx1.apply();
    let _ = block1.commit_world_overlay_for_testing();
    // Block 2: submit program; admission should accept
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(block2.world()),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    );
    let tx = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(TEST_GAS_LIMIT),
    )
    .with_metadata(contract_dispatch_metadata("main", &contract_address))
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
    .sign(kp.private_key());
    let mut ivm_cache = IvmCache::new();
    let accepted = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block2,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(
        result.is_ok(),
        "v1 abi_hash should allow admission, got {result:?}"
    );
}
#[test]
fn ivm_manifest_unknown_syscall_rejected_before_execution() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    use iroha_data_model::{
        permission,
        transaction::{Executable, TransactionBuilder},
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_ivm_manifest_keypair();
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
    let unknown_syscall = unlisted_syscall_number();
    let (valid_artifact, mut manifest) = minimal_contract_artifact(1);
    let prog = minimal_contract_artifact_with_syscall(1, unknown_syscall);
    let code_hash = ivm::contract_code_hash(&prog);
    let abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    assert_ne!(
        code_hash,
        ivm::contract_code_hash(&valid_artifact),
        "unknown-syscall artifact must have a distinct content hash"
    );
    // Block 1: grant permission and register the manifest with the correct abi_hash.
    let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block1 = state.block(header1);
    let mut stx1 = block1.transaction();
    stx1.world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(manifest_admission_root_parameter());
    let token = iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
    let perm: permission::Permission = token.into();
    Grant::account_permission(perm, account_id.clone())
        .execute(&account_id, &mut stx1)
        .expect("grant permission");
    manifest.code_hash = Some(code_hash);
    manifest.abi_hash = Some(iroha_crypto::Hash::prehashed(abi_hash));
    let manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &kp,
        )
        .expect("sign bounded fixture manifest");
    stx1.world.contract_manifests_mut_for_testing().insert(
        ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
        manifest,
    );
    stx1.apply();
    let _ = block1.commit_world_overlay_for_testing();
    // Block 2: submit the program with an unknown syscall; admission should reject before execution.
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(block2.world()),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    );
    let tx = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        fee_payment_with_gas_limit(TEST_GAS_LIMIT),
    )
    .with_metadata(contract_entrypoint_metadata("main"))
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
    .sign(kp.private_key());
    let mut ivm_cache = IvmCache::new();
    let accepted = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block2,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(
        matches!(
            result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::IvmAdmission(IvmAdmissionError::BytecodeDecodingFailed(ref message))
            )) if message == "invalid program metadata"
        ),
        "contract verification must reject the unknown syscall before host execution, got {result:?}"
    );
}
