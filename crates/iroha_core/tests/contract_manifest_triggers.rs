//! Contract manifest trigger registration tests.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    smartcontracts::triggers::{
        set::{ExecutableRef, SetReadOnly},
        specialized::LoadedActionTrait,
    },
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    events::EventFilterBox,
    events::data::{
        DataEventFilter,
        prelude::{AssetEventFilter, AssetEventSet},
    },
    events::pipeline::{BlockEventFilter, BlockStatus, PipelineEventFilterBox},
    events::time::{ExecutionTime, TimeEventFilter},
    isi::{
        contract_alias::SetContractAlias,
        error::{InstructionExecutionError, InvalidParameterError},
        smart_contract_code::{
            ActivateContractInstance, DeactivateContractInstance, RegisterSmartContractBytes,
            RegisterSmartContractCode,
        },
    },
    permission,
    prelude::*,
    smart_contract::manifest::{
        ContractManifest, EntryPointKind, EntrypointDescriptor, TriggerCallback, TriggerDescriptor,
    },
    trigger::action::Repeats,
};
use iroha_executor_data_model::permission::{
    account::{AccountAliasPermissionScope, CanManageAccountAlias},
    trigger::CanRegisterGlobalDataTrigger,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn contract_artifact(entrypoints: Vec<EntrypointDescriptor>) -> (Vec<u8>, ContractManifest) {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 4,
        abi_version: 1,
    };
    let embedded_entrypoints = entrypoints
        .iter()
        .enumerate()
        .map(|(index, entrypoint)| ivm::EmbeddedEntrypointDescriptor {
            name: entrypoint.name.clone(),
            kind: entrypoint.kind,
            params: entrypoint.params.clone(),
            argument_schema: entrypoint.argument_schema.clone(),
            return_type: entrypoint.return_type.clone(),
            return_schema: entrypoint.return_schema.clone(),
            authorization: entrypoint.authorization.clone(),
            read_keys: entrypoint.read_keys.clone(),
            write_keys: entrypoint.write_keys.clone(),
            access_hints_complete: entrypoint.access_hints_complete,
            access_hints_skipped: entrypoint.access_hints_skipped.clone(),
            triggers: entrypoint.triggers.clone(),
            entry_pc: u64::try_from(index).unwrap() * 16,
        })
        .collect();
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: entrypoints.iter().filter_map(|entry| match &entry.authorization {
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(name) => Some(name.clone()), _ => None,
        }).collect::<std::collections::BTreeSet<_>>().into_iter().map(|name| iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 {
            scope: if name.as_ref() == "CanEnactGovernance" { iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Chain { permission_name: name.clone() } } else { iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Instance }, name,
        }).collect(),
        callables: entrypoints
            .iter()
            .enumerate()
            .map(|(index, entrypoint)| {
                assert!(entrypoint.params.is_empty());
                assert_eq!(entrypoint.return_type.as_deref(), Some("()"));
                ivm::call::EmbeddedCallableV1 {
                    entry_pc: u64::try_from(index).unwrap() * 16,
                    frame_bytes: 0,
                    arguments: ivm::call::CallSchemaV1::empty(),
                    results: ivm::call::CallSchemaV1::unit(),
                }
            })
            .collect(),
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "contract-manifest-trigger-test".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: embedded_entrypoints,
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut code = Vec::new();
    for _ in &entrypoints {
        for instruction in [
            ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
            ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
        ] {
            code.extend_from_slice(&instruction.to_le_bytes());
        }
    }
    let mut out = meta.encode();
    out.extend_from_slice(&interface.encode_section());
    out.extend_from_slice(&code);
    let verified = ivm::verify_contract_artifact(&out).expect("valid test contract artifact");
    (out, verified.manifest)
}
#[test]
fn trigger_fixture_authenticates_each_distinct_unit_return_entrypoint() {
    let (_, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            "seiyaku TriggerFixture { view fn run() authorize(anyone) { () } view fn arm() authorize(anyone) { () } }",
        )
        .unwrap();
    let (program, _) = contract_artifact(manifest.entrypoints.unwrap());
    let metadata = ivm::ProgramMetadata::parse(&program).unwrap();
    let interface = metadata.contract_interface.as_ref().unwrap();
    assert_eq!(interface.callables.len(), 2);
    assert_ne!(
        interface.entrypoints[0].entry_pc,
        interface.entrypoints[1].entry_pc
    );
    for entrypoint in &interface.entrypoints {
        let mut vm = ivm::IVM::new(100_000);
        vm.load_program(&program).unwrap();
        vm.set_program_counter(metadata.prefix_len() as u64 + entrypoint.entry_pc)
            .unwrap();
        vm.run()
            .expect("each trigger target completes its own Unit table");
        assert_eq!(vm.call_result_word_count().unwrap(), 1);
        assert_eq!(vm.public_call_result_word(0).unwrap(), 0);
    }
}
fn checked_random_contract_manifest_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked contract manifest signer keypair")
}
#[test]
fn contract_manifest_trigger_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_contract_manifest_keypair();
}
fn setup_state() -> (State, AccountId, KeyPair) {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_contract_manifest_keypair();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let account_id = AccountId::new(kp.public_key().clone());
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], core::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query_handle);
    (state, account_id, kp)
}
fn opaque_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::from_uuid_bytes([
        0x68, 0x72, 0x45, 0x4e, 0x9c, 0x04, 0x46, 0x41, 0xaa, 0x58, 0x1e, 0xc5, 0xf3, 0x80, 0x16,
        0x19,
    ])
    .expect("opaque asset definition id")
}
fn contract_address(
    authority: &AccountId,
    deploy_nonce: u64,
) -> iroha_data_model::smart_contract::ContractAddress {
    iroha_data_model::smart_contract::ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        authority,
        deploy_nonce,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("contract address")
}
fn assert_contract_trigger_metadata(
    metadata: &Metadata,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
    code_hash: iroha_crypto::Hash,
    trigger_id: &TriggerId,
    user_key: &str,
    user_value: &str,
) {
    let key_address: Name = "contract_address".parse().expect("contract address key");
    let key_entrypoint: Name = "contract_entrypoint".parse().expect("entrypoint key");
    let key_code: Name = "contract_code_hash".parse().expect("code hash key");
    let key_trigger: Name = "contract_trigger_id".parse().expect("trigger id key");
    assert_eq!(
        metadata.get(&key_address),
        Some(&Json::from(contract_address.to_string().as_str()))
    );
    assert!(
        metadata
            .get(
                &"contract_namespace"
                    .parse::<Name>()
                    .expect("legacy namespace key")
            )
            .is_none()
    );
    assert!(
        metadata
            .get(&"contract_id".parse::<Name>().expect("legacy contract key"))
            .is_none()
    );
    assert_eq!(metadata.get(&key_entrypoint), Some(&Json::from(entrypoint)));
    let code_hash_json = Json::from(code_hash.to_string().as_str());
    assert_eq!(metadata.get(&key_code), Some(&code_hash_json));
    let trigger_id_json = Json::from(trigger_id.to_string().as_str());
    assert_eq!(metadata.get(&key_trigger), Some(&trigger_id_json));
    let user_name: Name = user_key.parse().expect("user metadata key");
    assert_eq!(metadata.get(&user_name), Some(&Json::from(user_value)));
}
#[test]
#[allow(clippy::too_many_lines)]
fn activate_registers_manifest_triggers_and_deactivate_removes() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (state, authority, kp) = setup_state();
    let contract_address = contract_address(&authority, 0);
    let contract_subject = contract_address.subject_id();
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let register_perm: permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(register_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanManageSmartContractCode");
    let enact_perm: permission::Permission =
        iroha_executor_data_model::permission::governance::CanEnactGovernance.into();
    Grant::account_permission(enact_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanEnactGovernance");
    let trigger_id: TriggerId = "wake".parse().expect("trigger id");
    let mut descriptor_metadata = Metadata::default();
    descriptor_metadata.insert("tag".parse::<Name>().expect("tag key"), Json::from("alpha"));
    let trigger = TriggerDescriptor {
        id: trigger_id.clone(),
        repeats: Repeats::Indefinitely,
        filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
        authority: None,
        metadata: descriptor_metadata,
        callback: TriggerCallback {
            namespace: None,
            entrypoint: "run".to_string(),
        },
    };
    let entrypoint = EntrypointDescriptor {
        name: "run".to_string(),
        kind: EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "CanEnactGovernance".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: vec![trigger],
    };
    let (program, manifest) = contract_artifact(vec![entrypoint]);
    let code_hash = manifest.code_hash.expect("manifest code hash");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: program,
    }
    .execute(&authority, &mut stx)
    .expect("register contract bytes");
    let manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &kp,
        )
        .expect("sign bounded fixture manifest");
    {
        let scoped_manifest = manifest;
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register manifest");
    let missing_lifecycle_error = ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&authority, &mut stx)
    .expect_err("raw activation must not create a lifecycle address");
    assert!(
        format!("{missing_lifecycle_error:?}").contains("lifecycle binding not found"),
        "unexpected missing lifecycle error: {missing_lifecycle_error}"
    );
    assert!(
        stx.world.triggers().ids().get(&trigger_id).is_none(),
        "failed activation registered the manifest trigger"
    );
    Register::account(Account::new(contract_subject.clone()))
        .execute(&authority, &mut stx)
        .expect("register the non-signable contract-subject account");
    stx.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), authority.clone());
    assert!(
        !stx.can_register_trigger_for(&authority, &contract_subject),
        "the activation authority must not receive persistent trigger-registration permission"
    );
    ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&authority, &mut stx)
    .expect("activate");
    let action = stx
        .world
        .triggers()
        .time_triggers()
        .get(&trigger_id)
        .expect("trigger registered");
    assert_eq!(
        action.authority(),
        &contract_address.subject_id(),
        "a manifest trigger without an explicit authority must execute as the immutable non-signable contract subject, not the activation signer"
    );
    let metadata = &action.metadata;
    let key_address: Name = "contract_address".parse().expect("contract address key");
    let key_entrypoint: Name = "contract_entrypoint".parse().expect("entrypoint key");
    let key_code: Name = "contract_code_hash".parse().expect("code hash key");
    let key_trigger: Name = "contract_trigger_id".parse().expect("trigger id key");
    assert_eq!(
        metadata.get(&key_address),
        Some(&Json::from(contract_address.to_string().as_str()))
    );
    assert!(
        metadata
            .get(
                &"contract_namespace"
                    .parse::<Name>()
                    .expect("legacy namespace key")
            )
            .is_none()
    );
    assert!(
        metadata
            .get(&"contract_id".parse::<Name>().expect("legacy contract key"))
            .is_none()
    );
    assert_eq!(metadata.get(&key_entrypoint), Some(&Json::from("run")));
    let code_hash_json = Json::from(code_hash.to_string().as_str());
    assert_eq!(metadata.get(&key_code), Some(&code_hash_json));
    let trigger_id_json = Json::from(trigger_id.to_string().as_str());
    assert_eq!(metadata.get(&key_trigger), Some(&trigger_id_json));
    let tag_key: Name = "tag".parse().expect("tag key");
    assert_eq!(metadata.get(&tag_key), Some(&Json::from("alpha")));
    DeactivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 2,
        reason: None,
    }
    .execute(&authority, &mut stx)
    .expect("deactivate");
    assert!(stx.world.triggers().ids().get(&trigger_id).is_none());
}
#[test]
fn activate_rejects_manifest_trigger_with_unauthorized_foreign_authority() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (state, authority, kp) = setup_state();
    let foreign = AccountId::new(
        KeyPair::try_random()
            .expect("generate foreign trigger authority")
            .public_key()
            .clone(),
    );
    let contract_address = contract_address(&authority, 0);
    let contract_subject = contract_address.subject_id();
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let register_perm: permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(register_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanManageSmartContractCode");
    Register::account(Account::new(contract_subject))
        .execute(&authority, &mut stx)
        .expect("register the non-signable contract-subject account");
    stx.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), authority.clone());
    let trigger_id: TriggerId = "foreign_wake".parse().expect("trigger id");
    let trigger = TriggerDescriptor {
        id: trigger_id.clone(),
        repeats: Repeats::Indefinitely,
        filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
        authority: Some(foreign.clone()),
        metadata: Metadata::default(),
        callback: TriggerCallback {
            namespace: None,
            entrypoint: "run".to_owned(),
        },
    };
    let entrypoint = EntrypointDescriptor {
        name: "run".to_owned(),
        kind: EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "ExecuteForeignAuthorityProbe".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: vec![trigger],
    };
    let (program, manifest) = contract_artifact(vec![entrypoint]);
    let code_hash = manifest.code_hash.expect("manifest code hash");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: program,
    }
    .execute(&authority, &mut stx)
    .expect("register contract bytes");
    {
        let scoped_manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register manifest");
    let error = ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&authority, &mut stx)
    .expect_err("manifest trigger must not impersonate a foreign account");
    assert!(
        format!("{error:?}").contains(&format!(
            "Missing CanRegisterTrigger{{authority: {foreign}}} permission"
        )),
        "unexpected foreign-authority error: {error}"
    );
    assert!(
        stx.world
            .triggers()
            .time_triggers()
            .get(&trigger_id)
            .is_none(),
        "unauthorized manifest trigger was registered"
    );
    assert!(
        stx.world
            .contract_instances()
            .get(&contract_address)
            .is_none(),
        "failed activation bound a contract instance"
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn activate_registers_manifest_data_and_pipeline_triggers_and_deactivate_removes_them() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (state, authority, kp) = setup_state();
    let contract_address = contract_address(&authority, 0);
    let contract_subject = contract_address.subject_id();
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let register_perm: permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(register_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanManageSmartContractCode");
    let enact_perm: permission::Permission =
        iroha_executor_data_model::permission::governance::CanEnactGovernance.into();
    Grant::account_permission(enact_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanEnactGovernance");
    let asset_definition = opaque_asset_definition_id();
    let data_trigger_id: TriggerId = "asset_added".parse().expect("data trigger id");
    let pipeline_trigger_id: TriggerId = "block_seen".parse().expect("pipeline trigger id");
    let mut data_metadata = Metadata::default();
    data_metadata.insert("tag".parse::<Name>().expect("tag key"), Json::from("data"));
    let data_trigger = TriggerDescriptor {
        id: data_trigger_id.clone(),
        repeats: Repeats::Indefinitely,
        filter: EventFilterBox::Data(DataEventFilter::Asset(
            AssetEventFilter::new()
                .for_events(AssetEventSet::Added)
                .for_asset_definition(asset_definition.clone()),
        )),
        authority: None,
        metadata: data_metadata,
        callback: TriggerCallback {
            namespace: None,
            entrypoint: "run".to_string(),
        },
    };
    let mut pipeline_metadata = Metadata::default();
    pipeline_metadata.insert(
        "tag".parse::<Name>().expect("tag key"),
        Json::from("pipeline"),
    );
    let pipeline_trigger = TriggerDescriptor {
        id: pipeline_trigger_id.clone(),
        repeats: Repeats::Indefinitely,
        filter: EventFilterBox::Pipeline(PipelineEventFilterBox::Block(
            BlockEventFilter::new().for_status(BlockStatus::Approved),
        )),
        authority: None,
        metadata: pipeline_metadata,
        callback: TriggerCallback {
            namespace: None,
            entrypoint: "run".to_string(),
        },
    };
    let entrypoint = EntrypointDescriptor {
        name: "run".to_string(),
        kind: EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "CanEnactGovernance".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: vec![data_trigger, pipeline_trigger],
    };
    let (program, manifest) = contract_artifact(vec![entrypoint]);
    let code_hash = manifest.code_hash.expect("manifest code hash");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: program,
    }
    .execute(&authority, &mut stx)
    .expect("register contract bytes");
    let manifest = manifest
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &kp,
        )
        .expect("sign bounded fixture manifest");
    {
        let scoped_manifest = manifest;
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register manifest");
    Register::account(Account::new(contract_subject.clone()))
        .execute(&authority, &mut stx)
        .expect("register the non-signable contract-subject account");
    stx.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), authority.clone());
    // The unregistered definition is outside the contract subject's owned scope.
    // A capability scoped to the activator cannot authorize the default subject.
    let wrong_scope: permission::Permission = CanRegisterGlobalDataTrigger {
        authority: authority.clone(),
    }
    .into();
    Grant::account_permission(wrong_scope, authority.clone())
        .execute(&authority, &mut stx)
        .expect("seed activator-scoped global data-trigger capability");
    let error = ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&authority, &mut stx)
    .expect_err("activation must require the exact contract-subject scope");
    assert_eq!(
        error,
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            "data trigger filter exceeds the trigger authority's exact owned scope; CanRegisterGlobalDataTrigger is required"
                .into(),
        )),
    );
    assert!(stx.world.triggers().ids().get(&data_trigger_id).is_none());
    assert!(
        stx.world
            .triggers()
            .ids()
            .get(&pipeline_trigger_id)
            .is_none()
    );
    assert!(
        stx.world
            .contract_instances()
            .get(&contract_address)
            .is_none()
    );
    let exact_scope: permission::Permission = CanRegisterGlobalDataTrigger {
        authority: contract_subject.clone(),
    }
    .into();
    Grant::account_permission(exact_scope, authority.clone())
        .execute(&authority, &mut stx)
        .expect("seed exact contract-subject global data-trigger capability on activator");
    ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&authority, &mut stx)
    .expect("activate");
    let data_action = stx
        .world
        .triggers()
        .data_triggers()
        .get(&data_trigger_id)
        .expect("data trigger registered");
    assert_eq!(
        data_action.filter,
        DataEventFilter::Asset(
            AssetEventFilter::new()
                .for_events(AssetEventSet::Added)
                .for_asset_definition(asset_definition),
        )
    );
    assert_eq!(data_action.authority, contract_subject);
    assert_contract_trigger_metadata(
        &data_action.metadata,
        &contract_address,
        "run",
        code_hash,
        &data_trigger_id,
        "tag",
        "data",
    );
    let pipeline_action = stx
        .world
        .triggers()
        .pipeline_triggers()
        .get(&pipeline_trigger_id)
        .expect("pipeline trigger registered");
    assert_eq!(
        pipeline_action.filter,
        PipelineEventFilterBox::Block(BlockEventFilter::new().for_status(BlockStatus::Approved))
    );
    assert_contract_trigger_metadata(
        &pipeline_action.metadata,
        &contract_address,
        "run",
        code_hash,
        &pipeline_trigger_id,
        "tag",
        "pipeline",
    );
    DeactivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 2,
        reason: None,
    }
    .execute(&authority, &mut stx)
    .expect("deactivate");
    assert!(
        stx.world
            .triggers()
            .data_triggers()
            .get(&data_trigger_id)
            .is_none()
    );
    assert!(
        stx.world
            .triggers()
            .pipeline_triggers()
            .get(&pipeline_trigger_id)
            .is_none()
    );
    assert!(stx.world.triggers().ids().get(&data_trigger_id).is_none());
    assert!(
        stx.world
            .triggers()
            .ids()
            .get(&pipeline_trigger_id)
            .is_none()
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn activate_registers_cross_contract_manifest_trigger_callback() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (state, authority, kp) = setup_state();
    let target_address = contract_address(&authority, 0);
    let source_address = contract_address(&authority, 1);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let register_perm: permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(register_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanManageSmartContractCode");
    let enact_perm: permission::Permission =
        iroha_executor_data_model::permission::governance::CanEnactGovernance.into();
    Grant::account_permission(enact_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanEnactGovernance");
    let alias_manage_permission: permission::Permission = CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
    }
    .into();
    Grant::account_permission(alias_manage_permission, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant universal-dataspace account-alias management");
    let target_entrypoint = EntrypointDescriptor {
        name: "run".to_string(),
        kind: EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "CanEnactGovernance".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
    };
    let (target_program, target_manifest) = contract_artifact(vec![target_entrypoint]);
    let target_code_hash = target_manifest.code_hash.expect("target code hash");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            target_code_hash,
        ),
        code: target_program,
    }
    .execute(&authority, &mut stx)
    .expect("register target bytes");
    {
        let scoped_manifest = target_manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register target manifest");
    stx.world
        .bind_inactive_contract_subject_for_testing(target_address.clone(), authority.clone());
    ActivateContractInstance {
        contract_address: target_address.clone(),
        expected_revision: 1,
        code_hash: target_code_hash,
    }
    .execute(&authority, &mut stx)
    .expect("activate target");
    let target_alias: iroha_data_model::smart_contract::ContractAlias =
        "callee::universal".parse().expect("contract alias");
    SetContractAlias::bind(target_address.clone(), target_alias.clone(), None)
        .execute(&authority, &mut stx)
        .expect("bind target alias");
    let trigger_id: TriggerId = "wake".parse().expect("trigger id");
    let mut descriptor_metadata = Metadata::default();
    descriptor_metadata.insert(
        "tag".parse::<Name>().expect("tag key"),
        Json::from("remote"),
    );
    let trigger = TriggerDescriptor {
        id: trigger_id.clone(),
        repeats: Repeats::Indefinitely,
        filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
        authority: None,
        metadata: descriptor_metadata,
        callback: TriggerCallback {
            namespace: Some("callee".to_string()),
            entrypoint: "run".to_string(),
        },
    };
    let source_entrypoint = EntrypointDescriptor {
        name: "arm".to_string(),
        kind: EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "CanEnactGovernance".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: vec![trigger],
    };
    let (source_program, source_manifest) = contract_artifact(vec![source_entrypoint]);
    let source_code_hash = source_manifest.code_hash.expect("source code hash");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            source_code_hash,
        ),
        code: source_program,
    }
    .execute(&authority, &mut stx)
    .expect("register source bytes");
    {
        let scoped_manifest = source_manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register source manifest");
    Register::account(Account::new(source_address.subject_id()))
        .execute(&authority, &mut stx)
        .expect("register the non-signable source contract-subject account");
    stx.world
        .bind_inactive_contract_subject_for_testing(source_address.clone(), authority.clone());
    // This direct lifecycle component fixture does not apply signed genesis.
    // The target registry lookup still requires explicit structurally valid
    // immutable root metadata; an empty World must never acquire Global scope.
    let denied =
        iroha_core::smartcontracts::code::fetch_bound_contract_record(&stx, &target_address)
            .expect_err("missing immutable root scope cannot access the callback artifact");
    assert!(matches!(denied,
        iroha_core::execution_attempt::ExecutionAttemptError::Rejected(
            iroha_data_model::ValidationFail::NotPermitted(message),
        ) if message == "artifact access requires immutable root scope"
    ));
    {
        use iroha_data_model::parameter::{
            Parameter,
            custom::CustomParameter,
            system::{
                ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
                consensus_metadata,
            },
        };
        let metadata = ConsensusHandshakeMetadata {
            mode: SumeragiConsensusMode::Permissioned,
            block_cadence_ms: nonzero!(1_000_u64),
            wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
            consensus_fingerprint: ConsensusFingerprint::new([0xA5; 32]),
            sumeragi_context:
                iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
        };
        metadata
            .validate()
            .expect("valid explicit component root metadata");
        stx.world
            .parameters_mut_for_testing()
            .get_mut()
            .set_parameter(Parameter::Custom(CustomParameter::new(
                consensus_metadata::handshake_meta_id(),
                Json::new(metadata),
            )));
        assert_eq!(
            iroha_core::sumeragi::lanes::routing::committed_root_scope(&*stx.world),
            Some(iroha_data_model::block::consensus::SumeragiRootScope::Global),
        );
    }
    ActivateContractInstance {
        contract_address: source_address.clone(),
        expected_revision: 1,
        code_hash: source_code_hash,
    }
    .execute(&authority, &mut stx)
    .expect("activate source");
    let action = stx
        .world
        .triggers()
        .time_triggers()
        .get(&trigger_id)
        .expect("trigger registered");
    assert_contract_trigger_metadata(
        &action.metadata,
        &target_address,
        "run",
        target_code_hash,
        &trigger_id,
        "tag",
        "remote",
    );
    let alias_key: Name = "contract_alias".parse().expect("contract alias key");
    assert_eq!(
        action.metadata.get(&alias_key),
        Some(&Json::from(target_alias.to_string().as_str()))
    );
    let namespace_key: Name = "contract_callback_namespace"
        .parse()
        .expect("callback namespace key");
    assert_eq!(
        action.metadata.get(&namespace_key),
        Some(&Json::from("callee"))
    );
    match action.executable() {
        ExecutableRef::ContractCall(invocation) => {
            assert_eq!(invocation.contract_address, target_address);
            assert_eq!(invocation.expected_code_hash, target_code_hash);
            assert_eq!(invocation.entrypoint, "run");
            assert_eq!(invocation.arguments, None);
        }
        other => panic!("unexpected trigger executable: {other:?}"),
    }
}
#[test]
fn activate_rejects_unresolved_cross_contract_manifest_trigger_callback() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (state, authority, kp) = setup_state();
    let source_address = contract_address(&authority, 0);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let register_perm: permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(register_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanManageSmartContractCode");
    let enact_perm: permission::Permission =
        iroha_executor_data_model::permission::governance::CanEnactGovernance.into();
    Grant::account_permission(enact_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanEnactGovernance");
    let trigger = TriggerDescriptor {
        id: "wake".parse().expect("trigger id"),
        repeats: Repeats::Indefinitely,
        filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
        authority: None,
        metadata: Metadata::default(),
        callback: TriggerCallback {
            namespace: Some("missing".to_string()),
            entrypoint: "run".to_string(),
        },
    };
    let source_entrypoint = EntrypointDescriptor {
        name: "arm".to_string(),
        kind: EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "CanEnactGovernance".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: vec![trigger],
    };
    let (source_program, source_manifest) = contract_artifact(vec![source_entrypoint]);
    let source_code_hash = source_manifest.code_hash.expect("source code hash");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            source_code_hash,
        ),
        code: source_program,
    }
    .execute(&authority, &mut stx)
    .expect("register source bytes");
    {
        let scoped_manifest = source_manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register source manifest");
    stx.world
        .bind_inactive_contract_subject_for_testing(source_address.clone(), authority.clone());
    let err = ActivateContractInstance {
        contract_address: source_address,
        expected_revision: 1,
        code_hash: source_code_hash,
    }
    .execute(&authority, &mut stx)
    .expect_err("unresolved cross-contract trigger namespace must fail activation");
    assert!(
        format!("{err:?}").contains("does not resolve"),
        "unexpected error: {err:?}"
    );
}
#[test]
fn activate_registers_kotodama_compiled_manifest_triggers_from_source() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (state, authority, kp) = setup_state();
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let register_perm: permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(register_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanManageSmartContractCode");
    let enact_perm: permission::Permission =
        iroha_executor_data_model::permission::governance::CanEnactGovernance.into();
    Grant::account_permission(enact_perm, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant CanEnactGovernance");
    let authority_literal = authority.to_string();
    let asset_definition = opaque_asset_definition_id();
    let source = format!(
        r#"
seiyaku Test {{ permission CanEnactGovernance;
  kotoage fn run() authorize(CanEnactGovernance) {{}}
  trigger asset_added -> run {{
    on data asset added {{
      asset_definition "{asset_definition}";
    }}
    authority "{authority_literal}";
    metadata {{
      tag: "data";
    }}
  }}
  trigger block_seen -> run {{
    on pipeline block approved;
    metadata {{
      tag: "pipeline";
    }}
  }}
}}
"#
    );
    let (program, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(&source)
        .expect("compile source with manifest");
    let code_hash = ivm::contract_code_hash(&program);
    let contract_address = contract_address(&authority, 0);
    Register::account(Account::new(contract_address.subject_id()))
        .execute(&authority, &mut stx)
        .expect("register the non-signable contract-subject account");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: program,
    }
    .execute(&authority, &mut stx)
    .expect("register contract bytes");
    {
        let scoped_manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register manifest");
    stx.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), authority.clone());
    let data_trigger_id: TriggerId = "asset_added".parse().expect("data trigger id");
    let pipeline_trigger_id: TriggerId = "block_seen".parse().expect("pipeline trigger id");
    let error = ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&authority, &mut stx)
    .expect_err("compiled manifest must not bypass data-trigger scope authorization");
    assert_eq!(
        error,
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            "data trigger filter exceeds the trigger authority's exact owned scope; CanRegisterGlobalDataTrigger is required"
                .into(),
        )),
    );
    assert!(stx.world.triggers().ids().get(&data_trigger_id).is_none());
    assert!(
        stx.world
            .triggers()
            .ids()
            .get(&pipeline_trigger_id)
            .is_none()
    );
    assert!(
        stx.world
            .contract_instances()
            .get(&contract_address)
            .is_none()
    );
    // Compiled explicit authorities require a direct capability scoped to that
    // authority, even when activation takes place in genesis.
    let exact_scope: permission::Permission = CanRegisterGlobalDataTrigger {
        authority: authority.clone(),
    }
    .into();
    Grant::account_permission(exact_scope, authority.clone())
        .execute(&authority, &mut stx)
        .expect("seed exact explicit-authority global data-trigger capability");
    ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash,
    }
    .execute(&authority, &mut stx)
    .expect("activate");
    let asset_definition = opaque_asset_definition_id();
    let data_action = stx
        .world
        .triggers()
        .data_triggers()
        .get(&data_trigger_id)
        .expect("data trigger registered");
    assert_eq!(
        data_action.filter,
        DataEventFilter::Asset(
            AssetEventFilter::new()
                .for_events(AssetEventSet::Added)
                .for_asset_definition(asset_definition),
        )
    );
    assert_eq!(data_action.authority, authority);
    assert_contract_trigger_metadata(
        &data_action.metadata,
        &contract_address,
        "run",
        code_hash,
        &data_trigger_id,
        "tag",
        "data",
    );
    let pipeline_action = stx
        .world
        .triggers()
        .pipeline_triggers()
        .get(&pipeline_trigger_id)
        .expect("pipeline trigger registered");
    assert_eq!(
        pipeline_action.filter,
        PipelineEventFilterBox::Block(BlockEventFilter::new().for_status(BlockStatus::Approved))
    );
    assert_eq!(
        pipeline_action.authority,
        contract_address.subject_id(),
        "a manifest trigger without an explicit authority must execute as the immutable contract subject"
    );
    assert_contract_trigger_metadata(
        &pipeline_action.metadata,
        &contract_address,
        "run",
        code_hash,
        &pipeline_trigger_id,
        "tag",
        "pipeline",
    );
}
