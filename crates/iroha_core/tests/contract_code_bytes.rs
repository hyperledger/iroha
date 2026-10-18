//! Tests for registering on-chain contract code bytes.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::KeyPair;
use iroha_data_model::isi::error::{InstructionExecutionError, InvalidParameterError};
use iroha_model_base::domain::DomainId;
use mv::storage::StorageReadOnly;
fn assert_smart_contract_error(error: &InstructionExecutionError, expected_message: &str) {
    match error {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert_eq!(message, expected_message),
        other => panic!("expected InvalidParameter(SmartContract), got {other:?}"),
    }
    let source = std::error::Error::source(error).expect("invalid parameter error has a source");
    assert_eq!(
        source.to_string(),
        format!("Invalid smart contract: {expected_message}")
    );
}
fn minimal_ivm_program(abi_version: u8) -> Vec<u8> {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 4,
        abi_version,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: Vec::new(),
        callables: vec![ivm::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm::call::CallSchemaV1::empty(),
                results: ivm::call::CallSchemaV1::unit(),
            }],
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "contract-code-bytes-test".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: None,
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut code = Vec::new();
    for instruction in [
        ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
        ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
    ] {
        code.extend_from_slice(&instruction.to_le_bytes());
    }
    let mut out = meta.encode();
    out.extend_from_slice(&interface.encode_section());
    out.extend_from_slice(&code);
    ivm::verify_contract_artifact(&out).expect("valid test contract artifact");
    out
}
#[test]
fn minimal_contract_fixture_completes_its_authenticated_unit_table() {
    let program = minimal_ivm_program(1);
    let metadata = ivm::ProgramMetadata::parse(&program).unwrap();
    let interface = metadata.contract_interface.as_ref().unwrap();
    assert_eq!(interface.callables.len(), 1);
    let entry_pc = metadata.prefix_len() as u64 + interface.entrypoints[0].entry_pc;
    let mut vm = ivm::IVM::new(100_000);
    vm.load_program(&program).unwrap();
    vm.set_program_counter(entry_pc).unwrap();
    vm.run()
        .expect("fixture returns through its authenticated callable");
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    assert_eq!(vm.public_call_result_word(0).unwrap(), 0);
}
fn multi_chunk_ivm_program() -> Vec<u8> {
    use iroha_data_model::isi::smart_contract_code::SMART_CONTRACT_CODE_CHUNK_BYTES;
    let mut program = minimal_ivm_program(1);
    let halt = ivm::encoding::wide::encode_halt().to_le_bytes();
    let minimum_len = SMART_CONTRACT_CODE_CHUNK_BYTES
        .checked_mul(2)
        .and_then(|len| len.checked_add(128))
        .expect("test artifact length");
    while program.len() < minimum_len {
        program.extend_from_slice(&halt);
    }
    ivm::verify_contract_artifact(&program).expect("valid multi-chunk contract artifact");
    program
}
fn checked_random_contract_code_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked contract code keypair")
}
#[test]
fn contract_code_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_contract_code_keypair();
}
#[test]
fn register_contract_code_bytes_stores_and_idempotent() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{isi::smart_contract_code::RegisterSmartContractBytes, prelude::*};
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let dom: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let auth = AccountId::of(pubkey);
    let domain = Domain::new(dom.clone()).build(&auth);
    let account = Account::new(auth.clone()).build(&auth);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, auth.clone())
        .execute(&auth, &mut stx)
        .expect("grant contract lifecycle authority");
    // Prepare program and code hash
    let prog = minimal_ivm_program(1);
    let code_hash = ivm::contract_code_hash(&prog);
    // Register bytes
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: prog.clone(),
    }
    .execute(&auth, &mut stx)
    .expect("register code bytes");
    stx.apply();
    // Verify stored (uncommitted block scope)
    let got = block
        .world
        .contract_code()
        .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ))
        .cloned();
    assert_eq!(got.as_deref(), Some(prog.as_slice()));
    block
        .commit_world_overlay_for_testing()
        .expect("commit initial block");
    // Idempotent re-register
    let mut block2 = state.block(iroha_data_model::block::BlockHeader::new(
        nonzero_ext::nonzero!(2_u64),
        None,
        None,
        0,
        0,
    ));
    let mut stx2 = block2.transaction();
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: prog.clone(),
    }
    .execute(&auth, &mut stx2)
    .expect("idempotent");
}
#[test]
fn register_contract_code_bytes_respects_size_cap() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{
        isi::smart_contract_code::RegisterSmartContractBytes,
        parameter::custom::{CustomParameter, CustomParameterId},
        prelude::*,
    };
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let dom: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let auth = AccountId::of(pubkey);
    let domain = Domain::new(dom.clone()).build(&auth);
    let account = Account::new(auth.clone()).build(&auth);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, auth.clone())
        .execute(&auth, &mut stx)
        .expect("grant contract lifecycle authority");
    // Set cap to a tiny value (8 bytes) via custom parameter
    let id = CustomParameterId("max_contract_code_bytes".parse().unwrap());
    let cap = CustomParameter::new(id, iroha_primitives::json::Json::new(8u64));
    SetParameter::new(Parameter::Custom(cap))
        .execute(&auth, &mut stx)
        .expect("set cap");
    // Prepare a minimal IVM program which should exceed 8 bytes overall
    let prog = minimal_ivm_program(1);
    let code_hash = ivm::contract_code_hash(&prog);
    // Register should fail due to cap
    let err = RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: prog,
    }
    .execute(&auth, &mut stx)
    .unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("code bytes exceed cap"));
}
/// The default cap (the committed parameter absent) is 16 MiB and inclusive: an artifact
/// of exactly the default passes the size check and fails later as no contract artifact,
/// and one byte more is refused for its size. The portable ceiling of the cap parameter is
/// inclusive as well: exactly 2,147,483,647 is accepted and one more is refused.
#[test]
fn contract_code_caps_admit_exactly_the_limit_and_reject_one_byte_over() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{
        isi::smart_contract_code::RegisterSmartContractBytes,
        parameter::custom::{CustomParameter, CustomParameterId},
        prelude::*,
    };
    const DEFAULT_CAP: usize = 16 * 1024 * 1024;
    const PORTABLE_CAP: u64 = 2_147_483_647;
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.clone().into_parts();
    let dom: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let auth = AccountId::of(pubkey);
    let domain = Domain::new(dom.clone()).build(&auth);
    let account = Account::new(auth.clone()).build(&auth);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, auth.clone())
        .execute(&auth, &mut stx)
        .expect("grant contract lifecycle authority");
    let register = |code: Vec<u8>, stx: &mut iroha_core::state::StateTransaction<'_, '_>| {
        RegisterSmartContractBytes {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                ivm::contract_code_hash(&code),
            ),
            code,
        }
        .execute(&auth, stx)
        .map_err(|error| format!("{error}"))
    };
    // The default applies: no custom cap is committed.
    let at_default = register(vec![0xA5; DEFAULT_CAP], &mut stx)
        .expect_err("the filler bytes are no contract artifact");
    assert!(
        !at_default.contains("code bytes exceed cap"),
        "an artifact of exactly the default cap passes the size check: {at_default}"
    );
    let over_default =
        register(vec![0xA5; DEFAULT_CAP + 1], &mut stx).expect_err("one byte over the default cap");
    assert!(
        over_default.contains("code bytes exceed cap: 16777217 > 16777216"),
        "{over_default}"
    );
    // A committed cap is inclusive in the same comparison: exactly the cap is registered.
    let program = minimal_ivm_program(1);
    let set_cap = |value: u64, stx: &mut iroha_core::state::StateTransaction<'_, '_>| {
        let id = CustomParameterId("max_contract_code_bytes".parse().unwrap());
        SetParameter::new(Parameter::Custom(CustomParameter::new(
            id,
            iroha_primitives::json::Json::new(value),
        )))
        .execute(&auth, stx)
    };
    let exact = u64::try_from(program.len()).expect("program length fits u64");
    set_cap(exact - 1, &mut stx).expect("lower the cap below the program");
    let over_cap =
        register(program.clone(), &mut stx).expect_err("one byte over the committed cap");
    assert!(
        over_cap.contains(&format!("code bytes exceed cap: {exact} > {}", exact - 1)),
        "{over_cap}"
    );
    set_cap(exact, &mut stx).expect("set the cap to the program length");
    register(program, &mut stx).expect("a program of exactly the committed cap is registered");
    // The portable ceiling of the cap itself.
    set_cap(PORTABLE_CAP, &mut stx).expect("a cap of exactly the portable ceiling is accepted");
    let over_portable =
        set_cap(PORTABLE_CAP + 1, &mut stx).expect_err("one above the portable ceiling");
    assert_smart_contract_error(
        &over_portable,
        "max_contract_code_bytes exceeds the portable consensus limit: 2147483648 > 2147483647",
    );
}
#[test]
fn native_contract_upload_accepts_out_of_order_chunks_and_cleans_up_on_finalize() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{
        events::{EventBox, data::DataEvent, data::smart_contract::SmartContractEvent},
        isi::smart_contract_code::{
            FinalizeSmartContractCodeUpload, SMART_CONTRACT_CODE_CHUNK_BYTES,
            UploadSmartContractCodeChunk,
        },
        prelude::*,
    };
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.into_parts();
    let auth = AccountId::of(pubkey);
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let world = World::with(
        [Domain::new(domain_id).build(&auth)],
        [Account::new(auth.clone()).build(&auth)],
        std::iter::empty::<AssetDefinition>(),
    );
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, auth.clone())
        .execute(&auth, &mut stx)
        .expect("grant contract lifecycle authority");
    stx.world.take_external_events();
    let program = multi_chunk_ivm_program();
    let code_hash = ivm::contract_code_hash(&program);
    let chunks = program
        .chunks(SMART_CONTRACT_CODE_CHUNK_BYTES)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let total_size = u64::try_from(program.len()).expect("program length fits u64");
    let chunk_count = u32::try_from(chunks.len()).expect("chunk count fits u32");
    assert!(chunk_count > 2, "fixture must exercise multiple chunks");
    let last_index = chunk_count - 1;
    let last_chunk = chunks[usize::try_from(last_index).unwrap()].clone();
    let upload_last = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_index: last_index,
        chunk_count,
        chunk: last_chunk.clone(),
    };
    upload_last
        .clone()
        .execute(&auth, &mut stx)
        .expect("out-of-order last chunk");
    upload_last
        .execute(&auth, &mut stx)
        .expect("identical duplicate is idempotent");
    let mut conflicting = last_chunk;
    conflicting[0] ^= 0x80;
    let conflict = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_index: last_index,
        chunk_count,
        chunk: conflicting,
    }
    .execute(&auth, &mut stx)
    .expect_err("conflicting duplicate must fail");
    assert!(format!("{conflict}").contains("conflicting duplicate"));
    let missing = FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_count,
    }
    .execute(&auth, &mut stx)
    .expect_err("missing chunks must retain staging");
    assert_smart_contract_error(
        &missing,
        &format!("contract upload is missing chunk 0 of {chunk_count}"),
    );
    let progress = stx
        .world()
        .contract_code_upload_progress(
            &auth,
            &iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash,
            ),
        )
        .expect("failed finalization retains progress");
    assert_eq!(progress.received_chunks, 1);
    for (chunk_index, chunk) in chunks.iter().enumerate().rev().skip(1) {
        UploadSmartContractCodeChunk {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash,
            ),
            total_size,
            chunk_index: u32::try_from(chunk_index).unwrap(),
            chunk_count,
            chunk: chunk.clone(),
        }
        .execute(&auth, &mut stx)
        .expect("upload remaining chunk");
    }
    FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_count,
    }
    .execute(&auth, &mut stx)
    .expect("finalize complete upload");
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| {
        matches!(
            event,
            EventBox::Data(data)
                if matches!(
                    data.as_ref(),
                    DataEvent::SmartContract(SmartContractEvent::CodeRegistered(registered))
                        if registered.artifact_id.code_hash == code_hash && registered.registrar == auth
                )
        )
    }));
    stx.apply();
    assert_eq!(
        block
            .world
            .contract_code()
            .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash
            ))
            .map(Vec::as_slice),
        Some(program.as_slice())
    );
    assert!(
        block
            .world
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_none(),
        "successful finalization must remove descriptor and chunks"
    );
}
#[test]
fn native_contract_upload_enforces_shape_quota_and_owner_cancellation() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{
        isi::smart_contract_code::{CancelSmartContractCodeUpload, UploadSmartContractCodeChunk},
        parameter::custom::{CustomParameter, CustomParameterId},
        prelude::*,
    };
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.into_parts();
    let auth = AccountId::of(pubkey);
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let world = World::with(
        [Domain::new(domain_id).build(&auth)],
        [Account::new(auth.clone()).build(&auth)],
        std::iter::empty::<AssetDefinition>(),
    );
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, auth.clone())
        .execute(&auth, &mut stx)
        .expect("grant contract lifecycle authority");
    let cap_id = CustomParameterId("max_contract_code_bytes".parse().unwrap());
    SetParameter::new(Parameter::Custom(CustomParameter::new(
        cap_id,
        iroha_primitives::json::Json::new(100u64),
    )))
    .execute(&auth, &mut stx)
    .expect("set code cap");
    let first_hash = iroha_crypto::Hash::new(b"quota-first");
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            first_hash,
        ),
        total_size: 60,
        chunk_index: 0,
        chunk_count: 1,
        chunk: vec![1; 60],
    }
    .execute(&auth, &mut stx)
    .expect("first pending upload");
    let descriptor_error = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            first_hash,
        ),
        total_size: 61,
        chunk_index: 0,
        chunk_count: 1,
        chunk: vec![1; 61],
    }
    .execute(&auth, &mut stx)
    .expect_err("descriptor changes must fail");
    assert!(format!("{descriptor_error}").contains("descriptor cannot change"));
    let count_shape_error = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            iroha_crypto::Hash::new(b"wrong-chunk-count"),
        ),
        total_size: 60,
        chunk_index: 0,
        chunk_count: 2,
        chunk: vec![3; 60],
    }
    .execute(&auth, &mut stx)
    .expect_err("non-canonical chunk count must fail");
    assert_smart_contract_error(
        &count_shape_error,
        "contract upload chunk_count mismatch: expected 1, got 2",
    );
    let zero_size_error = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            iroha_crypto::Hash::new(b"zero-sized-upload"),
        ),
        total_size: 0,
        chunk_index: 0,
        chunk_count: 0,
        chunk: Vec::new(),
    }
    .execute(&auth, &mut stx)
    .expect_err("zero-sized descriptors must fail before staging");
    assert_smart_contract_error(
        &zero_size_error,
        "contract upload total_size must be non-zero",
    );
    let portable_size_error = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            iroha_crypto::Hash::new(b"non-portable-upload"),
        ),
        total_size: 2_147_483_648,
        chunk_index: 0,
        chunk_count: u32::MAX,
        chunk: Vec::new(),
    }
    .execute(&auth, &mut stx)
    .expect_err("non-portable descriptors must fail deterministically");
    assert!(format!("{portable_size_error}").contains("portable consensus limit"));
    let index_shape_error = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            iroha_crypto::Hash::new(b"wrong-chunk-index"),
        ),
        total_size: 1,
        chunk_index: 1,
        chunk_count: 1,
        chunk: vec![3],
    }
    .execute(&auth, &mut stx)
    .expect_err("out-of-range chunk index must fail");
    assert_smart_contract_error(
        &index_shape_error,
        "contract upload chunk_index 1 is outside chunk_count 1",
    );
    let aggregate_error = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            iroha_crypto::Hash::new(b"quota-second"),
        ),
        total_size: 41,
        chunk_index: 0,
        chunk_count: 1,
        chunk: vec![2; 41],
    }
    .execute(&auth, &mut stx)
    .expect_err("aggregate declarations above cap must fail");
    assert!(format!("{aggregate_error}").contains("declared bytes exceed authority cap"));
    let malformed = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            iroha_crypto::Hash::new(b"malformed-shape"),
        ),
        total_size: 2,
        chunk_index: 0,
        chunk_count: 1,
        chunk: vec![0],
    }
    .execute(&auth, &mut stx)
    .expect_err("short chunk must fail");
    assert_smart_contract_error(
        &malformed,
        "contract upload chunk 0 length mismatch: expected 2, got 1",
    );
    let other = AccountId::new(checked_random_contract_code_keypair().public_key().clone());
    CancelSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            first_hash,
        ),
    }
    .execute(&other, &mut stx)
    .expect("another owner cancellation is an idempotent no-op");
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    first_hash
                )
            )
            .is_some(),
        "owner-scoped cancellation must not remove another authority's upload"
    );
    CancelSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            first_hash,
        ),
    }
    .execute(&auth, &mut stx)
    .expect("owner cancellation");
    CancelSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            first_hash,
        ),
    }
    .execute(&auth, &mut stx)
    .expect("owner cancellation is idempotent");
    for index in 0u8..4 {
        UploadSmartContractCodeChunk {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                iroha_crypto::Hash::new([index]),
            ),
            total_size: 1,
            chunk_index: 0,
            chunk_count: 1,
            chunk: vec![index],
        }
        .execute(&auth, &mut stx)
        .expect("pending upload within count quota");
    }
    let count_error = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            iroha_crypto::Hash::new(b"fifth-pending-upload"),
        ),
        total_size: 1,
        chunk_index: 0,
        chunk_count: 1,
        chunk: vec![5],
    }
    .execute(&auth, &mut stx)
    .expect_err("fifth pending upload must fail");
    assert!(format!("{count_error}").contains("at most 4 pending"));
}
#[test]
fn native_contract_upload_allows_registered_owner_without_code_management_permission() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{
        isi::smart_contract_code::{
            CancelSmartContractCodeUpload, FinalizeSmartContractCodeUpload,
            UploadSmartContractCodeChunk,
        },
        prelude::*,
    };
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.into_parts();
    let auth = AccountId::of(pubkey);
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let world = World::with(
        [Domain::new(domain_id).build(&auth)],
        [Account::new(auth.clone()).build(&auth)],
        std::iter::empty::<AssetDefinition>(),
    );
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let code = minimal_ivm_program(1);
    let code_hash = ivm::contract_code_hash(&code);
    let code_size = u64::try_from(code.len()).expect("test artifact size fits u64");
    let upload = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size: code_size,
        chunk_index: 0,
        chunk_count: 1,
        chunk: code.clone(),
    };
    let unregistered = AccountId::of(checked_random_contract_code_keypair().public_key().clone());
    let upload_error = upload
        .clone()
        .execute(&unregistered, &mut stx)
        .expect_err("an unregistered account cannot stage an upload");
    assert!(matches!(
        upload_error,
        InstructionExecutionError::Find(iroha_data_model::query::error::FindError::Account(
            missing
        )) if missing == unregistered
    ));
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &unregistered,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_none(),
        "rejected upload must not create staging"
    );
    upload
        .execute(&auth, &mut stx)
        .expect("registered account stages code without management permission");
    let finalize_error = FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size: code_size,
        chunk_count: 1,
    }
    .execute(&unregistered, &mut stx)
    .expect_err("an unregistered account cannot finalize another account's upload");
    assert!(matches!(
        finalize_error,
        InstructionExecutionError::Find(iroha_data_model::query::error::FindError::Account(
            missing
        )) if missing == unregistered
    ));
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_some(),
        "rejected finalization must retain the owner's staging"
    );
    FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size: code_size,
        chunk_count: 1,
    }
    .execute(&auth, &mut stx)
    .expect("registered owner finalizes a verified artifact without management permission");
    assert_eq!(
        stx.world()
            .contract_code()
            .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash
            ))
            .map(Vec::as_slice),
        Some(code.as_slice())
    );
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_none(),
        "successful finalization clears staging"
    );
    let pending_hash = iroha_crypto::Hash::new(b"owner-cleanup-upload");
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            pending_hash,
        ),
        total_size: 1,
        chunk_index: 0,
        chunk_count: 1,
        chunk: vec![0],
    }
    .execute(&auth, &mut stx)
    .expect("registered owner stages a second upload");
    CancelSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            pending_hash,
        ),
    }
    .execute(&auth, &mut stx)
    .expect("owner cleanup does not require management permission");
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    pending_hash
                )
            )
            .is_none()
    );
}
#[test]
fn native_finalize_cleans_staging_when_atomic_registration_wins_the_race() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{
        events::{EventBox, data::DataEvent, data::smart_contract::SmartContractEvent},
        isi::smart_contract_code::{
            CancelSmartContractCodeUpload, FinalizeSmartContractCodeUpload,
            RegisterSmartContractBytes, SMART_CONTRACT_CODE_CHUNK_BYTES,
            UploadSmartContractCodeChunk,
        },
        prelude::*,
    };
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.into_parts();
    let auth = AccountId::of(pubkey);
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let world = World::with(
        [Domain::new(domain_id).build(&auth)],
        [Account::new(auth.clone()).build(&auth)],
        std::iter::empty::<AssetDefinition>(),
    );
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, auth.clone())
        .execute(&auth, &mut stx)
        .expect("grant contract lifecycle authority");
    stx.world.take_external_events();
    let program = multi_chunk_ivm_program();
    let code_hash = ivm::contract_code_hash(&program);
    let chunks = program
        .chunks(SMART_CONTRACT_CODE_CHUNK_BYTES)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let total_size = u64::try_from(program.len()).unwrap();
    let chunk_count = u32::try_from(chunks.len()).unwrap();
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_index: 0,
        chunk_count,
        chunk: chunks[0].clone(),
    }
    .execute(&auth, &mut stx)
    .expect("stage a chunk before atomic registration wins");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        code: program.clone(),
    }
    .execute(&auth, &mut stx)
    .expect("atomic registration wins before upload completion");
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| {
        matches!(
            event,
            EventBox::Data(data)
                if matches!(
                    data.as_ref(),
                    DataEvent::SmartContract(SmartContractEvent::CodeRegistered(registered))
                        if registered.artifact_id.code_hash == code_hash && registered.registrar == auth
                )
        )
    }));
    let mut conflicting_chunk = chunks[0].clone();
    conflicting_chunk[0] ^= 0x80;
    let conflicting_duplicate = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_index: 0,
        chunk_count,
        chunk: conflicting_chunk,
    }
    .execute(&auth, &mut stx)
    .expect_err("registered code must not mask a conflicting staged duplicate");
    assert!(format!("{conflicting_duplicate}").contains("conflicting duplicate"));
    for chunk_index in 1..chunk_count {
        UploadSmartContractCodeChunk {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash,
            ),
            total_size,
            chunk_index,
            chunk_count,
            chunk: chunks[usize::try_from(chunk_index).unwrap()].clone(),
        }
        .execute(&auth, &mut stx)
        .expect("registered code keeps completing its existing staging descriptor");
    }
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_some(),
        "the prior descriptor models the registration/upload race"
    );
    FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_count,
    }
    .execute(&auth, &mut stx)
    .expect("finalization recognizes registered matching code and clears old staging");
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_none()
    );
    FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size,
        chunk_count,
    }
    .execute(&auth, &mut stx)
    .expect("finalization of already registered code remains idempotent");
    let mut corrupted_program = minimal_ivm_program(1);
    corrupted_program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    ivm::verify_contract_artifact(&corrupted_program).expect("valid second race artifact");
    let corrupted_hash = ivm::contract_code_hash(&corrupted_program);
    let corrupted_size = u64::try_from(corrupted_program.len()).unwrap();
    let mut staged_corruption = corrupted_program.clone();
    staged_corruption[0] ^= 0x80;
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            corrupted_hash,
        ),
        total_size: corrupted_size,
        chunk_index: 0,
        chunk_count: 1,
        chunk: staged_corruption,
    }
    .execute(&auth, &mut stx)
    .expect("stage corruption before direct registration");
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            corrupted_hash,
        ),
        code: corrupted_program.clone(),
    }
    .execute(&auth, &mut stx)
    .expect("direct registration wins the corrupt staging race");
    let conflicting_duplicate = UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            corrupted_hash,
        ),
        total_size: corrupted_size,
        chunk_index: 0,
        chunk_count: 1,
        chunk: corrupted_program,
    }
    .execute(&auth, &mut stx)
    .expect_err("matching registered code cannot overwrite a conflicting staged chunk");
    assert!(format!("{conflicting_duplicate}").contains("conflicting duplicate"));
    FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            corrupted_hash,
        ),
        total_size: corrupted_size,
        chunk_count: 1,
    }
    .execute(&auth, &mut stx)
    .expect_err("finalization must verify staged bytes even after direct registration");
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    corrupted_hash
                )
            )
            .is_some(),
        "failed race finalization retains corrupt staging for explicit cleanup"
    );
    CancelSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            corrupted_hash,
        ),
    }
    .execute(&auth, &mut stx)
    .expect("owner cancels corrupt race staging");
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    corrupted_hash
                )
            )
            .is_none()
    );
}
#[test]
fn failed_native_finalization_and_rejected_cap_updates_retain_staging() {
    use iroha_core::smartcontracts::Execute;
    use iroha_data_model::{
        isi::smart_contract_code::{FinalizeSmartContractCodeUpload, UploadSmartContractCodeChunk},
        parameter::custom::{CustomParameter, CustomParameterId},
        prelude::*,
    };
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let kp = checked_random_contract_code_keypair();
    let (pubkey, _) = kp.into_parts();
    let auth = AccountId::of(pubkey);
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let world = World::with(
        [Domain::new(domain_id).build(&auth)],
        [Account::new(auth.clone()).build(&auth)],
        std::iter::empty::<AssetDefinition>(),
    );
    let state = State::new_for_testing(world, kura, query);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, auth.clone())
        .execute(&auth, &mut stx)
        .expect("grant contract lifecycle authority");
    let malformed = vec![0xFF; 32];
    let malformed_hash = iroha_crypto::Hash::new(b"declared malformed artifact hash");
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            malformed_hash,
        ),
        total_size: u64::try_from(malformed.len()).unwrap(),
        chunk_index: 0,
        chunk_count: 1,
        chunk: malformed.clone(),
    }
    .execute(&auth, &mut stx)
    .expect("stage malformed artifact");
    FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            malformed_hash,
        ),
        total_size: u64::try_from(malformed.len()).unwrap(),
        chunk_count: 1,
    }
    .execute(&auth, &mut stx)
    .expect_err("malformed artifact must fail finalization");
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    malformed_hash
                )
            )
            .is_some()
    );
    let program = minimal_ivm_program(1);
    let wrong_hash = iroha_crypto::Hash::new(b"wrong complete artifact hash");
    let program_size = u64::try_from(program.len()).unwrap();
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            wrong_hash,
        ),
        total_size: program_size,
        chunk_index: 0,
        chunk_count: 1,
        chunk: program.clone(),
    }
    .execute(&auth, &mut stx)
    .expect("stage valid artifact under wrong hash");
    let wrong_hash_error = FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            wrong_hash,
        ),
        total_size: program_size,
        chunk_count: 1,
    }
    .execute(&auth, &mut stx)
    .expect_err("wrong hash must fail finalization");
    assert!(format!("{wrong_hash_error}").contains("code_hash"));
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    wrong_hash
                )
            )
            .is_some()
    );
    let correct_hash = ivm::contract_code_hash(&program);
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            correct_hash,
        ),
        total_size: program_size,
        chunk_index: 0,
        chunk_count: 1,
        chunk: program,
    }
    .execute(&auth, &mut stx)
    .expect("stage artifact before cap reduction");
    let invalid_cap_error = SetParameter::new(Parameter::Custom(CustomParameter::new(
        CustomParameterId("max_contract_code_bytes".parse().unwrap()),
        iroha_primitives::json::Json::new("not-a-u64"),
    )))
    .execute(&auth, &mut stx)
    .expect_err("contract code cap must decode as u64");
    assert_smart_contract_error(
        &invalid_cap_error,
        "max_contract_code_bytes must be a Norito u64",
    );
    let portable_cap_error = SetParameter::new(Parameter::Custom(CustomParameter::new(
        CustomParameterId("max_contract_code_bytes".parse().unwrap()),
        iroha_primitives::json::Json::new(u64::from(i32::MAX as u32) + 1),
    )))
    .execute(&auth, &mut stx)
    .expect_err("contract code cap must be portable across pointer widths");
    assert_smart_contract_error(
        &portable_cap_error,
        "max_contract_code_bytes exceeds the portable consensus limit: 2147483648 > 2147483647",
    );
    let cap_id = CustomParameterId("max_contract_code_bytes".parse().unwrap());
    let cap_error = SetParameter::new(Parameter::Custom(CustomParameter::new(
        cap_id,
        iroha_primitives::json::Json::new(program_size - 1),
    )))
    .execute(&auth, &mut stx)
    .expect_err("cap reduction below pending declarations must fail");
    assert!(format!("{cap_error}").contains("below pending declared bytes"));
    assert!(
        stx.world()
            .contract_code_upload_progress(
                &auth,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    correct_hash
                )
            )
            .is_some()
    );
}
