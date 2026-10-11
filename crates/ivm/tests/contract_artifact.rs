//! Admission coverage for authenticated V1 contract metadata and callable-table rules.
use iroha_data_model::{
    smart_contract::entrypoint::{
        EntrypointArgumentFieldV1, EntrypointArgumentSchemaV1, EntrypointListTypeNodeV1,
        EntrypointStructTypeNodeV1, EntrypointValueKindV1, EntrypointValueTypeNodeV1,
        EntrypointValueTypeV1,
    },
    smart_contract::manifest::{
        AccessSetHints, ContractErrorTypeDescriptor, DynamicAccessHint, EntryPointKind,
        EntrypointParamDescriptor, TriggerCallback, TriggerDescriptor,
    },
    trigger::{TriggerId, action::Repeats},
};
mod common;
fn time_trigger(id: &str, namespace: Option<&str>, entrypoint: &str) -> TriggerDescriptor {
    TriggerDescriptor {
        id: TriggerId::new(id.parse().expect("trigger id")),
        repeats: Repeats::Indefinitely,
        filter: iroha_data_model::events::EventFilterBox::Time(
            iroha_data_model::events::time::TimeEventFilter(
                iroha_data_model::events::time::ExecutionTime::PreCommit,
            ),
        ),
        authority: None,
        metadata: iroha_model_base::metadata::Metadata::default(),
        callback: TriggerCallback {
            namespace: namespace.map(str::to_owned),
            entrypoint: entrypoint.to_owned(),
        },
    }
}
fn entrypoint(
    name: &str,
    kind: EntryPointKind,
    entry_pc: u64,
) -> ivm::EmbeddedEntrypointDescriptor {
    ivm::EmbeddedEntrypointDescriptor {
        name: name.to_owned(),
        kind,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
            nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
        }),
        permission: (kind == EntryPointKind::Kotoage).then(|| "Execute".to_owned()),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: Some(true),
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
        entry_pc,
    }
}
fn contract_artifact(
    abi_version: u8,
    entrypoints: Vec<ivm::EmbeddedEntrypointDescriptor>,
) -> Vec<u8> {
    contract_artifact_with_access_hints(abi_version, entrypoints, None)
}
fn contract_artifact_with_access_hints(
    abi_version: u8,
    entrypoints: Vec<ivm::EmbeddedEntrypointDescriptor>,
    access_set_hints: Option<AccessSetHints>,
) -> Vec<u8> {
    contract_artifact_with_code(
        abi_version,
        entrypoints,
        access_set_hints,
        &common::unit_return_words(),
    )
}
fn contract_artifact_with_code(
    abi_version: u8,
    entrypoints: Vec<ivm::EmbeddedEntrypointDescriptor>,
    access_set_hints: Option<AccessSetHints>,
    code: &[u32],
) -> Vec<u8> {
    contract_artifact_with_mode_and_code(abi_version, 0, 0, entrypoints, access_set_hints, code)
}
fn callable_frame_bytes(code: &[u32], entry_pc: u64) -> u32 {
    use ivm::instruction::wide;
    match code.get(entry_pc as usize / 4).copied() {
        Some(word)
            if wide::opcode(word) == wide::arithmetic::ADDI
                && wide::rd(word) == 31
                && wide::rs1(word) == 31
                && wide::imm8(word) < 0 =>
        {
            u32::from(wide::imm8(word).unsigned_abs())
        }
        _ => 0,
    }
}
// A real caller frame: saved return address/result base plus disjoint child result scratch.
fn unit_caller_with_helper(long_call: bool, helper_body: &[u32]) -> Vec<u32> {
    use ivm::{encoding::wide as enc, instruction::wide};
    let mut code = vec![
        enc::encode_ri(wide::arithmetic::ADDI, 31, 31, -32),
        enc::encode_store(wide::memory::STORE64, 31, 1, 0),
        enc::encode_store(wide::memory::STORE64, 31, 12, 8),
        enc::encode_ri(wide::arithmetic::ADDI, 10, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 12, 31, 16),
        enc::encode_ri(wide::arithmetic::ADDI, 13, 0, 1),
        if long_call {
            enc::encode_offset24(wide::control::JALS, 8)
        } else {
            enc::encode_jump(wide::control::JAL, 1, 8)
        },
        enc::encode_load(wide::memory::LOAD64, 12, 31, 8),
        enc::encode_store(wide::memory::STORE64, 12, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
        enc::encode_load(wide::memory::LOAD64, 1, 31, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 31, 31, 32),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
    ];
    code.extend_from_slice(helper_body);
    code.extend_from_slice(&common::unit_return_words());
    code
}
fn callable_descriptors(
    entrypoints: &[ivm::EmbeddedEntrypointDescriptor],
    code: &[u32],
) -> Vec<ivm_abi::call::EmbeddedCallableV1> {
    use ivm::instruction::wide;
    use ivm_abi::call::CallSchemaV1;
    let mut callables = std::collections::BTreeMap::new();
    for entry in entrypoints {
        callables.insert(
            entry.entry_pc,
            ivm_abi::call::EmbeddedCallableV1 {
                entry_pc: entry.entry_pc,
                frame_bytes: callable_frame_bytes(code, entry.entry_pc),
                // Malformed public schemas intentionally retain a well-formed callable
                // so admission tests reach the public-schema rejection itself.
                arguments: entry
                    .argument_schema
                    .as_ref()
                    .and_then(CallSchemaV1::from_entrypoint_arguments)
                    .unwrap_or_else(CallSchemaV1::empty),
                results: entry
                    .return_schema
                    .as_ref()
                    .and_then(CallSchemaV1::from_entrypoint_type)
                    .unwrap_or_else(CallSchemaV1::unit),
            },
        );
    }
    for (index, word) in code.iter().copied().enumerate() {
        let offset = match wide::opcode(word) {
            wide::control::JALS => i64::from(wide::imm24(word)),
            wide::control::JAL if wide::rd(word) == 1 => i64::from(wide::imm16(word)),
            _ => continue,
        };
        if let Some(target) = (index as u64 * 4).checked_add_signed(offset * 4) {
            callables.entry(target).or_insert_with(|| {
                let mut callable = common::unit_callable(target);
                callable.frame_bytes = callable_frame_bytes(code, target);
                callable
            });
        }
    }
    callables.into_values().collect()
}
fn contract_artifact_with_mode_and_code(
    abi_version: u8,
    mode: u8,
    features_bitmap: u64,
    entrypoints: Vec<ivm::EmbeddedEntrypointDescriptor>,
    access_set_hints: Option<AccessSetHints>,
    code: &[u32],
) -> Vec<u8> {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode,
        vector_length: 0,
        max_cycles: 0,
        abi_version,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: callable_descriptors(&entrypoints, code),
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "ivm-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap,
        access_set_hints,
        kotoba: Vec::new(),
        entrypoints,
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut bytes = meta.encode();
    bytes.extend_from_slice(&interface.encode_section());
    for instruction in code {
        bytes.extend_from_slice(&instruction.to_le_bytes());
    }
    bytes
}
fn contract_artifact_with_error_types(error_types: Vec<ContractErrorTypeDescriptor>) -> Vec<u8> {
    contract_artifact_with_error_messages(error_types, Vec::new())
}
fn contract_artifact_with_error_messages(
    error_types: Vec<ContractErrorTypeDescriptor>,
    error_messages: Vec<iroha_data_model::smart_contract::manifest::ContractErrorMessage>,
) -> Vec<u8> {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: vec![common::unit_callable(0)],
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "ivm-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        error_messages,
        error_types,
        states: Vec::new(),
    };
    let mut bytes = meta.encode();
    bytes.extend_from_slice(&interface.encode_section());
    for word in common::unit_return_words() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn contract_artifact_with_states(states: Vec<ivm::EmbeddedStateDescriptor>) -> Vec<u8> {
    contract_artifact_with_access_hints_and_states(None, states)
}
fn contract_artifact_with_access_hints_and_states(
    access_set_hints: Option<AccessSetHints>,
    states: Vec<ivm::EmbeddedStateDescriptor>,
) -> Vec<u8> {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: vec![common::unit_callable(0)],
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "ivm-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints,
        kotoba: Vec::new(),
        entrypoints: vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states,
    };
    let mut bytes = meta.encode();
    bytes.extend_from_slice(&interface.encode_section());
    for word in common::unit_return_words() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn contract_artifact_with_seiyaku_name(seiyaku_name: &str) -> Vec<u8> {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: vec![common::unit_callable(0)],
        seiyaku_name: seiyaku_name.to_owned(),
        compiler_fingerprint: "ivm-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![entrypoint("run", EntryPointKind::Kotoage, 0)],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut bytes = meta.encode();
    bytes.extend_from_slice(&interface.encode_section());
    for word in common::unit_return_words() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn contract_artifact_with_execution_features(mode: u8, features_bitmap: u64) -> Vec<u8> {
    let metadata = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: vec![common::unit_callable(0)],
        seiyaku_name: "FeatureBinding".to_owned(),
        compiler_fingerprint: "ivm-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![entrypoint("inspect", EntryPointKind::View, 0)],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut bytes = metadata.encode();
    bytes.extend_from_slice(&interface.encode_section());
    for word in common::unit_return_words() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn value_type(kind: EntrypointValueKindV1) -> EntrypointValueTypeV1 {
    EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
    }
}
#[test]
fn verifier_rejects_stale_embedded_abi_hash_before_execution() {
    let artifact = contract_artifact(1, vec![entrypoint("inspect", EntryPointKind::View, 0)]);
    let parsed = ivm::ProgramMetadata::parse(&artifact).expect("parse valid contract artifact");
    let mut interface = parsed
        .contract_interface
        .expect("contract fixture carries CNTR");
    interface.abi_hash[0] ^= 0x80;
    let mut stale = parsed.metadata.encode();
    stale.extend_from_slice(&interface.encode_section());
    stale.extend_from_slice(
        artifact
            .get(parsed.code_offset..)
            .expect("parsed code offset is in bounds"),
    );
    let error = ivm::verify_contract_artifact(&stale)
        .expect_err("stale embedded ABI binding must fail closed");
    assert!(
        error
            .to_string()
            .contains("contract interface abi_hash does not match the runtime ABI descriptor"),
        "unexpected stale-ABI error: {error}"
    );
}
#[test]
fn verifier_rejects_mismatched_or_oversized_exact_boundary_schemas() {
    let mut argument_mismatch = entrypoint("inspect", EntryPointKind::View, 0);
    argument_mismatch.params = vec![EntrypointParamDescriptor {
        name: "value".to_owned(),
        type_name: "int".to_owned(),
    }];
    argument_mismatch.argument_schema = Some(EntrypointArgumentSchemaV1 {
        fields: vec![EntrypointArgumentFieldV1 {
            name: "value".to_owned(),
            ty: value_type(EntrypointValueKindV1::Bool),
        }],
    });
    let argument_code = [
        ivm::encoding::wide::encode_syscallx(ivm::syscalls::SYSCALL_DECODE_ARGUMENT_RECORD),
        ivm::encoding::wide::encode_halt(),
    ];
    let artifact = contract_artifact_with_code(1, vec![argument_mismatch], None, &argument_code);
    let error = ivm::verify_contract_artifact(&artifact)
        .expect_err("argument schema/type mismatch must fail");
    assert!(error.to_string().contains("invalid argument schema"));
    let mut return_mismatch = entrypoint("inspect", EntryPointKind::View, 0);
    return_mismatch.return_type = Some("int".to_owned());
    return_mismatch.return_schema = Some(value_type(EntrypointValueKindV1::Bool));
    let artifact = contract_artifact(1, vec![return_mismatch]);
    let error = ivm::verify_contract_artifact(&artifact)
        .expect_err("return schema/type mismatch must fail");
    assert!(error.to_string().contains("return schema"), "{error}");
    let mut oversized = entrypoint("inspect", EntryPointKind::View, 0);
    oversized.return_type = Some(format!("({})", vec!["int"; 256].join(", ")));
    oversized.return_schema = Some(EntrypointValueTypeV1 {
        nodes: std::iter::once(EntrypointValueTypeNodeV1::Tuple(256))
            .chain(std::iter::repeat_n(
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                256,
            ))
            .collect(),
    });
    let artifact = contract_artifact(1, vec![oversized]);
    assert!(matches!(
        ivm::ProgramMetadata::parse(&artifact),
        Err(ivm::VMError::InvalidMetadata)
    ));
    let error = ivm::verify_contract_artifact(&artifact)
        .expect_err("return schema beyond the 256-node boundary must fail closed");
    assert!(
        error.to_string().contains("metadata parse failed"),
        "{error}"
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn verifier_rejects_forged_reserved_query_page_schemas() {
    fn account_page_schema() -> EntrypointValueTypeV1 {
        EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "QueryPage".to_owned(),
                    fields: vec!["items".to_owned(), "next_offset".to_owned()],
                }),
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 64 }),
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "AccountView".to_owned(),
                    fields: vec!["id".to_owned(), "metadata".to_owned()],
                }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::AccountId),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Json),
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            ],
        }
    }
    let valid = account_page_schema();
    let singular = EntrypointValueTypeV1 {
        nodes: std::iter::once(EntrypointValueTypeNodeV1::Option)
            .chain(
                valid
                    .subtree_nodes(2)
                    .expect("page fixture has a valid AccountView subtree")
                    .iter()
                    .cloned(),
            )
            .collect(),
    };
    let mut singular_descriptor = entrypoint("account", EntryPointKind::View, 0);
    singular_descriptor.return_type = Some("Option<AccountView>".to_owned());
    singular_descriptor.return_schema = Some(singular);
    ivm::verify_contract_artifact(&contract_artifact(1, vec![singular_descriptor]))
        .expect("exact reserved singular projection schema must be admitted");
    let mut descriptor = entrypoint("inspect", EntryPointKind::View, 0);
    descriptor.return_type = Some("QueryPage<AccountView>".to_owned());
    descriptor.return_schema = Some(valid.clone());
    ivm::verify_contract_artifact(&contract_artifact(1, vec![descriptor]))
        .expect("exact reserved QueryPage schema must be admitted");
    let assert_rejected = |label: &str, schema: EntrypointValueTypeV1, return_type: &str| {
        let mut descriptor = entrypoint("inspect", EntryPointKind::View, 0);
        descriptor.return_type = Some(return_type.to_owned());
        descriptor.return_schema = Some(schema);
        let error = match ivm::verify_contract_artifact(&contract_artifact(1, vec![descriptor])) {
            Ok(_) => panic!("{label} must fail artifact admission"),
            Err(error) => error,
        };
        assert!(
            error.to_string().starts_with("invalid contract artifact:"),
            "{label}: {error}"
        );
    };
    let mut unknown_view = valid.clone();
    let EntrypointValueTypeNodeV1::Struct(view) = &mut unknown_view.nodes[2] else {
        unreachable!("page fixture has a projected struct")
    };
    view.name = "UnknownView".to_owned();
    assert_rejected("unknown projection", unknown_view, "QueryPage<UnknownView>");
    let mut wrong_fields = valid.clone();
    let EntrypointValueTypeNodeV1::Struct(view) = &mut wrong_fields.nodes[2] else {
        unreachable!("page fixture has a projected struct")
    };
    view.fields[1] = "content".to_owned();
    assert_rejected(
        "reserved projection with wrong fields",
        wrong_fields,
        "QueryPage<AccountView>",
    );
    let mut wrong_kind = valid.clone();
    wrong_kind.nodes[3] = EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::DomainId);
    assert_rejected(
        "reserved projection with wrong leaf kind",
        wrong_kind,
        "QueryPage<AccountView>",
    );
    let mut wrong_capacity = valid.clone();
    let EntrypointValueTypeNodeV1::List(items) = &mut wrong_capacity.nodes[1] else {
        unreachable!("page fixture has an items list")
    };
    items.capacity = 32;
    assert_rejected(
        "wrong page capacity",
        wrong_capacity,
        "QueryPage<AccountView>",
    );
    let mut wrong_next_offset = valid;
    wrong_next_offset.nodes[6] = EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String);
    assert_rejected(
        "wrong next_offset type",
        wrong_next_offset,
        "QueryPage<AccountView>",
    );
}
#[test]
fn compiler_embeds_exact_nested_return_schema_in_cntr_and_manifest() {
    let source = r#"
        seiyaku ExactReturn {
            struct Pair { int count, bool ready }

            view fn inspect() -> Result<Option<Pair>, (string, bool)> {
                return Result::ok(Option::some(Pair { count: 7, ready: true }));
            }
        }
    "#;
    let (artifact, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(source)
        .expect("compile nested return schema");
    let parsed = ivm::ProgramMetadata::parse(&artifact).expect("parse compiled artifact");
    let embedded = parsed
        .contract_interface
        .as_ref()
        .and_then(|interface| interface.entrypoints.first())
        .expect("embedded entrypoint");
    let schema = embedded
        .return_schema
        .as_ref()
        .expect("exact return schema");
    assert_eq!(
        schema.nodes,
        vec![
            EntrypointValueTypeNodeV1::Result,
            EntrypointValueTypeNodeV1::Option,
            EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                name: "Pair".to_owned(),
                fields: vec!["count".to_owned(), "ready".to_owned()],
            }),
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            EntrypointValueTypeNodeV1::Tuple(2),
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
        ],
    );
    assert_eq!(
        schema.word_count(),
        Some(1),
        "nested active-only Option/Result values cross the public register boundary as one typed handle"
    );
    assert_eq!(
        manifest
            .entrypoints
            .as_ref()
            .and_then(|entrypoints| entrypoints.first())
            .and_then(|entrypoint| entrypoint.return_schema.as_ref()),
        Some(schema),
    );
    ivm::verify_contract_artifact(&artifact).expect("verify exact nested return artifact");
}
#[test]
fn verify_nominal_error_catalog_allows_local_codes_and_rejects_schema_ambiguity() {
    use iroha_data_model::smart_contract::manifest::ContractErrorVariantDescriptor;
    let descriptor = |identity: &str, name: &str, code: u32| ContractErrorTypeDescriptor {
        identity: identity.to_owned(),
        variants: vec![ContractErrorVariantDescriptor {
            name: name.to_owned(),
            code,
        }],
    };
    let first = descriptor("Payment::PaymentError", "Unauthorized", 1001);
    let second = descriptor("Settlement::SettlementError", "Expired", 1001);
    ivm::verify_contract_artifact(&contract_artifact_with_error_types(vec![
        first.clone(),
        second,
    ]))
    .expect("enum-local numeric codes may coincide across nominal types");
    let duplicate = contract_artifact_with_error_types(vec![first.clone(), first]);
    assert!(
        ivm::verify_contract_artifact(&duplicate).is_err(),
        "duplicate type identity"
    );
    for invalid in [
        descriptor("Payment::PaymentError", "Unspecified", 0),
        descriptor("Invalid Error", "Unauthorized", 1),
        descriptor("Injected<Error>", "Unauthorized", 1),
        descriptor("Payment::PaymentError", "not-valid", 1),
        descriptor("Payment::PaymentError", "for", 1),
    ] {
        assert!(
            ivm::verify_contract_artifact(&contract_artifact_with_error_types(vec![invalid]))
                .is_err()
        );
    }
}

#[test]
fn compiler_emits_self_describing_contract_artifact() {
    let src = r#"
        seiyaku Demo {
            state int counter;

            hajimari() {
                counter = 0;
            }

            kotoage fn run() authorize("Admin") {
                debug::info("ready");
            }
        }
    "#;
    let (bytes, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile contract");
    let parsed = ivm::ProgramMetadata::parse(&bytes).expect("parse artifact");
    assert_eq!(parsed.metadata.version_minor, 1);
    let interface = parsed
        .contract_interface
        .as_ref()
        .expect("compiler must emit CNTR");
    assert_eq!(interface.seiyaku_name, "Demo");
    assert_eq!(manifest.seiyaku_name.as_deref(), Some("Demo"));
    let verified = ivm::verify_contract_artifact(&bytes).expect("verify artifact");
    assert!(
        verified.manifest.same_signed_content(&manifest),
        "compiler manifest must match the embedded contract interface",
    );
}
#[test]
fn verifier_binds_feature_bitmap_to_execution_capabilities_not_host_hardware() {
    for (mode, feature, label) in [
        (ivm::ivm_mode::ZK, ivm::CONTRACT_FEATURE_BIT_ZK, "ZK"),
        (
            ivm::ivm_mode::VECTOR,
            ivm::CONTRACT_FEATURE_BIT_VECTOR,
            "VECTOR",
        ),
    ] {
        let artifact = contract_artifact_with_execution_features(mode, feature);
        let verified = ivm::verify_contract_artifact(&artifact)
            .unwrap_or_else(|error| panic!("matching {label} capability must verify: {error}"));
        assert_eq!(verified.manifest.features_bitmap, Some(feature));
        let missing = contract_artifact_with_execution_features(mode, 0);
        let error = ivm::verify_contract_artifact(&missing)
            .expect_err("execution-header capability must be mirrored in CNTR");
        assert!(
            error.to_string().contains(label),
            "unexpected missing-{label} error: {error}"
        );
        let forged = contract_artifact_with_execution_features(0, feature);
        let error = ivm::verify_contract_artifact(&forged)
            .expect_err("CNTR cannot invent an execution capability");
        assert!(
            error.to_string().contains(label),
            "unexpected forged-{label} error: {error}"
        );
    }
    let hardware_like_bit = 1_u64 << 63;
    let error = ivm::verify_contract_artifact(&contract_artifact_with_execution_features(
        0,
        hardware_like_bit,
    ))
    .expect_err("unassigned feature bits must not encode host hardware availability");
    assert!(error.to_string().contains("unsupported bits"));
}
#[test]
fn contract_code_hash_binds_every_byte_of_compiled_deployable_image() {
    let source = r#"
        seiyaku FullImageBinding {
            kotoage fn run() -> Name authorize("ReadLiteral") {
                return Name::parse("indexed_literal");
            }
        }
    "#;
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile contract with CNTR, indexed literal, and code");
    let parsed = ivm::ProgramMetadata::parse(&bytes).expect("parse compiled artifact");
    assert!(parsed.contract_interface.is_some(), "CNTR must be present");
    let literals = parsed
        .literal_section
        .expect("compiled typed literal must produce LTLB");
    assert!(literals.count > 0, "LTLB must contain an indexed literal");
    assert!(
        parsed.code_offset < bytes.len(),
        "executable code must be present"
    );
    let expected = ivm::contract_code_hash(&bytes);
    for offset in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[offset] ^= 1;
        assert_ne!(
            ivm::contract_code_hash(&mutated),
            expected,
            "deployable artifact byte {offset} was not bound by contract_code_hash"
        );
    }
}
#[test]
fn sdk_code_readback_fixture_is_reproducible_and_admitted() {
    let _context = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let source = include_str!("../../iroha/tests/fixtures/contract_code_readback/code_readback.ko");
    let artifact =
        include_bytes!("../../iroha/tests/fixtures/contract_code_readback/code_readback.to");
    let rebuilt = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("reproduce the checked-in SDK contract artifact");
    assert_eq!(rebuilt.as_slice(), artifact);
    let admitted = ivm::verify_contract_artifact(artifact)
        .expect("admit the actual checked-in SDK contract artifact");
    assert_eq!(admitted.metadata.abi_version, 1);
    assert_eq!(
        admitted.manifest.seiyaku_name.as_deref(),
        Some("CodeReadbackFixture")
    );
    assert_eq!(
        admitted.code_hash,
        iroha_data_model::smart_contract::contract_code_hash(artifact)
    );
    assert_eq!(
        hex::encode(admitted.code_hash.as_ref()),
        "8ea032a639a92b0c46b366b93a8207699e3253bf4c14fd159c6f1f5261b928a9"
    );
}
#[test]
fn verified_code_hash_binds_execution_header() {
    let original = contract_artifact(1, vec![entrypoint("main", EntryPointKind::Kotoage, 0)]);
    let original_verified =
        ivm::verify_contract_artifact(&original).expect("verify original artifact");
    let original_hash = original_verified.code_hash;
    let mut changed_cycles = original.clone();
    changed_cycles[8..16].copy_from_slice(&1_u64.to_le_bytes());
    let changed_cycles_verified = ivm::verify_contract_artifact(&changed_cycles)
        .expect("verify artifact with changed max_cycles");
    assert_ne!(changed_cycles_verified.code_hash, original_hash);
    assert!(
        !changed_cycles_verified
            .manifest
            .same_signed_content(&original_verified.manifest),
        "manifest signatures must bind max_cycles"
    );
    let mut changed_vector_length = original;
    changed_vector_length[7] = 1;
    let changed_vector_hash = ivm::verify_contract_artifact(&changed_vector_length)
        .expect("verify artifact with changed vector length")
        .code_hash;
    assert_ne!(changed_vector_hash, original_hash);
}
#[test]
fn signed_manifest_rejects_every_execution_header_mutation() {
    let original = contract_artifact(1, vec![entrypoint("main", EntryPointKind::Kotoage, 0)]);
    let key = iroha_crypto::KeyPair::try_random().expect("test signing key");
    let max_frame_bytes = usize::try_from(
        iroha_data_model::parameter::system::TransactionParameters::default()
            .max_tx_bytes
            .get(),
    )
    .expect("canonical transaction byte ceiling");
    // This finite input-derived policy is shared by signing and every admitted
    // mutation. Rejected headers neither renew counters nor replenish slices.
    let cumulative_bytes =
        norito::canonical_decode_limits(original.len()).max_total_allocated_bytes();
    let physical_bytes = cumulative_bytes
        .checked_add(norito::core::DecodeBudgetContext::allocation_layout().size())
        .expect("finite original manifest allowance");
    let pool = iroha_allocation::AllocationBudget::new(physical_bytes);
    let mut grant = pool
        .try_reserve_bytes(physical_bytes)
        .expect("fund original manifest mutation operation");
    let context = norito::core::DecodeBudgetContext::from_reservation(
        norito::DecodeLimits::new(
            max_frame_bytes,
            max_frame_bytes,
            max_frame_bytes,
            cumulative_bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
        &mut grant,
    )
    .expect("retain original mutation accounting");
    let _signer_backing = grant
        .try_partition_bytes(key.public_key().retained_allocation_layout().size())
        .expect("retain original compact signer backing");
    let original_verified =
        ivm::verify_contract_artifact(&original).expect("verify original artifact");
    let frame_bytes = context
        .with(|| {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::encoded_frame_len_bounded(
                &original_verified.manifest.signature_payload(),
                max_frame_bytes,
            )
        })
        .expect("count original manifest payload");
    let signing_frame = grant
        .try_partition_bytes(frame_bytes)
        .expect("admit exact signing frame");
    let signed = original_verified
        .manifest
        .clone()
        .try_signed(&context, frame_bytes, &key)
        .expect("sign original manifest");
    drop(signing_frame);
    let provenance = signed.provenance.as_ref().expect("manifest provenance");
    let original_frame = grant
        .try_partition_bytes(frame_bytes)
        .expect("admit exact original verification frame");
    let original_payload = signed
        .signature_payload_bytes(&context, frame_bytes)
        .expect("encode original signed manifest payload");
    provenance
        .signature
        .verify(&provenance.signer, &original_payload)
        .expect("original manifest signature");
    drop(original_payload);
    drop(original_frame);
    let mut mutations = Vec::<(&str, Vec<u8>)>::new();
    for index in 0..ivm::METADATA_MAGIC.len() {
        let mut magic = original.clone();
        magic[index] ^= 0xff;
        mutations.push(("magic", magic));
    }
    let mut version_major = original.clone();
    version_major[4] = 2;
    mutations.push(("version_major", version_major));
    let mut version_minor = original.clone();
    version_minor[5] = 0;
    mutations.push(("version_minor", version_minor));
    let mut mode = original.clone();
    mode[6] = ivm::ivm_mode::ZK;
    mutations.push(("mode", mode));
    let mut vector_length = original.clone();
    vector_length[7] = 1;
    mutations.push(("vector_length", vector_length));
    let mut max_cycles = original.clone();
    max_cycles[8..16].copy_from_slice(&1_u64.to_le_bytes());
    mutations.push(("max_cycles", max_cycles));
    let mut abi_version = original.clone();
    abi_version[16] = 0;
    mutations.push(("abi_version", abi_version));
    for index in 17..ivm::HEADER_SIZE {
        let mut abi_hash = original.clone();
        abi_hash[index] ^= 0xff;
        mutations.push(("abi_hash", abi_hash));
    }
    for (field, mutated) in mutations {
        let Ok(verified) = ivm::verify_contract_artifact(&mutated) else {
            // Structural rejection is an admission rejection before provenance is checked.
            continue;
        };
        assert!(
            !verified.manifest.same_signed_content(&signed),
            "{field} mutation retained the signed manifest payload"
        );
        let frame_bytes = context
            .with(|| {
                let _canonical =
                    norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
                norito::core::encoded_frame_len_bounded(
                    &verified.manifest.signature_payload(),
                    max_frame_bytes,
                )
            })
            .expect("count admitted mutated manifest payload");
        let frame = grant
            .try_partition_bytes(frame_bytes)
            .expect("admit exact mutated verification frame");
        let payload = verified
            .manifest
            .signature_payload_bytes(&context, frame_bytes)
            .expect("encode admitted mutated manifest payload");
        assert!(
            provenance
                .signature
                .verify(&provenance.signer, &payload)
                .is_err(),
            "{field} mutation retained a valid signature"
        );
        drop(payload);
        drop(frame);
    }
}
#[test]
fn public_entrypoint_descriptor_targets_authenticated_callable() {
    let src = r#"
        seiyaku Demo {
            kotoage fn main()  authorize("Entry") {}

            kotoage fn run() -> int  authorize("Entry") {
                return 42;
            }
        }
    "#;
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile contract");
    let parsed = ivm::ProgramMetadata::parse(&bytes).expect("parse artifact");
    let contract_interface = parsed
        .contract_interface
        .as_ref()
        .expect("contract interface");
    let run = contract_interface
        .entrypoints
        .iter()
        .find(|candidate| candidate.name == "run")
        .expect("run entrypoint");
    let mut vm = ivm::IVM::new(u64::MAX);
    vm.load_program(&bytes).expect("load artifact");
    vm.set_program_counter(parsed.prefix_len() as u64 + run.entry_pc)
        .expect("select run entrypoint");
    vm.run().expect("run entrypoint");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 42);
}
#[test]
fn contract_artifact_with_cntr_requires_explicit_entrypoint_selection() {
    let src = r#"
seiyaku ContractArtifactFixture {

        kotoage fn main() -> int authorize("Entry") {
            debug::info("alpha");
            return 7;
        }

}
"#;
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile artifact");
    let parsed = ivm::ProgramMetadata::parse(&bytes).expect("parse artifact");
    let contract_interface = parsed
        .contract_interface
        .as_ref()
        .expect("CNTR must be present");
    let main = contract_interface
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "main")
        .expect("main entrypoint descriptor");
    let cntr_len = contract_interface.encode_section().len();
    assert!(
        parsed.code_offset > parsed.header_len + cntr_len,
        "string literals should emit a prefix section after CNTR",
    );
    let mut vm = ivm::IVM::new(u64::MAX);
    vm.load_program(&bytes).expect("load artifact");
    assert_eq!(vm.run(), Err(ivm::VMError::DecodeError));
    assert!(
        vm.call_result_word_count().is_err(),
        "unselected root cannot complete"
    );
    let mut vm = ivm::IVM::new(u64::MAX);
    vm.load_program(&bytes).expect("load artifact");
    vm.set_program_counter(parsed.prefix_len() as u64 + main.entry_pc)
        .expect("select CNTR main entrypoint");
    vm.run().expect("run selected main entrypoint");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 7);
}
#[test]
fn verify_rejects_missing_cntr() {
    let mut bytes = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    }
    .encode();
    bytes.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let err = ivm::verify_contract_artifact(&bytes).expect_err("missing CNTR must fail");
    assert!(err.to_string().contains("missing required CNTR"));
}
#[test]
fn verify_rejects_malformed_cntr() {
    let mut bytes = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    }
    .encode();
    bytes.extend_from_slice(b"CNTR");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(0xff);
    bytes.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let err = ivm::verify_contract_artifact(&bytes).expect_err("malformed CNTR must fail");
    assert!(err.to_string().contains("metadata parse failed"));
}
#[test]
fn verify_rejects_embedded_debug_metadata() {
    let mut bytes = contract_artifact(1, vec![entrypoint("main", EntryPointKind::Kotoage, 0)]);
    let parsed = ivm::ProgramMetadata::parse(&bytes).expect("parse base artifact");
    let code = bytes.split_off(parsed.code_offset);
    bytes.extend_from_slice(
        &ivm::EmbeddedContractDebugInfoV1 {
            source_map: Vec::new(),
            budget_report: Vec::new(),
        }
        .encode_section(),
    );
    bytes.extend_from_slice(&code);
    let err = ivm::verify_contract_artifact(&bytes)
        .expect_err("deployable artifacts must not contain debug metadata");
    assert!(err.to_string().contains("DBG1"));
}
#[test]
fn verify_rejects_undefined_opcodes_before_execution() {
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[0xff00_0000, ivm::encoding::wide::encode_halt()],
    );
    let error = ivm::verify_contract_artifact(&bytes)
        .expect_err("undefined opcode must fail shared artifact admission");
    assert_eq!(
        error.to_string(),
        "invalid contract artifact: invalid opcode 0xff at pc 0"
    );
}
#[test]
fn verify_rejects_noncanonical_poseidon6_encodings_before_execution() {
    use ivm::instruction::wide;

    for malformed in [
        ivm::encoding::wide::encode_rr(wide::crypto::POSEIDON6, 9, 10, 1),
        ivm::encoding::wide::encode_rr(wide::crypto::POSEIDON6, 9, 251, 0),
    ] {
        let bytes = contract_artifact_with_code(
            1,
            vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
            None,
            &[malformed, ivm::encoding::wide::encode_halt()],
        );
        let error = ivm::verify_contract_artifact(&bytes)
            .expect_err("noncanonical POSEIDON6 encoding must fail shared artifact admission");
        assert_eq!(
            error.to_string(),
            "invalid contract artifact: noncanonical POSEIDON6 encoding at pc 0"
        );
    }
}
#[test]
fn verify_rejects_direct_control_flow_outside_instruction_boundaries() {
    use ivm::instruction::wide;
    let outside = ivm::encoding::wide::encode_branch(wide::control::BEQ, 0, 0, 1);
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[outside],
    );
    let err = ivm::verify_contract_artifact(&bytes)
        .expect_err("branch to the end of the stream must be rejected");
    assert!(err.to_string().contains("instruction boundary"));
    let before_start = ivm::encoding::wide::encode_offset24(wide::control::JMP, -1);
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[before_start],
    );
    let err =
        ivm::verify_contract_artifact(&bytes).expect_err("jump before the stream must be rejected");
    assert!(err.to_string().contains("outside the executable stream"));
}
#[test]
fn verify_rejects_missing_direct_control_flow_fallthrough_even_when_unreachable() {
    use ivm::instruction::wide;
    let terminal_control_flow = [
        (
            "conditional branch",
            ivm::encoding::wide::encode_branch(wide::control::BEQ, 0, 0, 0),
        ),
        (
            "direct call",
            ivm::encoding::wide::encode_offset24(wide::control::JALS, 0),
        ),
        (
            "linking jump",
            ivm::encoding::wide::encode_jump(wide::control::JAL, 1, 0),
        ),
    ];
    for (encoding, terminal) in terminal_control_flow {
        let bytes = contract_artifact_with_code(
            1,
            vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
            None,
            &[ivm::encoding::wide::encode_halt(), terminal],
        );
        let error = ivm::verify_contract_artifact(&bytes)
            .expect_err("every direct control-flow fallthrough must be a decoded boundary");
        assert!(
            error.to_string().contains("control-flow fallthrough"),
            "{encoding} with a missing fallthrough was admitted: {error}"
        );
    }
}
#[test]
fn verify_rejects_unexecutable_control_flow_even_when_unreachable() {
    use ivm::instruction::wide;
    let invalid_control_flow = [
        (
            "indirect jump",
            ivm::encoding::wide::encode_rr(wide::control::JR, 2, 0, 0),
            "unverifiable indirect control flow",
        ),
        (
            "indirect call",
            ivm::encoding::wide::encode_rr(wide::control::JALR, 1, 2, 0),
            "unverifiable indirect control flow",
        ),
        (
            "unsupported link register",
            ivm::encoding::wide::encode_jump(wide::control::JAL, 2, 0),
            "unsupported link register r2",
        ),
    ];
    for (encoding, invalid, expected) in invalid_control_flow {
        let bytes = contract_artifact_with_code(
            1,
            vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
            None,
            &[ivm::encoding::wide::encode_halt(), invalid],
        );
        let error = ivm::verify_contract_artifact(&bytes)
            .expect_err("strict contract control-flow rules apply to the complete artifact");
        assert!(
            error.to_string().contains(expected),
            "unreachable {encoding} was admitted: {error}"
        );
    }
}
#[test]
fn verify_rejects_disallowed_syscalls_before_execution() {
    let disallowed_number = 0x54;
    let disallowed = ivm::encoding::wide::encode_sys(
        ivm::instruction::wide::system::SCALL,
        u8::try_from(disallowed_number).expect("unassigned syscall fits SCALL immediate"),
    );
    assert!(!ivm::syscalls::is_syscall_allowed(
        ivm::SyscallPolicy::AbiV1,
        disallowed_number
    ));
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[disallowed, ivm::encoding::wide::encode_halt()],
    );
    let err = ivm::verify_contract_artifact(&bytes)
        .expect_err("unknown bytecode syscall must fail artifact admission");
    assert!(err.to_string().contains("disallowed syscall"));
}
#[test]
fn verify_rejects_private_input_syscall_without_zk_mode() {
    let private_input = ivm::encoding::wide::encode_sys(
        ivm::instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_GET_PRIVATE_INPUT as u8,
    );
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[private_input, ivm::encoding::wide::encode_halt()],
    );
    let error = ivm::verify_contract_artifact(&bytes)
        .expect_err("non-ZK artifacts must not admit private-input syscalls");
    assert!(
        error.to_string().contains("requires ZK execution mode"),
        "unexpected admission error: {error}"
    );
}
#[test]
fn prepared_contract_derives_transitive_private_input_requirement_from_bytecode() {
    use ivm::instruction::wide;
    let private_input = ivm::encoding::wide::encode_sys(
        wide::system::SCALL,
        ivm::syscalls::SYSCALL_GET_PRIVATE_INPUT as u8,
    );
    let mut code = unit_caller_with_helper(true, &[private_input]);
    let plain_pc = (code.len() * 4) as u64;
    code.extend_from_slice(&common::unit_return_words());
    let bytes = contract_artifact_with_mode_and_code(
        1,
        ivm::ivm_mode::ZK,
        ivm::CONTRACT_FEATURE_BIT_ZK,
        vec![
            entrypoint("private_commitment", EntryPointKind::Kotoage, 0),
            entrypoint("plain", EntryPointKind::Kotoage, plain_pc),
        ],
        None,
        &code,
    );
    let prepared = ivm::prepare_contract(std::sync::Arc::from(bytes.into_boxed_slice()))
        .expect("valid ZK contract prepares");
    assert_eq!(
        prepared.entrypoint_requires_private_inputs("private_commitment"),
        Some(true),
        "private input hidden in a helper must be derived transitively"
    );
    assert_eq!(
        prepared.entrypoint_requires_private_inputs("plain"),
        Some(false)
    );
    assert_eq!(prepared.entrypoint_requires_private_inputs("missing"), None);
}
#[test]
fn verify_derives_transitive_view_effects_from_bytecode() {
    use ivm::instruction::wide;
    let state_write = ivm::encoding::wide::encode_sys(
        wide::system::SCALL,
        ivm::syscalls::SYSCALL_STATE_SET as u8,
    );
    for (encoding, long_call) in [("JAL", false), ("JALS", true)] {
        let code = unit_caller_with_helper(long_call, &[state_write]);
        let malicious_view = contract_artifact_with_code(
            1,
            vec![entrypoint("inspect", EntryPointKind::View, 0)],
            None,
            &code,
        );
        let error = ivm::verify_contract_artifact(&malicious_view)
            .expect_err("a view must not hide a state write in a helper");
        assert!(
            error
                .to_string()
                .contains("transitively reaches effectful syscall"),
            "{encoding} call was not included in view reachability: {error}"
        );
        let mut authorized = entrypoint("mutate", EntryPointKind::Kotoage, 0);
        authorized.write_keys = vec!["state:*".to_owned()];
        let authorized_entry = contract_artifact_with_code(1, vec![authorized], None, &code);
        ivm::verify_contract_artifact(&authorized_entry)
            .expect("the same write is valid behind an authorized entrypoint");
    }
}
#[test]
fn strict_return_integrity_traps_view_return_address_poisoning_before_the_write() {
    use ivm::instruction::wide;
    let code = [
        // Copy an attacker-controlled target into r1, then use the syntactically
        // canonical return form to try to enter the hidden state-write block.
        ivm::encoding::wide::encode_ri(wide::arithmetic::ADDI, 1, 2, 0),
        ivm::encoding::wide::encode_rr(wide::control::JALR, 0, 1, 0),
        ivm::encoding::wide::encode_sys(
            wide::system::SCALL,
            ivm::syscalls::SYSCALL_STATE_SET as u8,
        ),
        ivm::encoding::wide::encode_halt(),
    ];
    let malicious_view = contract_artifact_with_code(
        1,
        vec![entrypoint("inspect", EntryPointKind::View, 0)],
        None,
        &code,
    );
    ivm::verify_contract_artifact(&malicious_view)
        .expect("the hidden block is unreachable under protected return semantics");
    let prepared = ivm::prepare_contract(std::sync::Arc::from(malicious_view.into_boxed_slice()))
        .expect("poisoning fixture prepares");
    let entry_pc = prepared
        .entrypoint_pc("inspect")
        .expect("view entrypoint is indexed");
    let hidden_write_pc = entry_pc + 8;
    let mut vm = ivm::IVM::new(u64::MAX);
    vm.load_prepared(&prepared).expect("prepared view loads");
    vm.set_register(2, hidden_write_pc);
    vm.set_program_counter(entry_pc)
        .expect("select malicious view");
    let error = vm
        .run()
        .expect_err("a poisoned canonical return must trap before the write");
    assert_eq!(error, ivm::VMError::AssertionFailed);
    assert_eq!(vm.pc(), entry_pc + 4, "the hidden write was not reached");
}
#[test]
fn strict_outer_return_cannot_redirect_to_an_in_code_halt() {
    use ivm::instruction::wide;
    let code = [
        // Runtime binds the root return to the end of code. An in-code HALT
        // cannot substitute for that authenticated completion target.
        ivm::encoding::wide::encode_ri(wide::arithmetic::ADDI, 1, 2, 0),
        ivm::encoding::wide::encode_rr(wide::control::JALR, 0, 1, 0),
        ivm::encoding::wide::encode_halt(),
        ivm::encoding::wide::encode_halt(),
    ];
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("inspect", EntryPointKind::View, 0)],
        None,
        &code,
    );
    let prepared = ivm::prepare_contract(std::sync::Arc::from(bytes.into_boxed_slice()))
        .expect("poisoned return fixture prepares");
    let entry_pc = prepared
        .entrypoint_pc("inspect")
        .expect("view entrypoint is indexed");
    let mut vm = ivm::IVM::new(u64::MAX);
    vm.load_prepared(&prepared).expect("prepared view loads");
    vm.set_register(2, entry_pc + 12);
    vm.set_program_counter(entry_pc).expect("select view");
    assert_eq!(
        vm.run()
            .expect_err("outer return must remain bound to the end of code"),
        ivm::VMError::AssertionFailed
    );
    assert_eq!(vm.pc(), entry_pc + 4);
}
#[test]
fn verify_allows_read_only_helper_beside_a_mutating_entrypoint() {
    use ivm::instruction::wide;
    let mut code = unit_caller_with_helper(
        true,
        &[ivm::encoding::wide::encode_sys(
            wide::system::SCALL,
            ivm::syscalls::SYSCALL_STATE_GET as u8,
        )],
    );
    let mut inspect = entrypoint("inspect", EntryPointKind::View, 0);
    inspect.read_keys = vec!["state:*".to_owned()];
    let mutate_pc = (code.len() * 4) as u64;
    code.push(ivm::encoding::wide::encode_sys(
        wide::system::SCALL,
        ivm::syscalls::SYSCALL_STATE_SET as u8,
    ));
    code.extend_from_slice(&common::unit_return_words());
    let mut mutate = entrypoint("mutate", EntryPointKind::Kotoage, mutate_pc);
    mutate.write_keys = vec!["state:*".to_owned()];
    let bytes = contract_artifact_with_code(1, vec![inspect, mutate], None, &code);
    ivm::verify_contract_artifact(&bytes).expect(
        "a read-only helper must not inherit an unreachable sibling entrypoint's write effect",
    );
}
#[test]
fn strict_return_integrity_allows_nested_direct_calls_for_raw_and_prepared_loads() {
    let bytes = kotodama_lang::compiler::Compiler::new().compile_source(
        "seiyaku Calls { fn leaf() -> bool { true } fn middle() -> bool { leaf() } view fn main() -> bool { middle() } }"
    ).expect("compile nested table calls");
    let prepared =
        ivm::prepare_contract(std::sync::Arc::from(bytes.clone())).expect("prepare nested calls");
    let entry = prepared.entrypoint_pc("main").expect("public root");
    let mut raw = ivm::IVM::new(u64::MAX);
    raw.load_program(&bytes).expect("cold contract loads");
    raw.set_program_counter(entry).unwrap();
    raw.run().expect("cold nested table calls return");
    assert_eq!(raw.public_call_result_word(0), Ok(1));
    let mut warm = ivm::IVM::new(u64::MAX);
    warm.load_prepared(&prepared)
        .expect("prepared contract loads");
    warm.set_program_counter(entry).unwrap();
    warm.run().expect("prepared nested table calls return");
    assert_eq!(warm.public_call_result_word(0), Ok(1));
    assert_eq!(raw.remaining_gas(), warm.remaining_gas());
}
#[test]
fn verifier_rejects_self_recursive_direct_calls_before_execution() {
    use ivm::instruction::wide;
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[
            ivm::encoding::wide::encode_offset24(wide::control::JALS, 0),
            ivm::encoding::wide::encode_halt(),
        ],
    );
    let error = ivm::verify_contract_artifact(&bytes)
        .expect_err("self-recursive bytecode must fail artifact admission");
    assert!(
        error.to_string().contains("recursive direct-call cycle"),
        "unexpected recursion error: {error}"
    );
}
#[test]
fn verifier_rejects_mutual_and_unreachable_direct_call_cycles() {
    use ivm::instruction::wide;
    let return_from_helper = ivm::encoding::wide::encode_rr(wide::control::JALR, 0, 1, 0);
    let mutual = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[
            ivm::encoding::wide::encode_offset24(wide::control::JALS, 2),
            ivm::encoding::wide::encode_halt(),
            ivm::encoding::wide::encode_offset24(wide::control::JALS, 2),
            return_from_helper,
            ivm::encoding::wide::encode_offset24(wide::control::JALS, -2),
            return_from_helper,
        ],
    );
    let error = ivm::verify_contract_artifact(&mutual)
        .expect_err("mutually recursive helpers must fail artifact admission");
    assert!(error.to_string().contains("recursive direct-call cycle"));
    let unreachable = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[
            ivm::encoding::wide::encode_halt(),
            ivm::encoding::wide::encode_offset24(wide::control::JALS, 0),
            ivm::encoding::wide::encode_halt(),
        ],
    );
    let error = ivm::verify_contract_artifact(&unreachable)
        .expect_err("an unreachable recursive helper must still fail artifact admission");
    assert!(error.to_string().contains("recursive direct-call cycle"));
}
#[test]
fn verifier_does_not_confuse_an_ordinary_branch_loop_with_recursion() {
    use ivm::instruction::wide;
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        None,
        &[
            &[ivm::encoding::wide::encode_branch(
                wide::control::BNE,
                2,
                0,
                0,
            )][..],
            &common::unit_return_words(),
        ]
        .concat(),
    );
    ivm::verify_contract_artifact(&bytes)
        .expect("an ordinary control-flow loop is not a recursive function call");
}
#[test]
fn verify_view_can_call_a_read_only_helper_when_the_artifact_has_no_writes() {
    use ivm::instruction::wide;
    let code = unit_caller_with_helper(
        true,
        &[ivm::encoding::wide::encode_sys(
            wide::system::SCALL,
            ivm::syscalls::SYSCALL_STATE_GET as u8,
        )],
    );
    let mut inspect = entrypoint("inspect", EntryPointKind::View, 0);
    inspect.read_keys = vec!["state:*".to_owned()];
    let bytes = contract_artifact_with_code(1, vec![inspect], None, &code);
    ivm::verify_contract_artifact(&bytes)
        .expect("an indirect return is safe when no artifact instruction can write state");
}
#[test]
fn verify_view_effect_analysis_follows_both_branch_arms() {
    use ivm::instruction::wide;
    let code = [
        ivm::encoding::wide::encode_branch(wide::control::BEQ, 0, 0, 2),
        ivm::encoding::wide::encode_halt(),
        ivm::encoding::wide::encode_sys(
            wide::system::SCALL,
            ivm::syscalls::SYSCALL_STATE_SET as u8,
        ),
        ivm::encoding::wide::encode_halt(),
    ];
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("inspect", EntryPointKind::View, 0)],
        None,
        &code,
    );
    let error = ivm::verify_contract_artifact(&bytes)
        .expect_err("a taken branch must not hide a view write");
    assert!(
        error
            .to_string()
            .contains("transitively reaches effectful syscall")
    );
}
#[test]
fn verify_view_effect_analysis_decodes_scall_and_system_writes() {
    use ivm::instruction::wide;
    let encodings = [
        (
            "high-bit SCALL",
            ivm::encoding::wide::encode_sys(
                wide::system::SCALL,
                ivm::syscalls::SYSCALL_SORACLOUD_EMIT_STATE_MUTATION as u8,
            ),
        ),
        (
            "extended SYSTEM",
            ivm::encoding::wide::encode_syscallx(ivm::syscalls::SYSCALL_STATE_SET),
        ),
    ];
    for (encoding, write) in encodings {
        let bytes = contract_artifact_with_code(
            1,
            vec![entrypoint("inspect", EntryPointKind::View, 0)],
            None,
            &[write, ivm::encoding::wide::encode_halt()],
        );
        let error = ivm::verify_contract_artifact(&bytes)
            .expect_err("every syscall encoding must participate in view-effect validation");
        assert!(
            error
                .to_string()
                .contains("transitively reaches effectful syscall"),
            "{encoding} was not decoded as an effectful syscall: {error}"
        );
    }
}
#[test]
fn verify_view_effect_analysis_ignores_unreachable_write_code() {
    use ivm::instruction::wide;
    let state_write = ivm::encoding::wide::encode_sys(
        wide::system::SCALL,
        ivm::syscalls::SYSCALL_STATE_SET as u8,
    );
    let bytes = contract_artifact_with_code(
        1,
        vec![entrypoint("inspect", EntryPointKind::View, 0)],
        None,
        &[
            &common::unit_return_words()[..],
            &[state_write],
            &common::unit_return_words(),
        ]
        .concat(),
    );
    ivm::verify_contract_artifact(&bytes)
        .expect("unreachable code must not contaminate a read-only entrypoint");
}
#[test]
fn verify_rejects_unverifiable_indirect_entrypoint_control_flow() {
    use ivm::instruction::wide;
    let indirect_jumps = [
        ivm::encoding::wide::encode_rr(wide::control::JALR, 0, 2, 0),
        ivm::encoding::wide::encode_rr(wide::control::JR, 2, 0, 0),
    ];
    for indirect in indirect_jumps {
        let bytes = contract_artifact_with_code(
            1,
            vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
            None,
            &[indirect],
        );
        let error = ivm::verify_contract_artifact(&bytes)
            .expect_err("indirect entrypoint control flow cannot be admitted from CNTR claims");
        assert!(
            error
                .to_string()
                .contains("unverifiable indirect control flow")
        );
    }
}
#[test]
fn verify_rejects_helper_hidden_access_classes_under_reported_by_cntr() {
    use ivm::instruction::wide;
    for (label, syscall, expected_access) in [
        (
            "ledger write",
            ivm::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED,
            "LedgerWrite",
        ),
        (
            "dynamic nested call",
            ivm::syscalls::SYSCALL_CALL_CONTRACT,
            "Dynamic",
        ),
    ] {
        let code = [
            ivm::encoding::wide::encode_offset24(wide::control::JALS, 2),
            ivm::encoding::wide::encode_halt(),
            ivm::encoding::wide::encode_syscallx(syscall),
            ivm::encoding::wide::encode_rr(wide::control::JALR, 0, 1, 0),
        ];
        let mut forged = entrypoint("mutate", EntryPointKind::Kotoage, 0);
        forged.read_keys = vec!["state:decoy".to_owned()];
        forged.write_keys = vec!["state:decoy".to_owned()];
        let bytes = contract_artifact_with_code(1, vec![forged], None, &code);
        let error = ivm::verify_contract_artifact(&bytes)
            .expect_err("complete CNTR access claims must cover bytecode-derived access classes");
        let message = error.to_string();
        assert!(message.contains("under-reports transitively reachable"));
        assert!(
            message.contains(expected_access),
            "{label} did not report its derived access class: {message}"
        );
    }
}
#[test]
fn verify_rejects_duplicate_entrypoints() {
    let bytes = contract_artifact(
        1,
        vec![
            entrypoint("main", EntryPointKind::Kotoage, 0),
            entrypoint("main", EntryPointKind::Kotoage, 0),
        ],
    );
    let err = ivm::verify_contract_artifact(&bytes).expect_err("duplicate entrypoints must fail");
    assert!(err.to_string().contains("duplicate entrypoint `main`"));
}
#[test]
fn verify_rejects_entrypoint_pc_aliases_and_missing_authorization() {
    let bytes = contract_artifact(
        1,
        vec![
            entrypoint("first", EntryPointKind::Kotoage, 0),
            entrypoint("second", EntryPointKind::View, 0),
        ],
    );
    let err = ivm::verify_contract_artifact(&bytes).expect_err("entrypoint PC alias must fail");
    assert!(err.to_string().contains("reuses entry_pc"));
    let mut public = entrypoint("main", EntryPointKind::Kotoage, 0);
    public.permission = None;
    let bytes = contract_artifact(1, vec![public]);
    let err = ivm::verify_contract_artifact(&bytes)
        .expect_err("public entrypoint without authorization must fail");
    assert!(err.to_string().contains("missing caller authorization"));
}
#[test]
fn verify_rejects_noncanonical_or_reserved_entrypoint_names() {
    for name in [
        "1run",
        "run-now",
        "run!",
        "mаin",  // Cyrillic `а`.
        "ｍain", // Full-width `ｍ`.
        "言挙げ",
        "始まり_",
        "fn",
        "account_id",
        "Amount",
        "__kotodama_link_private",
    ] {
        let artifact = contract_artifact(1, vec![entrypoint(name, EntryPointKind::Kotoage, 0)]);
        let error = ivm::verify_contract_artifact(&artifact)
            .expect_err("noncanonical or reserved entrypoint name must fail admission");
        assert!(
            error
                .to_string()
                .contains("canonical Kotodama V1 identifier"),
            "unexpected error for `{name}`: {error}"
        );
    }
    for name in ["entry", "init", "upgrade", "_run2"] {
        ivm::verify_contract_artifact(&contract_artifact(
            1,
            vec![entrypoint(name, EntryPointKind::Kotoage, 0)],
        ))
        .unwrap_or_else(|error| panic!("valid ordinary identifier `{name}` was rejected: {error}"));
    }
    for name in kotodama_surface::source_policy::V1_RETIRED_NUMERIC_TYPE_NAMES {
        if !iroha_data_model::smart_contract::entrypoint::is_canonical_kotodama_identifier(name) {
            continue;
        }
        let artifact = contract_artifact(1, vec![entrypoint(name, EntryPointKind::Kotoage, 0)]);
        ivm::verify_contract_artifact(&artifact).unwrap_or_else(|error| {
            panic!("retired numeric entrypoint name `{name}` was rejected: {error}")
        });
    }
}
#[test]
fn verify_rejects_noncanonical_or_reserved_seiyaku_names() {
    for name in [
        "",
        "1Ledger",
        "Ledger-name",
        "Lеdger",  // Cyrillic `е`.
        "Ｌedger", // Full-width `Ｌ`.
        "seiyaku",
        "match",
        "__kotodama_link_private",
    ] {
        let artifact = contract_artifact_with_seiyaku_name(name);
        let error = ivm::verify_contract_artifact(&artifact)
            .expect_err("noncanonical or reserved seiyaku name must fail admission");
        assert!(
            error
                .to_string()
                .contains("canonical Kotodama V1 identifier"),
            "unexpected error for `{name}`: {error}"
        );
    }
    for name in kotodama_surface::source_policy::V1_RETIRED_NUMERIC_TYPE_NAMES {
        let artifact = contract_artifact_with_seiyaku_name(name);
        let error = ivm::verify_contract_artifact(&artifact)
            .expect_err("every retired numeric type name must remain reserved for source units");
        assert!(
            error
                .to_string()
                .contains("canonical Kotodama V1 identifier"),
            "unexpected error for retired seiyaku name `{name}`: {error}"
        );
    }
    let artifact = contract_artifact_with_seiyaku_name("_Ledger2");
    ivm::verify_contract_artifact(&artifact)
        .expect("valid ASCII seiyaku identifier must pass admission");
}
#[test]
fn verify_rejects_noncanonical_or_reserved_state_names() {
    for name in [
        "1counter",
        "counter-name",
        "cоunter",
        "状態",
        "state",
        "Option",
        "Amount",
    ] {
        let artifact = contract_artifact_with_states(vec![ivm::EmbeddedStateDescriptor {
            name: name.to_owned(),
            ty: ivm::EmbeddedStateType::Int,
        }]);
        let error = ivm::verify_contract_artifact(&artifact)
            .expect_err("noncanonical or reserved state name must fail admission");
        assert!(
            error
                .to_string()
                .contains("canonical Kotodama V1 identifier"),
            "unexpected error for `{name}`: {error}"
        );
    }
    ivm::verify_contract_artifact(&contract_artifact_with_states(vec![
        ivm::EmbeddedStateDescriptor {
            name: "_counter2".to_owned(),
            ty: ivm::EmbeddedStateType::Int,
        },
    ]))
    .expect("valid ASCII state identifier must pass admission");
    for ty in [
        ivm::EmbeddedStateType::Struct {
            name: "Rеcord".to_owned(), // Cyrillic `е`.
            fields: vec![],
        },
        ivm::EmbeddedStateType::Struct {
            name: "Record".to_owned(),
            fields: vec![ivm::EmbeddedStateFieldDescriptor {
                name: "field-name".to_owned(),
                ty: ivm::EmbeddedStateType::Int,
            }],
        },
        ivm::EmbeddedStateType::Struct {
            name: "Amount".to_owned(),
            fields: vec![],
        },
        ivm::EmbeddedStateType::Struct {
            name: "Record".to_owned(),
            fields: vec![ivm::EmbeddedStateFieldDescriptor {
                name: "Amount".to_owned(),
                ty: ivm::EmbeddedStateType::Int,
            }],
        },
    ] {
        let artifact = contract_artifact_with_states(vec![ivm::EmbeddedStateDescriptor {
            name: "record".to_owned(),
            ty,
        }]);
        let error = ivm::verify_contract_artifact(&artifact)
            .expect_err("noncanonical embedded struct identifier must fail admission");
        assert!(
            error.to_string().contains("canonical") || error.to_string().contains("noncanonical"),
            "unexpected embedded struct error: {error}"
        );
    }
}
#[test]
fn verify_rejects_source_controlled_lifecycle_authorization() {
    for (name, kind) in [
        ("hajimari", EntryPointKind::Hajimari),
        ("始まり", EntryPointKind::Hajimari),
        ("kaizen", EntryPointKind::Kaizen),
        ("改善", EntryPointKind::Kaizen),
    ] {
        let mut lifecycle = entrypoint(name, kind, 0);
        lifecycle.permission = Some("SourceCannotControlLifecycle".to_owned());
        let artifact = contract_artifact(1, vec![lifecycle]);
        let err = ivm::verify_contract_artifact(&artifact)
            .expect_err("lifecycle authorization must be runtime-defined");
        assert!(
            err.to_string()
                .contains("must use runtime-defined authorization"),
            "unexpected error for branded selector `{name}`: {err}"
        );
    }
}
#[test]
fn verify_requires_reserved_lifecycle_names_to_match_their_kinds() {
    for (name, kind, expected) in [
        (
            "renamed_hajimari",
            EntryPointKind::Hajimari,
            "must use the reserved `hajimari` or `始まり` selector",
        ),
        (
            "renamed_kaizen",
            EntryPointKind::Kaizen,
            "must use the reserved `kaizen` or `改善` selector",
        ),
        (
            "hajimari",
            EntryPointKind::Kotoage,
            "has the wrong entrypoint kind",
        ),
        (
            "改善",
            EntryPointKind::View,
            "has the wrong entrypoint kind",
        ),
    ] {
        let artifact = contract_artifact(1, vec![entrypoint(name, kind, 0)]);
        let error = ivm::verify_contract_artifact(&artifact)
            .expect_err("reserved lifecycle selector and kind must agree");
        assert!(
            error.to_string().contains(expected),
            "unexpected error for `{name}`: {error}"
        );
    }
    for (name, kind) in [
        ("hajimari", EntryPointKind::Hajimari),
        ("始まり", EntryPointKind::Hajimari),
        ("kaizen", EntryPointKind::Kaizen),
        ("改善", EntryPointKind::Kaizen),
    ] {
        ivm::verify_contract_artifact(&contract_artifact(1, vec![entrypoint(name, kind, 0)]))
            .unwrap_or_else(|error| {
                panic!("valid branded selector `{name}` was rejected: {error}")
            });
    }
}
#[test]
fn verify_rejects_inconsistent_access_completeness() {
    let mut complete = entrypoint("main", EntryPointKind::Kotoage, 0);
    complete.access_hints_skipped = vec!["dynamic path".to_owned()];
    let err = ivm::verify_contract_artifact(&contract_artifact(1, vec![complete]))
        .expect_err("complete hints with skipped reasons must fail");
    assert!(err.to_string().contains("marks access hints complete"));
    let mut incomplete = entrypoint("main", EntryPointKind::Kotoage, 0);
    incomplete.access_hints_complete = Some(false);
    let err = ivm::verify_contract_artifact(&contract_artifact(1, vec![incomplete]))
        .expect_err("incomplete hints without reason must fail");
    assert!(err.to_string().contains("without a reason"));
}
#[test]
fn verify_rejects_invalid_entry_pc() {
    for invalid_pc in [1, 2, 3, 16, u64::MAX] {
        let bytes = contract_artifact(
            1,
            vec![entrypoint("main", EntryPointKind::Kotoage, invalid_pc)],
        );
        let err = ivm::verify_contract_artifact(&bytes)
            .expect_err("misaligned and out-of-code entry PCs must fail");
        assert!(
            err.to_string().contains("invalid entry_pc"),
            "entry_pc {invalid_pc} produced an unexpected error: {err}"
        );
    }
}
#[test]
fn verify_rejects_invalid_trigger_callback_target() {
    let mut main = entrypoint("main", EntryPointKind::Kotoage, 0);
    main.triggers.push(time_trigger("wake", None, "missing"));
    let bytes = contract_artifact(1, vec![main]);
    let err = ivm::verify_contract_artifact(&bytes)
        .expect_err("invalid trigger callback target must fail");
    assert!(err.to_string().contains("callback target `missing`"));
}
#[test]
fn verify_rejects_forbidden_trigger_identifier_positions() {
    for (trigger, expected) in [
        (
            time_trigger("Amount", None, "main"),
            "trigger ID `Amount` must be a canonical Kotodama V1 declaration identifier",
        ),
        (
            time_trigger("wake", Some("Amount"), "main"),
            "callback namespace `Amount` must be a canonical Kotodama V1 seiyaku identifier",
        ),
    ] {
        let mut main = entrypoint("main", EntryPointKind::Kotoage, 0);
        main.triggers.push(trigger);
        let error = ivm::verify_contract_artifact(&contract_artifact(1, vec![main]))
            .expect_err("exact `Amount` must not be accepted in trigger source positions");
        assert!(
            error.to_string().contains(expected),
            "unexpected admission error: {error}"
        );
    }
}
#[test]
fn verify_rejects_raw_control_flow_into_a_distinct_entrypoint() {
    use ivm::instruction::wide;
    let transfers = [
        (
            "conditional branch",
            ivm::encoding::wide::encode_branch(wide::control::BEQ, 0, 0, 2),
            "ordinary control flow at pc 8 is shared by function roots",
        ),
        (
            "tail jump",
            ivm::encoding::wide::encode_jump(wide::control::JAL, 0, 2),
            "ordinary control flow at pc 8 is shared by function roots",
        ),
        (
            "direct call",
            ivm::encoding::wide::encode_jump(wide::control::JAL, 1, 2),
            "reaches distinct entrypoint",
        ),
        (
            "long jump",
            ivm::encoding::wide::encode_offset24(wide::control::JMP, 2),
            "ordinary control flow at pc 8 is shared by function roots",
        ),
        (
            "long direct call",
            ivm::encoding::wide::encode_offset24(wide::control::JALS, 2),
            "reaches distinct entrypoint",
        ),
    ];
    let targets = [
        ("admin", EntryPointKind::Kotoage),
        ("inspect", EntryPointKind::View),
        ("hajimari", EntryPointKind::Hajimari),
        ("kaizen", EntryPointKind::Kaizen),
    ];
    for (encoding, transfer, expected_error) in transfers {
        for (target_name, target_kind) in targets {
            let bytes = contract_artifact_with_code(
                1,
                vec![
                    entrypoint("run", EntryPointKind::Kotoage, 0),
                    entrypoint(target_name, target_kind, 8),
                ],
                None,
                &[
                    transfer,
                    ivm::encoding::wide::encode_halt(),
                    ivm::encoding::wide::encode_halt(),
                ],
            );
            let error = ivm::verify_contract_artifact(&bytes)
                .expect_err("raw cross-entrypoint control flow must fail admission");
            let error = error.to_string();
            assert!(
                error.contains(expected_error),
                "{encoding} into {target_name} returned the wrong error: {error}"
            );
            if expected_error == "reaches distinct entrypoint" {
                assert!(
                    error.contains(&format!("`{target_name}`")),
                    "{encoding} named the wrong target entrypoint: {error}"
                );
            }
        }
    }
}
#[test]
fn verify_rejects_duplicate_trigger_ids() {
    let mut main = entrypoint("main", EntryPointKind::Kotoage, 0);
    main.triggers.push(time_trigger("wake", None, "main"));
    main.triggers.push(time_trigger("wake", None, "main"));
    let err = ivm::verify_contract_artifact(&contract_artifact(1, vec![main]))
        .expect_err("duplicate trigger IDs must fail closed during artifact admission");
    assert!(err.to_string().contains("duplicate trigger `wake`"));
}
#[test]
fn verify_rejects_non_kotoage_local_trigger_callbacks() {
    for (target, kind) in [
        ("inspect", EntryPointKind::View),
        ("hajimari", EntryPointKind::Hajimari),
        ("kaizen", EntryPointKind::Kaizen),
    ] {
        let mut main = entrypoint("main", EntryPointKind::Kotoage, 0);
        main.triggers.push(time_trigger("wake", None, target));
        let target_entrypoint = entrypoint(target, kind, 4);
        let bytes = contract_artifact_with_code(
            1,
            vec![main, target_entrypoint],
            None,
            &[
                ivm::encoding::wide::encode_halt(),
                ivm::encoding::wide::encode_halt(),
            ],
        );
        let err = ivm::verify_contract_artifact(&bytes).unwrap_err();
        assert!(
            err.to_string()
                .contains("must be a `kotoage`/`言挙げ` entrypoint"),
            "unexpected admission error for {target}: {err}"
        );
    }
}
#[test]
fn verify_accepts_namespaced_trigger_callback_target() {
    let mut main = entrypoint("main", EntryPointKind::Kotoage, 0);
    main.triggers
        .push(time_trigger("amount", Some("callee"), "run"));
    let bytes = contract_artifact(1, vec![main]);
    ivm::verify_contract_artifact(&bytes)
        .expect("lowercase business identifiers remain valid trigger IDs");
}
#[test]
fn verify_accepts_global_access_wildcard_hints() {
    let hints = AccessSetHints {
        read_keys: vec!["*".to_owned()],
        write_keys: vec!["*".to_owned()],
        dynamic_reads: Vec::new(),
        dynamic_writes: Vec::new(),
    };
    let bytes = contract_artifact_with_access_hints(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        Some(hints),
    );
    ivm::verify_contract_artifact(&bytes).expect("global wildcard access hints are supported");
}
#[test]
fn verify_accepts_state_access_wildcard_hints() {
    let hints = AccessSetHints {
        read_keys: vec!["state:*".to_owned()],
        write_keys: vec!["state:*".to_owned()],
        dynamic_reads: Vec::new(),
        dynamic_writes: Vec::new(),
    };
    let bytes = contract_artifact_with_access_hints(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        Some(hints),
    );
    ivm::verify_contract_artifact(&bytes).expect("state wildcard access hints are supported");
}
#[test]
fn verify_rejects_invalid_dynamic_access_hints() {
    let hints = AccessSetHints {
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        dynamic_reads: vec![DynamicAccessHint {
            base_key: "state:*".to_owned(),
            key_type: "int".to_owned(),
            bound_kind: "take".to_owned(),
            max_keys: 64,
        }],
        dynamic_writes: Vec::new(),
    };
    let bytes = contract_artifact_with_access_hints(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        Some(hints),
    );
    let err = ivm::verify_contract_artifact(&bytes).expect_err("wildcard dynamic hint must fail");
    assert!(err.to_string().contains(
        "base_key must be `state:` followed by one canonical state declaration identifier"
    ));
    let hints = AccessSetHints {
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        dynamic_reads: Vec::new(),
        dynamic_writes: vec![DynamicAccessHint {
            base_key: "state:Orders".to_owned(),
            key_type: "int".to_owned(),
            bound_kind: "page".to_owned(),
            max_keys: 0,
        }],
    };
    let bytes = contract_artifact_with_access_hints(
        1,
        vec![entrypoint("main", EntryPointKind::Kotoage, 0)],
        Some(hints),
    );
    let err = ivm::verify_contract_artifact(&bytes).expect_err("zero dynamic hint must fail");
    assert!(err.to_string().contains("max_keys must be in 1..=64"));
}
#[test]
fn verify_dynamic_access_hints_resolve_the_exact_declared_state_map() {
    let hint = DynamicAccessHint {
        base_key: "state:amount".to_owned(),
        key_type: "quantity".to_owned(),
        bound_kind: "page".to_owned(),
        max_keys: 64,
    };
    let hints = AccessSetHints {
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        dynamic_reads: vec![hint.clone()],
        dynamic_writes: Vec::new(),
    };
    let state = ivm::EmbeddedStateDescriptor {
        name: "amount".to_owned(),
        ty: ivm::EmbeddedStateType::StateMap {
            key: Box::new(ivm::EmbeddedStateType::Quantity),
            value: Box::new(ivm::EmbeddedStateType::Bool),
        },
    };
    for bound_kind in ["page", "take"] {
        let mut valid_hints = hints.clone();
        valid_hints.dynamic_reads[0].bound_kind = bound_kind.to_owned();
        let artifact =
            contract_artifact_with_access_hints_and_states(Some(valid_hints), vec![state.clone()]);
        ivm::verify_contract_artifact(&artifact)
            .expect("each exact V1 dynamic bound must resolve to its declared StateMap");
    }
    let mut retired_hints = hints.clone();
    retired_hints.dynamic_reads[0].bound_kind = "range".to_owned();
    let artifact =
        contract_artifact_with_access_hints_and_states(Some(retired_hints), vec![state.clone()]);
    let error = ivm::verify_contract_artifact(&artifact)
        .expect_err("retired range metadata must reject even for an exact declared StateMap");
    assert!(
        error
            .to_string()
            .contains("bound_kind must be exactly `page` or `take`")
    );
    let mut mismatched_hints = hints.clone();
    mismatched_hints.dynamic_reads[0].key_type = "int".to_owned();
    let artifact =
        contract_artifact_with_access_hints_and_states(Some(mismatched_hints), vec![state]);
    let error =
        ivm::verify_contract_artifact(&artifact).expect_err("mismatched key type must fail");
    assert!(
        error
            .to_string()
            .contains("declares key_type `int` but its StateMap key type is `quantity`")
    );
    let artifact = contract_artifact_with_access_hints_and_states(
        Some(hints),
        vec![ivm::EmbeddedStateDescriptor {
            name: "amount".to_owned(),
            ty: ivm::EmbeddedStateType::Quantity,
        }],
    );
    let error = ivm::verify_contract_artifact(&artifact)
        .expect_err("a dynamic hint must not target scalar state");
    assert!(
        error
            .to_string()
            .contains("must reference a declared top-level StateMap")
    );
    let artifact = contract_artifact_with_access_hints_and_states(
        Some(AccessSetHints {
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            dynamic_reads: vec![hint],
            dynamic_writes: Vec::new(),
        }),
        Vec::new(),
    );
    let error =
        ivm::verify_contract_artifact(&artifact).expect_err("unknown dynamic base must fail");
    assert!(
        error
            .to_string()
            .contains("must reference a declared top-level StateMap")
    );
}
#[test]
fn verify_rejects_unsupported_abi_version() {
    let bytes = contract_artifact(2, vec![entrypoint("main", EntryPointKind::Kotoage, 0)]);
    let err = ivm::verify_contract_artifact(&bytes).expect_err("abi version mismatch must fail");
    assert!(
        err.to_string()
            .contains("unsupported IVM program ABI version 2")
    );
}

#[test]
fn admission_authenticates_bounded_static_error_messages() {
    use iroha_data_model::smart_contract::manifest::ContractErrorMessage;
    let error = ivm_abi::error_types::list_error_type();
    let message = ContractErrorMessage {
        error_type: error.identity.clone(),
        code: error.variants[0].code,
        message: "The index is outside the list".into(),
    };
    let artifact =
        contract_artifact_with_error_messages(vec![error.clone()], vec![message.clone()]);
    let verified = ivm::verify_contract_artifact(&artifact).unwrap();
    assert_eq!(
        verified.manifest.error_messages,
        Some(vec![message.clone()])
    );
    for invalid in [
        ContractErrorMessage {
            error_type: "Undeclared::Error".into(),
            ..message.clone()
        },
        ContractErrorMessage {
            code: u32::MAX,
            ..message.clone()
        },
        ContractErrorMessage {
            message: "é".repeat(2049),
            ..message.clone()
        },
        ContractErrorMessage {
            message: " ".into(),
            ..message.clone()
        },
    ] {
        let artifact = contract_artifact_with_error_messages(vec![error.clone()], vec![invalid]);
        assert!(ivm::verify_contract_artifact(&artifact).is_err());
    }
    let duplicate =
        contract_artifact_with_error_messages(vec![error], vec![message.clone(), message]);
    assert!(ivm::verify_contract_artifact(&duplicate).is_err());
}
