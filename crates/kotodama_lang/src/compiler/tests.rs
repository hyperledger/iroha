//! Compiler bytecode, source-policy, and access-hint regressions.

#[path = "tests/dead_operands.rs"]
mod dead_operands;
#[path = "tests/literal_helpers.rs"]
mod literal_helpers;
#[path = "tests/numeric_operands.rs"]
mod numeric_operands;
#[path = "tests/rematerialized.rs"]
mod rematerialized;
#[path = "tests/state_operands.rs"]
mod state_operands;

use super::{
    ACCOUNT_WILDCARD_KEY, AUTHORITY_ACCOUNT_KEY, AccessHintDiagnostics, AccessSets,
    COLLECTION_ITERATION_CAP, Compiler, CompilerMode, CompilerOptions, DEFAULT_MAX_CYCLES,
    DataKind, DeferredTransfer, GLOBAL_WILDCARD_KEY, HINT_SKIP_CONTRACT_CALL_TARGET,
    HINT_SKIP_DYNAMIC_INSTRUCTION_BRIDGE, HINT_SKIP_DYNAMIC_STATE_PATH,
    HINT_SKIP_LITERAL_TRIGGER_SPEC_DECODE, HINT_SKIP_OPAQUE_ISI, IrAccessClass, LiteralFixups,
    NFT_COARSE_KEY, STATE_WILDCARD_KEY, TRAMPOLINE_ISLAND_BYTES, TransferKind, WIDE_IMM_MAX,
    classify_ir_access, collect_dynamic_access_hints, decoded_control_target, emit_addi,
    emit_get_private_input_arguments, emit_load64, emit_parallel_register_moves,
    emit_private_numeric_valcom_arguments, emit_store64, encode_addi, encode_jal, encode_nop,
    patch_indexed_literal_load, patch_literal_load, pointer_type_for_kind, push_word,
    record_isi_access, relax_control_transfers_with_trampolines, reserve_word,
    stack_slot_offset_bytes,
};
use crate::{
    ast::BinaryOp,
    ir,
    parser::parse_test_fragment as parse,
    semantic::{self, analyze},
};
use crate::{
    encoding, instruction,
    metadata::{EmbeddedStateDescriptor, EmbeddedStateType, ProgramMetadata},
    pointer_abi::PointerType,
};
use indexmap::IndexSet;
use iroha_data_model::asset::{AssetBalanceScope, id::AssetDefinitionId};
use iroha_model_base::domain::DomainId;
use ivm_abi::syscalls;
use kotodama_surface::builtins::BuiltinAccess;
use std::collections::{HashMap, HashSet};

fn test_mode_compiler() -> Compiler {
    Compiler::new_with_options(CompilerOptions {
        mode: CompilerMode::Test,
        ..CompilerOptions::default()
    })
}
fn canonical_norito_hex<T: norito::NoritoSerialize>(value: &T) -> String {
    let bytes =
        ivm_abi::codec::encode_canonical_norito(value).expect("encode canonical test frame");
    format!("0x{}", hex::encode(bytes))
}
fn alternate_norito_hex<T: norito::NoritoSerialize>(value: &T) -> String {
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    let bytes = norito::to_bytes(value).expect("encode alternate-layout test frame");
    format!("0x{}", hex::encode(bytes))
}
fn compile_with_injected_ir(instructions: Vec<ir::Instr>) -> Result<Vec<u8>, String> {
    let options = CompilerOptions::default();
    let session = crate::session::CompilerSession::new(options.clone());
    let source_name = "axt_literal_validation.ko";
    let parsed = session
        .parse_compilation_unit(crate::session::CompileRequest {
            source: include_str!("fixtures/v1/c001.ko"),
            source_name: Some(source_name),
        })
        .map_err(|diagnostics| diagnostics.render_human())?;
    let resolved = session
        .resolve_compilation_unit(parsed)
        .map_err(|diagnostics| diagnostics.render_human())?;
    let typed = session
        .type_effect_compilation_unit(resolved)
        .map_err(|diagnostics| diagnostics.render_human())?;
    let compiler = Compiler::new_with_options(options);
    let lowered = compiler
        .lower_typed_program(typed, Some(source_name))
        .map_err(|diagnostics| diagnostics.render_human())?;
    let ssa = compiler
        .construct_ssa_program(lowered)
        .map_err(|diagnostics| diagnostics.render_human())?;
    let optimized = compiler
        .optimize_ssa_program(ssa)
        .map_err(|diagnostics| diagnostics.render_human())?;
    let mut codegen = compiler
        .destroy_ssa_program(optimized)
        .map_err(|diagnostics| diagnostics.render_human())?;
    let function = codegen
        .ir_program
        .functions
        .iter_mut()
        .find(|function| function.name == "run")
        .expect("production entrypoint survives SSA retention");
    function.entry = ir::Label(0);
    function.blocks = vec![ir::BasicBlock {
        label: ir::Label(0),
        instrs: instructions,
        terminator: ir::Terminator::Return(None),
    }];
    compiler
        .compile_codegen(codegen)
        .map(|artifact| artifact.bytes)
}
fn assert_internal_source_names_rejected(names: &[&str]) {
    let mut calls = String::new();
    for name in names {
        calls.push_str("    ");
        calls.push_str(name);
        calls.push_str("();\n");
    }
    let source = format!(
        "seiyaku CompilerFixture {{\n  view fn probe() authorize(anyone) -> int {{\n{calls}    return 0;\n  }}\n}}"
    );
    let error = test_mode_compiler()
        .compile_source(&source)
        .expect_err("compiler-internal operations must not resolve from source");
    let internal_diagnostics = error.matches("E_INTERNAL_BUILTIN").count();
    let unknown_diagnostics =
        error.matches("K2002").count() + error.matches("E_UNKNOWN_BUILTIN").count();
    assert!(
        internal_diagnostics + unknown_diagnostics >= names.len(),
        "compiler-internal calls were rejected for the wrong reason: {error}"
    );
    for name in names {
        assert!(
            error.contains(name),
            "missing rejection diagnostic for `{name}`: {error}"
        );
    }
}
fn assert_no_global_access_key(keys: &[String]) {
    assert!(
        keys.iter().all(|key| key != GLOBAL_WILDCARD_KEY),
        "access hints unexpectedly require the global wildcard in {keys:?}"
    );
}
fn assert_no_ledger_reads(keys: &[String]) {
    assert!(keys.is_empty(), "unexpected ledger reads in {keys:?}");
}
fn unresolved_world_access(instr: &ir::Instr) -> (AccessSets, IndexSet<String>) {
    let IrAccessClass::Ledger(access) = classify_ir_access(instr) else {
        panic!("expected ledger access for {instr:?}");
    };
    let string_map = HashMap::new();
    let authority_account_temps = HashSet::new();
    let dataref_kind_map = HashMap::new();
    let instruction_literal_access_map = HashMap::new();
    let mut access_set = AccessSets::default();
    let mut diagnostics = AccessHintDiagnostics::default();
    let mut skips = IndexSet::new();
    record_isi_access(
        instr,
        access,
        0,
        &string_map,
        &authority_account_temps,
        &dataref_kind_map,
        &instruction_literal_access_map,
        &mut access_set,
        &mut diagnostics,
        &mut skips,
    );
    (access_set, skips)
}
#[test]
fn ir_access_classification_is_registry_backed_and_fail_closed() {
    let temp = ir::Temp(0);
    assert_eq!(
        classify_ir_access(&ir::Instr::ResolveAccountAlias {
            dest: temp,
            alias: temp,
        }),
        IrAccessClass::Ledger(BuiltinAccess::LedgerRead)
    );
    for number in [
        syscalls::SYSCALL_ZK_VERIFY_BATCH,
        syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
        syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY,
    ] {
        assert_eq!(
            classify_ir_access(&ir::Instr::ZkVerify {
                number,
                payload: temp,
            }),
            IrAccessClass::Ledger(BuiltinAccess::LedgerRead)
        );
    }
    assert_eq!(
        classify_ir_access(&ir::Instr::ZkVerify {
            number: u32::MAX,
            payload: temp,
        }),
        IrAccessClass::Ledger(BuiltinAccess::Dynamic)
    );
    assert_eq!(
        classify_ir_access(&ir::Instr::CreateNftsForAllUsers),
        IrAccessClass::Ledger(BuiltinAccess::LedgerWrite)
    );
    assert_eq!(
        classify_ir_access(&ir::Instr::StateGet {
            dest: temp,
            path: temp,
        }),
        IrAccessClass::State(BuiltinAccess::StateRead)
    );
    assert_eq!(
        classify_ir_access(&ir::Instr::StateSet {
            path: temp,
            value: temp,
        }),
        IrAccessClass::State(BuiltinAccess::StateWrite)
    );
    assert_eq!(
        classify_ir_access(&ir::Instr::CommitOutput),
        IrAccessClass::None
    );
    assert_eq!(
        classify_ir_access(&ir::Instr::GetPrivateInput {
            dest: temp,
            index: temp,
            kind: ivm_abi::private_input::PrivateInputKindV1::Int,
        }),
        IrAccessClass::None
    );
    assert_eq!(
        classify_ir_access(&ir::Instr::PrivateNumericValcom {
            dest: temp,
            value: temp,
            blind: temp,
        }),
        IrAccessClass::None
    );
    assert_eq!(
        classify_ir_access(&ir::Instr::SetExecutionDepth { value: temp }),
        IrAccessClass::None
    );
}
#[test]
fn unresolved_world_ir_uses_read_or_write_appropriate_wildcards() {
    let temp = ir::Temp(0);
    let (access, skips) = unresolved_world_access(&ir::Instr::ResolveAccountAlias {
        dest: temp,
        alias: temp,
    });
    assert_eq!(
        access.reads,
        IndexSet::from([ACCOUNT_WILDCARD_KEY.to_owned()])
    );
    assert!(access.writes.is_empty());
    assert!(skips.is_empty());
    let (access, skips) = unresolved_world_access(&ir::Instr::ZkVerify {
        number: syscalls::SYSCALL_ZK_VERIFY_BATCH,
        payload: temp,
    });
    assert_eq!(
        access.reads,
        IndexSet::from([GLOBAL_WILDCARD_KEY.to_owned()])
    );
    assert!(access.writes.is_empty());
    assert_eq!(skips, IndexSet::from([HINT_SKIP_OPAQUE_ISI.to_owned()]));
    let (access, skips) = unresolved_world_access(&ir::Instr::CreateNftsForAllUsers);
    assert_eq!(
        access.reads,
        IndexSet::from([GLOBAL_WILDCARD_KEY.to_owned()])
    );
    assert_eq!(
        access.writes,
        IndexSet::from([GLOBAL_WILDCARD_KEY.to_owned()])
    );
    assert_eq!(skips, IndexSet::from([HINT_SKIP_OPAQUE_ISI.to_owned()]));
}
#[test]
fn dynamic_state_fallback_preserves_registry_read_write_class() {
    let temp = ir::Temp(0);
    let program = ir::Program {
        functions: vec![
            call_graph_function(
                "read",
                vec![ir::Instr::StateGet {
                    dest: temp,
                    path: temp,
                }],
            ),
            call_graph_function(
                "write",
                vec![ir::Instr::StateSet {
                    path: temp,
                    value: temp,
                }],
            ),
        ],
    };
    let mut access_sets = vec![AccessSets::default(); 2];
    let mut diagnostics = AccessHintDiagnostics::default();
    let mut skips = vec![IndexSet::new(); 2];
    super::derive_state_access_hints(
        &program,
        &HashMap::new(),
        &mut access_sets,
        &mut diagnostics,
        &mut skips,
    );
    assert_eq!(
        access_sets[0].reads,
        IndexSet::from([STATE_WILDCARD_KEY.to_owned()])
    );
    assert!(access_sets[0].writes.is_empty());
    assert_eq!(
        access_sets[1].reads,
        IndexSet::from([STATE_WILDCARD_KEY.to_owned()])
    );
    assert_eq!(
        access_sets[1].writes,
        IndexSet::from([STATE_WILDCARD_KEY.to_owned()])
    );
    assert_eq!(diagnostics.state_wildcards, 2);
    assert_eq!(
        skips,
        vec![
            IndexSet::from([HINT_SKIP_DYNAMIC_STATE_PATH.to_owned()]),
            IndexSet::from([HINT_SKIP_DYNAMIC_STATE_PATH.to_owned()]),
        ]
    );
}
fn canonical_state_key(
    base: &str,
    kind: ivm_abi::state_value::StateValueKindV1,
    atom: ivm_abi::state_value::StateValueAtomV1,
) -> String {
    use ivm_abi::state_value::{
        StateValueNodeV1, StateValueRecordV1, StateValueSchemaV1, state_value_schema_hash_v1,
    };
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(kind)],
    };
    let record = StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(
            &ivm_abi::codec::encode_canonical_norito(&schema).unwrap(),
        ),
        atoms: vec![atom],
    };
    format!(
        "state:{base}/{}",
        hex::encode(ivm_abi::codec::encode_canonical_norito(&record).unwrap())
    )
}
fn canonical_numeric_state_key(base: &str, kind: ir::DataRefKind, value: &str) -> String {
    let encoded = super::encode_pointer_tlv_bytes(kind, value, false)
        .expect("encode canonical pointer-backed numeric state key");
    use ivm_abi::state_value::{StateValueAtomV1 as A, StateValueKindV1 as K};
    let kind = match kind {
        ir::DataRefKind::Int => K::Int,
        ir::DataRefKind::Decimal => K::Decimal,
        ir::DataRefKind::Quantity => K::Quantity,
        _ => panic!("numeric key"),
    };
    canonical_state_key(base, kind, A::Pointer(encoded))
}

fn sample_account_id() -> iroha_data_model::account::AccountId {
    iroha_data_model::account::AccountId::new(
        "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
            .parse()
            .expect("public key"),
    )
}
fn sample_account_literal() -> String {
    sample_account_id().to_string()
}
fn kotodama_escrow_hex(name: &str) -> String {
    let name: iroha_model_base::name::Name = name.parse().expect("valid escrow name");
    let id = iroha_data_model::escrow::EscrowId::from_kotodama_name(&name);
    hex::encode(id.as_hash().as_ref())
}
fn sample_account_id_alt() -> iroha_data_model::account::AccountId {
    iroha_data_model::account::AccountId::new(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("public key"),
    )
}
#[test]
fn pointer_types_cover_all_data_ref_kinds() {
    use super::ir::DataRefKind::*;
    let cases = [
        (Account, PointerType::AccountId),
        (AssetDef, PointerType::AssetDefinitionId),
        (AssetId, PointerType::AssetId),
        (NftId, PointerType::NftId),
        (Name, PointerType::Name),
        (Json, PointerType::Json),
        (Domain, PointerType::DomainId),
        (Blob, PointerType::Blob),
        (NoritoBytes, PointerType::NoritoBytes),
        (DataSpaceId, PointerType::DataSpaceId),
        (AxtDescriptor, PointerType::AxtDescriptor),
        (AxtAnchoredSpendV1, PointerType::AxtAnchoredSpendV1),
        (ProofBlob, PointerType::ProofBlob),
        (SoracloudRequest, PointerType::SoracloudRequest),
        (SoracloudResponse, PointerType::SoracloudResponse),
        (Int, PointerType::Int),
        (Decimal, PointerType::Decimal),
        (Quantity, PointerType::Quantity),
    ];
    for (kind, expected) in cases {
        let ty = pointer_type_for_kind(kind);
        assert_eq!(
            ty,
            Some(expected),
            "DataRefKind::{kind:?} should map to PointerType::{expected:?}"
        );
    }
}
#[test]
fn axt_descriptor_literal_encoding_enforces_host_invariants() {
    use crate::axt::{AxtDescriptor, AxtTouchSpec};
    use iroha_model_base::topology::DataSpaceId;
    fn literal(descriptor: &AxtDescriptor) -> String {
        let bytes = norito::to_bytes(descriptor).expect("encode AXT descriptor");
        format!("0x{}", hex::encode(bytes))
    }
    let dsid = DataSpaceId::new(7);
    let other = DataSpaceId::new(11);
    let touch = AxtTouchSpec {
        dsid,
        read: vec!["orders".to_owned()],
        write: vec!["ledger".to_owned()],
    };
    let valid = AxtDescriptor {
        dsids: vec![dsid],
        touches: vec![touch.clone()],
    };
    let valid_literal = literal(&valid);
    assert!(
        super::encode_pointer_tlv_bytes(ir::DataRefKind::AxtDescriptor, &valid_literal, false)
            .is_some()
    );
    assert_eq!(
        super::decode_axt_descriptor_literal(&valid_literal),
        Some(valid.clone())
    );
    let alternate_literal = {
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        literal(&valid)
    };
    assert_ne!(alternate_literal, valid_literal);
    assert!(
        super::encode_pointer_tlv_bytes(ir::DataRefKind::AxtDescriptor, &alternate_literal, false)
            .is_none(),
        "the compiler must not normalize an alternate Norito layout"
    );
    assert_eq!(
        super::decode_axt_descriptor_literal(&alternate_literal),
        None
    );
    let invalid = [
        AxtDescriptor {
            dsids: Vec::new(),
            touches: Vec::new(),
        },
        AxtDescriptor {
            dsids: vec![dsid, dsid],
            touches: Vec::new(),
        },
        AxtDescriptor {
            dsids: vec![other],
            touches: vec![touch.clone()],
        },
        AxtDescriptor {
            dsids: vec![dsid],
            touches: vec![touch.clone(), touch],
        },
        AxtDescriptor {
            dsids: vec![other, dsid],
            touches: Vec::new(),
        },
        AxtDescriptor {
            dsids: vec![dsid, other],
            touches: vec![AxtTouchSpec {
                dsid,
                read: vec![String::new()],
                write: Vec::new(),
            }],
        },
    ];
    for descriptor in invalid {
        let raw = literal(&descriptor);
        assert!(
            super::encode_pointer_tlv_bytes(ir::DataRefKind::AxtDescriptor, &raw, false).is_none(),
            "compiler must reject host-invalid descriptor: {descriptor:?}"
        );
        assert_eq!(
            super::decode_axt_descriptor_literal(&raw),
            None,
            "access-hint decoding must reject host-invalid descriptor: {descriptor:?}"
        );
    }
}
#[test]
fn proof_pointer_encoding_rejects_empty_payload() {
    use crate::axt::ProofBlob;
    fn literal<T: norito::NoritoSerialize>(value: &T) -> String {
        let bytes = norito::to_bytes(value).expect("encode capability literal");
        format!("0x{}", hex::encode(bytes))
    }
    let empty_proof_literal = literal(&ProofBlob {
        payload: Vec::new(),
        expiry_slot: None,
    });
    assert!(
        super::encode_pointer_tlv_bytes(ir::DataRefKind::ProofBlob, &empty_proof_literal, false)
            .is_none()
    );
}
#[test]
fn instruction_access_hints_reject_alternate_layout_independent_of_ambient_flags() {
    let instruction = iroha_data_model::isi::InstructionBox::from(iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "canonical access hint".to_owned(),
    ));
    let canonical_payload = ivm_abi::codec::encode_canonical_norito(&instruction)
        .expect("encode canonical InstructionBox fixture");
    let canonical_literal = format!("0x{}", hex::encode(&canonical_payload));
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let alternate_payload = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&instruction).expect("encode alternate-layout InstructionBox fixture")
    };
    assert_ne!(alternate_payload, canonical_payload);
    assert!(
        norito::decode_from_bytes::<iroha_data_model::isi::InstructionBox>(&alternate_payload)
            .is_ok(),
        "ordinary Norito must accept its advertised alternate layout"
    );
    let alternate_literal = format!("0x{}", hex::encode(alternate_payload));
    let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    assert!(super::decode_instruction_box_literal(&canonical_literal).is_some());
    assert!(super::access_for_instruction_literal(&canonical_literal).is_some());
    assert!(super::decode_instruction_box_literal(&alternate_literal).is_none());
    assert!(super::access_for_instruction_literal(&alternate_literal).is_none());
}
#[test]
fn instruction_access_hints_do_not_unwrap_prewrapped_norito_tlvs() {
    let instruction = iroha_data_model::isi::InstructionBox::from(iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "prewrapped access hint".to_owned(),
    ));
    let instruction_literal = canonical_norito_hex(&instruction);
    let prewrapped =
        super::encode_pointer_tlv_bytes(ir::DataRefKind::NoritoBytes, &instruction_literal, false)
            .expect("wrap the canonical instruction as a source-level NoritoBytes TLV");
    let prewrapped_literal = format!("0x{}", hex::encode(&prewrapped));
    let emitted =
        super::encode_pointer_tlv_bytes(ir::DataRefKind::NoritoBytes, &prewrapped_literal, false)
            .expect("emit the literal's exact bytes in the outer pointer TLV");
    let emitted_tlv =
        crate::pointer_abi::validate_tlv_bytes(&emitted).expect("validate emitted pointer TLV");
    assert_eq!(emitted_tlv.payload, prewrapped.as_slice());
    assert_eq!(
        super::decode_norito_literal_payload(&prewrapped_literal),
        Some(prewrapped)
    );
    assert!(super::decode_instruction_box_literal(&prewrapped_literal).is_none());
    assert!(super::access_for_instruction_literal(&prewrapped_literal).is_none());
}
#[test]
fn instruction_access_hints_reject_direct_concrete_instruction_frames() {
    use iroha_data_model::{
        isi::{InstructionBox, zk::SubmitBallot},
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
    };
    let backend = "halo2/ipa".to_owned();
    let submit = SubmitBallot {
        election_id: "election".to_owned(),
        ciphertext: vec![1, 2, 3],
        ballot_proof: ProofAttachment::new_ref(
            backend.clone(),
            ProofBox::new(backend.clone(), vec![4, 5, 6]),
            VerifyingKeyId::new(backend, "ballot_vk"),
        ),
        nullifier: [7; 32],
    };
    let direct_literal = canonical_norito_hex(&submit);
    assert!(super::decode_instruction_box_literal(&direct_literal).is_none());
    assert!(super::access_for_instruction_literal(&direct_literal).is_none());
    let boxed_literal = canonical_norito_hex(&InstructionBox::from(submit));
    assert!(super::decode_instruction_box_literal(&boxed_literal).is_some());
    assert!(super::access_for_instruction_literal(&boxed_literal).is_some());
}
#[test]
fn codegen_rejects_noncanonical_or_invalid_literal_axt_touch_manifests() {
    use crate::axt::TouchManifest;
    let invalid = TouchManifest {
        read: vec!["z".to_owned(), "a".to_owned()],
        write: Vec::new(),
    };
    let valid = TouchManifest {
        read: vec!["orders".to_owned()],
        write: vec!["ledger".to_owned()],
    };
    let alternate = alternate_norito_hex(&valid);
    assert_ne!(alternate, canonical_norito_hex(&valid));
    for manifest in [canonical_norito_hex(&invalid), alternate] {
        let error = compile_with_injected_ir(vec![
            ir::Instr::DataRef {
                dest: ir::Temp(0),
                kind: ir::DataRefKind::DataSpaceId,
                value: "7".to_owned(),
            },
            ir::Instr::DataRef {
                dest: ir::Temp(1),
                kind: ir::DataRefKind::NoritoBytes,
                value: manifest,
            },
            ir::Instr::AxtTouch {
                dsid: ir::Temp(0),
                manifest: Some(ir::Temp(1)),
            },
        ])
        .expect_err("literal AXT touch manifests must fail closed during full codegen");
        assert!(
            error.contains("invalid AXT touch manifest literal")
                && error.contains("canonical, context-valid TouchManifest frame"),
            "unexpected compiler error: {error}"
        );
    }
}
#[test]
fn shared_host_requests_drive_canonical_roots_and_tally_access_hints() {
    use ivm_abi::host_payload::{RootsGetRequest, VoteGetTallyRequest};
    let asset: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        .parse()
        .expect("canonical asset definition");
    let roots = RootsGetRequest {
        asset_id: asset.to_string(),
        max: 8,
    };
    let tally = VoteGetTallyRequest {
        election_id: "election".to_owned(),
    };
    let mut roots_access = AccessSets::default();
    assert_eq!(
        super::record_zk_roots_get_access(&canonical_norito_hex(&roots), &mut roots_access),
        Some(())
    );
    assert_eq!(
        roots_access.reads,
        IndexSet::from([super::key_zk_asset(&asset)])
    );
    assert!(roots_access.writes.is_empty());
    let mut tally_access = AccessSets::default();
    assert_eq!(
        super::record_zk_vote_get_tally_access(&canonical_norito_hex(&tally), &mut tally_access),
        Some(())
    );
    assert_eq!(
        tally_access.reads,
        IndexSet::from(["zk:election:election:tally".to_owned()])
    );
    assert!(tally_access.writes.is_empty());
    let alternate_roots = alternate_norito_hex(&roots);
    let alternate_tally = alternate_norito_hex(&tally);
    assert_ne!(alternate_roots, canonical_norito_hex(&roots));
    assert_ne!(alternate_tally, canonical_norito_hex(&tally));
    for (raw, decode) in [
        (
            alternate_roots,
            super::record_zk_roots_get_access as fn(&str, &mut AccessSets) -> Option<()>,
        ),
        (
            canonical_norito_hex(&tally),
            super::record_zk_roots_get_access,
        ),
        (alternate_tally, super::record_zk_vote_get_tally_access),
        (
            canonical_norito_hex(&roots),
            super::record_zk_vote_get_tally_access,
        ),
    ] {
        let mut access = AccessSets::default();
        assert_eq!(decode(&raw, &mut access), None);
        assert!(access.reads.is_empty() && access.writes.is_empty());
    }
}
#[test]
fn default_max_cycles_matches_pipeline_bound() {
    let opts = CompilerOptions::default();
    assert_eq!(opts.max_cycles, DEFAULT_MAX_CYCLES);
    assert!(opts.max_cycles > 0);
}
#[test]
fn expression_and_named_call_sugar_emit_identical_executable_bytecode() {
    fn executable_code(source: &str) -> Vec<u8> {
        let artifact = Compiler::new()
            .compile_source(source)
            .expect("compile V1 source");
        let metadata = ProgramMetadata::parse(&artifact).expect("parse V1 artifact");
        artifact[metadata.code_offset..].to_vec()
    }
    let tail = executable_code(
        "seiyaku Equivalence { view fn main(int value) authorize(anyone) -> int { value } }",
    );
    let explicit = executable_code(
        "seiyaku Equivalence { view fn main(int value) authorize(anyone) -> int { return value; } }",
    );
    assert_eq!(
        tail, explicit,
        "function tail expressions must add no emitted instructions"
    );
    let positional = executable_code(
        "seiyaku Equivalence { fn choose(int _ count, bool _ enabled) -> int { if enabled { count } else { 0 } } view fn main() authorize(anyone) -> int { choose(7, true) } }",
    );
    let named = executable_code(
        "seiyaku Equivalence { fn choose(int count, bool enabled) -> int { if enabled { count } else { 0 } } view fn main() authorize(anyone) -> int { choose(count: 7, enabled: true) } }",
    );
    assert_eq!(
        named, positional,
        "named-call sugar must be erased before executable code generation"
    );
}
#[test]
fn source_metadata_changes_sidecars_but_not_lowered_ir_or_artifact_bytes() {
    let source_text =
        "seiyaku MetadataFree { view fn answer(int value) authorize(anyone) -> int { value + 1 } }";
    let source = crate::source::SourceFile::new(
        crate::source::SourceId(73),
        "contracts/metadata_free.ko",
        source_text,
    );
    let (parsed, _) =
        crate::parser::parse_source_spanned(&source, crate::source::FrontendBudget::v1())
            .expect("parse source-backed program");
    let resolved = crate::resolved::resolve(parsed, &source).expect("resolve source program");
    let sourced = semantic::SemanticContext::new()
        .analyze_resolved(&resolved)
        .expect("analyze source-backed program");
    let mut stripped = sourced.clone();
    stripped.source_files.clear();
    for item in &mut stripped.items {
        let semantic::TypedItem::Function(function) = item;
        function.source = None;
        function.name_source = None;
    }
    for state in &mut stripped.states {
        state.source = None;
    }
    let sourced_ir = ir::lower(&sourced).expect("lower source-backed HIR");
    let stripped_ir = ir::lower(&stripped).expect("lower metadata-free HIR");
    assert_eq!(
        sourced_ir, stripped_ir,
        "source metadata must not enter lowered semantic IR"
    );
    let compiler = Compiler::new();
    let sourced_output = compiler
        .compile_typed_program_with_manifest_and_report_diagnostics(sourced, None)
        .expect("compile source-backed HIR");
    let stripped_output = compiler
        .compile_typed_program_with_manifest_and_report_diagnostics(stripped, None)
        .expect("compile metadata-free HIR");
    assert_eq!(sourced_output.artifact, stripped_output.artifact);
    assert_eq!(sourced_output.manifest, stripped_output.manifest);
    assert_eq!(
        sourced_output.contract_interface,
        stripped_output.contract_interface
    );
    assert_eq!(
        sourced_output.report.artifact_hash,
        stripped_output.report.artifact_hash
    );
    assert!(sourced_output.report.source_map.iter().all(|entry| {
        entry.source.source_id == 73
            && entry.source.source_path.as_deref() == Some("contracts/metadata_free.ko")
    }));
    assert!(
        stripped_output
            .report
            .source_map
            .iter()
            .all(|entry| { entry.source.source_id == 0 && entry.source.source_path.is_none() })
    );
}
#[test]
fn compiler_api_rejects_bare_fragments_and_implicit_main() {
    let error = Compiler::new()
        .compile_source("fn main() {}")
        .expect_err("deployable source requires a named source unit");
    assert!(error.contains("exactly one"), "unexpected error: {error}");
}
#[test]
fn selected_max_cycles_is_embedded_in_artifact() {
    let opts = CompilerOptions {
        max_cycles: 42,
        ..CompilerOptions::default()
    };
    let compiler = Compiler::new_with_options(opts);
    let src = include_str!("fixtures/v1/c002.ko");
    let code = compiler.compile_source(src).expect("compile");
    let parsed = ProgramMetadata::parse(&code).expect("parse meta");
    assert_eq!(parsed.metadata.max_cycles, 42);
}
#[test]
fn zero_max_cycles_is_rejected_before_artifact_generation() {
    let compiler = Compiler::new_with_options(CompilerOptions {
        max_cycles: 0,
        ..CompilerOptions::default()
    });
    let error = compiler
        .compile_source("seiyaku InvalidBudget { hajimari() {} }")
        .expect_err("zero cycle ceiling must fail closed");
    assert!(error.contains("K4001"), "unexpected error: {error}");
    assert!(
        error.contains("max_cycles ceiling must be greater than zero"),
        "unexpected error: {error}"
    );
}
#[test]
fn loop_phi_lowering_is_deterministic() {
    let compiler = Compiler::new();
    let src = include_str!("fixtures/v1/c003.ko");
    let first = compiler.compile_source(src).expect("first compile");
    for _ in 0..8 {
        let next = compiler.compile_source(src).expect("repeat compile");
        assert_eq!(next, first);
    }
}
#[test]
fn emit_addi_zero_uses_addi_copy() {
    let mut code = Vec::new();
    emit_addi(&mut code, 5, 7, 0);
    assert_eq!(code.len(), 4);
    let word = u32::from_le_bytes(code[..4].try_into().unwrap());
    assert_eq!(
        word,
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 5, 7, 0)
    );
}
#[test]
fn emit_addi_combines_a_small_immediate_with_the_initial_copy() {
    let mut code = Vec::new();
    emit_addi(&mut code, 5, 7, 42);
    assert_eq!(code.len(), 4);
    let word = u32::from_le_bytes(code.try_into().expect("one addi word"));
    assert_eq!(
        word,
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 5, 7, 42)
    );
}
#[test]
fn emit_load64_uses_bounded_indexed_offset() {
    let mut code = Vec::new();
    let fixups = LiteralFixups::default();
    let offset = WIDE_IMM_MAX as i64 + 1;
    emit_load64(&mut code, &fixups, 5, 6, offset, None).expect("emit load64");
    let recorded = fixups.into_inner();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, 0);
    assert_eq!(recorded[0].1, super::LITERAL_SHIFT_REG);
    assert_eq!((recorded[0].2).0, DataKind::I64);
    patch_indexed_literal_load(
        &mut code,
        recorded[0].0,
        recorded[0].1,
        0,
        ivm_abi::metadata::LiteralKindV1::I64,
    );
    let words = code
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(words.len(), 3);
    assert_eq!(
        instruction::wide::opcode(words[0]),
        instruction::wide::memory::LDI64
    );
    assert_eq!(
        instruction::wide::opcode(words[1]),
        instruction::wide::arithmetic::ADD
    );
    assert_eq!(
        instruction::wide::opcode(words[2]),
        instruction::wide::memory::LOAD64
    );
}
#[test]
fn emit_store64_uses_bounded_indexed_offset() {
    let mut code = Vec::new();
    let fixups = LiteralFixups::default();
    let offset = WIDE_IMM_MAX as i64 + 1;
    emit_store64(&mut code, &fixups, 6, 5, offset, 7).expect("emit store64");
    let recorded = fixups.into_inner();
    assert_eq!(recorded.len(), 1);
    patch_indexed_literal_load(
        &mut code,
        recorded[0].0,
        recorded[0].1,
        0,
        ivm_abi::metadata::LiteralKindV1::I64,
    );
    let words = code
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(words.len(), 3);
    assert_eq!(
        instruction::wide::opcode(words[0]),
        instruction::wide::memory::LDI64
    );
    assert_eq!(
        instruction::wide::opcode(words[1]),
        instruction::wide::arithmetic::ADD
    );
    assert_eq!(
        instruction::wide::opcode(words[2]),
        instruction::wide::memory::STORE64
    );
}
#[test]
fn stack_slot_offsets_do_not_truncate_large_offsets() {
    let offset = i16::MAX as usize + 2048;
    let bytes = stack_slot_offset_bytes(8, offset);
    assert_eq!(bytes, 8i64 + offset as i64);
    assert!(bytes > i16::MAX as i64);
}
#[test]
fn stack_frame_alignment_is_checked_and_includes_odd_eight_byte_prefixes() {
    for (unpadded, expected) in [(0, 0), (8, 16), (16, 16), (24, 32), (4097, 4112)] {
        assert_eq!(
            crate::call_abi::checked_align_stack_frame_size(unpadded),
            Ok(expected),
            "unexpected alignment for {unpadded} bytes"
        );
    }
    assert!(crate::call_abi::checked_align_stack_frame_size(usize::MAX).is_err());
}
#[test]
fn indexed_literal_fixup_is_one_word() {
    let mut code = Vec::new();
    let start = reserve_word(&mut code);
    patch_literal_load(&mut code, start, 5, u16::MAX);
    assert_eq!(code.len(), 4);
    let word = u32::from_le_bytes(code[start..start + 4].try_into().unwrap());
    let (op, rd, index) = encoding::wide::decode_literal(word);
    assert_eq!(op, instruction::wide::memory::LDLIT);
    assert_eq!(rd, 5);
    assert_eq!(index, u16::MAX);
}
#[test]
fn far_jump_fixup_uses_one_word_signed24_transfer() {
    let mut code = Vec::new();
    let start = super::reserve_word(&mut code);
    super::patch_jump_transfer(&mut code, start, 200_000).expect("patch far jump");
    assert_eq!(code.len(), 4);
    let word = u32::from_le_bytes(code.try_into().unwrap());
    assert_eq!(
        instruction::wide::opcode(word),
        instruction::wide::control::JMP
    );
    assert_eq!(instruction::wide::imm24(word), 50_000);
}
#[test]
fn trampoline_jump_is_always_non_linking_and_range_checked() {
    let mut code = vec![0_u8; 4];
    super::patch_trampoline_jump(&mut code, 0, 4).expect("patch near trampoline hop");
    let word = u32::from_le_bytes(code.try_into().unwrap());
    assert_eq!(
        instruction::wide::opcode(word),
        instruction::wide::control::JMP,
        "even a near trampoline hop must not use a link-writing opcode"
    );
    assert_eq!(instruction::wide::imm24(word), 1);
    let mut code = vec![0_u8; 4];
    let first_out_of_range = 0x80_0000usize * 4;
    let error = super::patch_trampoline_jump(&mut code, 0, first_out_of_range)
        .expect_err("trampoline hops beyond signed24 must fail closed");
    assert!(error.contains("signed 24-bit word range"), "{error}");
}
#[test]
fn near_call_fixup_is_one_word_jal() {
    let mut code = Vec::new();
    let start = super::reserve_word(&mut code);
    super::patch_call_transfer(&mut code, start, start + 16).expect("patch near call");
    assert_eq!(code.len(), 4);
    let call_word = u32::from_le_bytes(code[start..start + 4].try_into().unwrap());
    assert_eq!(
        call_word,
        super::encode_jal(1, 16).expect("encode short call")
    );
}
#[test]
fn far_call_fixup_uses_one_word_signed24_transfer() {
    let mut code = Vec::new();
    let start = super::reserve_word(&mut code);
    super::patch_call_transfer(&mut code, start, 200_000).expect("patch far call");
    assert_eq!(code.len(), 4);
    let word = u32::from_le_bytes(code.try_into().unwrap());
    assert_eq!(
        instruction::wide::opcode(word),
        instruction::wide::control::JALS
    );
    assert_eq!(instruction::wide::imm24(word), 50_000);
}
#[test]
fn transfer_beyond_signed24_is_deferred_instead_of_rejected() {
    let mut code = Vec::new();
    let at = reserve_word(&mut code);
    let target = (0x80_0000usize + 1) * 4;
    let mut deferred = Vec::new();
    super::patch_or_defer_transfer(&mut code, at, target, TransferKind::Call, &mut deferred)
        .expect("far call must be deferred");
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].at, at);
    assert_eq!(deferred[0].target, target);
    assert_eq!(deferred[0].kind, TransferKind::Call);
    assert_eq!(
        u32::from_le_bytes(code.try_into().unwrap()),
        super::encode_nop()
    );
}
#[test]
fn ordinary_control_relaxation_is_byte_identical() {
    let mut code = Vec::new();
    push_word(&mut code, encode_jal(0, 8).expect("short jump must encode"));
    push_word(&mut code, encode_nop());
    push_word(&mut code, encoding::wide::encode_halt());
    let expected = code.clone();
    let (relaxed, offsets) =
        relax_control_transfers_with_trampolines(code, &[], 32).expect("relax near code");
    assert_eq!(relaxed, expected);
    assert!(offsets.islands.is_empty());
    assert_eq!(offsets.entry(8), 8);
    assert_eq!(offsets.instruction(8), 8);
}
#[test]
fn trampoline_relaxation_rejects_duplicate_or_out_of_image_fixups() {
    let code = encoding::wide::encode_halt().to_le_bytes().to_vec();
    let duplicate = DeferredTransfer {
        at: 0,
        target: 0,
        kind: TransferKind::Jump,
    };
    assert!(
        relax_control_transfers_with_trampolines(code.clone(), &[duplicate, duplicate], 32,)
            .expect_err("duplicate fixup sources must fail")
            .contains("duplicate")
    );
    assert!(
        relax_control_transfers_with_trampolines(
            code,
            &[DeferredTransfer {
                at: 0,
                target: 4,
                kind: TransferKind::Jump,
            }],
            32,
        )
        .expect_err("out-of-image target must fail")
        .contains("outside")
    );
}
#[test]
fn deferred_far_jump_uses_sparse_direct_trampoline_chain() {
    let mut code = Vec::new();
    let source = reserve_word(&mut code);
    for _ in 0..31 {
        push_word(&mut code, encode_nop());
    }
    let target = code.len();
    push_word(&mut code, encoding::wide::encode_halt());
    let deferred = [DeferredTransfer {
        at: source,
        target,
        kind: TransferKind::Jump,
    }];
    let (relaxed, offsets) =
        relax_control_transfers_with_trampolines(code, &deferred, 32).expect("relax deferred jump");
    assert!(offsets.islands.len() >= 3);
    assert_eq!(
        relaxed.len(),
        33 * 4 + offsets.islands.len() * TRAMPOLINE_ISLAND_BYTES
    );
    let mut pc = offsets.instruction(source);
    let expected_target = offsets.entry(target);
    for _ in 0..=offsets.islands.len() {
        let word = u32::from_le_bytes(relaxed[pc..pc + 4].try_into().unwrap());
        assert!(matches!(
            instruction::wide::opcode(word),
            instruction::wide::control::JAL | instruction::wide::control::JMP
        ));
        let offset_words = match instruction::wide::opcode(word) {
            instruction::wide::control::JAL => i64::from(instruction::wide::imm16(word)),
            instruction::wide::control::JMP => i64::from(instruction::wide::imm24(word)),
            _ => unreachable!(),
        };
        pc = decoded_control_target(pc, offset_words).expect("valid trampoline target");
    }
    assert_eq!(pc, expected_target);
    let halt = u32::from_le_bytes(relaxed[pc..pc + 4].try_into().unwrap());
    assert_eq!(
        instruction::wide::opcode(halt),
        instruction::wide::control::HALT
    );
    assert!(relaxed.chunks_exact(4).all(|word| {
        !matches!(
            instruction::wide::opcode(u32::from_le_bytes(word.try_into().unwrap())),
            instruction::wide::control::JR | instruction::wide::control::JALR
        )
    }));
}
#[test]
fn deferred_far_call_links_once_and_trampolines_without_relinking() {
    let mut code = Vec::new();
    let source = reserve_word(&mut code);
    for _ in 0..23 {
        push_word(&mut code, encode_nop());
    }
    let target = code.len();
    push_word(&mut code, encoding::wide::encode_halt());
    let deferred = [DeferredTransfer {
        at: source,
        target,
        kind: TransferKind::Call,
    }];
    let (relaxed, offsets) =
        relax_control_transfers_with_trampolines(code, &deferred, 24).expect("relax deferred call");
    let source = offsets.instruction(source);
    let source_word =
        u32::from_le_bytes(relaxed[source..source + 4].try_into().expect("source word"));
    assert!(matches!(
        instruction::wide::opcode(source_word),
        instruction::wide::control::JAL | instruction::wide::control::JALS
    ));
    if instruction::wide::opcode(source_word) == instruction::wide::control::JAL {
        assert_eq!(instruction::wide::rd(source_word), 1);
    }
    for island in &offsets.islands {
        let at = offsets.island_instruction(*island);
        let word = u32::from_le_bytes(relaxed[at..at + 4].try_into().unwrap());
        assert_eq!(
            instruction::wide::opcode(word),
            instruction::wide::control::JMP,
            "trampoline hops must preserve the original return address"
        );
    }
}
#[test]
fn indexed_literal_count_accepts_full_u16_domain() {
    assert!(super::validate_literal_count(usize::from(u16::MAX) + 1).is_ok());
    assert!(super::validate_literal_count(usize::from(u16::MAX) + 2).is_err());
}
#[test]
fn literal_and_call_heavy_minimal_program_has_no_stub_padding() {
    let source = include_str!("fixtures/v1/c004.ko");
    let (bytes, _manifest, report) = test_mode_compiler()
        .compile_source_with_manifest_and_report(source)
        .expect("compile compact literal/call program");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse compact program metadata");
    assert!(
        parsed.contract_debug.is_none(),
        "deployable V1 artifacts must not embed DBG1"
    );
    assert!(
        !report.source_map.is_empty(),
        "source maps remain available in the compile-report sidecar"
    );
    assert_eq!(
        report.artifact_hash,
        crate::metadata::contract_code_hash(&bytes)
    );
    let code = &bytes[parsed.code_offset..];
    let words = code
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("instruction word")))
        .collect::<Vec<_>>();
    assert!(
        words
            .iter()
            .any(|word| instruction::wide::opcode(*word) == instruction::wide::memory::LDLIT),
        "literal return must use indexed LDLIT"
    );
    assert!(
        words.iter().all(|word| *word != super::encode_nop()),
        "all one-word relocation placeholders must be patched"
    );
    assert!(
        code.len() <= 128,
        "minimal literal/call code unexpectedly retained relocation padding: {} bytes",
        code.len()
    );
}
#[test]
fn parameterized_entrypoint_uses_the_host_prepared_argument_table() {
    let source = include_str!("fixtures/v1/c005.ko");
    let bytes = test_mode_compiler()
        .compile_source(source)
        .expect("compile parameterized entrypoint");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse argument program metadata");
    let words = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("instruction word")))
        .collect::<Vec<_>>();
    let record_decodes = words
        .iter()
        .filter(|word| {
            instruction::wide::opcode(**word) == instruction::wide::system::SYSTEM
                && encoding::wide::decode_syscallx(**word)
                    == syscalls::SYSCALL_DECODE_ARGUMENT_RECORD
        })
        .count();
    assert_eq!(
        record_decodes, 0,
        "record preparation happens before guest execution"
    );
    let typed_getters = [
        syscalls::SYSCALL_JSON_GET_INT,
        syscalls::SYSCALL_JSON_GET_DECIMAL,
        syscalls::SYSCALL_JSON_GET_QUANTITY,
        syscalls::SYSCALL_JSON_GET_JSON,
        syscalls::SYSCALL_JSON_GET_NAME,
        syscalls::SYSCALL_JSON_GET_ACCOUNT_ID,
        syscalls::SYSCALL_JSON_GET_NFT_ID,
        syscalls::SYSCALL_JSON_GET_BLOB_HEX,
        syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID,
    ];
    assert!(words.iter().all(|word| {
        instruction::wide::opcode(*word) != instruction::wide::system::SYSTEM
            || !typed_getters.contains(&encoding::wide::decode_syscallx(*word))
    }));
}
#[test]
fn sum_type_join_fallbacks_do_not_become_false_constant_facts() {
    let source = include_str!("fixtures/v1/c006.ko");
    let bytes = test_mode_compiler()
        .compile_source(source)
        .expect("compile sum-type join fixture");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse sum-type join metadata");
    let add_count = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("instruction word")))
        .filter(|word| {
            instruction::wide::opcode(*word) == instruction::wide::system::SYSTEM
                && encoding::wide::decode_syscallx(*word) == syscalls::SYSCALL_INT_ADD
        })
        .count();
    assert_eq!(
        add_count, 1,
        "dynamic Option/Result joins must retain the checked source addition"
    );
}
#[test]
fn computation_samples_publish_only_public_views() {
    use iroha_data_model::smart_contract::manifest::{EntryPointKind, EntrypointAuthorizationV1};
    let sources = [
        (
            "tuple_return_demo.ko",
            include_str!("../samples/tuple_return_demo.ko"),
        ),
        (
            "02_view_public_fn.ko",
            include_str!("../../../ivm/docs/examples/02_view_public_fn.ko"),
        ),
        (
            "04_foreach_map.ko",
            include_str!("../../../ivm/docs/examples/04_foreach_map.ko"),
        ),
        (
            "05_range_for.ko",
            include_str!("../../../ivm/docs/examples/05_range_for.ko"),
        ),
        (
            "14_map_sum_take2.ko",
            include_str!("../../../ivm/docs/examples/14_map_sum_take2.ko"),
        ),
        (
            "15_modulo.ko",
            include_str!("../../../ivm/docs/examples/15_modulo.ko"),
        ),
        (
            "18_ternary.ko",
            include_str!("../../../ivm/docs/examples/18_ternary.ko"),
        ),
    ];
    for (name, source) in sources {
        let (_, manifest) = Compiler::new()
            .compile_source_with_manifest(source)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(manifest.permissions.is_empty(), "{name}: no mutation roles");
        let entrypoints = manifest
            .entrypoints
            .as_ref()
            .expect("public view descriptors");
        assert_eq!(entrypoints.len(), 1, "{name}");
        let entrypoint = &entrypoints[0];
        assert_eq!(entrypoint.kind, EntryPointKind::View, "{name}");
        assert_eq!(
            entrypoint.authorization,
            EntrypointAuthorizationV1::Anyone,
            "{name}"
        );
    }
}
#[test]
fn mint_trigger_takes_amount_from_one_typed_argument_record() {
    let source = include_str!("../samples/mint_rose_trigger.ko");
    let output = test_mode_compiler()
        .compile_source_output(source, None)
        .expect("compile typed mint trigger callback");
    let bytes = output.artifact;
    let parsed = ProgramMetadata::parse(&bytes).expect("parse trigger metadata");
    assert!(
        parsed.contract_interface.is_none(),
        "local test harness must keep its interface in the sidecar"
    );
    let run = output
        .contract_interface
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run callback descriptor");
    let schema = run
        .argument_schema
        .as_ref()
        .expect("typed trigger argument schema");
    assert_eq!(schema.fields.len(), 1);
    assert_eq!(schema.fields[0].name, "val");
    assert!(matches!(
        schema.fields[0].ty.nodes.as_slice(),
        [ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Leaf(
            ivm_abi::entrypoint::EntrypointValueKindV1::Quantity
        )]
    ));
    let words = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("instruction word")))
        .collect::<Vec<_>>();
    let record_decodes = words
        .iter()
        .filter(|word| {
            instruction::wide::opcode(**word) == instruction::wide::system::SYSTEM
                && encoding::wide::decode_syscallx(**word)
                    == syscalls::SYSCALL_DECODE_ARGUMENT_RECORD
        })
        .count();
    assert_eq!(
        record_decodes, 0,
        "trigger records are prepared before guest execution"
    );
    assert!(words.iter().all(|word| {
        instruction::wide::opcode(*word) != instruction::wide::system::SYSTEM
            || encoding::wide::decode_syscallx(*word) != syscalls::SYSCALL_JSON_GET_QUANTITY
    }));
}
fn call_graph_function(name: &str, instructions: Vec<ir::Instr>) -> ir::Function {
    ir::Function {
        name: name.to_owned(),
        params: Vec::new(),
        blocks: vec![ir::BasicBlock {
            label: ir::Label(0),
            instrs: instructions,
            terminator: ir::Terminator::Return(None),
        }],
        entry: ir::Label(0),
        location: crate::ast::SourceLocation { line: 1, column: 1 },
    }
}
fn direct_call(callee: &str) -> ir::Instr {
    ir::Instr::Call {
        callee: callee.to_owned(),
        args: Vec::new(),
        dest: None,
    }
}
#[test]
fn bool_state_map_keys_do_not_emit_public_int_codec_syscalls() {
    let artifact = Compiler::new()
        .compile_source(
            r#"seiyaku Test { permission Entry;
  state StateMap<bool, int> Foo;
  kotoage fn main() authorize(Entry) {
    Foo[true] = 2;
    let _x = Foo.get(true);
  }
}"#,
        )
        .expect("compile Bool-key StateMap fixture");
    let metadata = ProgramMetadata::parse(&artifact).expect("V1 metadata");
    let retired_bool_codec_words = [
        encoding::wide::encode_sys(instruction::wide::system::SCALL, 0x53_u8),
        encoding::wide::encode_sys(instruction::wide::system::SCALL, 0x55_u8),
    ];
    let executable = &artifact[metadata.code_offset..];
    assert!(executable.chunks_exact(4).all(|chunk| {
        let word = u32::from_le_bytes(chunk.try_into().expect("word"));
        !retired_bool_codec_words.contains(&word)
    }));
}
#[test]
fn access_hints_propagate_transitively_through_helper_calls() {
    let program = ir::Program {
        functions: vec![
            call_graph_function("entry", vec![direct_call("middle")]),
            call_graph_function("middle", vec![direct_call("leaf")]),
            call_graph_function("leaf", Vec::new()),
        ],
    };
    let mut access_sets = vec![super::AccessSets::default(); 3];
    access_sets[2].reads.insert("state:secret".to_owned());
    access_sets[2]
        .writes
        .insert(super::STATE_WILDCARD_KEY.to_owned());
    let mut hint_skips = vec![IndexSet::new(); 3];
    hint_skips[2].insert(super::HINT_SKIP_DYNAMIC_STATE_PATH.to_owned());
    super::propagate_transitive_access_hints(&program, &mut access_sets, &mut hint_skips);
    for index in [0, 1] {
        assert!(access_sets[index].reads.contains("state:secret"));
        assert!(
            access_sets[index]
                .writes
                .contains(super::STATE_WILDCARD_KEY)
        );
        assert!(
            hint_skips[index].contains(super::HINT_SKIP_DYNAMIC_STATE_PATH),
            "callee incompleteness must propagate to caller {index}"
        );
    }
}
#[test]
fn access_hint_fixed_point_handles_recursive_ir_cycles() {
    let program = ir::Program {
        functions: vec![
            call_graph_function("left", vec![direct_call("right")]),
            call_graph_function("right", vec![direct_call("left")]),
        ],
    };
    let mut access_sets = vec![super::AccessSets::default(); 2];
    access_sets[0].reads.insert("state:left".to_owned());
    access_sets[1].writes.insert("state:right".to_owned());
    let mut hint_skips = vec![IndexSet::new(); 2];
    super::propagate_transitive_access_hints(&program, &mut access_sets, &mut hint_skips);
    for access in &access_sets {
        assert!(access.reads.contains("state:left"));
        assert!(access.writes.contains("state:right"));
    }
}
#[test]
fn unresolved_and_indirect_calls_are_conservative() {
    let program = ir::Program {
        functions: vec![
            call_graph_function("unresolved", vec![direct_call("missing")]),
            call_graph_function(
                "indirect",
                vec![ir::Instr::InvokeEntrypointAs {
                    dest: Some(ir::Temp(0)),
                    actor: Some(ir::Temp(1)),
                    entrypoint: ir::Temp(2),
                    payload: ir::Temp(3),
                    argument_words: 0,
                }],
            ),
        ],
    };
    let mut access_sets = vec![super::AccessSets::default(); 2];
    let mut hint_skips = vec![IndexSet::new(); 2];
    super::propagate_transitive_access_hints(&program, &mut access_sets, &mut hint_skips);
    for access_set in &access_sets {
        assert!(access_set.reads.contains(super::GLOBAL_WILDCARD_KEY));
        assert!(access_set.writes.contains(super::GLOBAL_WILDCARD_KEY));
    }
    assert!(hint_skips[0].contains(super::HINT_SKIP_INTERNAL_CALL_TARGET));
    assert!(hint_skips[1].contains(super::HINT_SKIP_CONTRACT_CALL_TARGET));
}
#[test]
fn entrypoint_hints_include_access_hidden_behind_helper_chain() {
    let source = include_str!("fixtures/v1/c007.ko");
    let output = test_mode_compiler()
        .compile_source_output(source, None)
        .expect("compile helper-hidden state access");
    assert!(
        ProgramMetadata::parse(&output.artifact)
            .expect("parse artifact")
            .contract_interface
            .is_none(),
        "local test harness must keep its interface in the sidecar"
    );
    let run = output
        .contract_interface
        .entrypoints
        .into_iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    assert!(run.write_keys.contains(&"state:counter".to_owned()));
    assert_eq!(run.access_hints_complete, Some(true));
    assert!(run.access_hints_skipped.is_empty());
}
#[test]
fn entrypoint_hints_inherit_helper_incompleteness() {
    let source = include_str!("fixtures/v1/c008.ko");
    let output = test_mode_compiler()
        .compile_source_output(source, None)
        .expect("compile helper-hidden dynamic access");
    assert!(
        ProgramMetadata::parse(&output.artifact)
            .expect("parse artifact")
            .contract_interface
            .is_none(),
        "local test harness must keep its interface in the sidecar"
    );
    let run = output
        .contract_interface
        .entrypoints
        .into_iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    assert_eq!(run.access_hints_complete, Some(false));
    assert!(
        run.access_hints_skipped
            .contains(&super::HINT_SKIP_DYNAMIC_STATE_PATH.to_owned())
    );
}
#[test]
fn unknown_state_path_call_before_literal_keeps_helper_hints_conservative() {
    let source = include_str!("fixtures/v1/c009.ko");
    let output = test_mode_compiler()
        .compile_source_output(source, None)
        .expect("compile mixed dynamic/literal helper calls");
    for name in ["dynamic", "literal"] {
        let entrypoint = output
            .contract_interface
            .entrypoints
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("missing {name} entrypoint"));
        assert_eq!(
            entrypoint.read_keys,
            vec![super::STATE_WILDCARD_KEY.to_owned()],
            "the dynamic state path requires the exact state wildcard"
        );
        assert_eq!(entrypoint.access_hints_complete, Some(false));
        assert!(
            entrypoint
                .access_hints_skipped
                .contains(&super::HINT_SKIP_DYNAMIC_STATE_PATH.to_owned())
        );
    }
}
#[test]
fn unknown_ledger_argument_before_literal_keeps_helper_hints_conservative() {
    let source = r#"
seiyaku CompilerFixture { permission FixtureAccess;
  fn remove_role(Name _ role) {
    ledger::role::unregister(role: role);
  }

  kotoage fn main(Name dynamic_role) authorize(FixtureAccess) {
    remove_role(dynamic_role);
    remove_role(Name::parse("auditor"));
  }
}
"#;
    let (_artifact, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .expect("compile mixed dynamic/literal ledger helper calls");
    let hints = manifest
        .access_set_hints
        .expect("mixed helper calls must retain conservative access hints");
    assert!(hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_owned()));
    assert!(hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_owned()));
    assert!(!hints.read_keys.contains(&"role:auditor".to_owned()));
    assert!(!hints.write_keys.contains(&"role:auditor".to_owned()));
    let main = manifest
        .entrypoints
        .expect("entrypoints present")
        .into_iter()
        .find(|entrypoint| entrypoint.name == "main")
        .expect("main entrypoint");
    assert!(main.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_owned()));
    assert!(main.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_owned()));
    assert_eq!(main.access_hints_complete, Some(false));
    assert!(
        main.access_hints_skipped
            .contains(&HINT_SKIP_OPAQUE_ISI.to_owned())
    );
}
#[test]
fn dynamic_account_before_authority_keeps_helper_hints_conservative() {
    let source = r#"
seiyaku CompilerFixture { permission FixtureAccess;
  fn remove_account(AccountId _ account) {
    ledger::account::unregister(account: account);
  }

  kotoage fn main(AccountId dynamic_account) authorize(FixtureAccess) {
    remove_account(dynamic_account);
    remove_account(context::authority());
  }
}
"#;
    let (_artifact, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .expect("compile mixed dynamic/authority account helper calls");
    let hints = manifest
        .access_set_hints
        .expect("mixed account helper calls must retain conservative access hints");
    assert!(hints.read_keys.contains(&ACCOUNT_WILDCARD_KEY.to_owned()));
    assert!(hints.write_keys.contains(&ACCOUNT_WILDCARD_KEY.to_owned()));
    assert!(!hints.read_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    assert!(!hints.write_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    let main = manifest
        .entrypoints
        .expect("entrypoints present")
        .into_iter()
        .find(|entrypoint| entrypoint.name == "main")
        .expect("main entrypoint");
    assert!(main.read_keys.contains(&ACCOUNT_WILDCARD_KEY.to_owned()));
    assert!(main.write_keys.contains(&ACCOUNT_WILDCARD_KEY.to_owned()));
    assert!(!main.read_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    assert!(!main.write_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[test]
fn encode_addi_rejects_out_of_range_immediate() {
    let imm = (WIDE_IMM_MAX + 1) as i16;
    assert!(super::encode_addi(1, 1, imm).is_err());
}
#[test]
fn parallel_abi_moves_preserve_cycles_and_are_deterministic() {
    let moves = vec![(10, 11), (11, 12), (12, 10), (13, 14)];
    let mut code = Vec::new();
    emit_parallel_register_moves(&mut code, moves.clone(), 27)
        .expect("emit parallel ABI move cycle");
    let mut second = Vec::new();
    emit_parallel_register_moves(&mut second, moves, 27).expect("repeat parallel ABI move cycle");
    assert_eq!(code, second);
    let mut registers = [0u64; 32];
    registers[10] = 10;
    registers[11] = 11;
    registers[12] = 12;
    registers[13] = 13;
    registers[14] = 14;
    for word in code.chunks_exact(4) {
        let word = u32::from_le_bytes(word.try_into().expect("instruction word"));
        let (opcode, destination, source, immediate) = encoding::wide::decode_ri(word);
        assert_eq!(opcode, instruction::wide::arithmetic::ADDI);
        assert_eq!(immediate, 0);
        registers[usize::from(destination)] = registers[usize::from(source)];
    }
    assert_eq!(registers[10], 11);
    assert_eq!(registers[11], 12);
    assert_eq!(registers[12], 10);
    assert_eq!(registers[13], 14);
}
#[test]
fn private_numeric_valcom_staging_preserves_cross_aliased_operands() {
    let mut code = Vec::new();
    emit_private_numeric_valcom_arguments(&mut code, 11, 10, 29)
        .expect("stage cross-aliased private commitment operands");
    let mut registers = [0u64; 32];
    registers[10] = 101;
    registers[11] = 202;
    for word in code.chunks_exact(4) {
        let (opcode, destination, source, immediate) = encoding::wide::decode_ri(
            u32::from_le_bytes(word.try_into().expect("instruction word")),
        );
        assert_eq!(opcode, instruction::wide::arithmetic::ADDI);
        assert_eq!(immediate, 0);
        registers[usize::from(destination)] = registers[usize::from(source)];
    }
    assert_eq!(registers[10], 202);
    assert_eq!(registers[11], 101);
}
#[test]
fn get_private_input_staging_preserves_index_aliased_with_kind_register() {
    for kind in [
        ivm_abi::private_input::PrivateInputKindV1::Int,
        ivm_abi::private_input::PrivateInputKindV1::Decimal,
        ivm_abi::private_input::PrivateInputKindV1::Quantity,
    ] {
        let mut code = Vec::new();
        emit_get_private_input_arguments(&mut code, 11, kind, 29)
            .expect("stage private-input index and kind");
        let mut registers = [0u64; 32];
        registers[11] = 37;
        for word in code.chunks_exact(4) {
            let (opcode, destination, source, immediate) = encoding::wide::decode_ri(
                u32::from_le_bytes(word.try_into().expect("instruction word")),
            );
            assert_eq!(opcode, instruction::wide::arithmetic::ADDI);
            registers[usize::from(destination)] =
                registers[usize::from(source)].wrapping_add_signed(i64::from(immediate));
        }
        assert_eq!(registers[10], 37);
        assert_eq!(registers[11], kind.tag());
    }
}
#[test]
fn private_numeric_staging_rejects_reserved_scratch_aliases_without_emitting_code() {
    let mut commitment_code = Vec::new();
    let commitment_error = emit_private_numeric_valcom_arguments(&mut commitment_code, 29, 10, 29)
        .expect_err("commitment source must not alias staging scratch");
    assert!(commitment_error.contains("reserved scratch register"));
    assert!(commitment_code.is_empty());
    let mut private_input_code = Vec::new();
    let private_input_error = emit_get_private_input_arguments(
        &mut private_input_code,
        29,
        ivm_abi::private_input::PrivateInputKindV1::Int,
        29,
    )
    .expect_err("private-input index must not alias staging scratch");
    assert!(private_input_error.contains("reserved scratch register"));
    assert!(private_input_code.is_empty());
}
#[test]
fn encode_load64_rejects_out_of_range_offset() {
    let imm = (WIDE_IMM_MAX + 1) as i16;
    assert!(super::encode_load64_rv(1, 2, imm).is_err());
}
#[test]
fn encode_store64_rejects_out_of_range_offset() {
    let imm = (WIDE_IMM_MAX + 1) as i16;
    assert!(super::encode_store64_rv(1, 2, imm).is_err());
}
#[test]
fn encode_branch_rejects_unaligned_offsets() {
    assert!(super::encode_branch_rv(0x0, 1, 2, 2).is_err());
}
#[test]
fn encode_jal_rejects_unaligned_offsets() {
    assert!(super::encode_jal(0, 2).is_err());
}
#[test]
fn emit_load64_requires_scratch_when_rd_equals_base() {
    let mut code = Vec::new();
    let fixups = LiteralFixups::default();
    let err = emit_load64(&mut code, &fixups, 5, 5, 0, None).unwrap_err();
    assert!(err.contains("emit_load64 requires scratch"));
}
#[test]
fn emit_store64_requires_distinct_scratch() {
    let mut code = Vec::new();
    let fixups = LiteralFixups::default();
    let err = emit_store64(&mut code, &fixups, 5, 6, 256, 5).unwrap_err();
    assert!(err.contains("emit_store64 scratch"));
}
#[test]
fn decode_hex_or_raw_bytes_accepts_hex_prefix() {
    let bytes = super::decode_hex_or_raw_bytes("0x0a0b").expect("hex literal");
    assert_eq!(bytes, vec![0x0a, 0x0b]);
}
#[test]
fn decode_hex_or_raw_bytes_preserves_raw_text() {
    let bytes = super::decode_hex_or_raw_bytes("raw").expect("raw literal");
    assert_eq!(bytes, b"raw".to_vec());
}
#[test]
fn unary_neg_emits_exact_int_syscall() {
    let src = include_str!("fixtures/v1/c010.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler.compile_source(src).expect("compile neg");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let mut found = false;
    for chunk in bytes[parsed.code_offset..].chunks_exact(4) {
        let word = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap());
        if instruction::wide::opcode(word) == instruction::wide::system::SYSTEM
            && encoding::wide::decode_syscallx(word) == syscalls::SYSCALL_INT_NEG
        {
            found = true;
            break;
        }
    }
    assert!(found, "expected INT_NEG syscall in compiled code");
}
#[test]
fn signed_comparison_plans_match_i64_ordering_boundaries() {
    let values = [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX];
    for op in [BinaryOp::Lt, BinaryOp::Le, BinaryOp::Gt, BinaryOp::Ge] {
        for left in values {
            for right in values {
                let expected = match op {
                    BinaryOp::Lt => left < right,
                    BinaryOp::Le => left <= right,
                    BinaryOp::Gt => left > right,
                    BinaryOp::Ge => left >= right,
                    _ => unreachable!(),
                };
                let register = |index| match index {
                    0 => left,
                    1 => right,
                    _ => panic!("unexpected comparison-plan register {index}"),
                };
                let (cmp_left, cmp_right, invert) =
                    super::signed_compare_plan(op, 0, 1).expect("signed comparison plan");
                let comparison = register(cmp_left) < register(cmp_right);
                assert_eq!(
                    comparison ^ invert,
                    expected,
                    "value plan mismatch for {left} {op:?} {right}"
                );
                let (funct3, branch_left, branch_right) =
                    super::signed_branch_plan(op, 0, 1).expect("signed branch plan");
                let branch = match funct3 {
                    0x4 => register(branch_left) < register(branch_right),
                    0x5 => register(branch_left) >= register(branch_right),
                    _ => panic!("unexpected signed branch selector {funct3}"),
                };
                assert_eq!(
                    branch, expected,
                    "branch plan mismatch for {left} {op:?} {right}"
                );
            }
        }
    }
}
#[test]
fn adaptive_int_comparisons_use_exact_numeric_syscalls() {
    let src = include_str!("fixtures/v1/c011.ko");
    let bytes = test_mode_compiler()
        .compile_source(src)
        .expect("compile signed comparisons");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let words = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("instruction word")))
        .collect::<Vec<_>>();
    for syscall in [
        syscalls::SYSCALL_INT_LT,
        syscalls::SYSCALL_INT_LE,
        syscalls::SYSCALL_INT_GT,
        syscalls::SYSCALL_INT_GE,
    ] {
        assert!(
            words.iter().any(|word| {
                instruction::wide::opcode(*word) == instruction::wide::system::SYSTEM
                    && encoding::wide::decode_syscallx(*word) == syscall
            }),
            "missing exact adaptive-int comparison syscall {}",
            syscalls::syscall_name(syscall).unwrap_or("UNKNOWN")
        );
    }
    assert!(
        words.iter().all(|word| {
            !matches!(
                instruction::wide::opcode(*word),
                instruction::wide::arithmetic::SLT
                    | instruction::wide::control::BLT
                    | instruction::wide::control::BGE
                    | instruction::wide::arithmetic::SUB
                    | instruction::wide::arithmetic::SRA
            )
        }),
        "adaptive int pointers must never enter scalar signed comparison opcodes"
    );
}
#[test]
fn logical_operators_emit_control_flow_instead_of_eager_bitwise_ops() {
    let src = include_str!("fixtures/v1/c012.ko");
    let bytes = test_mode_compiler()
        .compile_source(src)
        .expect("compile short-circuit expressions");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let opcodes = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| {
            instruction::wide::opcode(u32::from_le_bytes(
                chunk.try_into().expect("instruction word"),
            ))
        })
        .collect::<Vec<_>>();
    assert!(
        opcodes.contains(&instruction::wide::control::BNE),
        "logical expressions must branch before the right-hand side"
    );
    assert!(
        !opcodes.contains(&instruction::wide::arithmetic::AND),
        "logical && must not compile to eager bitwise AND"
    );
    assert!(
        !opcodes.contains(&instruction::wide::arithmetic::OR),
        "logical || must not compile to eager bitwise OR"
    );
}
#[test]
fn get_quantity_emits_typed_option_quantity_syscall() {
    let src = include_str!("fixtures/v1/c013.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler.compile_source(src).expect("compile get_quantity");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle =
        encoding::wide::encode_syscallx(ivm_abi::syscalls::SYSCALL_JSON_GET_QUANTITY).to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected JSON_GET_QUANTITY syscall in compiled code"
    );
}
#[test]
fn get_asset_definition_id_emits_asset_definition_syscall() {
    let src = include_str!("fixtures/v1/c014.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(src)
        .expect("compile get_asset_definition_id");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected JSON_GET_ASSET_DEFINITION_ID syscall in compiled code"
    );
}
#[test]
fn native_escrow_builtins_emit_escrow_syscalls() {
    let src = include_str!("fixtures/v1/c015.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(src)
        .expect("compile native escrow builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_ESCROW_OPEN_OFFER,
            "ESCROW_OPEN_OFFER",
        ),
        (ivm_abi::syscalls::SYSCALL_ESCROW_ACCEPT, "ESCROW_ACCEPT"),
        (
            ivm_abi::syscalls::SYSCALL_ESCROW_MARK_PAYMENT_SENT,
            "ESCROW_MARK_PAYMENT_SENT",
        ),
        (ivm_abi::syscalls::SYSCALL_ESCROW_RELEASE, "ESCROW_RELEASE"),
        (ivm_abi::syscalls::SYSCALL_ESCROW_CANCEL, "ESCROW_CANCEL"),
        (
            ivm_abi::syscalls::SYSCALL_ESCROW_OPEN_DISPUTE,
            "ESCROW_OPEN_DISPUTE",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ESCROW_RESOLVE_DISPUTE,
            "ESCROW_RESOLVE_DISPUTE",
        ),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("escrow syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
}
#[test]
fn native_escrow_builtins_report_literal_access_hints() {
    let asset_def = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission EscrowAdmin;

kotoage fn main() authorize(EscrowAdmin) {{
  let evidence = b"00";
  ledger::escrow::open_offer(
    offer: Name::parse("aitai_offer"),
    asset_definition: AssetDefinitionId::parse("{asset_def}"),
    amount: 10,
    evidence: evidence,
  );
  ledger::escrow::accept(offer: Name::parse("aitai_offer"));
  ledger::escrow::mark_payment_sent(offer: Name::parse("aitai_offer"));
  ledger::escrow::release(offer: Name::parse("aitai_offer"));
  ledger::escrow::cancel(offer: Name::parse("aitai_offer"));
  ledger::escrow::open_dispute(offer: Name::parse("aitai_offer"), evidence: evidence);
  ledger::escrow::resolve_dispute(
    offer: Name::parse("aitai_offer"),
    buyer_amount: 6,
    seller_amount: 4,
    evidence: evidence,
  );
}}

}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile native escrow access hints");
    let hints = manifest
        .access_set_hints
        .expect("expected native escrow access hints");
    let escrow_hash = kotodama_escrow_hex("aitai_offer");
    for key in [
        format!("escrow_id:{escrow_hash}"),
        format!("asset_escrow:{escrow_hash}"),
        format!("asset_def:{asset_def}"),
        format!("asset:{asset_def}:$authority"),
    ] {
        assert!(hints.read_keys.contains(&key), "missing read key {key}");
        assert!(hints.write_keys.contains(&key), "missing write key {key}");
    }
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[test]
fn escrow_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c016.ko"),
            "ledger::escrow::open_offer expects (Name, AssetDefinitionId, quantity[, bytes evidence_hashes])",
        ),
        (
            include_str!("fixtures/v1/c017.ko"),
            "ledger::escrow::accept expects (Name)",
        ),
        (
            include_str!("fixtures/v1/c018.ko"),
            "ledger::escrow::open_dispute expects (Name[, bytes evidence_hashes])",
        ),
        (
            include_str!("fixtures/v1/c019.ko"),
            "ledger::escrow::resolve_dispute expects (Name, quantity, quantity[, bytes evidence_hashes])",
        ),
    ] {
        let parsed = parse(src).expect("parse invalid escrow source");
        let err = analyze(&parsed).expect_err("semantic analysis should reject escrow args");
        assert!(
            err.message.contains(expected),
            "expected error containing {expected:?}, got {}",
            err.message
        );
    }
}
#[test]
fn soracloud_envelopes_and_host_calls_are_not_source_apis() {
    for source in [
        "fn main(SoracloudRequest request) {}",
        "fn main(SoracloudResponse response) {}",
    ] {
        let error = test_mode_compiler()
            .compile_source(&format!("seiyaku CompilerFixture {{ {source} }}"))
            .expect_err("opaque Soracloud capabilities must remain compiler-internal");
        assert!(
            error.contains("unknown type") || error.contains("unknown function or builtin"),
            "unexpected Soracloud surface error: {error}"
        );
    }
    assert_internal_source_names_rejected(&[
        "soracloud_request",
        "soracloud_response",
        "soracloud::read_committed_state",
        "soracloud::emit_state_mutation",
        "soracloud::emit_mailbox_message",
        "soracloud::append_journal",
        "soracloud::publish_checkpoint",
        "soracloud::read_secret",
        "soracloud::read_credential",
        "soracloud::egress_fetch",
        "soracloud::read_config",
        "soracloud::read_secret_envelope",
    ]);
}
#[test]
fn static_account_multisig_admin_builtins_emit_exact_account_hints() {
    let account = sample_account_literal();
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission FixtureAccess;

kotoage fn main() authorize(FixtureAccess) {{
  let account = AccountId::parse("{account}");
  let signatory = Json::parse("\"ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774\"");
  ledger::account::add_signatory(account: account, signatory: signatory);
  ledger::account::remove_signatory(account: account, signatory: signatory);
  ledger::account::set_quorum(account: account, quorum: 2);
}}

}}
"#
    );
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile account multisig admin builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (ivm_abi::syscalls::SYSCALL_ADD_SIGNATORY, "ADD_SIGNATORY"),
        (
            ivm_abi::syscalls::SYSCALL_REMOVE_SIGNATORY,
            "REMOVE_SIGNATORY",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SET_ACCOUNT_QUORUM,
            "SET_ACCOUNT_QUORUM",
        ),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("account admin syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let hints = manifest
        .access_set_hints
        .expect("expected static account multisig access hints");
    assert!(hints.read_keys.contains(&format!("account:{account}")));
    assert!(hints.write_keys.contains(&format!("account:{account}")));
    assert!(!hints.read_keys.contains(&ACCOUNT_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&ACCOUNT_WILDCARD_KEY.to_string()));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn dynamic_account_quorum_emits_checked_conversion_and_scoped_account_hints() {
    let src = include_str!("fixtures/v1/c020.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile dynamic account quorum builtin");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    let set_quorum = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_SET_ACCOUNT_QUORUM)
            .expect("account quorum syscall id fits in u8"),
    )
    .to_le_bytes();
    assert!(
        code.windows(set_quorum.len())
            .any(|window| window == set_quorum),
        "expected SET_ACCOUNT_QUORUM syscall in compiled code"
    );
    let int_to_u64 =
        encoding::wide::encode_syscallx(ivm_abi::syscalls::SYSCALL_INT_TO_U64).to_le_bytes();
    assert!(
        code.windows(int_to_u64.len())
            .any(|window| window == int_to_u64),
        "dynamic quorum must use checked int-to-u64 conversion"
    );
    let hints = manifest
        .access_set_hints
        .expect("expected dynamic account quorum access hints");
    assert!(hints.read_keys.contains(&ACCOUNT_WILDCARD_KEY.to_string()));
    assert!(hints.write_keys.contains(&ACCOUNT_WILDCARD_KEY.to_string()));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn account_multisig_admin_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c021.ko"),
            "ledger::account::add_signatory expects (AccountId, Json)",
        ),
        (
            include_str!("fixtures/v1/c022.ko"),
            "ledger::account::set_quorum expects (AccountId, int)",
        ),
        (
            include_str!("fixtures/v1/c023.ko"),
            "account quorum must be in the protocol range 1..=65535",
        ),
        (
            include_str!("fixtures/v1/c024.ko"),
            "account quorum must be in the protocol range 1..=65535",
        ),
        (
            include_str!("fixtures/v1/c025.ko"),
            "account quorum must be in the protocol range 1..=65535",
        ),
        (
            include_str!("fixtures/v1/c026.ko"),
            "account quorum must be in the protocol range 1..=65535",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = analyze(&parsed).expect_err("semantic analysis should reject account admin args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn account_balance_query_builtin_emits_balance_syscall_and_exact_reads() {
    let account = sample_account_literal();
    let asset_definition = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = format!(
        r#"
seiyaku CompilerFixture {{

view fn read() authorize(anyone) -> quantity {{
  let account = AccountId::parse("{account}");
  let asset = AssetDefinitionId::parse("{asset_definition}");
  return ledger::asset::balance(account: account, asset_definition: asset);
}}

}}
"#
    );
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile account balance query builtin");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_GET_ACCOUNT_BALANCE)
            .expect("account balance syscall id fits in u8"),
    )
    .to_le_bytes();
    assert!(
        code.windows(needle.len()).any(|window| window == needle),
        "expected GET_ACCOUNT_BALANCE syscall in compiled code"
    );
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let read = entrypoints
        .iter()
        .find(|entry| entry.name == "read")
        .expect("read entrypoint");
    assert_eq!(read.access_hints_complete, Some(true));
    assert!(read.access_hints_skipped.is_empty());
    assert!(read.write_keys.is_empty());
    assert!(read.read_keys.contains(&format!("account:{account}")));
    assert!(
        read.read_keys
            .contains(&format!("asset:{asset_definition}#{account}"))
    );
    assert!(
        read.read_keys
            .contains(&format!("asset_def:{asset_definition}"))
    );
}
#[test]
fn account_balance_query_builtin_rejects_invalid_arguments() {
    let parsed = parse(include_str!("fixtures/v1/c027.ko")).expect("parse source");
    let err = analyze(&parsed).expect_err("semantic analysis should reject account balance args");
    assert!(
        err.message
            .contains("ledger::asset::balance expects (AccountId, AssetDefinitionId)"),
        "unexpected semantic error: {}",
        err.message
    );
}
#[test]
fn set_account_detail_builtin_emits_syscall_and_exact_access() {
    let account = sample_account_literal();
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission FixtureAccess;

kotoage fn main() authorize(FixtureAccess) {{
  ledger::account::set_metadata(
    account: AccountId::parse("{account}"),
    key: Name::parse("status"),
    value: Json::parse("{{}}"),
  );
  ledger::account::set_metadata(
    account: AccountId::parse("{account}"),
    key: Name::parse("mirror"),
    value: Json::parse("{{}}"),
  );
}}

}}
"#
    );
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile set_account_detail builtin");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SET_ACCOUNT_DETAIL,
            "SET_ACCOUNT_DETAIL",
        ),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("account-detail syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let hints = manifest
        .access_set_hints
        .expect("expected account detail access hints");
    assert!(hints.read_keys.contains(&format!("account:{account}")));
    for key in ["status", "mirror"] {
        let detail = format!("account.detail:{account}:{key}");
        assert!(hints.read_keys.contains(&detail));
        assert!(hints.write_keys.contains(&detail));
    }
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn set_account_detail_builtin_rejects_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c028.ko"),
            "ledger::account::set_metadata expects (AccountId, Name, Json)",
        ),
        (
            include_str!("fixtures/v1/c029.ko"),
            "ledger::account::set_metadata expects (AccountId, Name, Json)",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err =
            analyze(&parsed).expect_err("semantic analysis should reject account detail args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn native_asset_operation_builtins_emit_syscalls_and_exact_access() {
    let from = sample_account_id();
    let to = sample_account_id_alt();
    let from_literal = from.to_string();
    let to_literal = to.to_string();
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let asset_definition =
        iroha_data_model::asset::id::AssetDefinitionId::parse_address_literal(asset_literal)
            .expect("asset definition literal");
    let from_asset = iroha_data_model::asset::id::AssetId::with_scope(
        asset_definition.clone(),
        from.clone(),
        AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL),
    );
    let to_asset = iroha_data_model::asset::id::AssetId::with_scope(
        asset_definition.clone(),
        to.clone(),
        AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL),
    );
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission FixtureAccess;

kotoage fn main() authorize(FixtureAccess) {{
  ledger::asset::transfer(source: AccountId::parse("{from_literal}"), destination: AccountId::parse("{to_literal}"), asset_definition: AssetDefinitionId::parse("{asset_literal}"), amount: 1, dataspace: DataSpaceId::parse("0"));
  ledger::asset::mint(account: AccountId::parse("{to_literal}"), asset_definition: AssetDefinitionId::parse("{asset_literal}"), amount: 2);
  ledger::asset::burn(account: AccountId::parse("{from_literal}"), asset_definition: AssetDefinitionId::parse("{asset_literal}"), amount: 1);
  ledger::asset::transfer(source: AccountId::parse("{to_literal}"), destination: AccountId::parse("{from_literal}"), asset_definition: AssetDefinitionId::parse("{asset_literal}"), amount: 1, dataspace: DataSpaceId::parse("0"));
  ledger::asset::mint(account: AccountId::parse("{from_literal}"), asset_definition: AssetDefinitionId::parse("{asset_literal}"), amount: 2);
  ledger::asset::burn(account: AccountId::parse("{to_literal}"), asset_definition: AssetDefinitionId::parse("{asset_literal}"), amount: 1);
}}

}}
"#
    );
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile native asset operation builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED,
            "TRANSFER_ASSET_SCOPED",
        ),
        (ivm_abi::syscalls::SYSCALL_MINT_ASSET, "MINT_ASSET"),
        (ivm_abi::syscalls::SYSCALL_BURN_ASSET, "BURN_ASSET"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("asset operation syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let literal_section = parsed.literal_section.expect("literal section");
    let quantity_literal_indices = (0..literal_section.count)
        .filter(|&index| {
            let descriptor_start = literal_section.entries_start + index * 8;
            let raw = u64::from_le_bytes(
                bytes[descriptor_start..descriptor_start + 8]
                    .try_into()
                    .expect("literal descriptor"),
            );
            let (kind, relative_offset) = crate::metadata::decode_literal_descriptor(raw)
                .expect("literal descriptor metadata");
            if kind != crate::metadata::LiteralKindV1::PointerTlv {
                return false;
            }
            let literal_start = literal_section.start
                + usize::try_from(relative_offset).expect("literal offset fits usize");
            let pointer_type = u16::from_be_bytes(
                bytes[literal_start..literal_start + 2]
                    .try_into()
                    .expect("pointer type id"),
            );
            pointer_type == PointerType::Quantity as u16
        })
        .collect::<Vec<_>>();
    assert_eq!(quantity_literal_indices.len(), 2, "amounts 1 and 2");
    let quantity_loads = code
        .chunks_exact(4)
        .filter(|word| {
            let word = u32::from_le_bytes((*word).try_into().expect("instruction word"));
            instruction::wide::opcode(word) == instruction::wide::memory::LDLIT
                && quantity_literal_indices.contains(&instruction::wide::literal_index(word))
        })
        .count();
    assert_eq!(
        quantity_loads, 6,
        "every literal mint, burn, and transfer amount must load a canonical Quantity TLV"
    );
    let hints = manifest
        .access_set_hints
        .expect("expected asset operation access hints");
    assert!(
        hints
            .read_keys
            .contains(&format!("asset_def:{asset_definition}"))
    );
    for key in [format!("account:{from}"), format!("account:{to}")] {
        assert!(hints.read_keys.contains(&key), "missing read key {key}");
    }
    for key in [format!("asset:{from_asset}"), format!("asset:{to_asset}")] {
        assert!(hints.read_keys.contains(&key), "missing read key {key}");
        assert!(hints.write_keys.contains(&key), "missing write key {key}");
    }
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn native_asset_operation_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c030.ko"),
            "ledger::asset::transfer expects (AccountId, AccountId, AssetDefinitionId, quantity[, DataSpaceId])",
        ),
        (
            include_str!("fixtures/v1/c031.ko"),
            "ledger::asset::mint expects (AccountId, AssetDefinitionId, quantity)",
        ),
        (
            include_str!("fixtures/v1/c032.ko"),
            "ledger::asset::burn expects (AccountId, AssetDefinitionId, quantity)",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err =
            analyze(&parsed).expect_err("semantic analysis should reject asset operation args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn nft_asset_operation_builtins_emit_syscalls_and_exact_access() {
    let owner = sample_account_id();
    let recipient = sample_account_id_alt();
    let owner_literal = owner.to_string();
    let recipient_literal = recipient.to_string();
    let nft = "n0$wonderland.universal";
    let nft_alt = "n1$wonderland.universal";
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission FixtureAccess;

kotoage fn main() authorize(FixtureAccess) {{
  ledger::nft::mint(nft: NftId::parse("{nft}"), owner: AccountId::parse("{owner_literal}"));
  ledger::nft::set_metadata(nft: NftId::parse("{nft}"), key: Name::parse("issued"), value: Json::parse("{{\"meta\":1}}"));
  ledger::nft::transfer(source: AccountId::parse("{owner_literal}"), nft: NftId::parse("{nft}"), destination: AccountId::parse("{recipient_literal}"));
  ledger::nft::burn(nft: NftId::parse("{nft}"));
  ledger::nft::mint(nft: NftId::parse("{nft_alt}"), owner: AccountId::parse("{recipient_literal}"));
  ledger::nft::set_metadata(nft: NftId::parse("{nft_alt}"), key: Name::parse("mirror"), value: Json::parse("{{\"meta\":2}}"));
  ledger::nft::transfer(source: AccountId::parse("{recipient_literal}"), nft: NftId::parse("{nft_alt}"), destination: AccountId::parse("{owner_literal}"));
  ledger::nft::burn(nft: NftId::parse("{nft_alt}"));
}}

}}
"#
    );
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile NFT asset operation builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (ivm_abi::syscalls::SYSCALL_NFT_MINT_ASSET, "NFT_MINT_ASSET"),
        (
            ivm_abi::syscalls::SYSCALL_NFT_SET_METADATA,
            "NFT_SET_METADATA",
        ),
        (
            ivm_abi::syscalls::SYSCALL_NFT_TRANSFER_ASSET,
            "NFT_TRANSFER_ASSET",
        ),
        (ivm_abi::syscalls::SYSCALL_NFT_BURN_ASSET, "NFT_BURN_ASSET"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("NFT operation syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let hints = manifest
        .access_set_hints
        .expect("expected NFT operation access hints");
    assert!(hints.read_keys.contains(&NFT_COARSE_KEY.to_string()));
    assert!(hints.write_keys.contains(&NFT_COARSE_KEY.to_string()));
    for key in [
        format!("account:{owner}"),
        format!("account:{recipient}"),
        format!("nft:{nft}"),
        format!("nft:{nft_alt}"),
    ] {
        assert!(hints.read_keys.contains(&key), "missing read key {key}");
    }
    for key in [format!("nft:{nft}"), format!("nft:{nft_alt}")] {
        assert!(hints.write_keys.contains(&key), "missing write key {key}");
    }
    for detail in [
        format!("nft.detail:{nft}:issued"),
        format!("nft.detail:{nft_alt}:mirror"),
    ] {
        assert!(
            hints.read_keys.contains(&detail),
            "missing read detail {detail}"
        );
        assert!(
            hints.write_keys.contains(&detail),
            "missing write detail {detail}"
        );
    }
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn nft_asset_operation_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c033.ko"),
            "ledger::nft::mint expects (NftId, AccountId)",
        ),
        (
            include_str!("fixtures/v1/c034.ko"),
            "ledger::nft::set_metadata expects (NftId, Name, Json)",
        ),
        (
            include_str!("fixtures/v1/c035.ko"),
            "ledger::nft::burn expects (NftId)",
        ),
        (
            include_str!("fixtures/v1/c036.ko"),
            "ledger::nft::transfer expects (AccountId, NftId, AccountId)",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = analyze(&parsed).expect_err("semantic analysis should reject NFT operation args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn lifecycle_builtins_emit_syscalls_and_exact_access() {
    let owner = sample_account_id();
    let recipient = sample_account_id_alt();
    let owner_literal = owner.to_string();
    let recipient_literal = recipient.to_string();
    let domain = "wonderland.universal";
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let asset_definition =
        iroha_data_model::asset::id::AssetDefinitionId::parse_address_literal(asset_literal)
            .expect("asset definition literal");
    let owner_asset =
        iroha_data_model::asset::id::AssetId::of(asset_definition.clone(), owner.clone());
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission FixtureAccess;

kotoage fn main() authorize(FixtureAccess) {{
  let domain_id = DomainId::parse("{domain}");
  let owner = AccountId::parse("{owner_literal}");
  let recipient = AccountId::parse("{recipient_literal}");
  let asset = AssetDefinitionId::parse("{asset_literal}");
  ledger::domain::register(domain: domain_id);
  ledger::domain::unregister(domain: domain_id);
  ledger::domain::transfer(source: owner, domain: domain_id, destination: recipient);
  ledger::account::register(account: owner);
  ledger::account::unregister(account: recipient);
  ledger::asset::register(asset_definition: asset, name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
  ledger::asset::mint(account: owner, asset_definition: asset, amount: 7);
  ledger::asset::unregister(asset_definition: asset);
  ledger::domain::register(domain: domain_id);
  ledger::domain::unregister(domain: domain_id);
  ledger::domain::transfer(source: owner, domain: domain_id, destination: recipient);
  ledger::account::register(account: recipient);
  ledger::account::unregister(account: owner);
  ledger::asset::register(asset_definition: asset, name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
  ledger::asset::mint(account: owner, asset_definition: asset, amount: 3);
  ledger::asset::unregister(asset_definition: asset);
}}

}}
"#
    );
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile lifecycle builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_REGISTER_DOMAIN,
            "REGISTER_DOMAIN",
        ),
        (
            ivm_abi::syscalls::SYSCALL_UNREGISTER_DOMAIN,
            "UNREGISTER_DOMAIN",
        ),
        (
            ivm_abi::syscalls::SYSCALL_TRANSFER_DOMAIN,
            "TRANSFER_DOMAIN",
        ),
        (
            ivm_abi::syscalls::SYSCALL_REGISTER_ACCOUNT,
            "REGISTER_ACCOUNT",
        ),
        (
            ivm_abi::syscalls::SYSCALL_UNREGISTER_ACCOUNT,
            "UNREGISTER_ACCOUNT",
        ),
        (ivm_abi::syscalls::SYSCALL_REGISTER_ASSET, "REGISTER_ASSET"),
        (
            ivm_abi::syscalls::SYSCALL_UNREGISTER_ASSET,
            "UNREGISTER_ASSET",
        ),
        (ivm_abi::syscalls::SYSCALL_MINT_ASSET, "MINT_ASSET"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("lifecycle syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let hints = manifest
        .access_set_hints
        .expect("expected lifecycle access hints");
    for key in [
        format!("domain:{domain}"),
        format!("account:{owner}"),
        format!("account:{recipient}"),
        format!("asset_def:{asset_definition}"),
        format!("asset:{owner_asset}"),
    ] {
        assert!(hints.read_keys.contains(&key), "missing read key {key}");
    }
    for key in [
        format!("domain:{domain}"),
        format!("account:{owner}"),
        format!("account:{recipient}"),
        format!("asset_def:{asset_definition}"),
        format!("asset:{owner_asset}"),
    ] {
        assert!(hints.write_keys.contains(&key), "missing write key {key}");
    }
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn lifecycle_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c037.ko"),
            "ledger::domain::register expects (DomainId)",
        ),
        (
            include_str!("fixtures/v1/c038.ko"),
            "ledger::account::register expects (AccountId)",
        ),
        (
            include_str!("fixtures/v1/c039.ko"),
            "ledger::asset::unregister expects (AssetDefinitionId)",
        ),
        (
            include_str!("fixtures/v1/c040.ko"),
            "ledger::asset::register expects (asset_definition: AssetDefinitionId, name: string",
        ),
        (
            include_str!("fixtures/v1/c041.ko"),
            "ledger::asset::register expects (asset_definition: AssetDefinitionId, name: string",
        ),
        (
            include_str!("fixtures/v1/c042.ko"),
            "ledger::domain::transfer expects (AccountId, DomainId, AccountId)",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err =
            analyze(&parsed).expect_err("semantic analysis should reject lifecycle operation args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn peer_trigger_management_builtins_emit_syscalls() {
    let src = include_str!("fixtures/v1/c043.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(src)
        .expect("compile peer/trigger management builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (ivm_abi::syscalls::SYSCALL_REGISTER_PEER, "REGISTER_PEER"),
        (
            ivm_abi::syscalls::SYSCALL_UNREGISTER_PEER,
            "UNREGISTER_PEER",
        ),
        (ivm_abi::syscalls::SYSCALL_CREATE_TRIGGER, "CREATE_TRIGGER"),
        (ivm_abi::syscalls::SYSCALL_REMOVE_TRIGGER, "REMOVE_TRIGGER"),
        (
            ivm_abi::syscalls::SYSCALL_SET_TRIGGER_ENABLED,
            "SET_TRIGGER_ENABLED",
        ),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("peer/trigger syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
}
#[test]
fn peer_trigger_management_builtins_report_exact_trigger_access() {
    let src = include_str!("fixtures/v1/c044.ko");
    let compiler = test_mode_compiler();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile trigger access builtins");
    let hints = manifest
        .access_set_hints
        .expect("expected trigger access hints");
    let trigger_key = "trigger:wake".to_string();
    assert!(hints.read_keys.contains(&trigger_key));
    assert!(hints.write_keys.contains(&trigger_key));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn role_permission_management_builtins_emit_syscalls_and_exact_access() {
    let account = sample_account_id();
    let account_literal = account.to_string();
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission FixtureAccess;

kotoage fn main() authorize(FixtureAccess) {{
  let account = AccountId::parse("{account_literal}");
  let role = Name::parse("auditor");
  let perm = Name::parse("read_blocks");
  ledger::role::register(role: role, permissions: Json::parse("{{}}"));
  ledger::role::grant(account: account, role: role);
  ledger::role::revoke(account: account, role: role);
  ledger::permission::grant(account: account, permission: perm);
  ledger::permission::revoke(account: account, permission: perm);
  ledger::role::unregister(role: role);
  ledger::role::register(role: role, permissions: Json::parse("{{}}"));
  ledger::role::grant(account: account, role: role);
  ledger::role::revoke(account: account, role: role);
  ledger::permission::grant(account: account, permission: perm);
  ledger::permission::revoke(account: account, permission: perm);
  ledger::role::unregister(role: role);
}}

}}
"#
    );
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile role/permission management builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (ivm_abi::syscalls::SYSCALL_CREATE_ROLE, "CREATE_ROLE"),
        (ivm_abi::syscalls::SYSCALL_DELETE_ROLE, "DELETE_ROLE"),
        (ivm_abi::syscalls::SYSCALL_GRANT_ROLE, "GRANT_ROLE"),
        (ivm_abi::syscalls::SYSCALL_REVOKE_ROLE, "REVOKE_ROLE"),
        (
            ivm_abi::syscalls::SYSCALL_GRANT_PERMISSION,
            "GRANT_PERMISSION",
        ),
        (
            ivm_abi::syscalls::SYSCALL_REVOKE_PERMISSION,
            "REVOKE_PERMISSION",
        ),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("role/permission syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let hints = manifest
        .access_set_hints
        .expect("expected role/permission access hints");
    for key in [format!("account:{account}"), "role:auditor".to_string()] {
        assert!(hints.read_keys.contains(&key), "missing read key {key}");
    }
    for key in [
        format!("account:{account}"),
        "role:auditor".to_string(),
        format!("role.binding:{account}:auditor"),
        format!("perm.account:{account}:read_blocks"),
    ] {
        assert!(hints.write_keys.contains(&key), "missing write key {key}");
    }
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
}
#[test]
fn role_permission_peer_trigger_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c045.ko"),
            "ledger::peer::register expects (Json)",
        ),
        (
            include_str!("fixtures/v1/c046.ko"),
            "ledger::trigger::register expects (Json)",
        ),
        (
            include_str!("fixtures/v1/c047.ko"),
            "ledger::trigger::unregister expects (Name)",
        ),
        (
            include_str!("fixtures/v1/c048.ko"),
            "ledger::trigger::set_enabled expects (Name, bool)",
        ),
        (
            include_str!("fixtures/v1/c049.ko"),
            "ledger::role::register expects (Name, Json)",
        ),
        (
            include_str!("fixtures/v1/c050.ko"),
            "ledger::role::unregister expects (Name)",
        ),
        (
            include_str!("fixtures/v1/c051.ko"),
            "ledger::role::grant expects (AccountId, Name)",
        ),
        (
            include_str!("fixtures/v1/c052.ko"),
            "ledger::permission::revoke expects (AccountId, Name|Json)",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err =
            analyze(&parsed).expect_err("semantic analysis should reject management helper args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn public_input_builtin_emits_public_input_syscall_and_complete_access() {
    let src = include_str!("fixtures/v1/c053.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile get_public_input builtin");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (
            ivm_abi::syscalls::SYSCALL_GET_PUBLIC_INPUT,
            "GET_PUBLIC_INPUT",
        ),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("public-input syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let read_input = entrypoints
        .iter()
        .find(|entry| entry.name == "read_input")
        .expect("read_input entrypoint");
    assert_ne!(read_input.access_hints_complete, Some(false));
    assert!(read_input.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&read_input.read_keys);
    assert!(read_input.write_keys.is_empty());
}
#[test]
fn public_input_builtin_rejects_invalid_arguments() {
    let parsed = parse(include_str!("fixtures/v1/c054.ko")).expect("parse source");
    let err = analyze(&parsed).expect_err("semantic analysis should reject public input key type");
    assert!(
        err.message.contains("context::public_input expects (Name)"),
        "unexpected semantic error: {}",
        err.message
    );
}
#[test]
fn debug_info_emits_full_width_pointer_codec_and_complete_access() {
    let src = include_str!("fixtures/v1/c055.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile debug builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_DEBUG_LOG).expect("debug syscall id fits in u8"),
    )
    .to_le_bytes();
    assert!(
        code.windows(needle.len()).any(|window| window == needle),
        "expected DEBUG_LOG syscall in compiled code"
    );
    let retired_print = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_DEBUG_PRINT).expect("debug syscall id fits in u8"),
    )
    .to_le_bytes();
    assert!(
        !code
            .windows(retired_print.len())
            .any(|window| window == retired_print),
        "V1 source must not expose the raw integer debug syscall"
    );
    let publish_needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
    )
    .to_le_bytes();
    let pointer_codec = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_POINTER_TO_NORITO as u8,
    )
    .to_le_bytes();
    let logging_codec_calls: Vec<_> = code
        .chunks_exact(4)
        .filter(|word| *word == needle || *word == pointer_codec || *word == publish_needle)
        .map(|word| <[u8; 4]>::try_from(word).expect("one complete instruction"))
        .collect();
    // The synchronous pointer codec validates the original owned public TLV.
    // String logging needs no conversion; numeric logging must encode the full
    // typed value before DEBUG_LOG, without an intermediate publication copy.
    assert_eq!(
        logging_codec_calls,
        [needle, pointer_codec, needle],
        "string log, full-width pointer codec, and numeric log must stay ordered"
    );
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let inspect = entrypoints
        .iter()
        .find(|entry| entry.name == "inspect")
        .expect("inspect entrypoint");
    assert_ne!(inspect.access_hints_complete, Some(false));
    assert!(inspect.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&inspect.read_keys);
    assert!(inspect.write_keys.is_empty());
}
#[test]
fn debug_info_preserves_wide_int_without_retired_syscalls() {
    let source = r#"
seiyaku WideInfo { permission FixtureAccess;
  kotoage fn inspect(int value) authorize(FixtureAccess) -> int {
    debug::info(value);
    return value;
  }
  kotoage fn boundary() authorize(FixtureAccess) -> int {
    let value = 1267650600228229401496703205376;
    debug::info(value);
    return value;
  }
}
"#;
    let artifact = Compiler::new()
        .compile_source(source)
        .expect("compile full-width Int logging");
    let metadata = ProgramMetadata::parse(&artifact).expect("V1 metadata");
    let code = &artifact[metadata.code_offset..];
    for syscall in [
        syscalls::SYSCALL_POINTER_TO_NORITO,
        syscalls::SYSCALL_DEBUG_LOG,
    ] {
        let encoded = encoding::wide::encode_sys(instruction::wide::system::SCALL, syscall as u8)
            .to_le_bytes();
        assert!(
            code.windows(encoded.len()).any(|window| window == encoded),
            "expected V1 pointer/log syscall {syscall:#x}"
        );
    }
    for retired in [0x53_u8, 0x55_u8] {
        let encoded =
            encoding::wide::encode_sys(instruction::wide::system::SCALL, retired).to_le_bytes();
        assert!(
            !code.windows(encoded.len()).any(|window| window == encoded),
            "retired i64 codec syscall {retired:#x} must not be emitted"
        );
    }
}
#[test]
fn debug_surface_rejects_raw_variants_and_invalid_info_arguments() {
    for call in [
        "debug::print_i64(1)",
        "debug::log(b\"raw\")",
        "debug::info(Name::parse(\"not-a-message\"))",
    ] {
        let source = format!(
            "seiyaku CompilerFixture {{ permission DebugContract;  kotoage fn run() authorize(DebugContract) {{ {call}; }} }}"
        );
        let err = Compiler::new()
            .compile_source(&source)
            .expect_err("non-canonical debug call must fail");
        assert!(
            err.contains("unknown function or builtin")
                || err.contains("E_UNKNOWN_BUILTIN")
                || err.contains("compiler-internal")
                || err.contains("debug::info expects (string|int)"),
            "unexpected diagnostic for `{call}`: {err}"
        );
    }
}
#[test]
fn assertion_logging_builtins_emit_abort_and_log_syscalls() {
    let src = include_str!("fixtures/v1/c056.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile assertion/logging builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (ivm_abi::syscalls::SYSCALL_DEBUG_LOG, "DEBUG_LOG"),
        (ivm_abi::syscalls::SYSCALL_ABORT, "ABORT"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("assertion/logging syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let inspect = entrypoints
        .iter()
        .find(|entry| entry.name == "inspect")
        .expect("inspect entrypoint");
    assert_ne!(inspect.access_hints_complete, Some(false));
    assert!(inspect.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&inspect.read_keys);
    assert!(inspect.write_keys.is_empty());
}
#[test]
fn assertion_logging_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c057.ko"),
            "test::assert expects a bool condition, found `int`",
        ),
        (
            include_str!("fixtures/v1/c058.ko"),
            "require expects (bool, ErrorEnum::Variant)",
        ),
        (
            include_str!("fixtures/v1/c059.ko"),
            "debug::info expects (string|int)",
        ),
        (
            include_str!("fixtures/v1/c060.ko"),
            "test::assert_eq compares `actual` and `expected` of one type, found `bool` and `int`",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&parsed)
            .expect_err("semantic analysis should reject invalid args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn privacy_output_builtins_emit_runtime_syscalls() {
    let src = include_str!("fixtures/v1/c061.ko");
    let compiler = Compiler::new_with_options(CompilerOptions {
        force_zk: true,
        mode: CompilerMode::Test,
        ..CompilerOptions::default()
    });
    let bytes = compiler
        .compile_source(src)
        .expect("compile privacy/output builtins");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_GET_PRIVATE_INPUT,
            "GET_PRIVATE_INPUT",
        ),
        (
            ivm_abi::syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM,
            "PRIVATE_NUMERIC_VALCOM",
        ),
        (ivm_abi::syscalls::SYSCALL_COMMIT_OUTPUT, "COMMIT_OUTPUT"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("privacy/output syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
}
#[test]
fn privacy_output_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c062.ko"),
            "crypto::private_input expects (int index)",
        ),
        (
            include_str!("fixtures/v1/c063.ko"),
            "call `crypto::commit_output` expects at most 0 arguments",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = semantic::SemanticContext::with_capabilities(true, false)
            .analyze(&parsed)
            .expect_err("ZK semantic analysis should reject invalid args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn compiler_internal_seiyaku_lifecycle_operations_are_not_source_apis() {
    assert_internal_source_names_rejected(&[
        "deactivate_contract_instance",
        "remove_smart_contract_bytes",
        "register_smart_contract_code",
        "register_smart_contract_bytes",
        "activate_contract_instance",
    ]);
    for name in [
        "seiyaku::deactivate_instance",
        "seiyaku::remove_code",
        "seiyaku::register_code",
        "seiyaku::register_bytes",
        "seiyaku::activate_instance",
        "contract::deactivate_instance",
        "contract::remove_code",
        "contract::register_code",
        "contract::register_bytes",
        "contract::activate_instance",
    ] {
        let source = format!(
            "seiyaku CompilerFixture {{ view fn probe() authorize(anyone) -> int {{ {name}(); return 0; }} }}"
        );
        let error = test_mode_compiler()
            .compile_source(&source)
            .expect_err("retired lifecycle namespace must not resolve from source");
        assert!(
            error.contains("K1001")
                || error.contains("K2002")
                || error.contains("E_UNKNOWN_BUILTIN")
                || error.contains("E_INTERNAL_BUILTIN"),
            "lifecycle operation `{name}` was rejected for the wrong reason: {error}"
        );
    }
}
#[test]
fn raw_transfer_batch_boundaries_are_not_source_apis() {
    for source in [
        include_str!("fixtures/v1/c064.ko"),
        include_str!("fixtures/v1/c065.ko"),
        include_str!("fixtures/v1/c066.ko"),
        include_str!("fixtures/v1/c067.ko"),
        include_str!("fixtures/v1/c068.ko"),
        include_str!("fixtures/v1/c069.ko"),
    ] {
        let error = Compiler::new()
            .compile_source(source)
            .expect_err("only typed transfer_batch is a source API");
        assert!(
            error.contains("E_UNKNOWN_BUILTIN") || error.contains("K2002"),
            "{error}"
        );
    }
}
#[test]
fn transfer_batch_builtin_lowers_entries_between_boundaries() {
    let src = include_str!("fixtures/v1/c070.ko");
    let parsed = parse(src).expect("parse transfer_batch source");
    let typed = analyze(&parsed).expect("analyze transfer_batch source");
    let ir = ir::lower(&typed).expect("lower transfer_batch source");
    let mut begins = 0;
    let mut transfers = 0;
    let mut ends = 0;
    for instr in ir
        .functions
        .iter()
        .flat_map(|function| function.blocks.iter())
        .flat_map(|block| block.instrs.iter())
    {
        match instr {
            ir::Instr::TransferBatchBegin => begins += 1,
            ir::Instr::TransferBatchAsset { .. } => transfers += 1,
            ir::Instr::TransferBatchEnd => ends += 1,
            _ => {}
        }
    }
    assert_eq!(begins, 1, "one nonempty batch opens one atomic scope");
    assert_eq!(transfers, 1, "one bounded loop visits each active entry");
    assert_eq!(ends, 1, "one nonempty batch closes one atomic scope");
    for source in [
        "seiyaku EmptyBatch { permission Writer;  kotoage fn main() authorize(Writer) { ledger::asset::transfer_batch(transfers: []); } }",
        "seiyaku SavedBatch { permission Writer;  kotoage fn main() authorize(Writer) { let List<(AccountId, AccountId, AssetDefinitionId, quantity), 8> transfers = []; ledger::asset::transfer_batch(transfers: transfers); } }",
    ] {
        Compiler::new()
            .compile_source(source)
            .expect("empty and saved typed lists compile");
    }
}
#[test]
fn transfer_batch_builtin_rejects_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c071.ko"),
            "call `ledger::asset::transfer_batch` is missing required argument `transfers`",
        ),
        (
            include_str!("fixtures/v1/c072.ko"),
            "ledger::asset::transfer_batch expects named transfers: List<(AccountId, AccountId, AssetDefinitionId, quantity), N>",
        ),
    ] {
        let parsed = parse(src).expect("parse invalid transfer_batch source");
        let err =
            analyze(&parsed).expect_err("semantic analysis should reject transfer_batch args");
        assert!(
            err.message.contains(expected),
            "expected error containing {expected:?}, got {}",
            err.message
        );
    }
}
#[test]
fn raw_axt_capabilities_and_unanchored_proof_are_not_source_apis() {
    for source in [
        "fn main(AxtDescriptor value) {}",
        "fn main(AssetHandle value) {}",
        "fn main(AxtAnchoredSpendV1 value) {}",
        "fn main(ProofBlob value) {}",
    ] {
        let error = test_mode_compiler()
            .compile_source(&format!("seiyaku CompilerFixture {{ {source} }}"))
            .expect_err("opaque AXT capabilities must remain compiler-internal");
        assert!(
            error.contains("unknown type") || error.contains("unknown function or builtin"),
            "unexpected AXT surface error: {error}"
        );
    }
    assert_internal_source_names_rejected(&["asset_handle", "proof_blob", "axt::verify_proof"]);
}
#[test]
fn signed_axt_spend_source_emits_the_typed_v1_staging_syscall() {
    let descriptor_fixture: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../iroha_data_model/tests/fixtures/axt_descriptor_multi_ds.json"
    )))
    .expect("current descriptor fixture");
    let descriptor: crate::axt::AxtDescriptor =
        norito::json::from_value(descriptor_fixture["descriptor"].clone())
            .expect("ABI descriptor fixture");
    let spend_fixture: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../iroha_data_model/tests/fixtures/axt_envelope_multi_ds.json"
    )))
    .expect("current signed-spend fixture");
    let spend: iroha_data_model::nexus::AxtAnchoredSpendV1 =
        norito::json::from_value(spend_fixture["spends"]["happy"][0].clone())
            .expect("signed spend fixture");
    let descriptor_hex = canonical_norito_hex(&descriptor);
    let spend_hex = canonical_norito_hex(&spend);
    let source = format!(
        r#"seiyaku SignedAxt {{ permission UseAxt;
                kotoage fn main() authorize(UseAxt) {{
                    let descriptor = AxtDescriptor::parse("{descriptor_hex}");
                    let spend = AxtAnchoredSpendV1::parse("{spend_hex}");
                    axt::begin(descriptor: descriptor);
                    axt::stage_anchored_spend(spend: spend);
                    axt::commit();
                }}
            }}"#
    );
    let artifact = test_mode_compiler()
        .compile_source(&source)
        .expect("typed signed-spend source compiles");
    let metadata = ProgramMetadata::parse(&artifact).expect("parse program metadata");
    let code = &artifact[metadata.code_offset..];
    let encoded = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND)
            .expect("B5 fits the V1 immediate"),
    )
    .to_le_bytes();
    assert!(
        code.windows(encoded.len()).any(|window| window == encoded),
        "source producer must emit the final typed B5 syscall"
    );
}
#[test]
fn opaque_pointer_abi_types_are_not_source_types() {
    for type_name in ["Domain", "Blob", "NoritoBytes", "Opaque"] {
        let source = format!(
            "seiyaku CompilerFixture {{ view fn inspect({type_name} value) authorize(anyone) -> int {{ return 0; }} }}"
        );
        let error = test_mode_compiler()
            .compile_source(&source)
            .expect_err("opaque pointer-ABI types must not resolve from source");
        assert!(
            error.contains("unknown type") && error.contains(type_name),
            "unexpected type rejection for `{type_name}`: {error}"
        );
    }
    assert_internal_source_names_rejected(&[
        "domain",
        "blob",
        "norito_bytes",
        "axt_descriptor",
        "asset_handle",
        "proof_blob",
        "soracloud_request",
        "soracloud_response",
    ]);
}
#[test]
fn verify_proof_builtin_emits_verify_proof_syscall_and_complete_access() {
    let src = include_str!("fixtures/v1/c073.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile verify_proof builtin");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (ivm_abi::syscalls::SYSCALL_VERIFY_PROOF, "VERIFY_PROOF"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("verify_proof syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let check = entrypoints
        .iter()
        .find(|entry| entry.name == "check")
        .expect("check entrypoint");
    assert_ne!(check.access_hints_complete, Some(false));
    assert!(check.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&check.read_keys);
    assert!(check.write_keys.is_empty());
}
#[test]
fn verify_proof_builtin_rejects_invalid_arguments() {
    let parsed = parse(include_str!("fixtures/v1/c074.ko")).expect("parse source");
    let err = analyze(&parsed).expect_err("semantic analysis should reject proof payload type");
    assert!(
        err.message.contains(
            "crypto::verify_proof expects (bytes) pointer to NoritoBytes OpenVerifyEnvelope"
        ),
        "unexpected semantic error: {}",
        err.message
    );
}
#[test]
fn execution_summary_builtin_emits_execution_summary_syscall_and_complete_access() {
    let src = include_str!("fixtures/v1/c075.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile execution_summary builtin");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_EXECUTION_SUMMARY)
            .expect("execution_summary syscall id fits in u8"),
    )
    .to_le_bytes();
    assert!(
        code.windows(needle.len()).any(|window| window == needle),
        "expected EXECUTION_SUMMARY syscall in compiled code"
    );
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let proof = entrypoints
        .iter()
        .find(|entry| entry.name == "summary")
        .expect("proof entrypoint");
    assert_ne!(proof.access_hints_complete, Some(false));
    assert!(proof.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&proof.read_keys);
    assert!(proof.write_keys.is_empty());
}
#[test]
fn execution_summary_builtin_rejects_arguments() {
    let parsed = parse(include_str!("fixtures/v1/c076.ko")).expect("parse source");
    let err = analyze(&parsed).expect_err("semantic analysis should reject proof arguments");
    assert!(
        err.message
            .contains("call `crypto::execution_summary` expects at most 0 arguments"),
        "unexpected semantic error: {}",
        err.message
    );
}
#[test]
fn allocation_and_heap_controls_are_not_source_apis() {
    assert_internal_source_names_rejected(&[
        "alloc",
        "grow_heap",
        "memory::alloc",
        "memory::grow_heap",
    ]);
}
#[test]
fn raw_memory_merkle_controls_are_not_source_apis() {
    assert_internal_source_names_rejected(&[
        "get_merkle_path",
        "get_merkle_compact",
        "get_register_merkle_compact",
        "memory::get_merkle_path",
        "memory::get_merkle_compact",
        "memory::get_register_merkle_compact",
    ]);
}
#[test]
fn direct_codec_numeric_builtins_are_not_source_apis() {
    assert_internal_source_names_rejected(&[
        "json_get_int_direct",
        "json_get_numeric_direct",
        "json_get_json_direct",
        "json_get_name_direct",
        "json_get_account_id_direct",
        "json_get_asset_definition_id_direct",
        "json_get_nft_id_direct",
        "json_get_blob_hex_direct",
        "json_set_int_direct",
        "json_set_account_id_direct",
        "build_path_key_norito_direct",
        "schema_info_direct",
        "encode_schema_direct",
        "decode_schema_direct",
        "schema_encode_direct",
        "schema_decode_direct",
        "numeric_to_int_direct",
        "numeric_add_direct",
        "numeric_sub_direct",
        "numeric_mul_direct",
        "numeric_div_direct",
        "numeric_rem_direct",
        "numeric_neg_direct",
        "numeric_eq_direct",
        "numeric_ne_direct",
        "numeric_lt_direct",
        "numeric_le_direct",
        "numeric_gt_direct",
        "numeric_ge_direct",
    ]);
}
#[test]
fn schema_codec_builtins_are_not_source_apis() {
    assert_internal_source_names_rejected(&[
        "encode_schema",
        "decode_schema",
        "schema_info",
        "codec::schema::encode",
        "codec::schema::decode",
        "codec::schema::info",
    ]);
}
#[test]
fn vrf_builtins_emit_vrf_syscalls() {
    let src = include_str!("fixtures/v1/c077.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler.compile_source(src).expect("compile VRF helpers");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (
            ivm_abi::syscalls::SYSCALL_NORMALIZE_NORITO_BYTES,
            "NORMALIZE_NORITO_BYTES",
        ),
        (ivm_abi::syscalls::SYSCALL_VRF_VERIFY, "VRF_VERIFY"),
        (
            ivm_abi::syscalls::SYSCALL_VRF_VERIFY_BATCH,
            "VRF_VERIFY_BATCH",
        ),
    ] {
        let needle = if let Ok(imm8) = u8::try_from(syscall) {
            encoding::wide::encode_sys(instruction::wide::system::SCALL, imm8)
        } else {
            encoding::wide::encode_syscallx(syscall)
        }
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let publish = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV)
            .expect("INPUT_PUBLISH_TLV syscall id fits in u8"),
    )
    .to_le_bytes();
    assert_eq!(
        code.windows(publish.len())
            .filter(|window| *window == publish)
            .count(),
        2,
        "single and batch VRF verification each publish exactly one request envelope"
    );
    let syscall_words = code
        .chunks_exact(4)
        .filter_map(|chunk| {
            let word = u32::from_le_bytes(chunk.try_into().expect("four-byte instruction"));
            match instruction::wide::opcode(word) {
                instruction::wide::system::SCALL => {
                    Some(u32::from(encoding::wide::decode_sys(word).1))
                }
                instruction::wide::system::SYSTEM => Some(encoding::wide::decode_syscallx(word)),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    for operation in [
        ivm_abi::syscalls::SYSCALL_VRF_VERIFY,
        ivm_abi::syscalls::SYSCALL_VRF_VERIFY_BATCH,
    ] {
        assert!(
            syscall_words.windows(2).any(|window| {
                window == [ivm_abi::syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, operation]
            }),
            "NORMALIZE_NORITO_BYTES must immediately precede VRF syscall {operation:#x}"
        );
    }
}
#[test]
fn vrf_builtins_reject_invalid_arguments() {
    for (src, expected_code, expected_message) in [
        (
            include_str!("fixtures/v1/c078.ko"),
            Some("E_RETIRED_VRF_VERIFY_ARGS"),
            "four-register VRF verify form is retired",
        ),
        (
            include_str!("fixtures/v1/c079.ko"),
            None,
            "crypto::vrf::verify expects one bytes-encoded VrfVerifyRequest",
        ),
        (
            include_str!("fixtures/v1/c080.ko"),
            None,
            "crypto::vrf::verify_batch expects (bytes)",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = analyze(&parsed).expect_err("semantic analysis should reject VRF args");
        if let Some(expected_code) = expected_code {
            assert_eq!(err.code, expected_code);
        }
        assert!(
            err.message.contains(expected_message),
            "expected `{expected_message}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn zk_verify_builtins_emit_verify_syscalls() {
    let src = include_str!("fixtures/v1/c081.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(src)
        .expect("compile ZK verify helpers");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ZK_VERIFY_BATCH,
            "ZK_VERIFY_BATCH",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
            "ZK_VOTE_VERIFY_BALLOT",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY,
            "ZK_VOTE_VERIFY_TALLY",
        ),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("ZK syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
}
#[test]
fn zk_verify_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c082.ko"),
            "crypto::zk::verify_batch expects (bytes) where the argument is a pointer to NoritoBytes TLV in INPUT",
        ),
        (
            include_str!("fixtures/v1/c083.ko"),
            "ledger::governance::verify_tally expects (bytes) where the argument is a pointer to NoritoBytes TLV in INPUT",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = analyze(&parsed).expect_err("semantic analysis should reject ZK verify args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn inline_submit_ballot_builtin_lowers_to_ir() {
    let nullifier = "\\x00".repeat(32);
    let src = format!(
        r#"
seiyaku CompilerFixture {{

fn main() {{
  let _ballot = ledger::governance::build_submit_ballot(
    election_id: "election",
    ciphertext: b"00",
    nullifier: b"{nullifier}",
    backend: "halo2",
    proof: b"proof",
    verification_key: b"vk",
  );
}}

}}
"#
    );
    let parsed = parse(&src).expect("parse inline builder source");
    let typed = analyze(&parsed).expect("analyze inline builder source");
    let ir = ir::lower(&typed).expect("lower inline builder source");
    assert!(
        ir.functions
            .iter()
            .flat_map(|function| function.blocks.iter())
            .flat_map(|block| block.instrs.iter())
            .any(|instr| matches!(instr, ir::Instr::BuildSubmitBallotInline { .. })),
        "expected BuildSubmitBallotInline IR"
    );
}
#[test]
fn inline_submit_ballot_requires_a_canonical_governance_selector() {
    let nullifier = "\\x00".repeat(32);
    let source = |selector: &str| {
        format!(
            r#"
seiyaku CompilerFixture {{ permission FixtureAccess;

kotoage fn main() authorize(FixtureAccess) {{
  let _ballot = ledger::governance::build_submit_ballot(
    election_id: "{selector}",
    ciphertext: b"00",
    nullifier: b"{nullifier}",
    backend: "halo2",
    proof: b"proof",
    verification_key: b"vk",
  );
}}

}}
"#
        )
    };
    Compiler::new()
        .compile_source(&source(&"a".repeat(128)))
        .expect("a 128-byte canonical governance selector must compile");
    let overlong = "a".repeat(129);
    for (case, selector) in [
        ("empty", ""),
        ("dot", "."),
        ("leading dot", ".hidden"),
        ("slash", "a/b"),
        ("percent", "a%2Fb"),
        ("whitespace", "a b"),
        ("Unicode", "投票"),
        ("overlong", overlong.as_str()),
    ] {
        let error = Compiler::new()
            .compile_source(&source(selector))
            .expect_err("a noncanonical governance selector must fail compilation");
        assert!(
            error.contains(
                "election_id must be 1-128 RFC 3986 unreserved ASCII characters and must not start with a dot"
            ),
            "case={case}: unexpected diagnostic: {error}"
        );
    }
}
#[test]
fn noncanonical_inline_submit_ballot_cannot_seed_access_hints() {
    let election_id = ir::Temp(0);
    let ciphertext = ir::Temp(1);
    let nullifier = ir::Temp(2);
    let backend = ir::Temp(3);
    let proof = ir::Temp(4);
    let vk = ir::Temp(5);
    let func_idx = 0;
    let base_map = |selector: &str| {
        let mut string_map = HashMap::new();
        string_map.insert((func_idx, election_id), selector.to_owned());
        string_map.insert((func_idx, ciphertext), "0x00".to_owned());
        string_map.insert((func_idx, nullifier), format!("0x{}", "00".repeat(32)));
        string_map.insert((func_idx, backend), "halo2/ipa".to_owned());
        string_map.insert((func_idx, proof), "0x01".to_owned());
        string_map.insert((func_idx, vk), "vk_ballot".to_owned());
        string_map
    };
    let fold = |selector: &str| {
        super::submit_ballot_inline_instruction_literal(
            &base_map(selector),
            func_idx,
            election_id,
            ciphertext,
            nullifier,
            backend,
            proof,
            vk,
        )
    };
    let maximum = "a".repeat(128);
    for selector in ["a", maximum.as_str()] {
        let raw = fold(selector).expect("canonical selector must produce a literal");
        assert!(
            super::access_for_instruction_literal(&raw).is_some(),
            "canonical selector must remain eligible for static access hints"
        );
    }
    let overlong = "a".repeat(129);
    for selector in [
        "",
        ".",
        ".hidden",
        "a/b",
        "a%2Fb",
        "a b",
        "a\0b",
        "投票",
        overlong.as_str(),
    ] {
        assert!(
            fold(selector).is_none(),
            "noncanonical selector {selector:?} must not produce an instruction literal or access hints"
        );
    }
}
#[test]
fn literal_instruction_bridge_keeps_transitive_access_hints_conservative() {
    let source = r#"
seiyaku BallotAccess { permission Invoke;
    fn submit() {
        let instruction = ledger::governance::build_submit_ballot(
            election_id: "election",
            ciphertext: b"ciphertext",
            nullifier: b"0123456789abcdef0123456789abcdef",
            backend: "halo2/ipa",
            proof: b"proof",
            verification_key: b"key",
        );
        ledger::governance::submit_ballot(value: instruction);
    }
    kotoage fn run() authorize(Invoke) {
        submit();
    }
}
"#;
    let (program, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .expect("compile a literal instruction behind an internal call");
    let entrypoints = manifest.entrypoints.expect("manifest entrypoints");
    let entrypoint = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .unwrap();
    assert_eq!(entrypoint.access_hints_complete, Some(false));
    assert!(entrypoint.write_keys.iter().any(|key| key == "*"));
    assert!(
        entrypoint
            .write_keys
            .iter()
            .any(|key| key == "zk:election:election:nullifiers")
    );
    assert!(
        entrypoint
            .access_hints_skipped
            .iter()
            .any(|reason| reason == HINT_SKIP_DYNAMIC_INSTRUCTION_BRIDGE)
    );
    let parsed = ProgramMetadata::parse(&program).expect("parse emitted contract");
    let interface = parsed
        .contract_interface
        .expect("embedded contract interface");
    let embedded = interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .unwrap();
    assert_eq!(
        embedded.access_hints_complete,
        entrypoint.access_hints_complete
    );
    assert_eq!(embedded.write_keys, entrypoint.write_keys);
}

#[test]
fn inline_submit_ballot_builtin_rejects_invalid_arguments() {
    let src = include_str!("fixtures/v1/c084.ko");
    let expected = "ledger::governance::build_submit_ballot expects (string election_id, bytes ciphertext, bytes nullifier32, string backend, bytes proof, bytes vk)";
    let parsed = parse(src).expect("parse invalid inline builder source");
    let err = analyze(&parsed).expect_err("semantic analysis should reject inline builder args");
    assert!(
        err.message.contains(expected),
        "expected error containing {expected:?}, got {}",
        err.message
    );
}
#[test]
fn vendor_bridge_and_subscription_builtins_emit_syscalls() {
    let src = include_str!("fixtures/v1/c197.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(src)
        .expect("compile vendor bridge and subscription helpers");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    let syscall_needle = |syscall: u32| {
        encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("test syscall id fits in u8"),
        )
        .to_le_bytes()
    };
    let execute_instruction =
        syscall_needle(ivm_abi::syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION);
    let execute_instruction_count = code
        .windows(execute_instruction.len())
        .filter(|window| *window == execute_instruction)
        .count();
    assert_eq!(
        execute_instruction_count, 1,
        "the typed governance operation should lower to SMARTCONTRACT_EXECUTE_INSTRUCTION"
    );
    let tag_word = encode_addi(
        11,
        0,
        i16::try_from(ivm_abi::syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT)
            .expect("instruction tag fits i16"),
    )
    .expect("encode instruction tag")
    .to_le_bytes();
    assert!(
        code.windows(tag_word.len())
            .any(|window| window == tag_word),
        "expected SubmitBallot operation tag in compiled code"
    );
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SUBSCRIPTION_BILL,
            "SUBSCRIPTION_BILL",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SUBSCRIPTION_RECORD_USAGE,
            "SUBSCRIPTION_RECORD_USAGE",
        ),
    ] {
        let needle = syscall_needle(syscall);
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
}
#[test]
fn vendor_bridge_and_subscription_builtins_reject_invalid_arguments() {
    let expected = "call `ledger::subscription::record_usage` expects at most 0 arguments";
    let parsed = parse(include_str!("fixtures/v1/c087.ko")).expect("parse source");
    let err =
        analyze(&parsed).expect_err("semantic analysis should reject bridge/subscription args");
    assert!(
        err.message.contains(expected),
        "expected `{expected}`, got `{}`",
        err.message
    );
    assert_internal_source_names_rejected(&[
        "query_execute_norito",
        "execute_query",
        "ledger::query::execute_raw",
    ]);
}
#[test]
fn raw_contract_calls_are_not_a_source_api() {
    for call in [
        r#"contract::call(contract: target, entrypoint: "settle", arguments: payload)"#,
        r#"seiyaku::call(contract: target, entrypoint: "settle", arguments: payload)"#,
        r#"call_contract(target, "settle", payload)"#,
    ] {
        let src = format!(
            r#"seiyaku Relay {{ permission Admin;
  kotoage fn run(bytes target, Json payload) authorize(Admin) -> bytes {{
    return {call};
  }}
}}"#
        );
        let error = test_mode_compiler()
            .compile_source(&src)
            .expect_err("raw contract-call bridge must be compiler-internal");
        assert!(
            error.contains("K1001")
                || error.contains("unknown function or builtin")
                || error.contains("E_UNKNOWN_BUILTIN")
                || error.contains("compiler-internal"),
            "unexpected raw-call error: {error}"
        );
    }
}
#[test]
fn hash_builtins_emit_hash_syscalls_and_complete_access() {
    let src = include_str!("fixtures/v1/c088.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile hash helpers");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (ivm_abi::syscalls::SYSCALL_SM3_HASH, "SM3_HASH"),
        (ivm_abi::syscalls::SYSCALL_SHA256_HASH, "SHA256_HASH"),
        (ivm_abi::syscalls::SYSCALL_SHA3_HASH, "SHA3_HASH"),
        (
            ivm_abi::syscalls::SYSCALL_BLAKE2B256_HASH,
            "BLAKE2B256_HASH",
        ),
        (ivm_abi::syscalls::SYSCALL_KECCAK256_HASH, "KECCAK256_HASH"),
        (ivm_abi::syscalls::SYSCALL_IROHA_HASH, "IROHA_HASH"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("hash syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let digest = entrypoints
        .iter()
        .find(|entry| entry.name == "digest")
        .expect("digest entrypoint");
    assert_ne!(digest.access_hints_complete, Some(false));
    assert!(digest.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&digest.read_keys);
    assert!(digest.write_keys.is_empty());
}
#[test]
fn hash_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c089.ko"),
            "crypto::sha256 expects (bytes) argument pointing to INPUT TLV",
        ),
        (
            include_str!("fixtures/v1/c090.ko"),
            "crypto::sm3 expects (bytes) argument pointing to INPUT TLV",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = analyze(&parsed).expect_err("semantic analysis should reject hash args");
        assert!(
            err.message.contains(expected),
            "expected `{expected}`, got `{}`",
            err.message
        );
    }
}
#[test]
fn crypto_builtins_emit_signature_and_sm4_syscalls_and_complete_access() {
    let src = include_str!("fixtures/v1/c091.ko");
    let compiler = test_mode_compiler();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile crypto helpers");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
            "INPUT_PUBLISH_TLV",
        ),
        (ivm_abi::syscalls::SYSCALL_SM2_VERIFY, "SM2_VERIFY"),
        (
            ivm_abi::syscalls::SYSCALL_VERIFY_SIGNATURE,
            "VERIFY_SIGNATURE",
        ),
        (ivm_abi::syscalls::SYSCALL_SM4_GCM_SEAL, "SM4_GCM_SEAL"),
        (ivm_abi::syscalls::SYSCALL_SM4_GCM_OPEN, "SM4_GCM_OPEN"),
        (ivm_abi::syscalls::SYSCALL_SM4_CCM_SEAL, "SM4_CCM_SEAL"),
        (ivm_abi::syscalls::SYSCALL_SM4_CCM_OPEN, "SM4_CCM_OPEN"),
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("crypto syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall in compiled code"
        );
    }
    let entrypoints = manifest.entrypoints.expect("entrypoints must be present");
    let crypt = entrypoints
        .iter()
        .find(|entry| entry.name == "crypt")
        .expect("crypt entrypoint");
    assert_ne!(crypt.access_hints_complete, Some(false));
    assert!(crypt.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&crypt.read_keys);
    assert!(crypt.write_keys.is_empty());
}
#[test]
fn crypto_builtins_reject_invalid_arguments() {
    for (src, expected) in [
        (
            include_str!("fixtures/v1/c092.ko"),
            "E_MISSING_NAMED_ARGUMENT",
        ),
        (
            include_str!("fixtures/v1/c093.ko"),
            "crypto::sm2::verify optional distid must be provided as bytes pointer",
        ),
        (
            include_str!("fixtures/v1/c094.ko"),
            "crypto::verify_signature expects (message: bytes, signature: bytes, public_key: bytes, scheme: SignatureScheme)",
        ),
        (
            include_str!("fixtures/v1/c095.ko"),
            "crypto::sm4_gcm::seal expects (bytes, bytes, bytes, bytes)",
        ),
        (
            include_str!("fixtures/v1/c096.ko"),
            "crypto::sm4_ccm::seal optional tag length must be int",
        ),
    ] {
        let parsed = parse(src).expect("parse source");
        let err = analyze(&parsed).expect_err("semantic analysis should reject crypto args");
        if expected.starts_with("E_") {
            assert_eq!(err.code, expected, "unexpected diagnostic: {err:?}");
        } else {
            assert!(
                err.message.contains(expected),
                "expected `{expected}`, got `{}`",
                err.message
            );
        }
    }
}
#[test]
fn raw_codec_builtins_are_not_a_source_api() {
    assert_internal_source_names_rejected(&[
        "encode_int",
        "decode_int",
        "encode_json",
        "decode_json",
        "codec::encode_i64",
        "codec::decode_i64",
        "codec::encode_json",
        "codec::decode_json",
    ]);
}
#[test]
fn truncated_scalar_crypto_and_ephemeral_nullifiers_are_not_source_apis() {
    assert_internal_source_names_rejected(&[
        "crypto::poseidon2",
        "crypto::poseidon6",
        "crypto::pubkgen",
        "crypto::use_nullifier",
    ]);
}
#[test]
fn public_scalar_valcom_is_rejected() {
    let src = include_str!("fixtures/v1/c097.ko");
    let parsed = parse(src).expect("parse public valcom source");
    let error = semantic::SemanticContext::with_zk_enabled(true)
        .analyze(&parsed)
        .expect_err("public scalar valcom must fail closed");
    assert_eq!(error.code, "K2003");
    assert_eq!(
        error.message,
        "crypto::valcom expects two typed Secret<int|decimal|quantity> arguments"
    );
}
#[test]
fn retired_numeric_helper_surface_is_rejected() {
    for call in [
        "numeric::neg(1)",
        "numeric::to_i64(1)",
        "numeric::add(left: 1, right: 2)",
        "numeric::rem(left: 1, right: 2)",
        "numeric::ge(left: 1, right: 2)",
    ] {
        let source = format!(
            "seiyaku CompilerFixture {{ view fn probe() authorize(anyone) -> int {{ let value = {call}; return 0; }} }}"
        );
        let error = test_mode_compiler()
            .compile_source(&source)
            .expect_err("retired numeric helper must be unknown");
        assert!(
            error.contains("E_RETIRED_NUMERIC_HELPER"),
            "unexpected rejection for {call}: {error}"
        );
    }
    let canonical = include_str!("fixtures/v1/c098.ko");
    test_mode_compiler()
        .compile_source(canonical)
        .expect("canonical V1 wrapping helpers must not match retired-helper diagnostics");
}
#[test]
fn numeric_operators_emit_the_nominal_v1_syscall_families() {
    let source = include_str!("fixtures/v1/c099.ko");
    let artifact = test_mode_compiler()
        .compile_source(source)
        .expect("compile exact numeric operators");
    let metadata = ProgramMetadata::parse(&artifact).expect("parse metadata");
    let code = &artifact[metadata.code_offset..];
    for syscall in [
        ivm_abi::syscalls::SYSCALL_INT_ADD,
        ivm_abi::syscalls::SYSCALL_DECIMAL_MUL,
        ivm_abi::syscalls::SYSCALL_QUANTITY_SUB,
        ivm_abi::syscalls::SYSCALL_QUANTITY_RATIO_EXACT,
        ivm_abi::syscalls::SYSCALL_QUANTITY_GE,
    ] {
        let encoded = encoding::wide::encode_syscallx(syscall).to_le_bytes();
        assert!(
            code.windows(encoded.len()).any(|window| window == encoded),
            "missing V1 numeric syscall {syscall:#x}"
        );
    }
}
#[test]
fn raw_name_decode_builtin_is_not_a_source_api() {
    assert_internal_source_names_rejected(&["name_decode", "codec::decode_name"]);
}
#[test]
fn raw_pointer_codec_plumbing_is_not_a_source_api() {
    assert_internal_source_names_rejected(&[
        "tlv_eq",
        "tlv_len",
        "pointer_to_norito",
        "codec::tlv_eq",
        "codec::tlv_len",
        "codec::to_norito",
    ]);
    for (name, code, message) in [
        (
            "path",
            "K2002",
            "`path(...)` was removed as a free helper; use `base.path(segment)`",
        ),
        (
            "codec::path",
            "E_UNKNOWN_BUILTIN",
            "unknown builtin `codec::path`",
        ),
    ] {
        let source = format!(
            "seiyaku CompilerFixture {{ view fn probe() authorize(anyone) -> int {{ {name}(); return 0; }} }}"
        );
        let error = test_mode_compiler()
            .compile_source(&source)
            .expect_err("retired raw path helpers must not resolve from source");
        assert!(
            error.contains(code) && error.contains(message),
            "path helper `{name}` did not retain its canonical rejection: {error}"
        );
    }
}
#[test]
fn bytes_len_emits_only_the_typed_tlv_length_path_and_complete_access() {
    let source = include_str!("fixtures/v1/c100.ko");
    let (artifact, manifest) = test_mode_compiler()
        .compile_source_with_manifest(source)
        .expect("typed bytes length must compile");
    let parsed = ProgramMetadata::parse(&artifact).expect("parse bytes length artifact");
    let code = &artifact[parsed.code_offset..];
    for syscall in [
        ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV,
        ivm_abi::syscalls::SYSCALL_TLV_LEN,
    ] {
        let needle = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscall).expect("bytes length syscall id fits in u8"),
        )
        .to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "missing bytes length syscall {syscall:#x}"
        );
    }
    let entrypoint = manifest
        .entrypoints
        .expect("entrypoint manifest")
        .into_iter()
        .find(|entrypoint| entrypoint.name == "length")
        .expect("length entrypoint");
    assert_ne!(entrypoint.access_hints_complete, Some(false));
    assert!(entrypoint.access_hints_skipped.is_empty());
    assert_no_ledger_reads(&entrypoint.read_keys);
    assert!(entrypoint.write_keys.is_empty());
}
#[test]
fn bytes_len_rejects_wrong_types_flat_aliases_and_raw_codec_names() {
    for ty in ["Json", "Name", "AccountId", "string", "int"] {
        let source = format!(
            "seiyaku CompilerFixture {{ view fn probe({ty} value) authorize(anyone) -> int {{ return bytes::len(value); }} }}"
        );
        let error = test_mode_compiler()
            .compile_source(&source)
            .expect_err("bytes::len must accept only bytes");
        assert!(
            error.contains("bytes::len expects exactly one bytes argument"),
            "wrong-type `{ty}` was rejected for the wrong reason: {error}"
        );
    }
    for name in [
        "len",
        "bytes_len",
        "codec::len",
        "tlv_len",
        "codec::tlv_len",
    ] {
        let source = format!(
            "seiyaku CompilerFixture {{ view fn probe(bytes value) authorize(anyone) -> int {{ return {name}(value); }} }}"
        );
        let error = test_mode_compiler()
            .compile_source(&source)
            .expect_err("legacy or raw length helper must not resolve");
        assert!(
            error.contains("K1001")
                || error.contains("K2002")
                || error.contains("E_INTERNAL_BUILTIN")
                || error.contains("E_UNKNOWN_BUILTIN")
                || error.contains("unknown function or builtin")
                || error.contains("compiler-internal"),
            "helper `{name}` was rejected for the wrong reason: {error}"
        );
    }
}
#[test]
fn account_id_alias_literal_emits_resolve_account_alias_syscall() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c101.ko"))
        .expect("compile alias shorthand");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected RESOLVE_ACCOUNT_ALIAS syscall for alias shorthand"
    );
}
#[test]
fn account_id_domain_qualified_alias_literal_emits_resolve_account_alias_syscall() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c102.ko"))
        .expect("compile domain-qualified alias shorthand");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected RESOLVE_ACCOUNT_ALIAS syscall for domain-qualified alias shorthand"
    );
}
#[test]
fn resolve_account_alias_builtin_emits_syscall() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c103.ko"))
        .expect("compile builtin alias resolution");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected RESOLVE_ACCOUNT_ALIAS syscall for builtin alias resolution"
    );
}
#[test]
fn resolve_account_alias_builtin_rejects_invalid_arguments() {
    let parsed =
        parse(include_str!("fixtures/v1/c104.ko")).expect("parse invalid alias resolution");
    let err = analyze(&parsed).expect_err("semantic analysis should reject alias arg type");
    assert!(
        err.message
            .contains("ledger::account::resolve_alias expects (string|bytes)"),
        "unexpected semantic error: {}",
        err.message
    );
}
#[test]
fn public_context_builtins_emit_syscalls() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c105.ko"))
        .expect("compile runtime sysvars");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (ivm_abi::syscalls::SYSCALL_GET_AUTHORITY, "GET_AUTHORITY"),
        (
            ivm_abi::syscalls::SYSCALL_SYSVAR_CONTRACT_SUBJECT,
            "SYSVAR_CONTRACT_SUBJECT",
        ),
        (
            ivm_abi::syscalls::SYSCALL_CURRENT_TIME_MS,
            "CURRENT_TIME_MS",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT,
            "SYSVAR_BLOCK_HEIGHT",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SYSVAR_CHAIN_ID,
            "SYSVAR_CHAIN_ID",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS,
            "SYSVAR_CONTRACT_ADDRESS",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SYSVAR_ENTRYPOINT,
            "SYSVAR_ENTRYPOINT",
        ),
    ] {
        let word = if let Ok(imm8) = u8::try_from(syscall) {
            encoding::wide::encode_sys(instruction::wide::system::SCALL, imm8)
        } else {
            encoding::wide::encode_syscallx(syscall)
        };
        let needle = word.to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall"
        );
    }
}
#[test]
fn public_context_builtins_reject_invalid_arguments() {
    for (source, expected) in [
        (
            include_str!("fixtures/v1/c106.ko"),
            "call `context::authority` expects at most 0 arguments",
        ),
        (
            include_str!("fixtures/v1/c107.ko"),
            "call `context::seiyaku_subject` expects at most 0 arguments",
        ),
        (
            include_str!("fixtures/v1/c108.ko"),
            "call `context::block_height` expects at most 0 arguments",
        ),
        (
            include_str!("fixtures/v1/c109.ko"),
            "call `context::chain_id` expects at most 0 arguments",
        ),
    ] {
        let parsed = parse(source).expect("parse invalid runtime sysvar call");
        let err = analyze(&parsed).expect_err("semantic analysis should reject sysvar arity");
        assert!(
            err.message.contains(expected),
            "unexpected semantic error: {}",
            err.message
        );
    }
    assert_internal_source_names_rejected(&["sysvar_authority"]);
}
#[test]
fn native_control_and_recovery_builtins_emit_typed_syscalls() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c110.ko"))
        .expect("compile typed native control and recovery calls");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    for (syscall, label) in [
        (
            ivm_abi::syscalls::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY,
            "SET_ASSET_TRANSFER_AVAILABILITY",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT,
            "SET_ASSET_TRANSFER_DAILY_LIMIT",
        ),
        (
            ivm_abi::syscalls::SYSCALL_SET_ASSET_HOLDING_LIMIT,
            "SET_ASSET_HOLDING_LIMIT",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_PROPOSE,
            "ACCOUNT_RECOVERY_PROPOSE",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_APPROVE,
            "ACCOUNT_RECOVERY_APPROVE",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_CANCEL,
            "ACCOUNT_RECOVERY_CANCEL",
        ),
        (
            ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_FINALIZE,
            "ACCOUNT_RECOVERY_FINALIZE",
        ),
    ] {
        let needle = encoding::wide::encode_syscallx(syscall).to_le_bytes();
        assert!(
            code.windows(needle.len()).any(|window| window == needle),
            "expected {label} syscall"
        );
    }
}
#[test]
fn native_control_and_recovery_builtins_reject_wrong_types_and_arity() {
    for (source, expected) in [
        (
            include_str!("fixtures/v1/c111.ko"),
            "ledger::asset::set_transfer_availability expects (AccountId, AssetDefinitionId, int, bool, bool, Option<string>)",
        ),
        (
            include_str!("fixtures/v1/c112.ko"),
            "ledger::asset::set_transfer_daily_limit expects (AccountId, AssetDefinitionId, Option<quantity>)",
        ),
        (
            include_str!("fixtures/v1/c113.ko"),
            "ledger::asset::set_holding_limit expects (AccountId, AssetDefinitionId, Option<quantity>)",
        ),
        (
            include_str!("fixtures/v1/c114.ko"),
            "ledger::account::recovery::propose expects (string, AccountId, int)",
        ),
        (
            include_str!("fixtures/v1/c115.ko"),
            "ledger::account::recovery::approve expects (string, int)",
        ),
        (
            include_str!("fixtures/v1/c116.ko"),
            "call `ledger::account::recovery::cancel` expects at most 2 arguments",
        ),
        (
            include_str!("fixtures/v1/c117.ko"),
            "call `ledger::account::recovery::finalize` is missing required argument `alias`",
        ),
    ] {
        let parsed = parse(source).expect("parse invalid native control/recovery call");
        let error = analyze(&parsed)
            .expect_err("semantic analysis must reject invalid native control/recovery call");
        assert!(
            error.message.contains(expected),
            "expected `{expected}`, got `{}`",
            error.message
        );
    }
}
#[test]
fn recovery_builtins_require_explicit_request_generation() {
    for (call, expected) in [
        (
            "ledger::account::recovery::propose(alias: alias, replacement: replacement)",
            "missing required argument `request_generation`",
        ),
        (
            "ledger::account::recovery::approve(alias: alias)",
            "missing required argument `request_generation`",
        ),
        (
            "ledger::account::recovery::cancel(alias: alias, request_generation: \"one\")",
            "expects (string, int)",
        ),
        (
            "ledger::account::recovery::finalize(alias: alias, request_generation: true)",
            "expects (string, int)",
        ),
    ] {
        let source = format!(
            "seiyaku RecoveryGeneration {{ fn apply(string alias, AccountId replacement) {{ {call}; }} }}"
        );
        let parsed = parse(&source).expect("parse recovery generation guard case");
        let error = analyze(&parsed).expect_err("unbound recovery mutations must be rejected");
        assert!(
            error.message.contains(expected),
            "expected `{expected}`, got `{}`",
            error.message
        );
    }
}
#[test]
fn create_nfts_for_all_users_builtin_emits_syscall() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c118.ko"))
        .expect("compile create-for-all-users operation");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let code = &bytes[parsed.code_offset..];
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_abi::syscalls::SYSCALL_CREATE_NFTS_FOR_ALL_USERS)
            .expect("create-for-all-users syscall fits imm8"),
    )
    .to_le_bytes();
    assert!(
        code.windows(needle.len()).any(|window| window == needle),
        "expected CREATE_NFTS_FOR_ALL_USERS syscall"
    );
}
#[test]
fn create_nfts_for_all_users_builtin_rejects_invalid_arguments() {
    let source = include_str!("fixtures/v1/c119.ko");
    let parsed = parse(source).expect("parse invalid create-for-all-users call");
    let err = analyze(&parsed).expect_err("semantic analysis should reject unexpected args");
    assert!(
        err.message
            .contains("call `ledger::nft::create_for_all_users` expects at most 0 arguments"),
        "unexpected semantic error: {}",
        err.message
    );
}
#[test]
fn runtime_execution_controls_are_not_source_apis() {
    assert_internal_source_names_rejected(&[
        "set_execution_depth",
        "ledger::parameters::set_execution_depth",
    ]);
}
#[test]
fn resolve_account_alias_invalid_literal_emits_syscall() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c120.ko"))
        .expect("compile malformed builtin alias resolution");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected RESOLVE_ACCOUNT_ALIAS syscall for malformed builtin alias literals"
    );
}
#[test]
fn resolve_account_alias_domain_qualified_builtin_emits_syscall() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c121.ko"))
        .expect("compile domain-qualified builtin alias resolution");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected RESOLVE_ACCOUNT_ALIAS syscall for domain-qualified builtin"
    );
}
#[test]
fn resolve_account_alias_invalid_domain_qualified_literal_emits_syscall() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c122.ko"))
        .expect("compile malformed domain-qualified builtin alias resolution");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let needle = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(needle.len())
            .any(|window| window == needle),
        "expected RESOLVE_ACCOUNT_ALIAS syscall for malformed domain-qualified builtin alias literals"
    );
}
#[test]
fn account_id_canonical_literal_stays_static_without_alias_resolution() {
    let canonical = iroha_data_model::account::AccountId::new(
        "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
            .parse()
            .expect("public key"),
    )
    .to_string();
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(&format!(
            r#"
seiyaku CompilerFixture {{
view fn account() authorize(anyone) -> AccountId {{ return AccountId::parse("{canonical}"); }}
}}
"#
        ))
        .expect("compile canonical account literal");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let resolve = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        !bytes[parsed.code_offset..]
            .windows(resolve.len())
            .any(|window| window == resolve),
        "canonical AccountId literals must not emit alias resolution syscalls"
    );
    let static_tlv =
        super::encode_pointer_tlv_bytes(super::ir::DataRefKind::Account, &canonical, false)
            .expect("encode static AccountId tlv");
    assert!(
        bytes
            .windows(static_tlv.len())
            .any(|window| window == static_tlv),
        "canonical AccountId literals should be embedded as static TLVs"
    );
}
#[test]
fn account_id_invalid_alias_shaped_literal_compiles_for_runtime_resolution() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c123.ko"))
        .expect("compile invalid alias-shaped literal");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let resolve = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(resolve.len())
            .any(|window| window == resolve),
        "alias-shaped literals should defer validation to runtime resolution"
    );
}
#[test]
fn account_id_invalid_domain_qualified_alias_shaped_literal_compiles_for_runtime_resolution() {
    let compiler = test_mode_compiler();
    let bytes = compiler
        .compile_source(include_str!("fixtures/v1/c124.ko"))
        .expect("compile invalid domain-qualified alias-shaped literal");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    let resolve = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_abi::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS as u8,
    )
    .to_le_bytes();
    assert!(
        bytes[parsed.code_offset..]
            .windows(resolve.len())
            .any(|window| window == resolve),
        "invalid domain-qualified alias-shaped literals should defer validation to runtime resolution"
    );
}
#[test]
fn account_id_invalid_non_alias_literal_fails_compile_time_encoding() {
    let compiler = test_mode_compiler();
    let err = compiler
        .compile_source(include_str!("fixtures/v1/c125.ko"))
        .expect_err("invalid non-alias account literal should fail compile-time encoding");
    assert!(
        err.contains("invalid AccountId literal"),
        "expected AccountId literal error, got: {err}"
    );
    assert!(
        err.contains("merchant"),
        "expected failing literal in error, got: {err}"
    );
}
#[test]
fn detect_vector_usage_includes_vector_gated_crypto_ops() {
    let ops = [
        instruction::wide::crypto::SHA256BLOCK,
        instruction::wide::crypto::AESENC,
        instruction::wide::crypto::AESDEC,
    ];
    for op in ops {
        let word = encoding::wide::encode_rr(op, 0, 0, 0);
        let code = word.to_le_bytes();
        assert!(
            super::detect_vector_usage(&code),
            "expected vector usage for opcode {op:#04x}"
        );
    }
}
#[test]
fn detect_zk_usage_includes_zk_ops() {
    let ops = [
        instruction::wide::zk::ASSERT,
        instruction::wide::zk::ASSERT_EQ,
        instruction::wide::zk::FADD,
    ];
    for op in ops {
        let word = encoding::wide::encode_rr(op, 0, 0, 0);
        let code = word.to_le_bytes();
        assert!(
            super::detect_zk_usage(&code),
            "expected zk usage for opcode {op:#04x}"
        );
    }
}
#[test]
fn require_exports_nominal_error_type_and_uses_contract_abort_syscall() {
    let src = include_str!("fixtures/v1/c126.ko");
    let compiler = test_mode_compiler();
    let output = compiler
        .compile_source_output(src, None)
        .expect("compile require");
    let bytes = output.artifact;
    let manifest = output.manifest;
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    assert_eq!(
        parsed.metadata.mode & crate::metadata::mode::ZK,
        0,
        "require should not enable ZK mode"
    );
    assert!(
        parsed.contract_interface.is_none(),
        "local test harness must keep its interface in the sidecar"
    );
    let sidecar_types = output.contract_interface.error_types.as_slice();
    let manifest_types = manifest
        .error_types
        .as_deref()
        .expect("manifest error types");
    assert_eq!(sidecar_types, manifest_types);
    let payment_error = sidecar_types
        .iter()
        .find(|descriptor| descriptor.identity.ends_with("::PaymentError"))
        .expect("PaymentError descriptor");
    assert_eq!(payment_error.variants.len(), 1);
    assert_eq!(payment_error.variants[0].name, "Unauthorized");
    assert_eq!(payment_error.variants[0].code, 1001);
    let mut found_abort = false;
    let mut found_zk_assert = false;
    for chunk in bytes[parsed.code_offset..].chunks_exact(4) {
        let word = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap());
        let op = instruction::wide::opcode(word);
        if op == instruction::wide::system::SCALL {
            let (_op, imm8) = encoding::wide::decode_sys(word);
            if imm8 == crate::syscalls::SYSCALL_CONTRACT_ABORT as u8 {
                found_abort = true;
            }
        }
        if op == instruction::wide::zk::ASSERT || op == instruction::wide::zk::ASSERT_EQ {
            found_zk_assert = true;
        }
    }
    assert!(
        found_abort,
        "expected CONTRACT_ABORT syscall in compiled require"
    );
    assert!(
        !found_zk_assert,
        "require should not emit ZK ASSERT/ASSERT_EQ opcodes"
    );
}
#[test]
fn assert_compiles_without_zk_mode_and_uses_abort_syscall() {
    let src = include_str!("fixtures/v1/c127.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler.compile_source(src).expect("compile assert");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    assert_eq!(
        parsed.metadata.mode & crate::metadata::mode::ZK,
        0,
        "assert should not enable ZK mode"
    );
    let mut found_abort = false;
    let mut found_zk_assert = false;
    for chunk in bytes[parsed.code_offset..].chunks_exact(4) {
        let word = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap());
        let op = instruction::wide::opcode(word);
        if op == instruction::wide::system::SCALL {
            let (_op, imm8) = encoding::wide::decode_sys(word);
            if imm8 == crate::syscalls::SYSCALL_ABORT as u8 {
                found_abort = true;
            }
        }
        if op == instruction::wide::zk::ASSERT || op == instruction::wide::zk::ASSERT_EQ {
            found_zk_assert = true;
        }
    }
    assert!(found_abort, "expected ABORT syscall in compiled assert");
    assert!(
        !found_zk_assert,
        "assert should not emit ZK ASSERT/ASSERT_EQ opcodes"
    );
}
#[test]
fn assert_eq_compiles_without_zk_mode_and_uses_abort_syscall() {
    let src = include_str!("fixtures/v1/c128.ko");
    let compiler = test_mode_compiler();
    let bytes = compiler.compile_source(src).expect("compile assert_eq");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse metadata");
    assert_eq!(
        parsed.metadata.mode & crate::metadata::mode::ZK,
        0,
        "assert_eq should not enable ZK mode"
    );
    let mut found_abort = false;
    let mut found_zk_assert = false;
    for chunk in bytes[parsed.code_offset..].chunks_exact(4) {
        let word = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap());
        let op = instruction::wide::opcode(word);
        if op == instruction::wide::system::SCALL {
            let (_op, imm8) = encoding::wide::decode_sys(word);
            if imm8 == crate::syscalls::SYSCALL_ABORT as u8 {
                found_abort = true;
            }
        }
        if op == instruction::wide::zk::ASSERT || op == instruction::wide::zk::ASSERT_EQ {
            found_zk_assert = true;
        }
    }
    assert!(found_abort, "expected ABORT syscall in compiled assert_eq");
    assert!(
        !found_zk_assert,
        "assert_eq should not emit ZK ASSERT/ASSERT_EQ opcodes"
    );
}
#[test]
fn source_meta_cannot_override_build_configuration() {
    let src = include_str!("fixtures/v1/c129.ko");
    let compiler = Compiler::new();
    let err = compiler
        .compile_source(src)
        .expect_err("source policy must be rejected");
    assert!(err.contains("source-level `meta { ... }` is not supported"));
}
#[test]
fn production_rejects_test_only_assertions() {
    for assertion in [
        "test::assert(true);",
        "test::assert_eq(actual: 1, expected: 1);",
    ] {
        let source = format!(
            "seiyaku Test {{ permission Entry;  kotoage fn main() authorize(Entry) {{ {assertion} }} }}"
        );
        let error = Compiler::new()
            .compile_source(&source)
            .expect_err("production assertion must be rejected");
        assert!(
            error.contains("E_TEST_ONLY_PRODUCTION")
                && error.contains("explicit compiler test mode"),
            "unexpected error for `{assertion}`: {error}"
        );
        test_mode_compiler()
            .compile_source(&source)
            .expect("test mode should enable assertion builtins");
    }
}
#[test]
fn vector_length_is_compiler_owned() {
    for expression in ["runtime::set_vector_length(8)", "setvl(8)"] {
        let src = format!(
            r#"seiyaku Test {{ permission Entry;
  kotoage fn main() authorize(Entry) {{ {expression}; }}
}}"#
        );
        let error = Compiler::new()
            .compile_source(&src)
            .expect_err("source must not select vector metadata");
        assert!(
            error.contains("unknown function or builtin") || error.contains("compiler-internal"),
            "unexpected vector-control error: {error}"
        );
    }
}
#[test]
fn manifest_access_set_hints_from_state_only_contract() {
    let src = include_str!("fixtures/v1/c130.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert_eq!(hints.read_keys, vec![STATE_WILDCARD_KEY.to_string()]);
    assert_eq!(hints.write_keys, vec![STATE_WILDCARD_KEY.to_string()]);
}
#[test]
fn zero_arg_public_entrypoint_retains_scalar_state_hints() {
    let src = include_str!("fixtures/v1/c131.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert_eq!(hints.read_keys, vec!["state:counter".to_string()]);
    assert_eq!(
        hints.write_keys,
        vec!["state:counter".to_string()],
        "the seiyaku-wide union must include the hajimari write"
    );
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let run = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    assert_eq!(run.read_keys, vec!["state:counter".to_string()]);
    assert!(run.write_keys.is_empty());
    assert_eq!(run.access_hints_complete, Some(true));
    assert!(run.access_hints_skipped.is_empty());
}
#[test]
fn whole_program_dce_excludes_dead_private_dynamic_access_hints() {
    let src = include_str!("fixtures/v1/c132.ko");
    let (_bytes, manifest, report) = Compiler::new()
        .compile_source_with_manifest_and_report(src)
        .expect("compile reachable access hints");
    assert!(
        report
            .budget_report
            .iter()
            .all(|function| function.function_name != "dead_lookup")
    );
    let hints = manifest
        .access_set_hints
        .expect("reachable scalar state emits access hints");
    assert!(
        hints.dynamic_reads.is_empty(),
        "a dynamic read in removed private code must not constrain scheduler metadata: {hints:?}"
    );
}
#[test]
fn unreachable_scans_in_retained_functions_emit_no_dynamic_hints() {
    for body in [
        include_str!("fixtures/v1/c133.ko"),
        include_str!("fixtures/v1/c134.ko"),
        include_str!("fixtures/v1/c135.ko"),
        include_str!("fixtures/v1/c136.ko"),
    ] {
        let source = format!(
            r#"
seiyaku ReachableHintControlFlow {{
  state StateMap<int, int> Entries;

  view fn scan(bool flag) authorize(anyone) -> int {{
{body}
  }}
}}
"#
        );
        let (_bytes, manifest) = Compiler::new()
            .compile_source_with_manifest(&source)
            .expect("compile retained function with unreachable scan");
        assert!(
            manifest
                .access_set_hints
                .as_ref()
                .is_none_or(|hints| hints.dynamic_reads.is_empty()),
            "a scan with no reachable bytecode must not emit a dynamic hint"
        );
    }
}
#[test]
fn expression_nested_scans_retain_post_optimization_provenance() {
    let cases = [
        (
            include_str!("fixtures/v1/c137.ko"),
            ("state:Entries", "Name", "take", 64),
        ),
        (
            include_str!("fixtures/v1/c138.ko"),
            ("state:Entries", "int", "page", 64),
        ),
    ];
    for (source, expected) in cases {
        let (_artifact, manifest) = Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile expression-nested StateMap scan");
        let hints = manifest
            .access_set_hints
            .expect("reachable expression scan must emit access hints");
        let actual = hints
            .dynamic_reads
            .iter()
            .map(|hint| {
                (
                    hint.base_key.as_str(),
                    hint.key_type.as_str(),
                    hint.bound_kind.as_str(),
                    hint.max_keys,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, vec![expected]);
    }
}
#[test]
fn optimized_ir_dynamic_provenance_must_match_the_emitted_state_schema() {
    use iroha_data_model::smart_contract::manifest::DynamicAccessHint;
    fn state_scan(dynamic_access_hint: DynamicAccessHint) -> ir::Instr {
        ir::Instr::StateScan {
            page: ir::Temp(0),
            next: ir::Temp(1),
            count: ir::Temp(2),
            examined: ir::Temp(3),
            base: ir::Temp(4),
            after: ir::Temp(5),
            limit: ir::Temp(6),
            dynamic_access_hint,
        }
    }
    fn hint(key_type: &str) -> DynamicAccessHint {
        DynamicAccessHint {
            base_key: "state:Orders".to_owned(),
            key_type: key_type.to_owned(),
            bound_kind: "take".to_owned(),
            max_keys: 64,
        }
    }
    fn state(name: &str, ty: EmbeddedStateType) -> EmbeddedStateDescriptor {
        EmbeddedStateDescriptor {
            name: name.to_owned(),
            ty,
        }
    }
    let exact_hint = hint("int");
    let exact_states = [state(
        "Orders",
        EmbeddedStateType::StateMap {
            key: Box::new(EmbeddedStateType::Int),
            value: Box::new(EmbeddedStateType::Bool),
        },
    )];
    let (reads, writes) = collect_dynamic_access_hints(
        &[call_graph_function(
            "scan",
            vec![state_scan(exact_hint.clone())],
        )],
        &exact_states,
    )
    .expect("exact optimized-IR provenance must validate");
    assert_eq!(reads, vec![exact_hint]);
    assert!(writes.is_empty());
    let (reads, writes) = collect_dynamic_access_hints(
        &[call_graph_function(
            "direct_state_count",
            vec![ir::Instr::StateCount {
                dest: ir::Temp(0),
                prefix: ir::Temp(1),
            }],
        )],
        &[],
    )
    .expect("a raw count has no bounded traversal provenance");
    assert!(reads.is_empty());
    assert!(writes.is_empty());
    for (states, expected) in [
        (Vec::new(), "does not name a declared top-level StateMap"),
        (
            vec![state("Orders", EmbeddedStateType::Int)],
            "does not name a declared top-level StateMap",
        ),
        (
            vec![state(
                "Orders",
                EmbeddedStateType::StateMap {
                    key: Box::new(EmbeddedStateType::Quantity),
                    value: Box::new(EmbeddedStateType::Bool),
                },
            )],
            "declared StateMap key type is `quantity`",
        ),
    ] {
        let error = collect_dynamic_access_hints(
            &[call_graph_function("scan", vec![state_scan(hint("int"))])],
            &states,
        )
        .expect_err("unknown, scalar, or key-mismatched provenance must fail closed");
        assert!(error.starts_with("K3098:"), "{error}");
        assert!(error.contains(expected), "{error}");
    }
}
#[test]
fn bounded_state_map_scans_emit_exact_dynamic_read_hints() {
    let src = include_str!("fixtures/v1/c139.ko");
    let (_bytes, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile bounded StateMap scans");
    let hints = manifest
        .access_set_hints
        .expect("bounded scans must emit access hints");
    let dynamic_reads = hints
        .dynamic_reads
        .iter()
        .map(|hint| {
            (
                hint.base_key.as_str(),
                hint.key_type.as_str(),
                hint.bound_kind.as_str(),
                hint.max_keys,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        dynamic_reads,
        vec![
            ("state:Names", "Name", "page", 64),
            ("state:Names", "Name", "take", 64),
            ("state:Quantities", "quantity", "page", 64),
        ]
    );
    assert!(
        hints.dynamic_writes.is_empty(),
        "first-release scan hints never infer dynamic writes"
    );
}
#[test]
fn zero_length_state_map_scan_limits_are_rejected() {
    for iterator in [
        "Entries.take(0)",
        "Entries.page(after: Option::none, limit: 0).items",
    ] {
        let source = format!(
            r#"
seiyaku ZeroScanNoOp {{
  state StateMap<int, int> Entries;

  view fn scan() authorize(anyone) -> int {{
    var int total = 0;
    for (key, value) in {iterator} {{
      total = total + key + value;
    }}
    return total;
  }}
}}
"#
        );
        let error = Compiler::new()
            .compile_source_with_manifest(&source)
            .expect_err("scan limits are always positive");
        assert!(error.contains("E_ITERATION_LIMIT"), "{iterator}: {error}");
    }
}
#[test]
fn free_calls_cannot_forge_state_map_scan_provenance() {
    for iterator in ["take(Names, 2)", "range(Names, 0, 2)"] {
        let source = format!(
            r#"
seiyaku ExactScanProvenance {{
  state StateMap<Name, int> Names;

  view fn scan() authorize(anyone) -> int {{
    var int total = 0;
    for (name, value) in {iterator} {{
      total = total + value;
    }}
    return total;
  }}
}}
"#
        );
        let error = Compiler::new()
            .compile_source_with_manifest(&source)
            .expect_err("unresolved free calls cannot provide scan provenance");
        assert!(
            error.contains(iterator.split('(').next().expect("call name")),
            "{iterator}: {error}"
        );
    }
}
#[test]
fn entrypoint_hints_distinguish_dynamic_and_literal_state_map_paths() {
    let src = include_str!("fixtures/v1/c141.ko");
    let compiler = Compiler::new();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let embedded = ProgramMetadata::parse(&bytes)
        .expect("parse exact embedded interface")
        .contract_interface
        .expect("embedded interface");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    let literal_key = canonical_numeric_state_key("Foo", ir::DataRefKind::Int, "1");
    assert_eq!(hints.read_keys, vec![STATE_WILDCARD_KEY.to_string()]);
    assert_eq!(embedded.access_set_hints.as_ref(), Some(&hints));
    assert!(hints.write_keys.is_empty());
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let read_dyn = entrypoints
        .iter()
        .find(|entry| entry.name == "read_dyn")
        .expect("read_dyn entrypoint");
    let read_lit = entrypoints
        .iter()
        .find(|entry| entry.name == "read_lit")
        .expect("read_lit entrypoint");
    assert_eq!(read_dyn.read_keys, vec![STATE_WILDCARD_KEY.to_string()]);
    assert!(read_dyn.write_keys.is_empty());
    assert_eq!(read_dyn.access_hints_complete, Some(false));
    assert_eq!(
        read_dyn.access_hints_skipped,
        vec![HINT_SKIP_DYNAMIC_STATE_PATH.to_owned()]
    );
    assert_eq!(read_lit.read_keys, vec![literal_key]);
    assert!(read_lit.write_keys.is_empty());
    assert_eq!(read_lit.access_hints_complete, Some(true));
    assert!(read_lit.access_hints_skipped.is_empty());
    for entrypoint in [read_dyn, read_lit] {
        let actual = embedded
            .entrypoints
            .iter()
            .find(|entry| entry.name == entrypoint.name)
            .expect("the same public entrypoint is embedded");
        assert_eq!(actual.read_keys, entrypoint.read_keys);
        assert_eq!(actual.write_keys, entrypoint.write_keys);
        assert_eq!(
            actual.access_hints_complete,
            entrypoint.access_hints_complete
        );
        assert_eq!(actual.access_hints_skipped, entrypoint.access_hints_skipped);
    }
}
#[test]
fn manifest_build_rejects_dynamic_state_iteration_bounds() {
    let src = include_str!("fixtures/v1/c142.ko");
    let error = Compiler::new()
        .compile_source_with_manifest(src)
        .expect_err("V1 build must reject nonliteral iteration bounds");
    assert!(error.contains("E_UNBOUNDED_ITERATION"), "{error}");
    assert!(
        error.contains("bound must be a compile-time int constant expression"),
        "{error}"
    );
}
#[test]
fn manifest_access_set_hints_preserve_state_wildcard_for_dynamic_state_path() {
    let src = include_str!("fixtures/v1/c143.ko");
    let compiler = test_mode_compiler();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert_no_global_access_key(&hints.read_keys);
    assert_no_global_access_key(&hints.write_keys);
    assert!(hints.read_keys.iter().any(|key| key == STATE_WILDCARD_KEY));
    assert!(hints.write_keys.is_empty());
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let read = entrypoints
        .iter()
        .find(|entry| entry.name == "read")
        .expect("read entrypoint");
    assert_no_global_access_key(&read.read_keys);
    assert_no_global_access_key(&read.write_keys);
    assert!(read.read_keys.iter().any(|key| key == STATE_WILDCARD_KEY));
    assert!(read.write_keys.is_empty());
    assert_eq!(read.access_hints_complete, Some(false));
    assert!(!read.access_hints_skipped.is_empty());
}
#[test]
fn manifest_compilation_rejects_raw_call_contract() {
    let src = include_str!("fixtures/v1/c144.ko");
    let error = test_mode_compiler()
        .compile_source_with_manifest(src)
        .expect_err("raw contract-call bridge must be rejected before manifest generation");
    assert!(
        error.contains("K1001")
            || error.contains("unknown function or builtin")
            || error.contains("E_UNKNOWN_BUILTIN"),
        "{error}"
    );
}
#[test]
fn compile_native_json_object_with_exact_int_and_pointer_values() {
    let src = include_str!("fixtures/v1/c145.ko");
    let compiler = Compiler::new();
    compiler
        .compile_source_with_manifest(src)
        .expect("compile json object builders");
}
#[test]
fn native_json_accepts_returned_state_cursors() {
    let source = r#"seiyaku CursorJson {
        state StateMap<int, int> values;
        view fn page() authorize(anyone) -> Json {
            let batch = values.page(after: Option::none, limit: 2);
            json { after: batch.next }
        }
    }"#;
    Compiler::new()
        .compile_source(source)
        .expect("opaque cursors are native JSON values");
}

#[test]
fn native_json_construction_emits_one_extended_build_syscall() {
    let source = include_str!("fixtures/v1/c146.ko");
    let bytes = test_mode_compiler()
        .compile_source(source)
        .expect("compile native JSON construction");
    let parsed = ProgramMetadata::parse(&bytes).expect("parse native JSON metadata");
    let words = bytes[parsed.code_offset..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("instruction word")))
        .collect::<Vec<_>>();
    assert_eq!(
        words
            .iter()
            .filter(|word| {
                instruction::wide::opcode(**word) == instruction::wide::system::SYSTEM
                    && encoding::wide::decode_syscallx(**word) == syscalls::SYSCALL_JSON_BUILD
            })
            .count(),
        1,
        "one native JSON expression must perform exactly one host build"
    );
    for retired in [
        syscalls::SYSCALL_JSON_OBJECT,
        syscalls::SYSCALL_JSON_SET_I64,
        syscalls::SYSCALL_JSON_SET_ACCOUNT_ID,
    ] {
        assert!(words.iter().all(|word| {
            instruction::wide::opcode(*word) != instruction::wide::system::SCALL
                || instruction::wide::imm8(*word) as u8 as u32 != retired
        }));
    }
}
#[test]
fn manifest_access_set_hints_include_register_trigger_from_json() {
    let src = include_str!("fixtures/v1/c147.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    let expected = vec![
        "trigger.repetitions:t1".to_string(),
        "trigger:t1".to_string(),
    ];
    assert_eq!(hints.read_keys, expected);
    assert_eq!(hints.write_keys, expected);
}
#[test]
fn manifest_access_set_hints_include_nft_set_metadata_literal() {
    let src = include_str!("fixtures/v1/c148.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    let nft_key = "nft:n0$wonderland.universal".to_string();
    let nft_detail = "nft.detail:n0$wonderland.universal:dpn_metadata".to_string();
    assert!(hints.read_keys.contains(&NFT_COARSE_KEY.to_string()));
    assert!(hints.write_keys.contains(&NFT_COARSE_KEY.to_string()));
    assert!(hints.read_keys.contains(&nft_key));
    assert!(hints.write_keys.contains(&nft_key));
    assert!(hints.read_keys.contains(&nft_detail));
    assert!(hints.write_keys.contains(&nft_detail));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[test]
fn manifest_access_set_hints_include_coarse_key_for_dynamic_nft_set_metadata() {
    let src = include_str!("fixtures/v1/c149.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(hints.read_keys.contains(&NFT_COARSE_KEY.to_string()));
    assert!(hints.write_keys.contains(&NFT_COARSE_KEY.to_string()));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let entry = entrypoints
        .iter()
        .find(|entry| entry.name == "set_metadata")
        .expect("set_metadata entrypoint");
    assert_eq!(entry.access_hints_complete, Some(true));
    assert!(entry.access_hints_skipped.is_empty());
}
#[test]
fn manifest_access_set_hints_include_coarse_key_for_dynamic_nft_mint() {
    let src = include_str!("fixtures/v1/c150.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(hints.read_keys.contains(&NFT_COARSE_KEY.to_string()));
    assert!(hints.write_keys.contains(&NFT_COARSE_KEY.to_string()));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let entry = entrypoints
        .iter()
        .find(|entry| entry.name == "mint")
        .expect("mint entrypoint");
    assert_eq!(entry.access_hints_complete, Some(true));
    assert!(entry.access_hints_skipped.is_empty());
}
#[test]
fn manifest_access_set_hints_include_asset_registration_literals() {
    use iroha_data_model::asset::id::{AssetDefinitionId, AssetId};
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let asset_def = AssetDefinitionId::parse_address_literal(asset_literal).unwrap();
    let account = sample_account_id();
    let account_literal = account.to_string();
    let asset_id = AssetId::of(asset_def.clone(), account.clone());
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission AssetAdmin;

kotoage fn main() authorize(AssetAdmin) {{
  ledger::asset::register(
    asset_definition: AssetDefinitionId::parse("{asset_literal}"),
    name: "ROSE",
    spec: NumericSpec::integer(),
    mintable: Mintable::Once,
  );
  ledger::asset::mint(
    account: AccountId::parse("{account_literal}"),
    asset_definition: AssetDefinitionId::parse("{asset_literal}"),
    amount: 1,
  );
}}

}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(hints.read_keys.contains(&format!("asset_def:{asset_def}")));
    assert!(hints.write_keys.contains(&format!("asset_def:{asset_def}")));
    assert!(hints.read_keys.contains(&format!("asset:{asset_id}")));
    assert!(hints.write_keys.contains(&format!("asset:{asset_id}")));
    assert!(hints.read_keys.contains(&format!("account:{account}")));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[test]
fn manifest_access_set_hints_include_authority_placeholders() {
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission AssetAdmin;

kotoage fn main() authorize(AssetAdmin) {{
  ledger::asset::register(
    asset_definition: AssetDefinitionId::parse("{asset_literal}"),
    name: "ROSE",
    spec: NumericSpec::integer(),
    mintable: Mintable::Once,
  );
  ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{{\"perms\":[\"mint_asset:{asset_literal}\"]}}"));
  ledger::role::grant(account: context::authority(), role: Name::parse("minter"));
  ledger::asset::mint(
    account: context::authority(),
    asset_definition: AssetDefinitionId::parse("{asset_literal}"),
    amount: 1,
  );
}}

}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(hints.read_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    assert!(hints.write_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    assert!(
        hints
            .write_keys
            .contains(&"role.binding:$authority:minter".to_owned())
    );
    assert!(
        hints
            .read_keys
            .contains(&format!("asset:{asset_literal}:$authority"))
    );
    assert!(
        hints
            .write_keys
            .contains(&format!("asset:{asset_literal}:$authority"))
    );
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[test]
fn manifest_access_set_hints_propagate_context_authority_bindings() {
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let source = format!(
        r#"
seiyaku CompilerFixture {{ permission AssetAdmin;

kotoage fn main() authorize(AssetAdmin) {{
  let caller = context::authority();
  let asset = AssetDefinitionId::parse("{asset_literal}");
  ledger::asset::transfer(
    source: caller,
    destination: caller,
    asset_definition: asset,
    amount: 1,
    dataspace: DataSpaceId::parse("0"),
  );
  ledger::account::set_metadata(
    account: caller,
    key: Name::parse("status"),
    value: Json::parse("{{}}"),
  );
}}

}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&source)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    let authority_asset = format!(
        "asset:{asset_literal}:$authority:dataspace:{}",
        iroha_model_base::topology::DataSpaceId::UNIVERSAL
    );
    let authority_detail = "account.detail:$authority:status".to_owned();
    assert!(hints.read_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    assert!(hints.read_keys.contains(&authority_asset));
    assert!(hints.write_keys.contains(&authority_asset));
    assert!(hints.read_keys.contains(&authority_detail));
    assert!(hints.write_keys.contains(&authority_detail));
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
    assert!(main.read_keys.contains(&AUTHORITY_ACCOUNT_KEY.to_owned()));
    assert!(main.read_keys.contains(&authority_asset));
    assert!(main.write_keys.contains(&authority_asset));
    assert!(main.read_keys.contains(&authority_detail));
    assert!(main.write_keys.contains(&authority_detail));
}
#[test]
fn manifest_access_set_hints_include_inline_ballot_vendor_payload() {
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(include_str!("../samples/zk_vote_ballot.ko"))
        .expect("compile sample manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(
        hints
            .write_keys
            .contains(&"zk:election:election-1:ciphertexts".to_string())
    );
    assert!(
        hints
            .write_keys
            .contains(&"zk:election:election-1:nullifiers".to_string())
    );
    assert!(hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_owned()));
    assert!(hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_owned()));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let demo = entrypoints
        .iter()
        .find(|entry| entry.name == "demo")
        .expect("demo entrypoint");
    assert_eq!(demo.access_hints_complete, Some(false));
    assert_eq!(
        demo.access_hints_skipped,
        vec![
            HINT_SKIP_OPAQUE_ISI.to_owned(),
            HINT_SKIP_DYNAMIC_INSTRUCTION_BRIDGE.to_owned(),
        ],
        "opaque proofs require conservative reads and the instruction bridge requires conservative writes even for an exact ballot payload"
    );
}
#[test]
fn manifest_access_set_hints_include_transfer_domain_literal() {
    use iroha_model_base::domain::DomainId;
    let from_literal = sample_account_literal();
    let to = sample_account_id_alt();
    let to_literal = to.to_string();
    let domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let src = format!(
        "seiyaku CompilerFixture {{ permission Admin;  kotoage fn main() authorize(Admin) {{ ledger::domain::transfer(source: AccountId::parse(\"{from_literal}\"), domain: DomainId::parse(\"{domain}\"), destination: AccountId::parse(\"{to_literal}\")); }} }}"
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(hints.read_keys.contains(&format!("domain:{domain}")));
    assert!(hints.write_keys.contains(&format!("domain:{domain}")));
    assert!(hints.read_keys.contains(&format!("account:{to}")));
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[derive(Clone, Copy)]
enum AliasTransferDestination {
    Literal(&'static str),
    Resolved(&'static str),
}
impl AliasTransferDestination {
    fn source_expression(self) -> String {
        match self {
            Self::Literal(alias) => format!(r#"AccountId::parse("{alias}")"#),
            Self::Resolved(alias) => {
                format!(r#"ledger::account::resolve_alias(alias: "{alias}")"#)
            }
        }
    }
}
fn assert_alias_transfer_uses_scoped_access(destination: AliasTransferDestination) {
    let from_literal = sample_account_literal();
    let destination = destination.source_expression();
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = format!(
        r#"
seiyaku CompilerFixture {{ permission AssetAdmin;
kotoage fn main() authorize(AssetAdmin) {{
  ledger::asset::transfer(
    source: AccountId::parse("{from_literal}"),
    destination: {destination},
    asset_definition: AssetDefinitionId::parse("{asset_literal}"),
    amount: 1,
    dataspace: DataSpaceId::parse("0"),
  );
}}
}}
"#
    );
    let (_bytes, manifest) = test_mode_compiler()
        .compile_source_with_manifest(&src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert_no_global_access_key(&hints.read_keys);
    assert_no_global_access_key(&hints.write_keys);
    let main = manifest
        .entrypoints
        .expect("entrypoints present")
        .into_iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_no_global_access_key(&main.read_keys);
    assert_no_global_access_key(&main.write_keys);
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[test]
fn manifest_access_set_hints_conservatively_serialize_alias_shorthand_account_id() {
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Literal("merchant@paynet"));
}
#[test]
fn manifest_access_set_hints_omit_global_wildcard_for_invalid_alias_shorthand_account_id_transfer()
{
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Literal("merchant@"));
}
#[test]
fn manifest_access_set_hints_omit_global_wildcard_for_domain_qualified_alias_shorthand_account_id()
{
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Literal(
        "merchant@bank.paynet",
    ));
}
#[test]
fn manifest_access_set_hints_omit_global_wildcard_for_invalid_domain_qualified_alias_shorthand_account_id_transfer()
 {
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Literal("merchant@bank."));
}
#[test]
fn manifest_access_set_hints_omit_global_wildcard_for_resolve_account_alias_builtin_transfer() {
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Resolved("merchant@paynet"));
}
#[test]
fn manifest_access_set_hints_omit_global_wildcard_for_invalid_resolve_account_alias_builtin_transfer()
 {
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Resolved("merchant@"));
}
#[test]
fn manifest_access_set_hints_omit_global_wildcard_for_domain_qualified_resolve_account_alias_builtin_transfer()
 {
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Resolved(
        "merchant@bank.paynet",
    ));
}
#[test]
fn manifest_access_set_hints_omit_global_wildcard_for_invalid_domain_qualified_resolve_account_alias_builtin_transfer()
 {
    assert_alias_transfer_uses_scoped_access(AliasTransferDestination::Resolved("merchant@bank."));
}
#[test]
fn manifest_access_set_hints_preserve_coarse_asset_keys_for_dynamic_asset_contract() {
    let src = include_str!("fixtures/v1/c151.ko");
    let compiler = test_mode_compiler();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert_no_global_access_key(&hints.read_keys);
    assert_no_global_access_key(&hints.write_keys);
    for key in [super::ASSET_WILDCARD_KEY, super::ASSET_DEF_WILDCARD_KEY] {
        assert!(hints.read_keys.iter().any(|actual| actual == key));
        assert!(hints.write_keys.iter().any(|actual| actual == key));
    }
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "move")
        .expect("move entrypoint");
    assert_no_global_access_key(&main.read_keys);
    assert_no_global_access_key(&main.write_keys);
    for key in [super::ASSET_WILDCARD_KEY, super::ASSET_DEF_WILDCARD_KEY] {
        assert!(main.read_keys.iter().any(|actual| actual == key));
        assert!(main.write_keys.iter().any(|actual| actual == key));
    }
    assert_eq!(main.access_hints_complete, Some(true));
    assert!(main.access_hints_skipped.is_empty());
}
#[test]
fn manifest_access_set_hints_preserve_global_wildcard_for_opaque_host_calls() {
    let src = include_str!("fixtures/v1/c152.ko");
    let compiler = test_mode_compiler();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("opaque host calls must preserve their conservative wildcard hint");
    assert!(hints.read_keys.iter().any(|key| key == GLOBAL_WILDCARD_KEY));
    assert!(
        hints
            .write_keys
            .iter()
            .any(|key| key == GLOBAL_WILDCARD_KEY)
    );
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let register = entrypoints
        .iter()
        .find(|entry| entry.name == "register")
        .expect("register entrypoint");
    assert!(
        register
            .read_keys
            .iter()
            .any(|key| key == GLOBAL_WILDCARD_KEY)
    );
    assert!(
        register
            .write_keys
            .iter()
            .any(|key| key == GLOBAL_WILDCARD_KEY)
    );
    assert_eq!(register.access_hints_complete, Some(false));
    assert!(!register.access_hints_skipped.is_empty());
}
#[test]
fn internal_lifecycle_access_derivation_decodes_typed_requests() {
    let code_hash = iroha_crypto::Hash::new(b"kotodama lifecycle access hints");
    let artifact_id = iroha_data_model::smart_contract::ContractArtifactId::new(
        iroha_model_base::topology::DataSpaceId::new(u64::MAX - 1),
        code_hash,
    );
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"kotodama lifecycle access-hint network"),
    ));
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        &network_id,
        &sample_account_id(),
        0,
        artifact_id.dataspace_id,
    )
    .expect("contract address");
    let manifest = iroha_data_model::smart_contract::manifest::ContractManifest {
        seiyaku_name: None,
        code_hash: Some(code_hash),
        abi_hash: None,
        compiler_fingerprint: Some("test".to_owned()),
        features_bitmap: Some(0),
        access_set_hints: None,
        permissions: Vec::new(),
        events: Vec::new(),
        enum_types: Vec::new(),
        entrypoints: None,
        states: None,
        kotoba: None,
        error_types: None,
        error_messages: None,
        provenance: None,
    };
    let register_code = norito::to_bytes(
        &iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode {
            artifact_id,
            manifest,
        },
    )
    .expect("register manifest request");
    let register_bytes = norito::to_bytes(
        &iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes {
            artifact_id,
            code: vec![0, 1, 2, 3],
        },
    )
    .expect("register bytes request");
    let activate = norito::to_bytes(
        &iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        },
    )
    .expect("activate request");
    let remove = norito::to_bytes(
        &iroha_data_model::isi::smart_contract_code::RemoveSmartContractBytes {
            artifact_id,
            reason: Some("test cleanup".to_owned()),
        },
    )
    .expect("remove request");
    let mut access = super::AccessSets::default();
    for (request, syscall) in [
        (
            register_code,
            syscalls::SYSCALL_REGISTER_SMART_CONTRACT_CODE,
        ),
        (
            register_bytes,
            syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
        ),
        (activate, syscalls::SYSCALL_ACTIVATE_CONTRACT_INSTANCE),
        (remove, syscalls::SYSCALL_REMOVE_SMART_CONTRACT_BYTES),
    ] {
        let literal = format!("0x{}", hex::encode(request));
        assert!(
            super::record_smart_contract_lifecycle_access(&literal, syscall, &mut access).is_some(),
            "typed lifecycle request must decode for syscall {syscall:#x}"
        );
    }
    for key in [
        super::key_contract_code(&artifact_id),
        super::key_contract_manifest(&artifact_id),
        super::key_contract_instance(&contract_address),
        super::key_contract_instance_code_hash(&artifact_id),
    ] {
        assert!(
            access.reads.contains(&key),
            "missing lifecycle read key {key}; got {:?}",
            access.reads
        );
    }
    for key in [
        super::key_contract_code(&artifact_id),
        super::key_contract_manifest(&artifact_id),
        super::key_contract_instance(&contract_address),
        super::key_contract_instance_code_hash(&artifact_id),
    ] {
        assert!(
            access.writes.contains(&key),
            "missing lifecycle write key {key}; got {:?}",
            access.writes
        );
    }
    let foreign_artifact = iroha_data_model::smart_contract::ContractArtifactId::new(
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        code_hash,
    );
    for key in [
        super::key_contract_code(&foreign_artifact),
        super::key_contract_manifest(&foreign_artifact),
        super::key_contract_instance_code_hash(&foreign_artifact),
    ] {
        assert!(
            !access.reads.contains(&key),
            "foreign artifact read key {key}"
        );
        assert!(
            !access.writes.contains(&key),
            "foreign artifact write key {key}"
        );
    }
}

#[test]
fn ephemeral_u64_nullifier_helper_is_rejected_from_source() {
    let src = include_str!("fixtures/v1/c153.ko");
    let compiler = Compiler::new_with_options(CompilerOptions {
        force_zk: true,
        ..CompilerOptions::default()
    });
    let error = compiler
        .compile_source_with_manifest(src)
        .expect_err("invocation-local u64 nullifiers must not be deployable source APIs");
    assert!(
        error.contains("crypto::use_nullifier")
            && (error.contains("K2002") || error.contains("E_UNKNOWN_BUILTIN")),
        "unexpected nullifier rejection: {error}"
    );
    assert!(
        !error.contains("E_INTERNAL_BUILTIN"),
        "removed nullifier compiler metadata still influenced resolution: {error}"
    );
}
#[test]
fn manifest_access_set_hints_include_static_peer_helpers() {
    let public_key = "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774";
    let peer = iroha_model_base::peer::PeerId::from(
        public_key
            .parse::<iroha_crypto::PublicKey>()
            .expect("public key"),
    );
    let src = format!(
        r#"
seiyaku Test {{ permission Admin;
  kotoage fn peers() authorize(Admin) {{
    ledger::peer::register(peer: Json::parse("{{\"pop\":[],\"public_key\":\"{public_key}\"}}"));
    ledger::peer::unregister(peer: Json::parse("{{\"public_key\":\"{public_key}\"}}"));
  }}
}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("static peer helpers should have complete access hints");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let peers = entrypoints
        .iter()
        .find(|entry| entry.name == "peers")
        .expect("peers entrypoint");
    let peer_key = format!("peer:{peer}");
    assert_eq!(peers.access_hints_complete, Some(true));
    assert!(peers.access_hints_skipped.is_empty());
    assert_no_global_access_key(&peers.read_keys);
    assert_no_global_access_key(&peers.write_keys);
    assert_eq!(peers.read_keys, std::slice::from_ref(&peer_key));
    assert_eq!(peers.write_keys, [peer_key]);
}
#[test]
fn manifest_access_set_hints_include_subscription_helpers() {
    let src = include_str!("fixtures/v1/c154.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("subscription helpers should have complete access hints");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let subscription = entrypoints
        .iter()
        .find(|entry| entry.name == "subscription")
        .expect("subscription entrypoint");
    let keys = [
        "subscription:trigger_context:bill".to_owned(),
        "subscription:trigger_context:usage".to_owned(),
    ];
    assert_eq!(subscription.access_hints_complete, Some(true));
    assert!(subscription.access_hints_skipped.is_empty());
    assert_no_global_access_key(&subscription.read_keys);
    assert_no_global_access_key(&subscription.write_keys);
    assert_eq!(subscription.read_keys, keys);
    assert_eq!(subscription.write_keys, keys);
}
#[test]
fn manifest_access_set_hints_make_adversarial_static_host_payloads_conservative() {
    let src = include_str!("fixtures/v1/c155.ko");
    let compiler = test_mode_compiler();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("test mode should report incomplete host access hints");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let entry = entrypoints
        .iter()
        .find(|entry| entry.name == "bad_peer")
        .expect("entrypoint");
    assert_eq!(entry.access_hints_complete, Some(false));
    assert_eq!(entry.read_keys, [GLOBAL_WILDCARD_KEY.to_owned()]);
    assert_eq!(entry.write_keys, [GLOBAL_WILDCARD_KEY.to_owned()]);
    assert_eq!(
        entry.access_hints_skipped,
        [HINT_SKIP_OPAQUE_ISI.to_owned()]
    );
    let (_bytes, production_manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("production must preserve conservative incomplete metadata");
    let production_entry = production_manifest
        .entrypoints
        .expect("entrypoints")
        .into_iter()
        .find(|entry| entry.name == "bad_peer")
        .expect("bad_peer entrypoint");
    assert_eq!(production_entry.read_keys, [GLOBAL_WILDCARD_KEY.to_owned()]);
    assert_eq!(production_entry.write_keys, entry.write_keys);
    assert_eq!(
        production_entry.access_hints_complete,
        entry.access_hints_complete
    );
    assert_eq!(
        production_entry.access_hints_skipped,
        entry.access_hints_skipped
    );
}
#[test]
fn manifest_trigger_decl_sets_authority() {
    use iroha_data_model::account::AccountId;
    let authority_literal = sample_account_literal();
    let src = format!(
        r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on time pre_commit;
    authority "{authority_literal}";
  }}
}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile manifest");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let run = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    assert_eq!(run.triggers.len(), 1);
    let trigger = &run.triggers[0];
    assert_eq!(trigger.id.to_string(), "wake");
    assert_eq!(
        trigger.authority,
        Some(AccountId::parse_encoded(authority_literal.as_str()).expect("authority literal"),)
    );
}
#[test]
fn manifest_trigger_decl_rejects_unchecked_namespaced_callback() {
    let src = include_str!("fixtures/v1/c156.ko");
    let error = Compiler::new()
        .compile_source_with_manifest(src)
        .expect_err("remote callbacks cannot bypass authenticated source signatures");
    assert!(error.contains("E_TRIGGER_TARGET_NAMESPACE"), "{error}");
}
#[test]
fn execute_trigger_callback_uses_exact_public_argument_schema() {
    let source = r#"seiyaku TriggerArguments {
        kotoage fn run(int amount, Name recipient) authorize(anyone) {}
        trigger wake -> run { on execute trigger wake; }
    }"#;
    let (_, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .expect("typed execute callback");
    let entrypoints = manifest.entrypoints.unwrap();
    let callback = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .unwrap();
    let schema = callback.argument_schema.as_ref().unwrap();
    assert_eq!(
        schema
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        vec!["amount", "recipient"]
    );
    let payload =
        iroha_primitives::json::Json::from_str_norito(r#"{"amount":"7","recipient":"buyer"}"#)
            .unwrap();
    ivm_abi::arguments::argument_record_from_json(schema, &payload)
        .expect("execute event matches typed callback");
    let wrong =
        iroha_primitives::json::Json::from_str_norito(r#"{"amount":7,"recipient":"buyer"}"#)
            .unwrap();
    assert!(ivm_abi::arguments::argument_record_from_json(schema, &wrong).is_err());
    assert_eq!(callback.triggers[0].callback.namespace, None);
    assert_eq!(callback.triggers[0].callback.entrypoint, "run");
}
#[test]
fn trigger_callback_dispatches_only_through_cntr_entry_pc() {
    let src = include_str!("fixtures/v1/c157.ko");
    let compiler = Compiler::new();
    let (bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let run = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    let parsed = ivm_abi::metadata::ProgramMetadata::parse(&bytes).expect("parse metadata");
    let embedded = parsed
        .contract_interface
        .expect("embedded contract interface");
    let run_embedded = embedded
        .entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .expect("embedded run entrypoint");
    assert_ne!(run_embedded.entry_pc, 0);
    let first_word = u32::from_le_bytes(
        bytes[parsed.code_offset..parsed.code_offset + 4]
            .try_into()
            .expect("raw entry word"),
    );
    assert_eq!(
        instruction::wide::opcode(first_word),
        instruction::wide::control::HALT,
        "raw PC 0 must not dispatch a trigger callback"
    );
    assert_eq!(run.name, "run");
}
#[test]
fn source_order_and_main_name_do_not_select_raw_dispatch() {
    let src = include_str!("fixtures/v1/c158.ko");
    let (bytes, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    assert_eq!(entrypoints.len(), 3);
    let main = entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    assert_eq!(main.name, "main");
    let parsed = ivm_abi::metadata::ProgramMetadata::parse(&bytes).expect("parse metadata");
    let embedded = parsed
        .contract_interface
        .expect("embedded contract interface");
    let main_embedded = embedded
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("embedded main entrypoint");
    let write_embedded = embedded
        .entrypoints
        .iter()
        .find(|entry| entry.name == "write_detail")
        .expect("embedded write_detail entrypoint");
    assert_ne!(main_embedded.entry_pc, 0);
    assert_ne!(write_embedded.entry_pc, 0);
    assert!(
        main_embedded.entry_pc < write_embedded.entry_pc,
        "entrypoint bodies must be laid out by symbol, not declaration order"
    );
    for entrypoint in [main_embedded, write_embedded] {
        let callable = embedded
            .callables
            .iter()
            .find(|callable| callable.entry_pc == entrypoint.entry_pc)
            .expect("every selected entrypoint has one authenticated callable root");
        assert!(callable.validate());
        assert!(callable.frame_bytes >= 16);
    }
    let first_word = u32::from_le_bytes(
        bytes[parsed.code_offset..parsed.code_offset + 4]
            .try_into()
            .expect("raw entry word"),
    );
    assert_eq!(
        instruction::wide::opcode(first_word),
        instruction::wide::control::HALT,
        "raw PC 0 must not imply a `main` entrypoint"
    );
}
include!("tests/staged_mint_access_hints.rs");
#[test]
fn manifest_trigger_decl_lowers_structured_data_filter() {
    use iroha_data_model::events::{
        EventFilterBox,
        data::{
            DataEventFilter,
            prelude::{AssetEventFilter, AssetEventSet},
        },
    };
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain"),
        "rose".parse().expect("name"),
    );
    let asset_definition_literal = asset_definition.to_string();
    let src = format!(
        r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger intercept -> run {{
    on data asset added {{
      asset_definition "{asset_definition_literal}";
    }}
  }}
}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile manifest");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let run = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    assert_eq!(run.triggers.len(), 1);
    assert_eq!(
        run.triggers[0].filter,
        EventFilterBox::Data(DataEventFilter::Asset(
            AssetEventFilter::new()
                .for_events(AssetEventSet::Added)
                .for_asset_definition(asset_definition),
        ))
    );
}
#[test]
fn manifest_trigger_decl_lowers_structured_data_filters_for_core_families() {
    use iroha_data_model::{
        account::AccountId,
        asset::AssetId,
        events::{
            EventFilterBox,
            data::{
                DataEventFilter,
                prelude::{
                    AccountEventFilter, AccountEventSet, AssetDefinitionEventFilter,
                    AssetDefinitionEventSet, AssetEventFilter, AssetEventSet,
                    ConfigurationEventFilter, ConfigurationEventSet, DomainEventFilter,
                    DomainEventSet, ExecutorEventFilter, ExecutorEventSet, NftEventFilter,
                    NftEventSet, PeerEventFilter, PeerEventSet, RoleEventFilter, RoleEventSet,
                    RwaEventFilter, RwaEventSet, TriggerEventFilter, TriggerEventSet,
                },
            },
        },
        nft::NftId,
        role::RoleId,
        rwa::RwaId,
        trigger::TriggerId,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::peer::PeerId;
    let account_literal = sample_account_literal();
    let account = AccountId::parse_encoded(account_literal.as_str()).expect("account");
    let peer_literal = "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D";
    let peer: PeerId = peer_literal.parse().expect("peer");
    let domain: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain"),
        "rose".parse().expect("name"),
    );
    let asset = AssetId::new(asset_definition.clone(), account.clone());
    let asset_literal = asset.canonical_literal();
    let nft: NftId = "n0$wonderland.universal".parse().expect("nft");
    let rwa: RwaId = format!(
        "{}$wonderland.universal",
        iroha_crypto::Hash::prehashed([7; iroha_crypto::Hash::LENGTH])
    )
    .parse()
    .expect("rwa");
    let trigger_id: TriggerId = "wake".parse().expect("trigger");
    let role_id: RoleId = "auditor".parse().expect("role");
    let cases = vec![
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data peer added {{
      peer "{peer_literal}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Peer(
                PeerEventFilter::new()
                    .for_events(PeerEventSet::Added)
                    .for_peer(peer),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data domain created {{
      domain "{domain}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Domain(
                DomainEventFilter::new()
                    .for_events(DomainEventSet::Created)
                    .for_domain(domain.clone()),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data account created {{
      account "{account_literal}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Account(
                AccountEventFilter::new()
                    .for_events(AccountEventSet::Created)
                    .for_account(account.clone()),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data asset added {{
      asset "{asset_literal}";
      asset_definition "{asset_definition}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Asset(
                AssetEventFilter::new()
                    .for_events(AssetEventSet::Added)
                    .for_asset(asset.clone())
                    .for_asset_definition(asset_definition.clone()),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data asset_definition created {{
      asset_definition "{asset_definition}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::AssetDefinition(
                AssetDefinitionEventFilter::new()
                    .for_events(AssetDefinitionEventSet::Created)
                    .for_asset_definition(asset_definition.clone()),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data nft created {{
      nft "{nft}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Nft(
                NftEventFilter::new()
                    .for_events(NftEventSet::Created)
                    .for_nft(nft),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data rwa created {{
      rwa "{rwa}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Rwa(
                RwaEventFilter::new()
                    .for_events(RwaEventSet::Created)
                    .for_rwa(rwa),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data trigger created {{
      trigger "{trigger_id}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Trigger(
                TriggerEventFilter::new()
                    .for_events(TriggerEventSet::Created)
                    .for_trigger(trigger_id),
            )),
        ),
        (
            format!(
                r#"
seiyaku Test {{ permission Entry;
  kotoage fn run() authorize(Entry) {{}}
  trigger wake -> run {{
    on data role created {{
      role "{role_id}";
    }}
  }}
}}
"#
            ),
            EventFilterBox::Data(DataEventFilter::Role(
                RoleEventFilter::new()
                    .for_events(RoleEventSet::Created)
                    .for_role(role_id),
            )),
        ),
        (
            include_str!("fixtures/v1/c159.ko").to_string(),
            EventFilterBox::Data(DataEventFilter::Configuration(
                ConfigurationEventFilter::new().for_events(ConfigurationEventSet::Changed),
            )),
        ),
        (
            include_str!("fixtures/v1/c160.ko").to_string(),
            EventFilterBox::Data(DataEventFilter::Executor(
                ExecutorEventFilter::new().for_events(ExecutorEventSet::Upgraded),
            )),
        ),
    ];
    let compiler = Compiler::new();
    for (src, expected_filter) in cases {
        let (_bytes, manifest) = compiler
            .compile_source_with_manifest(&src)
            .expect("compile manifest");
        let entrypoints = manifest.entrypoints.expect("entrypoints present");
        let run = entrypoints
            .iter()
            .find(|entry| entry.name == "run")
            .expect("run entrypoint");
        assert_eq!(run.triggers.len(), 1);
        assert_eq!(run.triggers[0].filter, expected_filter);
    }
}
#[test]
fn manifest_trigger_decl_lowers_pipeline_filter() {
    use iroha_data_model::events::{
        EventFilterBox,
        pipeline::{BlockEventFilter, BlockStatus, PipelineEventFilterBox},
    };
    let src = include_str!("fixtures/v1/c161.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let run = entrypoints
        .iter()
        .find(|entry| entry.name == "run")
        .expect("run entrypoint");
    assert_eq!(run.triggers.len(), 1);
    assert_eq!(
        run.triggers[0].filter,
        EventFilterBox::Pipeline(PipelineEventFilterBox::Block(
            BlockEventFilter::new().for_status(BlockStatus::Approved),
        ))
    );
}
#[test]
fn access_hint_diagnostics_report_isi_wildcards() {
    let src = include_str!("fixtures/v1/c162.ko");
    let compiler = test_mode_compiler();
    let (_bytes, _manifest, diag) = compiler
        .compile_source_with_manifest_and_diagnostics(src)
        .expect("compile manifest");
    assert!(diag.isi_wildcards > 0);
    assert_eq!(diag.state_wildcards, 0);
}
#[test]
fn access_hint_diagnostics_report_literal_trigger_spec_decode_failures() {
    let src = include_str!("fixtures/v1/c163.ko");
    let compiler = test_mode_compiler();
    let (_bytes, manifest, diag) = compiler
        .compile_source_with_manifest_and_diagnostics(src)
        .expect("compile manifest");
    assert_eq!(diag.literal_trigger_spec_decode_failures, 1);
    assert_eq!(diag.isi_wildcards, 1);
    assert_eq!(diag.state_wildcards, 0);
    assert!(!diag.is_empty());
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let register = entrypoints
        .iter()
        .find(|entry| entry.name == "register")
        .expect("register entrypoint");
    assert_eq!(register.access_hints_complete, Some(false));
    assert_eq!(
        register.access_hints_skipped,
        vec![HINT_SKIP_LITERAL_TRIGGER_SPEC_DECODE.to_string()]
    );
}
#[test]
fn production_accepts_dynamic_state_path_access_fallback() {
    let src = include_str!("fixtures/v1/c164.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("dynamic state fallback should be deployable in production");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let read = entrypoints
        .iter()
        .find(|entry| entry.name == "read")
        .expect("read entrypoint");
    assert_no_global_access_key(&read.read_keys);
    assert_no_global_access_key(&read.write_keys);
    assert!(read.read_keys.iter().any(|key| key == STATE_WILDCARD_KEY));
    assert!(read.write_keys.is_empty());
    assert_eq!(read.access_hints_complete, Some(false));
    assert_eq!(
        read.access_hints_skipped,
        vec![HINT_SKIP_DYNAMIC_STATE_PATH.to_string()]
    );
}
#[test]
fn production_rejects_literal_trigger_spec_decode_failures_with_hint() {
    let src = include_str!("fixtures/v1/c165.ko");
    let compiler = Compiler::new();
    let err = compiler
        .compile_source_with_manifest(src)
        .expect_err("production should reject undecodable literal trigger specs");
    assert!(err.contains("E_ACCESS_INCOMPLETE"));
    assert!(err.contains(HINT_SKIP_LITERAL_TRIGGER_SPEC_DECODE));
}
#[test]
fn production_rejects_raw_call_contract_surface() {
    let src = include_str!("fixtures/v1/c166.ko");
    let error = Compiler::new()
        .compile_source_with_manifest(src)
        .expect_err("raw contract-call bridge must not reach production admission");
    assert!(
        error.contains("K1001")
            || error.contains("unknown function or builtin")
            || error.contains("E_UNKNOWN_BUILTIN"),
        "{error}"
    );
}
fn compile_contract_import(
    source: &str,
    callee: &str,
) -> Result<crate::session::CompileOutput, crate::driver::BuildError> {
    use crate::linker::{SourceContractArtifact, SourceLinkRequest, SourceModuleUnit};
    let artifact = Compiler::new()
        .compile_source(callee)
        .expect("compile imported interface");
    let request = SourceLinkRequest {
        root: SourceModuleUnit {
            source_name: "app.ko".into(),
            source: source.into(),
        },
        artifacts: vec![SourceContractArtifact {
            source_name: "pool.to".into(),
            artifact,
        }],
        sources: Vec::new(),
        imports: Vec::new(),
        packages: Vec::new(),
    };
    crate::driver::BuildDriver::new(
        crate::session::CompilerSession::default(),
        "contract-import-test",
    )
    .compile_project(request, "app.ko")
}
#[test]
fn production_contract_import_emits_typed_a9_and_exact_access_kind() {
    let callee = "seiyaku Pool { view fn quote(quantity amount) authorize(anyone) -> quantity { amount } kotoage fn swap(quantity amount) authorize(anyone) -> quantity { amount } }";
    for (kind, method, writes) in [("view", "quote", false), ("kotoage", "swap", true)] {
        let source = format!(
            r#"seiyaku Caller {{ import seiyaku "pool.to" as Pool; {kind} fn relay(bytes address, quantity amount) authorize(anyone) -> quantity {{ let pool = Pool::at(address: address); pool.{method}(amount: amount) }} }}"#
        );
        let output =
            compile_contract_import(&source, callee).unwrap_or_else(|error| panic!("{error}"));
        let parsed = ProgramMetadata::parse(&output.artifact).unwrap();
        assert!(
            output.artifact[parsed.code_offset..]
                .chunks_exact(4)
                .any(|chunk| {
                    let word = u32::from_le_bytes(chunk.try_into().unwrap());
                    word == encoding::wide::encode_sys(
                        instruction::wide::system::SCALL,
                        ivm_abi::syscalls::SYSCALL_CALL_CONTRACT as u8,
                    )
                })
        );
        let entry = output
            .manifest
            .entrypoints
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == "relay")
            .unwrap();
        assert_eq!(entry.read_keys, [GLOBAL_WILDCARD_KEY.to_owned()]);
        assert_eq!(
            entry.write_keys,
            if writes {
                vec![GLOBAL_WILDCARD_KEY.to_owned()]
            } else {
                vec![]
            }
        );
        assert_eq!(
            entry.access_hints_skipped,
            [HINT_SKIP_CONTRACT_CALL_TARGET.to_owned()]
        );
    }
}
#[test]
fn imported_contract_calls_reject_wrong_nominal_types_modes_and_lifecycle() {
    let callee = "seiyaku Pool { struct Payload { int amount; } hajimari() {} view fn quote(Payload payload) authorize(anyone) -> Payload { payload } kotoage fn change() authorize(anyone) {} }";
    for (body, expected) in [
        (
            "let pool = Pool::at(address: address); pool.quote(payload: 7);",
            "type",
        ),
        (
            "let pool = Pool::at(address: address); pool.quote(amount: 7);",
            "E_UNKNOWN_NAMED_ARGUMENT",
        ),
        (
            "let pool = Pool::at(address: address); pool.hajimari();",
            "keyword `hajimari`",
        ),
        (
            "let pool = Pool::at(address: address); pool.change();",
            "view",
        ),
        (
            "let pool = Pool::at(address: address); pool.missing();",
            "E_CONTRACT_METHOD",
        ),
        (
            "let pool = Pool::at(address: address); let values = [pool];",
            "List",
        ),
        (
            "let pool = Pool::at(address: address); let value = json { reference: pool };",
            "JSON",
        ),
    ] {
        let source = format!(
            r#"seiyaku Caller {{ import seiyaku "pool.to" as Pool; view fn relay(bytes address) authorize(anyone) {{ {body} }} }}"#
        );
        let error = compile_contract_import(&source, callee)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{body}: {error}");
    }
}
#[test]
fn imported_nominal_types_keep_exact_identity_through_aliases_and_records() {
    let callee = "seiyaku Pool { enum Status { Active = 7, Paused = 9 } struct Payload { Status status; List<int, 2> amounts; } view fn echo(Payload payload) authorize(anyone) -> Payload { payload } }";
    let source = r#"seiyaku Caller {
        import seiyaku "pool.to" as Pool;
        import type "Pool::Payload" from Pool as Payload;
        import type "Pool::Status" from Pool as Status;
        view fn relay(bytes address) authorize(anyone) -> Pool::Payload {
            let pool = Pool::at(address: address);
            pool.echo(payload: Payload { amounts: [1], status: Status::Active })
        }
    }"#;
    let output = compile_contract_import(source, callee).unwrap_or_else(|error| panic!("{error}"));
    let entry = output.manifest.entrypoints.unwrap().remove(0);
    assert_eq!(entry.return_type.as_deref(), Some("struct Pool::Payload"));
    let schema = entry.return_schema.unwrap();
    assert!(schema.nodes.iter().any(|node| matches!(node, ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Enum(value) if value.identity == "Pool::Status")));
    let wrong = source.replace(
        "import type \"Pool::Payload\" from Pool as Payload;",
        "struct Payload { Pool::Status status; List<int, 2> amounts; }",
    );
    assert!(
        compile_contract_import(&wrong, callee).is_err(),
        "equal field shape does not erase nominal identity"
    );
}
#[test]
fn contract_references_stay_private_and_imported_type_aliases_cannot_shadow_declarations() {
    let callee = "seiyaku Pool { struct Payload { int amount; } view fn echo(Payload payload) authorize(anyone) -> Payload { payload } }";
    for declaration in [
        "state Pool stored;",
        "fn invalid(Option<Pool> reference) {}",
        "fn invalid(Result<int, Pool> reference) {}",
        "struct Holder { Pool reference; } fn invalid(Option<Holder> value) {}",
        "struct Holder { Pool reference; } fn invalid(List<Holder, 2> values) {}",
        "view fn invalid(Pool reference) authorize(anyone) {}",
        "view fn invalid(bytes address) authorize(anyone) -> Pool { Pool::at(address: address) }",
        "fn invalid(bytes address) { let value = Option::some(Pool::at(address: address)); }",
        "import type \"Pool::Payload\" from Pool as Payload; struct Payload { int amount; }",
        "struct Pool { int amount; }",
    ] {
        let source =
            format!(r#"seiyaku Caller {{ import seiyaku "pool.to" as Pool; {declaration} }}"#);
        assert!(
            compile_contract_import(&source, callee).is_err(),
            "accepted invalid reference boundary: {declaration}"
        );
    }
}
#[test]
fn retired_contract_invoke_is_not_a_source_api() {
    let source = include_str!("fixtures/v1/c167.ko");
    let error = Compiler::new().compile_source(source).unwrap_err();
    assert!(
        error.contains("error[K2002] resolve: unknown function or builtin `contract::invoke`"),
        "{error}"
    );
}
#[test]
fn production_accepts_opaque_isi_access_fallback() {
    let src = include_str!("fixtures/v1/c168.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("opaque ISI fallback should be deployable in production");
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let register = entrypoints
        .iter()
        .find(|entry| entry.name == "register")
        .expect("register entrypoint");
    assert!(
        register
            .read_keys
            .iter()
            .any(|key| key == GLOBAL_WILDCARD_KEY)
    );
    assert!(
        register
            .write_keys
            .iter()
            .any(|key| key == GLOBAL_WILDCARD_KEY)
    );
    assert_eq!(register.access_hints_complete, Some(false));
    assert_eq!(
        register.access_hints_skipped,
        vec![HINT_SKIP_OPAQUE_ISI.to_string()]
    );
}
#[test]
fn production_preserves_dynamic_asset_definition_transfer_coarse_hints() {
    let src = include_str!("fixtures/v1/c169.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("dynamic asset transfers should use coarse asset access hints");
    let hints = manifest
        .access_set_hints
        .expect("production must preserve coarse wildcard access hints");
    for key in [super::ASSET_WILDCARD_KEY, super::ASSET_DEF_WILDCARD_KEY] {
        assert!(hints.read_keys.iter().any(|actual| actual == key));
        assert!(hints.write_keys.iter().any(|actual| actual == key));
    }
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let move_entry = entrypoints
        .iter()
        .find(|entry| entry.name == "move")
        .expect("move entrypoint");
    assert_no_global_access_key(&move_entry.read_keys);
    assert_no_global_access_key(&move_entry.write_keys);
    for key in [super::ASSET_WILDCARD_KEY, super::ASSET_DEF_WILDCARD_KEY] {
        assert!(move_entry.read_keys.iter().any(|actual| actual == key));
        assert!(move_entry.write_keys.iter().any(|actual| actual == key));
    }
    assert_eq!(move_entry.access_hints_complete, Some(true));
    assert!(move_entry.access_hints_skipped.is_empty());
}
#[test]
fn production_accepts_fixed_asset_dynamic_account_transfer_hints() {
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = format!(
        r#"
seiyaku Test {{ permission Admin;
  kotoage fn move(AccountId from, AccountId to, quantity amount) authorize(Admin) {{
    ledger::asset::transfer(
      source: from,
      destination: to,
      asset_definition: AssetDefinitionId::parse("{asset_literal}"),
      amount: amount,
      dataspace: DataSpaceId::parse("0"),
    );
  }}
}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("fixed asset dynamic accounts should have bounded access hints");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(
        !hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()),
        "fixed asset transfers should not require global read wildcards"
    );
    assert!(
        !hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()),
        "fixed asset transfers should not require global write wildcards"
    );
    assert_no_global_access_key(&hints.read_keys);
    assert_no_global_access_key(&hints.write_keys);
    assert!(
        hints
            .read_keys
            .contains(&format!("asset_def:{asset_literal}"))
    );
    assert!(
        hints
            .write_keys
            .contains(&format!("asset_def:{asset_literal}"))
    );
    let entrypoints = manifest.entrypoints.expect("entrypoints present");
    let move_entry = entrypoints
        .iter()
        .find(|entry| entry.name == "move")
        .expect("move entrypoint");
    assert_eq!(move_entry.access_hints_complete, Some(true));
    assert!(move_entry.access_hints_skipped.is_empty());
}
#[test]
fn production_propagates_asset_definition_helper_return_into_access_hints() {
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = format!(
        r#"
seiyaku Test {{ permission Admin;
  fn settlement_asset() -> AssetDefinitionId {{
    let asset = AssetDefinitionId::parse("{asset_literal}");
    return asset;
  }}

  kotoage fn move(AccountId from, AccountId to, quantity amount) authorize(Admin) {{
    let asset = settlement_asset();
    ledger::asset::transfer(
      source: from,
      destination: to,
      asset_definition: asset,
      amount: amount,
      dataspace: DataSpaceId::parse("0"),
    );
  }}
}}
"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("literal asset helper return should feed access hints");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    assert!(!hints.read_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert!(!hints.write_keys.contains(&GLOBAL_WILDCARD_KEY.to_string()));
    assert_no_global_access_key(&hints.read_keys);
    assert_no_global_access_key(&hints.write_keys);
    assert!(
        hints
            .read_keys
            .contains(&format!("asset_def:{asset_literal}"))
    );
    assert!(
        hints
            .write_keys
            .contains(&format!("asset_def:{asset_literal}"))
    );
}
#[test]
fn explicit_global_wildcards_are_rejected() {
    let src = include_str!("fixtures/v1/c170.ko");
    let compiler = Compiler::new();
    let err = compiler
        .compile_source_with_manifest(src)
        .expect_err("manual access hints should be rejected");
    assert!(err.contains("access metadata is generated by the compiler"));
}
#[test]
fn manifest_access_set_hints_rejects_explicit_access() {
    let account_literal = sample_account_literal();
    let account_key = format!("account:{account_literal}");
    let src = format!(
        r#"
seiyaku Test {{ permission Admin;
  #[access(read="{account_key}", write="{account_key}")]
  kotoage fn move(AccountId from, AccountId to, AssetDefinitionId asset, quantity amount) authorize(Admin) {{
    ledger::asset::transfer(
      source: from,
      destination: to,
      asset_definition: asset,
      amount: amount,
      dataspace: DataSpaceId::parse("0"),
    );
  }}
}}
"#
    );
    let compiler = Compiler::new();
    let err = compiler
        .compile_source_with_manifest(&src)
        .expect_err("manual access hints should be rejected");
    assert!(err.contains("access metadata is generated by the compiler"));
}
#[test]
fn manifest_access_set_hints_include_literal_map_keys() {
    let src = include_str!("fixtures/v1/c171.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    let literal_key = canonical_numeric_state_key("Foo", ir::DataRefKind::Int, "1");
    assert_eq!(hints.read_keys, vec![literal_key.clone()]);
    assert_eq!(hints.write_keys, vec![literal_key]);
}
#[test]
fn manifest_access_set_hints_use_canonical_records_for_bool_map_keys() {
    let src = include_str!("fixtures/v1/c172.ko");
    let (_bytes, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile bool map access hints");
    let hints = manifest.access_set_hints.expect("access hints");
    let literal_key = canonical_state_key(
        "Foo",
        ivm_abi::state_value::StateValueKindV1::Bool,
        ivm_abi::state_value::StateValueAtomV1::Bool(true),
    );
    assert!(hints.read_keys.contains(&literal_key), "{hints:?}");
    assert!(hints.write_keys.contains(&literal_key), "{hints:?}");
}
#[test]
fn manifest_access_set_hints_support_canonical_quantity_map_keys() {
    let src = include_str!("fixtures/v1/c173.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("quantity is a canonical-Norito durable map key");
    let hints = manifest.access_set_hints.expect("access hints");
    let literal_key = canonical_numeric_state_key("Foo", ir::DataRefKind::Quantity, "7");
    assert!(hints.read_keys.contains(&literal_key), "{hints:?}");
    assert!(hints.write_keys.contains(&literal_key), "{hints:?}");
    assert_eq!(
        hints
            .read_keys
            .iter()
            .filter(|key| key.starts_with("state:Foo/"))
            .count(),
        1,
        "7.00 and 7 must canonicalize to the same quantity key"
    );
}
#[test]
fn manifest_access_set_hints_include_literal_pointer_map_keys() {
    let src = include_str!("fixtures/v1/c174.ko");
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    let tlv = super::encode_pointer_tlv_bytes(super::ir::DataRefKind::Name, "alice", false)
        .expect("encode pointer tlv");
    let expected = canonical_state_key(
        "Foo",
        ivm_abi::state_value::StateValueKindV1::Name,
        ivm_abi::state_value::StateValueAtomV1::Pointer(tlv),
    );
    assert!(hints.read_keys.contains(&expected));
    assert!(hints.write_keys.contains(&expected));
}
#[test]
fn manifest_access_set_hints_include_create_trigger() {
    use iroha_data_model::{
        account::AccountId,
        events::{EventFilterBox, execute_trigger::ExecuteTriggerEventFilter},
        transaction::{Executable, IvmBytecode},
        trigger::{
            Trigger, TriggerId,
            action::{Action, Repeats},
        },
    };
    use iroha_model_base::name::Name;
    use std::str::FromStr;
    let trigger_id = TriggerId::new(Name::from_str("wake").expect("trigger name"));
    let authority = AccountId::new(
        "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
            .parse()
            .expect("public key"),
    );
    let filter = EventFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new());
    let action = Action::new(
        Executable::Ivm(IvmBytecode::from_compiled(Vec::new())),
        Repeats::Indefinitely,
        authority,
        filter,
    )
    .expect("trigger action fixture satisfies validation invariants");
    let trigger = Trigger::new(trigger_id.clone(), action);
    let json_value = norito::json::to_value(&trigger).expect("trigger json value");
    let raw_json = norito::json::to_string(&json_value).expect("trigger json");
    let escaped = raw_json.replace('\\', "\\\\").replace('"', "\\\"");
    let src = format!(
        r#"seiyaku Test {{ permission Admin;  kotoage fn main() authorize(Admin) {{ ledger::trigger::register(trigger_spec: Json::parse("{escaped}")); }} }}"#
    );
    let compiler = Compiler::new();
    let (_bytes, manifest) = compiler
        .compile_source_with_manifest(&src)
        .expect("compile manifest");
    let hints = manifest
        .access_set_hints
        .expect("expected access_set_hints");
    let trigger_key = format!("trigger:{trigger_id}");
    let repetitions_key = format!("trigger.repetitions:{trigger_id}");
    assert!(hints.read_keys.contains(&trigger_key));
    assert!(hints.write_keys.contains(&trigger_key));
    assert!(hints.write_keys.contains(&repetitions_key));
}
#[test]
fn state_path_for_norito_key_uses_reversible_canonical_hex() {
    let base = "Map";
    let raw = "0x6162";
    assert_eq!(
        super::state_path_for_norito_key(base, raw).as_deref(),
        Some("Map/6162")
    );
}
#[test]
fn source_string_pointer_encoding_keeps_hex_prefix_literal() {
    for spelling in ["0x", "0x1", "0xzz", "0x6162"] {
        let encoded = super::encode_pointer_tlv_bytes(ir::DataRefKind::Blob, spelling, true)
            .expect("all UTF-8 source strings encode directly");
        let length = u32::from_be_bytes(encoded[3..7].try_into().expect("TLV length")) as usize;
        assert_eq!(&encoded[7..7 + length], spelling.as_bytes());
    }
    let encoded = super::encode_pointer_tlv_bytes(ir::DataRefKind::Blob, "0x6162", false)
        .expect("byte carrier hex still decodes");
    assert_eq!(&encoded[7..9], b"ab");
}
#[test]
fn state_codegen_rejects_legacy_name_literal_carrier() {
    let path = ir::Temp(0);
    let strings = HashMap::from([((0, path), "legacy".to_owned())]);
    let kinds = HashMap::from([((0, path), ir::DataRefKind::Name)]);
    let error = super::state_path_literal_data_key(0, path, &strings, &kinds)
        .expect_err("Name must not remain a state-path carrier");
    assert!(error.contains("expected NoritoBytes(StatePath)"), "{error}");
}
#[test]
fn entry_spills_use_stack_frame() {
    // The compiler pipeline may use a few MiB of stack in debug builds; run this test on a
    // larger stack so it doesn't depend on the test harness' thread stack size.
    std::thread::Builder::new()
        .name("kotodama_entry_spills_use_stack_frame".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // Literal table references intentionally need no stack homes. Use
            // genuine runtime parameters all live at one call to test spills.
            let count = 32;
            let parameters = (0..count).map(|index| format!("int a{index}")).collect::<Vec<_>>().join(", ");
            let arguments = (0..count).map(|index| format!("a{index}")).collect::<Vec<_>>().join(", ");
            let sum = (0..count).map(|index| format!("a{index}")).collect::<Vec<_>>().join(" + ");
            let src = format!("seiyaku SpillTest {{ fn sum({parameters}) -> int {{ return {sum}; }} fn main({parameters}) -> int {{ return sum({arguments}); }} }}");
            let parsed = crate::parser::parse(&src).expect("parse spill test");
            let typed = crate::semantic::analyze(&parsed).expect("type spill test");
            let ir_prog = crate::ir::lower(&typed).expect("lower spill test");
            let func = ir_prog
                .functions
                .iter()
                .find(|func| func.name == "main")
                .expect("main function");
            let alloc = crate::regalloc::allocate(func);
            assert!(
                !alloc.stack.is_empty(),
                "expected spills to allocate stack slots"
            );
            assert!(alloc.frame_size > 0, "expected non-zero frame size");
        })
        .expect("spawn large-stack test thread")
        .join()
        .expect("test thread panicked");
}
/// Every syscall word emitted in an artifact's code section, in program order.
fn emitted_syscalls(bytes: &[u8]) -> Vec<u32> {
    let parsed = ProgramMetadata::parse(bytes).expect("parse metadata");
    bytes[parsed.code_offset..]
        .chunks_exact(4)
        .filter_map(|word| {
            let word = u32::from_le_bytes(word.try_into().expect("four-byte word"));
            match instruction::wide::opcode(word) {
                instruction::wide::system::SCALL => {
                    Some(u32::from(encoding::wide::decode_sys(word).1))
                }
                instruction::wide::system::SYSTEM => Some(encoding::wide::decode_syscallx(word)),
                _ => None,
            }
        })
        .collect()
}
#[test]
fn json_string_and_bool_getters_emit_their_extended_syscalls() {
    let source = r#"
seiyaku JsonFields {
    view fn flags() authorize(anyone) -> bool {
        return read_flag(json { label: "rose", flag: true });
    }
    fn read_flag(Json value) -> bool {
        let label = value.get_string("label");
        return label.is_some() && value.get_bool("flag").unwrap_or(false);
    }
}
"#;
    let bytes = Compiler::new()
        .compile_source(source)
        .expect("compile string and bool getters");
    let emitted = emitted_syscalls(&bytes);
    for builtin in [
        kotodama_surface::builtins::Builtin::GetString,
        kotodama_surface::builtins::Builtin::GetBool,
    ] {
        for syscall in builtin.operation_syscalls() {
            assert!(
                emitted.contains(syscall),
                "{builtin:?} must emit {syscall:#x}; emitted {emitted:x?}"
            );
        }
    }
}
#[test]
fn ledger_builtin_codegen_emits_exactly_the_registry_operation_syscalls() {
    use kotodama_surface::builtins::{Builtin, BuiltinLowering, BuiltinMode, BuiltinSurface};
    const PARAMS: &str = "AccountId account, AccountId source, AccountId destination, \
        AssetDefinitionId asset_definition, quantity amount, NftId nft, AccountId owner, \
        Name key, Json value, DomainId domain, Name role, Json permissions, Name permission_token, \
        Json peer, Json trigger_spec, Name trigger_id, bool enabled, Json signatory, int quorum, \
        string alias, int request_generation, Name offer, bytes evidence, string name, \
        DataSpaceId dataspace, Option<quantity> cap, Option<quantity> limit, bytes ballot";
    // One representative call per production ledger mutation. Label punning keeps
    // most calls short; every other argument is named explicitly.
    let cases: &[(Builtin, &str)] = &[
        (
            Builtin::SetAccountMetadata,
            "ledger::account::set_metadata(account, key, value)",
        ),
        (
            Builtin::RegisterAccount,
            "ledger::account::register(account)",
        ),
        (
            Builtin::UnregisterAccount,
            "ledger::account::unregister(account)",
        ),
        (
            Builtin::AddSignatory,
            "ledger::account::add_signatory(account, signatory)",
        ),
        (
            Builtin::RemoveSignatory,
            "ledger::account::remove_signatory(account, signatory)",
        ),
        (
            Builtin::SetAccountQuorum,
            "ledger::account::set_quorum(account, quorum)",
        ),
        (
            Builtin::AccountRecoveryPropose,
            "ledger::account::recovery::propose(alias, replacement: account, request_generation: request_generation)",
        ),
        (
            Builtin::AccountRecoveryApprove,
            "ledger::account::recovery::approve(alias, request_generation)",
        ),
        (
            Builtin::AccountRecoveryCancel,
            "ledger::account::recovery::cancel(alias, request_generation)",
        ),
        (
            Builtin::AccountRecoveryFinalize,
            "ledger::account::recovery::finalize(alias, request_generation)",
        ),
        (
            Builtin::RegisterAsset,
            "ledger::asset::register(asset_definition, name, spec: NumericSpec::fractional(2), mintable: Mintable::Limited(3))",
        ),
        (
            Builtin::UnregisterAsset,
            "ledger::asset::unregister(asset_definition)",
        ),
        (
            Builtin::MintAsset,
            "ledger::asset::mint(account, asset_definition, amount)",
        ),
        (
            Builtin::BurnAsset,
            "ledger::asset::burn(account, asset_definition, amount)",
        ),
        (
            Builtin::TransferAsset,
            "ledger::asset::transfer(source, destination, asset_definition, amount)",
        ),
        (
            Builtin::SetAssetTransferDailyLimit,
            "ledger::asset::set_transfer_daily_limit(account, asset_definition, cap)",
        ),
        (
            Builtin::SetAssetHoldingLimit,
            "ledger::asset::set_holding_limit(account, asset_definition, limit)",
        ),
        (Builtin::NftMintAsset, "ledger::nft::mint(nft, owner)"),
        (
            Builtin::NftSetMetadata,
            "ledger::nft::set_metadata(nft, key, value)",
        ),
        (Builtin::NftBurnAsset, "ledger::nft::burn(nft)"),
        (
            Builtin::NftTransferAsset,
            "ledger::nft::transfer(source, nft, destination)",
        ),
        (Builtin::RegisterDomain, "ledger::domain::register(domain)"),
        (
            Builtin::UnregisterDomain,
            "ledger::domain::unregister(domain)",
        ),
        (
            Builtin::TransferDomain,
            "ledger::domain::transfer(source, domain, destination)",
        ),
        (Builtin::RegisterPeer, "ledger::peer::register(peer)"),
        (Builtin::UnregisterPeer, "ledger::peer::unregister(peer)"),
        (
            Builtin::RegisterTrigger,
            "ledger::trigger::register(trigger_spec: trigger_spec)",
        ),
        (
            Builtin::UnregisterTrigger,
            "ledger::trigger::unregister(trigger_id)",
        ),
        (
            Builtin::SetTriggerEnabled,
            "ledger::trigger::set_enabled(trigger: trigger_id, enabled: enabled)",
        ),
        (
            Builtin::RegisterRole,
            "ledger::role::register(role, permissions)",
        ),
        (Builtin::UnregisterRole, "ledger::role::unregister(role)"),
        (Builtin::GrantRole, "ledger::role::grant(account, role)"),
        (Builtin::RevokeRole, "ledger::role::revoke(account, role)"),
        (
            Builtin::GrantPermission,
            "ledger::permission::grant(account, permission: permission_token)",
        ),
        (
            Builtin::RevokePermission,
            "ledger::permission::revoke(account, permission: permission_token)",
        ),
        (
            Builtin::GrantContractPermission,
            "ledger::seiyaku::grant_permission(account, permission: ProbeAccess)",
        ),
        (
            Builtin::RevokeContractPermission,
            "ledger::seiyaku::revoke_permission(account, permission: ProbeAccess)",
        ),
        (
            Builtin::EscrowOpenOffer,
            "ledger::escrow::open_offer(offer, asset_definition, amount)",
        ),
        (Builtin::EscrowAccept, "ledger::escrow::accept(offer)"),
        (
            Builtin::EscrowMarkPaymentSent,
            "ledger::escrow::mark_payment_sent(offer)",
        ),
        (Builtin::EscrowRelease, "ledger::escrow::release(offer)"),
        (Builtin::EscrowCancel, "ledger::escrow::cancel(offer)"),
        (
            Builtin::EscrowOpenDispute,
            "ledger::escrow::open_dispute(offer, evidence)",
        ),
        (
            Builtin::ScExecuteSubmitBallot,
            "ledger::governance::submit_ballot(ballot)",
        ),
        (
            Builtin::EscrowResolveDispute,
            "ledger::escrow::resolve_dispute(offer, buyer_amount: amount, seller_amount: amount)",
        ),
        // Non-ledger builtins whose registry set must also match codegen.
        (
            Builtin::VerifySignature,
            "let _verified = crypto::verify_signature(message: evidence, signature: evidence, public_key: evidence, scheme: SignatureScheme::MlDsa)",
        ),
        (
            Builtin::TransactionTimeMs,
            "let _now = context::transaction_time_ms()",
        ),
        (
            Builtin::Sha256Hash,
            "let _digest = crypto::sha256(evidence)",
        ),
    ];
    let compile = |body: &str| {
        let source = format!(
            "seiyaku Probe {{ permission ProbeAccess; kotoage fn probe({PARAMS}) authorize(ProbeAccess) {{ {body} }} }}"
        );
        let bytes = Compiler::new()
            .compile_source(&source)
            .unwrap_or_else(|error| panic!("`{body}` must compile: {error}"));
        emitted_syscalls(&bytes)
    };
    let baseline = compile("").into_iter().collect::<HashSet<_>>();
    let mut covered = HashSet::new();
    for (builtin, call) in cases {
        covered.insert(*builtin);
        let spec = builtin.spec();
        let emitted = compile(&format!("{call};"))
            .into_iter()
            // Pointer publication, checked `int` narrowing and its trap are
            // compiler-owned plumbing, not ledger operations.
            .filter(|syscall| {
                !baseline.contains(syscall)
                    && *syscall != syscalls::SYSCALL_INPUT_PUBLISH_TLV
                    && *syscall != syscalls::SYSCALL_ABORT
                    && !syscalls::is_numeric_v1_syscall(*syscall)
            })
            .collect::<HashSet<_>>();
        let declared = spec
            .operation_syscalls
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        match spec.lowering {
            BuiltinLowering::DirectSyscall => assert_eq!(
                emitted, declared,
                "{builtin:?} must emit exactly its registry operation syscall"
            ),
            BuiltinLowering::DerivedSyscalls => {
                assert!(!emitted.is_empty(), "{builtin:?} emitted no operation");
                assert!(
                    emitted.is_subset(&declared),
                    "{builtin:?} emitted {emitted:x?} outside its registry set {declared:x?}"
                );
            }
            BuiltinLowering::Instructions => {
                assert!(emitted.is_empty(), "{builtin:?} must not reach the host")
            }
        }
    }
    for (builtin, spec) in Builtin::registry() {
        if spec.name.starts_with("ledger::")
            && spec.surface == BuiltinSurface::Function
            && spec.mode == BuiltinMode::Any
            && spec.access == BuiltinAccess::LedgerWrite
            && !matches!(
                builtin,
                Builtin::TransferBatch
                    | Builtin::SetAssetTransferAvailability
                    | Builtin::CreateNftsForAllUsers
                    | Builtin::SubscriptionBill
                    | Builtin::SubscriptionRecordUsage
            )
        {
            assert!(
                covered.contains(&builtin),
                "add a codegen/registry syscall case for {builtin:?}"
            );
        }
    }
}
/// Probe-call argument for one registry parameter descriptor, or `None` when
/// the descriptor needs a bespoke call shape (generic, aggregate, ZK, AXT or
/// state-handle arguments).
fn registry_probe_argument(descriptor: &str) -> Option<&'static str> {
    Some(match descriptor.strip_suffix('?').unwrap_or(descriptor) {
        "AccountId" => "account",
        "AssetDefinitionId" => "asset_definition",
        "AssetId" => "asset",
        "DataSpaceId" => "dataspace",
        "DomainId" | "DomainId|Name" => "domain",
        "Json" => "value",
        "Name" | "Name|Json" => "key",
        "Name|bytes" | "bytes" => "evidence",
        "NftId" => "nft",
        "Option<quantity>" => "cap",
        "Option<string>" => "note",
        "bool" => "enabled",
        "int" | "int|bytes" | "int|decimal" | "int|decimal|quantity" => "quorum",
        "quantity" => "amount",
        "string" | "string|bytes" | "string|int" => "name",
        "T" | "K" | "bool|int|decimal|quantity|string|Name" => "quorum",
        "Permission" => "ProbeAccess",
        "NumericSpec" => "NumericSpec::integer()",
        "Mintable" => "Mintable::Once",
        "SignatureScheme" => "SignatureScheme::Ed25519",
        "ErrorEnum::Variant" => "ProbeError::Rejected",
        "List<(AccountId,AccountId,AssetDefinitionId,quantity),N>" => {
            "[(account, account, asset_definition, amount)]"
        }
        _ => return None,
    })
}
#[test]
fn every_builtin_codegen_matches_its_registry_operation_syscalls() {
    use kotodama_surface::builtins::{Builtin, BuiltinLowering, BuiltinMode, BuiltinSurface};
    const PARAMS: &str = "AccountId account, AssetDefinitionId asset_definition, AssetId asset, \
        DataSpaceId dataspace, DomainId domain, Json value, Name key, bytes evidence, NftId nft, \
        Option<quantity> cap, Option<string> note, bool enabled, int quorum, quantity amount, \
        string name";
    let compile = |body: &str| {
        let source = format!(
            "seiyaku Probe {{ permission ProbeAccess; error enum ProbeError {{ Rejected = 1 }} \
             kotoage fn probe({PARAMS}) authorize(ProbeAccess) {{ {body} }} }}"
        );
        Compiler::new()
            .compile_source(&source)
            .map(|bytes| emitted_syscalls(&bytes))
    };
    let baseline = compile("")
        .expect("empty probe compiles")
        .into_iter()
        .collect::<HashSet<_>>();
    // Pointer publication, normalization and encoding, heap allocation,
    // checked `int` narrowing and its trap are compiler-owned plumbing unless
    // the builtin declares them as its operation.
    let plumbing = |syscall: u32| {
        syscall == syscalls::SYSCALL_INPUT_PUBLISH_TLV
            || syscall == syscalls::SYSCALL_ALLOC
            || syscall == syscalls::SYSCALL_NORMALIZE_NORITO_BYTES
            || syscall == syscalls::SYSCALL_POINTER_TO_NORITO
            || syscall == syscalls::SYSCALL_ABORT
            || syscalls::is_numeric_v1_syscall(syscall)
    };
    let mut checked = 0_usize;
    let mut unprobed = Vec::new();
    let mut failures = Vec::new();
    for (builtin, spec) in Builtin::registry() {
        if spec.surface != BuiltinSurface::Function
            || spec.mode != BuiltinMode::Any
            || matches!(builtin, Builtin::PointerConstructor(_))
            || builtin.is_compile_time_nominal()
        {
            continue;
        }
        if builtin == Builtin::TriggerEvent {
            // Readable only from a trigger body; `trigger_event` codegen is
            // covered by the trigger lowering tests.
            unprobed.push(spec.name);
            continue;
        }
        // Arguments that must be compile-time literals at the call.
        let literal = |label: &str| match (builtin, label) {
            (
                Builtin::GrantContractPermission | Builtin::RevokeContractPermission,
                "permission",
            ) => Some("ProbeAccess"),
            (Builtin::BuildSubmitBallotInline, "election_id" | "backend") => Some("\"probe\""),
            (Builtin::BuildSubmitBallotInline, "ciphertext") => Some("b\"ciphertext\""),
            (Builtin::BuildSubmitBallotInline, "nullifier") => {
                Some("b\"0123456789abcdef0123456789abcdef\"")
            }
            (Builtin::BuildSubmitBallotInline, "proof") => Some("b\"proof\""),
            (Builtin::BuildSubmitBallotInline, "verification_key") => Some("b\"vk\""),
            _ => None,
        };
        let arguments = spec
            .signature
            .parameters
            .iter()
            .zip(spec.signature.parameter_names)
            .map(|(descriptor, label)| {
                literal(label)
                    .or_else(|| registry_probe_argument(descriptor))
                    .map(|argument| format!("{label}: {argument}"))
            })
            .collect::<Option<Vec<_>>>();
        let Some(arguments) = arguments else {
            unprobed.push(spec.name);
            continue;
        };
        // Rule (a) of the label policy: a label equal to the declared
        // parameter name is accepted by every builtin.
        let call = format!("{}({})", spec.name, arguments.join(", "));
        let statement = if spec.signature.return_type == "()" {
            format!("{call};")
        } else {
            format!("let _probe = {call};")
        };
        let emitted = match compile(&statement) {
            Ok(emitted) => emitted,
            Err(error) => {
                failures.push(format!(
                    "{builtin:?}: `{statement}` failed to compile: {error}"
                ));
                continue;
            }
        };
        let declared = spec
            .operation_syscalls
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let emitted = emitted
            .into_iter()
            .filter(|syscall| {
                !baseline.contains(syscall) && (declared.contains(syscall) || !plumbing(*syscall))
            })
            .collect::<HashSet<_>>();
        let consistent = match spec.lowering {
            BuiltinLowering::DirectSyscall => emitted == declared,
            BuiltinLowering::DerivedSyscalls => !emitted.is_empty() && emitted.is_subset(&declared),
            BuiltinLowering::Instructions => emitted.is_empty(),
        };
        if !consistent {
            failures.push(format!(
                "{builtin:?} ({:?}): `{statement}` emitted {emitted:x?}, registry declares {declared:x?}",
                spec.lowering
            ));
        }
        checked += 1;
    }
    // Receiver methods (StateMap helpers, JSON getters, `Name.path`) run in a
    // private helper, where JSON payload getters are permitted.
    const ARGS: &str = "account, asset_definition, asset, dataspace, domain, value, key, \
        evidence, nft, cap, note, enabled, quorum, amount, name";
    let compile_method = |body: &str| {
        let source = format!(
            "seiyaku Probe {{ permission ProbeAccess; state StateMap<int, int> Balances; fn run({PARAMS}) {{ {body} }} \
             kotoage fn probe({PARAMS}) authorize(ProbeAccess) {{ run({ARGS}); }} }}"
        );
        Compiler::new()
            .compile_source(&source)
            .map(|bytes| emitted_syscalls(&bytes))
    };
    let method_baseline = compile_method("")
        .expect("empty method probe compiles")
        .into_iter()
        .collect::<HashSet<_>>();
    let mut methods = 0_usize;
    for (builtin, spec) in Builtin::registry() {
        if spec.surface != BuiltinSurface::MethodOnly || spec.mode != BuiltinMode::Any {
            continue;
        }
        let parameters = spec
            .signature
            .parameters
            .iter()
            .zip(spec.signature.parameter_names);
        let mut receiver = None;
        let mut arguments = Vec::new();
        for (index, (descriptor, label)) in parameters.enumerate() {
            let argument = match *descriptor {
                "StateMap<K,V>" => "Balances",
                "K" | "V" => "quorum",
                other => registry_probe_argument(other)
                    .unwrap_or_else(|| panic!("{builtin:?}: no probe for `{other}`")),
            };
            if index == 0 {
                receiver = Some(argument);
            } else {
                arguments.push(format!("{label}: {argument}"));
            }
        }
        let receiver = receiver.unwrap_or_else(|| panic!("{builtin:?} has no receiver"));
        let statement = format!(
            "let _probe = {receiver}.{}({});",
            spec.name,
            arguments.join(", ")
        );
        let declared = spec
            .operation_syscalls
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        match compile_method(&statement) {
            Ok(emitted) => {
                let emitted = emitted
                    .into_iter()
                    .filter(|syscall| {
                        !method_baseline.contains(syscall)
                            && (declared.contains(syscall) || !plumbing(*syscall))
                    })
                    .collect::<HashSet<_>>();
                let consistent = match spec.lowering {
                    BuiltinLowering::DirectSyscall => emitted == declared,
                    BuiltinLowering::DerivedSyscalls => {
                        !emitted.is_empty() && emitted.is_subset(&declared)
                    }
                    BuiltinLowering::Instructions => emitted.is_empty(),
                };
                if !consistent {
                    failures.push(format!(
                        "{builtin:?} ({:?}): `{statement}` emitted {emitted:x?}, registry declares {declared:x?}",
                        spec.lowering
                    ));
                }
            }
            Err(error) => failures.push(format!(
                "{builtin:?}: `{statement}` failed to compile: {error}"
            )),
        }
        methods += 1;
    }
    assert!(methods >= 15, "only {methods} receiver methods were probed");
    unprobed.sort_unstable();
    assert!(
        failures.is_empty(),
        "{}\nunprobed: {unprobed:?}",
        failures.join("\n")
    );
    // Builtins whose arguments need bespoke shapes (AXT descriptors) or a
    // trigger body; each is covered by a dedicated codegen test. Adding a
    // builtin with plain arguments extends the sweep automatically.
    assert_eq!(
        unprobed,
        [
            "axt::begin",
            "axt::stage_anchored_spend",
            "context::trigger_event"
        ],
        "registry builtins the sweep cannot synthesize a call for"
    );
    assert!(checked > 100, "only {checked} builtins were probed");
}

#[test]
fn declared_authorization_inventory_is_authenticated_in_artifact_and_manifest() {
    use iroha_data_model::smart_contract::manifest::{
        ContractPermissionScopeV1, EntrypointAuthorizationV1,
    };
    let source = r#"誓約 Guarded {
        permission Unused;
        permission Admin;
        import permission "CanSetParameters" as ChainAdmin;
        始まり() {}
        kaizen() {}
        言挙げ fn update() authorize(Admin) {}
        view fn inspect() authorize(ChainAdmin) -> int { 1 }
        kotoage fn open() authorize(anyone) {}
    }"#;
    let (artifact, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .expect("declared permissions");
    let interface = ProgramMetadata::parse(&artifact)
        .unwrap()
        .contract_interface
        .unwrap();
    assert_eq!(interface.permissions, manifest.permissions);
    assert_eq!(
        interface
            .permissions
            .iter()
            .map(|permission| permission.name.as_ref())
            .collect::<Vec<&str>>(),
        ["Admin", "ChainAdmin", "Unused"]
    );
    assert_eq!(
        interface.permissions[0].scope,
        ContractPermissionScopeV1::Instance
    );
    assert_eq!(
        interface.permissions[1].scope,
        ContractPermissionScopeV1::Chain {
            permission_name: "CanSetParameters".parse().unwrap()
        }
    );
    let authorization = |name: &str| {
        &interface
            .entrypoints
            .iter()
            .find(|entry| entry.name == name)
            .unwrap()
            .authorization
    };
    assert_eq!(
        authorization("update"),
        &EntrypointAuthorizationV1::Permission("Admin".parse().unwrap())
    );
    assert_eq!(
        authorization("inspect"),
        &EntrypointAuthorizationV1::Permission("ChainAdmin".parse().unwrap())
    );
    assert_eq!(authorization("open"), &EntrypointAuthorizationV1::Anyone);
    assert_eq!(
        authorization("hajimari"),
        &EntrypointAuthorizationV1::RuntimeLifecycle
    );
    assert_eq!(
        authorization("kaizen"),
        &EntrypointAuthorizationV1::RuntimeLifecycle
    );
}

#[test]
fn scoped_permission_grants_emit_canonical_name_pointer_operations() {
    let source = r#"seiyaku Grants {
        permission Admin; permission Pay;
        kotoage fn grant(AccountId account) authorize(Admin) {
            ledger::seiyaku::grant_permission(account: account, permission: Pay);
            ledger::誓約::revoke_permission(account: account, permission: Pay);
        }
    }"#;
    let artifact = Compiler::new()
        .compile_source(source)
        .expect("instance permission grant and revoke");
    let syscalls = emitted_syscalls(&artifact);
    assert!(syscalls.contains(&crate::syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION));
    assert!(syscalls.contains(&crate::syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION));
}

#[test]
fn ordinary_enums_keep_distinct_public_call_json_and_durable_state_schemas() {
    use ivm_abi::entrypoint::{EntrypointValueAtomV1 as Atom, EntrypointValueTypeNodeV1 as Node};
    let source = r#"seiyaku EnumValues {
        enum Status { Active = 1, Paused = 2 }
        struct Record { Status status; Option<Status> previous; List<Status, 4> history; }
        state Record Snapshot;
        state StateMap<int, Status> Values;
        hajimari() { Snapshot = Record { status: Status::Active, previous: Option::none, history: [Status::Active] }; }
        view fn echo(Status value) authorize(anyone) -> Status { value }
        view fn inspect() authorize(anyone) -> Record { Snapshot }
        view fn pending() authorize(anyone) -> Result<int, Status> { Result::err(Status::Paused) }
        view fn json_value(Status value) authorize(anyone) -> Json { json { status: value } }
        kotoage fn store(int key, Status value) authorize(anyone) { Values[key] = value; }
    }"#;
    let (artifact, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .expect("enum ABI and state");
    let interface = ProgramMetadata::parse(&artifact)
        .unwrap()
        .contract_interface
        .unwrap();
    assert!(
        interface
            .error_types
            .iter()
            .all(|descriptor| !descriptor.identity.ends_with("::Status"))
    );
    assert_eq!(interface.enum_types, manifest.enum_types);
    assert_eq!(interface.enum_types.len(), 1);
    assert_eq!(interface.enum_types[0].identity, "EnumValues::Status");
    assert!(manifest.error_types.as_ref().is_none_or(|types| {
        types
            .iter()
            .all(|descriptor| !descriptor.identity.ends_with("::Status"))
    }));
    let echo = interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "echo")
        .unwrap();
    let schema = echo.argument_schema.as_ref().unwrap();
    assert!(
        matches!(&schema.fields[0].ty.nodes[..], [Node::Enum(descriptor)] if descriptor.identity == "EnumValues::Status")
    );
    let record = ivm_abi::arguments::argument_record_from_json(
        schema,
        &iroha_primitives::json::Json::from_str_norito(r#"{"value":"Paused"}"#).unwrap(),
    )
    .unwrap();
    assert!(matches!(record.atoms.as_slice(), [Atom::EnumCode(2)]));
    for invalid in [
        iroha_primitives::json::Json::from_str_norito(r#"{"value":2}"#).unwrap(),
        iroha_primitives::json::Json::from_str_norito(r#"{"value":"2"}"#).unwrap(),
        iroha_primitives::json::Json::from_str_norito(r#"{"value":"EnumValues::Status::Paused"}"#)
            .unwrap(),
    ] {
        assert!(ivm_abi::arguments::argument_record_from_json(schema, &invalid).is_err());
    }
    assert!(
        interface
            .states
            .iter()
            .any(|state| format!("{:?}", state.ty).contains("Enum(")),
        "nested stored schemas carry the nominal data enum"
    );
}

#[test]
fn native_events_embed_exact_sorted_payload_schemas_and_enum_inventory() {
    use ivm_abi::entrypoint::EntrypointValueTypeNodeV1 as Node;
    let source = r#"seiyaku EventValues {
        enum Status { Active = 1, Paused = 2 }
        struct Details { Status status; List<int, 4> changes; }
        event Transfer { AccountId from; Option<Details> details; quantity amount; }
        event Empty {}
        kotoage fn run(AccountId owner) authorize(anyone) {
            emit Transfer { amount: 2.5, details: Option::some(Details { status: Status::Active, changes: [1, 2] }), from: owner };
            emit Empty {};
        }
    }"#;
    let (artifact, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .expect("native event compilation");
    let interface = ProgramMetadata::parse(&artifact)
        .unwrap()
        .contract_interface
        .unwrap();
    assert_eq!(interface.events, manifest.events);
    assert_eq!(
        interface
            .events
            .iter()
            .map(|event| event.name.as_ref())
            .collect::<Vec<_>>(),
        ["Empty", "Transfer"]
    );
    assert!(interface.events.iter().all(|event| event.validate()));
    assert_eq!(interface.enum_types.len(), 1);
    let Node::Struct(root) = &interface.events[1].payload_type.nodes[0] else {
        panic!("event payload root")
    };
    assert_eq!(root.name, "EventValues::Transfer");
    assert_eq!(root.fields, ["from", "details", "amount"]);
    assert!(interface.events[1].payload_type.nodes.iter().any(
        |node| matches!(node, Node::Enum(descriptor) if descriptor == &interface.enum_types[0])
    ));
}

#[test]
fn vrf_epoch_seed_accepts_typed_exact_epochs_and_returns_an_option() {
    let source = "seiyaku Seeds { view fn read(int epoch) authorize(anyone) -> Option<bytes> { crypto::vrf::epoch_seed(epoch: epoch) } }";
    let parsed = parse(source).unwrap();
    let typed = analyze(&parsed).unwrap();
    let lowered = ir::lower(&typed).unwrap();
    assert!(
        lowered
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instrs)
            .any(|instruction| matches!(instruction, ir::Instr::IntToU64 { .. }))
    );
    assert!(
        lowered
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instrs)
            .any(|instruction| matches!(instruction, ir::Instr::VrfEpochSeed { .. }))
    );
    Compiler::new()
        .compile_source(source)
        .expect("typed VRF source compiles");
    for expression in [
        "crypto::vrf::epoch_seed(epoch: bytes(\"0x00\"))",
        "crypto::vrf::epoch_seed(epoch: -1)",
        "crypto::vrf::epoch_seed(epoch: 18446744073709551616)",
    ] {
        let source = format!(
            "seiyaku Seeds {{ view fn read() authorize(anyone) -> Option<bytes> {{ {expression} }} }}"
        );
        assert!(
            Compiler::new().compile_source(&source).is_err(),
            "{expression}"
        );
    }
}

#[test]
fn public_value_utilities_compile_exact_schemas_and_reject_private_or_cursor_values() {
    Compiler::new().compile_source(r#"seiyaku Utilities {
        enum Status { Ready = 1 }
        struct Payload { Status status; List<Option<int>, 2> values; Json metadata }
        view fn encode(Payload value) authorize(anyone) -> bytes { codec::encode(value) }
        view fn text(Name value) authorize(anyone) -> string { string::from(value) }
        view fn concat(string left, string right) authorize(anyone) -> string { string::concat(left, right) }
        view fn decode(bytes value) authorize(anyone) -> Option<string> { string::from_bytes(value) }
    }"#).expect("canonical public utilities");
    for source in [
        "module Reject { fn encode(StateCursor<int> value) -> bytes { codec::encode(value) } }",
        "module Reject { fn encode(Option<StateCursor<int>> value) -> bytes { codec::encode(value) } }",
        "module Reject { fn text(AccountId value) -> string { string::from(value) } }",
        "module Reject { fn text(bytes value) -> string { string::from(value) } }",
        "module Reject { fn text(int value) -> string { string::as_bytes(value) } }",
    ] {
        let error = Compiler::new()
            .compile_source(source)
            .expect_err("utility must reject unsupported source type");
        assert!(error.contains("K2003"), "{error}");
    }
}

#[test]
fn numeric_selection_retains_exact_domains_and_rejects_implicit_mixing() {
    Compiler::new().compile_source("seiyaku NumericSelection { view fn select(decimal a, decimal b, quantity q, quantity r) authorize(anyone) -> (decimal, decimal, decimal, quantity, quantity, quantity) { (math::min(a, b), math::max(a, b), math::abs(a), math::min(q, r), math::max(q, r), math::abs(q)) } }").expect("all exact numeric domains");
    for expression in [
        "math::min(1, 2.0)",
        "math::max(1.0, 2)",
        "math::abs(true)",
        "math::mean(1.0, 2.0)",
    ] {
        let source = format!("module Rejected {{ fn bad() {{ let _value = {expression}; }} }}");
        let error = Compiler::new()
            .compile_source(&source)
            .expect_err("mixed or unsupported numeric operands");
        assert!(error.contains("K2003"), "{error}");
    }
}

#[test]
fn account_filtered_asset_pages_keep_the_exact_owner_and_typed_projection() {
    let source = "seiyaku Inventory { view fn assets(AccountId account, int offset) authorize(anyone) -> QueryPage<AssetView> { ledger::query::assets_of(account: account, offset: offset, limit: 2) } }";
    let typed = analyze(&parse(source).unwrap()).unwrap();
    let lowered = ir::lower(&typed).unwrap();
    assert!(
        lowered
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instrs)
            .any(|instruction| matches!(
                instruction,
                ir::Instr::CoreQueryPage {
                    account: Some(_),
                    entity: ivm_abi::core_query::CoreQueryEntityTagV1::Asset,
                    ..
                }
            ))
    );
    Compiler::new()
        .compile_source(source)
        .expect("typed owner filter");
    for args in [
        "account: 3, offset: 0, limit: 2",
        "account: account, offset: -1, limit: 2",
        "account: account, offset: 0, limit: 65",
    ] {
        let source = format!(
            "seiyaku Inventory {{ view fn assets(AccountId account) authorize(anyone) -> QueryPage<AssetView> {{ ledger::query::assets_of({args}) }} }}"
        );
        assert!(Compiler::new().compile_source(&source).is_err(), "{args}");
    }
}

#[test]
fn tuple_state_keys_emit_exact_cursor_and_dynamic_access_schemas() {
    use ivm_abi::entrypoint::EntrypointValueTypeNodeV1 as Node;
    let source = r#"seiyaku TupleSchema {
        state StateMap<(int, (Name, bool)), quantity> balances;
        view fn page(Option<StateCursor<(int, (Name, bool))>> after) authorize(anyone) -> StatePage<(int, (Name, bool)), quantity, 2> {
            balances.page(after: after, limit: 2)
        }
    }"#;
    let (artifact, manifest) = Compiler::new()
        .compile_source_with_manifest(source)
        .unwrap();
    let parsed = ProgramMetadata::parse(&artifact).unwrap();
    let interface = parsed.contract_interface.unwrap();
    let schema = interface.entrypoints[0].argument_schema.as_ref().unwrap();
    let Node::StateCursor(key) = &schema.fields[0].ty.nodes[1] else {
        panic!("cursor key schema");
    };
    assert_eq!(
        key.canonical_type_name().as_deref(),
        Some("(int, (Name, bool))")
    );
    let hints = manifest.access_set_hints.unwrap();
    assert_eq!(hints.dynamic_reads[0].key_type, "(int, (Name, bool))");
}
#[test]
fn tuple_state_keys_reject_unsupported_leaves_and_mismatched_cursor_layouts() {
    for key in [
        "(int, Json)",
        "(int, Option<int>)",
        "(int, List<int, 2>)",
        "(int, StateCursor<int>)",
        "(int, ())",
    ] {
        let source = format!(
            "seiyaku InvalidKey {{ state StateMap<{key}, int> values; view fn read() authorize(anyone) {{ () }} }}"
        );
        let error = Compiler::new().compile_source(&source).unwrap_err();
        assert!(error.contains("StateMap key type"), "{key}: {error}");
    }
    let source = "seiyaku WrongCursor { state StateMap<(int, Name), int> values; view fn page(Option<StateCursor<(Name, int)>> after) authorize(anyone) { let _ = values.page(after: after, limit: 1); } }";
    let error = Compiler::new().compile_source(source).unwrap_err();
    assert!(error.contains("StateCursor"), "{error}");
}

#[test]
fn literal_scalar_and_tuple_map_keys_keep_exact_canonical_child_hints() {
    use ivm_abi::state_value::{
        StateValueAtomV1 as Atom, StateValueKindV1 as Kind, StateValueNodeV1 as Node,
        StateValueRecordV1, StateValueSchemaV1, state_value_schema_hash_v1,
    };
    let output = Compiler::new().compile_source_output(r#"seiyaku ConstantKeys {
        state StateMap<int, int> Singles;
        state StateMap<(int, bool), int> Pairs;
        view fn known() authorize(anyone) -> bool { Singles.contains(1) && Pairs.contains((1, true)) }
        view fn dynamic(int key) authorize(anyone) -> bool { Singles.contains(key) }
    }"#, None).expect("compile canonical literal keys");
    let known = output
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "known")
        .unwrap();
    let schema = StateValueSchemaV1 {
        nodes: vec![
            Node::Tuple { arity: 2 },
            Node::Leaf(Kind::Int),
            Node::Leaf(Kind::Bool),
        ],
    };
    let record = StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(
            &ivm_abi::codec::encode_canonical_norito(&schema).unwrap(),
        ),
        atoms: vec![
            Atom::Pointer(
                super::encode_pointer_tlv_bytes(ir::DataRefKind::Int, "1", false).unwrap(),
            ),
            Atom::Bool(true),
        ],
    };
    let pair_key = format!(
        "state:Pairs/{}",
        hex::encode(ivm_abi::codec::encode_canonical_norito(&record).unwrap())
    );
    assert_eq!(known.access_hints_complete, Some(true));
    assert!(known.read_keys.contains(&canonical_numeric_state_key(
        "Singles",
        ir::DataRefKind::Int,
        "1"
    )));
    assert!(known.read_keys.contains(&pair_key));
    // The folded record load still belongs to the source operation; it must
    // never become an unassigned generated-code gap in statement traces.
    let parsed = ProgramMetadata::parse(&output.artifact).unwrap();
    let directory = ivm_abi::metadata::LiteralDirectory::validate(
        &output.artifact,
        parsed.header_len,
        parsed.literal_section,
        ivm_abi::SyscallPolicy::AbiV1,
    )
    .unwrap();
    let encoded_record = ivm_abi::codec::encode_canonical_norito(&record).unwrap();
    let literal_index = (0..parsed.literal_section.unwrap().count).find(|index| {
        matches!(directory.get(*index), Some(ivm_abi::metadata::ValidatedLiteral::Pointer { type_id: PointerType::NoritoBytes, payload, .. }) if payload == encoded_record)
    }).expect("literal tuple key record");
    let positions = output.artifact[parsed.code_offset..]
        .chunks_exact(4)
        .enumerate()
        .filter_map(|(index, bytes)| {
            let word = u32::from_le_bytes(bytes.try_into().unwrap());
            (instruction::wide::opcode(word) == instruction::wide::memory::LDLIT
                && instruction::wide::literal_index(word) == literal_index)
                .then_some(index as u64 * 4)
        })
        .collect::<Vec<_>>();
    assert!(
        !positions.is_empty(),
        "the canonical record must be loaded by the folded key operation"
    );
    for pc in positions {
        assert!(
            output
                .report
                .statement_map
                .iter()
                .any(|entry| entry.pc_start <= pc
                    && pc < entry.pc_end
                    && entry.function_name == "known"
                    && entry.source.line == 4),
            "folded key load at {pc} lost its source statement"
        );
    }
    let dynamic = output
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "dynamic")
        .unwrap();
    assert_eq!(dynamic.access_hints_complete, Some(false));
    assert!(!dynamic.access_hints_skipped.is_empty());
}
