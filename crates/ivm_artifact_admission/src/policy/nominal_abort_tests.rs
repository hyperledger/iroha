//! Closed terminal-abort ownership, original security mutations and complete artifact controls.

use super::*;
use ivm_abi::{encoding::wide as enc, instruction::wide, syscalls};
#[path = "../../../../fixtures/kotodama/compact_emission/cases.rs"]
mod cases;

fn abort_tail() -> [u32; 6] {
    [
        enc::encode_sys(
            wide::system::SCALL,
            syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
        ),
        enc::encode_ri(wide::arithmetic::ADDI, 12, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 13, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 14, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 15, 0, 0),
        enc::encode_sys(wide::system::SCALL, syscalls::SYSCALL_CONTRACT_ABORT as u8),
    ]
}
fn ops(words: &[u32]) -> Vec<DecodedOp> {
    words
        .iter()
        .enumerate()
        .map(|(index, &inst)| DecodedOp {
            pc: (index as u64) * 4,
            inst,
        })
        .collect()
}
fn shared_words() -> Vec<u32> {
    [
        enc::encode_jump(wide::control::JAL, 0, 2),
        enc::encode_jump(wide::control::JAL, 0, 1),
    ]
    .into_iter()
    .chain(abort_tail())
    .collect()
}
fn graph_roots(decoded: &[DecodedOp], entries: &BTreeSet<u64>) -> BTreeSet<u64> {
    let mut roots = entries.clone();
    roots.extend(
        decoded
            .iter()
            .filter(|op| is_direct_call(op))
            .map(|op| direct_control_flow_target(op).unwrap()),
    );
    roots
}
fn proven(decoded: &[DecodedOp], entries: &BTreeSet<u64>) -> BTreeSet<u64> {
    let instructions = decoded.iter().map(|op| (op.pc, op)).collect();
    shared_nominal_abort_tail_pcs(decoded, &instructions, &graph_roots(decoded, entries))
}
fn assert_shared_refusal(words: &[u32], roots: &BTreeSet<u64>) {
    let decoded = ops(words);
    assert!(
        proven(&decoded, roots).is_empty(),
        "mutation must not acquire a shared suffix proof"
    );
    let error = validate_nonrecursive_direct_calls(&decoded, roots)
        .expect_err("original ownership rule rejects unproven sharing");
    assert!(
        error.to_string().contains("ordinary control flow"),
        "original ownership failure retained: {error}"
    );
}

#[test]
fn exact_terminal_abort_suffix_alone_may_be_shared_without_call_or_return() {
    let decoded = ops(&shared_words());
    let roots = BTreeSet::from([0, 4]);
    assert_eq!(
        proven(&decoded, &roots),
        BTreeSet::from([8, 12, 16, 20, 24, 28])
    );
    validate_bytecode_security(&decoded, false, ValidationProfile::Production).unwrap();
    validate_nonrecursive_direct_calls(&decoded, &roots).unwrap();
    for root in roots {
        let reach = reachable_syscalls(&decoded, root, "source").unwrap();
        assert_eq!(
            reach.syscalls,
            BTreeSet::from([
                syscalls::SYSCALL_INPUT_PUBLISH_TLV,
                syscalls::SYSCALL_CONTRACT_ABORT
            ])
        );
        assert_eq!(reach.pcs, BTreeSet::from([root, 8, 12, 16, 20, 24, 28]));
    }
}

#[test]
fn shared_abort_suffix_rejects_every_substituted_word_effect_return_and_reserved_input() {
    let roots = BTreeSet::from([0, 4]);
    let words = shared_words();
    for index in 2..words.len() {
        let mut mutated = words.clone();
        mutated[index] ^= 1;
        assert_shared_refusal(&mutated, &roots);
    }
    for replacement in [
        enc::encode_sys(wide::system::SCALL, syscalls::SYSCALL_STATE_SET as u8),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 12, 1, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 13, 0, 0),
    ] {
        let mut mutated = words.clone();
        mutated[3] = replacement;
        assert_shared_refusal(&mutated, &roots);
    }
    let mut noncanonical_publish = words.clone();
    noncanonical_publish[2] |= 0x100;
    assert_shared_refusal(&noncanonical_publish, &roots);
    let mut substituted_terminal = words.clone();
    substituted_terminal[7] = enc::encode_syscallx(syscalls::SYSCALL_CONTRACT_ABORT);
    assert_shared_refusal(&substituted_terminal, &roots);
    let mut inserted_effect = words.clone();
    inserted_effect.insert(
        2,
        enc::encode_sys(wide::system::SCALL, syscalls::SYSCALL_STATE_SET as u8),
    );
    assert_shared_refusal(&inserted_effect, &roots);
}

#[test]
fn shared_abort_suffix_rejects_middle_targets_and_any_callable_root() {
    let roots = BTreeSet::from([0, 4]);
    for offset in 1..6 {
        let mut words = shared_words();
        words[1] = enc::encode_jump(wide::control::JAL, 0, 1 + offset);
        assert_shared_refusal(&words, &roots);
    }
    for pc in [8, 12, 16, 20, 24, 28] {
        let mut additional = roots.clone();
        additional.insert(pc);
        assert_shared_refusal(&shared_words(), &additional);
    }
    let words = [
        enc::encode_jump(wide::control::JAL, 1, 4),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
        enc::encode_jump(wide::control::JAL, 0, 2),
        enc::encode_halt(),
    ]
    .into_iter()
    .chain(abort_tail())
    .collect::<Vec<_>>();
    assert_shared_refusal(&words, &BTreeSet::from([0, 8]));
}

#[test]
fn shared_abort_suffix_rejects_conditional_entry_fallthrough_and_arbitrary_body_sharing() {
    let roots = BTreeSet::from([0, 4]);
    for replacement in [
        enc::encode_rr(wide::control::BEQ, 0, 0, 1),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 0, 0),
    ] {
        let mut words = shared_words();
        words[1] = replacement;
        assert_shared_refusal(&words, &roots);
    }
    let words = [
        enc::encode_jump(wide::control::JAL, 0, 2),
        enc::encode_jump(wide::control::JAL, 0, 1),
        enc::encode_ri(wide::arithmetic::ADDI, 10, 0, 0),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
    ];
    assert_shared_refusal(&words, &roots);
}

#[test]
fn terminal_abort_suffix_does_not_relax_original_direct_recursion_or_unknown_syscall_security() {
    let words = [
        enc::encode_jump(wide::control::JAL, 1, 0),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
        enc::encode_jump(wide::control::JAL, 0, 2),
        enc::encode_halt(),
    ]
    .into_iter()
    .chain(abort_tail())
    .collect::<Vec<_>>();
    let decoded = ops(&words);
    let roots = BTreeSet::from([0, 8]);
    assert!(!proven(&decoded, &roots).is_empty());
    let error = validate_nonrecursive_direct_calls(&decoded, &roots).unwrap_err();
    assert!(error.to_string().contains("recursive direct-call cycle"));
    let unknown = ops(&[
        enc::encode_sys(wide::system::SCALL, syscalls::SYSCALL_CONTRACT_ABORT as u8),
        enc::encode_syscallx(0x00ff_ffff),
    ]);
    assert_eq!(
        reachable_syscalls(&unknown, 0, "source").unwrap().pcs,
        BTreeSet::from([0])
    );
    assert!(
        validate_bytecode_security(&unknown, false, ValidationProfile::Production)
            .unwrap_err()
            .to_string()
            .contains("disallowed syscall")
    );
}

#[test]
fn terminal_abort_reachability_keeps_prior_effects_and_stops_before_following_entrypoint() {
    let abort = enc::encode_sys(wide::system::SCALL, syscalls::SYSCALL_CONTRACT_ABORT as u8);
    let write = enc::encode_sys(wide::system::SCALL, syscalls::SYSCALL_STATE_SET as u8);
    let after = ops(&[abort, write, enc::encode_halt()]);
    let reach = reachable_syscalls(&after, 0, "source").unwrap();
    assert_eq!(reach.pcs, BTreeSet::from([0]));
    assert_eq!(
        reach.syscalls,
        BTreeSet::from([syscalls::SYSCALL_CONTRACT_ABORT])
    );
    validate_view_effects("source", &reach.syscalls).unwrap();
    validate_bytecode_security(&after, false, ValidationProfile::Production).unwrap();
    validate_nonrecursive_direct_calls(&after, &BTreeSet::from([0, 4])).unwrap();
    let before = ops(&[write, abort, enc::encode_halt()]);
    let reach = reachable_syscalls(&before, 0, "source").unwrap();
    assert_eq!(reach.pcs, BTreeSet::from([0, 4]));
    assert!(validate_view_effects("source", &reach.syscalls).is_err());
}

#[test]
fn genuine_complete_scalar_and_compact_artifacts_both_pass_canonical_admission_with_original_roles()
{
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pairs = cases::load_pairs(&root);
    for case in cases::CASES {
        let pair = &pairs[case.id];
        let before = crate::verify_contract_artifact(&pair.before)
            .unwrap_or_else(|error| panic!("complete genuine scalar {}: {error}", case.id));
        let after = crate::verify_contract_artifact(&pair.after)
            .unwrap_or_else(|error| panic!("complete genuine compact {}: {error}", case.id));
        let metadata_values = |metadata: &ProgramMetadata| {
            (
                metadata.version_major,
                metadata.version_minor,
                metadata.mode,
                metadata.vector_length,
                metadata.max_cycles,
                metadata.abi_version,
            )
        };
        assert_eq!(
            metadata_values(&before.metadata),
            metadata_values(&after.metadata)
        );
        assert_eq!(before.abi_hash, after.abi_hash);
        assert_eq!(
            before.contract_interface.error_types,
            after.contract_interface.error_types
        );
        assert_eq!(
            before.contract_interface.error_messages,
            after.contract_interface.error_messages
        );
        assert_eq!(
            before
                .contract_interface
                .entrypoints
                .iter()
                .map(EmbeddedEntrypointDescriptor::to_manifest_descriptor)
                .collect::<Vec<_>>(),
            after
                .contract_interface
                .entrypoints
                .iter()
                .map(EmbeddedEntrypointDescriptor::to_manifest_descriptor)
                .collect::<Vec<_>>()
        );
        let callable_roles = |interface: &EmbeddedContractInterfaceV1| {
            interface
                .callables
                .iter()
                .map(|callable| {
                    (
                        callable.frame_bytes,
                        callable.arguments.clone(),
                        callable.results.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            callable_roles(&before.contract_interface),
            callable_roles(&after.contract_interface)
        );
        let main = after
            .contract_interface
            .entrypoints
            .iter()
            .find(|entry| entry.name == "main")
            .unwrap();
        match case.outcome {
            cases::Outcome::Success(words) => assert_eq!(
                main.return_schema.as_ref().unwrap().word_count(),
                Some(words.len())
            ),
            cases::Outcome::Abort { code, name } => assert!(
                after
                    .contract_interface
                    .error_types
                    .iter()
                    .any(|descriptor| descriptor
                        .variant(code)
                        .is_some_and(|variant| variant.name == name))
            ),
            cases::Outcome::Permission => {
                assert_eq!(main.authorization, iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission("ManageRoles".parse().unwrap()))
            }
            cases::Outcome::DivisionByZero | cases::Outcome::InvalidScale => assert!(
                after
                    .contract_interface
                    .error_types
                    .iter()
                    .any(|descriptor| descriptor.identity == "kotodama::NumericError")
            ),
        }
        if case.trace.is_some() {
            assert!(
                after
                    .contract_interface
                    .states
                    .iter()
                    .any(|state| state.name == "trace")
            );
        }
    }
}

#[test]
fn current_compiler_complete_cross_function_nominal_abort_artifact_is_admissible() {
    use kotodama_lang::session::{CompileRequest, CompilerSession};
    let source = include_str!("../../../../fixtures/kotodama/compact_emission/abort_second.ko");
    let output = CompilerSession::default()
        .build(CompileRequest {
            source,
            source_name: Some("compact_emission.ko"),
        })
        .expect("complete current canonical compiler artifact");
    let verified = crate::verify_contract_artifact(&output.artifact).expect("complete current artifact admission, including exact literals, callables and entrypoint authorization");
    let decoded =
        crate::decode_instruction_stream(&output.artifact[verified.code_offset..]).unwrap();
    let roots = verified
        .contract_interface
        .entrypoints
        .iter()
        .map(|entry| entry.entry_pc)
        .collect();
    let tail = proven(&decoded, &roots);
    assert_eq!(tail.len(), 6);
    let start = *tail.first().unwrap();
    assert!(
        decoded
            .iter()
            .filter(|op| direct_control_flow_target(op) == Some(start))
            .count()
            >= 2
    );
    let main = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .unwrap();
    let hajimari = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "hajimari")
        .unwrap();
    let reach = reachable_syscalls(&decoded, main.entry_pc, "main").unwrap();
    assert!(tail.is_subset(&reach.pcs));
    assert!(!reach.pcs.contains(&hajimari.entry_pc));
    let owners = output
        .report
        .budget_report
        .iter()
        .filter(|function| function.pc_start <= start && *tail.last().unwrap() < function.pc_end)
        .collect::<Vec<_>>();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].function_name, "guarded");
}

#[test]
fn complete_shared_abort_artifact_retains_dispatch_authorization_and_entrypoint_isolation() {
    let source = include_str!("../../../../fixtures/kotodama/compact_emission/abort_second.ko");
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .unwrap();
    let parsed = ProgramMetadata::parse(&artifact).unwrap();
    let decoded = crate::decode_instruction_stream(&artifact[parsed.code_offset..]).unwrap();
    let interface = parsed.contract_interface.unwrap();
    validate_contract_interface(
        &parsed.metadata,
        &interface,
        &decoded,
        ValidationProfile::Production,
    )
    .unwrap();
    let main = interface
        .entrypoints
        .iter()
        .position(|entry| entry.name == "main")
        .unwrap();
    let hajimari = interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "hajimari")
        .unwrap()
        .entry_pc;
    let mut unauthenticated = interface.clone();
    unauthenticated.entrypoints[main].authorization =
        iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
            "Undeclared".parse().unwrap(),
        );
    assert!(
        validate_contract_interface(
            &parsed.metadata,
            &unauthenticated,
            &decoded,
            ValidationProfile::Production
        )
        .unwrap_err()
        .to_string()
        .contains("must use explicit declared authorization")
    );
    let mut view = interface.clone();
    view.entrypoints[main].kind = EntryPointKind::View;
    assert!(
        validate_contract_interface(
            &parsed.metadata,
            &view,
            &decoded,
            ValidationProfile::Production
        )
        .unwrap_err()
        .to_string()
        .contains("effectful syscall")
    );
    let main_pc = interface.entrypoints[main].entry_pc;
    let mut bypass = decoded.clone();
    let index = bypass.iter().position(|op| op.pc == main_pc).unwrap();
    let offset = i16::try_from((i128::from(hajimari) - i128::from(main_pc)) / 4).unwrap();
    bypass[index].inst = enc::encode_jump(wide::control::JAL, 0, offset);
    assert!(
        validate_contract_interface(
            &parsed.metadata,
            &interface,
            &bypass,
            ValidationProfile::Production
        )
        .is_err()
    );
    let roots = interface
        .entrypoints
        .iter()
        .map(|entry| entry.entry_pc)
        .collect();
    let start = *proven(&decoded, &roots).first().unwrap();
    let mut exported_tail = interface;
    exported_tail.entrypoints[main].entry_pc = start;
    assert!(
        validate_contract_interface(
            &parsed.metadata,
            &exported_tail,
            &decoded,
            ValidationProfile::Production
        )
        .is_err()
    );
}
