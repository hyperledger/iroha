//! Same-compiler artifact, metadata and rejection controls for borrowed state operands.

use crate::{
    compiler::{CompilerOptions, state_operands::with_publication},
    encoding, instruction,
    ir::{DataRefKind, Instr, Temp},
    metadata::ProgramMetadata,
    session::{CompileOutput, CompileRequest, CompilerSession},
};
use ivm_abi::syscalls;

const SOURCE: &str = r#"seiyaku StateOperands { permission WriteState;
    state int Counter;
    state StateMap<Name, int> Values;
    hajimari() {
        Counter = 0;
    }
    fn update(Name key, int amount) -> int {
        Values[key] = Values.get(key).unwrap_or(0) + amount;
        Counter = Counter + amount;
        return Values.get(key).unwrap_or(0) + Counter;
    }
    kotoage fn run() authorize(WriteState) -> int {
        Counter = 0;
        return update(key: Name::parse("alice"), amount: 3);
    }
}"#;

fn compile(source: &str, retain_publication: bool) -> CompileOutput {
    crate::session::run_with_compiler_stack(|| {
        // Isolate this publication experiment from the independent register-policy
        // optimization; both sides keep their original exact frame geometry.
        let build = || {
            crate::regalloc::with_conservative_host_operands(|| {
                CompilerSession::new(CompilerOptions::default())
                    .build(CompileRequest {
                        source,
                        source_name: Some("state_operands.ko"),
                    })
                    .expect("canonical typing, SSA, literal and codegen validation")
            })
        };
        if retain_publication {
            with_publication(build)
        } else {
            build()
        }
    })
    .unwrap()
}

fn publication_words(output: &CompileOutput) -> usize {
    let offset = ProgramMetadata::parse(&output.artifact)
        .unwrap()
        .code_offset;
    let publish = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
    );
    output.artifact[offset..]
        .chunks_exact(4)
        .filter(|word| u32::from_le_bytes((*word).try_into().unwrap()) == publish)
        .count()
}

fn same_tables_and_frames(before: &CompileOutput, after: &CompileOutput) {
    super::rematerialized::assert_same_semantic_metadata(before, after);
    let frames = |output: &CompileOutput| {
        output
            .report
            .budget_report
            .iter()
            .map(|function| (function.function_name.clone(), function.frame_bytes))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        frames(before),
        frames(after),
        "all original authenticated frames remain exact"
    );
}

#[test]
fn borrowed_state_operands_preserve_all_call_tables_interfaces_and_frames() {
    let before = compile(SOURCE, true);
    let after = compile(SOURCE, false);
    same_tables_and_frames(&before, &after);
    assert!(publication_words(&before) >= 12);
    assert_eq!(publication_words(&after), 0);
    assert!(before.artifact.len() - after.artifact.len() >= 100);
    assert_eq!(compile(SOURCE, false).artifact, after.artifact);
}

#[test]
fn borrowed_state_operands_preserve_original_literal_and_path_rejections() {
    let cases: [fn() -> Vec<Instr>; 4] = [
        || {
            vec![
                Instr::DataRef {
                    dest: Temp(770),
                    kind: DataRefKind::Int,
                    value: "bad-int".into(),
                },
                Instr::PointerToNorito {
                    dest: Temp(771),
                    value: Temp(770),
                },
            ]
        },
        || {
            vec![
                Instr::DataRef {
                    dest: Temp(770),
                    kind: DataRefKind::Name,
                    value: "bad name".into(),
                },
                Instr::DataRef {
                    dest: Temp(771),
                    kind: DataRefKind::NoritoBytes,
                    value: "0x00".into(),
                },
                Instr::PathMapKeyNorito {
                    dest: Temp(772),
                    base: Temp(770),
                    key_blob: Temp(771),
                },
            ]
        },
        || {
            vec![
                Instr::DataRef {
                    dest: Temp(770),
                    kind: DataRefKind::NoritoBytes,
                    value: "0x00".into(),
                },
                Instr::StateGet {
                    dest: Temp(771),
                    path: Temp(770),
                },
            ]
        },
        || {
            vec![
                Instr::DataRef {
                    dest: Temp(770),
                    kind: DataRefKind::Name,
                    value: "counter".into(),
                },
                Instr::DataRef {
                    dest: Temp(771),
                    kind: DataRefKind::NoritoBytes,
                    value: "0x00".into(),
                },
                Instr::StateSet {
                    path: Temp(770),
                    value: Temp(771),
                },
            ]
        },
    ];
    for instructions in cases {
        let before = crate::session::run_with_compiler_stack(|| {
            with_publication(|| super::compile_with_injected_ir(instructions()))
        })
        .unwrap()
        .expect_err("original compiler rejects invalid typed literal/path");
        let after = crate::session::run_with_compiler_stack(|| {
            super::compile_with_injected_ir(instructions())
        })
        .unwrap()
        .expect_err("borrowed lowering retains original rejection");
        assert_eq!(before, after);
    }
}

#[test]
fn canonical_dlmm_borrowed_state_operands_measure_material_byte_reduction() {
    let source = include_str!("../../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    same_tables_and_frames(&before, &after);
    let savings = before.artifact.len() - after.artifact.len();
    assert!(
        savings >= 4_000,
        "measured state/path owner must materially shrink: {savings}"
    );
    assert!(publication_words(&after) < publication_words(&before));
    eprintln!(
        "canonical DLMM borrowed state operands: baseline_bytes={} optimized_bytes={} saved_bytes={} baseline_code_bytes={} optimized_code_bytes={} baseline_publish={} optimized_publish={} baseline_hash={} optimized_hash={}",
        before.artifact.len(),
        after.artifact.len(),
        savings,
        before.artifact.len()
            - ProgramMetadata::parse(&before.artifact)
                .unwrap()
                .code_offset,
        after.artifact.len() - ProgramMetadata::parse(&after.artifact).unwrap().code_offset,
        publication_words(&before),
        publication_words(&after),
        before.report.artifact_hash,
        after.report.artifact_hash
    );
    // Actual payout/rounding runtime and the unchanged default 4M policy remain separate gates.
}

#[test]
fn state_operand_baseline_scope_retires_after_unwind() {
    assert!(!crate::compiler::state_operands::retain_publication());
    let failure = std::panic::catch_unwind(|| {
        with_publication(|| {
            assert!(crate::compiler::state_operands::retain_publication());
            panic!("intentional state-lowering baseline unwind");
        })
    });
    assert!(failure.is_err());
    assert!(!crate::compiler::state_operands::retain_publication());
    assert_eq!(publication_words(&compile(SOURCE, false)), 0);
}
