//! Same-compiler register-policy comparison without altering source validation or call ABI.

use crate::{
    compiler::CompilerOptions,
    instruction,
    ir::{DataRefKind, Instr, Temp},
    metadata::ProgramMetadata,
    regalloc::with_conservative_host_operands,
    session::{CompileOutput, CompileRequest, CompilerSession},
};

fn compile(source: &str, conservative: bool) -> CompileOutput {
    crate::session::run_with_compiler_stack(|| {
        let build = || {
            CompilerSession::new(CompilerOptions::default())
                .build(CompileRequest {
                    source,
                    source_name: Some("dead_operands.ko"),
                })
                .expect("canonical typing, SSA, codegen, literal and call-table validation")
        };
        if conservative {
            with_conservative_host_operands(build)
        } else {
            build()
        }
    })
    .expect("existing compiler worker")
}
fn memory_words(output: &CompileOutput) -> usize {
    let offset = ProgramMetadata::parse(&output.artifact)
        .unwrap()
        .code_offset;
    output.artifact[offset..]
        .chunks_exact(4)
        .filter(|bytes| {
            matches!(
                instruction::wide::opcode(u32::from_le_bytes((*bytes).try_into().unwrap())),
                instruction::wide::memory::LOAD64 | instruction::wide::memory::STORE64
            )
        })
        .count()
}
fn frame_bytes(output: &CompileOutput) -> usize {
    output
        .report
        .budget_report
        .iter()
        .map(|function| usize::try_from(function.frame_bytes).unwrap())
        .sum()
}
fn assert_exact_tables(before: &CompileOutput, after: &CompileOutput) {
    super::rematerialized::assert_same_semantic_metadata(before, after);
    assert_eq!(
        before.contract_interface.callables.len(),
        after.contract_interface.callables.len()
    );
    for output in [before, after] {
        for function in &output.report.budget_report {
            let callable = output
                .contract_interface
                .callables
                .iter()
                .find(|callable| callable.entry_pc == function.pc_start)
                .unwrap();
            assert!(callable.validate());
            assert_eq!(callable.frame_bytes, function.frame_bytes);
            assert_eq!(callable.frame_bytes % 16, 0);
        }
    }
}

#[test]
fn dead_numeric_operands_reduce_real_saves_and_keep_authenticated_tables() {
    let source = r#"seiyaku DeadOperands {
        fn difference(int left, int right) -> int { return left - right; }
        view fn main(int left, int right) authorize(anyone) -> int { return difference(left: left, right: right); }
    }"#;
    let before = compile(source, true);
    let after = compile(source, false);
    assert_exact_tables(&before, &after);
    assert!(after.artifact.len() < before.artifact.len());
    assert!(memory_words(&after) < memory_words(&before));
    assert!(frame_bytes(&after) < frame_bytes(&before));
    assert_eq!(after.artifact, compile(source, false).artifact);
}

#[test]
fn canonical_dlmm_dead_operands_measure_actual_frame_and_byte_savings() {
    let source = include_str!("../../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    assert_exact_tables(&before, &after);
    assert!(after.artifact.len() < before.artifact.len());
    assert!(memory_words(&after) < memory_words(&before));
    assert!(frame_bytes(&after) < frame_bytes(&before));
    eprintln!(
        "canonical DLMM dead operands: baseline_bytes={} optimized_bytes={} saved_bytes={} baseline_code_bytes={} optimized_code_bytes={} baseline_memory_words={} optimized_memory_words={} baseline_frame_bytes={} optimized_frame_bytes={} baseline_hash={} optimized_hash={}",
        before.artifact.len(),
        after.artifact.len(),
        before.artifact.len() - after.artifact.len(),
        before.artifact.len()
            - ProgramMetadata::parse(&before.artifact)
                .unwrap()
                .code_offset,
        after.artifact.len() - ProgramMetadata::parse(&after.artifact).unwrap().code_offset,
        memory_words(&before),
        memory_words(&after),
        frame_bytes(&before),
        frame_bytes(&after),
        before.report.artifact_hash,
        after.report.artifact_hash,
    );
    // This reports actual emitted savings only. The unchanged default 4M payout
    // policy still requires measured Core execution and monetary qualification.
}

#[test]
fn dead_operand_eligibility_preserves_unused_literal_and_state_path_errors() {
    let cases: [fn() -> Vec<Instr>; 3] = [
        || {
            vec![Instr::DataRef {
                dest: Temp(770),
                kind: DataRefKind::Int,
                value: "not-int".into(),
            }]
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
            with_conservative_host_operands(|| super::compile_with_injected_ir(instructions()))
        })
        .unwrap()
        .expect_err("original complete validation rejects malformed input");
        let after = crate::session::run_with_compiler_stack(|| {
            super::compile_with_injected_ir(instructions())
        })
        .unwrap()
        .expect_err("register eligibility cannot remove validation");
        assert_eq!(before, after);
    }
}
