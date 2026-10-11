//! Same-compiler bytecode and canonical-boundary controls for borrowed numeric operands.

use crate::{
    ast::BinaryOp,
    compiler::{CompilerOptions, numeric_operands::with_publication},
    encoding, instruction,
    ir::{DataRefKind, Instr, Temp, WideNumericKind},
    metadata::ProgramMetadata,
    session::{CompileOutput, CompileRequest, CompilerSession},
};
use ivm_abi::syscalls;

const SOURCE: &str = r#"seiyaku NumericOperands {
    fn arithmetic(int left, int right) -> int {
        if (left < right) { return (left + right) * (right - left); }
        return (left - right) + (left * right);
    }
    view fn run(int left, int right) authorize(anyone) -> int { return arithmetic(left, right); }
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
                        source_name: Some("numeric_operands.ko"),
                    })
                    .expect("canonical source, typing, SSA and codegen validation")
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
    let start = ProgramMetadata::parse(&output.artifact)
        .unwrap()
        .code_offset;
    let publication = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
    );
    output.artifact[start..]
        .chunks_exact(4)
        .filter(|word| u32::from_le_bytes((*word).try_into().unwrap()) == publication)
        .count()
}

#[test]
fn numeric_operands_reduce_real_marshalling_without_removing_typed_calls() {
    let baseline = compile(SOURCE, true);
    let optimized = compile(SOURCE, false);
    super::rematerialized::assert_same_semantic_metadata(&baseline, &optimized);
    assert!(publication_words(&baseline) >= 10);
    assert_eq!(publication_words(&optimized), 0);
    assert!(baseline.artifact.len() - optimized.artifact.len() >= 100);
    assert_eq!(compile(SOURCE, false).artifact, optimized.artifact);
    let baseline_functions = baseline
        .report
        .budget_report
        .iter()
        .map(|f| (&f.function_name, f.frame_bytes))
        .collect::<Vec<_>>();
    let optimized_functions = optimized
        .report
        .budget_report
        .iter()
        .map(|f| (&f.function_name, f.frame_bytes))
        .collect::<Vec<_>>();
    assert_eq!(
        baseline_functions, optimized_functions,
        "original argument/result tables and authenticated call frames remain"
    );
}

#[test]
fn borrowed_numeric_operands_preserve_invalid_literal_rejections_in_both_positions() {
    for (kind, numeric, invalid) in [
        (DataRefKind::Int, WideNumericKind::Int, "bad-int"),
        (
            DataRefKind::Decimal,
            WideNumericKind::Decimal,
            "bad-decimal",
        ),
        (
            DataRefKind::Quantity,
            WideNumericKind::Quantity,
            "bad-quantity",
        ),
    ] {
        for invalid_left in [false, true] {
            for compare in [false, true] {
                let make = || {
                    vec![
                        Instr::DataRef {
                            dest: Temp(770),
                            kind,
                            value: if invalid_left { invalid } else { "1" }.into(),
                        },
                        Instr::DataRef {
                            dest: Temp(771),
                            kind,
                            value: if invalid_left { "1" } else { invalid }.into(),
                        },
                        if compare {
                            Instr::NumericCompare {
                                dest: Temp(772),
                                op: BinaryOp::Lt,
                                left: Temp(770),
                                right: Temp(771),
                                kind: numeric,
                            }
                        } else {
                            Instr::NumericBinary {
                                dest: Temp(772),
                                op: BinaryOp::Add,
                                left: Temp(770),
                                right: Temp(771),
                                left_kind: numeric,
                                right_kind: numeric,
                                result_kind: numeric,
                            }
                        },
                    ]
                };
                let baseline = crate::session::run_with_compiler_stack(|| {
                    with_publication(|| super::compile_with_injected_ir(make()))
                })
                .unwrap()
                .expect_err("original codegen rejects malformed canonical literal");
                let optimized = crate::session::run_with_compiler_stack(|| {
                    super::compile_with_injected_ir(make())
                })
                .unwrap()
                .expect_err("borrowed lowering retains original literal validator");
                assert_eq!(optimized, baseline);
            }
        }
    }
}

#[test]
fn canonical_dlmm_borrowed_numeric_operands_measure_material_byte_reduction() {
    let source = include_str!("../../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let baseline = compile(source, true);
    let optimized = compile(source, false);
    super::rematerialized::assert_same_semantic_metadata(&baseline, &optimized);
    let before = ProgramMetadata::parse(&baseline.artifact).unwrap();
    let after = ProgramMetadata::parse(&optimized.artifact).unwrap();
    let savings = baseline.artifact.len() - optimized.artifact.len();
    assert!(
        savings >= 3_000,
        "the measured dominant operand marshalling must actually shrink: {savings}"
    );
    assert!(publication_words(&optimized) < publication_words(&baseline));
    eprintln!(
        "canonical DLMM borrowed numeric operands: baseline_bytes={} optimized_bytes={} saved_bytes={} baseline_code_bytes={} optimized_code_bytes={} baseline_publish={} optimized_publish={} baseline_hash={} optimized_hash={}",
        baseline.artifact.len(),
        optimized.artifact.len(),
        savings,
        baseline.artifact.len() - before.code_offset,
        optimized.artifact.len() - after.code_offset,
        publication_words(&baseline),
        publication_words(&optimized),
        baseline.report.artifact_hash,
        optimized.report.artifact_hash
    );
    // Actual payout/rounding runtime and the unchanged default-4M policy remain
    // independent gates; this measurement does not assert release qualification.
}

#[test]
fn numeric_operand_baseline_scope_retires_after_unwind() {
    assert!(!crate::compiler::numeric_operands::retain_publication());
    let failure = std::panic::catch_unwind(|| {
        with_publication(|| {
            assert!(crate::compiler::numeric_operands::retain_publication());
            panic!("intentional numeric-lowering baseline unwind");
        })
    });
    assert!(failure.is_err());
    assert!(!crate::compiler::numeric_operands::retain_publication());
    let output = compile(SOURCE, false);
    assert_eq!(publication_words(&output), 0);
}
