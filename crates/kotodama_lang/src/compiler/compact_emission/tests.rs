//! Exact terminal ownership, metadata, scalar comparison and measured artifact controls.

use super::*;
use crate::session::{CompileOutput, CompileRequest, CompilerSession};

pub(super) fn compile(source: &str, scalar: bool) -> CompileOutput {
    crate::session::run_with_compiler_stack(|| {
        let build = || {
            CompilerSession::default()
                .build(CompileRequest {
                    source,
                    source_name: Some("compact_emission.ko"),
                })
                .expect("complete canonical source, SSA, literal and artifact validation")
        };
        if scalar {
            with_scalar_emission(build)
        } else {
            build()
        }
    })
    .expect("original canonical compiler worker")
}
pub(super) fn assert_metadata(before: &CompileOutput, after: &CompileOutput) {
    super::super::single_use_private::assert_public_metadata(before, after);
    let geometry = |output: &CompileOutput| {
        output
            .report
            .budget_report
            .iter()
            .map(|function| {
                let callable = output
                    .contract_interface
                    .callables
                    .iter()
                    .find(|callable| callable.entry_pc == function.pc_start)
                    .unwrap();
                (
                    function.function_name.clone(),
                    (
                        function.frame_bytes,
                        callable.arguments.clone(),
                        callable.results.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(
        before.report.budget_report.len(),
        after.report.budget_report.len()
    );
    assert_eq!(
        before.contract_interface.callables.len(),
        after.contract_interface.callables.len()
    );
    assert_eq!(
        geometry(before),
        geometry(after),
        "all original frame and full argument/result schemas remain exact"
    );
    assert_eq!(
        before.report.access_hint_diagnostics,
        after.report.access_hint_diagnostics
    );
}
fn syscall_words(output: &CompileOutput, number: u32) -> usize {
    let offset = ProgramMetadata::parse(&output.artifact)
        .unwrap()
        .code_offset;
    let word = if let Ok(number) = u8::try_from(number) {
        encoding::wide::encode_sys(instruction::wide::system::SCALL, number)
    } else {
        encoding::wide::encode_syscallx(number)
    };
    output.artifact[offset..]
        .chunks_exact(4)
        .filter(|bytes| u32::from_le_bytes((*bytes).try_into().unwrap()) == word)
        .count()
}
#[test]
fn shared_nominal_abort_body_keeps_original_publication_reserved_inputs_and_terminal_consumer() {
    let mut code = Vec::new();
    emit_nominal_abort_tail(&mut code).unwrap();
    let mut expected = Vec::new();
    push_syscall(&mut expected, syscalls::SYSCALL_INPUT_PUBLISH_TLV);
    for register in 12..=15 {
        push_word(&mut expected, encode_addi(register, 0, 0).unwrap());
    }
    push_syscall(&mut expected, syscalls::SYSCALL_CONTRACT_ABORT);
    assert_eq!(code, expected);
    assert_eq!(code.len(), 24);
}
#[test]
fn shared_nominal_abort_scope_preserves_all_original_callable_frames_and_full_error_metadata() {
    let source = include_str!("../../../../../fixtures/kotodama/compact_emission/unit_loop.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    assert_metadata(&before, &after);
    assert_eq!(syscall_words(&before, syscalls::SYSCALL_CONTRACT_ABORT), 2);
    assert_eq!(syscall_words(&after, syscalls::SYSCALL_CONTRACT_ABORT), 1);
    assert_eq!(before.artifact.len() - after.artifact.len(), 16);
    let parsed = ProgramMetadata::parse(&after.artifact).unwrap();
    let abort_word = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        syscalls::SYSCALL_CONTRACT_ABORT as u8,
    );
    let abort_pc = after.artifact[parsed.code_offset..]
        .chunks_exact(4)
        .position(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) == abort_word)
        .unwrap()
        * 4;
    let owners = after
        .report
        .budget_report
        .iter()
        .filter(|function| {
            function.pc_start <= abort_pc as u64 && (abort_pc as u64) < function.pc_end
        })
        .collect::<Vec<_>>();
    assert_eq!(
        owners.len(),
        1,
        "the shared body remains inside exactly one original complete function range"
    );
    assert_eq!(owners[0].function_name, "guarded");
    assert_eq!(compile(source, false).artifact, after.artifact);
    let single = "seiyaku OneCheck { error enum Failure { Bad = 3 } view fn main() authorize(anyone) -> int { require(true, Failure::Bad); return 1; } }";
    assert_eq!(
        compile(single, true).artifact,
        compile(single, false).artifact
    );
}
#[test]
fn scalar_compact_comparison_scope_restores_after_nested_unwind() {
    assert!(!retain_scalar());
    with_scalar_emission(|| {
        assert!(retain_scalar());
        assert!(
            std::panic::catch_unwind(|| with_scalar_emission(|| panic!("comparison unwind")))
                .is_err()
        );
        assert!(retain_scalar());
    });
    assert!(!retain_scalar());
}
#[test]
fn rounded_and_typed_integer_operands_keep_original_full_schemas_consumers_and_precision() {
    let source =
        include_str!("../../../../../fixtures/kotodama/compact_emission/rounded_values.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    assert_metadata(&before, &after);
    assert!(after.artifact.len() < before.artifact.len());
    assert!(
        syscall_words(&after, syscalls::SYSCALL_INPUT_PUBLISH_TLV)
            < syscall_words(&before, syscalls::SYSCALL_INPUT_PUBLISH_TLV)
    );
    assert_eq!(compile(source, false).artifact, after.artifact);
    let parsed = ProgramMetadata::parse(&after.artifact).unwrap();
    assert_eq!(parsed.metadata.abi_version, 1);
    for syscall in [
        syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND,
        syscalls::SYSCALL_DECIMAL_DIV_ROUND,
        syscalls::SYSCALL_QUANTITY_RATIO_ROUND,
        syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND,
        syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND,
        syscalls::SYSCALL_INT_ABS,
        syscalls::SYSCALL_INT_ISQRT,
        syscalls::SYSCALL_INT_MIN,
        syscalls::SYSCALL_INT_GCD,
    ] {
        assert_eq!(
            syscall_words(&before, syscall),
            syscall_words(&after, syscall),
            "no original typed or metered operation disappears"
        );
        assert!(syscall_words(&after, syscall) > 0);
    }
}
#[test]
fn canonical_dlmm_compact_emission_measures_full_artifact_and_exact_unchanged_metadata() {
    let source = include_str!("../../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    assert_metadata(&before, &after);
    let old = ProgramMetadata::parse(&before.artifact).unwrap();
    let new = ProgramMetadata::parse(&after.artifact).unwrap();
    assert!(before.artifact.len() - after.artifact.len() >= 1_000);
    eprintln!(
        "dlmm_compact_emission before_bytes={} after_bytes={} saved_bytes={} before_code={} after_code={} before_cntr={} after_cntr={} before_literals={} after_literals={} before_publish={} after_publish={} before_abort={} after_abort={} before_hash={} after_hash={}",
        before.artifact.len(),
        after.artifact.len(),
        before.artifact.len() - after.artifact.len(),
        before.artifact.len() - old.code_offset,
        after.artifact.len() - new.code_offset,
        before.contract_interface.encode_section().len(),
        after.contract_interface.encode_section().len(),
        old.code_offset - old.header_len - before.contract_interface.encode_section().len(),
        new.code_offset - new.header_len - after.contract_interface.encode_section().len(),
        syscall_words(&before, syscalls::SYSCALL_INPUT_PUBLISH_TLV),
        syscall_words(&after, syscalls::SYSCALL_INPUT_PUBLISH_TLV),
        syscall_words(&before, syscalls::SYSCALL_CONTRACT_ABORT),
        syscall_words(&after, syscalls::SYSCALL_CONTRACT_ABORT),
        before.report.artifact_hash,
        after.report.artifact_hash
    );
    // TODO: actual Core payout and disposable-network validation under the
    // unchanged default4M policy remain required; byte savings do not qualify it.
}

fn compile_with_injected(instructions: Vec<Instr>, scalar: bool) -> Result<Vec<u8>, String> {
    crate::session::run_with_compiler_stack(|| {
        let build = || {
            let options = CompilerOptions::default();
            let session = CompilerSession::new(options.clone());
            let source_name = "compact_invalid_literal.ko";
            let parsed = session
                .parse_compilation_unit(CompileRequest {
                    source: include_str!("../fixtures/v1/c001.ko"),
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
                .unwrap();
            function.entry = ir::Label(0);
            function.blocks = vec![ir::BasicBlock {
                label: ir::Label(0),
                instrs: instructions,
                terminator: Terminator::Return(None),
            }];
            compiler
                .compile_codegen(codegen)
                .map(|artifact| artifact.bytes)
        };
        if scalar {
            with_scalar_emission(build)
        } else {
            build()
        }
    })
    .unwrap()
}
#[test]
fn compact_numeric_operands_keep_canonical_literal_rejections_for_every_original_typed_position() {
    use ir::{DataRefKind, NumericRoundOp, Temp, WideNumericKind};
    for fused in [false, true] {
        for quantity in [false, true] {
            for invalid in 0..if fused { 4 } else { 3 } {
                let make = || {
                    let kinds = [
                        if quantity {
                            DataRefKind::Quantity
                        } else {
                            DataRefKind::Decimal
                        },
                        DataRefKind::Decimal,
                        DataRefKind::Decimal,
                        DataRefKind::Int,
                    ];
                    let positions = if fused {
                        vec![0, 1, 2, 3]
                    } else {
                        vec![0, 2, 3]
                    };
                    let mut instructions = kinds
                        .iter()
                        .enumerate()
                        .map(|(index, kind)| Instr::DataRef {
                            dest: Temp(770 + index),
                            kind: *kind,
                            value: if index == positions[invalid] {
                                "bad-original-literal"
                            } else {
                                "1"
                            }
                            .to_owned(),
                        })
                        .collect::<Vec<_>>();
                    instructions.push(Instr::Const {
                        dest: Temp(774),
                        value: 0,
                    });
                    instructions.push(Instr::NumericRound {
                        dest: Temp(775),
                        dividend: Temp(770),
                        multiplier: fused.then_some(Temp(771)),
                        divisor: Temp(772),
                        scale: Temp(773),
                        mode: Temp(774),
                        op: match (quantity, fused) {
                            (true, true) => NumericRoundOp::QuantityMulDiv,
                            (false, true) => NumericRoundOp::DecimalMulDiv,
                            (true, false) => NumericRoundOp::QuantityDiv,
                            (false, false) => NumericRoundOp::DecimalDiv,
                        },
                        result_kind: if quantity {
                            WideNumericKind::Quantity
                        } else {
                            WideNumericKind::Decimal
                        },
                    });
                    instructions
                };
                let before = compile_with_injected(make(), true)
                    .expect_err("original canonical literal rejection");
                let after = compile_with_injected(make(), false)
                    .expect_err("same original validator remains");
                assert_eq!(
                    before, after,
                    "complete typed rejection at original operand {invalid}"
                );
            }
        }
    }
}

#[test]
fn shared_nominal_abort_cross_function_jump_keeps_complete_caller_and_target_ranges() {
    let source = include_str!("../../../../../fixtures/kotodama/compact_emission/abort_second.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    assert_metadata(&before, &after);
    assert_eq!(syscall_words(&before, syscalls::SYSCALL_CONTRACT_ABORT), 2);
    assert_eq!(syscall_words(&after, syscalls::SYSCALL_CONTRACT_ABORT), 1);
    let parsed = ProgramMetadata::parse(&after.artifact).unwrap();
    let words = after.artifact[parsed.code_offset..]
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect::<Vec<_>>();
    let abort = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        syscalls::SYSCALL_CONTRACT_ABORT as u8,
    );
    let abort_pc = words.iter().position(|word| *word == abort).unwrap() as u64 * 4;
    let tail_pc = abort_pc.checked_sub(20).unwrap();
    let owner = after
        .report
        .budget_report
        .iter()
        .find(|function| function.function_name == "guarded")
        .expect("twice-called original private function remains authenticated");
    let caller = after
        .report
        .budget_report
        .iter()
        .find(|function| function.function_name == "main")
        .unwrap();
    assert!(owner.pc_start <= tail_pc && abort_pc < owner.pc_end);
    assert!(tail_pc < caller.pc_start && owner.pc_end <= caller.pc_start);
    assert!(
        after
            .contract_interface
            .callables
            .iter()
            .all(|callable| callable.entry_pc != tail_pc),
        "terminal body is a normal instruction target, never a new callable"
    );
    let cross_jumps = words
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, word)| {
            let pc = *index as u64 * 4;
            if pc < caller.pc_start || pc >= caller.pc_end {
                return false;
            }
            let offset = match instruction::wide::opcode(*word) {
                instruction::wide::control::JAL if instruction::wide::rd(*word) == 0 => {
                    i64::from(instruction::wide::imm16(*word))
                }
                instruction::wide::control::JMP => i64::from(instruction::wide::imm24(*word)),
                _ => return false,
            };
            pc.checked_add_signed(offset * 4) == Some(tail_pc)
        })
        .count();
    assert_eq!(
        cross_jumps, 1,
        "main's taken High failure uses the original relaxed jump into guarded's sole terminal body"
    );
    for output in [&before, &after] {
        assert_eq!(
            output.contract_interface.error_types[0]
                .variant(3)
                .unwrap()
                .name,
            "Low"
        );
        assert_eq!(
            output.contract_interface.error_types[0]
                .variant(9)
                .unwrap()
                .name,
            "High"
        );
    }
    assert_eq!(compile(source, false).artifact, after.artifact);
    // The same mandatory eight-row native capture and existing full-error,
    // prior-write and transaction-rollback VM consumer execute this actual path.
}
