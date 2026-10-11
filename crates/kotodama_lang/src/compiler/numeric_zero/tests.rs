//! Exact physical clobber/relocation controls and genuine complete compiler comparisons.
use super::*;
use crate::session::{CompileOutput, CompileRequest, CompilerSession};
pub(super) fn compile(source: &str, original: bool) -> CompileOutput {
    crate::session::run_with_compiler_stack(|| {
        let build = || {
            CompilerSession::default()
                .build(CompileRequest {
                    source,
                    source_name: Some("numeric_zero.ko"),
                })
                .expect("complete canonical typed source, SSA, literal and artifact admission")
        };
        if original {
            with_original_zeros(build)
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
        before.contract_interface.callables.len(),
        after.contract_interface.callables.len()
    );
    assert_eq!(
        geometry(before),
        geometry(after),
        "every complete original private/public callable, frame and eager argument/result schema"
    );
    assert_eq!(
        before.report.access_hint_diagnostics,
        after.report.access_hint_diagnostics
    );
}
fn seed() -> (Block, Vec<u8>, LiteralFixups) {
    let mut block = Block::new(0);
    let mut code = Vec::new();
    let fixups = LiteralFixups::default();
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    assert_eq!(code.len(), 12);
    (block, code, fixups)
}
#[test]
fn same_block_reuses_only_exact_zero_inputs_across_original_numeric_kernel_and_stores() {
    let (mut block, mut code, fixups) = seed();
    push_syscall(&mut code, syscalls::SYSCALL_QUANTITY_ADD);
    push_word(&mut code, encode_addi(10, 11, 0).unwrap());
    push_word(&mut code, encode_store64_rv(2, 10, 0).unwrap());
    push_syscall(&mut code, syscalls::SYSCALL_QUANTITY_LT);
    let end = code.len();
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    assert_eq!(code.len(), end);
    assert_eq!(block.zero, 7);
}
#[test]
fn actual_alu_split_spill_and_parallel_move_destinations_invalidate_each_allocatable_input() {
    for register in 12..=14 {
        for word in [
            encode_addi(register, 10, 0).unwrap(),
            encode_load64_rv(register, 2, 0).unwrap(),
            encoding::wide::encode_rr(instruction::wide::arithmetic::CMOV, register, 10, 11),
        ] {
            let (mut block, mut code, fixups) = seed();
            push_word(&mut code, word);
            let end = code.len();
            block.emit_trap_inputs(&mut code, &fixups).unwrap();
            assert_eq!(code.len() - end, 4);
            assert_eq!(
                u32::from_le_bytes(code[end..].try_into().unwrap()),
                encode_addi(register, 0, 0).unwrap()
            );
        }
    }
}
#[test]
fn unresolved_literal_loads_invalidate_their_final_exact_destination() {
    for register in [10, 12, 13, 14, 27] {
        let (mut block, mut code, fixups) = seed();
        emit_literal_load(
            &mut code,
            &fixups,
            register,
            DataKey(DataKind::Int, "9".to_owned()),
        );
        let end = code.len();
        block.emit_trap_inputs(&mut code, &fixups).unwrap();
        assert_eq!(
            code.len() - end,
            if (12..=14).contains(&register) { 4 } else { 0 }
        );
    }
}
#[test]
fn pending_calls_control_unknown_syscalls_and_new_blocks_keep_all_original_zero_assignments() {
    for word in [
        encode_nop(),
        encoding::wide::encode_halt(),
        encoding::wide::encode_offset24(instruction::wide::control::JMP, 1),
        encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            syscalls::SYSCALL_STATE_GET as u8,
        ),
        0xff00_0000,
    ] {
        let (mut block, mut code, fixups) = seed();
        push_word(&mut code, word);
        let end = code.len();
        block.emit_trap_inputs(&mut code, &fixups).unwrap();
        assert_eq!(code.len() - end, 12);
    }
    let (_, mut code, fixups) = seed();
    let end = code.len();
    let mut next = Block::new(end);
    next.emit_trap_inputs(&mut code, &fixups).unwrap();
    assert_eq!(code.len() - end, 12);
}
#[test]
fn original_numeric_zero_comparison_scope_restores_after_nested_unwind() {
    assert!(!retain_original());
    with_original_zeros(|| {
        assert!(retain_original());
        assert!(
            std::panic::catch_unwind(|| with_original_zeros(|| panic!("comparison unwind")))
                .is_err()
        );
        assert!(retain_original());
    });
    assert!(!retain_original());
}
fn syscalls(output: &CompileOutput) -> Vec<u32> {
    let offset = ProgramMetadata::parse(&output.artifact)
        .unwrap()
        .code_offset;
    output.artifact[offset..]
        .chunks_exact(4)
        .filter_map(|bytes| {
            let word = u32::from_le_bytes(bytes.try_into().unwrap());
            match instruction::wide::opcode(word) {
                instruction::wide::system::SCALL => Some(word & 0xff),
                instruction::wide::system::SYSTEM => Some(word & 0x00ff_ffff),
                _ => None,
            }
        })
        .collect()
}
#[test]
fn complete_typed_numeric_chain_keeps_all_original_calls_schemas_and_syscalls() {
    let source = "seiyaku ZeroChain { fn chain(quantity left, quantity right) -> quantity { let first=left+right; let second=first+right; return second+left; } view fn main() authorize(anyone) ->quantity { let quantity left=5; let quantity right=7; return chain(left: left,right:right); } }";
    let before = compile(source, true);
    let after = compile(source, false);
    assert_metadata(&before, &after);
    assert_eq!(syscalls(&before), syscalls(&after));
    assert!(
        after.artifact.len() < before.artifact.len(),
        "actual exact numeric chain must remove proven redundant words"
    );
    assert_eq!(compile(source, true).artifact, before.artifact);
    assert_eq!(compile(source, false).artifact, after.artifact);
}
#[test]
fn actual_dlmm_zero_staging_measures_complete_artifact_and_preserves_full_fee_callback_abi() {
    let source = include_str!("../../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    assert_metadata(&before, &after);
    assert_eq!(
        syscalls(&before),
        syscalls(&after),
        "no real monetary, typed numeric or custody consumer is removed"
    );
    assert!(after.artifact.len() <= before.artifact.len());
    eprintln!(
        "dlmm_numeric_zero before_bytes={} after_bytes={} saved_bytes={} before_hash={} after_hash={}",
        before.artifact.len(),
        after.artifact.len(),
        before.artifact.len() - after.artifact.len(),
        before.report.artifact_hash,
        after.report.artifact_hash
    );
    // TODO: actual default-4M Core signed callback and unchanged-candidate network qualification remain mandatory.
}

#[test]
fn indexed_pending_relocations_keep_all_new_writes_after_many_prior_literal_fixups() {
    let mut code = Vec::new();
    let fixups = LiteralFixups::default();
    // These older relocations precede this block's first public-zero fact.
    for value in 0..128 {
        emit_literal_load(
            &mut code,
            &fixups,
            12,
            DataKey(DataKind::Int, value.to_string()),
        );
    }
    let mut block = Block::new(code.len());
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    for register in [10, 12, 27, 14] {
        emit_literal_load(
            &mut code,
            &fixups,
            register,
            DataKey(DataKind::Int, "9".to_owned()),
        );
    }
    let first = code.len();
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    let words = code[first..]
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        words,
        vec![
            encode_addi(12, 0, 0).unwrap(),
            encode_addi(14, 0, 0).unwrap()
        ]
    );
    emit_literal_load(
        &mut code,
        &fixups,
        13,
        DataKey(DataKind::Int, "0".to_owned()),
    );
    push_syscall(&mut code, syscalls::SYSCALL_QUANTITY_LT);
    let second = code.len();
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    assert_eq!(code.len() - second, 4);
    assert_eq!(
        u32::from_le_bytes(code[second..].try_into().unwrap()),
        encode_addi(13, 0, 0).unwrap()
    );
    push_syscall(&mut code, syscalls::SYSCALL_QUANTITY_ADD);
    let third = code.len();
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    assert_eq!(code.len(), third);
}

#[test]
fn scanned_public_zero_writes_never_establish_trap_input_facts() {
    let (mut block, mut code, fixups) = seed();
    for register in 12..=14 {
        push_word(&mut code, encode_addi(register, 0, 0).unwrap());
    }
    let end = code.len();
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    assert_eq!(code.len() - end, 12);
    assert_eq!(code[end..], code[..12]);
    let next = code.len();
    // Only the emitter's own complete, unconditional setup now teaches facts.
    block.emit_trap_inputs(&mut code, &fixups).unwrap();
    assert_eq!(code.len(), next);
}

#[test]
fn skipped_path_zero_writes_cannot_reestablish_facts_after_control_or_pending_calls() {
    for boundary in [
        encode_branch_rv(0x0, 0, 0, 16).unwrap(),
        encode_nop(),
        0xff00_0000,
    ] {
        let (mut block, mut code, fixups) = seed();
        push_word(&mut code, encode_addi(12, 0, 5).unwrap());
        // The taken BEQ targets the end of these three zero assignments. A
        // linear byte scan encounters them, but actual execution skips them.
        push_word(&mut code, boundary);
        for register in 12..=14 {
            push_word(&mut code, encode_addi(register, 0, 0).unwrap());
        }
        push_syscall(&mut code, syscalls::SYSCALL_QUANTITY_LT);
        let end = code.len();
        block.emit_trap_inputs(&mut code, &fixups).unwrap();
        assert_eq!(code.len() - end, 12);
        assert_eq!(code[end..], code[..12]);
        assert_eq!(block.zero, 7);
        push_syscall(&mut code, syscalls::SYSCALL_QUANTITY_ADD);
        let next = code.len();
        block.emit_trap_inputs(&mut code, &fixups).unwrap();
        assert_eq!(code.len(), next);
    }
}
