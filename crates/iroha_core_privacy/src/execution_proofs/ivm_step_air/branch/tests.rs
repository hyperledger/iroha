//! Interpreter parity and adversarial checks for the conditional-branch chip.

use super::*;
use crate::execution_proofs::stark::proof_managed_note_stark::{
    prove_proof_managed_note_stark_v1, verify_proof_managed_note_stark_v1,
};
use iroha_allocation::AllocationBudget;
use ivm::{
    IVM,
    execution_step_recorder::{
        DiagnosticStepOutcome, DiagnosticStepRecord, DiagnosticStepRecorder,
    },
    host::DefaultHost,
};

fn interpreter_statement(
    opcode: u8,
    left_register: u8,
    right_register: u8,
    left: u64,
    right: u64,
    offset: i8,
    backward: bool,
) -> BranchStepStatement {
    let word = ivm::encoding::wide::encode_branch(opcode, left_register, right_register, offset);
    let branch_pc = if backward { 4 } else { 0 };
    let instructions = if backward {
        [
            ivm::encoding::wide::encode_halt(),
            word,
            ivm::encoding::wide::encode_halt(),
        ]
    } else {
        [
            word,
            ivm::encoding::wide::encode_halt(),
            ivm::encoding::wide::encode_halt(),
        ]
    };
    // Selecting the backward-branch entry requires an admitted, prepared
    // instruction boundary. Raw `load_code` intentionally has no such map.
    let metadata = ivm::ProgramMetadata {
        mode: ivm::ivm_mode::ZK,
        max_cycles: 4,
        ..ivm::ProgramMetadata::default()
    };
    assert_eq!(metadata.abi_version, 1);
    let mut program = metadata.encode();
    program.extend(instructions.into_iter().flat_map(u32::to_le_bytes));
    let budget = AllocationBudget::new(3 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(3, &budget).unwrap();
    let mut vm = IVM::new(1_000);
    vm.load_program(&program).unwrap();
    vm.set_register(left_register.into(), left);
    vm.set_register(right_register.into(), right);
    assert!(matches!(
        (&(vm.set_program_counter(2)), &(ivm::VMError::DecodeError)),
        (Err(ivm::VMError::DecodeError), ivm::VMError::DecodeError)
    ));
    assert!(matches!(
        (&(vm.set_program_counter(12)), &(ivm::VMError::DecodeError)),
        (Err(ivm::VMError::DecodeError), ivm::VMError::DecodeError)
    ));
    vm.set_program_counter(branch_pc).unwrap();
    vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder)
        .unwrap();
    let step = &recorder.records()[0];
    assert_eq!(step.instruction, Some(word));
    assert_eq!(step.opcode_gas, Some(1));
    assert_eq!(step.outcome, DiagnosticStepOutcome::Completed);
    assert_eq!(step.changed_registers().count(), 0);
    assert_eq!(step.before.registers, step.after.registers);
    assert_eq!(step.before.tags, step.after.tags);
    assert_eq!(step.before.pc, branch_pc);
    let left_index = wide::rd(word);
    let right_index = wide::rs1(word);
    BranchStepStatement {
        word,
        before_pc: step.before.pc.try_into().unwrap(),
        after_pc: step.after.pc.try_into().unwrap(),
        before_gas: step.before.gas_remaining.try_into().unwrap(),
        after_gas: step.after.gas_remaining.try_into().unwrap(),
        before_cycles: step.before.cycles.try_into().unwrap(),
        after_cycles: step.after.cycles.try_into().unwrap(),
        left: step.before.registers[left_index],
        right: step.before.registers[right_index],
        left_after: step.after.registers[left_index],
        right_after: step.after.registers[right_index],
        left_tag: step.before.tags[left_index],
        right_tag: step.before.tags[right_index],
        left_tag_after: step.after.tags[left_index],
        right_tag_after: step.after.tags[right_index],
    }
}

fn assert_relation(statement: BranchStepStatement) {
    statement.validate().unwrap();
    let residuals = residues(&statement.witness(), &statement.fixed(), statement.word).unwrap();
    assert_eq!(residuals.len(), CONSTRAINT_COUNT);
    assert!(
        residuals.iter().all(|residual| *residual == F::ZERO),
        "branch word={:#010x} left={:#x} right={:#x} pc={} -> {}",
        statement.word,
        statement.left,
        statement.right,
        statement.before_pc,
        statement.after_pc,
    );
}

fn assert_rejected(statement: BranchStepStatement) {
    let residuals = residues(&statement.witness(), &statement.fixed(), statement.word).unwrap();
    assert!(
        residuals.iter().any(|residual| *residual != F::ZERO),
        "accepted forged branch statement {statement:?}"
    );
}

fn columns(statement: BranchStepStatement) -> Vec<Vec<F>> {
    let row = statement.witness();
    let mut columns = vec![vec![F::ZERO; TRACE_SIZE]; NOTE_COPY_WIDTH_V1];
    columns.extend(row.into_iter().map(|value| vec![value; TRACE_SIZE]));
    columns
}

#[test]
fn all_six_branch_predicates_match_interpreter_pc_registers_and_gas() {
    for (opcode, left, right, expected_taken) in [
        (wide::control::BEQ, 7, 7, true),
        (wide::control::BEQ, 7, 8, false),
        (wide::control::BNE, 7, 8, true),
        (wide::control::BNE, 7, 7, false),
        (wide::control::BLT, i64::cast_unsigned(i64::MIN), 0, true),
        (
            wide::control::BLT,
            i64::MAX as u64,
            i64::cast_unsigned(i64::MIN),
            false,
        ),
        (
            wide::control::BGE,
            i64::MAX as u64,
            i64::cast_unsigned(i64::MIN),
            true,
        ),
        (wide::control::BGE, i64::cast_unsigned(i64::MIN), 0, false),
        (wide::control::BLTU, 0, u64::MAX, true),
        (wide::control::BLTU, u64::MAX, 0, false),
        (wide::control::BGEU, u64::MAX, 0, true),
        (wide::control::BGEU, 0, u64::MAX, false),
    ] {
        let statement = interpreter_statement(opcode, 1, 2, left, right, 2, false);
        assert_eq!(statement.after_pc, if expected_taken { 8 } else { 4 });
        assert_eq!(statement.before_gas - statement.after_gas, 1);
        assert_eq!(statement.after_cycles - statement.before_cycles, 1);
        assert_relation(statement);
    }
    for (left_register, right_register, left, right) in [
        (0, 0, u64::MAX, 42),
        (0, 2, 55, 0),
        (1, 0, 0, 77),
        (1, 1, 88, 99),
    ] {
        let statement = interpreter_statement(
            wide::control::BEQ,
            left_register,
            right_register,
            left,
            right,
            -1,
            true,
        );
        assert_eq!(statement.after_pc, 0);
        assert_relation(statement);
    }
}

#[test]
fn self_consistent_forged_branch_statements_and_rows_fail_air() {
    let base = interpreter_statement(
        wide::control::BLT,
        1,
        2,
        i64::cast_unsigned(i64::MIN),
        i64::MAX as u64,
        2,
        false,
    );
    assert_relation(base);
    for forged in [
        BranchStepStatement {
            after_pc: 4,
            ..base
        },
        BranchStepStatement {
            after_gas: base.after_gas - 1,
            ..base
        },
        BranchStepStatement {
            after_cycles: base.after_cycles + 1,
            ..base
        },
        BranchStepStatement {
            left_after: 0,
            ..base
        },
        BranchStepStatement {
            right_after: 0,
            ..base
        },
        BranchStepStatement {
            word: ivm::encoding::wide::encode_branch(wide::control::BLT, 1, 2, 1),
            ..base
        },
        BranchStepStatement {
            word: ivm::encoding::wide::encode_branch(wide::control::BGE, 1, 2, 2),
            ..base
        },
        BranchStepStatement {
            word: ivm::encoding::wide::encode_branch(wide::control::BLT, 1, 1, 2),
            ..base
        },
        BranchStepStatement {
            word: ivm::encoding::wide::encode_branch(wide::control::BLT, 0, 2, 2),
            ..base
        },
    ] {
        forged.validate().unwrap();
        assert_rejected(forged);
    }
    let fixed = base.fixed();
    for changed in [
        LEFT_OFFSET + 3,
        RIGHT_OFFSET,
        DIFF_OFFSET,
        BORROW_OFFSET + 3,
        ZERO_OFFSET,
        INVERSE_OFFSET,
        DIGIT_OFFSET + 31,
        SOURCE_OFFSET + 63,
        EQUALITY_OFFSET,
        TAKEN_OFFSET,
        LEFT_AFTER_OFFSET,
        1,
        3,
    ] {
        let mut row = base.witness();
        row[changed] = row[changed].add(F::ONE);
        assert!(
            residues(&row, &fixed, base.word)
                .unwrap()
                .iter()
                .any(|residual| *residual != F::ZERO),
            "accepted forged row column {changed}"
        );
    }
    assert!(
        BranchStepStatement {
            left_tag: true,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        BranchStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::ADD, 1, 2, 3),
            ..base
        }
        .validate()
        .is_err()
    );
}

#[test]
fn native_stark_proves_branch_comparison_and_rejects_changed_statement_or_row() {
    let statement = interpreter_statement(
        wide::control::BLT,
        1,
        2,
        i64::cast_unsigned(i64::MIN),
        i64::MAX as u64,
        2,
        false,
    );
    let adapter = BranchStepAdapter(statement);
    let proof = prove_proof_managed_note_stark_v1(&adapter, &columns(statement)).unwrap();
    verify_proof_managed_note_stark_v1(&adapter, &proof).unwrap();
    for changed in [
        BranchStepStatement {
            after_pc: 4,
            ..statement
        },
        BranchStepStatement {
            right: 0,
            right_after: 0,
            ..statement
        },
        BranchStepStatement {
            word: ivm::encoding::wide::encode_branch(wide::control::BGE, 1, 2, 2),
            ..statement
        },
    ] {
        assert!(verify_proof_managed_note_stark_v1(&BranchStepAdapter(changed), &proof).is_err());
    }
    let mut forged_columns = columns(statement);
    forged_columns[NOTE_COPY_WIDTH_V1 + BORROW_OFFSET + 3][0] = F::ONE;
    assert!(prove_proof_managed_note_stark_v1(&adapter, &forged_columns).is_err());
}

#[test]
fn append_bank_preserves_the_original_residual_owner_and_exact_constraint_count() {
    for (selector, opcode) in [
        wide::control::BEQ,
        wide::control::BNE,
        wide::control::BLT,
        wide::control::BGE,
        wide::control::BLTU,
        wide::control::BGEU,
    ]
    .into_iter()
    .enumerate()
    {
        for (left, right) in [
            (0, 0),
            (u64::MAX, 1),
            (i64::cast_unsigned(i64::MIN), i64::MAX as u64),
        ] {
            let source_bits = word::witness(left, right);
            let source = Sources::new(&source_bits);
            let bank = bank_witness(opcode, left, right);
            let limbs = core::array::from_fn(|operand| {
                core::array::from_fn(|limb| source.limb(operand, limb))
            });
            let signs = [source.sign(0), source.sign(1)];
            let selectors = core::array::from_fn(|i| F(u64::from(i == selector)));
            let mut out = Vec::with_capacity(BANK_CONSTRAINTS + 2);
            out.extend([F(17), F(23)]);
            let original = out.as_ptr();
            append_bank_residues(&mut out, &bank, limbs, signs, selectors);
            assert_eq!(out.as_ptr(), original);
            assert_eq!(&out[..2], &[F(17), F(23)]);
            assert_eq!(out.len(), BANK_CONSTRAINTS + 2);
            assert!(out[2..].iter().all(|v| *v == F::ZERO));
            assert_eq!(&out[2..], bank_residues(&bank, limbs, signs, selectors));
        }
    }
}
