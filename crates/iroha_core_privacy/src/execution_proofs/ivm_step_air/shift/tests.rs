//! Interpreter, polynomial-degree and adversarial tests for the shift chip.

use super::*;
use crate::execution_proofs::stark::proof_managed_note_stark::{
    degree_audit::measured_maximum_affine_degree_v1, prove_proof_managed_note_stark_v1,
    verify_proof_managed_note_stark_v1,
};
use iroha_allocation::AllocationBudget;
use ivm::{
    IVM, ProgramMetadata,
    execution_step_recorder::{
        DiagnosticStepOutcome, DiagnosticStepRecord, DiagnosticStepRecorder,
    },
    host::DefaultHost,
};

const REGISTER_OPCODES: [u8; 5] = [
    wide::arithmetic::SLL,
    wide::arithmetic::SRL,
    wide::arithmetic::SRA,
    wide::arithmetic::ROTL,
    wide::arithmetic::ROTR,
];
const IMMEDIATE_OPCODES: [u8; 2] = [wide::arithmetic::ROTL_IMM, wide::arithmetic::ROTR_IMM];

fn interpreter_statement(word: u32, left: u64, amount: u64) -> ShiftStepStatement {
    let mut program = ProgramMetadata {
        mode: ivm::ivm_mode::ZK,
        max_cycles: 4,
        ..ProgramMetadata::default()
    }
    .encode();
    program.extend(
        [word, ivm::encoding::wide::encode_halt()]
            .into_iter()
            .flat_map(u32::to_le_bytes),
    );
    let budget = AllocationBudget::new(2 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(2, &budget).unwrap();
    let mut vm = IVM::new(1_000);
    vm.load_program(&program).unwrap();
    vm.set_register(wide::rs1(word), left);
    if immediate_amount(word).is_none() {
        vm.set_register(wide::rs2(word), amount);
    }
    vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder)
        .unwrap();
    let step = &recorder.records()[0];
    let (rd, rs1, rs2) = (wide::rd(word), wide::rs1(word), wide::rs2(word));
    assert_eq!(step.instruction, Some(word));
    assert_eq!(step.outcome, DiagnosticStepOutcome::Completed);
    assert_eq!(step.opcode_gas, gas::cost_of(word));
    for register in 0..256 {
        if register != rd || rd == 0 {
            assert_eq!(
                step.before.registers[register],
                step.after.registers[register]
            );
            assert_eq!(step.before.tags[register], step.after.tags[register]);
        }
    }
    let left = step.before.registers[rs1];
    let amount = immediate_amount(word).unwrap_or(step.before.registers[rs2]);
    ShiftStepStatement {
        word,
        before_pc: step.before.pc.try_into().unwrap(),
        after_pc: step.after.pc.try_into().unwrap(),
        before_gas: step.before.gas_remaining.try_into().unwrap(),
        after_gas: step.after.gas_remaining.try_into().unwrap(),
        before_cycles: step.before.cycles.try_into().unwrap(),
        after_cycles: step.after.cycles.try_into().unwrap(),
        left,
        amount,
        result: ShiftKind::from_word(word)
            .unwrap()
            .apply(left, (amount & 63) as u32),
        destination_after: step.after.registers[rd],
        left_after: step.after.registers[rs1],
        amount_after: immediate_amount(word).unwrap_or(step.after.registers[rs2]),
        left_tag: step.before.tags[rs1],
        amount_tag: immediate_amount(word).is_none() && step.before.tags[rs2],
        destination_tag: step.after.tags[rd],
        left_tag_after: step.after.tags[rs1],
        amount_tag_after: immediate_amount(word).is_none() && step.after.tags[rs2],
    }
}

fn assert_relation(statement: ShiftStepStatement) {
    statement.validate().unwrap();
    let residuals = residues(&statement.witness(), &statement.fixed(), statement.word).unwrap();
    assert_eq!(residuals.len(), CONSTRAINT_COUNT);
    assert!(
        residuals.iter().all(|value| *value == F::ZERO),
        "invalid relation for {statement:?}"
    );
    assert_eq!(
        statement.before_gas - statement.after_gas,
        gas::cost_of(statement.word).unwrap() as u32
    );
    assert_eq!(statement.after_cycles - statement.before_cycles, 1);
}

fn assert_rejected(statement: ShiftStepStatement) {
    let row = statement.witness();
    let fixed = statement.fixed();
    assert_eq!(&row[..PUBLIC_WIDTH], &fixed[..]);
    assert!(
        residues(&row, &fixed, statement.word)
            .unwrap()
            .iter()
            .any(|value| *value != F::ZERO),
        "accepted forged statement {statement:?}"
    );
}

#[test]
fn shift_all_seven_opcodes_match_interpreter_boundaries_and_masked_amounts() {
    for opcode in REGISTER_OPCODES {
        for left in [
            0,
            1,
            u64::MAX,
            i64::cast_unsigned(i64::MIN),
            i64::MAX as u64,
            0xa55a_8001_f00f_1234,
        ] {
            for amount in [
                0,
                1,
                2,
                3,
                4,
                8,
                9,
                15,
                16,
                31,
                32,
                40,
                63,
                64,
                65,
                127,
                128,
                255,
                u64::MAX,
            ] {
                let word = ivm::encoding::wide::encode_rr(opcode, 3, 1, 2);
                assert_relation(interpreter_statement(word, left, amount));
            }
        }
    }
    for opcode in IMMEDIATE_OPCODES {
        for amount in [0, 1, 3, 8, 9, 16, 31, 32, 40, 63, 64, 127, 128, 255] {
            for left in [
                0,
                1,
                u64::MAX,
                i64::cast_unsigned(i64::MIN),
                0xa55a_8001_f00f_1234,
            ] {
                let word =
                    ivm::encoding::wide::encode_ri(opcode, 3, 1, u8::cast_signed(amount as u8));
                let statement = interpreter_statement(word, left, u64::MAX);
                assert_eq!(statement.amount, amount);
                assert_relation(statement);
            }
        }
    }
}

#[test]
fn shift_register_aliases_r0_and_immediate_register_nonreads_match_interpreter() {
    for opcode in REGISTER_OPCODES {
        for (rd, rs1, rs2) in [
            (3, 1, 2),
            (1, 1, 2),
            (2, 1, 2),
            (3, 1, 1),
            (1, 1, 1),
            (3, 0, 2),
            (3, 1, 0),
            (3, 0, 0),
            (0, 1, 2),
            (0, 0, 2),
            (0, 1, 0),
            (0, 0, 0),
            (1, 0, 1),
            (2, 2, 0),
        ] {
            assert_relation(interpreter_statement(
                ivm::encoding::wide::encode_rr(opcode, rd, rs1, rs2),
                0x8000_0000_0000_003f,
                0xfedc_ba98_7654_3221,
            ));
        }
    }
    for opcode in IMMEDIATE_OPCODES {
        for (rd, rs1) in [(3, 1), (1, 1), (0, 1), (3, 0), (0, 0), (255, 255)] {
            for amount in [0, 1, 255] {
                assert_relation(interpreter_statement(
                    ivm::encoding::wide::encode_ri(opcode, rd, rs1, u8::cast_signed(amount as u8)),
                    0x8000_0000_0000_003f,
                    0xdead_beef,
                ));
            }
        }
    }
}

#[test]
fn shift_quadratic_selectors_pick_one_wire_and_single_step_degree_is_two() {
    for digit in 0..4 {
        let selectors = stage_selectors(F(digit & 1), F(digit >> 1));
        for (index, selector) in selectors.into_iter().enumerate() {
            assert_eq!(
                selector,
                if index as u64 == digit {
                    F::ONE
                } else {
                    F::ZERO
                }
            );
        }
    }
    for opcode in REGISTER_OPCODES.into_iter().chain(IMMEDIATE_OPCODES) {
        let word = ivm::encoding::wide::encode_rr(opcode, 1, 1, 2);
        let measured = measured_maximum_affine_degree_v1(
            [opcode; 32],
            [ROW_WIDTH, 0, 0, 0, FIXED_WIDTH],
            3,
            MAXIMUM_DEGREE,
            |current, _, _, _, fixed| residues(current, fixed, word),
        );
        assert_eq!(measured, 2);
        assert!(measured <= usize::from(MAXIMUM_DEGREE));
    }
}

#[test]
fn shift_self_consistent_forged_results_control_aliases_and_immediates_fail_air() {
    let word = ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 3, 1, 2);
    let base = interpreter_statement(word, 0x8000_0000_0000_0001, 36);
    assert_relation(base);
    for forged in [
        ShiftStepStatement {
            result: base.result ^ 1,
            destination_after: base.destination_after ^ 1,
            ..base
        },
        ShiftStepStatement {
            result: base.left >> 36,
            destination_after: base.left >> 36,
            ..base
        },
        ShiftStepStatement {
            destination_after: base.destination_after ^ 1,
            ..base
        },
        ShiftStepStatement {
            left_after: base.left_after ^ 1,
            ..base
        },
        ShiftStepStatement {
            amount_after: base.amount_after ^ 1,
            ..base
        },
        ShiftStepStatement {
            after_pc: base.after_pc + 4,
            ..base
        },
        ShiftStepStatement {
            after_gas: base.after_gas - 1,
            ..base
        },
        ShiftStepStatement {
            after_cycles: base.after_cycles + 1,
            ..base
        },
        ShiftStepStatement {
            amount: 37,
            amount_after: 37,
            ..base
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRL, 3, 1, 2),
            ..base
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 0, 1, 2),
            ..base
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 1, 1, 2),
            ..base
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 2, 1, 2),
            ..base
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 3, 0, 2),
            ..base
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 3, 1, 0),
            ..base
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 3, 1, 1),
            ..base
        },
    ] {
        forged.validate().unwrap();
        assert_rejected(forged);
    }
    let immediate = interpreter_statement(
        ivm::encoding::wide::encode_ri(wide::arithmetic::ROTL_IMM, 3, 1, -1),
        0x1234_5678_8000_0001,
        0,
    );
    assert_eq!(immediate.amount, 255);
    assert!(
        ShiftStepStatement {
            amount: u64::MAX,
            ..immediate
        }
        .validate()
        .is_err()
    );
    assert_rejected(ShiftStepStatement {
        amount_after: u64::MAX,
        ..immediate
    });
    assert!(
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::ADD, 3, 1, 2),
            ..base
        }
        .validate()
        .is_err()
    );
}

#[test]
fn shift_witness_bit_digit_and_every_barrel_stage_mutation_fail_air() {
    let base = interpreter_statement(
        ivm::encoding::wide::encode_rr(wide::arithmetic::ROTR, 3, 1, 2),
        0xa55a_8001_f00f_1234,
        0x1234_5678_9abc_0039,
    );
    let fixed = base.fixed();
    let mut positions = vec![
        SOURCE_OFFSET,
        SOURCE_OFFSET + 63,
        SOURCE_OFFSET + 64,
        SOURCE_OFFSET + 68,
        SOURCE_OFFSET + 127,
        SOURCE_OFFSET + 64,
        SOURCE_OFFSET + 69,
        STAGE_SELECTORS_OFFSET,
        STAGE_SELECTORS_OFFSET + 11,
    ];
    positions.extend((0..STAGES).flat_map(|stage| {
        [
            STAGE_OFFSET + stage * WORD_BITS,
            STAGE_OFFSET + stage * WORD_BITS + 63,
        ]
    }));
    for position in positions {
        let mut row = base.witness();
        row[position] = row[position].add(F::ONE);
        assert!(
            residues(&row, &fixed, base.word)
                .unwrap()
                .iter()
                .any(|value| *value != F::ZERO),
            "accepted forged column {position}"
        );
    }
    // Values outside the Boolean sets must fail even if a reconstructed limb
    // and its public fixed value are changed consistently with the forged digit.
    for (column, forged) in [(SOURCE_OFFSET, F(2)), (SOURCE_OFFSET + 64, F(2))] {
        let mut row = base.witness();
        row[column] = forged;
        let operand = if column == SOURCE_OFFSET {
            LEFT_OFFSET
        } else {
            AMOUNT_OFFSET
        };
        let delta = forged.sub(base.witness()[column]);
        row[operand] = row[operand].add(delta);
        let mut fixed = fixed;
        fixed[operand] = row[operand];
        assert!(
            residues(&row, &fixed, base.word)
                .unwrap()
                .iter()
                .any(|value| *value != F::ZERO)
        );
    }
    assert!(residues(&base.witness()[..ROW_WIDTH - 1], &fixed, base.word).is_err());
    assert!(residues(&base.witness(), &fixed[..FIXED_WIDTH - 1], base.word).is_err());
}

#[test]
fn shift_public_profile_rejects_every_private_input_and_output_tag() {
    let base = interpreter_statement(
        ivm::encoding::wide::encode_rr(wide::arithmetic::SLL, 3, 1, 2),
        7,
        1,
    );
    for statement in [
        ShiftStepStatement {
            left_tag: true,
            ..base
        },
        ShiftStepStatement {
            amount_tag: true,
            ..base
        },
        ShiftStepStatement {
            destination_tag: true,
            ..base
        },
        ShiftStepStatement {
            left_tag_after: true,
            ..base
        },
        ShiftStepStatement {
            amount_tag_after: true,
            ..base
        },
    ] {
        assert!(statement.validate().is_err());
        assert_rejected(statement);
    }
}

fn columns(statement: ShiftStepStatement) -> Vec<Vec<F>> {
    let mut columns = vec![vec![F::ZERO; TRACE_SIZE]; NOTE_COPY_WIDTH_V1];
    columns.extend(
        statement
            .witness()
            .into_iter()
            .map(|value| vec![value; TRACE_SIZE]),
    );
    columns
}

#[test]
fn native_stark_proves_shift_sign_fill_and_rejects_changed_statement_or_stage() {
    let statement = interpreter_statement(
        ivm::encoding::wide::encode_rr(wide::arithmetic::SRA, 1, 1, 2),
        0x8000_1234_5678_9abc,
        0xffff_ffff_ffff_ffff,
    );
    let adapter = ShiftStepAdapter(statement);
    adapter.protocol_v1().validate().unwrap();
    let proof = prove_proof_managed_note_stark_v1(&adapter, &columns(statement)).unwrap();
    verify_proof_managed_note_stark_v1(&adapter, &proof).unwrap();
    for changed in [
        ShiftStepStatement {
            result: statement.result ^ 1,
            destination_after: statement.destination_after ^ 1,
            left_after: statement.left_after ^ 1,
            ..statement
        },
        ShiftStepStatement {
            amount: 62,
            amount_after: 62,
            ..statement
        },
        ShiftStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SRL, 1, 1, 2),
            ..statement
        },
        ShiftStepStatement {
            after_gas: statement.after_gas - 1,
            ..statement
        },
    ] {
        assert!(verify_proof_managed_note_stark_v1(&ShiftStepAdapter(changed), &proof).is_err());
    }
    let mut forged_columns = columns(statement);
    forged_columns[NOTE_COPY_WIDTH_V1 + STAGE_OFFSET + WORD_BITS + 63][0] = F::ZERO;
    assert!(prove_proof_managed_note_stark_v1(&adapter, &forged_columns).is_err());
}

#[test]
fn shared_shift_appends_original_residues_and_fixed_position_digit_witnesses() {
    for opcode in REGISTER_OPCODES.into_iter().chain(IMMEDIATE_OPCODES) {
        let kind = ShiftKind::from_word(ivm::encoding::wide::encode_rr(opcode, 3, 1, 2)).unwrap();
        for amount in (0..256).chain([u64::MAX, 0x1234_5678_9abc_def0]) {
            let left = 0x8000_1234_5678_9abc;
            let bank = bank_witness(opcode, left, amount);
            for stage in 0..STAGES {
                let digit = (amount >> (2 * stage)) & 3;
                for position in 0..4 {
                    assert_eq!(
                        bank[SELECTORS + 4 * stage + position],
                        F(u64::from(position as u64 == digit))
                    );
                }
            }
            let bits = word::witness(left, amount);
            let sources = Sources::new(&bits);
            let kinds = kind_selectors(kind);
            let mut appended = vec![F(0x4321)];
            append_bank_residues(&mut appended, &bank, sources, kinds);
            assert_eq!(appended[0], F(0x4321));
            assert_eq!(appended.len(), 1 + BANK_CONSTRAINTS);
            assert!(appended[1..].iter().all(|value| *value == F::ZERO));
            assert_eq!(appended[1..], bank_residues(&bank, sources, kinds));
        }
    }
}

#[test]
fn shared_shift_bank_with_private_kind_selectors_has_degree_three() {
    let measured = measured_maximum_affine_degree_v1(
        [0x57; 32],
        [BANK_WIDTH + word::WIDTH + 4, 0, 0, 0, 0],
        8,
        MAXIMUM_DEGREE,
        |row, _, _, _, _| {
            let sources = Sources::new(&row[BANK_WIDTH..BANK_WIDTH + word::WIDTH]);
            let selected = &row[BANK_WIDTH + word::WIDTH..];
            let kinds = [
                F::ONE.sub(selected.iter().copied().fold(F::ZERO, F::add)),
                selected[0],
                selected[1],
                selected[2],
                selected[3],
            ];
            let mut out = Vec::new();
            sources.append_residues(&mut out);
            append_bank_residues(&mut out, &row[..BANK_WIDTH], sources, kinds);
            Ok::<_, core::convert::Infallible>(out)
        },
    );
    assert_eq!(measured, 3);
}
