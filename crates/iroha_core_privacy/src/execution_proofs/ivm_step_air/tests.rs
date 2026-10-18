//! Focused interpreter and native-STARK checks for the public ALU chip.

use super::*;
use crate::execution_proofs::stark::proof_managed_note_stark::{
    prove_proof_managed_note_stark_v1, verify_proof_managed_note_stark_v1,
};

fn statement() -> AluStepStatement {
    AluStepStatement {
        word: ivm::encoding::wide::encode_rr(wide::arithmetic::ADD, 3, 1, 2),
        before_pc: 40,
        after_pc: 44,
        before_gas: 100,
        after_gas: 99,
        before_cycles: 7,
        after_cycles: 8,
        left: u64::MAX,
        right: 2,
        result: 1,
        destination_after: 1,
        left_tag: false,
        right_tag: false,
        result_tag: false,
    }
}

fn sub_statement() -> AluStepStatement {
    AluStepStatement {
        word: ivm::encoding::wide::encode_rr(wide::arithmetic::SUB, 3, 1, 2),
        left: 0,
        right: 1,
        result: u64::MAX,
        destination_after: u64::MAX,
        ..statement()
    }
}

fn expected_result(opcode: u8, left: u64, right: u64) -> u64 {
    match opcode {
        wide::arithmetic::ADD => left.wrapping_add(right),
        wide::arithmetic::SUB => left.wrapping_sub(right),
        wide::arithmetic::AND => left & right,
        wide::arithmetic::OR => left | right,
        wide::arithmetic::XOR => left ^ right,
        _ => panic!("unsupported test opcode {opcode}"),
    }
}

fn bitwise_statement(opcode: u8, left: u64, right: u64) -> AluStepStatement {
    let result = expected_result(opcode, left, right);
    AluStepStatement {
        word: ivm::encoding::wide::encode_rr(opcode, 3, 1, 2),
        left,
        right,
        result,
        destination_after: result,
        ..statement()
    }
}

fn columns(statement: AluStepStatement) -> Vec<Vec<F>> {
    let row = statement.witness();
    let mut columns = vec![vec![F::ZERO; TRACE_SIZE]; NOTE_COPY_WIDTH_V1];
    columns.extend(row.into_iter().map(|value| vec![value; TRACE_SIZE]));
    columns
}

#[test]
fn admitted_add_wraps_full_width_with_zero_air_residues() {
    for (left, right) in [
        (0, 0),
        (u64::MAX, 1),
        (u64::MAX, 2),
        (0xffff_0000_ffff_0000, 0x0001_ffff_0001_ffff),
    ] {
        let statement = AluStepStatement {
            left,
            right,
            result: left.wrapping_add(right),
            destination_after: left.wrapping_add(right),
            ..statement()
        };
        statement.validate().unwrap();
        let residuals = residues(&statement.witness(), &statement.fixed()).unwrap();
        assert_eq!(residuals.len(), CONSTRAINT_COUNT);
        assert!(residuals.iter().all(|residual| *residual == F::ZERO));
    }
}

#[test]
fn admitted_sub_wraps_full_width_with_zero_air_residues() {
    for (left, right) in [
        (0, 0),
        (0, 1),
        (u64::MAX, u64::MAX),
        (i64::cast_unsigned(i64::MIN), 1),
        (i64::MAX as u64, u64::MAX),
        (0x0001_0000_0000_0000, 1),
        (0x0000_0000_0000_0001, 0x0001_0000_0000_0000),
    ] {
        let result = left.wrapping_sub(right);
        let statement = AluStepStatement {
            word: ivm::encoding::wide::encode_rr(wide::arithmetic::SUB, 3, 1, 2),
            left,
            right,
            result,
            destination_after: result,
            ..statement()
        };
        statement.validate().unwrap();
        let residuals = residues(&statement.witness(), &statement.fixed()).unwrap();
        assert_eq!(residuals.len(), CONSTRAINT_COUNT);
        assert!(residuals.iter().all(|residual| *residual == F::ZERO));
    }
}

#[test]
fn bitwise_truth_tables_and_full_width_patterns_have_zero_air_residues() {
    for opcode in [
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
    ] {
        for left in 0..4 {
            for right in 0..4 {
                let statement = bitwise_statement(opcode, left, right);
                statement.validate().unwrap();
                let residuals = residues(&statement.witness(), &statement.fixed()).unwrap();
                assert_eq!(residuals.len(), CONSTRAINT_COUNT);
                assert!(
                    residuals.iter().all(|residual| *residual == F::ZERO),
                    "opcode={opcode}, left={left}, right={right}"
                );
            }
        }
        for (left, right) in [
            (0, u64::MAX),
            (u64::MAX, u64::MAX),
            (0xaaaa_aaaa_aaaa_aaaa, 0xcccc_cccc_cccc_cccc),
            (0x5555_5555_5555_5555, 0x3333_3333_3333_3333),
            (1_u64 << 63, u64::MAX),
        ] {
            let statement = bitwise_statement(opcode, left, right);
            assert!(
                residues(&statement.witness(), &statement.fixed())
                    .unwrap()
                    .iter()
                    .all(|residual| *residual == F::ZERO),
                "opcode={opcode}, left={left}, right={right}"
            );
        }
    }
}

#[test]
fn immediate_operands_are_exact_signed_eight_bit_words() {
    for opcode in [
        wide::arithmetic::ADDI,
        wide::arithmetic::ANDI,
        wide::arithmetic::ORI,
        wide::arithmetic::XORI,
    ] {
        for imm in [i8::MIN, -1, 0, 1, i8::MAX] {
            let word = ivm::encoding::wide::encode_ri(opcode, 3, 1, imm);
            assert_eq!(
                immediate_operand(word),
                Some(i64::cast_unsigned(i64::from(imm)))
            );
            assert_eq!(gas::cost_of(word), Some(1));
            let statement = AluStepStatement {
                word,
                right: i64::cast_unsigned(i64::from(imm)),
                ..statement()
            };
            assert!(statement.validate().is_ok());
            for wrong in [
                u64::from(i8::cast_unsigned(imm)),
                i64::cast_unsigned(i64::from(imm)) ^ (1_u64 << 63),
            ] {
                if wrong != statement.right {
                    assert!(
                        AluStepStatement {
                            right: wrong,
                            ..statement
                        }
                        .validate()
                        .is_err()
                    );
                }
            }
            assert!(matches!(
                semantic_opcode(opcode),
                wide::arithmetic::ADD
                    | wide::arithmetic::AND
                    | wide::arithmetic::OR
                    | wide::arithmetic::XOR
            ));
        }
    }
    assert_eq!(
        semantic_opcode(wide::arithmetic::SUB),
        wide::arithmetic::SUB
    );
    assert_eq!(immediate_operand(statement().word), None);
}

#[test]
fn immediate_alu_full_width_results_and_zero_register_shapes_satisfy_air() {
    for opcode in [
        wide::arithmetic::ADDI,
        wide::arithmetic::ANDI,
        wide::arithmetic::ORI,
        wide::arithmetic::XORI,
    ] {
        for left in [
            0,
            1,
            u64::MAX,
            i64::cast_unsigned(i64::MIN),
            0xaaaa_5555_ffff_0000,
        ] {
            for imm in [i8::MIN, -1, 0, 1, i8::MAX] {
                let right = i64::cast_unsigned(i64::from(imm));
                let result = expected_result(semantic_opcode(opcode), left, right);
                let instance = AluStepStatement {
                    word: ivm::encoding::wide::encode_ri(opcode, 3, 1, imm),
                    left,
                    right,
                    result,
                    destination_after: result,
                    ..statement()
                };
                instance.validate().unwrap();
                assert!(
                    residues(&instance.witness(), &instance.fixed())
                        .unwrap()
                        .iter()
                        .all(|residual| *residual == F::ZERO),
                    "opcode={opcode}, left={left:#x}, imm={imm}"
                );
            }
        }
    }
    for opcode in [
        wide::arithmetic::ADDI,
        wide::arithmetic::ANDI,
        wide::arithmetic::ORI,
        wide::arithmetic::XORI,
    ] {
        for (rd, rs1) in [(3, 1), (1, 1), (4, 4), (3, 0), (0, 1), (0, 0)] {
            for imm in [i8::MIN, -1, 0, 1, i8::MAX] {
                let instance = diagnostic_immediate_statement(opcode, rd, rs1, imm);
                assert_eq!(
                    instance.destination_after,
                    if rd == 0 { 0 } else { instance.result }
                );
                instance.validate().unwrap();
                assert!(
                    residues(&instance.witness(), &instance.fixed())
                        .unwrap()
                        .iter()
                        .all(|residual| *residual == F::ZERO),
                    "interpreter opcode={opcode}, rd={rd}, rs1={rs1}, imm={imm}"
                );
            }
        }
    }
}

#[test]
fn forged_immediate_operand_result_and_destination_fail_the_relation() {
    for opcode in [
        wide::arithmetic::ADDI,
        wide::arithmetic::ANDI,
        wide::arithmetic::ORI,
        wide::arithmetic::XORI,
    ] {
        let instance = diagnostic_immediate_statement(opcode, 4, 4, -1);
        let forged_operand = AluStepStatement {
            right: 1,
            ..instance
        };
        assert!(forged_operand.validate().is_err());
        let changed_word = AluStepStatement {
            word: ivm::encoding::wide::encode_ri(opcode, 4, 4, i8::MIN),
            ..instance
        };
        assert!(changed_word.validate().is_err());
        assert_ne!(instance.fixed(), changed_word.fixed());
        let fixed = instance.fixed();
        for changed in [LIMB_OFFSET + 4, LIMB_OFFSET + 8, POST_OFFSET] {
            let mut row = instance.witness();
            row[changed] = row[changed].add(F::ONE);
            assert!(
                residues(&row, &fixed)
                    .unwrap()
                    .iter()
                    .any(|residual| *residual != F::ZERO),
                "unconstrained immediate opcode={opcode} column={changed}"
            );
        }
        let forged_result = AluStepStatement {
            result: instance.result ^ 1,
            destination_after: instance.destination_after ^ 1,
            ..instance
        };
        assert!(
            residues(&forged_result.witness(), &forged_result.fixed())
                .unwrap()
                .iter()
                .any(|residual| *residual != F::ZERO),
            "self-consistent false result for opcode={opcode}"
        );
    }
}

fn diagnostic_statement(opcode: u8, rd: u8, rs1: u8, rs2: u8) -> AluStepStatement {
    diagnostic_step_statement(ivm::encoding::wide::encode_rr(opcode, rd, rs1, rs2))
}

fn diagnostic_immediate_statement(opcode: u8, rd: u8, rs1: u8, imm: i8) -> AluStepStatement {
    diagnostic_step_statement(ivm::encoding::wide::encode_ri(opcode, rd, rs1, imm))
}

fn diagnostic_step_statement(word: u32) -> AluStepStatement {
    use iroha_allocation::AllocationBudget;
    use ivm::{
        IVM,
        execution_step_recorder::{DiagnosticStepRecord, DiagnosticStepRecorder},
        host::DefaultHost,
    };

    let instructions = [
        ivm::encoding::wide::encode_ri(wide::arithmetic::ADDI, 1, 0, 2),
        ivm::encoding::wide::encode_ri(wide::arithmetic::ADDI, 2, 0, 3),
        ivm::encoding::wide::encode_ri(wide::arithmetic::ADDI, 3, 0, 5),
        word,
        ivm::encoding::wide::encode_halt(),
    ];
    let code = instructions
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let budget = AllocationBudget::new(5 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(5, &budget).unwrap();
    let mut vm = IVM::new(1_000);
    vm.load_code(&code).unwrap();
    vm.set_register(4, u64::MAX);
    vm.set_zk_mode(true)
        .expect("private lifecycle cleanup succeeds");
    // ZK padding is metered, so keep this local diagnostic horizon finite.
    vm.set_max_cycles(8);
    vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder)
        .unwrap();
    let step = &recorder.records()[3];
    assert_eq!(step.opcode_gas, Some(1));
    assert_eq!(
        step.outcome,
        ivm::execution_step_recorder::DiagnosticStepOutcome::Completed
    );
    let (rd, rs1, rs2) = (wide::rd(word), wide::rs1(word), wide::rs2(word));
    let left = step.before.registers[rs1];
    let right = immediate_operand(word).unwrap_or(step.before.registers[rs2]);
    for index in 0..256 {
        if index != rd || rd == 0 {
            assert_eq!(step.before.registers[index], step.after.registers[index]);
            assert_eq!(step.before.tags[index], step.after.tags[index]);
        }
    }
    AluStepStatement {
        word: step.instruction.unwrap(),
        before_pc: step.before.pc.try_into().unwrap(),
        after_pc: step.after.pc.try_into().unwrap(),
        before_gas: step.before.gas_remaining.try_into().unwrap(),
        after_gas: step.after.gas_remaining.try_into().unwrap(),
        before_cycles: step.before.cycles.try_into().unwrap(),
        after_cycles: step.after.cycles.try_into().unwrap(),
        left,
        right,
        result: expected_result(semantic_opcode(wide::opcode(word)), left, right),
        destination_after: step.after.registers[rd],
        left_tag: step.before.tags[rs1],
        right_tag: if immediate_operand(word).is_some() {
            false
        } else {
            step.before.tags[rs2]
        },
        result_tag: step.after.tags[rd],
    }
}

#[test]
fn diagnostic_interpreter_alu_shapes_satisfy_the_same_air() {
    // Every equality pattern among rd, rs1, and rs2 is represented,
    // including each position occupied by the hardwired zero register.
    for (opcode, rd, rs1, rs2) in [
        wide::arithmetic::ADD,
        wide::arithmetic::SUB,
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
    ]
    .into_iter()
    .flat_map(|opcode| {
        [
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
        ]
        .into_iter()
        .map(move |(rd, rs1, rs2)| (opcode, rd, rs1, rs2))
    }) {
        let statement = diagnostic_statement(opcode, rd, rs1, rs2);
        assert_eq!(
            statement.destination_after,
            if rd == 0 { 0 } else { statement.result }
        );
        statement.validate().unwrap();
        assert!(
            residues(&statement.witness(), &statement.fixed())
                .unwrap()
                .iter()
                .all(|residual| *residual == F::ZERO),
            "arithmetic opcode={opcode}, rd={rd}, rs1={rs1}, rs2={rs2}"
        );
    }
}

#[test]
fn forged_add_and_sub_result_transfer_digit_tag_gas_and_pc_fail_the_polynomial_relation() {
    for statement in [statement(), sub_statement()] {
        let fixed = statement.fixed();
        for changed in [
            LIMB_OFFSET + 8,
            POST_OFFSET,
            TRANSFER_OFFSET,
            DIGIT_OFFSET,
            TAG_OFFSET + 2,
            1,
            3,
        ] {
            let mut row = statement.witness();
            row[changed] = row[changed].add(F::ONE);
            assert!(
                residues(&row, &fixed)
                    .unwrap()
                    .iter()
                    .any(|residual| *residual != F::ZERO),
                "unconstrained opcode={} row column {changed}",
                wide::opcode(statement.word)
            );
        }
    }
}

#[test]
fn forged_boolean_borrow_fails_subtraction_equation() {
    let statement = sub_statement();
    let mut row = statement.witness();
    assert_eq!(row[TRANSFER_OFFSET], F::ONE);
    row[TRANSFER_OFFSET] = F::ZERO;
    assert_eq!(bit(row[TRANSFER_OFFSET]), F::ZERO);
    assert!(
        residues(&row, &statement.fixed())
            .unwrap()
            .iter()
            .any(|residual| *residual != F::ZERO)
    );
}

#[test]
fn forged_shared_source_bits_and_inactive_transfers_fail_the_polynomial_relation() {
    for opcode in [
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
    ] {
        let statement = bitwise_statement(opcode, 3, 1);
        let fixed = statement.fixed();
        let mut row = statement.witness();
        assert_eq!(row[SOURCE_OFFSET], F::ONE);
        row[SOURCE_OFFSET] = F::ZERO;
        assert_eq!(bit(row[SOURCE_OFFSET]), F::ZERO);
        assert!(
            residues(&row, &fixed)
                .unwrap()
                .iter()
                .any(|residual| *residual != F::ZERO),
            "forged Boolean low bit for opcode {opcode}"
        );

        let mut row = statement.witness();
        row[TRANSFER_OFFSET] = F::ONE;
        assert_eq!(bit(row[TRANSFER_OFFSET]), F::ZERO);
        assert!(
            residues(&row, &fixed)
                .unwrap()
                .iter()
                .any(|residual| *residual != F::ZERO),
            "inactive transfer for opcode {opcode}"
        );
    }
    let statement = statement();
    let mut row = statement.witness();
    row[SOURCE_OFFSET] = F::ZERO;
    assert!(
        residues(&row, &statement.fixed())
            .unwrap()
            .iter()
            .any(|residual| *residual != F::ZERO),
        "ADD source bits must remain bound even outside bitwise dispatch"
    );
}

#[test]
fn self_consistent_public_rows_still_require_alu_and_control_equations() {
    for valid in [
        statement(),
        sub_statement(),
        bitwise_statement(wide::arithmetic::AND, 3, 1),
        bitwise_statement(wide::arithmetic::OR, 2, 1),
        bitwise_statement(wide::arithmetic::XOR, 3, 1),
    ] {
        for changed in [
            AluStepStatement {
                result: valid.result ^ 1,
                ..valid
            },
            AluStepStatement {
                destination_after: valid.destination_after ^ 1,
                ..valid
            },
            AluStepStatement {
                after_pc: 48,
                ..valid
            },
            AluStepStatement {
                after_gas: 98,
                ..valid
            },
            AluStepStatement {
                after_cycles: 9,
                ..valid
            },
        ] {
            let row = changed.witness();
            let fixed = changed.fixed();
            assert_eq!(&row[..PUBLIC_WIDTH], &fixed[..PUBLIC_WIDTH]);
            assert!(
                residues(&row, &fixed)
                    .unwrap()
                    .iter()
                    .any(|residual| *residual != F::ZERO)
            );
        }
    }
}

#[test]
fn forged_alias_and_zero_register_shapes_fail_the_polynomial_relation() {
    for (opcode, base) in [
        (wide::arithmetic::ADD, statement()),
        (
            wide::arithmetic::SUB,
            AluStepStatement {
                left: 2,
                right: 3,
                result: u64::MAX,
                destination_after: u64::MAX,
                ..sub_statement()
            },
        ),
        (
            wide::arithmetic::AND,
            bitwise_statement(wide::arithmetic::AND, 3, 1),
        ),
        (
            wide::arithmetic::OR,
            bitwise_statement(wide::arithmetic::OR, 2, 1),
        ),
        (
            wide::arithmetic::XOR,
            bitwise_statement(wide::arithmetic::XOR, 3, 1),
        ),
    ] {
        for forged in [
            AluStepStatement {
                word: ivm::encoding::wide::encode_rr(opcode, 3, 1, 1),
                ..base
            },
            AluStepStatement {
                word: ivm::encoding::wide::encode_rr(opcode, 3, 0, 2),
                ..base
            },
            AluStepStatement {
                word: ivm::encoding::wide::encode_rr(opcode, 3, 1, 0),
                ..base
            },
            AluStepStatement {
                word: ivm::encoding::wide::encode_rr(opcode, 0, 1, 2),
                ..base
            },
            AluStepStatement {
                word: ivm::encoding::wide::encode_rr(opcode, 1, 1, 2),
                destination_after: base.left,
                ..base
            },
        ] {
            forged.validate().unwrap();
            let fixed = forged.fixed();
            let row = forged.witness();
            assert_eq!(&row[..PUBLIC_WIDTH], &fixed[..PUBLIC_WIDTH]);
            assert!(
                residues(&row, &fixed)
                    .unwrap()
                    .iter()
                    .any(|residual| *residual != F::ZERO),
                "forged ALU word {:#010x}",
                forged.word
            );
        }
    }
}

#[test]
fn invalid_opcode_secret_tag_and_unaligned_pc_are_not_profile_instances() {
    let mut candidate = statement();
    candidate.word = ivm::encoding::wide::encode_rr(wide::arithmetic::SLL, 3, 1, 2);
    assert!(candidate.validate().is_err());
    for opcode in [
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
    ] {
        candidate = AluStepStatement {
            left_tag: true,
            ..bitwise_statement(opcode, 3, 1)
        };
        assert!(candidate.validate().is_err());
        candidate = AluStepStatement {
            right_tag: true,
            ..bitwise_statement(opcode, 3, 1)
        };
        assert!(candidate.validate().is_err());
    }
    candidate = AluStepStatement {
        left_tag: true,
        ..statement()
    };
    assert!(candidate.validate().is_err());
    candidate = AluStepStatement {
        right_tag: true,
        ..statement()
    };
    assert!(candidate.validate().is_err());
    candidate = AluStepStatement {
        word: ivm::encoding::wide::encode_rr(wide::arithmetic::ADD, 0, 1, 2),
        result_tag: true,
        ..statement()
    };
    assert!(candidate.validate().is_err());
    candidate = AluStepStatement {
        before_pc: 41,
        after_pc: 45,
        ..statement()
    };
    assert!(candidate.validate().is_err());
}

#[test]
fn native_stark_checks_add_relation_and_statement_mutations() {
    let statement = statement();
    let adapter = AluStepAdapter(statement);
    let proof = prove_proof_managed_note_stark_v1(&adapter, &columns(statement)).unwrap();
    verify_proof_managed_note_stark_v1(&adapter, &proof).unwrap();
    for mutated in [
        AluStepStatement {
            result: 2,
            ..statement
        },
        AluStepStatement {
            destination_after: 2,
            ..statement
        },
        AluStepStatement {
            after_gas: 98,
            ..statement
        },
        AluStepStatement {
            after_pc: 48,
            ..statement
        },
    ] {
        assert!(verify_proof_managed_note_stark_v1(&AluStepAdapter(mutated), &proof).is_err());
    }
    let mut bad_columns = columns(statement);
    bad_columns[NOTE_COPY_WIDTH_V1 + LIMB_OFFSET + 8][0] = F(2);
    assert!(prove_proof_managed_note_stark_v1(&adapter, &bad_columns).is_err());
}

#[test]
fn native_stark_accepts_alias_and_r0_shapes_and_rejects_forged_shape_proofs() {
    let add = wide::arithmetic::ADD;
    let alias = diagnostic_statement(add, 1, 1, 1);
    let r0 = diagnostic_statement(add, 0, 1, 2);
    for admitted in [alias, r0] {
        let adapter = AluStepAdapter(admitted);
        let proof = prove_proof_managed_note_stark_v1(&adapter, &columns(admitted)).unwrap();
        verify_proof_managed_note_stark_v1(&adapter, &proof).unwrap();
        let mutated = AluStepStatement {
            word: ivm::encoding::wide::encode_rr(add, 3, 1, 2),
            ..admitted
        };
        assert!(verify_proof_managed_note_stark_v1(&AluStepAdapter(mutated), &proof).is_err());
    }

    let forged = AluStepStatement {
        word: ivm::encoding::wide::encode_rr(add, 0, 1, 2),
        ..statement()
    };
    assert!(prove_proof_managed_note_stark_v1(&AluStepAdapter(forged), &columns(forged)).is_err());
}

#[test]
fn native_stark_accepts_interpreter_sub_alias_and_r0_and_rejects_forged_subtraction() {
    let sub = wide::arithmetic::SUB;
    for admitted in [
        diagnostic_statement(sub, 1, 1, 1),
        diagnostic_statement(sub, 0, 1, 2),
    ] {
        let adapter = AluStepAdapter(admitted);
        let proof = prove_proof_managed_note_stark_v1(&adapter, &columns(admitted)).unwrap();
        verify_proof_managed_note_stark_v1(&adapter, &proof).unwrap();
        let mut wrong_opcode = admitted;
        wrong_opcode.word = ivm::encoding::wide::encode_rr(
            wide::arithmetic::ADD,
            wide::rd(admitted.word) as u8,
            wide::rs1(admitted.word) as u8,
            wide::rs2(admitted.word) as u8,
        );
        assert!(verify_proof_managed_note_stark_v1(&AluStepAdapter(wrong_opcode), &proof).is_err());
    }

    let forged = AluStepStatement {
        result: 0,
        destination_after: 0,
        ..sub_statement()
    };
    assert!(prove_proof_managed_note_stark_v1(&AluStepAdapter(forged), &columns(forged)).is_err());
}

#[test]
fn native_stark_accepts_interpreter_bitwise_family_and_rejects_forged_witness() {
    for (opcode, rd, rs1, rs2, wrong_opcode) in [
        (wide::arithmetic::AND, 2, 1, 2, wide::arithmetic::OR),
        (wide::arithmetic::OR, 0, 1, 2, wide::arithmetic::XOR),
        (wide::arithmetic::XOR, 3, 1, 1, wide::arithmetic::AND),
    ] {
        let admitted = diagnostic_statement(opcode, rd, rs1, rs2);
        let adapter = AluStepAdapter(admitted);
        let proof = prove_proof_managed_note_stark_v1(&adapter, &columns(admitted)).unwrap();
        verify_proof_managed_note_stark_v1(&adapter, &proof).unwrap();
        let wrong_opcode_statement = AluStepStatement {
            word: ivm::encoding::wide::encode_rr(wrong_opcode, rd, rs1, rs2),
            ..admitted
        };
        assert!(
            verify_proof_managed_note_stark_v1(&AluStepAdapter(wrong_opcode_statement), &proof)
                .is_err()
        );
    }

    let admitted = bitwise_statement(wide::arithmetic::AND, 3, 1);
    let mut forged_columns = columns(admitted);
    assert_eq!(
        forged_columns[NOTE_COPY_WIDTH_V1 + SOURCE_OFFSET][0],
        F::ONE
    );
    forged_columns[NOTE_COPY_WIDTH_V1 + SOURCE_OFFSET][0] = F::ZERO;
    assert!(prove_proof_managed_note_stark_v1(&AluStepAdapter(admitted), &forged_columns).is_err());
}

#[test]
fn native_stark_checks_interpreter_immediate_arithmetic_and_bitwise_relations() {
    // Both semantic equations use the immediate decoded from the public word.
    // The other two bitwise-immediate selectors share the same Boolean chip.
    for opcode in [wide::arithmetic::ADDI, wide::arithmetic::XORI] {
        let admitted = diagnostic_immediate_statement(opcode, 4, 4, i8::MIN);
        let adapter = AluStepAdapter(admitted);
        let proof = prove_proof_managed_note_stark_v1(&adapter, &columns(admitted)).unwrap();
        verify_proof_managed_note_stark_v1(&adapter, &proof).unwrap();

        for invalid in [
            AluStepStatement {
                right: i8::MAX as u64,
                ..admitted
            },
            AluStepStatement {
                word: ivm::encoding::wide::encode_ri(opcode, 4, 4, i8::MAX),
                right: i8::MAX as u64,
                ..admitted
            },
            AluStepStatement {
                after_gas: admitted.after_gas - 1,
                ..admitted
            },
        ] {
            assert!(verify_proof_managed_note_stark_v1(&AluStepAdapter(invalid), &proof).is_err());
        }
        let mut forged_columns = columns(admitted);
        forged_columns[NOTE_COPY_WIDTH_V1 + LIMB_OFFSET + 4][0] = F::ZERO;
        assert!(prove_proof_managed_note_stark_v1(&adapter, &forged_columns).is_err());
    }
}
