//! Native conditional-branch captures on the original private dispatcher ports.

use super::*;

const OPCODES: [u8; 6] = [
    wide::control::BEQ,
    wide::control::BNE,
    wide::control::BLT,
    wide::control::BGE,
    wide::control::BLTU,
    wide::control::BGEU,
];

fn capture(
    body: &[u32],
    inputs: &[(usize, u64, bool)],
    gas: u64,
    cycle_limit: u64,
) -> (Program, DiagnosticStepRecorder, Result<(), ivm::VMError>) {
    let program = Program::new(contract(body, cycle_limit, ivm::ivm_mode::ZK)).unwrap();
    let mut vm = IVM::new(gas);
    vm.load_prepared(program.artifact()).unwrap();
    for &(register, value, tag) in inputs {
        vm.set_register(register, value);
        vm.registers.set_tag(register, tag);
    }
    let budget = AllocationBudget::new(64 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(64, &budget).unwrap();
    let outcome = vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
    (program, recorder, outcome)
}

fn first_branch(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let prefix = usize::try_from((-i16::from(wide::imm8(instruction))).max(0)).unwrap();
    let mut body = vec![enc::encode_ri(wide::arithmetic::ADDI, 0, 0, 0); prefix];
    body.push(instruction);
    let (program, recorder, _later_outcome) = capture(&body, inputs, 16, 32);
    let record = recorder
        .records()
        .get(prefix)
        .expect("native branch attempt");
    assert_eq!(record.instruction, Some(instruction));
    assert_eq!(record.opcode_gas, Some(1));
    assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
    assert_eq!(record.before.registers, record.after.registers);
    assert_eq!(record.before.tags, record.after.tags);
    assert_eq!(record.changed_registers().count(), 0);
    assert_eq!(record.after.gas_remaining + 1, record.before.gas_remaining);
    assert_eq!(record.after.cycles, record.before.cycles + 1);
    assert!(!record.after.halted);
    let fixture = ScalarFixture::from_record(&program, record);
    assert!(fixture.accepts(&program));
    assert!(
        fixture.0.packets.fields[SCALAR_DESTINATION]
            .iter()
            .all(|cell| *cell == F::ZERO)
    );
    (program, fixture)
}

#[test]
fn native_private_fetch_branches_cover_all_predicates_offsets_aliases_and_r0() {
    let pairs = [
        (0, 0),
        (0, 1),
        (1, 0),
        (u64::MAX, 0),
        (0, u64::MAX),
        (u64::MAX, u64::MAX),
        (i64::cast_unsigned(i64::MIN), i64::MAX as u64),
        (i64::MAX as u64, i64::cast_unsigned(i64::MIN)),
        (0xffff_ffff_0000_0001, 0),
        (0, 0xffff_ffff_0000_0001),
        (0x1234_ffff_0000_0001, 0x1234_0000_ffff_0001),
    ];
    for opcode in OPCODES {
        for (left, right) in pairs {
            for offset in [-2, -1, 0, 1, 2, 4] {
                first_branch(
                    enc::encode_branch(opcode, 2, 3, offset),
                    &[(2, left, false), (3, right, false)],
                );
            }
        }
        for (left, right) in [(2, 2), (0, 0), (0, 3), (2, 0), (255, 254)] {
            first_branch(
                enc::encode_branch(opcode, left, right, 2),
                &[
                    (2, u64::MAX, false),
                    (3, 1, false),
                    (255, i64::cast_unsigned(i64::MIN), false),
                    (254, i64::MAX as u64, false),
                ],
            );
        }
    }
}

#[test]
fn native_branch_rejects_either_private_tag_even_when_tags_match() {
    for opcode in OPCODES {
        for (left_tag, right_tag) in [(true, false), (false, true), (true, true)] {
            let instruction = enc::encode_branch(opcode, 2, 3, 2);
            let (_, recorder, outcome) = capture(
                &[instruction],
                &[(2, 17, left_tag), (3, 23, right_tag)],
                16,
                32,
            );
            assert!(matches!(outcome, Err(ivm::VMError::PrivacyViolation)));
            let record = &recorder.records()[0];
            assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
            assert_eq!(record.after.pc, record.before.pc);
            assert_eq!(record.after.cycles, record.before.cycles);
            assert_eq!(record.after.registers, record.before.registers);
            assert_eq!(record.after.tags, record.before.tags);
            assert_eq!(record.after.gas_remaining + 1, record.before.gas_remaining);
            let (program, mut forged) =
                first_branch(instruction, &[(2, 17, false), (3, 23, false)]);
            for (slot, tag) in [(SCALAR_LEFT, left_tag), (SCALAR_RIGHT, right_tag)] {
                forged.0.packets.fields[slot][BEFORE_TAG] = F(u64::from(tag));
                forged.0.packets.fields[slot][AFTER_TAG] = F(u64::from(tag));
            }
            assert!(!forged.accepts(&program));
        }
    }
}

#[test]
fn every_branch_original_field_and_workspace_mutation_rejects() {
    for opcode in OPCODES {
        let (program, fixture) = first_branch(
            enc::encode_branch(opcode, 2, 3, 2),
            &[(2, u64::MAX, false), (3, 0, false)],
        );
        for slot in 0..PORTS {
            for column in 0..packet::WIDTH {
                let mut bad = fixture.clone();
                bad.0.packets.fields[slot][column] = bad.0.packets.fields[slot][column].add(F::ONE);
                assert!(
                    !bad.accepts(&program),
                    "opcode {opcode} slot {slot} column {column}"
                );
            }
        }
        for column in 0..super::super::super::WIDTH {
            let mut bad = fixture.clone();
            bad.0.row[column] = bad.0.row[column].add(F::ONE);
            assert!(!bad.accepts(&program), "opcode {opcode} workspace {column}");
        }
    }
}

#[test]
fn branch_fetch_predicate_register_offset_zero_and_modular_alias_forgery_reject() {
    let instruction = enc::encode_branch(wide::control::BEQ, 2, 3, 2);
    let (program, fixture) = first_branch(instruction, &[(2, 17, false), (3, 17, false)]);
    for replacement in [
        enc::encode_branch(wide::control::BNE, 2, 3, 2),
        enc::encode_branch(wide::control::BEQ, 3, 2, 2),
        enc::encode_branch(wide::control::BEQ, 2, 2, 2),
        enc::encode_branch(wide::control::BEQ, 2, 3, 3),
        enc::encode_rr(wide::arithmetic::SEQ, 2, 3, 2),
    ] {
        let changed = Program::new(contract(&[replacement], 32, ivm::ivm_mode::ZK)).unwrap();
        assert!(!fixture.accepts(&changed));
    }
    let mut bad = fixture.clone();
    bad.0.row[FETCH] = F::ZERO;
    bad.0.row[FETCH + 1] = F::ONE;
    assert!(!bad.accepts(&program));
    let (program, mut reduced) = first_branch(
        instruction,
        &[(2, 0xffff_ffff_0000_0001, false), (3, 0, false)],
    );
    reduced.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
        .copy_from_slice(&branch::bank_witness(wide::control::BEQ, 0, 0));
    for limb in 0..4 {
        reduced.0.packets.fields[PC_WRITE][AFTER + limb] =
            constant_limb(u64::from(program.first_pc) + 8, limb);
    }
    assert!(!reduced.accepts(&program));
    let (program, mut zero) = first_branch(enc::encode_branch(wide::control::BEQ, 0, 0, 2), &[]);
    for slot in [SCALAR_LEFT, SCALAR_RIGHT] {
        zero.0.packets.fields[slot][BEFORE] = F::ONE;
        zero.0.packets.fields[slot][AFTER] = F::ONE;
    }
    zero.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(1, 1));
    fill_product(&mut zero.0, 1, 1);
    zero.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
        wide::arithmetic::ADD,
        1,
        1,
    ));
    zero.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS].copy_from_slice(&branch::bank_witness(
        wide::control::BEQ,
        1,
        1,
    ));
    zero.0.row[SCALAR + SHIFT..super::super::super::WIDTH].copy_from_slice(&shift::bank_witness(
        wide::arithmetic::SLL,
        1,
        1,
    ));
    assert!(!zero.accepts(&program));
}

#[test]
fn branch_gas_cycle_underflow_and_false_halt_cannot_form_successful_rows() {
    let instruction = enc::encode_branch(wide::control::BEQ, 0, 0, 0);
    for gas in [0, root_result_table_gas()] {
        let (program, recorder, outcome) = capture(&[instruction], &[], gas, 32);
        assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
        assert_root_preflight_out_of_gas(&program, &recorder, gas);
    }
    let (_, recorder, outcome) = capture(&[instruction], &[], root_setup_gas(), 32);
    assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
    assert_eq!(recorder.records().len(), 1);
    let trapped = &recorder.records()[0];
    assert_eq!(trapped.instruction, Some(instruction));
    assert_eq!(trapped.opcode_gas, Some(1));
    assert_eq!(trapped.before.gas_remaining, 0);
    assert!(matches!(trapped.outcome, DiagnosticStepOutcome::Trapped(_)));
    assert_eq!(trapped.after, trapped.before);
    let (program, fixture) = first_branch(instruction, &[]);
    let mut underflow = fixture.clone();
    for (word, value) in [(1, 0), (2, u64::MAX)] {
        bits(
            &mut underflow.0.row[WORDS + word * 64..WORDS + (word + 1) * 64],
            value,
        );
    }
    for limb in 0..4 {
        underflow.0.packets.fields[GAS_DEBIT][BEFORE + limb] = F::ZERO;
        underflow.0.packets.fields[GAS_DEBIT][AFTER + limb] = F(0xffff);
    }
    carries(&mut underflow.0.row[CARRIES..CARRIES + 4], 0, 1, true);
    assert!(!underflow.accepts(&program));
    let (limited, recorder, outcome) = capture(&[instruction], &[], 16, 1);
    assert!(matches!(outcome, Err(ivm::VMError::ExceededMaxCycles)));
    assert_eq!(recorder.records().len(), 1);
    let mut exhausted = ScalarFixture::from_record(&limited, &recorder.records()[0]);
    assert!(exhausted.accepts(&limited));
    for (word, value) in [(3, 1), (4, 2), (9, u64::MAX)] {
        bits(
            &mut exhausted.0.row[WORDS + word * 64..WORDS + (word + 1) * 64],
            value,
        );
    }
    exhausted.0.packets.fields[CYCLE_WRITE][BEFORE] = F::ONE;
    exhausted.0.packets.fields[CYCLE_WRITE][AFTER] = F(2);
    carries(&mut exhausted.0.row[CARRIES + 4..CARRIES + 8], 1, 1, false);
    carries(&mut exhausted.0.row[CARRIES + 16..CARRIES + 20], 0, 1, true);
    assert!(!exhausted.accepts(&limited));
    let mut forged = fixture.clone();
    forged.0.row[HALT] = F::ONE;
    forged.0.packets.fields[RUNNING_WRITE][AFTER] = F::ZERO;
    assert!(!forged.accepts(&program));
}

#[test]
fn consecutive_native_scalar_branch_loop_preserves_original_boundaries() {
    let body = [
        enc::encode_ri(wide::arithmetic::ADDI, 2, 0, 2),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1),
        enc::encode_branch(wide::control::BNE, 2, 0, -1),
        enc::encode_ri(wide::arithmetic::ADDI, 4, 2, 7),
    ];
    let (program, recorder, _later_return) = capture(&body, &[], 32, 64);
    let executed = [0, 1, 2, 1, 2, 3];
    let records = &recorder.records()[..executed.len()];
    for (slot, record) in executed.into_iter().zip(records) {
        assert_eq!(record.instruction, Some(body[slot]));
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
    for pair in records.windows(2) {
        assert_eq!(pair[0].after, pair[1].before);
    }
    assert_eq!(records.last().unwrap().after.registers[2], 0);
    assert_eq!(records.last().unwrap().after.registers[4], 7);
}

#[test]
fn canonical_preparation_rejects_branch_targets_outside_original_instruction_boundaries() {
    let artifact = contract(
        &[enc::encode_branch(wide::control::BEQ, 0, 0, 0)],
        32,
        ivm::ivm_mode::ZK,
    );
    // The current qualification image has at most 64 words. Neither signed
    // imm8 extreme can have an in-image target; code_end is not a boundary.
    for opcode in OPCODES {
        for offset in [i8::MIN, -1, 5, i8::MAX] {
            let mut invalid = artifact.artifact().to_vec();
            invalid[artifact.code_offset()..artifact.code_offset() + 4]
                .copy_from_slice(&enc::encode_branch(opcode, 0, 0, offset).to_le_bytes());
            assert!(ivm::prepare_contract(invalid.into()).is_err());
        }
    }
    // A final branch with a valid taken target still has no fallthrough.
    let mut invalid = artifact.artifact().to_vec();
    let last = invalid.len() - 4;
    invalid[last..]
        .copy_from_slice(&enc::encode_branch(wide::control::BEQ, 0, 0, -1).to_le_bytes());
    assert!(ivm::prepare_contract(invalid.into()).is_err());
}

#[test]
fn native_branches_reach_distant_boundaries_of_the_bounded_private_image() {
    let nop = enc::encode_ri(wide::arithmetic::ADDI, 0, 0, 0);
    for backward in [false, true] {
        let mut body = vec![nop; 60];
        let slot = if backward { 59 } else { 0 };
        body[slot] = enc::encode_branch(wide::control::BEQ, 0, 0, if backward { -59 } else { 63 });
        let (program, recorder, _later_outcome) = capture(&body, &[], 128, 256);
        assert_eq!(program.words.len(), MAX_WORDS);
        let record = &recorder.records()[slot];
        assert_eq!(record.instruction, Some(body[slot]));
        assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
        assert_eq!(
            record.after.pc,
            u64::from(program.first_pc) + if backward { 0 } else { 63 * 4 }
        );
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
}
