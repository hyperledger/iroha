//! Native shifts and rotates through the original private dispatcher producers.

use super::*;

const REGISTER_OPS: [u8; 5] = [
    wide::arithmetic::SLL,
    wide::arithmetic::SRL,
    wide::arithmetic::SRA,
    wide::arithmetic::ROTL,
    wide::arithmetic::ROTR,
];
const IMMEDIATE_OPS: [u8; 2] = [wide::arithmetic::ROTL_IMM, wide::arithmetic::ROTR_IMM];

fn expected(opcode: u8, left: u64, amount: u64) -> u64 {
    let amount = (amount & 63) as u32;
    match opcode {
        wide::arithmetic::SLL => left << amount,
        wide::arithmetic::SRL => left >> amount,
        wide::arithmetic::SRA => i64::cast_unsigned(u64::cast_signed(left) >> amount),
        wide::arithmetic::ROTL | wide::arithmetic::ROTL_IMM => left.rotate_left(amount),
        wide::arithmetic::ROTR | wide::arithmetic::ROTR_IMM => left.rotate_right(amount),
        _ => panic!("shift fixture opcode"),
    }
}

fn instructions(rd: u8) -> [u32; 7] {
    [
        enc::encode_rr(wide::arithmetic::SLL, rd, 2, 3),
        enc::encode_rr(wide::arithmetic::SRL, rd, 2, 3),
        enc::encode_rr(wide::arithmetic::SRA, rd, 2, 3),
        enc::encode_rr(wide::arithmetic::ROTL, rd, 2, 3),
        enc::encode_rr(wide::arithmetic::ROTR, rd, 2, 3),
        enc::encode_ri(wide::arithmetic::ROTL_IMM, rd, 2, i8::MIN),
        enc::encode_ri(wide::arithmetic::ROTR_IMM, rd, 2, -1),
    ]
}

fn checked_native(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let packets = &fixture.0.packets.fields;
    let left = packet::half(&packets[SCALAR_LEFT], BEFORE, 0);
    let amount = right_immediate(instruction)
        .unwrap_or_else(|| packet::half(&packets[SCALAR_RIGHT], BEFORE, 0));
    let result = expected(wide::opcode(instruction), left, amount);
    assert_eq!(
        packet::half(&packets[SCALAR_DESTINATION], AFTER, 0),
        if wide::rd(instruction) == 0 {
            0
        } else {
            result
        }
    );
    assert_eq!(
        packets[SCALAR_DESTINATION][AFTER_TAG],
        if wide::rd(instruction) == 0 {
            F::ZERO
        } else {
            packets[SCALAR_LEFT][BEFORE_TAG]
        }
    );
    assert_eq!(
        packet::half(&packets[PC_WRITE], AFTER, 0),
        packet::half(&packets[PC_READ], BEFORE, 0) + 4
    );
    assert_eq!(
        packet::half(&packets[CYCLE_WRITE], AFTER, 0),
        packet::half(&packets[CYCLE_WRITE], BEFORE, 0) + 1
    );
    assert_eq!(
        packet::half(&packets[GAS_DEBIT], BEFORE, 0) - packet::half(&packets[GAS_DEBIT], AFTER, 0),
        1 + u64::from(is_rotate(instruction))
    );
    if right_immediate(instruction).is_some() {
        assert!(packets[SCALAR_RIGHT].iter().all(|cell| *cell == F::ZERO));
    }
    (program, fixture)
}

pub(super) fn capture_program(
    program: Program,
    inputs: &[(usize, u64, bool)],
    gas: u64,
) -> (Program, DiagnosticStepRecorder, Result<(), ivm::VMError>) {
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

pub(super) fn capture(
    body: &[u32],
    inputs: &[(usize, u64, bool)],
    gas: u64,
    cycle_limit: u64,
) -> (Program, DiagnosticStepRecorder, Result<(), ivm::VMError>) {
    capture_program(
        Program::new(contract(body, cycle_limit, ivm::ivm_mode::ZK)).unwrap(),
        inputs,
        gas,
    )
}

/// Rebuild every arithmetic bank when an adversary changes the source words.
fn replace_sources(fixture: &mut ScalarFixture, instruction: u32, left: u64, right: u64) {
    fixture.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(left, right));
    fill_product(&mut fixture.0, left, right);
    fixture.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
        wide::arithmetic::ADD,
        left,
        right,
    ));
    fixture.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
        .copy_from_slice(&branch::bank_witness(0, left, right));
    fixture.0.row[SCALAR + SHIFT..super::super::super::WIDTH]
        .copy_from_slice(&shift::bank_witness(wide::opcode(instruction), left, right));
}

#[test]
fn native_private_shift_register_amounts_tags_aliases_and_zero_match() {
    let values = [
        0,
        1,
        u64::MAX,
        i64::cast_unsigned(i64::MIN),
        0xaaaa_5555_8000_0001,
        0x1234_5678_9abc_def0,
    ];
    for opcode in REGISTER_OPS {
        for tag in [false, true] {
            for amount in (0..64).chain([64, 127, 128, 255, u64::MAX, 0x1234_5678_9abc_def0]) {
                checked_native(
                    enc::encode_rr(opcode, 4, 2, 3),
                    &[
                        (2, values[amount as usize % values.len()], tag),
                        (3, amount, tag),
                    ],
                );
            }
            for (rd, left, right) in [(0, 2, 3), (2, 2, 3), (3, 2, 3), (4, 2, 2), (2, 2, 2)] {
                checked_native(
                    enc::encode_rr(opcode, rd, left, right),
                    &[(2, u64::MAX, tag), (3, 63, tag)],
                );
            }
        }
        for (rd, left, right) in [(4, 0, 0), (0, 0, 0), (4, 0, 3), (4, 2, 0)] {
            checked_native(
                enc::encode_rr(opcode, rd, left, right),
                &[(2, u64::MAX, false), (3, 63, false), (4, 17, true)],
            );
        }
    }
}

#[test]
fn native_private_rotate_immediates_are_unsigned_and_never_read_raw_byte_registers() {
    for opcode in IMMEDIATE_OPS {
        for raw in 0..=u8::MAX {
            for tag in [false, true] {
                let instruction = enc::encode_ri(opcode, 4, 2, u8::cast_signed(raw));
                let (program, fixture) =
                    checked_native(instruction, &[(2, 0x8000_1234_5678_9abc, tag)]);
                assert_eq!(right_immediate(instruction), Some(u64::from(raw)));
                let source = word::Sources::new(&fixture.0.row[SCALAR..SCALAR + ALU]);
                assert_eq!(source.limb(1, 0), F(u64::from(raw)));
                for limb in 1..4 {
                    assert_eq!(source.limb(1, limb), F::ZERO);
                }
                if raw == 128 || raw == 255 {
                    let mut signed = fixture.clone();
                    replace_sources(
                        &mut signed,
                        instruction,
                        0x8000_1234_5678_9abc,
                        i64::cast_unsigned(i64::from(u8::cast_signed(raw))),
                    );
                    assert!(!signed.accepts(&program));
                }
            }
        }
        for raw in [0, 2, 4, 128, 255] {
            for rd in [0, 2, raw] {
                checked_native(
                    enc::encode_ri(opcode, rd, 2, u8::cast_signed(raw)),
                    &[(2, u64::MAX, true)],
                );
            }
        }
        checked_native(
            enc::encode_ri(opcode, 4, 0, -1),
            &[(4, 19, true), (255, 17, true)],
        );
        let instruction = enc::encode_ri(opcode, 4, 2, -1);
        let (program, first) = checked_native(instruction, &[(2, 17, true), (255, 0, false)]);
        let (_, second) = checked_native(instruction, &[(2, 17, true), (255, u64::MAX, true)]);
        assert_eq!(first.0.row, second.0.row);
        assert_eq!(first.0.packets.fields, second.0.packets.fields);
        let mut read = first.clone();
        read.0.packets.fields[SCALAR_RIGHT] = event(
            Space::Register,
            0,
            255,
            0,
            0,
            false,
            read.0.schedule.clocks[SCALAR_RIGHT],
            false,
            false,
        );
        assert!(!read.accepts(&program));
    }
}

#[test]
fn native_shift_mismatched_tags_trap_after_exact_gas_even_for_zero_destination() {
    for opcode in REGISTER_OPS {
        for rd in [0, 4] {
            for (left_tag, right_tag) in [(true, false), (false, true)] {
                let instruction = enc::encode_rr(opcode, rd, 2, 3);
                let cost = 1 + u64::from(is_rotate(instruction));
                let (_, recorder, outcome) = capture(
                    &[instruction],
                    &[(2, 17, left_tag), (3, 63, right_tag)],
                    16,
                    32,
                );
                assert!(matches!(outcome, Err(ivm::VMError::PrivacyViolation)));
                let record = &recorder.records()[0];
                assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
                assert_eq!(record.opcode_gas, Some(cost));
                assert_eq!(record.after.pc, record.before.pc);
                assert_eq!(record.after.cycles, record.before.cycles);
                assert_eq!(record.after.registers, record.before.registers);
                assert_eq!(record.after.tags, record.before.tags);
                assert_eq!(
                    record.after.gas_remaining + cost,
                    record.before.gas_remaining
                );
                let (program, mut forged) =
                    checked_native(instruction, &[(2, 17, false), (3, 63, false)]);
                for (slot, tag) in [(SCALAR_LEFT, left_tag), (SCALAR_RIGHT, right_tag)] {
                    forged.0.packets.fields[slot][BEFORE_TAG] = F(u64::from(tag));
                    forged.0.packets.fields[slot][AFTER_TAG] = F(u64::from(tag));
                }
                if rd != 0 {
                    forged.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F(u64::from(left_tag));
                }
                assert!(!forged.accepts(&program));
            }
        }
    }
}

#[test]
fn every_shift_original_producer_and_workspace_cell_is_constrained() {
    for rd in [0, 2, 3, 4] {
        for instruction in instructions(rd) {
            let (program, fixture) = checked_native(
                instruction,
                &[
                    (2, 0xa55a_8001_f00f_1234, true),
                    (3, 0x1234_5678_9abc_0039, true),
                ],
            );
            for slot in 0..PORTS {
                for column in 0..packet::WIDTH {
                    let mut bad = fixture.clone();
                    bad.0.packets.fields[slot][column] =
                        bad.0.packets.fields[slot][column].add(F::ONE);
                    let prior_destination = slot == SCALAR_DESTINATION
                        && rd != 0
                        && rd != 2
                        && (right_immediate(instruction).is_some() || rd != 3)
                        && ((BEFORE..BEFORE + 4).contains(&column) || column == BEFORE_TAG);
                    if !prior_destination {
                        assert!(
                            !bad.accepts(&program),
                            "instruction {instruction:x} slot {slot} column {column}"
                        );
                    }
                }
            }
            for column in 0..super::super::super::WIDTH {
                let mut bad = fixture.clone();
                bad.0.row[column] = bad.0.row[column].add(F::ONE);
                assert!(
                    !bad.accepts(&program),
                    "instruction {instruction:x} workspace {column}"
                );
            }
        }
    }
}

#[test]
fn shift_fetch_direction_sign_high_amount_bits_and_coherent_zero_forgery_reject() {
    let instruction = enc::encode_rr(wide::arithmetic::SRA, 4, 2, 3);
    let (_, fixture) = checked_native(
        instruction,
        &[(2, 0x8000_0000_0000_0001, true), (3, 63, true)],
    );
    for replacement in [
        enc::encode_rr(wide::arithmetic::SRL, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SRA, 3, 2, 3),
        enc::encode_rr(wide::arithmetic::SRA, 4, 3, 2),
        enc::encode_rr(wide::arithmetic::SRA, 4, 2, 2),
        enc::encode_ri(wide::arithmetic::ROTR_IMM, 4, 2, 63),
    ] {
        let changed = Program::new(contract(&[replacement], 1_000, ivm::ivm_mode::ZK)).unwrap();
        assert!(!fixture.accepts(&changed));
    }
    for opcode in REGISTER_OPS {
        let instruction = enc::encode_rr(opcode, 4, 2, 3);
        let (program, fixture) = checked_native(
            instruction,
            &[(2, 0x8000_0000_0000_0001, true), (3, 1, true)],
        );
        let mut high = fixture.clone();
        replace_sources(&mut high, instruction, 0x8000_0000_0000_0001, (1 << 63) | 1);
        assert_eq!(
            &high.0.row[SCALAR + SHIFT..],
            &fixture.0.row[SCALAR + SHIFT..]
        );
        assert!(!high.accepts(&program));
        let (program, mut reduced) = checked_native(
            instruction,
            &[(2, 0xffff_ffff_0000_0001, true), (3, 0, true)],
        );
        replace_sources(&mut reduced, instruction, 0, 0);
        for limb in 0..4 {
            reduced.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = F::ZERO;
        }
        assert!(!reduced.accepts(&program));
        let instruction = enc::encode_rr(opcode, 4, 0, 0);
        let (program, mut zero) = checked_native(instruction, &[]);
        for slot in [SCALAR_LEFT, SCALAR_RIGHT] {
            zero.0.packets.fields[slot][BEFORE] = F::ONE;
            zero.0.packets.fields[slot][AFTER] = F::ONE;
        }
        replace_sources(&mut zero, instruction, 1, 1);
        for limb in 0..4 {
            zero.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] =
                constant_limb(expected(opcode, 1, 1), limb);
        }
        assert!(!zero.accepts(&program));
    }
}

#[test]
fn shift_workspace_is_canonical_on_old_scalar_branch_and_padding_rows() {
    let (program, scalar) = native(
        enc::encode_rr(wide::arithmetic::ADD, 4, 2, 3),
        &[(2, u64::MAX, true), (3, 1, true)],
    );
    let (branch_program, branching) = native(
        enc::encode_branch(wide::control::BEQ, 2, 3, 2),
        &[(2, 17, false), (3, 17, false)],
    );
    let padding = ScalarFixture(Fixture::padding());
    for (program, fixture) in [
        (&program, &scalar),
        (&branch_program, &branching),
        (&program, &padding),
    ] {
        assert!(fixture.accepts(program));
        for column in SCALAR + SHIFT..super::super::super::WIDTH {
            let mut bad = fixture.clone();
            bad.0.row[column] = bad.0.row[column].add(F::ONE);
            assert!(!bad.accepts(program), "inactive shift column {column}");
        }
    }
}

#[test]
fn shift_gas_boundaries_underflow_cycle_limit_and_false_halt_reject() {
    let root_gas = root_setup_gas();
    for instruction in instructions(4) {
        let cost = 1 + u64::from(is_rotate(instruction));
        let inputs = [(2, 0x8000_0000_0000_0001, true), (3, 63, true)];
        // Root invocation pays for the original Unit result table and its bitmap
        // before the interpreter begins a diagnostic opcode step.
        for initial_gas in 0..root_gas {
            let (program, recorder, outcome) = capture(&[instruction], &inputs, initial_gas, 32);
            assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
            assert_root_preflight_out_of_gas(&program, &recorder, initial_gas);
        }
        for gas in 0..cost {
            let (_, recorder, outcome) = capture(&[instruction], &inputs, root_gas + gas, 32);
            assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
            assert_eq!(recorder.records().len(), 1);
            let record = &recorder.records()[0];
            assert_eq!(record.instruction, Some(instruction));
            assert_eq!(record.opcode_gas, Some(cost));
            assert_eq!(record.before.gas_remaining, gas);
            assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
            assert_eq!(record.before, record.after);
        }
        for gas in [root_gas + cost, 0xffff, 0x10000, u64::MAX] {
            let (program, recorder, _later_outcome) = capture(&[instruction], &inputs, gas, 32);
            let record = &recorder.records()[0];
            assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
            assert_eq!(record.before.gas_remaining, gas - root_gas);
            assert_eq!(record.after.gas_remaining, gas - root_gas - cost);
            assert!(ScalarFixture::from_record(&program, record).accepts(&program));
        }
        let (program, fixture) = checked_native(instruction, &inputs);
        let mut underflow = fixture.clone();
        for (word, value) in [(1, 0), (2, 0_u64.wrapping_sub(cost))] {
            bits(
                &mut underflow.0.row[WORDS + 64 * word..WORDS + 64 * (word + 1)],
                value,
            );
            let offset = if word == 1 { BEFORE } else { AFTER };
            for limb in 0..4 {
                underflow.0.packets.fields[GAS_DEBIT][offset + limb] = constant_limb(value, limb);
            }
        }
        carries(&mut underflow.0.row[CARRIES..CARRIES + 4], 0, cost, true);
        assert!(!underflow.accepts(&program));
        let (limited, recorder, outcome) = capture(&[instruction], &inputs, 16, 1);
        assert!(matches!(outcome, Err(ivm::VMError::ExceededMaxCycles)));
        assert_eq!(recorder.records().len(), 1);
        let mut exhausted = ScalarFixture::from_record(&limited, &recorder.records()[0]);
        assert!(exhausted.accepts(&limited));
        for (word, value) in [(3, 1), (4, 2), (9, u64::MAX)] {
            bits(
                &mut exhausted.0.row[WORDS + 64 * word..WORDS + 64 * (word + 1)],
                value,
            );
        }
        exhausted.0.packets.fields[CYCLE_WRITE][BEFORE] = F::ONE;
        exhausted.0.packets.fields[CYCLE_WRITE][AFTER] = F(2);
        carries(&mut exhausted.0.row[CARRIES + 4..CARRIES + 8], 1, 1, false);
        carries(&mut exhausted.0.row[CARRIES + 16..CARRIES + 20], 0, 1, true);
        assert!(!exhausted.accepts(&limited));
        let mut halt = fixture.clone();
        halt.0.row[HALT] = F::ONE;
        halt.0.packets.fields[RUNNING_WRITE][AFTER] = F::ZERO;
        assert!(!halt.accepts(&program));
    }
}

#[test]
fn native_shift_requires_admitted_return_and_remains_running_before_it() {
    for instruction in instructions(4) {
        let artifact = contract(&[instruction], 32, ivm::ivm_mode::ZK);
        let mut code = artifact.artifact().to_vec();
        code.truncate(artifact.code_offset() + 4);
        // V1 admission rejects reachable fallthrough outside the instruction image
        // before execution. Do not bypass it with a standalone opcode image.
        let error = ivm::prepare_contract(code.into())
            .expect_err("the signed entrypoint cannot fall through missing code");
        assert!(error.to_string().contains("reaches non-instruction pc 4"));
        assert!(matches!(
            error.into_vm_error(),
            ivm::VMError::InvalidMetadata
        ));
        let program = Program::new(artifact).unwrap();
        let (program, recorder, outcome) =
            capture_program(program, &[(2, 17, true), (3, 1, true)], 100);
        assert!(outcome.is_ok());
        let record = &recorder.records()[0];
        assert_eq!(record.instruction, Some(instruction));
        assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
        assert_eq!(record.after.pc, u64::from(program.first_pc) + 4);
        assert!(record.after.pc < program.code_end());
        assert!(!record.after.halted);
        let fixture = ScalarFixture::from_record(&program, record);
        assert!(fixture.accepts(&program));
        assert_eq!(fixture.0.packets.fields[RUNNING_WRITE][AFTER], F::ONE);
        let mut falsely_halted = fixture.clone();
        falsely_halted.0.row[HALT] = F::ONE;
        falsely_halted.0.packets.fields[RUNNING_WRITE][AFTER] = F::ZERO;
        assert!(!falsely_halted.accepts(&program));
        let end = recorder.end().unwrap();
        assert_eq!(end.outcome, Ok(()));
        assert!(end.state.halted);
        assert_eq!(end.state.pc, program.code_end());
    }
}

pub(super) fn mixed_body() -> [u32; 10] {
    [
        enc::encode_ri(wide::arithmetic::ADDI, 2, 0, -1),
        enc::encode_ri(wide::arithmetic::ADDI, 3, 0, 63),
        enc::encode_rr(wide::arithmetic::SLL, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SRL, 4, 4, 3),
        enc::encode_branch(wide::control::BEQ, 4, 0, 2),
        enc::encode_rr(wide::arithmetic::SRA, 2, 2, 3),
        enc::encode_rr(wide::arithmetic::ROTL, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::ROTR, 3, 4, 3),
        enc::encode_ri(wide::arithmetic::ROTL_IMM, 2, 3, i8::MIN),
        enc::encode_ri(wide::arithmetic::ROTR_IMM, 4, 2, -1),
    ]
}

#[test]
fn consecutive_native_alu_branch_shift_records_preserve_original_boundaries() {
    let body = mixed_body();
    let (program, recorder, _later_outcome) = capture(&body, &[], 64, 64);
    let records = &recorder.records()[..body.len()];
    for (instruction, record) in body.into_iter().zip(records) {
        assert_eq!(record.instruction, Some(instruction));
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
    for pair in records.windows(2) {
        assert_eq!(pair[0].after, pair[1].before);
    }
    assert_eq!(records.last().unwrap().after.registers[4], u64::MAX);
}
