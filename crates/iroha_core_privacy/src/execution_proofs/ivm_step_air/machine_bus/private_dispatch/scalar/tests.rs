//! Local native private scalar captures and original-column adversaries.

use super::super::tests::{Fixture, bits, bytes, carries, contract, event};
use super::*;
use iroha_allocation::AllocationBudget;
use ivm::{
    IVM,
    encoding::wide as enc,
    execution_step_recorder::{
        DiagnosticStepOutcome, DiagnosticStepRecord, DiagnosticStepRecorder,
    },
    host::DefaultHost,
};

/// Test-only scalar, branch and direct-jump workspace; packet backing erases on Drop.
#[derive(Clone)]
struct ScalarFixture(Fixture);
impl Drop for ScalarFixture {
    fn drop(&mut self) {
        for field in &mut self.0.row {
            field.zeroize_v1();
        }
    }
}
impl ScalarFixture {
    fn from_record(program: &Program, record: &DiagnosticStepRecord) -> Self {
        assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
        let instruction = record.instruction.unwrap();
        assert!(is_supported(instruction) || role(instruction) == Some(Role::Jump));
        let pc = record.before.pc;
        let slot = usize::try_from((pc - u64::from(program.first_pc)) / 4).unwrap();
        assert_eq!(program.words[slot], instruction);
        let mut fixture = Fixture::padding();
        fixture.row[FETCH + slot] = F::ONE;
        let words = [
            pc,
            record.before.gas_remaining,
            record.after.gas_remaining,
            record.before.cycles,
            record.after.cycles,
            0,
            0,
            0,
            0,
            program.cycle_limit - 1 - record.before.cycles,
        ];
        for (i, word) in words.into_iter().enumerate() {
            bits(&mut fixture.row[WORDS + 64 * i..WORDS + 64 * (i + 1)], word);
        }
        carries(
            &mut fixture.row[CARRIES..CARRIES + 4],
            record.before.gas_remaining,
            record.opcode_gas.expect("native opcode tariff"),
            true,
        );
        carries(
            &mut fixture.row[CARRIES + 4..CARRIES + 8],
            record.before.cycles,
            record.after.cycles - record.before.cycles,
            false,
        );
        carries(
            &mut fixture.row[CARRIES + 16..CARRIES + 20],
            program.cycle_limit - 1,
            record.before.cycles,
            true,
        );
        for (slot, owner, before, after, write) in [
            (PC_READ, PC_OWNER, pc, pc, false),
            (
                GAS_DEBIT,
                GAS_OWNER,
                record.before.gas_remaining,
                record.after.gas_remaining,
                true,
            ),
            (CALL_DEPTH, CALL_DEPTH_OWNER, 0, 0, false),
            (PC_WRITE, PC_OWNER, pc, record.after.pc, true),
            (
                CYCLE_WRITE,
                CYCLE_OWNER,
                record.before.cycles,
                record.after.cycles,
                true,
            ),
            (RUNNING_WRITE, RUNNING_OWNER, 1, 1, true),
        ] {
            fixture.packets.fields[slot] = event(
                Space::Owner,
                0,
                owner,
                before,
                after,
                write,
                fixture.schedule.clocks[slot],
                false,
                false,
            );
        }
        if role(instruction) == Some(Role::Jump) {
            // The native jump has no operand/tag or lifecycle effect. Keep
            // those original producer slots and their workspace inactive.
            return Self(fixture);
        }
        let left = left_register(instruction);
        let right = right_register(instruction);
        let destination = wide::rd(instruction);
        let taken = !is_conditional_move(instruction) || record.before.registers[left] != 0;
        if is_conditional_move(instruction) && !taken {
            assert_eq!(
                record.before.registers[destination],
                record.after.registers[destination]
            );
            assert_eq!(
                record.before.tags[destination],
                record.after.tags[destination]
            );
        }
        for (slot, register, enabled, write) in [
            (SCALAR_LEFT, left, reads_left(instruction), false),
            (
                SCALAR_RIGHT,
                right,
                right_immediate(instruction).is_none() && taken,
                false,
            ),
            (
                SCALAR_DESTINATION,
                destination,
                has_destination(instruction) && taken,
                true,
            ),
        ] {
            if enabled {
                fixture.packets.fields[slot] = event(
                    Space::Register,
                    0,
                    register as u32,
                    record.before.registers[register],
                    if write {
                        record.after.registers[register]
                    } else {
                        record.before.registers[register]
                    },
                    write,
                    fixture.schedule.clocks[slot],
                    record.before.tags[register],
                    if write {
                        record.after.tags[register]
                    } else {
                        record.before.tags[register]
                    },
                );
            }
        }
        let left = if reads_left(instruction) {
            record.before.registers[left]
        } else {
            0
        };
        let right = right_immediate(instruction).unwrap_or(if taken {
            record.before.registers[right]
        } else {
            0
        });
        let (left, right) =
            if wide::opcode(instruction) == wide::arithmetic::NEG || is_absolute(instruction) {
                (0, left)
            } else {
                (left, right)
            };
        fixture.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(left, right));
        fill_product(&mut fixture, left, right);
        fill_count(
            &mut fixture,
            left,
            wide::opcode(instruction) == wide::arithmetic::CLZ,
        );
        fixture.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
            if is_alu(instruction) || is_absolute(instruction) {
                alu_opcode(instruction)
            } else {
                wide::arithmetic::ADD
            },
            left,
            right,
        ));
        let predicate = comparison_predicate(instruction).map_or(0, |index| {
            [
                wide::control::BEQ,
                wide::control::BNE,
                wide::control::BLT,
                wide::control::BGE,
                wide::control::BLTU,
                wide::control::BGEU,
            ][index]
        });
        fixture.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
            .copy_from_slice(&branch::bank_witness(predicate, left, right));
        fixture.row[SCALAR + SHIFT..super::super::WIDTH].copy_from_slice(&shift::bank_witness(
            if shift_kind(instruction).is_some() {
                wide::opcode(instruction)
            } else {
                wide::arithmetic::SLL
            },
            left,
            right,
        ));
        if let Some(kind) = division_kind(instruction) {
            fill_division(&mut fixture, left, right, record.before.gas_remaining, kind);
            if kind == 4 {
                let result = ceiling::witness(&fixture.row[SCALAR + SHIFT..super::super::WIDTH]);
                fixture.row[SCALAR + MEAN..SCALAR + SHIFT].copy_from_slice(&result);
            }
        }
        if is_square_root(instruction) {
            fill_square_root(&mut fixture, left, record.before.gas_remaining);
        }
        if is_absolute(instruction) {
            fill_absolute_zero_test(&mut fixture, right);
        }
        if is_mean(instruction) {
            fixture.row[SCALAR + MEAN..SCALAR + SHIFT]
                .copy_from_slice(&mean::result_witness(left, right));
        }
        if is_gcd(instruction) {
            gcd::fill(&mut fixture.row[SCALAR..], left, right);
        }
        Self(fixture)
    }
    fn accepts(&self, program: &Program) -> bool {
        self.0.accepts(program)
    }
}

// Reuse the original zero-test cells with the full canonical ABS overflow delta.
fn fill_absolute_zero_test(fixture: &mut Fixture, value: u64) {
    let delta = F(u64::from((value ^ (1 << 63)).count_ones()));
    fixture.row[SCALAR + MOVE_ZERO] = F(u64::from(delta == F::ZERO));
    fixture.row[SCALAR + MOVE_INVERSE] = delta.inv().unwrap_or(F::ZERO);
}

// The successful native division uses the same original source words and gas.
fn fill_division(fixture: &mut Fixture, left: u64, right: u64, gas: u64, kind: usize) {
    let witness = division::witness(left, right, gas, kind);
    fixture.row[SCALAR + SHIFT..super::super::WIDTH].copy_from_slice(&witness.bank);
    fixture.row[SCALAR + PRODUCT_DIGITS..SCALAR + MULTIPLY].copy_from_slice(&witness.digits);
    fixture.row[SCALAR + MULTIPLY..SCALAR + COUNT].copy_from_slice(&witness.product);
    fixture.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS].copy_from_slice(&branch::bank_witness(
        0,
        witness.remainder,
        witness.denominator,
    ));
}

// Fill the same product and shift storage from the existing exact root bank.
fn fill_square_root(fixture: &mut Fixture, value: u64, gas: u64) {
    let witness = square_root::witness(value, gas);
    fixture.row[SCALAR + SHIFT..super::super::WIDTH].copy_from_slice(&witness.bank);
    fixture.row[SCALAR + PRODUCT_DIGITS..SCALAR + MULTIPLY].copy_from_slice(&witness.digits);
    fixture.row[SCALAR + MULTIPLY..SCALAR + COUNT].copy_from_slice(&witness.product);
}

// Fill the shared exact-product workspace, including unused-operation rows.
fn fill_product(fixture: &mut Fixture, left: u64, right: u64) {
    fill_count(fixture, left, false);
    let digits = multiply::product_digits(left, right);
    fixture.row[SCALAR + PRODUCT_DIGITS..SCALAR + MULTIPLY].copy_from_slice(&digits);
    fixture.row[SCALAR + MULTIPLY..SCALAR + COUNT]
        .copy_from_slice(&multiply::witness(left, right, &digits, true));
}

fn fill_count(fixture: &mut Fixture, left: u64, leading: bool) {
    let population = F(u64::from(left.count_ones()));
    fixture.row[SCALAR + MOVE_ZERO] = F(u64::from(left == 0));
    fixture.row[SCALAR + MOVE_INVERSE] = population.inv().unwrap_or(F::ZERO);
    let sources = word::witness(left, 0);
    fixture.row[SCALAR + COUNT..SCALAR + MOVE]
        .copy_from_slice(&bit_count::witness(&sources[..64], leading));
}

// Authenticated Unit calls reserve their one-word result table before the first
// diagnostic instruction. This is invocation setup, not an opcode debit.
fn root_result_table_gas() -> u64 {
    let callable = crate::ivm_test_support::unit_callable(0);
    assert_eq!(callable.argument_word_count(), Some(0));
    u64::try_from(callable.result_word_count().unwrap() * ivm::call::CALL_WORD_BYTES_V1).unwrap()
}

fn root_setup_gas() -> u64 {
    let callable = crate::ivm_test_support::unit_callable(0);
    assert_eq!(callable.argument_word_count(), Some(0));
    assert_eq!(callable.frame_bytes, 0);
    // Native call_gas::frame charges one bitmap byte per result slot here.
    root_result_table_gas() + u64::try_from(callable.result_word_count().unwrap()).unwrap()
}

#[test]
fn typed_unit_schema_charges_its_node_at_return_only() {
    assert_eq!(root_setup_gas(), 9);
    let return_words = crate::ivm_test_support::unit_return();
    let opcode_gas = return_words
        .chunks_exact(4)
        .map(|bytes| ivm::gas::cost_of(u32::from_le_bytes(bytes.try_into().unwrap())).unwrap())
        .sum::<u64>();
    let validation_gas = 1 + ivm::call::CALL_WORD_BYTES_V1 as u64;
    let total_gas = root_setup_gas() + opcode_gas + validation_gas;
    // This test isolates call/return work. Match the exact instruction count so
    // ordinary ZK cycle padding requires neither extra gas nor another record.
    let cycles = u64::try_from(return_words.len() / 4).unwrap();
    let (_, recorder, outcome) = shifts::capture(&[], &[], total_gas, cycles);
    outcome.unwrap();
    let records = recorder.records();
    assert_eq!(records.len(), return_words.len() / 4);
    assert_eq!(
        records[0].before.gas_remaining,
        total_gas - root_setup_gas()
    );
    let terminal = records.last().unwrap();
    assert_eq!(terminal.opcode_gas, Some(2));
    assert_eq!(terminal.before.gas_remaining, 2 + validation_gas);
    assert_eq!(terminal.after.gas_remaining, 0);
    assert!(terminal.after.halted);

    // One gas short pays JALR and the schema node, then fails the complete
    // Unit-word validation debit. It must not publish a completed root return.
    let (_, recorder, outcome) = shifts::capture(&[], &[], total_gas - 1, cycles);
    assert!(matches!(
        (&(outcome), &(ivm::VMError::OutOfGas)),
        (Err(ivm::VMError::OutOfGas), ivm::VMError::OutOfGas)
    ));
    let terminal = recorder.records().last().unwrap();
    assert_eq!(terminal.before.gas_remaining, 1 + validation_gas);
    assert_eq!(
        terminal.after.gas_remaining,
        ivm::call::CALL_WORD_BYTES_V1 as u64 - 1
    );
    assert!(!terminal.after.halted);
}

fn assert_root_preflight_out_of_gas(
    program: &Program,
    recorder: &DiagnosticStepRecorder,
    gas: u64,
) {
    assert!(gas < root_setup_gas());
    assert!(recorder.records().is_empty());
    let end = recorder.end().expect("native root invocation trap");
    assert_eq!(end.outcome, Err(ivm::error::VmTrapKind::OutOfGas));
    assert_eq!(end.state.pc, u64::from(program.first_pc));
    let remaining = if gas < root_result_table_gas() {
        gas
    } else {
        // Result allocation completed, but frame bitmap admission did not.
        gas - root_result_table_gas()
    };
    assert_eq!(end.state.gas_remaining, remaining);
    assert_eq!(end.state.cycles, 0);
    assert!(!end.state.halted);
    assert_eq!(end.padding_cycles, 0);
}

fn native(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let artifact = contract(&[instruction], 1_000, ivm::ivm_mode::ZK);
    let mut vm = IVM::new(100);
    vm.load_prepared(&artifact).unwrap();
    for &(register, value, tag) in inputs {
        vm.set_register(register, value);
        vm.registers.set_tag(register, tag);
    }
    let budget = AllocationBudget::new(64 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(64, &budget).unwrap();
    // This is a local native diagnostic boundary, not an authenticated private
    // invocation initializer. Some alias cases overwrite the later return ABI.
    let _later_outcome =
        vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
    let program = Program::new(artifact).unwrap();
    let record = recorder
        .records()
        .first()
        .expect("actual native scalar attempt");
    assert_eq!(record.instruction, Some(instruction));
    assert_eq!(record.opcode_gas, ivm::gas::cost_of(instruction));
    assert_eq!(record.before.gas_remaining, 100 - root_setup_gas());
    let fixture = ScalarFixture::from_record(&program, record);
    assert!(fixture.accepts(&program));
    (program, fixture)
}

#[test]
fn native_private_and_public_scalar_register_immediate_and_aliases_match() {
    let values = [0, 1, u64::MAX, 0x8000_0000_0000_0000, 0xa5a5_1234_ffff_0001];
    for opcode in [
        wide::arithmetic::ADD,
        wide::arithmetic::SUB,
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
    ] {
        for tag in [false, true] {
            for (left, right) in values.into_iter().zip(values.into_iter().rev()) {
                for (rd, rs1, rs2) in [(4, 2, 3), (2, 2, 3), (3, 2, 3), (2, 2, 2), (0, 2, 3)] {
                    native(
                        enc::encode_rr(opcode, rd, rs1, rs2),
                        &[(2, left, tag), (3, right, tag), (4, 19, !tag)],
                    );
                }
            }
        }
        native(enc::encode_rr(opcode, 4, 0, 0), &[(4, u64::MAX, true)]);
    }
    for opcode in [
        wide::arithmetic::ADDI,
        wide::arithmetic::ANDI,
        wide::arithmetic::ORI,
        wide::arithmetic::XORI,
    ] {
        for tag in [false, true] {
            for immediate in [i8::MIN, -1, 0, 1, i8::MAX] {
                for rd in [0, 2, 4] {
                    native(
                        enc::encode_ri(opcode, rd, 2, immediate),
                        &[(2, u64::MAX, tag), (4, 77, !tag)],
                    );
                }
            }
        }
        native(enc::encode_ri(opcode, 4, 0, -1), &[(4, 17, true)]);
    }
}

#[test]
fn native_public_subset_rejects_shared_valid_private_scalars_and_unjoined_public_roles() {
    for (opcode, private) in [
        (wide::arithmetic::ADD, true),
        (wide::arithmetic::ANDI, true),
        (wide::arithmetic::NEG, true),
        (wide::arithmetic::SLT, true),
        (wide::arithmetic::MIN, true),
        (wide::arithmetic::SLL, true),
        (wide::arithmetic::SRL, true),
        (wide::arithmetic::SRA, true),
        (wide::arithmetic::ROTL, true),
        (wide::arithmetic::ROTR, true),
        (wide::arithmetic::ROTL_IMM, true),
        (wide::arithmetic::ROTR_IMM, true),
        (wide::arithmetic::MUL, true),
        (wide::arithmetic::MULH, true),
        (wide::arithmetic::MULHU, true),
        (wide::arithmetic::MULHSU, true),
        (wide::arithmetic::POPCNT, true),
        (wide::arithmetic::CLZ, true),
        (wide::arithmetic::CTZ, true),
        (wide::arithmetic::CMOV, false),
        (wide::system::GETGAS, false),
    ] {
        let word = enc::encode_rr(opcode, 4, 2, 3);
        let (program, fixture) = native(word, &[(2, u64::MAX, private), (3, 1, private)]);
        assert!(fixture.accepts(&program), "shared control {opcode:#x}");
        let mut residues = Vec::new();
        super::super::native_witness::append_subset_residues(
            &mut residues,
            &program,
            &fixture.0.row,
            &fixture.0.packets,
        );
        assert!(
            residues.iter().any(|value| *value != F::ZERO),
            "native subset must reject opcode {opcode:#x}, private={private}",
        );
    }
}

#[test]
fn native_private_comparison_tariffs_bind_two_gas_and_reject_coherent_other_debits() {
    for opcode in [
        wide::arithmetic::SLT,
        wide::arithmetic::SLTU,
        wide::arithmetic::SEQ,
        wide::arithmetic::SNE,
    ] {
        let (program, fixture) = native(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, u64::MAX, true), (3, 1, true)],
        );
        let before = packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0);
        let after = packet::half(&fixture.0.packets.fields[GAS_DEBIT], AFTER, 0);
        assert_eq!(before - after, 2);
        for wrong_cost in [0, 1, 3] {
            let mut forged = fixture.clone();
            let wrong_after = before - wrong_cost;
            bits(&mut forged.0.row[WORDS + 128..WORDS + 192], wrong_after);
            carries(
                &mut forged.0.row[CARRIES..CARRIES + 4],
                before,
                wrong_cost,
                true,
            );
            for limb in 0..4 {
                forged.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(wrong_after, limb);
            }
            assert!(!forged.accepts(&program));
        }
    }
}

#[test]
fn native_mismatched_tags_trap_and_cannot_form_a_successful_private_scalar_row() {
    for opcode in [
        wide::arithmetic::ADD,
        wide::arithmetic::SUB,
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
        wide::arithmetic::SLT,
        wide::arithmetic::SLTU,
        wide::arithmetic::SEQ,
        wide::arithmetic::SNE,
        wide::arithmetic::MIN,
        wide::arithmetic::MAX,
        wide::arithmetic::MUL,
        wide::arithmetic::MULHU,
        wide::arithmetic::MULHSU,
        wide::arithmetic::MULH,
        wide::arithmetic::MEAN,
    ] {
        for rd in [0, 4] {
            let instruction = enc::encode_rr(opcode, rd, 2, 3);
            let artifact = contract(&[instruction], 1_000, ivm::ivm_mode::ZK);
            let mut vm = IVM::new(100);
            vm.load_prepared(&artifact).unwrap();
            vm.set_register(2, 11);
            vm.set_register(3, 23);
            vm.registers.set_tag(2, true);
            let budget = AllocationBudget::new(8 * std::mem::size_of::<DiagnosticStepRecord>());
            let mut recorder = DiagnosticStepRecorder::try_new(8, &budget).unwrap();
            assert!(matches!(
                vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder),
                Err(ivm::VMError::PrivacyViolation)
            ));
            let record = &recorder.records()[0];
            assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
            assert_eq!(record.after.registers, record.before.registers);
            let cost = ivm::gas::cost_of(instruction).unwrap();
            assert_eq!(record.opcode_gas, Some(cost));
            assert_eq!(
                record.after.gas_remaining + cost,
                record.before.gas_remaining
            );
            let (program, mut forged) = native(instruction, &[(2, 11, false), (3, 23, false)]);
            forged.0.packets.fields[SCALAR_LEFT][BEFORE_TAG] = F::ONE;
            forged.0.packets.fields[SCALAR_LEFT][AFTER_TAG] = F::ONE;
            if rd != 0 {
                forged.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F::ONE;
            }
            assert!(!forged.accepts(&program));
        }
    }
}

#[test]
fn every_scalar_original_field_and_workspace_mutation_rejects_except_prior_destination() {
    for instruction in [
        enc::encode_rr(wide::arithmetic::MUL, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::MULHU, 2, 2, 3),
        enc::encode_rr(wide::arithmetic::MULHSU, 3, 2, 3),
        enc::encode_rr(wide::arithmetic::MULH, 0, 2, 3),
        enc::encode_rr(wide::arithmetic::MEAN, 2, 2, 3),
        enc::encode_rr(wide::arithmetic::ISQRT, 2, 2, 255),
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 2, 2, 3),
        enc::encode_rr(wide::arithmetic::GCD, 2, 2, 3),
        enc::encode_rr(wide::arithmetic::NEG, 2, 2, 255),
        enc::encode_rr(wide::arithmetic::NOT, 4, 2, 255),
        enc::encode_rr(wide::arithmetic::MIN, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::MAX, 0, 2, 3),
        enc::encode_rr(wide::arithmetic::ADD, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SLT, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SLTU, 2, 2, 3),
        enc::encode_rr(wide::arithmetic::SEQ, 3, 2, 3),
        enc::encode_rr(wide::arithmetic::SNE, 0, 2, 3),
        enc::encode_rr(wide::arithmetic::XOR, 2, 2, 3),
        enc::encode_ri(wide::arithmetic::ANDI, 4, 2, -1),
        enc::encode_ri(wide::arithmetic::ADDI, 0, 2, -1),
    ] {
        let (program, fixture) = native(
            instruction,
            &[
                (2, u64::MAX, !is_division(instruction)),
                (3, 3, !is_division(instruction)),
                (4, 9, false),
            ],
        );
        for slot in 0..PORTS {
            for column in 0..packet::WIDTH {
                let mut bad = fixture.clone();
                bad.0.packets.fields[slot][column] = bad.0.packets.fields[slot][column].add(F::ONE);
                let free = slot == SCALAR_DESTINATION
                    && wide::rd(instruction) != 0
                    && wide::rd(instruction) != wide::rs1(instruction)
                    && (right_immediate(instruction).is_some()
                        || wide::rd(instruction) != wide::rs2(instruction))
                    && ((BEFORE..BEFORE + 4).contains(&column) || column == BEFORE_TAG);
                if !free {
                    assert!(!bad.accepts(&program), "slot {slot} column {column}");
                }
            }
        }
        for index in 0..super::super::WIDTH {
            let mut bad = fixture.clone();
            bad.0.row[index] = bad.0.row[index].add(F::ONE);
            assert!(!bad.accepts(&program), "workspace {index}");
        }
    }
}

#[test]
fn scalar_fetch_signed_immediate_alias_zero_and_tag_substitution_reject() {
    let instruction = enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1);
    let (program, fixture) = native(instruction, &[(2, u64::MAX, true)]);
    for replacement in [
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, 1),
        enc::encode_ri(wide::arithmetic::ADDI, 3, 2, -1),
        enc::encode_ri(wide::arithmetic::ANDI, 2, 2, -1),
        enc::encode_rr(wide::arithmetic::ADD, 2, 2, 255),
    ] {
        let replaced = Program::new(contract(&[replacement], 1_000, ivm::ivm_mode::ZK)).unwrap();
        assert!(!fixture.accepts(&replaced));
    }
    let mut bad = fixture.clone();
    bad.0.packets.fields[SCALAR_DESTINATION][BEFORE] = F::ZERO;
    assert!(!bad.accepts(&program));
    let (zero_program, mut zero) = native(enc::encode_ri(wide::arithmetic::ADDI, 4, 0, 1), &[]);
    zero.0.packets.fields[SCALAR_LEFT][BEFORE_TAG] = F::ONE;
    zero.0.packets.fields[SCALAR_LEFT][AFTER_TAG] = F::ONE;
    zero.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F::ONE;
    assert!(!zero.accepts(&zero_program));
    let mut bad = fixture.clone();
    bad.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F::ZERO;
    assert!(!bad.accepts(&program));
}

#[test]
fn native_division_and_getgas_share_canonical_fetch_without_register_read_leakage() {
    for opcode in [
        wide::arithmetic::DIV,
        wide::arithmetic::DIVU,
        wide::arithmetic::REM,
        wide::arithmetic::REMU,
        wide::arithmetic::DIV_CEIL,
        wide::arithmetic::GCD,
    ] {
        let instructions = [
            enc::encode_rr(opcode, 4, 2, 3),
            enc::encode_rr(wide::system::GETGAS, 5, 4, 5),
            enc::encode_rr(opcode, 4, 5, 3),
        ];
        let (program, recorder, _) = shifts::capture(
            &instructions,
            &[(2, u64::MAX, false), (3, 3, false), (5, 29, true)],
            100,
            32,
        );
        assert!(recorder.records().len() >= instructions.len());
        for (instruction, record) in instructions.into_iter().zip(recorder.records()) {
            assert_eq!(record.instruction, Some(instruction));
            let fixture = ScalarFixture::from_record(&program, record);
            assert!(fixture.accepts(&program));
            let packets = &fixture.0.packets.fields;
            assert_eq!(packets[SCALAR_DESTINATION][AFTER_TAG], F::ZERO);
            if is_getgas(instruction) {
                assert_eq!(packets[SCALAR_DESTINATION][BEFORE_TAG], F::ONE);
                for slot in [SCALAR_LEFT, SCALAR_RIGHT] {
                    assert!(packets[slot].iter().all(|cell| *cell == F::ZERO));
                }
                assert!(
                    fixture.0.row[SCALAR + SOURCES..SCALAR + ALU]
                        .iter()
                        .all(|cell| *cell == F::ZERO)
                );
                assert_eq!(
                    packet::half(&packets[SCALAR_DESTINATION], AFTER, 0),
                    record.after.gas_remaining
                );
            } else {
                for slot in [SCALAR_LEFT, SCALAR_RIGHT] {
                    assert_eq!(packets[slot][ENABLED], F::ONE);
                    assert_eq!(packets[slot][BEFORE_TAG], F::ZERO);
                }
            }
        }
    }
}

#[test]
fn composed_private_scalar_polynomials_have_degree_four() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let artifact = contract(
        &[
            enc::encode_jump(wide::control::JAL, 0, 1),
            enc::encode_offset24(wide::control::JMP, 1),
            enc::encode_rr(wide::arithmetic::DIV, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::DIVU, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::REM, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::REMU, 4, 2, 3),
            enc::encode_rr(wide::system::GETGAS, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::ABS, 4, 2, 255),
            enc::encode_rr(wide::arithmetic::MEAN, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::ISQRT, 4, 2, 255),
            enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::GCD, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::CMOV, 4, 2, 3),
            enc::encode_ri(wide::arithmetic::CMOVI, 4, 2, -1),
            enc::encode_rr(wide::arithmetic::NOT, 4, 2, 255),
            enc::encode_rr(wide::arithmetic::NEG, 4, 2, 255),
            enc::encode_rr(wide::arithmetic::POPCNT, 4, 2, 255),
            enc::encode_rr(wide::arithmetic::CLZ, 4, 2, 255),
            enc::encode_rr(wide::arithmetic::CTZ, 4, 2, 255),
            enc::encode_rr(wide::arithmetic::MUL, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::MULHU, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::MULHSU, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::MULH, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::MIN, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::MAX, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::XOR, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::SLT, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::SLTU, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::SEQ, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::SNE, 4, 2, 3),
            enc::encode_ri(wide::arithmetic::ADDI, 4, 2, -1),
            enc::encode_branch(wide::control::BEQ, 2, 3, -1),
            enc::encode_branch(wide::control::BNE, 2, 3, 1),
            enc::encode_branch(wide::control::BLT, 2, 3, -2),
            enc::encode_branch(wide::control::BGE, 2, 3, 2),
            enc::encode_branch(wide::control::BLTU, 2, 3, -3),
            enc::encode_branch(wide::control::BGEU, 2, 3, 3),
            enc::encode_rr(wide::arithmetic::SLL, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::SRL, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::SRA, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::ROTL, 4, 2, 3),
            enc::encode_rr(wide::arithmetic::ROTR, 4, 2, 3),
            enc::encode_ri(wide::arithmetic::ROTL_IMM, 4, 2, i8::MIN),
            enc::encode_ri(wide::arithmetic::ROTR_IMM, 4, 2, -1),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    );
    let program = Program::new(artifact).unwrap();
    let schedule = Schedule::new(7, core::array::from_fn(|i| i as u32)).unwrap();
    let measured = measured_maximum_affine_degree_v1(
        [0x3d; 32],
        [super::super::WIDTH + PORTS * packet::WIDTH, 0, 0, 0, 0],
        8,
        4,
        |row, _, _, _, _| {
            let packets = OriginalPackets::candidate(core::array::from_fn(|slot| {
                row[super::super::WIDTH + slot * packet::WIDTH
                    ..super::super::WIDTH + (slot + 1) * packet::WIDTH]
                    .try_into()
                    .unwrap()
            }));
            let mut out = Vec::new();
            super::super::append_residues(
                &mut out,
                &program,
                schedule,
                row[..super::super::WIDTH].try_into().unwrap(),
                &packets,
            );
            Ok::<_, core::convert::Infallible>(out)
        },
    );
    assert_eq!(measured, 4);
}

#[test]
fn every_original_scalar_port_joins_all_private_history_stages() {
    use history::accepts;
    let (_, gas) = native(
        enc::encode_rr(wide::system::GETGAS, 4, 2, 3),
        &[(2, u64::MAX, true), (3, 23, true), (4, 19, true)],
    );
    assert!(accepts(&gas, None));
    for slot in [GAS_DEBIT, SCALAR_DESTINATION] {
        assert!(!accepts(&gas, Some((slot, false))));
        assert!(!accepts(&gas, Some((slot, true))));
    }
    for opcode in [
        wide::arithmetic::ADD,
        wide::arithmetic::SLT,
        wide::arithmetic::SLTU,
        wide::arithmetic::SEQ,
        wide::arithmetic::SNE,
        wide::arithmetic::MIN,
        wide::arithmetic::MAX,
        wide::arithmetic::MUL,
        wide::arithmetic::MULHU,
        wide::arithmetic::MULHSU,
        wide::arithmetic::MULH,
        wide::arithmetic::MEAN,
        wide::arithmetic::DIV,
        wide::arithmetic::DIVU,
        wide::arithmetic::REM,
        wide::arithmetic::REMU,
        wide::arithmetic::DIV_CEIL,
        wide::arithmetic::GCD,
    ] {
        let instruction = enc::encode_rr(opcode, 4, 2, 3);
        let tag = !is_division(instruction);
        let (_, fixture) = native(instruction, &[(2, 17, tag), (3, 23, tag), (4, 19, false)]);
        assert!(accepts(&fixture, None));
        for slot in [SCALAR_LEFT, SCALAR_RIGHT, SCALAR_DESTINATION] {
            assert!(!accepts(&fixture, Some((slot, false))));
            assert!(!accepts(&fixture, Some((slot, true))));
        }
    }
    for opcode in [
        wide::arithmetic::SLL,
        wide::arithmetic::SRL,
        wide::arithmetic::SRA,
        wide::arithmetic::ROTL,
        wide::arithmetic::ROTR,
    ] {
        let (_, fixture) = native(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, u64::MAX, true), (3, 63, true)],
        );
        assert!(accepts(&fixture, None));
        for slot in [SCALAR_LEFT, SCALAR_RIGHT, SCALAR_DESTINATION] {
            assert!(!accepts(&fixture, Some((slot, false))));
            assert!(!accepts(&fixture, Some((slot, true))));
        }
    }
    for opcode in [
        wide::arithmetic::ROTL_IMM,
        wide::arithmetic::ROTR_IMM,
        wide::arithmetic::NOT,
        wide::arithmetic::NEG,
        wide::arithmetic::ABS,
        wide::arithmetic::ISQRT,
    ] {
        let instruction = enc::encode_ri(opcode, 4, 2, -1);
        let (_, fixture) = native(
            instruction,
            &[(2, u64::MAX, !is_absolute(instruction)), (255, 17, false)],
        );
        assert!(accepts(&fixture, None));
        assert!(
            fixture.0.packets.fields[SCALAR_RIGHT]
                .iter()
                .all(|cell| *cell == F::ZERO)
        );
        for slot in [SCALAR_LEFT, SCALAR_DESTINATION] {
            assert!(!accepts(&fixture, Some((slot, false))));
            assert!(!accepts(&fixture, Some((slot, true))));
        }
    }
    // Shared source keys and complete source/destination aliasing require the
    // alternative history to propagate a replacement through every read.
    for opcode in [
        wide::arithmetic::ADD,
        wide::arithmetic::SLL,
        wide::arithmetic::GCD,
    ] {
        for (destination, left, right) in [(4, 2, 2), (2, 2, 2), (2, 2, 3), (3, 2, 3)] {
            let (_, fixture) = native(
                enc::encode_rr(opcode, destination, left, right),
                &[(2, 17, true), (3, 23, true), (4, 19, false)],
            );
            assert!(accepts(&fixture, None));
            for slot in [SCALAR_LEFT, SCALAR_RIGHT, SCALAR_DESTINATION] {
                assert!(!accepts(&fixture, Some((slot, false))));
                assert!(!accepts(&fixture, Some((slot, true))));
            }
        }
    }
    let body = shifts::mixed_body();
    let (program, recorder, _later_outcome) = shifts::capture(&body, &[], 64, 64);
    for record in &recorder.records()[..body.len()] {
        let fixture = ScalarFixture::from_record(&program, record);
        assert!(fixture.accepts(&program));
        assert!(accepts(&fixture, None));
        for slot in [SCALAR_LEFT, SCALAR_RIGHT, SCALAR_DESTINATION] {
            if fixture.0.packets.fields[slot][ENABLED] == F::ONE {
                assert!(!accepts(&fixture, Some((slot, false))));
                assert!(!accepts(&fixture, Some((slot, true))));
            }
        }
    }
    for opcode in [
        wide::control::BEQ,
        wide::control::BNE,
        wide::control::BLT,
        wide::control::BGE,
        wide::control::BLTU,
        wide::control::BGEU,
    ] {
        let (_, fixture) = native(
            enc::encode_branch(opcode, 2, 3, 2),
            &[(2, u64::MAX, false), (3, 0, false)],
        );
        assert!(accepts(&fixture, None));
        for slot in [SCALAR_LEFT, SCALAR_RIGHT] {
            assert!(!accepts(&fixture, Some((slot, false))));
            assert!(!accepts(&fixture, Some((slot, true))));
        }
    }
}

#[test]
fn consecutive_native_private_scalar_records_preserve_exact_register_and_control_boundaries() {
    let body = [
        enc::encode_rr(wide::arithmetic::ADD, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SUB, 2, 4, 2),
        enc::encode_ri(wide::arithmetic::XORI, 3, 2, -1),
        enc::encode_rr(wide::arithmetic::AND, 4, 3, 4),
        enc::encode_ri(wide::arithmetic::ORI, 2, 4, i8::MIN),
        enc::encode_rr(wide::arithmetic::OR, 3, 2, 3),
        enc::encode_ri(wide::arithmetic::ANDI, 4, 3, 127),
        enc::encode_ri(wide::arithmetic::ADDI, 4, 4, -1),
        enc::encode_rr(wide::arithmetic::XOR, 0, 4, 2),
        enc::encode_rr(wide::arithmetic::SLT, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SLTU, 2, 3, 2),
        enc::encode_rr(wide::arithmetic::SEQ, 3, 4, 2),
        enc::encode_rr(wide::arithmetic::SNE, 0, 2, 3),
    ];
    let artifact = contract(&body, 1_000, ivm::ivm_mode::ZK);
    let mut vm = IVM::new(100);
    vm.load_prepared(&artifact).unwrap();
    for (register, value) in [(2, u64::MAX), (3, 2)] {
        vm.set_register(register, value);
        vm.registers.set_tag(register, true);
    }
    let budget = AllocationBudget::new(64 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(64, &budget).unwrap();
    let _later_return =
        vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
    let program = Program::new(artifact).unwrap();
    let records = &recorder.records()[..body.len()];
    for (instruction, record) in body.into_iter().zip(records) {
        assert_eq!(record.instruction, Some(instruction));
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
    for pair in records.windows(2) {
        assert_eq!(pair[0].after, pair[1].before);
    }
    assert_eq!(records.last().unwrap().after.registers[0], 0);
    assert!(!records.last().unwrap().after.tags[0]);
}

#[test]
fn native_private_comparisons_cover_signed_unsigned_equality_aliases_and_r0() {
    // Include a whole-field modulus to reject equality via a reduced u64 cell.
    let pairs = [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (u64::MAX, 0),
        (0, u64::MAX),
        (u64::MAX, u64::MAX),
        (i64::MAX as u64, i64::MIN as u64),
        (i64::MIN as u64, i64::MAX as u64),
        (i64::MIN as u64, u64::MAX),
        (0xffff_ffff_0000_0001, 0),
        (0, 0xffff_ffff_0000_0001),
        (0x1234_ffff_0000_0001, 0x1234_0000_ffff_0001),
    ];
    for opcode in [
        wide::arithmetic::SLT,
        wide::arithmetic::SLTU,
        wide::arithmetic::SEQ,
        wide::arithmetic::SNE,
    ] {
        for (left, right) in pairs {
            for tag in [false, true] {
                for (rd, rs1, rs2) in [(4, 2, 3), (2, 2, 3), (3, 2, 3), (2, 2, 2), (0, 2, 3)] {
                    native(
                        enc::encode_rr(opcode, rd, rs1, rs2),
                        &[(2, left, tag), (3, right, tag), (4, 19, !tag)],
                    );
                }
            }
        }
        for (rd, rs1, rs2) in [(4, 0, 0), (0, 0, 0), (4, 0, 3), (4, 2, 0)] {
            native(
                enc::encode_rr(opcode, rd, rs1, rs2),
                &[
                    (2, u64::MAX, false),
                    (3, i64::MIN as u64, false),
                    (4, 19, true),
                ],
            );
        }
    }
}

#[test]
fn comparison_fetch_sign_predicate_result_and_modular_alias_forgery_reject() {
    let instruction = enc::encode_rr(wide::arithmetic::SLT, 4, 2, 3);
    let (program, fixture) = native(instruction, &[(2, u64::MAX, true), (3, 0, true)]);
    for replacement in [
        enc::encode_rr(wide::arithmetic::SLTU, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SEQ, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::SLT, 4, 3, 2),
        enc::encode_rr(wide::arithmetic::SLT, 4, 2, 2),
        enc::encode_rr(wide::arithmetic::SLT, 5, 2, 3),
    ] {
        let changed = Program::new(contract(&[replacement], 1_000, ivm::ivm_mode::ZK)).unwrap();
        assert!(!fixture.accepts(&changed));
    }
    let mut changed = fixture.clone();
    changed.0.row[SCALAR + 63] = F::ZERO;
    assert!(!changed.accepts(&program));
    for limb in 0..4 {
        let mut changed = fixture.clone();
        changed.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = F(2);
        assert!(!changed.accepts(&program));
    }
    let (program, mut reduced) = native(
        enc::encode_rr(wide::arithmetic::SEQ, 4, 2, 3),
        &[(2, 0xffff_ffff_0000_0001, true), (3, 0, true)],
    );
    // A complete, internally coherent comparison workspace for equal reduced
    // words still cannot replace the original canonical register operands.
    reduced.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
        .copy_from_slice(&branch::bank_witness(wide::control::BEQ, 0, 0));
    reduced.0.packets.fields[SCALAR_DESTINATION][AFTER] = F::ONE;
    assert!(!reduced.accepts(&program));
}

#[test]
fn comparison_workspace_remains_canonical_on_alu_and_padding_rows() {
    let (program, fixture) = native(
        enc::encode_rr(wide::arithmetic::ADD, 4, 2, 3),
        &[(2, u64::MAX, true), (3, 1, true)],
    );
    let padding = ScalarFixture(Fixture::padding());
    assert!(padding.accepts(&program));
    for original in [fixture, padding] {
        for column in SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS {
            let mut changed = original.clone();
            changed.0.row[column] = changed.0.row[column].add(F::ONE);
            assert!(
                !changed.accepts(&program),
                "unused comparison column {column}"
            );
        }
    }
}

mod branches;
mod multiplication;
mod shifts;
mod unary_select;

mod bit_counts;

mod conditional_moves;

mod absolute;
mod div_rem;
mod getgas;

mod history;
mod jumps;
mod means;
mod square_roots;

mod ceiling_division;
mod greatest_common_divisor;
