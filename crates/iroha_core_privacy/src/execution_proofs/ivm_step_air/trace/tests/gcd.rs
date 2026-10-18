//! Native parity, physical-slot ownership and direct forged Euclidean witnesses.

use super::super::gcd as gcd_air;
use super::div_rem::attempted;
use super::*;

const F91: u64 = 4_660_046_610_375_530_309;
const F92: u64 = 7_540_113_804_746_346_429;

fn expected(a: u64, b: u64) -> (u64, usize) {
    // Independent integer reference; the verifier never calls this implementation.
    let (mut a, mut b) = (
        u64::cast_signed(a).unsigned_abs(),
        u64::cast_signed(b).unsigned_abs(),
    );
    let mut divisions = 0;
    while b != 0 {
        (a, b) = (b, a % b);
        divisions += 1;
    }
    (a, divisions)
}

fn single(
    a: u64,
    b: u64,
    gas: u64,
    destination: usize,
) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    attempted(
        &[enc::encode_rr(
            wide::arithmetic::GCD,
            destination as u8,
            6,
            7,
        )],
        1,
        &[(6, a), (7, b), (8, 91)],
        gas,
    )
}

#[test]
fn gcd_native_full_signed_domain_edges_aliases_and_exact_gas_cycles() {
    let values = [
        0,
        1,
        u64::MAX,
        12,
        i64::cast_unsigned(-18_i64),
        i64::cast_unsigned(i64::MIN),
        i64::MAX as u64,
        F91,
        F92,
    ];
    for a in values {
        for b in values {
            let (segment, records) = single(a, b, 12, 8);
            assert_eq!(segment.stride(), 93);
            let rows = segment.witness_rows(&records).unwrap();
            assert_eq!(rows.len(), 94);
            assert_rows(&segment, &rows);
            let (result, divisions) = expected(a, b);
            assert!(divisions <= 91);
            assert_eq!(segment.after.registers[8], result);
            assert_eq!(
                segment.before.gas_remaining - segment.after.gas_remaining,
                12
            );
            assert_eq!(segment.after.cycles - segment.before.cycles, 12);
            assert_eq!(segment.after.pc - segment.before.pc, 4);
            for row in &rows[..93] {
                assert_eq!(&row[..REGISTER_WIDTH], &rows[0][..REGISTER_WIDTH]);
                assert_eq!(row[PC], rows[0][PC]);
                assert_eq!(&row[GAS..GAS + 2], &rows[0][GAS..GAS + 2]);
                assert_eq!(&row[CYCLES..CYCLES + 2], &rows[0][CYCLES..CYCLES + 2]);
            }
        }
    }
    assert_eq!(expected(F91, F92), (1, 91));
    let f93 = u128::from(F91) + u128::from(F92);
    assert_eq!(f93, 12_200_160_415_121_876_738);
    assert!(f93 > 1_u128 << 63);
    for destination in [0, 6, 7, 8] {
        let (segment, records) = single(i64::cast_unsigned(i64::MIN), 0, 12, destination);
        assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        for register in 0..REGISTERS {
            assert_eq!(
                segment.after.registers[register],
                if register == destination && register != 0 {
                    1 << 63
                } else {
                    segment.before.registers[register]
                }
            );
        }
    }
}

#[test]
fn gcd_oog_precedes_arithmetic_and_keeps_every_architectural_component() {
    for gas in [0, 1, 3, 4, 7, 8, 11, 12, 13, 15, 16, (1 << 32) - 1, 1 << 32] {
        let (segment, records) = single(i64::cast_unsigned(i64::MIN), 0, gas, 8);
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        if gas < 12 {
            assert_eq!(segment.outcome, SegmentOutcome::OutOfGas);
            assert_eq!(segment.before, segment.after);
            assert!(
                rows.iter()
                    .all(|row| row[GCD..].iter().all(|cell| *cell == F::ZERO))
            );
        } else {
            assert_eq!(segment.outcome, SegmentOutcome::Continue);
            assert_eq!(segment.after.gas_remaining, gas - 12);
            assert_eq!(segment.after.registers[8], 1 << 63);
        }
        for (row, column) in [
            (0, ABSOLUTE + 40),
            (0, MEAN_GAS),
            (0, MEAN_GAS + 1),
            (92, GAS_BORROW),
            (92, CYCLE_CARRY),
        ] {
            let mut changed = rows.clone();
            changed[row][column] = changed[row][column].add(F::ONE);
            assert!(
                rejects(&segment, &changed),
                "gas={gas}, row={row}, column={column}"
            );
        }
    }
}

#[test]
fn gcd_modes_fetch_magnitudes_division_and_terminal_cannot_be_forged() {
    let (segment, records) = single(F91, F92, 12, 8);
    let rows = segment.witness_rows(&records).unwrap();
    assert_rows(&segment, &rows);
    let mut mutations = Vec::new();
    for phase in [0, 1, 2, 45, 91, 92, 93] {
        for mode in 0..gcd_air::WIDTH {
            mutations.push((phase, GCD + mode));
        }
    }
    mutations.extend([
        (0, MULTIPLY + multiply::SIGNED_UNSIGNED),
        (0, MULTIPLY + multiply::SIGNED_SIGNED),
        (0, MULTIPLY + multiply::PRODUCT),
        (0, SHIFT + division::QUOTIENT),
        (1, SOURCES),
        (1, SHIFT + division::QUOTIENT),
        (1, SHIFT + division::REMAINDER),
        (1, SHIFT + division::ZERO_DENOMINATOR),
        (1, SHIFT + division::ZERO_INVERSE),
        (1, SHIFT + division::SUM_CARRIES + 7),
        (1, MULTIPLY + multiply::PRODUCT + 7),
        (1, MULTIPLY + multiply::CARRY),
        (1, BRANCH + branch::BORROW + 3),
        (45, 2 * 255),
        (45, PC),
        (45, GAS),
        (45, CYCLES),
        (45, FETCH),
        (92, RESULT),
        (92, SOURCES + 64),
        (93, 2 * 8),
    ]);
    for (phase, column) in mutations {
        let mut changed = rows.clone();
        changed[phase][column] = changed[phase][column].add(F::ONE);
        assert!(
            rejects(&segment, &changed),
            "phase={phase}, column={column}"
        );
    }
    // A complete valid foreign Euclidean chain still cannot replace this entry.
    let (foreign, foreign_records) = single(12, 18, 12, 8);
    let foreign_rows = foreign.witness_rows(&foreign_records).unwrap();
    let mut changed = rows.clone();
    for phase in 1..93 {
        changed[phase][SOURCES..].copy_from_slice(&foreign_rows[phase][SOURCES..]);
    }
    assert!(rejects(&segment, &changed));
    // A coherently generated final row with B nonzero must fail its fixed terminal.
    let mut changed = rows.clone();
    changed[92] = segment.witness_row_at(&segment.before, Some((0, segment.words[0])), 92, [1, 1]);
    assert!(rejects(&segment, &changed));
}

#[test]
fn gcd_zero_denominator_slots_freeze_without_internal_division_or_gas() {
    let (segment, records) = single(42, 0, 12, 8);
    let rows = segment.witness_rows(&records).unwrap();
    assert_rows(&segment, &rows);
    for row in &rows[1..92] {
        assert_eq!(row[GCD + gcd_air::WORK], F::ONE);
        assert_eq!(row[GCD + gcd_air::DIVIDE], F::ZERO);
        assert_eq!(Sources::new(&row[SOURCES..ALU]).half(0, 0), F(42));
        assert_eq!(row[SHIFT + division::ZERO_DENOMINATOR], F::ONE);
        assert!(
            row[SHIFT + division::QUOTIENT..SHIFT + division::QUOTIENT + 4]
                .iter()
                .all(|v| *v == F::ZERO)
        );
        assert!(
            row[MULTIPLY + multiply::PRODUCT..MULTIPLY + multiply::PRODUCT + 8]
                .iter()
                .all(|v| *v == F::ZERO)
        );
    }
    for column in [
        SHIFT + division::QUOTIENT,
        SHIFT + division::REMAINDER,
        MULTIPLY + multiply::PRODUCT,
        GCD + gcd_air::DIVIDE,
        GAS_BORROW,
        CYCLE_CARRY,
    ] {
        let mut changed = rows.clone();
        changed[40][column] = F::ONE;
        assert!(rejects(&segment, &changed));
    }
}

#[test]
fn gcd_schedule_comes_from_complete_code_and_binds_unreachable_words() {
    let add = enc::encode_ri(wide::arithmetic::ADDI, 8, 0, 1);
    let gcd = enc::encode_rr(wide::arithmetic::GCD, 9, 6, 7);
    let (plain, plain_records) = attempted(&[add], 1, &[], 1);
    let (expanded, records) = attempted(&[add, gcd], 1, &[], 1);
    assert_eq!(plain.stride(), 1);
    assert_eq!(
        expanded.stride(),
        93,
        "unreachable GCD participates in authenticated code policy"
    );
    let rows = expanded.witness_rows(&records).unwrap();
    assert_rows(&expanded, &rows);
    assert_eq!(rows.len(), 94);
    assert_ne!(plain.digest().unwrap(), expanded.digest().unwrap());
    let short = plain.witness_rows(&plain_records).unwrap();
    // Supplying one physical step to the expanded schedule cannot commit at row zero.
    let mut changed = rows.clone();
    changed[1] = short[1].clone();
    assert!(rejects(&expanded, &changed));
    let mut changed = rows.clone();
    changed[0][FETCH] = F::ZERO;
    changed[0][FETCH + 1] = F::ONE;
    assert!(
        rejects(&expanded, &changed),
        "witness cannot replace fetched ADD with unreachable GCD"
    );
    let mut invented = expanded;
    invented.words[1] = add;
    assert!(
        invented.validate().is_err(),
        "schedule word substitution must disagree with prepared artifact"
    );
}

#[test]
fn gcd_cycle_limit_allows_last_crossing_and_rejects_a_later_attempt() {
    let body = [
        enc::encode_rr(wide::arithmetic::GCD, 8, 6, 7),
        enc::encode_ri(wide::arithmetic::ADDI, 9, 0, 1),
    ];
    let prepared = contract_with_cycle_policy(&body, 11, 0);
    let mut vm = IVM::new(1_000);
    vm.load_prepared(&prepared).unwrap();
    vm.set_register(6, F91);
    vm.set_register(7, F92);
    let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
    assert!(
        vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder)
            .is_err()
    );
    let first = recorder.records()[0];
    assert_eq!(first.outcome, DiagnosticStepOutcome::Completed);
    assert_eq!(first.after.cycles, 12);
    let segment = ScalarSegment::new(
        prepared.clone(),
        1,
        first.before,
        first.after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    let first_rows = segment.witness_rows(std::slice::from_ref(&first)).unwrap();
    assert_rows(&segment, &first_rows);
    let mut invented_after = first.after;
    invented_after.pc += 4;
    invented_after.cycles += 1;
    invented_after.gas_remaining -= 1;
    invented_after.registers[9] = 1;
    let invented = ScalarSegment::new(
        prepared,
        2,
        first.before,
        invented_after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    let mut rows = first_rows[..93].to_vec();
    for phase in 0..93 {
        rows.push(invented.witness_row_at(&first.after, Some((1, body[1])), phase, [0, 0]));
    }
    rows.push(invented.witness_row(&invented_after, None));
    assert!(
        rejects(&invented, &rows),
        "the second attempt begins after the artifact's cycle limit"
    );
}

fn maximum() -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let mut body = vec![
        enc::encode_rr(wide::arithmetic::GCD, 9, 6, 7),
        enc::encode_rr(wide::arithmetic::MEAN, 10, 6, 7),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1),
        enc::encode_branch(wide::control::BNE, 2, 0, -3),
    ];
    body.resize(
        MAX_WORDS - crate::ivm_test_support::unit_return().len() / 4,
        enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
    );
    let (segment, records) = attempted(&body, 64, &[(2, 16), (6, F91), (7, F92)], 256);
    assert_eq!(segment.words.len(), MAX_WORDS);
    assert_eq!(segment.steps, MAX_STEPS);
    assert_eq!(segment.after.cycles - segment.before.cycles, 272);
    assert_eq!(segment.after.gas_remaining, 0);
    assert_eq!(segment.after.registers[9], 1);
    assert_eq!(segment.physical_steps(), 5952);
    (segment, records)
}

#[test]
fn gcd_both_schedules_preserve_query_cap_geometry_and_native_degree_four() {
    let (expanded, records) = maximum();
    assert_rows(&expanded, &expanded.witness_rows(&records).unwrap());
    let (plain, records) = attempted(
        &[enc::encode_ri(wide::arithmetic::ADDI, 8, 0, 1)],
        1,
        &[],
        1,
    );
    assert_rows(&plain, &plain.witness_rows(&records).unwrap());
    for segment in [plain, expanded] {
        assert_eq!(segment.base_width_v1(), 1_356);
        assert_eq!(segment.profile_fixed_width_v1(), 10);
        assert_eq!(segment.profile_constraint_count_v1(), 3_369);
        let protocol = segment.protocol_v1();
        protocol.validate().unwrap();
        assert_eq!(protocol.parameters.query_count, 136);
        assert_eq!(protocol.parameters.maximum_proof_bytes, 4 * 1024 * 1024);
        let layout = AggregateProofLayoutV1::new(
            protocol.parameters,
            vec![AggregateTraceGroupLayoutV1 {
                native_trace_log2: TRACE_LOG2,
                segment_instances: 1,
                base_width: segment.base_width_v1(),
                aux_width: NOTE_COPY_AUX_WIDTH_V1,
            }],
        )
        .unwrap();
        assert_eq!(
            maximum_encoded_proof_with_deep_bytes_v1(protocol.parameters, &layout).unwrap(),
            4_153_152
        );
        assert_eq!(
            measured_maximum_affine_degree_v1(
                [0xe9; 32],
                [ROW_WIDTH, ROW_WIDTH, 0, 0, FIXED_WIDTH],
                3,
                4,
                |row, next, _, _, fixed| residues(&segment, row, next, fixed)
            ),
            4
        );
    }
}

#[test]
fn native_stark_proves_maximum_gcd_microsteps_and_rejects_boundary_and_schedule_substitution() {
    let (segment, records) = maximum();
    let columns = segment.columns(&records).unwrap();
    let proof = prove_proof_managed_note_stark_v1(&segment, &columns).unwrap();
    assert!(proof.len() <= 4_153_152);
    verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
    for field in 0..4 {
        let mut after = segment.after;
        match field {
            0 => after.registers[9] ^= 1,
            1 => after.gas_remaining += 1,
            2 => after.cycles += 1,
            _ => after.pc += 4,
        }
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            segment.steps,
            segment.before,
            after,
            segment.outcome,
        )
        .unwrap();
        assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
    }
    let (plain, _) = attempted(
        &[enc::encode_ri(wide::arithmetic::ADDI, 8, 0, 1)],
        1,
        &[],
        1,
    );
    assert!(verify_proof_managed_note_stark_v1(&plain, &proof).is_err());
    for (physical, column) in [
        (1, SOURCES),
        (45, GCD + gcd_air::WORK),
        (92, RESULT),
        (5951, GCD + gcd_air::COMMIT),
    ] {
        let mut changed = columns.clone();
        changed[NOTE_COPY_WIDTH_V1 + column][physical] =
            changed[NOTE_COPY_WIDTH_V1 + column][physical].add(F::ONE);
        assert!(prove_proof_managed_note_stark_v1(&segment, &changed).is_err());
    }
}
