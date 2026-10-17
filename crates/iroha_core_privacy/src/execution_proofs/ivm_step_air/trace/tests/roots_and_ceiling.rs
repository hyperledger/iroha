//! Native scalar nonlinear arithmetic, malformed witnesses and unchanged proof limits.

use super::div_rem::attempted;
use super::*;

fn single(
    opcode: u8,
    left: u64,
    right: u64,
    gas: u64,
) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    attempted(
        &[enc::encode_rr(opcode, 8, 6, 7)],
        1,
        &[(6, left), (7, right), (8, 91)],
        gas,
    )
}

fn assert_result(
    segment: &ScalarSegment,
    rd: u8,
    result: Result<u64, SegmentOutcome>,
    cost: u64,
    cycles: u64,
) {
    let outcome = result.err().unwrap_or(SegmentOutcome::Continue);
    let completed = !outcome.trapped();
    let mut registers = segment.before.registers;
    if let Ok(value) = result {
        if rd != 0 {
            registers[usize::from(rd)] = value;
        }
    }
    assert_eq!(segment.outcome, outcome);
    assert_eq!(segment.after.registers, registers);
    assert_eq!(segment.after.tags, segment.before.tags);
    assert_eq!(
        segment.after.pc,
        segment.before.pc + 4 * u64::from(completed)
    );
    assert_eq!(
        segment.after.cycles,
        segment.before.cycles + cycles * u64::from(completed)
    );
    assert_eq!(
        segment.after.gas_remaining,
        segment.before.gas_remaining
            - if outcome == SegmentOutcome::OutOfGas {
                0
            } else {
                cost
            }
    );
    assert!(!segment.after.halted && !segment.after.constraint_failed);
}

#[test]
fn isqrt_matches_native_square_boundaries_aliases_r0_unused_operand_and_gas() {
    let mut values = vec![0, 1, 2, 3, u64::MAX, 0xffff_ffff_0000_0001, 1 << 63];
    for root in [
        2_u64,
        3,
        255,
        256,
        65_535,
        65_536,
        (1 << 31) - 1,
        1 << 31,
        u64::from(u32::MAX),
    ] {
        let square = root * root;
        values.extend([square - 1, square, square + 1]);
    }
    for value in values {
        for (rd, rs) in [(8, 6), (6, 6), (0, 6), (8, 0), (0, 0)] {
            for gas in [0, 5, 6, 7, 1 << 32] {
                let (segment, records) = attempted(
                    &[enc::encode_rr(wide::arithmetic::ISQRT, rd, rs, 255)],
                    1,
                    &[(6, value), (8, 91), (255, u64::MAX)],
                    gas,
                );
                let source = segment.before.registers[usize::from(rs)];
                let root = segment.after.registers[usize::from(rd)];
                if gas >= 6 && rd != 0 {
                    assert!(u128::from(root) * u128::from(root) <= u128::from(source));
                    assert!(u128::from(root + 1) * u128::from(root + 1) > u128::from(source));
                    assert!(root <= u64::from(u32::MAX));
                }
                assert_result(
                    &segment,
                    rd,
                    if gas < 6 {
                        Err(SegmentOutcome::OutOfGas)
                    } else {
                        Ok(root)
                    },
                    6,
                    6,
                );
                assert_eq!(records[0].opcode_gas, Some(6));
                let rows = segment.witness_rows(&records).unwrap();
                assert_rows(&segment, &rows);
                let sources = Sources::new(&rows[0][SOURCES..ALU]);
                assert_eq!(sources.half(1, 0), F::ZERO);
                assert_eq!(sources.half(1, 1), F::ZERO);
            }
        }
    }
}

#[test]
fn div_ceil_matches_native_all_signs_overflow_zero_aliases_r0_and_gas_precedence() {
    let pairs = [
        (0, 1),
        (17, 5),
        (-17, 5),
        (17, -5),
        (-17, -5),
        (20, 5),
        (-20, -5),
        (1, 2),
        (-1, 2),
        (1, -2),
        (-1, -2),
        (i64::MIN, -1),
        (i64::MIN, 1),
        (i64::MIN, i64::MIN),
        (i64::MAX, 1),
        (i64::MAX, 2),
        (17, 0),
        (0, 0),
    ];
    for (left, right) in pairs {
        for (rd, rs1, rs2) in [
            (8, 6, 7),
            (6, 6, 7),
            (7, 6, 7),
            (6, 6, 6),
            (0, 6, 7),
            (8, 0, 7),
            (8, 6, 0),
            (0, 0, 0),
        ] {
            for gas in [0, 11, 12, 13, 1 << 32] {
                let (segment, records) = attempted(
                    &[enc::encode_rr(wide::arithmetic::DIV_CEIL, rd, rs1, rs2)],
                    1,
                    &[
                        (6, i64::cast_unsigned(left)),
                        (7, i64::cast_unsigned(right)),
                        (8, 91),
                    ],
                    gas,
                );
                let a = i128::from(u64::cast_signed(segment.before.registers[usize::from(rs1)]));
                let b = i128::from(u64::cast_signed(segment.before.registers[usize::from(rs2)]));
                let result = if gas < 12 {
                    Err(SegmentOutcome::OutOfGas)
                } else if b == 0 || (a == i128::from(i64::MIN) && b == -1) {
                    Err(SegmentOutcome::AssertionFailed)
                } else {
                    Ok((a / b + i128::from(a % b != 0 && (a < 0) == (b < 0))) as u64)
                };
                assert_result(&segment, rd, result, 12, 12);
                assert_eq!(records[0].opcode_gas, Some(12));
                assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            }
        }
    }
}

#[test]
fn root_and_ceiling_all_interior_columns_are_bound_on_success_and_native_traps() {
    for (opcode, a, b, gas) in [
        (wide::arithmetic::ISQRT, u64::MAX, 99, 7),
        (wide::arithmetic::ISQRT, u64::MAX, 99, 6),
        (
            wide::arithmetic::DIV_CEIL,
            i64::cast_unsigned(-17_i64),
            i64::cast_unsigned(-5_i64),
            13,
        ),
        (wide::arithmetic::DIV_CEIL, 17, 0, 13),
        (
            wide::arithmetic::DIV_CEIL,
            i64::cast_unsigned(i64::MIN),
            u64::MAX,
            12,
        ),
    ] {
        let (segment, records) = attempted(
            &[
                enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
                enc::encode_rr(opcode, 8, 6, 7),
            ],
            2,
            &[(6, a), (7, b), (8, 91)],
            gas,
        );
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        for column in 0..ROW_WIDTH {
            let mut forged = rows.clone();
            forged[1][column] = forged[1][column].add(F::ONE);
            assert!(
                rejects(&segment, &forged),
                "opcode {opcode:#x} {:?}, column {column}",
                segment.outcome
            );
        }
    }
}

fn changed_destination(
    segment: &ScalarSegment,
    records: &[DiagnosticStepRecord],
    value: u64,
) -> (ScalarSegment, Vec<Vec<F>>) {
    let mut records = records.to_vec();
    records[0].after.registers[8] = value;
    let changed = ScalarSegment::new(
        segment.contract.clone(),
        1,
        records[0].before,
        records[0].after,
        segment.outcome,
    )
    .unwrap();
    let mut rows = changed.witness_rows(&records).unwrap();
    rows[0][RESULT..RESULT + 2].copy_from_slice(&halves(value));
    (changed, rows)
}

fn replace_word(bank: &mut [F], offset: usize, value: u64) {
    for limb in 0..4 {
        bank[offset + limb] = F((value >> (16 * limb)) & 0xffff);
    }
    word::fill_digits(&mut bank[offset + 4..offset + 36], value);
}

#[test]
fn isqrt_rejects_coherent_smaller_root_even_when_product_plus_remainder_is_exact() {
    let (segment, records) = single(wide::arithmetic::ISQRT, 25, 99, 6);
    // q=4,r=9 preserves 25=q²+r, but violates r<=2q. The complete product,
    // digits, signed-correction slots, result and public destination agree.
    let (changed, mut rows) = changed_destination(&segment, &records, 4);
    let bank = &mut rows[0][SHIFT..RESULT];
    replace_word(bank, division::QUOTIENT, 4);
    replace_word(bank, division::REMAINDER, 9);
    replace_word(bank, division::REMAINDER_RESULT, 8);
    let bound = multiply::correction_witness(8, 9);
    bank[division::QUOTIENT_RESULT..division::QUOTIENT_RESULT + 36].copy_from_slice(&bound[..36]);
    bank[division::QUOTIENT_BORROWS..division::QUOTIENT_BORROWS + 4].copy_from_slice(&bound[36..]);
    bank[division::SUM_CARRIES..division::SUM_CARRIES + 8].fill(F::ZERO);
    let digits = multiply::product_digits(4, 4);
    let mut product = multiply::witness(4, 4, &digits, true);
    product[multiply::SIGNED_UNSIGNED..multiply::SIGNED_SIGNED]
        .copy_from_slice(&multiply::correction_witness(25, 0));
    product[multiply::SIGNED_SIGNED..].copy_from_slice(&multiply::correction_witness(4, 0));
    rows[0][BIT_COUNT..MULTIPLY].copy_from_slice(&digits);
    rows[0][MULTIPLY..ABSOLUTE].copy_from_slice(&product);
    assert!(rejects(&changed, &rows));
    rows[0][SHIFT + division::QUOTIENT_BORROWS + 3] = F::ZERO;
    assert!(
        rejects(&changed, &rows),
        "forged bound carry cannot erase the underflow"
    );
}

#[test]
fn div_ceil_rejects_truncation_wrong_sign_correction_and_false_remainder_zero() {
    for (a, b, false_value) in [
        (17_i64, 5_i64, 3_u64),
        (-17, -5, 3),
        (-17, 5, i64::cast_unsigned(-2_i64)),
        (20, 5, 5),
    ] {
        let (segment, records) = single(
            wide::arithmetic::DIV_CEIL,
            i64::cast_unsigned(a),
            i64::cast_unsigned(b),
            12,
        );
        let (changed, mut rows) = changed_destination(&segment, &records, false_value);
        replace_word(&mut rows[0][ABSOLUTE..MEAN_GAS], 0, false_value);
        rows[0][ABSOLUTE + 36..ABSOLUTE + 40].fill(F::ZERO);
        rows[0][ABSOLUTE + 42] = F(u64::from(false_value != i64::cast_unsigned(a / b)));
        assert!(rejects(&changed, &rows));
        rows[0][ABSOLUTE + 40] = F::ZERO;
        rows[0][ABSOLUTE + 41] = F::ZERO;
        assert!(rejects(&changed, &rows));
    }
}

#[test]
fn root_and_ceiling_exact_cycle_carries_and_limit_crossing_match_native_ordering() {
    for (opcode, cost) in [
        (wide::arithmetic::ISQRT, 6),
        (wide::arithmetic::DIV_CEIL, 12),
    ] {
        for gas in [cost - 1, cost] {
            let (original, actual) = single(opcode, 17, 5, gas);
            for before in [u64::from(u32::MAX) - cost + 1, u64::from(u32::MAX)] {
                let mut records = actual.clone();
                records[0].before.cycles = before;
                records[0].after.cycles = before + if gas >= cost { cost } else { 0 };
                let segment = ScalarSegment::new(
                    original.contract.clone(),
                    1,
                    records[0].before,
                    records[0].after,
                    original.outcome,
                )
                .unwrap();
                let rows = segment.witness_rows(&records).unwrap();
                assert_rows(&segment, &rows);
                assert_eq!(rows[0][CYCLE_CARRY], F(u64::from(gas >= cost)));
            }
        }
        let body = [
            enc::encode_rr(opcode, 8, 6, 7),
            enc::encode_ri(wide::arithmetic::ADDI, 9, 9, 1),
        ];
        let prepared = contract_with_cycle_policy(&body, cost - 1, 0);
        let root_words = crate::ivm_test_support::unit_callable(0)
            .result_word_count()
            .unwrap() as u64;
        let mut vm = IVM::new(100 + root_words * (ivm_abi::call::CALL_WORD_BYTES_V1 as u64 + 1));
        vm.load_prepared(&prepared).unwrap();
        vm.set_register(6, 17);
        vm.set_register(7, 5);
        let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
        let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
        assert!(matches!(
            vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder),
            Err(ivm::VMError::ExceededMaxCycles)
        ));
        assert_eq!(recorder.records().len(), 1);
        let record = &recorder.records()[0];
        assert_eq!(record.after.cycles - record.before.cycles, cost);
        let segment = ScalarSegment::new(
            prepared.clone(),
            1,
            record.before,
            record.after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert_rows(
            &segment,
            &segment.witness_rows(std::slice::from_ref(record)).unwrap(),
        );
        let mut final_state = record.after;
        final_state.pc += 4;
        final_state.cycles += 1;
        final_state.gas_remaining -= ivm::gas::cost_of(body[1]).unwrap();
        final_state.registers[9] += 1;
        let invented = ScalarSegment::new(
            prepared,
            2,
            record.before,
            final_state,
            SegmentOutcome::Continue,
        )
        .unwrap();
        let rows = vec![
            invented.witness_row(&record.before, Some((0, body[0]))),
            invented.witness_row(&record.after, Some((1, body[1]))),
            invented.witness_row(&final_state, None),
        ];
        assert!(rejects(&invented, &rows));
    }
}

fn maximum(tail_gas: u64) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let mut body = vec![
        enc::encode_rr(wide::arithmetic::ISQRT, 8, 6, 7),
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 9, 6, 7),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1),
        enc::encode_branch(wide::control::BNE, 2, 0, -3),
        enc::encode_rr(wide::arithmetic::ISQRT, 8, 6, 7),
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 9, 6, 7),
        enc::encode_rr(wide::arithmetic::MEAN, 10, 6, 7),
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 0, 6, 0),
    ];
    let cost = body[..4]
        .iter()
        .map(|w| ivm::gas::cost_of(*w).unwrap())
        .sum::<u64>()
        * 15
        + body[4..7]
            .iter()
            .map(|w| ivm::gas::cost_of(*w).unwrap())
            .sum::<u64>();
    body.resize(
        MAX_WORDS - crate::ivm_test_support::unit_return().len() / 4,
        enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
    );
    let (segment, records) = attempted(
        &body,
        MAX_STEPS,
        &[(2, 15), (6, i64::MAX as u64), (7, 5)],
        cost + tail_gas,
    );
    assert_eq!(segment.steps, MAX_STEPS);
    assert_eq!(segment.words.len(), MAX_WORDS);
    assert_eq!(segment.after.cycles - segment.before.cycles, 321);
    assert_eq!(
        segment.outcome,
        if tail_gas < 12 {
            SegmentOutcome::OutOfGas
        } else {
            SegmentOutcome::AssertionFailed
        }
    );
    (segment, records)
}

#[test]
fn nonlinear_scalar_maximum_geometry_preserves_cap_queries_and_degree_four() {
    for tail in [11, 12] {
        let (segment, records) = maximum(tail);
        assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        assert_eq!(segment.base_width_v1(), 1_356);
        assert_eq!(segment.profile_constraint_count_v1(), 3_369);
        assert_eq!(segment.profile_fixed_width_v1(), 10);
        let protocol = segment.protocol_v1();
        protocol.validate().unwrap();
        assert_eq!(protocol.maximum_constraint_degree, 4);
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
        let bound = maximum_encoded_proof_with_deep_bytes_v1(protocol.parameters, &layout).unwrap();
        assert_eq!(bound, 4_153_152);
        assert_eq!(protocol.parameters.maximum_proof_bytes - bound, 41_152);
        assert_eq!(
            measured_maximum_affine_degree_v1(
                [0xd0 + tail as u8; 32],
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
fn native_stark_proves_nonlinear_maximum_trace_and_binds_boundaries_and_workspaces() {
    for tail in [11, 12] {
        let (segment, records) = maximum(tail);
        let columns = segment.columns(&records).unwrap();
        let proof = prove_proof_managed_note_stark_v1(&segment, &columns).unwrap();
        assert!(proof.len() <= 4_153_152);
        verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
        for field in 0..4 {
            let mut after = segment.after;
            match field {
                0 => after.registers[9] ^= 1,
                1 => after.gas_remaining ^= 1,
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
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            segment.steps,
            segment.before,
            segment.after,
            if tail < 12 {
                SegmentOutcome::AssertionFailed
            } else {
                SegmentOutcome::OutOfGas
            },
        )
        .unwrap();
        assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
        for (row, column) in [
            (0, SHIFT + division::QUOTIENT),
            (0, MULTIPLY),
            (1, ABSOLUTE + 42),
            (63, SHIFT + division::LOCAL_TRAP),
        ] {
            let mut forged = columns.clone();
            forged[NOTE_COPY_WIDTH_V1 + column][row] =
                forged[NOTE_COPY_WIDTH_V1 + column][row].add(F::ONE);
            assert!(prove_proof_managed_note_stark_v1(&segment, &forged).is_err());
        }
    }
}
