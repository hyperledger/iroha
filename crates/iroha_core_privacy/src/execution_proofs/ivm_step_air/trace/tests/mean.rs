//! Native signed MEAN parity, cycle admission and adversarial proof controls.

use super::div_rem::attempted;
use super::*;

fn single(left: u64, right: u64, gas: u64) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    attempted(
        &[enc::encode_rr(wide::arithmetic::MEAN, 8, 6, 7)],
        1,
        &[(6, left), (7, right), (8, 91)],
        gas,
    )
}

#[test]
fn mean_matches_interpreter_full_width_signed_rounding_aliases_r0_and_gas() {
    let values = [
        0,
        1,
        2,
        3,
        u64::MAX,
        i64::cast_unsigned(-2_i64),
        i64::cast_unsigned(-3_i64),
        i64::cast_unsigned(i64::MIN),
        i64::cast_unsigned(i64::MIN + 1),
        i64::MAX as u64,
        0xffff_ffff_0000_0001,
        0x1_0000_0000,
    ];
    for left in values {
        for right in values {
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
                for gas in [0, 1, 2, 3, 1 << 32] {
                    let (segment, records) = attempted(
                        &[enc::encode_rr(wide::arithmetic::MEAN, rd, rs1, rs2)],
                        1,
                        &[(6, left), (7, right), (8, 91)],
                        gas,
                    );
                    let a =
                        i128::from(u64::cast_signed(segment.before.registers[usize::from(rs1)]));
                    let b =
                        i128::from(u64::cast_signed(segment.before.registers[usize::from(rs2)]));
                    let completed = gas >= 2;
                    let mut expected = segment.before.registers;
                    if completed && rd != 0 {
                        expected[usize::from(rd)] = ((a + b) / 2) as u64;
                    }
                    assert_eq!(segment.after.registers, expected);
                    assert_eq!(segment.after.tags, segment.before.tags);
                    assert_eq!(
                        segment.after.pc,
                        segment.before.pc + 4 * u64::from(completed)
                    );
                    assert_eq!(
                        segment.after.cycles,
                        segment.before.cycles + 3 * u64::from(completed)
                    );
                    assert_eq!(
                        segment.after.gas_remaining,
                        if completed { gas - 2 } else { gas }
                    );
                    assert_eq!(
                        segment.outcome,
                        if completed {
                            SegmentOutcome::Continue
                        } else {
                            SegmentOutcome::OutOfGas
                        }
                    );
                    assert_eq!(records[0].opcode_gas, Some(2));
                    assert_rows(&segment, &segment.witness_rows(&records).unwrap());
                }
            }
        }
    }
}

#[test]
fn mean_rejects_forged_workspace_reads_result_gas_cycles_and_outcomes() {
    for (left, right, gas) in [
        (0, u64::MAX, 2),
        (
            i64::cast_unsigned(i64::MIN),
            i64::cast_unsigned(i64::MIN),
            2,
        ),
        (i64::MAX as u64, i64::MAX as u64, 2),
        (17, 2, 1),
        (17, 2, 0),
    ] {
        let (segment, records) = single(left, right, gas);
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        for column in (ABSOLUTE..ROW_WIDTH)
            .chain(SOURCES..BRANCH)
            .chain(RESULT..RESULT + 2)
            .chain(GAS..FETCH)
        {
            let mut changed = rows.clone();
            changed[0][column] = changed[0][column].add(F::ONE);
            assert!(
                rejects(&segment, &changed),
                "column {column}, a {left}, b {right}, gas {gas}"
            );
        }
        for outcome in [
            SegmentOutcome::Continue,
            SegmentOutcome::AssertionFailed,
            SegmentOutcome::OutOfGas,
        ] {
            if outcome == segment.outcome {
                continue;
            }
            let mut fixed = segment.fixed_row(0);
            fixed[OUT_OF_GAS] = F(u64::from(outcome == SegmentOutcome::OutOfGas));
            fixed[ASSERTION_FAILED] = F(u64::from(outcome == SegmentOutcome::AssertionFailed));
            assert!(
                residues(&segment, &rows[0], &rows[1], &fixed)
                    .unwrap()
                    .iter()
                    .any(|r| *r != F::ZERO)
            );
        }
        let mut tagged = segment.before;
        tagged.tags[6] = true;
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                1,
                tagged,
                segment.after,
                segment.outcome
            )
            .is_err()
        );
    }
}

#[test]
fn mean_cycle_carry_is_three_on_success_and_zero_before_gas_failure() {
    for gas in [1, 2] {
        let (original, actual) = single(i64::cast_unsigned(-3_i64), 0, gas);
        // Algebraic counter-boundary fixture derived from an actual opcode record;
        // this does not claim the interpreter executed four billion instructions.
        for before in [
            u64::from(u32::MAX) - 2,
            u64::from(u32::MAX) - 1,
            u64::from(u32::MAX),
        ] {
            let mut records = actual.clone();
            records[0].before.cycles = before;
            records[0].after.cycles = before + if gas >= 2 { 3 } else { 0 };
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
            assert_eq!(rows[0][CYCLE_CARRY], F(u64::from(gas >= 2)));
            let mut forged = rows;
            forged[0][CYCLE_CARRY] = F::ONE.sub(forged[0][CYCLE_CARRY]);
            assert!(rejects(&segment, &forged));
        }
        let mut wrong = actual.clone();
        wrong[0].after.cycles = wrong[0].before.cycles + 1;
        if let Ok(segment) = ScalarSegment::new(
            original.contract.clone(),
            1,
            wrong[0].before,
            wrong[0].after,
            original.outcome,
        ) {
            assert!(segment.witness_rows(&wrong).is_err());
        }
    }
    let (segment, _) = single(17, 2, 2);
    let mut before = segment.before;
    let mut after = segment.after;
    before.cycles = u64::MAX - 1;
    after.cycles = 1;
    assert!(ScalarSegment::new(segment.contract, 1, before, after, segment.outcome).is_err());
}

#[test]
fn mean_native_cycle_policy_allows_last_crossing_and_refuses_next_attempt() {
    let body = [
        enc::encode_rr(wide::arithmetic::MEAN, 8, 6, 7),
        enc::encode_ri(wide::arithmetic::ADDI, 9, 9, 1),
    ];
    let prepared = contract_with_cycle_policy(&body, 2, 0);
    let root_words = crate::ivm_test_support::unit_callable(0)
        .result_word_count()
        .unwrap() as u64;
    let root_gas = root_words * (ivm_abi::call::CALL_WORD_BYTES_V1 as u64 + 1);
    let mut vm = IVM::new(20 + root_gas);
    vm.load_prepared(&prepared).unwrap();
    vm.set_register(6, i64::cast_unsigned(-3_i64));
    vm.set_register(7, 0);
    let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
    assert!(matches!(
        vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder),
        Err(ivm::VMError::ExceededMaxCycles)
    ));
    assert_eq!(recorder.records().len(), 1);
    let record = recorder.records()[0].clone();
    assert_eq!(record.before.cycles, 0);
    assert_eq!(record.after.cycles, 3);
    assert_eq!(record.before.gas_remaining, 20);
    assert_eq!(record.after.gas_remaining, 18);
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
        &segment.witness_rows(std::slice::from_ref(&record)).unwrap(),
    );

    // A two-step invented trace can satisfy the coarse public cycle interval,
    // but its final ADDI starts at the forbidden cycle. Exercise the AIR check
    // independently of recorder admission, which also refuses the same trace.
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
    let last = residues(&invented, &rows[1], &rows[2], &invented.fixed_row(1)).unwrap();
    assert_eq!(
        last[2 * MAX_WORDS],
        F::ONE,
        "exact final-attempt cycle refusal"
    );
}

#[test]
fn mean_native_gas_failure_keeps_cycles_and_cannot_follow_a_limit_crossing() {
    let body = [
        enc::encode_rr(wide::arithmetic::MEAN, 8, 6, 7),
        enc::encode_rr(wide::arithmetic::MEAN, 9, 6, 7),
    ];
    let root_words = crate::ivm_test_support::unit_callable(0)
        .result_word_count()
        .unwrap() as u64;
    let root_gas = root_words * (ivm_abi::call::CALL_WORD_BYTES_V1 as u64 + 1);
    for limit in [1, 2, 3] {
        for gas in [0, 1, 2, 3] {
            let prepared = contract_with_cycle_policy(&body, limit, 0);
            let mut vm = IVM::new(gas + root_gas);
            vm.load_prepared(&prepared).unwrap();
            vm.set_register(6, i64::cast_unsigned(i64::MIN));
            vm.set_register(7, i64::MAX as u64);
            let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
            let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
            let actual =
                vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
            assert_eq!(recorder.records().len(), 1);
            let record = recorder.records()[0].clone();
            let outcome = if gas < 2 {
                assert!(matches!(actual, Err(ivm::VMError::OutOfGas)));
                assert_eq!(record.before, record.after);
                SegmentOutcome::OutOfGas
            } else {
                assert!(matches!(actual, Err(ivm::VMError::ExceededMaxCycles)));
                assert_eq!(record.after.cycles, 3);
                SegmentOutcome::Continue
            };
            let segment =
                ScalarSegment::new(prepared.clone(), 1, record.before, record.after, outcome)
                    .unwrap();
            assert_rows(
                &segment,
                &segment.witness_rows(std::slice::from_ref(&record)).unwrap(),
            );
            if gas >= 2 {
                // The next opcode has insufficient gas, but cycle admission still
                // precedes fetch and pricing. A fabricated gas trap is forbidden.
                let invented = ScalarSegment::new(
                    prepared,
                    2,
                    record.before,
                    record.after,
                    SegmentOutcome::OutOfGas,
                );
                if limit == 1 {
                    assert!(invented.is_err());
                    continue;
                }
                let invented = invented.unwrap();
                let rows = vec![
                    invented.witness_row(&record.before, Some((0, body[0]))),
                    invented.witness_row(&record.after, Some((1, body[1]))),
                    invented.witness_row(&record.after, None),
                ];
                assert!(rejects(&invented, &rows));
                assert_eq!(
                    residues(&invented, &rows[1], &rows[2], &invented.fixed_row(1)).unwrap()
                        [2 * MAX_WORDS],
                    F::ONE
                );
            }
        }
    }
}

#[test]
fn absolute_mean_inactive_workspace_cells_reject_all_single_cell_changes() {
    for opcode in [
        wide::arithmetic::ADD,
        wide::arithmetic::POPCNT,
        wide::arithmetic::MUL,
        wide::arithmetic::DIV,
        wide::arithmetic::ABS,
    ] {
        let (segment, records) = attempted(
            &[enc::encode_rr(opcode, 8, 6, 7)],
            1,
            &[(6, 17), (7, 2)],
            100,
        );
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        let first = if opcode == wide::arithmetic::ABS {
            MEAN_GAS
        } else {
            ABSOLUTE
        };
        for column in first..ROW_WIDTH {
            assert_eq!(rows[0][column], F::ZERO);
            let mut changed = rows.clone();
            changed[0][column] = F::ONE;
            assert!(
                rejects(&segment, &changed),
                "opcode {opcode}, column {column}"
            );
        }
        for column in ABSOLUTE..ROW_WIDTH {
            let mut changed = rows.clone();
            changed[1][column] = F::ONE;
            assert!(
                rejects(&segment, &changed),
                "inactive terminal column {column}"
            );
        }
    }
}

fn maximum_segment(tail_gas: u64) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let mut body = vec![
        enc::encode_rr(wide::arithmetic::MEAN, 8, 6, 7),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1),
        enc::encode_branch(wide::control::BNE, 2, 0, -2),
        enc::encode_rr(wide::arithmetic::MEAN, 9, 6, 7),
    ];
    let loop_gas = body[..3]
        .iter()
        .map(|w| ivm::gas::cost_of(*w).unwrap())
        .sum::<u64>()
        * 21;
    body.resize(
        MAX_WORDS - crate::ivm_test_support::unit_return().len() / 4,
        enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
    );
    let (segment, records) = attempted(
        &body,
        MAX_STEPS,
        &[
            (2, 21),
            (6, i64::cast_unsigned(i64::MIN)),
            (7, i64::MAX as u64),
        ],
        loop_gas + tail_gas,
    );
    assert_eq!(segment.steps, MAX_STEPS);
    assert_eq!(segment.words.len(), MAX_WORDS);
    assert_eq!(
        segment.after.cycles - segment.before.cycles,
        105 + if tail_gas >= 2 { 3 } else { 0 }
    );
    assert_eq!(
        segment.after.gas_remaining,
        if tail_gas >= 2 {
            tail_gas - 2
        } else {
            tail_gas
        }
    );
    (segment, records)
}

#[test]
fn mean_maximum_profile_fits_unchanged_caps_and_degree_four() {
    for tail_gas in [0, 1, 2] {
        let (segment, records) = maximum_segment(tail_gas);
        assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        assert_eq!(segment.base_width_v1(), 1_356);
        assert_eq!(segment.profile_constraint_count_v1(), 3_369);
        assert_eq!(segment.profile_fixed_width_v1(), 10);
        let protocol = segment.protocol_v1();
        protocol.validate().unwrap();
        assert_eq!(protocol.maximum_constraint_degree, 4);
        assert_eq!(protocol.parameters.query_count, 136);
        assert_eq!(protocol.parameters.blowup_log2, 3);
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
                [0xb1 + tail_gas as u8; 32],
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
fn native_stark_proves_maximum_mean_and_binds_registers_gas_cycles_pc_outcome_code() {
    for tail_gas in [1, 2] {
        let (segment, records) = maximum_segment(tail_gas);
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
        if segment.outcome.trapped() {
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                segment.steps,
                segment.before,
                segment.after,
                SegmentOutcome::AssertionFailed,
            )
            .unwrap();
            assert_ne!(changed.digest().unwrap(), segment.digest().unwrap());
            assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
        }
        let mut artifact = segment.contract.artifact().to_vec();
        let offset = segment.contract.code_offset() + 12;
        artifact[offset..offset + 4]
            .copy_from_slice(&enc::encode_rr(wide::arithmetic::ADD, 9, 6, 7).to_le_bytes());
        let changed = ScalarSegment::new(
            ivm::prepare_contract(Arc::from(artifact)).unwrap(),
            segment.steps,
            segment.before,
            segment.after,
            segment.outcome,
        )
        .unwrap();
        assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
        for column in [ABSOLUTE, MEAN_GAS, CYCLE_CARRY] {
            let mut forged = columns.clone();
            forged[NOTE_COPY_WIDTH_V1 + column][MAX_STEPS - 1] =
                forged[NOTE_COPY_WIDTH_V1 + column][MAX_STEPS - 1].add(F::ONE);
            assert!(prove_proof_managed_note_stark_v1(&segment, &forged).is_err());
        }
    }
}
