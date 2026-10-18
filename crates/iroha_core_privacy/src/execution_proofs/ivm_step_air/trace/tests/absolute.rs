//! Native ABS boundary parity and forged-magnitude/outcome rejection.

use super::div_rem::attempted;
use super::*;

fn single(
    value: u64,
    gas: u64,
    rd: u8,
    rs1: u8,
    rs2: u8,
) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    attempted(
        &[enc::encode_rr(wide::arithmetic::ABS, rd, rs1, rs2)],
        1,
        &[(6, value), (7, 0xdead_beef), (8, 91)],
        gas,
    )
}

#[test]
fn absolute_matches_interpreter_full_width_aliases_r0_and_unused_source() {
    for value in [
        0,
        1,
        u64::MAX,
        i64::MAX as u64,
        i64::cast_unsigned(i64::MIN),
        i64::cast_unsigned(i64::MIN + 1),
        0xffff_ffff_0000_0001,
        0x1_0000_0000,
    ] {
        for (rd, rs1, rs2) in [
            (8, 6, 7),
            (6, 6, 7),
            (7, 6, 7),
            (0, 6, 7),
            (8, 0, 7),
            (8, 6, 0),
        ] {
            for gas in [0, 1, 2, 1 << 32] {
                let (segment, records) = single(value, gas, rd, rs1, rs2);
                let input = u64::cast_signed(segment.before.registers[usize::from(rs1)]);
                let expected = if gas == 0 {
                    Err(SegmentOutcome::OutOfGas)
                } else {
                    input
                        .checked_abs()
                        .map(|v| i64::cast_unsigned(v))
                        .ok_or(SegmentOutcome::AssertionFailed)
                };
                assert_eq!(
                    segment.outcome,
                    expected.err().unwrap_or(SegmentOutcome::Continue)
                );
                let mut wanted = segment.before.registers;
                if let Ok(result) = expected {
                    if rd != 0 {
                        wanted[usize::from(rd)] = result;
                    }
                }
                assert_eq!(segment.after.registers, wanted);
                assert_eq!(segment.after.tags, segment.before.tags);
                assert_eq!(segment.after.gas_remaining, gas.saturating_sub(1));
                assert_eq!(
                    segment.after.pc,
                    segment.before.pc + 4 * u64::from(expected.is_ok())
                );
                assert_eq!(
                    segment.after.cycles,
                    segment.before.cycles + u64::from(expected.is_ok())
                );
                assert_eq!(records[0].opcode_gas, Some(1));
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
fn absolute_rejects_mutated_magnitude_source_gas_and_outcome_witnesses() {
    for (value, gas) in [
        (17, 1),
        (i64::cast_unsigned(-17_i64), 1),
        (i64::cast_unsigned(i64::MIN), 1),
        (i64::cast_unsigned(i64::MIN), 0),
    ] {
        let (segment, records) = single(value, gas, 8, 6, 7);
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        for column in (ABSOLUTE..ROW_WIDTH)
            .chain(RESULT..RESULT + 2)
            .chain(SOURCES..ALU)
            .chain(GAS..GAS + 2)
        {
            let mut changed = rows.clone();
            changed[0][column] = changed[0][column].add(F::ONE);
            assert!(
                residues(&segment, &changed[0], &changed[1], &segment.fixed_row(0))
                    .unwrap()
                    .iter()
                    .any(|x| *x != F::ZERO),
                "column {column}, value {value}, gas {gas}"
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
                    .any(|x| *x != F::ZERO)
            );
        }
    }
}

fn maximum_segment(tail_value: u64, tail_gas: u64) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let mut body = vec![
        enc::encode_rr(wide::arithmetic::ABS, 8, 6, 255),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1),
        enc::encode_branch(wide::control::BNE, 2, 0, -2),
        enc::encode_rr(wide::arithmetic::ABS, 9, 7, 255),
    ];
    let cost = body[..3]
        .iter()
        .map(|word| ivm::gas::cost_of(*word).unwrap())
        .sum::<u64>()
        * 21;
    body.resize(
        MAX_WORDS - crate::ivm_test_support::unit_return().len() / 4,
        enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
    );
    let result = attempted(
        &body,
        MAX_STEPS,
        &[
            (2, 21),
            (6, i64::cast_unsigned(-17_i64)),
            (7, tail_value),
            (255, u64::MAX),
        ],
        cost + tail_gas,
    );
    assert_eq!(result.0.steps, MAX_STEPS);
    assert_eq!(result.0.words.len(), MAX_WORDS);
    result
}

#[test]
fn absolute_maximum_segments_fit_existing_security_caps_and_keep_degree_four() {
    for (value, gas) in [
        (17, 1),
        (i64::cast_unsigned(i64::MIN), 1),
        (i64::cast_unsigned(i64::MIN), 0),
    ] {
        let (segment, records) = maximum_segment(value, gas);
        assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        assert_eq!(segment.base_width_v1(), 1_356);
        assert_eq!(segment.profile_constraint_count_v1(), 3_369);
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
                [0xac + gas as u8; 32],
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
fn native_stark_proves_maximum_absolute_segment_and_binds_trap_state_code() {
    for (value, gas) in [
        (17, 1),
        (i64::cast_unsigned(i64::MIN), 1),
        (i64::cast_unsigned(i64::MIN), 0),
    ] {
        let (segment, records) = maximum_segment(value, gas);
        let columns = segment.columns(&records).unwrap();
        let proof = prove_proof_managed_note_stark_v1(&segment, &columns).unwrap();
        assert!(proof.len() <= 4_153_152);
        verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
        for changed_field in 0..3 {
            let mut after = segment.after;
            match changed_field {
                0 => after.registers[9] ^= 1,
                1 => after.gas_remaining ^= 1,
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
            let other = if segment.outcome == SegmentOutcome::OutOfGas {
                SegmentOutcome::AssertionFailed
            } else {
                SegmentOutcome::OutOfGas
            };
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                segment.steps,
                segment.before,
                segment.after,
                other,
            )
            .unwrap();
            assert_ne!(changed.digest().unwrap(), segment.digest().unwrap());
            assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
        }
        let mut artifact = segment.contract.artifact().to_vec();
        let offset = segment.contract.code_offset() + 12;
        artifact[offset..offset + 4]
            .copy_from_slice(&enc::encode_rr(wide::arithmetic::NEG, 9, 7, 255).to_le_bytes());
        let changed = ScalarSegment::new(
            ivm::prepare_contract(Arc::from(artifact)).unwrap(),
            segment.steps,
            segment.before,
            segment.after,
            segment.outcome,
        )
        .unwrap();
        assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
        let mut forged = columns;
        forged[NOTE_COPY_WIDTH_V1 + ABSOLUTE][MAX_STEPS - 1] =
            forged[NOTE_COPY_WIDTH_V1 + ABSOLUTE][MAX_STEPS - 1].add(F::ONE);
        assert!(prove_proof_managed_note_stark_v1(&segment, &forged).is_err());
    }
}
