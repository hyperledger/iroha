//! Maximum geometry, dynamic degree and native proof ownership of terminal outcomes.

use super::*;

fn maximum_segment(out_of_gas: bool) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let mut body = DIVISION_OPS
        .map(|opcode| enc::encode_rr(opcode, 8, 6, 7))
        .to_vec();
    body.extend([
        enc::encode_rr(wide::arithmetic::MULH, 9, 6, 7),
        enc::encode_rr(wide::arithmetic::CLZ, 20, 6, 255),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1),
        enc::encode_ri(wide::arithmetic::XORI, 21, 6, -128),
        enc::encode_branch(wide::control::BNE, 2, 0, -8),
        enc::encode_rr(wide::arithmetic::REM, 0, 6, 0),
    ]);
    let cost = body[..9]
        .iter()
        .map(|word| ivm::gas::cost_of(*word).unwrap())
        .sum::<u64>()
        * 7;
    body.resize(
        MAX_WORDS - crate::ivm_test_support::unit_return().len() / 4,
        enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
    );
    let (segment, records) = attempted(
        &body,
        MAX_STEPS,
        &[
            (2, 7),
            (6, i64::cast_unsigned(i64::MIN)),
            (7, 7),
            (255, u64::MAX),
        ],
        cost + if out_of_gas { 9 } else { 10 },
    );
    assert_eq!(segment.words.len(), MAX_WORDS);
    assert_eq!(segment.steps, MAX_STEPS);
    assert_eq!(segment.after.cycles - segment.before.cycles, 63);
    assert_eq!(
        segment.outcome,
        if out_of_gas {
            SegmentOutcome::OutOfGas
        } else {
            SegmentOutcome::AssertionFailed
        }
    );
    (segment, records)
}

#[test]
fn division_retains_native_security_geometry_and_degree_with_maximum_attempted_trace() {
    for out_of_gas in [false, true] {
        let (segment, records) = maximum_segment(out_of_gas);
        assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        assert_eq!(segment.base_width_v1(), 1_356);
        assert_eq!(segment.profile_constraint_count_v1(), 3_369);
        assert_eq!(segment.profile_fixed_width_v1(), 10);
        let fixed = segment.profile_fixed_columns_v1().unwrap();
        for row in 0..TRACE_SIZE {
            assert_eq!(
                fixed[OUT_OF_GAS][row],
                F(u64::from(out_of_gas && row == MAX_STEPS - 1))
            );
            assert_eq!(
                fixed[ASSERTION_FAILED][row],
                F(u64::from(!out_of_gas && row == MAX_STEPS - 1))
            );
        }
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
                [0xdc + u8::from(out_of_gas); 32],
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
fn native_stark_proves_maximum_division_segment_and_binds_exact_trap_reason_gas_and_code() {
    for out_of_gas in [false, true] {
        let (segment, records) = maximum_segment(out_of_gas);
        let columns = segment.columns(&records).unwrap();
        let proof = prove_proof_managed_note_stark_v1(&segment, &columns).unwrap();
        assert!(proof.len() <= 4_153_152);
        verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
        let other = if out_of_gas {
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
        for changed_field in 0..3 {
            let mut after = segment.after;
            match changed_field {
                0 => after.registers[8] ^= 1,
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
        let mut artifact = segment.contract.artifact().to_vec();
        let offset = segment.contract.code_offset();
        artifact[offset..offset + 4]
            .copy_from_slice(&enc::encode_rr(wide::arithmetic::DIVU, 8, 6, 7).to_le_bytes());
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
        forged[NOTE_COPY_WIDTH_V1 + SHIFT + division::LOCAL_TRAP][MAX_STEPS - 1] = F::ZERO;
        assert!(prove_proof_managed_note_stark_v1(&segment, &forged).is_err());
    }
}
