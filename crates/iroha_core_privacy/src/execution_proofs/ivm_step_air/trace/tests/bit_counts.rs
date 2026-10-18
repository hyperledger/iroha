//! Bit-count interpreter parity, prefix forgeries and exact maximum geometry.

use super::*;

fn expected(opcode: u8, value: u64) -> u64 {
    u64::from(match opcode {
        wide::arithmetic::POPCNT => value.count_ones(),
        wide::arithmetic::CLZ => value.leading_zeros(),
        wide::arithmetic::CTZ => value.trailing_zeros(),
        _ => unreachable!("bit-count fixture opcode"),
    })
}

fn maximum_segment() -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let return_words = crate::ivm_test_support::unit_return().len() / 4;
    let body_words = MAX_WORDS - return_words;
    let mut body = (0..body_words - 1)
        .map(|index| {
            enc::encode_rr(
                COUNT_OPS[index % COUNT_OPS.len()],
                8 + (index % 3) as u8,
                6,
                255,
            )
        })
        .collect::<Vec<_>>();
    body.push(enc::encode_offset24(
        wide::control::JMP,
        -((body_words - 1) as i32),
    ));
    let (segment, records) = recorded(
        &body,
        MAX_STEPS,
        &[(6, 0x0001_2345_6789_ab00), (255, u64::MAX)],
        100_000,
    );
    assert_eq!(segment.steps, MAX_STEPS);
    assert_eq!(segment.words.len(), MAX_WORDS);
    (segment, records)
}

#[test]
fn bit_count_ops_match_interpreter_all_singleton_bits_and_full_width_boundaries() {
    let values = [
        0,
        u64::MAX,
        i64::cast_unsigned(i64::MIN),
        i64::MAX as u64,
        0xffff_ffff_0000_0001,
        0xaaaa_aaaa_aaaa_aaaa,
        0x5555_5555_5555_5555,
        0x0000_ffff_ffff_0000,
    ]
    .into_iter()
    .chain((0..64).map(|position| 1 << position));
    for value in values {
        for opcode in COUNT_OPS {
            let (segment, records) = recorded(
                &[enc::encode_rr(opcode, 8, 6, 255)],
                1,
                &[(6, value), (8, 91), (255, !value)],
                1_000,
            );
            assert_eq!(segment.after.registers[8], expected(opcode, value));
            assert_eq!(
                segment.after.gas_remaining + 6,
                segment.before.gas_remaining
            );
            assert_eq!(segment.after.cycles, segment.before.cycles + 1);
            assert_eq!(segment.after.pc, segment.before.pc + 4);
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        }
    }
}

#[test]
fn bit_count_ops_match_interpreter_aliases_r0_and_ignore_encoded_rs2() {
    for opcode in COUNT_OPS {
        for value in [0, u64::MAX, 1 << 63, 1 << 32, 1] {
            for (rd, source, unused) in [
                (8, 6, 255),
                (6, 6, 6),
                (0, 6, 255),
                (8, 0, 6),
                (0, 0, 0),
                (1, 6, 0),
                (255, 6, 255),
            ] {
                let (segment, records) = recorded(
                    &[enc::encode_rr(opcode, rd, source, unused)],
                    1,
                    &[(6, value), (8, 91), (255, !value)],
                    1_000,
                );
                let mut wanted = segment.before.registers;
                if rd != 0 {
                    wanted[usize::from(rd)] = expected(opcode, wanted[usize::from(source)]);
                }
                assert_eq!(segment.after.registers, wanted);
                assert_eq!(segment.after.tags, segment.before.tags);
                assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            }
        }
    }
}

#[test]
fn count_prefixes_share_boolean_source_bits_and_have_canonical_padding() {
    for value in [0, u64::MAX, 1, 1 << 63, 0x100] {
        let bank = word::witness(value, 0);
        let bits = Sources::new(&bank).bits(0);
        assert_eq!(bits.len(), bit_count::WIDTH);
        assert_eq!(
            bits.iter()
                .enumerate()
                .fold(0, |word, (index, bit)| word | (bit.0 << index)),
            value
        );
        for leading in [false, true] {
            let prefixes = bit_count::witness(bits, leading);
            let mut equations = Vec::new();
            bit_count::append_residues(&mut equations, &prefixes, bits, F(u64::from(leading)));
            assert_eq!(equations.len(), bit_count::CONSTRAINTS);
            assert!(equations.iter().all(|value| *value == F::ZERO));
            assert_eq!(
                prefixes.into_iter().map(|value| value.0).sum::<u64>(),
                if leading {
                    u64::from(value.leading_zeros())
                } else {
                    u64::from(value.trailing_zeros())
                }
            );
        }
    }
    let (segment, records) = recorded(
        &[enc::encode_rr(wide::arithmetic::POPCNT, 8, 6, 255)],
        1,
        &[(6, u64::MAX)],
        1_000,
    );
    let mut rows = segment.witness_rows(&records).unwrap();
    assert!(
        rows[segment.steps][BIT_COUNT..MULTIPLY]
            .iter()
            .all(|prefix| *prefix == F::ONE)
    );
    assert_rows(&segment, &rows);
    rows[segment.steps][BIT_COUNT..MULTIPLY].fill(F::ZERO);
    assert!(rejects(&segment, &rows));
}

#[test]
fn coherent_wrong_counts_prefixes_and_orientation_cannot_change_public_results() {
    for opcode in COUNT_OPS {
        let value = 0x100_u64;
        let (segment, records) = recorded(
            &[enc::encode_rr(opcode, 8, 6, 255)],
            1,
            &[(6, value)],
            1_000,
        );
        for result in [expected(opcode, value) + 1, 65, 1 << 32] {
            let mut forged = records.clone();
            forged[0].after.registers[8] = result;
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                1,
                forged[0].before,
                forged[0].after,
                SegmentOutcome::Continue,
            )
            .unwrap();
            let mut rows = changed.witness_rows(&forged).unwrap();
            rows[0][RESULT..RESULT + 2].copy_from_slice(&halves(result));
            assert!(rejects(&changed, &rows));
        }
        if opcode != wide::arithmetic::POPCNT {
            let rows = segment.witness_rows(&records).unwrap();
            let prefixes = bit_count::witness(
                Sources::new(&rows[0][SOURCES..ALU]).bits(0),
                opcode != wide::arithmetic::CLZ,
            );
            let false_count = prefixes.into_iter().map(|value| value.0).sum::<u64>();
            assert_ne!(false_count, segment.after.registers[8]);
            let mut forged = records.clone();
            forged[0].after.registers[8] = false_count;
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                1,
                forged[0].before,
                forged[0].after,
                SegmentOutcome::Continue,
            )
            .unwrap();
            let mut rows = changed.witness_rows(&forged).unwrap();
            rows[0][BIT_COUNT..MULTIPLY].copy_from_slice(&prefixes);
            rows[0][MULTIPLY..ABSOLUTE]
                .copy_from_slice(&multiply::witness(value, 0, &prefixes, false));
            rows[0][RESULT] = F(false_count);
            assert!(rejects(&changed, &rows));
        }
    }
}

#[test]
fn coherent_count_banks_cannot_substitute_a_different_source_word() {
    for opcode in COUNT_OPS {
        let (segment, records) =
            recorded(&[enc::encode_rr(opcode, 8, 6, 255)], 1, &[(6, 0)], 1_000);
        let source = 0x8000_0000_0000_0001;
        let false_count = expected(opcode, source);
        assert_ne!(false_count, segment.after.registers[8]);
        let mut forged = records.clone();
        forged[0].after.registers[8] = false_count;
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            1,
            forged[0].before,
            forged[0].after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        let mut rows = changed.witness_rows(&forged).unwrap();
        replace_auxiliary_sources(&mut rows[0], enc::encode_rr(opcode, 8, 6, 255), source, 0);
        rows[0][RESULT] = F(false_count);
        assert!(rejects(&changed, &rows));
    }
}

#[test]
fn bit_count_modes_constrain_every_interior_column_and_nonselected_prefixes() {
    for opcode in [
        wide::arithmetic::POPCNT,
        wide::arithmetic::CLZ,
        wide::arithmetic::CTZ,
        wide::arithmetic::ADDI,
    ] {
        let word = if opcode == wide::arithmetic::ADDI {
            enc::encode_ri(opcode, 8, 6, 0)
        } else {
            enc::encode_rr(opcode, 8, 6, 255)
        };
        let (segment, records) = recorded(
            &[
                enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
                word,
                enc::encode_ri(wide::arithmetic::ADDI, 25, 25, 0),
            ],
            3,
            &[(6, 0x100), (255, u64::MAX)],
            1_000,
        );
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        for column in 0..ROW_WIDTH {
            let mut forged = rows[1].clone();
            forged[column] = forged[column].add(F::ONE);
            let incoming = residues(&segment, &rows[0], &forged, &segment.fixed_row(0)).unwrap();
            let outgoing = residues(&segment, &forged, &rows[2], &segment.fixed_row(1)).unwrap();
            assert!(
                incoming
                    .iter()
                    .chain(&outgoing)
                    .any(|value| *value != F::ZERO),
                "accepted count opcode {opcode:#x} column {column}"
            );
        }
    }
}

#[test]
fn count_family_maximum_words_and_steps_fit_unchanged_security_and_envelope() {
    let (segment, records) = maximum_segment();
    assert_rows(&segment, &segment.witness_rows(&records).unwrap());
    assert_eq!(segment.base_width_v1(), 1_356);
    assert_eq!(segment.profile_constraint_count_v1(), 3_369);
    let protocol = segment.protocol_v1();
    protocol.validate().unwrap();
    assert_eq!(protocol.parameters.query_count, 136);
    assert_eq!(protocol.parameters.blowup_log2, 3);
    assert_eq!(protocol.maximum_constraint_degree, 4);
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
            [0xf9; 32],
            [ROW_WIDTH, ROW_WIDTH, 0, 0, FIXED_WIDTH],
            3,
            4,
            |row, next, _, _, fixed| residues(&segment, row, next, fixed)
        ),
        4
    );
}

#[test]
fn native_stark_proves_maximum_count_segment_and_binds_result_and_orientation() {
    let (segment, records) = maximum_segment();
    let proof =
        prove_proof_managed_note_stark_v1(&segment, &segment.columns(&records).unwrap()).unwrap();
    assert!(proof.len() <= 4_153_152);
    verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
    for register in [8, 9, 10] {
        let mut after = segment.after;
        after.registers[register] ^= 1;
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            segment.steps,
            segment.before,
            after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
    }
    let mut artifact = segment.contract.artifact().to_vec();
    let offset = segment.contract.code_offset() + 4;
    artifact[offset..offset + 4]
        .copy_from_slice(&enc::encode_rr(wide::arithmetic::CTZ, 9, 6, 255).to_le_bytes());
    let changed = ScalarSegment::new(
        ivm::prepare_contract(Arc::from(artifact)).unwrap(),
        segment.steps,
        segment.before,
        segment.after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
}
