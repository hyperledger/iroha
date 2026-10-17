//! Unary arithmetic, gas reads and pure direct control interpreter/AIR checks.

use super::*;

fn jump(opcode: u8, displacement: i16) -> u32 {
    match opcode {
        wide::control::JMP => enc::encode_offset24(opcode, i32::from(displacement)),
        wide::control::JAL => enc::encode_jump(opcode, 0, displacement),
        _ => unreachable!("pure direct jump fixture"),
    }
}

fn unary_control_mix() -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    recorded(
        &[
            enc::encode_rr(wide::system::GETGAS, 20, 255, 254),
            enc::encode_rr(wide::arithmetic::NEG, 6, 6, 255),
            jump(wide::control::JMP, 2),
            enc::encode_ri(wide::arithmetic::ADDI, 23, 0, 99),
            enc::encode_rr(wide::arithmetic::NOT, 7, 6, 255),
            jump(wide::control::JAL, 2),
            enc::encode_ri(wide::arithmetic::ADDI, 23, 0, 99),
            enc::encode_rr(wide::system::GETGAS, 21, 20, 20),
            enc::encode_rr(wide::arithmetic::SLT, 22, 6, 7),
            enc::encode_ri(wide::arithmetic::ROTR_IMM, 23, 7, -1),
            jump(wide::control::JMP, 1),
            enc::encode_ri(wide::arithmetic::ADDI, 24, 23, -1),
        ],
        10,
        &[
            (6, i64::cast_unsigned(i64::MIN)),
            (255, u64::MAX),
            (254, 19),
        ],
        u64::MAX,
    )
}

#[test]
fn unary_ops_match_interpreter_wrapping_extrema_aliases_and_unused_fields() {
    for opcode in [wide::arithmetic::NEG, wide::arithmetic::NOT] {
        for value in [
            0,
            1,
            u64::MAX,
            i64::cast_unsigned(i64::MIN),
            i64::MAX as u64,
            1 << 32,
        ] {
            for (rd, src, unused) in [(8, 6, 255), (6, 6, 6), (0, 6, 255), (8, 0, 6), (0, 0, 0)] {
                let (segment, records) = recorded(
                    &[enc::encode_rr(opcode, rd, src, unused)],
                    1,
                    &[(6, value), (255, !value)],
                    1_000,
                );
                let source = records[0].before.registers[usize::from(src)];
                let expected = if opcode == wide::arithmetic::NEG {
                    source.wrapping_neg()
                } else {
                    !source
                };
                assert_eq!(
                    records[0].after.registers[usize::from(rd)],
                    if rd == 0 { 0 } else { expected }
                );
                assert_eq!(
                    records[0].before.gas_remaining - records[0].after.gas_remaining,
                    1
                );
                assert_eq!(records[0].after.pc, records[0].before.pc + 4);
                assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            }
        }
    }
}

#[test]
fn getgas_matches_interpreter_full_width_zero_cost_and_ignores_both_source_fields() {
    for gas in [1_000, 1 << 32, u64::MAX] {
        for (rd, left, right) in [(8, 6, 7), (6, 6, 6), (0, 255, 254), (255, 0, 0)] {
            let (segment, records) = recorded(
                &[enc::encode_rr(wide::system::GETGAS, rd, left, right)],
                1,
                &[(6, u64::MAX), (7, 17), (254, 9)],
                gas,
            );
            assert_eq!(records[0].opcode_gas, Some(0));
            assert_eq!(
                records[0].after.gas_remaining,
                records[0].before.gas_remaining
            );
            assert_eq!(
                records[0].after.registers[usize::from(rd)],
                if rd == 0 {
                    0
                } else {
                    records[0].before.gas_remaining
                }
            );
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        }
    }
    // These are explicit later-segment boundaries, not root setup budgets.
    // Zero and a full Goldilocks modulus remain distinct full-width gas words.
    let (segment, records) = recorded(
        &[enc::encode_rr(wide::system::GETGAS, 6, 6, 6)],
        1,
        &[(6, 91)],
        1_000,
    );
    for gas in [0, 0xffff_ffff_0000_0001, u64::MAX] {
        let mut records = records.clone();
        records[0].before.gas_remaining = gas;
        records[0].after.gas_remaining = gas;
        records[0].after.registers[6] = gas;
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            1,
            records[0].before,
            records[0].after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert_rows(&changed, &changed.witness_rows(&records).unwrap());
    }
}

#[test]
fn pure_direct_jumps_match_interpreter_signed_control_without_link_writes() {
    for opcode in [wide::control::JMP, wide::control::JAL] {
        for displacement in [0, 1, 2] {
            let (segment, records) = recorded(
                &[
                    jump(opcode, displacement),
                    enc::encode_ri(wide::arithmetic::ADDI, 6, 6, 1),
                    enc::encode_ri(wide::arithmetic::ADDI, 7, 7, 1),
                ],
                1,
                &[(6, 91), (7, 37), (255, u64::MAX)],
                1_000,
            );
            assert_eq!(
                records[0].after.pc,
                records[0].before.pc + displacement as u64 * 4
            );
            assert_eq!(records[0].after.registers, records[0].before.registers);
            assert_eq!(records[0].after.tags, records[0].before.tags);
            assert_eq!(
                records[0].before.gas_remaining - records[0].after.gas_remaining,
                2
            );
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        }
        let (segment, records) = recorded(
            &[
                enc::encode_ri(wide::arithmetic::ADDI, 6, 6, 1),
                jump(opcode, -1),
            ],
            3,
            &[(6, 91), (255, u64::MAX)],
            1_000,
        );
        assert_eq!(records[1].after.pc + 4, records[1].before.pc);
        assert_eq!(records[1].after.registers, records[1].before.registers);
        assert_rows(&segment, &segment.witness_rows(&records).unwrap());
    }
    for displacement in [i16::MIN, -1, 0, i16::MAX] {
        assert!(
            matches!(family(enc::encode_jump(wide::control::JAL, 0, displacement)), Some(Family::Jump(bytes)) if bytes == i64::from(displacement) * 4)
        );
    }
    for displacement in [-0x80_0000, -1, 0, 0x7f_ffff] {
        assert!(
            matches!(family(enc::encode_offset24(wide::control::JMP, displacement)), Some(Family::Jump(bytes)) if bytes == i64::from(displacement) * 4)
        );
    }
    for rd in [1, 2, 255] {
        assert!(family(enc::encode_jump(wide::control::JAL, rd, 1)).is_none());
    }
    for opcode in [
        wide::control::JALS,
        wide::control::JALR,
        wide::control::JR,
        wide::control::HALT,
    ] {
        assert!(family(enc::encode_rr(opcode, 0, 0, 0)).is_none());
    }
    // Admission must reject direct targets outside executable code; the AIR
    // does not substitute an attacker-supplied target/boundary table.
    let admitted = contract(&[jump(wide::control::JMP, 1)]);
    for word in [jump(wide::control::JMP, -1), jump(wide::control::JAL, 64)] {
        let mut artifact = admitted.artifact().to_vec();
        let offset = admitted.code_offset();
        artifact[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        assert!(ivm::prepare_contract(Arc::from(artifact)).is_err());
    }
}

#[test]
fn unary_gas_and_direct_control_coherent_false_boundaries_fail_air() {
    for word in [
        enc::encode_rr(wide::arithmetic::NEG, 6, 6, 255),
        enc::encode_rr(wide::arithmetic::NOT, 6, 6, 255),
        enc::encode_rr(wide::system::GETGAS, 6, 6, 255),
        jump(wide::control::JMP, 2),
        jump(wide::control::JAL, 2),
    ] {
        let (segment, records) = recorded(
            &[
                word,
                enc::encode_ri(wide::arithmetic::ADDI, 7, 7, 0),
                enc::encode_ri(wide::arithmetic::ADDI, 8, 8, 0),
            ],
            1,
            &[(6, i64::cast_unsigned(i64::MIN)), (255, 37)],
            1_000,
        );
        for mutation in 0..6 {
            let mut forged = records.clone();
            let after = &mut forged[0].after;
            match mutation {
                0 => after.registers[6] ^= 1,
                1 => after.registers[6] ^= 1 << 32,
                2 => after.registers[255] ^= 1,
                3 => after.gas_remaining -= 1,
                4 => {
                    after.pc = if matches!(family(word), Some(Family::Jump(_))) {
                        segment.before.pc + 4
                    } else {
                        segment.before.pc + 8
                    }
                }
                // A JAL link-write claim must fail even if public boundaries
                // and all candidate row registers consistently carry it.
                _ => after.registers[1] = segment.before.pc + 4,
            }
            assert_ne!(*after, records[0].after);
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                1,
                forged[0].before,
                forged[0].after,
                SegmentOutcome::Continue,
            )
            .unwrap();
            assert!(rejects(&changed, &changed.witness_rows(&forged).unwrap()));
        }
    }
}

#[test]
fn unary_gas_and_direct_control_reject_every_interior_profile_column_mutation() {
    for word in [
        enc::encode_rr(wide::arithmetic::NEG, 6, 6, 255),
        enc::encode_rr(wide::arithmetic::NOT, 6, 6, 255),
        enc::encode_rr(wide::system::GETGAS, 6, 6, 255),
        jump(wide::control::JMP, -1),
        jump(wide::control::JAL, -1),
    ] {
        let (segment, records) = recorded(
            &[
                enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
                word,
                enc::encode_ri(wide::arithmetic::ADDI, 25, 25, 0),
            ],
            3,
            &[(6, i64::cast_unsigned(i64::MIN)), (255, u64::MAX)],
            1_000,
        );
        assert_eq!(records[1].instruction, Some(word));
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
                "accepted opcode {:#x} column {column}",
                wide::opcode(word)
            );
        }
    }
}

#[test]
fn unary_direct_mix_keeps_degree_four_and_exact_native_geometry() {
    let (segment, records) = unary_control_mix();
    assert_rows(&segment, &segment.witness_rows(&records).unwrap());
    assert_eq!(segment.after.registers[6], i64::cast_unsigned(i64::MIN));
    assert_eq!(segment.after.registers[7], i64::MAX as u64);
    assert_eq!(segment.after.registers[20] - segment.after.registers[21], 6);
    assert_eq!(segment.base_width_v1(), 1_356);
    assert_eq!(segment.profile_constraint_count_v1(), 3_369);
    assert_eq!(
        measured_maximum_affine_degree_v1(
            [0xd7; 32],
            [ROW_WIDTH, ROW_WIDTH, 0, 0, FIXED_WIDTH],
            3,
            4,
            |row, next, _, _, fixed| residues(&segment, row, next, fixed)
        ),
        4
    );
    let protocol = segment.protocol_v1();
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
}

#[test]
fn native_stark_proves_unary_direct_mix_and_binds_gas_reads_and_jump_artifact() {
    let (segment, records) = unary_control_mix();
    let proof =
        prove_proof_managed_note_stark_v1(&segment, &segment.columns(&records).unwrap()).unwrap();
    verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
    for register in [6, 7, 20, 21] {
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
    let offset = segment.contract.code_offset() + 2 * 4;
    artifact[offset..offset + 4].copy_from_slice(&jump(wide::control::JMP, 1).to_le_bytes());
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

#[test]
fn coherent_unary_banks_and_result_cannot_replace_the_canonical_source_read() {
    for opcode in [
        wide::arithmetic::NEG,
        wide::arithmetic::NOT,
        wide::system::GETGAS,
    ] {
        let word = enc::encode_rr(opcode, 6, 6, 255);
        let (segment, records) = recorded(&[word], 1, &[(6, 11), (255, 37)], 1_000);
        let selected = family(word).unwrap();
        let Family::Alu(operation) = selected else {
            unreachable!()
        };
        let [mut left, mut right] =
            operands(word, selected).map(|source| source.value(&segment.before));
        if opcode == wide::arithmetic::NEG {
            right ^= 1;
        } else {
            left ^= 1;
        }
        let bank = alu_bank_witness(operation, left, right);
        let result = half_from_limbs(&bank, 0, 0).0 | (half_from_limbs(&bank, 0, 1).0 << 32);
        assert_ne!(result, segment.after.registers[6]);
        let mut forged = records.clone();
        forged[0].after.registers[6] = result;
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            1,
            forged[0].before,
            forged[0].after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        let mut rows = changed.witness_rows(&forged).unwrap();
        // Every bank and the public output agree on the false source. Their
        // internal arithmetic is valid; canonical register/gas read links fail.
        replace_auxiliary_sources(&mut rows[0], word, left, right);
        rows[0][RESULT..RESULT + 2].copy_from_slice(&halves(result));
        assert!(rejects(&changed, &rows));
    }
}
