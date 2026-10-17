//! Full-word predicates, source roles, aliases and destination retention for moves.

use super::*;

fn move_mix() -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    recorded(
        &[
            enc::encode_rr(wide::arithmetic::CMOV, 8, 6, 7),
            enc::encode_rr(wide::arithmetic::CMOV, 9, 6, 0),
            enc::encode_ri(wide::arithmetic::CMOVI, 20, 7, -128),
            enc::encode_ri(wide::arithmetic::CMOVI, 21, 0, -1),
            enc::encode_rr(wide::arithmetic::CMOV, 7, 20, 7),
            enc::encode_rr(wide::arithmetic::SLTU, 22, 7, 6),
            enc::encode_branch(wide::control::BNE, 22, 0, 2),
            enc::encode_ri(wide::arithmetic::ADDI, 23, 0, 99),
            enc::encode_ri(wide::arithmetic::ROTR_IMM, 23, 20, 8),
            enc::encode_rr(wide::system::GETGAS, 24, 255, 255),
        ],
        9,
        &[
            (6, u64::MAX),
            (7, 0xffff_ffff_0000_0001),
            (8, 55),
            (9, 56),
            (20, 57),
            (21, 58),
        ],
        u64::MAX,
    )
}

#[test]
fn cmov_matches_interpreter_full_word_conditions_and_all_aliases() {
    for condition in [
        0,
        1,
        1 << 16,
        1 << 32,
        1 << 48,
        1 << 63,
        0xffff_ffff_0000_0001,
        u64::MAX,
    ] {
        for value in [0, 91, i64::cast_unsigned(i64::MIN), u64::MAX] {
            for (rd, source, cond) in [
                (8, 6, 7),
                (6, 6, 7),
                (7, 6, 7),
                (8, 6, 6),
                (6, 6, 6),
                (0, 6, 7),
                (8, 0, 7),
                (8, 6, 0),
                (0, 0, 0),
                (255, 254, 253),
                (1, 6, 7),
            ] {
                let (segment, records) = recorded(
                    &[enc::encode_rr(wide::arithmetic::CMOV, rd, source, cond)],
                    1,
                    &[
                        (6, value),
                        (7, condition),
                        (8, 55),
                        (254, value),
                        (253, condition),
                        (255, 55),
                    ],
                    1_000,
                );
                let before = records[0].before;
                let mut expected = before.registers;
                if rd != 0 && before.registers[usize::from(cond)] != 0 {
                    expected[usize::from(rd)] = before.registers[usize::from(source)];
                }
                assert_eq!(records[0].after.registers, expected);
                assert_eq!(records[0].after.tags, before.tags);
                assert_eq!(before.gas_remaining - records[0].after.gas_remaining, 3);
                assert_eq!(records[0].after.pc, before.pc + 4);
                assert_eq!(records[0].after.cycles, before.cycles + 1);
                assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            }
        }
    }
}

#[test]
fn cmovi_matches_interpreter_signed_immediates_retention_and_condition_alias() {
    for condition in [0, 1, 1 << 32, 0xffff_ffff_0000_0001, u64::MAX] {
        for immediate in [i8::MIN, -1, 0, 1, i8::MAX] {
            for (rd, cond) in [(8, 7), (7, 7), (0, 7), (8, 0), (0, 0), (255, 253), (1, 7)] {
                let (segment, records) = recorded(
                    &[enc::encode_ri(wide::arithmetic::CMOVI, rd, cond, immediate)],
                    1,
                    &[
                        (7, condition),
                        (8, 55),
                        (253, condition),
                        (255, 91),
                        (128, 92),
                        (127, 93),
                    ],
                    1_000,
                );
                let before = records[0].before;
                let mut expected = before.registers;
                if rd != 0 && before.registers[usize::from(cond)] != 0 {
                    expected[usize::from(rd)] = i64::cast_unsigned(i64::from(immediate));
                }
                assert_eq!(records[0].after.registers, expected);
                assert_eq!(records[0].after.tags, before.tags);
                assert_eq!(before.gas_remaining - records[0].after.gas_remaining, 3);
                assert_eq!(records[0].after.pc, before.pc + 4);
                assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            }
        }
    }
}

#[test]
fn moves_bind_zero_and_nonzero_predicates_even_with_coherent_false_outputs() {
    for word in [
        enc::encode_rr(wide::arithmetic::CMOV, 8, 6, 7),
        enc::encode_ri(wide::arithmetic::CMOVI, 8, 7, -128),
    ] {
        for condition in [0, 1, 1 << 32, 0xffff_ffff_0000_0001] {
            let (segment, records) =
                recorded(&[word], 1, &[(6, 91), (7, condition), (8, 55)], 1_000);
            let Family::Move(value) = family(word).unwrap() else {
                unreachable!()
            };
            let false_result = if condition == 0 {
                value.value(&segment.before)
            } else {
                segment.before.registers[8]
            };
            assert_ne!(false_result, segment.after.registers[8]);
            let mut forged = records.clone();
            forged[0].after.registers[8] = false_result;
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                1,
                forged[0].before,
                forged[0].after,
                SegmentOutcome::Continue,
            )
            .unwrap();
            let mut rows = changed.witness_rows(&forged).unwrap();
            rows[0][BRANCH + branch::TAKEN_BANK_OFFSET] = F(u64::from(condition == 0));
            rows[0][RESULT..RESULT + 2].copy_from_slice(&halves(false_result));
            assert!(rejects(&changed, &rows));
            // Internally valid banks for a fake condition do not establish a
            // read from the canonical condition register or erase its high bits.
            let false_condition = u64::from(condition == 0);
            replace_auxiliary_sources(&mut rows[0], word, false_condition, 0);
            assert!(rejects(&changed, &rows));
        }
    }
}

#[test]
fn moves_bind_selected_values_retained_values_and_untouched_registers() {
    for word in [
        enc::encode_rr(wide::arithmetic::CMOV, 8, 6, 7),
        enc::encode_ri(wide::arithmetic::CMOVI, 8, 7, -128),
    ] {
        for condition in [0, 1] {
            let (segment, records) =
                recorded(&[word], 1, &[(6, 91), (7, condition), (8, 55)], 1_000);
            for (register, mask) in [(8, 1), (8, 1 << 32), (6, 1), (7, 1), (255, 1)] {
                let mut forged = records.clone();
                forged[0].after.registers[register] ^= mask;
                let changed = ScalarSegment::new(
                    segment.contract.clone(),
                    1,
                    forged[0].before,
                    forged[0].after,
                    SegmentOutcome::Continue,
                )
                .unwrap();
                let mut rows = changed.witness_rows(&forged).unwrap();
                if register == 8 {
                    rows[0][RESULT..RESULT + 2]
                        .copy_from_slice(&halves(forged[0].after.registers[8]));
                }
                assert!(rejects(&changed, &rows));
            }
            let mut forged = records.clone();
            forged[0].after.pc += 4;
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
fn conditional_moves_reject_every_interior_column_in_both_predicate_modes() {
    for word in [
        enc::encode_rr(wide::arithmetic::CMOV, 8, 6, 7),
        enc::encode_ri(wide::arithmetic::CMOVI, 8, 7, -128),
    ] {
        for condition in [0, 0xffff_ffff_0000_0001] {
            let (segment, records) = recorded(
                &[
                    enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
                    word,
                    enc::encode_ri(wide::arithmetic::ADDI, 25, 25, 0),
                ],
                3,
                &[(6, 91), (7, condition), (8, 55)],
                1_000,
            );
            let rows = segment.witness_rows(&records).unwrap();
            assert_rows(&segment, &rows);
            for column in 0..ROW_WIDTH {
                let mut forged = rows[1].clone();
                forged[column] = forged[column].add(F::ONE);
                let incoming =
                    residues(&segment, &rows[0], &forged, &segment.fixed_row(0)).unwrap();
                let outgoing =
                    residues(&segment, &forged, &rows[2], &segment.fixed_row(1)).unwrap();
                assert!(
                    incoming
                        .iter()
                        .chain(&outgoing)
                        .any(|value| *value != F::ZERO),
                    "accepted opcode {:#x}, condition {condition:#x}, column {column}",
                    wide::opcode(word)
                );
            }
        }
    }
}

#[test]
fn conditional_moves_keep_public_tags_and_reject_private_condition_source_and_retention_claims() {
    for word in [
        enc::encode_rr(wide::arithmetic::CMOV, 8, 6, 7),
        enc::encode_ri(wide::arithmetic::CMOVI, 8, 7, -128),
    ] {
        for condition in [0, 1] {
            let contract = contract_with_cycle_policy(&[word], 32, ivm::ivm_mode::ZK);
            let mut vm = IVM::new(1_000);
            vm.load_prepared(&contract).unwrap();
            for (register, value) in [(6, 91), (7, condition), (8, 55)] {
                vm.set_register(register, value);
            }
            let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
            let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
            let _outcome =
                vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
            let record = recorder.records()[0].clone();
            assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
            assert!(
                record
                    .before
                    .tags
                    .iter()
                    .chain(&record.after.tags)
                    .all(|tag| !tag)
            );
            let segment = ScalarSegment::new(
                contract.clone(),
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
            // The bounded relation intentionally does not attest a private
            // source or retained private destination, even on a false condition.
            for register in [6, 7, 8] {
                for before in [false, true] {
                    let mut entry = record.before;
                    let mut exit = record.after;
                    if before {
                        entry.tags[register] = true;
                    } else {
                        exit.tags[register] = true;
                    }
                    assert!(
                        ScalarSegment::new(
                            contract.clone(),
                            1,
                            entry,
                            exit,
                            SegmentOutcome::Continue
                        )
                        .is_err()
                    );
                }
            }
        }
    }
}

#[test]
fn mixed_moves_preserve_degree_four_and_native_profile_geometry() {
    let (segment, records) = move_mix();
    assert_rows(&segment, &segment.witness_rows(&records).unwrap());
    assert_eq!(segment.after.registers[8], u64::MAX);
    assert_eq!(segment.after.registers[9], 56);
    assert_eq!(segment.after.registers[20], i64::cast_unsigned(-128_i64));
    assert_eq!(segment.after.registers[21], 58);
    assert_eq!(segment.after.registers[7], i64::cast_unsigned(-128_i64));
    assert_eq!(segment.base_width_v1(), 1_356);
    assert_eq!(segment.profile_constraint_count_v1(), 3_369);
    assert_eq!(
        measured_maximum_affine_degree_v1(
            [0xe8; 32],
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
fn native_stark_proves_moves_and_binds_both_branches_and_signed_immediate() {
    let (segment, records) = move_mix();
    let proof =
        prove_proof_managed_note_stark_v1(&segment, &segment.columns(&records).unwrap()).unwrap();
    verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
    for register in [7, 8, 9, 20, 21] {
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
    artifact[offset..offset + 4]
        .copy_from_slice(&enc::encode_ri(wide::arithmetic::CMOVI, 20, 7, 127).to_le_bytes());
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
