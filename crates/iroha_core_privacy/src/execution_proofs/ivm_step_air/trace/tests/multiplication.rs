//! Full-width multiply parity, shared-bank regressions, carry attacks and native geometry.

use super::*;

fn expected(opcode: u8, left: u64, right: u64) -> u64 {
    match opcode {
        wide::arithmetic::MUL => left.wrapping_mul(right),
        wide::arithmetic::MULHU => ((u128::from(left) * u128::from(right)) >> 64) as u64,
        wide::arithmetic::MULHSU => {
            ((i128::from(u64::cast_signed(left)) * i128::from(right)) >> 64) as u64
        }
        wide::arithmetic::MULH => {
            ((i128::from(u64::cast_signed(left)) * i128::from(u64::cast_signed(right))) >> 64)
                as u64
        }
        _ => unreachable!("multiply fixture opcode"),
    }
}

fn maximum_segment() -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let return_words = crate::ivm_test_support::unit_return().len() / 4;
    let body_words = MAX_WORDS - return_words;
    let mut body = (0..body_words - 1)
        .map(|index| match index % 7 {
            0..=3 => enc::encode_rr(MULTIPLY_OPS[index % 7], 8 + (index % 4) as u8, 6, 7),
            4 => enc::encode_rr(wide::arithmetic::CLZ, 20, 6, 255),
            5 => enc::encode_rr(wide::arithmetic::CTZ, 21, 7, 255),
            _ => enc::encode_ri(wide::arithmetic::XORI, 22, 6, -128),
        })
        .collect::<Vec<_>>();
    body.push(enc::encode_offset24(
        wide::control::JMP,
        -((body_words - 1) as i32),
    ));
    let (segment, records) = recorded(
        &body,
        MAX_STEPS,
        &[
            (6, 0xffff_ffff_ffff_fffe),
            (7, 0x8000_ffff_ffff_ffff),
            (255, u64::MAX),
        ],
        100_000,
    );
    assert_eq!(segment.steps, MAX_STEPS);
    assert_eq!(segment.words.len(), MAX_WORDS);
    (segment, records)
}

#[test]
fn multiply_variants_match_interpreter_full_width_boundaries_aliases_and_r0() {
    let pairs = [
        (0, 0),
        (0, u64::MAX),
        (1, u64::MAX),
        (u64::MAX, u64::MAX),
        (i64::cast_unsigned(i64::MIN), i64::cast_unsigned(i64::MIN)),
        (i64::MAX as u64, i64::MAX as u64),
        (i64::cast_unsigned(i64::MIN), u64::MAX),
        (i64::MAX as u64, u64::MAX),
        (0x0000_ffff_0000_ffff, 0xffff_0000_ffff_0000),
        (0xffff_ffff_0000_0001, 0x8000_0000_0000_0001),
        (0x0000_0001_ffff_ffff, 0x0000_ffff_ffff_ffff),
        (0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa),
    ];
    for opcode in MULTIPLY_OPS {
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
                let (segment, records) = recorded(
                    &[enc::encode_rr(opcode, rd, rs1, rs2)],
                    1,
                    &[(6, left), (7, right), (8, 91)],
                    1_000,
                );
                let mut wanted = segment.before.registers;
                if rd != 0 {
                    wanted[usize::from(rd)] =
                        expected(opcode, wanted[usize::from(rs1)], wanted[usize::from(rs2)]);
                }
                assert_eq!(segment.after.registers, wanted);
                assert_eq!(segment.after.tags, segment.before.tags);
                assert_eq!(segment.after.pc, segment.before.pc + 4);
                assert_eq!(segment.after.cycles, segment.before.cycles + 1);
                assert_eq!(
                    segment.after.gas_remaining + 3,
                    segment.before.gas_remaining
                );
                assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            }
        }
    }
}

#[test]
fn signed_unsigned_product_preserves_operand_asymmetry_and_exact_carry_bounds() {
    let left = i64::cast_unsigned(i64::MIN);
    let right = u64::MAX;
    assert_ne!(
        expected(wide::arithmetic::MULHSU, left, right),
        expected(wide::arithmetic::MULHSU, right, left)
    );
    for (a, b) in [(left, right), (right, left), (u64::MAX, u64::MAX)] {
        let (segment, records) = recorded(
            &[enc::encode_rr(wide::arithmetic::MULHSU, 8, 6, 7)],
            1,
            &[(6, a), (7, b)],
            1_000,
        );
        let rows = segment.witness_rows(&records).unwrap();
        let carries = &rows[0][MULTIPLY + multiply::CARRY..MULTIPLY + multiply::CARRY_DIGITS];
        assert!(carries.iter().all(|carry| carry.0 < 1 << 18));
        if a == u64::MAX && b == u64::MAX {
            assert_eq!(carries.iter().map(|carry| carry.0).max(), Some(262_139));
        }
        assert_rows(&segment, &rows);
    }
}

fn forged_result(
    segment: &ScalarSegment,
    records: &[DiagnosticStepRecord],
    value: u64,
) -> (ScalarSegment, Vec<Vec<F>>) {
    let mut forged = records.to_vec();
    forged[0].after.registers[8] = value;
    let changed = ScalarSegment::new(
        segment.contract.clone(),
        1,
        forged[0].before,
        forged[0].after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    let mut rows = changed.witness_rows(&forged).unwrap();
    rows[0][RESULT..RESULT + 2].copy_from_slice(&halves(value));
    (changed, rows)
}

#[test]
fn coherent_wrong_product_halves_and_signedness_cannot_change_public_boundaries() {
    let (left, right) = (0xffff_ffff_ffff_fffd, 0x8000_0000_0000_0001);
    for (kind, opcode) in MULTIPLY_OPS.into_iter().enumerate() {
        let (segment, records) = recorded(
            &[enc::encode_rr(opcode, 8, 6, 7)],
            1,
            &[(6, left), (7, right)],
            1_000,
        );
        for alternative in MULTIPLY_OPS {
            let result = expected(alternative, left, right);
            if result != segment.after.registers[8] {
                let (changed, rows) = forged_result(&segment, &records, result);
                assert!(rejects(&changed, &rows));
            }
        }
        // Every product digit, limb and signed correction agrees with a false
        // 128-bit product; source-derived carry equations must still reject it.
        let digits = multiply::product_digits(left ^ 1, right);
        let bank = multiply::witness(left, right, &digits, true);
        let result = multiply::result_half(&bank, kind, 0).0
            | (multiply::result_half(&bank, kind, 1).0 << 32);
        assert_ne!(result, segment.after.registers[8]);
        let (changed, mut rows) = forged_result(&segment, &records, result);
        rows[0][BIT_COUNT..MULTIPLY].copy_from_slice(&digits);
        rows[0][MULTIPLY..ABSOLUTE].copy_from_slice(&bank);
        assert!(rejects(&changed, &rows));
    }
}

#[test]
fn omitted_signed_corrections_and_coherent_false_source_banks_fail_air() {
    let (left, right) = (0xffff_ffff_ffff_fffd, 0x8000_0000_0000_0001);
    for (kind, opcode) in MULTIPLY_OPS.into_iter().enumerate() {
        let word = enc::encode_rr(opcode, 8, 6, 7);
        let (segment, records) = recorded(&[word], 1, &[(6, left), (7, right)], 1_000);
        let false_left = left ^ (1 << 63);
        let false_result = expected(opcode, false_left, right);
        assert_ne!(false_result, segment.after.registers[8]);
        let (changed, mut rows) = forged_result(&segment, &records, false_result);
        replace_auxiliary_sources(&mut rows[0], word, false_left, right);
        assert!(rejects(&changed, &rows));
        if kind >= 2 {
            let digits = multiply::product_digits(left, right);
            let mut bank = multiply::witness(left, right, &digits, true);
            let without_sign =
                multiply::witness(left & !(1 << 63), right & !(1 << 63), &digits, true);
            bank[multiply::SIGNED_UNSIGNED..]
                .copy_from_slice(&without_sign[multiply::SIGNED_UNSIGNED..]);
            let result = multiply::result_half(&bank, kind, 0).0
                | (multiply::result_half(&bank, kind, 1).0 << 32);
            assert_ne!(result, segment.after.registers[8]);
            let (changed, mut rows) = forged_result(&segment, &records, result);
            rows[0][MULTIPLY..ABSOLUTE].copy_from_slice(&bank);
            assert!(rejects(&changed, &rows));
        }
    }
}

#[test]
fn carries_final_product_and_workspace_ownership_reject_coherent_forgeries() {
    let (left, right) = (u64::MAX, u64::MAX);
    let (segment, records) = recorded(
        &[enc::encode_rr(wide::arithmetic::MULHU, 8, 6, 7)],
        1,
        &[(6, left), (7, right)],
        1_000,
    );
    let rows = segment.witness_rows(&records).unwrap();
    for carry in 0..7 {
        let mut forged = rows.clone();
        let value = forged[0][MULTIPLY + multiply::CARRY + carry].0 + 1;
        forged[0][MULTIPLY + multiply::CARRY + carry] = F(value);
        word::fill_digits(
            &mut forged[0][MULTIPLY + multiply::CARRY_DIGITS + 9 * carry
                ..MULTIPLY + multiply::CARRY_DIGITS + 9 * (carry + 1)],
            value,
        );
        assert!(
            rejects(&segment, &forged),
            "range-valid false carry {carry}"
        );
    }
    let mut forged = rows.clone();
    forged[0][MULTIPLY + multiply::CARRY] = F(1 << 18);
    forged[0][MULTIPLY + multiply::CARRY_DIGITS..MULTIPLY + multiply::CARRY_DIGITS + 9]
        .fill(F::ZERO);
    forged[0][MULTIPLY + multiply::CARRY_DIGITS + 8] = F(4);
    assert!(rejects(&segment, &forged), "coherent 19-bit carry");
    // Alter the top product limb and output together: no unbound final carry
    // may erase the exact top convolution equation.
    let mut digits = multiply::product_digits(left, right);
    digits[63] = digits[63].sub(F::ONE);
    let bank = multiply::witness(left, right, &digits, true);
    let result =
        multiply::result_half(&bank, 1, 0).0 | (multiply::result_half(&bank, 1, 1).0 << 32);
    let (changed, mut forged) = forged_result(&segment, &records, result);
    forged[0][BIT_COUNT..MULTIPLY].copy_from_slice(&digits);
    forged[0][MULTIPLY..ABSOLUTE].copy_from_slice(&bank);
    assert!(rejects(&changed, &forged));
    // A local carry/product compensation preserves one convolution equation,
    // but requires a negative low limb and must fail canonical digit bounds.
    let mut forged = rows.clone();
    forged[0][MULTIPLY + multiply::CARRY] = forged[0][MULTIPLY + multiply::CARRY].add(F::ONE);
    let carry = forged[0][MULTIPLY + multiply::CARRY].0;
    word::fill_digits(
        &mut forged[0][MULTIPLY + multiply::CARRY_DIGITS..MULTIPLY + multiply::CARRY_DIGITS + 9],
        carry,
    );
    forged[0][MULTIPLY + multiply::PRODUCT] =
        forged[0][MULTIPLY + multiply::PRODUCT].sub(F(1 << 16));
    forged[0][BIT_COUNT] = forged[0][BIT_COUNT].sub(F(1 << 16));
    assert!(rejects(&segment, &forged));
    // The old prefix semantics remain compulsory for all old instructions.
    let (old, records) = recorded(
        &[enc::encode_rr(wide::arithmetic::ADD, 8, 6, 7)],
        1,
        &[(6, left), (7, right)],
        1_000,
    );
    let mut old_rows = old.witness_rows(&records).unwrap();
    let digits = multiply::product_digits(left, right);
    old_rows[0][BIT_COUNT..MULTIPLY].copy_from_slice(&digits);
    old_rows[0][MULTIPLY..ABSOLUTE]
        .copy_from_slice(&multiply::witness(left, right, &digits, false));
    assert!(
        rejects(&old, &old_rows),
        "multiply digits in nonmultiply workspace"
    );
    let mut old_rows = old.witness_rows(&records).unwrap();
    old_rows[0][MULTIPLY + multiply::CARRY] = F::ONE;
    old_rows[0][MULTIPLY + multiply::CARRY_DIGITS] = F::ONE;
    assert!(rejects(&old, &old_rows), "unconstrained inactive carry");
    let mut forged = rows.clone();
    let prefixes = bit_count::witness(Sources::new(&forged[0][SOURCES..ALU]).bits(0), false);
    forged[0][BIT_COUNT..MULTIPLY].copy_from_slice(&prefixes);
    forged[0][MULTIPLY..ABSOLUTE].copy_from_slice(&multiply::witness(left, right, &prefixes, true));
    assert!(
        rejects(&segment, &forged),
        "count prefixes in multiply workspace"
    );
}

#[test]
fn common_source_view_preserves_every_old_family_and_all_profile_columns() {
    let mut words = Vec::new();
    for opcode in [
        wide::arithmetic::ADD,
        wide::arithmetic::SUB,
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
        wide::arithmetic::SLL,
        wide::arithmetic::SRL,
        wide::arithmetic::SRA,
        wide::arithmetic::ROTL,
        wide::arithmetic::ROTR,
    ] {
        words.push(enc::encode_rr(opcode, 8, 6, 7));
    }
    for opcode in [
        wide::arithmetic::ADDI,
        wide::arithmetic::ANDI,
        wide::arithmetic::ORI,
        wide::arithmetic::XORI,
        wide::arithmetic::ROTL_IMM,
        wide::arithmetic::ROTR_IMM,
    ] {
        words.push(enc::encode_ri(opcode, 8, 6, -128));
    }
    words.extend(COMPARE_OPS.map(|opcode| enc::encode_rr(opcode, 8, 6, 7)));
    words.extend(BRANCH_OPS.map(|opcode| enc::encode_branch(opcode, 6, 7, 1)));
    words.extend(COUNT_OPS.map(|opcode| enc::encode_rr(opcode, 8, 6, 255)));
    words.extend(MULTIPLY_OPS.map(|opcode| enc::encode_rr(opcode, 8, 6, 7)));
    for opcode in [
        wide::arithmetic::NEG,
        wide::arithmetic::NOT,
        wide::system::GETGAS,
    ] {
        words.push(enc::encode_rr(opcode, 8, 6, 255));
    }
    for condition in [0, 7] {
        words.push(enc::encode_rr(wide::arithmetic::CMOV, 8, 6, condition));
        words.push(enc::encode_ri(wide::arithmetic::CMOVI, 8, condition, -128));
    }
    words.push(enc::encode_offset24(wide::control::JMP, 1));
    words.push(enc::encode_jump(wide::control::JAL, 0, 1));
    for word in words {
        let (segment, records) = recorded(
            &[
                enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
                word,
                enc::encode_ri(wide::arithmetic::ADDI, 25, 25, 0),
            ],
            3,
            &[
                (6, 0x8000_ffff_ffff_ffff),
                (7, u64::MAX),
                (8, 91),
                (255, 37),
            ],
            u64::MAX,
        );
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        let sources = Sources::new(&rows[1][SOURCES..ALU]);
        let expected =
            operands(word, family(word).unwrap()).map(|source| source.value(&records[1].before));
        for operand in 0..2 {
            for half in 0..2 {
                assert_eq!(sources.half(operand, half), halves(expected[operand])[half]);
            }
        }
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
                "opcode {:#x} leaves column {column} unbound",
                wide::opcode(word)
            );
        }
    }
}

#[test]
fn multiplication_keeps_public_tag_boundary_and_complete_register_restrictions() {
    let (segment, records) = recorded(
        &[enc::encode_rr(wide::arithmetic::MULH, 0, 6, 7)],
        1,
        &[(6, u64::MAX), (7, i64::cast_unsigned(i64::MIN))],
        1_000,
    );
    for register in [0, 6, 7, 8, 255] {
        let mut before = segment.before;
        before.tags[register] = true;
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                1,
                before,
                segment.after,
                SegmentOutcome::Continue
            )
            .is_err()
        );
        let mut after = segment.after;
        after.tags[register] = true;
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                1,
                segment.before,
                after,
                SegmentOutcome::Continue
            )
            .is_err()
        );
    }
    let mut rows = segment.witness_rows(&records).unwrap();
    rows[1][0] = F::ONE;
    assert!(rejects(&segment, &rows));
}

#[test]
fn multiply_maximum_segment_stays_degree_four_inside_unchanged_native_envelope() {
    let (segment, records) = maximum_segment();
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
            [0xda; 32],
            [ROW_WIDTH, ROW_WIDTH, 0, 0, FIXED_WIDTH],
            3,
            4,
            |row, next, _, _, fixed| residues(&segment, row, next, fixed)
        ),
        4
    );
}

#[test]
fn native_stark_proves_maximum_multiply_segment_and_binds_signedness_and_outputs() {
    let (segment, records) = maximum_segment();
    let columns = segment.columns(&records).unwrap();
    let proof = prove_proof_managed_note_stark_v1(&segment, &columns).unwrap();
    assert!(proof.len() <= 4_153_152);
    verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
    for register in [8, 9, 10, 11] {
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
    let offset = segment.contract.code_offset() + 8;
    artifact[offset..offset + 4]
        .copy_from_slice(&enc::encode_rr(wide::arithmetic::MULHU, 10, 6, 7).to_le_bytes());
    let changed = ScalarSegment::new(
        ivm::prepare_contract(Arc::from(artifact)).unwrap(),
        segment.steps,
        segment.before,
        segment.after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
    let mut forged = columns;
    forged[NOTE_COPY_WIDTH_V1 + MULTIPLY + multiply::CARRY][0] = F::ZERO;
    assert!(prove_proof_managed_note_stark_v1(&segment, &forged).is_err());
}

#[test]
fn product_limb_equations_match_wide_integer_oracle_for_seeded_inputs() {
    let mut seed = 0x76b9_0241_faca_8182_u64;
    let boundary = (0..64).flat_map(|position| {
        [
            (1_u64 << position, u64::MAX),
            (
                (1_u64 << position).wrapping_sub(1),
                (1_u64 << position).wrapping_add(1),
            ),
        ]
    });
    let random = (0..512).map(|_| {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let left = seed;
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (left, seed)
    });
    for (left, right) in boundary.chain(random) {
        let bits = word::witness(left, right);
        let sources = Sources::new(&bits);
        let digits = multiply::product_digits(left, right);
        let bank = multiply::witness(left, right, &digits, true);
        let mut equations = Vec::new();
        sources.append_residues(&mut equations);
        multiply::append_residues(
            &mut equations,
            &bank,
            &digits,
            sources,
            multiply::Selection {
                multiply: F::ONE,
                division: F::ZERO,
                square: F::ZERO,
                other: F::ZERO,
                signed: F::ZERO,
                success: F::ZERO,
                quotient: [F::ZERO; 4],
            },
        );
        assert_eq!(equations.len(), word::WIDTH + multiply::CONSTRAINTS);
        assert!(equations.iter().all(|value| *value == F::ZERO));
        for (kind, opcode) in MULTIPLY_OPS.into_iter().enumerate() {
            let result = multiply::result_half(&bank, kind, 0).0
                | (multiply::result_half(&bank, kind, 1).0 << 32);
            assert_eq!(result, expected(opcode, left, right));
        }
    }
}
