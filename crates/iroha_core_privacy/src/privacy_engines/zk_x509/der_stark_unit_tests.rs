//! Exact DER STARK arithmetic, schedule and boundary regression tests.

use super::*;
use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
use sha2::{Digest as _, Sha256};
#[test]
fn parser_private_inverse_cells_preserve_byte_and_zero_boundaries() {
    let mut state = ParserStateV1::for_document(0, 1).expect("parser state");
    state.phase = PHASE_PRIMITIVE_CONTENT;
    for delta in [0, 1, ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 as u64] {
        state.check_delta = delta;
        for byte in 0_u8..=u8::MAX {
            let row = encode_parser_state_v1(&state, Some(byte)).expect("byte state");
            assert_eq!(row[BASE_CHECK_IS_ZERO], F(u64::from(delta == 0)));
            assert_eq!(row[BASE_CHECK_INVERSE], F(delta).inv().unwrap_or(F::ZERO));
            assert_eq!(row[BASE_PAYLOAD + 6], F(u64::from(byte == 0)));
            assert_eq!(
                row[BASE_PAYLOAD + 7],
                F(u64::from(byte)).inv().unwrap_or(F::ZERO)
            );
            assert_eq!(row[BASE_PAYLOAD + 8], F(u64::from(byte == u8::MAX)));
            assert_eq!(
                row[BASE_PAYLOAD + 9],
                F(u64::from(byte)).sub(F(255)).inv().unwrap_or(F::ZERO)
            );
        }
    }
    assert!(matches!(
        encode_parser_state_v1(&state, None),
        Err(ZkX509DerStarkErrorV1::Row)
    ));
    assert_eq!(
        inverse_or_zero_v1(GOLDILOCKS_MODULUS_V1 - 1),
        F(GOLDILOCKS_MODULUS_V1 - 1)
    );
    for word in [GOLDILOCKS_MODULUS_V1, GOLDILOCKS_MODULUS_V1 + 1, u64::MAX] {
        assert!(std::panic::catch_unwind(|| inverse_or_zero_v1(word)).is_err());
    }
}

#[test]
fn zero_test_witness_preserves_canonical_and_malformed_row_effects() {
    for word in (0_u64..=255).chain([
        GOLDILOCKS_MODULUS_V1 - 1,
        GOLDILOCKS_MODULUS_V1,
        GOLDILOCKS_MODULUS_V1 + 1,
        u64::MAX,
    ]) {
        let mut row = [F(37); ZK_X509_DER_STARK_AUX_WIDTH_V1];
        let mut expected = row;
        expected[3] = F(u64::from(word == 0));
        let result = write_zero_test_witness_v1(&mut row, 3, 7, F(word));
        if let Some(value) = F::canonical(word) {
            expected[7] = value.inv().unwrap_or(F::ZERO);
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(ZkX509DerStarkErrorV1::Row)));
        }
        assert_eq!(row, expected, "word {word}");
    }
}

fn assert_lookup_inverse_witnesses(
    trace: &ZkX509DerStarkTraceV1,
    challenges: ZkX509DerStarkChallengesV1,
) {
    for (index, (base, aux)) in trace.base.rows.iter().zip(&trace.aux_rows).enumerate() {
        let parser = index < trace.base.private_shape.parser_rows;
        let phase = pack_bits_v1(&base[BASE_PHASE_BITS..BASE_PHASE_BITS + 3]).0;
        let consuming = parser
            && matches!(
                phase as usize,
                PHASE_IDENTIFIER_FIRST
                    | PHASE_IDENTIFIER_HIGH
                    | PHASE_LENGTH_FIRST
                    | PHASE_LENGTH_BODY
                    | PHASE_PRIMITIVE_CONTENT
            );
        for lane in 0..ZK_X509_DER_STARK_BUS_LANES_V1 {
            let mut table_delta = F::ZERO;
            let mut table_zero_delta = F::ZERO;
            let mut query_delta = F::ZERO;
            let mut query_zero_delta = F::ZERO;
            if consuming {
                let denominator = byte_denominator_v1(
                    byte_tuple_v1(
                        base[BASE_DOCUMENT],
                        base[BASE_OFFSET],
                        base[BASE_BYTE_VALUE],
                    ),
                    lane,
                    &challenges,
                );
                let inverse = denominator.inv().unwrap_or(F::ZERO);
                let zero = F(u64::from(denominator == F::ZERO));
                assert_eq!(aux[AUX_BYTE_TABLE_INVERSE + lane], inverse);
                assert_eq!(aux[AUX_BYTE_TABLE_ZERO + lane], zero);
                table_delta = base[BASE_BYTE_LOOKUP_MULTIPLICITY].mul(inverse);
                table_zero_delta = base[BASE_BYTE_LOOKUP_MULTIPLICITY].mul(zero);
            }
            if !parser {
                for (tuple, inverse_column, zero_column) in [
                    (
                        byte_tuple_v1(base[0], base[4].add(base[9]), base[10]),
                        AUX_BYTE_LEFT_QUERY_INVERSE + lane,
                        AUX_BYTE_LEFT_QUERY_ZERO + lane,
                    ),
                    (
                        byte_tuple_v1(base[0], base[6].add(base[9]), base[11]),
                        AUX_BYTE_RIGHT_QUERY_INVERSE + lane,
                        AUX_BYTE_RIGHT_QUERY_ZERO + lane,
                    ),
                ] {
                    let denominator = byte_denominator_v1(tuple, lane, &challenges);
                    let inverse = denominator.inv().unwrap_or(F::ZERO);
                    let zero = F(u64::from(denominator == F::ZERO));
                    assert_eq!(aux[inverse_column], inverse);
                    assert_eq!(aux[zero_column], zero);
                    query_delta = query_delta.add(inverse);
                    query_zero_delta = query_zero_delta.add(zero);
                }
            }
            for (before, after, delta) in [
                (
                    AUX_BYTE_TABLE_SUM_BEFORE,
                    AUX_BYTE_TABLE_SUM_AFTER,
                    table_delta,
                ),
                (
                    AUX_BYTE_TABLE_ZERO_COUNT_BEFORE,
                    AUX_BYTE_TABLE_ZERO_COUNT_AFTER,
                    table_zero_delta,
                ),
                (
                    AUX_BYTE_QUERY_SUM_BEFORE,
                    AUX_BYTE_QUERY_SUM_AFTER,
                    query_delta,
                ),
                (
                    AUX_BYTE_QUERY_ZERO_COUNT_BEFORE,
                    AUX_BYTE_QUERY_ZERO_COUNT_AFTER,
                    query_zero_delta,
                ),
            ] {
                assert_eq!(aux[after + lane], aux[before + lane].add(delta));
            }
        }
    }
}

fn challenges() -> ZkX509DerStarkChallengesV1 {
    ZkX509DerStarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|column| {
                F(u64::try_from(1_000 + lane * 100 + column).expect("challenge"))
            })
        }),
        byte_lookup: [F(9_001), F(9_002), F(9_003), F(9_004)],
    }
}
fn private_shape() -> ZkX509DerStarkPrivateShapeV1 {
    ZkX509DerStarkPrivateShapeV1 {
        document_lengths: vec![2, 3],
        parser_rows: 9,
        comparator_rows: 4,
    }
}
fn try_low_degree_aux(
    base: &[F; ZK_X509_DER_STARK_BASE_WIDTH_V1],
    fixed: &[F; ZK_X509_DER_STARK_FIXED_WIDTH_V1],
) -> Result<[F; ZK_X509_DER_STARK_AUX_WIDTH_V1], ZkX509DerStarkErrorV1> {
    let mut aux = [F::ZERO; ZK_X509_DER_STARK_AUX_WIDTH_V1];
    populate_low_degree_auxiliaries_v1(base, fixed, &mut aux)?;
    Ok(aux)
}
fn low_degree_aux(
    base: &[F; ZK_X509_DER_STARK_BASE_WIDTH_V1],
    fixed: &[F; ZK_X509_DER_STARK_FIXED_WIDTH_V1],
) -> [F; ZK_X509_DER_STARK_AUX_WIDTH_V1] {
    try_low_degree_aux(base, fixed).expect("low-degree auxiliaries")
}
fn transcript_with_base_root(root_word: u64) -> TransparentTranscriptV1 {
    let profile = PrivacyOuterDigestV1::from_bytes([0x41; 48]);
    let public = PrivacyOuterDigestV1::from_bytes([0x83; 48]);
    let root = PrivacyOuterDigestV1::from_bytes(
        root_word
            .to_be_bytes()
            .repeat(6)
            .try_into()
            .expect("48 fixture bytes"),
    )
    .to_bytes();
    let mut transcript = TransparentTranscriptV1::new(
        super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
        b"zk-x509-der-challenge-test-suite-v1",
        &profile,
        &public,
    )
    .expect("transcript");
    transcript
        .absorb(b"zk-x509-der-base-root-test-v1", &[&root])
        .expect("base root");
    transcript
}
#[test]
fn transcript_challenge_schedule_is_lane_major_base_bound_and_pinned() {
    let mut transcript = transcript_with_base_root(0x25);
    let derived = derive_zk_x509_der_stark_challenges_v1(&mut transcript).expect("DER challenges");
    derived.validate().expect("valid DER challenges");
    let mut replay = transcript_with_base_root(0x25);
    assert_eq!(
        derived,
        derive_zk_x509_der_stark_challenges_v1(&mut replay).expect("replayed challenges")
    );
    let mut encoding = Vec::with_capacity(
        ZK_X509_DER_STARK_BUS_LANES_V1 * (DER_TUPLE_CHALLENGE_LABELS_V1.len() + 1) * 8,
    );
    for lane in 0..ZK_X509_DER_STARK_BUS_LANES_V1 {
        for coefficient in derived.tuple[lane] {
            encoding.extend_from_slice(&coefficient.0.to_be_bytes());
        }
        encoding.extend_from_slice(&derived.byte_lookup[lane].0.to_be_bytes());
    }
    // Independently replayed with byte-framed SHA3-384, big-endian rejection
    // sampling and all 48 accepted digest bytes absorbed after each challenge.
    // The MAIN context binds family 1 and the fixed public nonce [0x5a; 32].
    let digest: [u8; 32] = Sha256::digest(&encoding).into();
    assert_eq!(
        digest,
        [
            0xcd, 0x5a, 0x09, 0xe2, 0xf2, 0x66, 0xe1, 0x16, 0xf8, 0x60, 0xbe, 0xa6, 0x62, 0x7d,
            0xa9, 0x91, 0x3e, 0x41, 0x73, 0xbb, 0xa8, 0xb0, 0x8a, 0x59, 0xf2, 0xd9, 0xcf, 0x94,
            0x22, 0x30, 0x2f, 0xf0,
        ]
    );
    let mut changed_root = transcript_with_base_root(0x26);
    let changed =
        derive_zk_x509_der_stark_challenges_v1(&mut changed_root).expect("changed-root challenges");
    assert_ne!(derived, changed);
    for lane in 0..ZK_X509_DER_STARK_BUS_LANES_V1 {
        assert_ne!(derived.tuple[lane], changed.tuple[lane]);
        assert_ne!(derived.byte_lookup[lane], changed.byte_lookup[lane]);
    }
    // A tuple-first schedule is consensus-significant: sampling the lookup
    // shift before the twelve coefficients must not reproduce a lane.
    let mut wrong_order = transcript_with_base_root(0x25);
    let first_lookup = wrong_order
        .challenge_field(DER_BYTE_LOOKUP_CHALLENGE_LABEL_V1)
        .expect("wrong-order lookup");
    let wrong_tuple = core::array::from_fn(|slot| {
        wrong_order
            .challenge_field(DER_TUPLE_CHALLENGE_LABELS_V1[slot])
            .expect("wrong-order tuple")
    });
    assert_ne!(derived.byte_lookup[0], first_lookup);
    assert_ne!(derived.tuple[0], wrong_tuple);
}
#[test]
fn fixed_schedule_is_exact_over_parser_comparator_and_padding_boundaries() {
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("fixed schedule");
    assert_eq!(
        schedule.active_rows(),
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1
    );
    assert_eq!(schedule.aggregate_rows(), ZK_X509_DER_STARK_TRACE_SIZE_V1);
    assert_eq!(ZK_X509_DER_STARK_FIXED_PADDING_ROWS_V1, 196_608);
    assert_eq!(
        schedule.active_rows() + ZK_X509_DER_STARK_FIXED_PADDING_ROWS_V1,
        schedule.aggregate_rows()
    );
    let first = schedule.fixed_row(0).expect("first");
    assert_eq!(first[FIX_ACTIVE], F::ONE);
    assert_eq!(first[FIX_FIRST_ACTIVE], F::ONE);
    assert_eq!(first[FIX_PARSER], F::ONE);
    assert_eq!(first[FIX_FIRST_PARSER], F::ONE);
    let last_parser = schedule
        .fixed_row(ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 - 1)
        .expect("last parser capacity row");
    assert_eq!(last_parser[FIX_LAST_PARSER], F::ONE);
    assert_eq!(last_parser[FIX_COMPARATOR], F::ZERO);
    let first_comparator = schedule
        .fixed_row(ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1)
        .expect("first comparator");
    assert_eq!(first_comparator[FIX_COMPARATOR], F::ONE);
    assert_eq!(first_comparator[FIX_FIRST_COMPARATOR], F::ONE);
    let last_active = schedule
        .fixed_row(ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1 - 1)
        .expect("last fixed-capacity row");
    assert_eq!(last_active[FIX_LAST_ACTIVE], F::ONE);
    assert_eq!(last_active[FIX_LAST_COMPARATOR], F::ONE);
    let first_padding = schedule
        .fixed_row(ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1)
        .expect("first padding");
    assert_eq!(first_padding[FIX_PADDING], F::ONE);
    assert_eq!(first_padding[FIX_ACTIVE], F::ZERO);
    let final_row = schedule
        .fixed_row(ZK_X509_DER_STARK_TRACE_SIZE_V1 - 1)
        .expect("final aggregate row");
    assert_eq!(final_row[FIX_PADDING], F::ONE);
    assert_eq!(final_row[FIX_LAST_AGGREGATE], F::ONE);
}
#[test]
fn private_geometry_cannot_change_public_transcript_or_fixed_schedule() {
    let first = private_shape();
    let second = ZkX509DerStarkPrivateShapeV1 {
        document_lengths: vec![4],
        parser_rows: 6,
        comparator_rows: 1,
    };
    first.validate().expect("first private shape");
    second.validate().expect("second private shape");
    assert_ne!(first, second);
    let public = ZkX509DerStarkShapeV1;
    assert_eq!(
        public.transcript_bytes(),
        b"zk-x509-der-stark-fixed-registration-v1"
    );
    let first_schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(public).expect("first schedule");
    let second_schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(public).expect("second schedule");
    for index in [
        0,
        ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 - 1,
        ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1 - 1,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        ZK_X509_DER_STARK_TRACE_SIZE_V1 - 1,
    ] {
        assert_eq!(
            first_schedule.fixed_row(index).expect("first fixed row"),
            second_schedule.fixed_row(index).expect("second fixed row")
        );
    }
}
#[test]
fn private_shape_rejects_empty_zero_oversized_and_overfull_profiles() {
    let mut mutations = Vec::new();
    let mut changed = private_shape();
    changed.document_lengths.clear();
    mutations.push(changed);
    changed = private_shape();
    changed.document_lengths[0] = 0;
    mutations.push(changed);
    changed = private_shape();
    changed.document_lengths[0] =
        u16::try_from(ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1 + 1).expect("limit fits");
    mutations.push(changed);
    changed = private_shape();
    changed.document_lengths = vec![1; ZK_X509_DER_STARK_MAX_DOCUMENTS_V1 + 1];
    changed.parser_rows = changed.document_lengths.len() * 3;
    mutations.push(changed);
    changed = private_shape();
    changed.document_lengths = vec![
        u16::try_from(ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1)
            .expect("proof cap fits");
        9
    ];
    changed.parser_rows =
        changed.document_lengths.len() * (ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1 + 2);
    changed.comparator_rows = 0;
    mutations.push(changed);
    changed = private_shape();
    changed.parser_rows = 1;
    mutations.push(changed);
    changed = private_shape();
    changed.comparator_rows = ZK_X509_DER_STARK_TRACE_SIZE_V1;
    mutations.push(changed);
    for (index, mutation) in mutations.into_iter().enumerate() {
        assert!(
            mutation.validate().is_err(),
            "shape mutation {index} must reject"
        );
    }
}
#[test]
fn numeric_layout_uses_two_base_and_four_honest_auxiliary_chunks() {
    assert_eq!(ZK_X509_DER_STARK_BASE_WIDTH_V1, 76);
    assert_eq!(
        ZK_X509_DER_STARK_BASE_WIDTH_V1.div_ceil(64),
        2,
        "private activity and document-count metadata use a second physical chunk"
    );
    assert_eq!(
        ZK_X509_DER_STARK_AUX_WIDTH_V1.div_ceil(64),
        4,
        "zero-safe lookup witnesses and degree-reduction intermediates must remain explicit"
    );
    assert_eq!(ZK_X509_DER_STARK_TRACE_LOG2_V1, 19);
    assert_eq!(ZK_X509_DER_STARK_TRACE_SIZE_V1, 1 << 19);
    assert_eq!(ZK_X509_DER_STARK_MAX_TOTAL_DOCUMENT_BYTES_V1, 32_768);
    assert_eq!(ZK_X509_DER_STARK_MAX_COMPARATOR_ROWS_V1, 262_144);
    assert_eq!(ZK_X509_DER_MAX_NESTING_DEPTH_V1, 16);
    assert_eq!(ZK_X509_DER_MAX_VALUES_V1, 2_048);
}
include!("der_stark/tuple_compression_test.rs");
#[test]
fn canonical_documents_compile_to_exact_streaming_and_set_rows() {
    let sequence = [0x30, 0x03, 0x02, 0x01, 0x01];
    let ordered_set = [0x31, 0x04, 0x05, 0x00, 0x05, 0x00];
    let base =
        build_zk_x509_der_stark_base_v1(&[&sequence, &ordered_set]).expect("numeric DER base");
    assert_eq!(base.private_shape.document_lengths, vec![5, 6]);
    assert!(base.private_shape.parser_rows > 11);
    assert_eq!(base.private_shape.comparator_rows, 2);
    assert_eq!(
        base.rows.len(),
        base.private_shape.active_rows().expect("active")
    );
    let first = &base.rows[0];
    assert_eq!(first[BASE_DOCUMENT], F::ZERO);
    assert_eq!(first[BASE_DOCUMENT_LEN], F(5));
    assert_eq!(first[BASE_OFFSET], F::ZERO);
    assert_eq!(first[BASE_BYTE_VALUE], F(0x30));
    assert_eq!(first[BASE_DOCUMENT_FIRST], F::ONE);
    assert_eq!(
        pack_bits_v1(&first[BASE_PHASE_BITS..BASE_PHASE_BITS + 3]),
        F(PHASE_IDENTIFIER_FIRST as u64)
    );
    let comparator = &base.rows[base.private_shape.parser_rows];
    assert_eq!(comparator[0], F::ONE);
    assert_eq!(comparator[28], F::ONE);
    assert_eq!(comparator[29], F::ZERO);
    assert_eq!(comparator[9], F::ZERO);
    let comparator_terminal = base.rows.last().expect("comparator terminal");
    assert_eq!(comparator_terminal[29], F::ONE);
    assert_eq!(comparator_terminal[9], F::ONE);
}
#[test]
fn malformed_and_noncanonical_documents_never_reach_numeric_compilation() {
    let adversarial: [&[u8]; 8] = [
        &[],
        &[0x30, 0x80, 0x00, 0x00],
        &[0x30, 0x81, 0x00],
        &[0x1f, 0x80, 0x01, 0x00],
        &[0x02, 0x02, 0x00, 0x01],
        &[0x03, 0x01, 0x08],
        &[0x06, 0x01, 0x80],
        &[0x31, 0x04, 0x05, 0x00, 0x01, 0x00],
    ];
    for (index, document) in adversarial.into_iter().enumerate() {
        assert!(
            build_zk_x509_der_stark_base_v1(&[document]).is_err(),
            "malformed DER family {index} must reject"
        );
    }
}
#[test]
fn numeric_air_rejects_nonminimal_identifier_length_and_primitive_families() {
    let mutate_byte = |row: &mut [F; ZK_X509_DER_STARK_BASE_WIDTH_V1], byte: u8| {
        row[BASE_BYTE_VALUE] = F(u64::from(byte));
        for bit in 0..8 {
            row[BASE_BYTE_BITS + bit] = F(u64::from((byte >> bit) & 1));
        }
        if pack_bits_v1(&row[BASE_PHASE_BITS..BASE_PHASE_BITS + 3])
            == F(PHASE_PRIMITIVE_CONTENT as u64)
        {
            let value = F(u64::from(byte));
            let ff_delta = value.sub(F(0xff));
            row[BASE_PAYLOAD + 6] = F(u64::from(byte == 0));
            row[BASE_PAYLOAD + 7] = value.inv().unwrap_or(F::ZERO);
            row[BASE_PAYLOAD + 8] = F(u64::from(byte == 0xff));
            row[BASE_PAYLOAD + 9] = ff_delta.inv().unwrap_or(F::ZERO);
        }
    };
    let rejects_pair = |index: usize,
                        current: [F; ZK_X509_DER_STARK_BASE_WIDTH_V1],
                        next: [F; ZK_X509_DER_STARK_BASE_WIDTH_V1]| {
        let schedule =
            compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("schedule");
        let fixed = schedule.fixed_row(index).expect("fixed");
        let next_fixed = schedule.fixed_row(index + 1).expect("next fixed");
        evaluate_zk_x509_der_stark_base_residues_v1(
            &current,
            &next,
            &low_degree_aux(&current, &fixed),
            &fixed,
            &next_fixed,
        )
        .iter()
        .any(|residue| *residue != F::ZERO)
    };
    let high_tag = [0x9f, 0x1f, 0x00];
    let base = build_zk_x509_der_stark_base_v1(&[&high_tag]).expect("high tag");
    let high_row = base
        .rows
        .iter()
        .position(|row| {
            pack_bits_v1(&row[BASE_PHASE_BITS..BASE_PHASE_BITS + 3])
                == F(PHASE_IDENTIFIER_HIGH as u64)
        })
        .expect("high row");
    let mut current = base.rows[high_row];
    let mut next = base.rows[high_row + 1];
    mutate_byte(&mut current, 0x1e);
    next[BASE_TAG_ACCUMULATOR] = F(30);
    assert!(rejects_pair(high_row, current, next));
    let mut long_length = vec![0x04, 0x81, 0x80];
    long_length.resize(3 + 128, 0x00);
    let base = build_zk_x509_der_stark_base_v1(&[&long_length]).expect("long length");
    let length_body = base
        .rows
        .iter()
        .position(|row| {
            pack_bits_v1(&row[BASE_PHASE_BITS..BASE_PHASE_BITS + 3]) == F(PHASE_LENGTH_BODY as u64)
        })
        .expect("length body");
    current = base.rows[length_body];
    mutate_byte(&mut current, 0x7f);
    assert!(rejects_pair(
        length_body,
        current,
        base.rows[length_body + 1]
    ));
    let integer = [0x02, 0x02, 0x00, 0x80];
    let base = build_zk_x509_der_stark_base_v1(&[&integer]).expect("integer");
    let first_content = base
        .rows
        .iter()
        .position(|row| row[BASE_PRIMITIVE_FIRST] == F::ONE)
        .expect("first content");
    current = base.rows[first_content];
    next = base.rows[first_content + 1];
    mutate_byte(&mut next, 0x7f);
    assert!(rejects_pair(first_content, current, next));
    let boolean = [0x01, 0x01, 0xff];
    let base = build_zk_x509_der_stark_base_v1(&[&boolean]).expect("boolean");
    let content = base
        .rows
        .iter()
        .position(|row| row[BASE_PRIMITIVE_FIRST] == F::ONE)
        .expect("content");
    current = base.rows[content];
    mutate_byte(&mut current, 0x01);
    assert!(rejects_pair(content, current, base.rows[content + 1]));
    let oid = [0x06, 0x01, 0x2a];
    let base = build_zk_x509_der_stark_base_v1(&[&oid]).expect("oid");
    let content = base
        .rows
        .iter()
        .position(|row| row[BASE_PRIMITIVE_FIRST] == F::ONE)
        .expect("content");
    current = base.rows[content];
    mutate_byte(&mut current, 0x80);
    assert!(rejects_pair(content, current, base.rows[content + 1]));
    let bit_string = [0x03, 0x02, 0x01, 0x80];
    let base = build_zk_x509_der_stark_base_v1(&[&bit_string]).expect("bit string");
    let last_content = base
        .rows
        .iter()
        .position(|row| {
            pack_bits_v1(&row[BASE_PHASE_BITS..BASE_PHASE_BITS + 3])
                == F(PHASE_PRIMITIVE_CONTENT as u64)
                && row[BASE_CHECK_IS_ZERO] == F::ONE
        })
        .expect("last content");
    current = base.rows[last_content];
    mutate_byte(&mut current, 0x81);
    assert!(rejects_pair(
        last_content,
        current,
        base.rows[last_content + 1]
    ));
}
#[test]
fn every_canonical_streaming_and_set_row_satisfies_numeric_base_air() {
    let nested = [
        0x30, 0x0a, 0x31, 0x04, 0x05, 0x00, 0x05, 0x00, 0x02, 0x02, 0x00, 0x80,
    ];
    let base = build_zk_x509_der_stark_base_v1(&[&nested]).expect("numeric DER base");
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("fixed schedule");
    for index in 0..base.rows.len() {
        let native_index =
            zk_x509_der_stark_compact_row_native_index_v1(&base.private_shape, index)
                .expect("native row");
        let next = zk_x509_der_stark_aggregate_base_row_v1(&base, native_index + 1)
            .expect("next native row");
        let fixed = schedule.fixed_row(native_index).expect("fixed row");
        let next_fixed = schedule
            .fixed_row(native_index + 1)
            .expect("next fixed row");
        let aux = low_degree_aux(&base.rows[index], &fixed);
        let residues = evaluate_zk_x509_der_stark_base_residues_v1(
            &base.rows[index],
            &next,
            &aux,
            &fixed,
            &next_fixed,
        );
        assert!(
            residues.iter().all(|residue| *residue == F::ZERO),
            "row {index} phase {} -> {} has nonzero residues at {:?}; current {:?}; next {:?}",
            pack_bits_v1(&base.rows[index][BASE_PHASE_BITS..BASE_PHASE_BITS + 3]).0,
            pack_bits_v1(&next[BASE_PHASE_BITS..BASE_PHASE_BITS + 3]).0,
            residues
                .iter()
                .enumerate()
                .filter(|(_, residue)| **residue != F::ZERO)
                .take(16)
                .collect::<Vec<_>>(),
            base.rows[index]
                .iter()
                .enumerate()
                .filter(|(_, value)| **value != F::ZERO)
                .collect::<Vec<_>>(),
            next.iter()
                .enumerate()
                .filter(|(_, value)| **value != F::ZERO)
                .collect::<Vec<_>>()
        );
    }
    let first_inactive_parser_index = base.private_shape.parser_rows;
    let inactive = zk_x509_der_stark_aggregate_base_row_v1(&base, first_inactive_parser_index)
        .expect("inactive parser row");
    let next_inactive =
        zk_x509_der_stark_aggregate_base_row_v1(&base, first_inactive_parser_index + 1)
            .expect("next inactive parser row");
    let fixed = schedule
        .fixed_row(first_inactive_parser_index)
        .expect("first inactive parser fixed");
    let next_fixed = schedule
        .fixed_row(first_inactive_parser_index + 1)
        .expect("next inactive parser fixed");
    let aux = low_degree_aux(&inactive, &fixed);
    assert!(
        evaluate_zk_x509_der_stark_base_residues_v1(
            &inactive,
            &next_inactive,
            &aux,
            &fixed,
            &next_fixed,
        )
        .iter()
        .all(|residue| *residue == F::ZERO)
    );
}
#[test]
fn adversarial_activity_restart_inactive_payload_and_document_count_fail() {
    let integer = [0x02, 0x01, 0x01];
    let base = build_zk_x509_der_stark_base_v1(&[&integer]).expect("numeric DER base");
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("schedule");
    let mut dropped = base.clone();
    dropped.rows[1][BASE_ROW_ACTIVE] = F::ZERO;
    assert_eq!(
        validate_zk_x509_der_stark_base_trace_v1(&dropped),
        Err(ZkX509DerStarkErrorV1::Transition)
    );
    let inactive_index = base.private_shape.parser_rows;
    let inactive =
        zk_x509_der_stark_aggregate_base_row_v1(&base, inactive_index).expect("inactive row");
    let mut restarted = base.rows[1];
    restarted[BASE_FINAL_DOCUMENT] = inactive[BASE_FINAL_DOCUMENT];
    restarted[BASE_FINAL_DOCUMENT_BITS..BASE_FINAL_DOCUMENT_BITS + 5]
        .copy_from_slice(&inactive[BASE_FINAL_DOCUMENT_BITS..BASE_FINAL_DOCUMENT_BITS + 5]);
    restarted[BASE_FINAL_DOCUMENT_SLACK_BITS..BASE_FINAL_DOCUMENT_SLACK_BITS + 5].copy_from_slice(
        &inactive[BASE_FINAL_DOCUMENT_SLACK_BITS..BASE_FINAL_DOCUMENT_SLACK_BITS + 5],
    );
    let fixed = schedule.fixed_row(inactive_index).expect("inactive fixed");
    let next_fixed = schedule
        .fixed_row(inactive_index + 1)
        .expect("restart fixed");
    let aux = low_degree_aux(&inactive, &fixed);
    assert!(
        evaluate_zk_x509_der_stark_base_residues_v1(
            &inactive,
            &restarted,
            &aux,
            &fixed,
            &next_fixed,
        )
        .iter()
        .any(|residue| *residue != F::ZERO),
        "an inactive parser prefix cannot restart"
    );
    let next_inactive = zk_x509_der_stark_aggregate_base_row_v1(&base, inactive_index + 1)
        .expect("next inactive row");
    let mut payload = inactive;
    payload[BASE_BYTE_VALUE] = F::ONE;
    let payload_aux = low_degree_aux(&payload, &fixed);
    assert!(
        evaluate_zk_x509_der_stark_base_residues_v1(
            &payload,
            &next_inactive,
            &payload_aux,
            &fixed,
            &next_fixed,
        )
        .iter()
        .any(|residue| *residue != F::ZERO),
        "inactive rows have no payload channel"
    );
    let mut wrong_count = inactive;
    wrong_count[BASE_FINAL_DOCUMENT_SLACK_BITS] =
        F::ONE.sub(wrong_count[BASE_FINAL_DOCUMENT_SLACK_BITS]);
    let wrong_count_aux = low_degree_aux(&wrong_count, &fixed);
    assert!(
        evaluate_zk_x509_der_stark_base_residues_v1(
            &wrong_count,
            &next_inactive,
            &wrong_count_aux,
            &fixed,
            &next_fixed,
        )
        .iter()
        .any(|residue| *residue != F::ZERO),
        "the privately committed document count is range- and carry-bound"
    );
}
#[test]
fn every_active_base_cell_is_algebraically_observed() {
    let nested = [
        0x30, 0x0a, 0x31, 0x04, 0x05, 0x00, 0x05, 0x00, 0x02, 0x02, 0x00, 0x80,
    ];
    let base = build_zk_x509_der_stark_base_v1(&[&nested]).expect("numeric DER base");
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("fixed schedule");
    for row_index in 0..base.rows.len() {
        for column in 0..ZK_X509_DER_STARK_BASE_WIDTH_V1 {
            // The lookup multiplicity is committed in the base trace and
            // observed only after byte challenges are sampled. Restored
            // parent-frame cells on constructed boundaries are likewise
            // bound by the post-commitment stack permutation.
            let phase = pack_bits_v1(&base.rows[row_index][BASE_PHASE_BITS..BASE_PHASE_BITS + 3]);
            let stack_pop_cell = phase == F(PHASE_BOUNDARY as u64)
                && base.rows[row_index][BASE_CONSTRUCTED] == F::ONE
                && (BASE_PAYLOAD..BASE_PAYLOAD + 8).contains(&column);
            if column == BASE_BYTE_LOOKUP_MULTIPLICITY || stack_pop_cell {
                continue;
            }
            let mut rows = base.rows.clone();
            rows[row_index][column] = rows[row_index][column].add(F(7));
            let changed_base = ZkX509DerStarkBaseV1 {
                private_shape: base.private_shape.clone(),
                rows,
            };
            let native_index = zk_x509_der_stark_compact_row_native_index_v1(
                &changed_base.private_shape,
                row_index,
            )
            .expect("native row");
            let next = zk_x509_der_stark_aggregate_base_row_v1(&changed_base, native_index + 1)
                .expect("next native row");
            let current_fixed = schedule.fixed_row(native_index).expect("current fixed");
            let next_fixed = schedule.fixed_row(native_index + 1).expect("next fixed");
            let current_residues =
                match try_low_degree_aux(&changed_base.rows[row_index], &current_fixed) {
                    Ok(current_aux) => evaluate_zk_x509_der_stark_base_residues_v1(
                        &changed_base.rows[row_index],
                        &next,
                        &current_aux,
                        &current_fixed,
                        &next_fixed,
                    ),
                    Err(_) => vec![F::ONE],
                };
            let family_first =
                row_index == 0 || row_index == changed_base.private_shape.parser_rows;
            let previous_residues = if family_first {
                Vec::new()
            } else {
                let previous_native_index = native_index - 1;
                let previous_compact_index = row_index - 1;
                let previous_fixed = schedule
                    .fixed_row(previous_native_index)
                    .expect("previous fixed");
                let previous_aux =
                    low_degree_aux(&changed_base.rows[previous_compact_index], &previous_fixed);
                evaluate_zk_x509_der_stark_base_residues_v1(
                    &changed_base.rows[previous_compact_index],
                    &changed_base.rows[row_index],
                    &previous_aux,
                    &previous_fixed,
                    &current_fixed,
                )
            };
            assert!(
                current_residues
                    .iter()
                    .chain(&previous_residues)
                    .any(|residue| *residue != F::ZERO),
                "row {row_index} column {column} is not observed"
            );
        }
    }
}
#[test]
fn complete_numeric_trace_closes_stack_set_document_and_byte_buses() {
    let nested = [
        0x30, 0x0a, 0x31, 0x04, 0x05, 0x00, 0x05, 0x00, 0x02, 0x02, 0x00, 0x80,
    ];
    let challenges = challenges();
    let base = build_zk_x509_der_stark_base_v1(&[&nested]).expect("base");
    let trace = build_zk_x509_der_stark_trace_v1(base, challenges).expect("complete DER trace");
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("fixed schedule");
    let public = derive_zk_x509_der_stark_public_terminals_v1(&ZkX509DerStarkShapeV1, &challenges)
        .expect("public terminal");
    let private_document_product = derive_zk_x509_der_stark_private_document_product_v1(
        &trace.base.private_shape,
        &challenges,
    )
    .expect("private document product");
    let terminals = zk_x509_der_stark_terminals_v1(&trace).expect("terminals");
    let terminal_claims = zk_x509_der_stark_terminal_claims_v1(&trace).expect("terminal claims");
    assert_eq!(terminals.stack_push, terminals.stack_pop);
    assert_eq!(terminals.document, private_document_product);
    assert_eq!(terminals.pair_producer, terminals.pair_consumer);
    assert_eq!(terminals.byte_table_sum, terminals.byte_query_sum);
    assert_eq!(
        terminals.byte_table_zero_count,
        terminals.byte_query_zero_count
    );
    assert_ne!(terminals.node, [F::ONE; ZK_X509_DER_STARK_BUS_LANES_V1]);
    let comparator_end =
        ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 + trace.base.private_shape.comparator_rows;
    let mut indices: Vec<_> = (0..=trace.base.private_shape.parser_rows)
        .chain(ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1..=comparator_end)
        .collect();
    indices.extend([
        ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 - 1,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1 - 1,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        ZK_X509_DER_STARK_TRACE_SIZE_V1 - 2,
        ZK_X509_DER_STARK_TRACE_SIZE_V1 - 1,
    ]);
    indices.sort_unstable();
    indices.dedup();
    let mut reusable_residues = Vec::with_capacity(ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1);
    let reusable_allocation = reusable_residues.as_ptr();
    for index in indices {
        let next_index = (index + 1) % ZK_X509_DER_STARK_TRACE_SIZE_V1;
        let current =
            zk_x509_der_stark_aggregate_base_row_v1(&trace.base, index).expect("base row");
        let next =
            zk_x509_der_stark_aggregate_base_row_v1(&trace.base, next_index).expect("next base");
        let current_aux = zk_x509_der_stark_aggregate_aux_row_v1(&trace, index).expect("aux row");
        let next_aux =
            zk_x509_der_stark_aggregate_aux_row_v1(&trace, next_index).expect("next aux");
        let fixed = schedule.fixed_row(index).expect("fixed");
        let next_fixed = schedule.fixed_row(next_index).expect("next fixed");
        let residues = evaluate_zk_x509_der_stark_residues_v1(
            &current,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            &next_fixed,
            challenges,
            public,
            terminal_claims,
        )
        .expect("numeric residues");
        evaluate_zk_x509_der_stark_residues_into_v1(
            &current,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            &next_fixed,
            challenges,
            public,
            terminal_claims,
            &mut reusable_residues,
        )
        .expect("reused numeric residues");
        assert_eq!(reusable_residues, residues);
        assert_eq!(
            reusable_residues.as_ptr(),
            reusable_allocation,
            "streaming evaluator must reuse its preallocated residue buffer"
        );
        assert!(
            residues.iter().all(|residue| *residue == F::ZERO),
            "aggregate row {index} has nonzero residues at {:?}",
            residues
                .iter()
                .enumerate()
                .filter(|(_, residue)| **residue != F::ZERO)
                .take(16)
                .collect::<Vec<_>>()
        );
    }
}
#[test]
fn native_column_streaming_is_an_exact_transpose_at_all_boundaries() {
    let ordered_set = [0x31, 0x04, 0x05, 0x00, 0x05, 0x00];
    let challenges = challenges();
    let base = build_zk_x509_der_stark_base_v1(&[&ordered_set]).expect("base");
    let trace = build_zk_x509_der_stark_trace_v1(base, challenges).expect("complete DER trace");
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("fixed schedule");
    let comparator_end =
        ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 + trace.base.private_shape.comparator_rows;
    let mut sample_rows = vec![
        0,
        trace.base.private_shape.parser_rows - 1,
        trace.base.private_shape.parser_rows,
        ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 - 1,
        ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1,
        comparator_end - 1,
        comparator_end,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        ZK_X509_DER_STARK_TRACE_SIZE_V1 - 1,
    ];
    sample_rows.sort_unstable();
    sample_rows.dedup();
    for column_index in 0..ZK_X509_DER_STARK_BASE_WIDTH_V1 {
        let column = build_zk_x509_der_stark_native_base_column_v1(&trace.base, column_index)
            .expect("base column");
        assert_eq!(column.len(), ZK_X509_DER_STARK_TRACE_SIZE_V1);
        for row in sample_rows.iter().copied() {
            assert_eq!(
                column[row],
                zk_x509_der_stark_native_base_cell_v1(&trace.base, row, column_index)
                    .expect("base cell")
            );
        }
    }
    for column_index in 0..ZK_X509_DER_STARK_AUX_WIDTH_V1 {
        let column =
            build_zk_x509_der_stark_native_aux_column_v1(&trace, column_index).expect("aux column");
        assert_eq!(column.len(), ZK_X509_DER_STARK_TRACE_SIZE_V1);
        for row in sample_rows.iter().copied() {
            assert_eq!(
                column[row],
                zk_x509_der_stark_native_aux_cell_v1(&trace, row, column_index).expect("aux cell")
            );
        }
    }
    for column_index in 0..ZK_X509_DER_STARK_FIXED_WIDTH_V1 {
        let column = build_zk_x509_der_stark_native_fixed_column_v1(&schedule, column_index)
            .expect("fixed column");
        assert_eq!(column.len(), ZK_X509_DER_STARK_TRACE_SIZE_V1);
        for row in sample_rows.iter().copied() {
            assert_eq!(
                column[row],
                zk_x509_der_stark_native_fixed_cell_v1(&schedule, row, column_index)
                    .expect("fixed cell")
            );
        }
    }
    assert!(
        build_zk_x509_der_stark_native_base_column_v1(&trace.base, ZK_X509_DER_STARK_BASE_WIDTH_V1)
            .is_err()
    );
    assert!(
        build_zk_x509_der_stark_native_aux_column_v1(&trace, ZK_X509_DER_STARK_AUX_WIDTH_V1)
            .is_err()
    );
    assert!(
        build_zk_x509_der_stark_native_fixed_column_v1(&schedule, ZK_X509_DER_STARK_FIXED_WIDTH_V1)
            .is_err()
    );
}
#[test]
fn every_auxiliary_cell_and_post_commitment_base_cell_is_observed() {
    let nested = [
        0x30, 0x0a, 0x31, 0x04, 0x05, 0x00, 0x05, 0x00, 0x02, 0x02, 0x00, 0x80,
    ];
    let challenges = challenges();
    let base = build_zk_x509_der_stark_base_v1(&[&nested]).expect("base");
    let trace = build_zk_x509_der_stark_trace_v1(base, challenges).expect("complete DER trace");
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("fixed schedule");
    let public = derive_zk_x509_der_stark_public_terminals_v1(&ZkX509DerStarkShapeV1, &challenges)
        .expect("public");
    let terminal_claims = zk_x509_der_stark_terminal_claims_v1(&trace).expect("terminal claims");
    let fixed = schedule.fixed_row(0).expect("fixed");
    let next_fixed = schedule.fixed_row(1).expect("next fixed");
    let next = trace.base.rows[1];
    let next_aux = trace.aux_rows[1];
    for column in 0..ZK_X509_DER_STARK_AUX_WIDTH_V1 {
        let mut changed = trace.aux_rows[0];
        changed[column] = changed[column].add(F(7));
        let residues = evaluate_zk_x509_der_stark_residues_v1(
            &trace.base.rows[0],
            &next,
            &changed,
            &next_aux,
            &fixed,
            &next_fixed,
            challenges,
            public,
            terminal_claims,
        )
        .expect("numeric residues");
        assert!(
            residues.iter().any(|residue| *residue != F::ZERO),
            "auxiliary column {column} is not observed"
        );
    }
    let byte_row = trace
        .base
        .rows
        .iter()
        .position(|row| row[BASE_BYTE_LOOKUP_MULTIPLICITY] != F::ZERO)
        .expect("queried byte row");
    let mut changed = trace.base.rows[byte_row];
    changed[BASE_BYTE_LOOKUP_MULTIPLICITY] = changed[BASE_BYTE_LOOKUP_MULTIPLICITY].add(F::ONE);
    let next_index = byte_row + 1;
    let fixed = schedule.fixed_row(byte_row).expect("fixed");
    let next_fixed = schedule.fixed_row(next_index).expect("next fixed");
    let residues = evaluate_zk_x509_der_stark_residues_v1(
        &changed,
        &trace.base.rows[next_index],
        &trace.aux_rows[byte_row],
        &trace.aux_rows[next_index],
        &fixed,
        &next_fixed,
        challenges,
        public,
        terminal_claims,
    )
    .expect("numeric residues");
    assert!(residues.iter().any(|residue| *residue != F::ZERO));
    let stack_pop_row = trace
        .base
        .rows
        .iter()
        .position(|row| {
            pack_bits_v1(&row[BASE_PHASE_BITS..BASE_PHASE_BITS + 3]) == F(PHASE_BOUNDARY as u64)
                && row[BASE_CONSTRUCTED] == F::ONE
                && pack_bits_v1(&row[BASE_DEPTH_BITS..BASE_DEPTH_BITS + 5]) != F::ONE
        })
        .expect("nested stack pop");
    let mut changed = trace.base.rows[stack_pop_row];
    changed[BASE_PAYLOAD + 5] = changed[BASE_PAYLOAD + 5].add(F::ONE);
    let next_index = stack_pop_row + 1;
    let fixed = schedule.fixed_row(stack_pop_row).expect("fixed");
    let next_fixed = schedule.fixed_row(next_index).expect("next fixed");
    let residues = evaluate_zk_x509_der_stark_residues_v1(
        &changed,
        &trace.base.rows[next_index],
        &trace.aux_rows[stack_pop_row],
        &trace.aux_rows[next_index],
        &fixed,
        &next_fixed,
        challenges,
        public,
        terminal_claims,
    )
    .expect("numeric residues");
    assert!(residues.iter().any(|residue| *residue != F::ZERO));
}
#[test]
fn adversarial_bus_challenge_shape_and_terminal_mutations_fail_closed() {
    let nested = [
        0x30, 0x0a, 0x31, 0x04, 0x05, 0x00, 0x05, 0x00, 0x02, 0x02, 0x00, 0x80,
    ];
    let canonical_challenges = challenges();
    let canonical_base = build_zk_x509_der_stark_base_v1(&[&nested]).expect("canonical base");
    let mut invalid_challenges = canonical_challenges;
    invalid_challenges.tuple[0][0] = F::ZERO;
    assert!(build_zk_x509_der_stark_trace_v1(canonical_base.clone(), invalid_challenges).is_err());
    invalid_challenges = canonical_challenges;
    invalid_challenges.tuple[1] = invalid_challenges.tuple[0];
    assert!(build_zk_x509_der_stark_trace_v1(canonical_base.clone(), invalid_challenges).is_err());
    invalid_challenges = canonical_challenges;
    invalid_challenges.byte_lookup[2] = invalid_challenges.byte_lookup[1];
    assert!(build_zk_x509_der_stark_trace_v1(canonical_base.clone(), invalid_challenges).is_err());
    let queried_byte_row = canonical_base
        .rows
        .iter()
        .position(|row| row[BASE_BYTE_LOOKUP_MULTIPLICITY] != F::ZERO)
        .expect("SET lookup byte");
    let queried_byte_tuple = byte_tuple_v1(
        canonical_base.rows[queried_byte_row][BASE_DOCUMENT],
        canonical_base.rows[queried_byte_row][BASE_OFFSET],
        canonical_base.rows[queried_byte_row][BASE_BYTE_VALUE],
    );
    invalid_challenges = canonical_challenges;
    invalid_challenges.byte_lookup[0] = F::ZERO.sub(compress_tuple_v1(
        &queried_byte_tuple,
        invalid_challenges.tuple[0],
    ));
    assert_ne!(invalid_challenges.byte_lookup[0], F::ZERO);
    assert!(invalid_challenges.validate().is_ok());
    let collision_trace =
        build_zk_x509_der_stark_trace_v1(canonical_base.clone(), invalid_challenges)
            .expect("zero denominator is a complete lookup case");
    assert_lookup_inverse_witnesses(&collision_trace, invalid_challenges);
    let collision_terminals =
        zk_x509_der_stark_terminals_v1(&collision_trace).expect("collision terminals");
    assert_ne!(
        collision_terminals.byte_table_zero_count[0],
        F::ZERO,
        "the forced collision must exercise the zero-count path"
    );
    assert_eq!(
        collision_terminals.byte_table_zero_count,
        collision_terminals.byte_query_zero_count
    );
    let collision_schedule = compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1)
        .expect("collision schedule");
    let collision_index = ZK_X509_DER_STARK_TRACE_SIZE_V1 - 1;
    let collision_current =
        zk_x509_der_stark_aggregate_base_row_v1(&collision_trace.base, collision_index)
            .expect("collision base");
    let collision_next = zk_x509_der_stark_aggregate_base_row_v1(&collision_trace.base, 0)
        .expect("collision next base");
    let mut collision_aux =
        zk_x509_der_stark_aggregate_aux_row_v1(&collision_trace, collision_index)
            .expect("collision aux");
    let collision_next_aux =
        zk_x509_der_stark_aggregate_aux_row_v1(&collision_trace, 0).expect("collision next aux");
    collision_aux[AUX_BYTE_TABLE_ZERO_COUNT_AFTER] =
        collision_aux[AUX_BYTE_TABLE_ZERO_COUNT_AFTER].add(F::ONE);
    let collision_residues = evaluate_zk_x509_der_stark_residues_v1(
        &collision_current,
        &collision_next,
        &collision_aux,
        &collision_next_aux,
        &collision_schedule
            .fixed_row(collision_index)
            .expect("collision fixed"),
        &collision_schedule
            .fixed_row(0)
            .expect("collision next fixed"),
        invalid_challenges,
        ZkX509DerStarkPublicTerminalsV1,
        zk_x509_der_stark_terminal_claims_v1(&collision_trace).expect("collision terminal claims"),
    )
    .expect("collision residues");
    assert!(
        collision_residues.iter().any(|residue| *residue != F::ZERO),
        "a forged singular-factor count must fail"
    );
    let mut changed = canonical_base.clone();
    let stack_pop = changed
        .rows
        .iter()
        .position(|row| {
            pack_bits_v1(&row[BASE_PHASE_BITS..BASE_PHASE_BITS + 3]) == F(PHASE_BOUNDARY as u64)
                && row[BASE_CONSTRUCTED] == F::ONE
                && pack_bits_v1(&row[BASE_DEPTH_BITS..BASE_DEPTH_BITS + 5]) != F::ONE
        })
        .expect("nested pop");
    changed.rows[stack_pop][BASE_PAYLOAD + 5] =
        changed.rows[stack_pop][BASE_PAYLOAD + 5].add(F::ONE);
    assert!(
        build_zk_x509_der_stark_trace_v1(changed, canonical_challenges).is_err(),
        "wrong restored parent frame must break the stack permutation"
    );
    changed = canonical_base.clone();
    let queried_byte = changed
        .rows
        .iter()
        .position(|row| row[BASE_BYTE_LOOKUP_MULTIPLICITY] != F::ZERO)
        .expect("queried byte");
    changed.rows[queried_byte][BASE_BYTE_LOOKUP_MULTIPLICITY] =
        changed.rows[queried_byte][BASE_BYTE_LOOKUP_MULTIPLICITY].add(F::ONE);
    assert!(
        build_zk_x509_der_stark_trace_v1(changed, canonical_challenges).is_err(),
        "wrong table multiplicity must break the byte lookup"
    );
    changed = canonical_base.clone();
    changed.private_shape.document_lengths[0] += 1;
    assert!(
        build_zk_x509_der_stark_trace_v1(changed, canonical_challenges).is_err(),
        "private document lengths must bind the document product"
    );
    let trace = build_zk_x509_der_stark_trace_v1(canonical_base.clone(), canonical_challenges)
        .expect("canonical trace");
    assert_lookup_inverse_witnesses(&trace, canonical_challenges);
    let schedule =
        compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1).expect("schedule");
    let final_index = ZK_X509_DER_STARK_TRACE_SIZE_V1 - 1;
    let current = zk_x509_der_stark_aggregate_base_row_v1(&trace.base, final_index).expect("base");
    let next = zk_x509_der_stark_aggregate_base_row_v1(&trace.base, 0).expect("next");
    let current_aux = zk_x509_der_stark_aggregate_aux_row_v1(&trace, final_index).expect("aux");
    let next_aux = zk_x509_der_stark_aggregate_aux_row_v1(&trace, 0).expect("next aux");
    let fixed = schedule.fixed_row(final_index).expect("fixed");
    let next_fixed = schedule.fixed_row(0).expect("next fixed");
    let public =
        derive_zk_x509_der_stark_public_terminals_v1(&ZkX509DerStarkShapeV1, &canonical_challenges)
            .expect("public");
    let mut terminal_claims =
        zk_x509_der_stark_terminal_claims_v1(&trace).expect("terminal claims");
    terminal_claims.input_byte[1] = terminal_claims.input_byte[1].add(F::ONE);
    let residues = evaluate_zk_x509_der_stark_residues_v1(
        &current,
        &next,
        &current_aux,
        &next_aux,
        &fixed,
        &next_fixed,
        canonical_challenges,
        public,
        terminal_claims,
    )
    .expect("residues");
    assert!(residues.iter().any(|residue| *residue != F::ZERO));
}
#[test]
fn complete_evaluator_has_witness_independent_residue_shape() {
    let challenges = challenges();
    let public = ZkX509DerStarkPublicTerminalsV1;
    let terminal_claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F(31), F(37), F(41), F(43)],
        node: [F(47), F(53), F(59), F(61)],
    };
    let mut state = 0x8b8b_8b8b_1234_5678_u64;
    let mut sample = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        F(state % 1_000_003)
    };
    let mut expected = None;
    for _ in 0..256 {
        let current = core::array::from_fn(|_| sample());
        let next = core::array::from_fn(|_| sample());
        let current_aux = core::array::from_fn(|_| sample());
        let next_aux = core::array::from_fn(|_| sample());
        let fixed = core::array::from_fn(|_| sample());
        let next_fixed = core::array::from_fn(|_| sample());
        let residues = evaluate_zk_x509_der_stark_residues_v1(
            &current,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            &next_fixed,
            challenges,
            public,
            terminal_claims,
        )
        .expect("total numeric evaluator");
        match expected {
            Some(expected) => assert_eq!(residues.len(), expected),
            None => expected = Some(residues.len()),
        }
    }
    assert_eq!(expected, Some(ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1));
}
fn affine_row<const N: usize>(seed: u64, role: u64, point: F) -> [F; N] {
    core::array::from_fn(|index| {
        let index = u64::try_from(index).expect("column index fits u64");
        let intercept = F(seed
            .wrapping_mul(1_000_003)
            .wrapping_add(role.wrapping_mul(65_537))
            .wrapping_add(index.wrapping_mul(257))
            % (GOLDILOCKS_MODULUS_V1 - 1)
            + 1);
        let slope = F(seed
            .wrapping_mul(524_287)
            .wrapping_add(role.wrapping_mul(8_191))
            .wrapping_add(index.wrapping_mul(131))
            % (GOLDILOCKS_MODULUS_V1 - 1)
            + 1);
        intercept.add(slope.mul(point))
    })
}
fn finite_difference_degrees(samples: &[Vec<F>]) -> Vec<usize> {
    let residue_count = samples.first().map_or(0, Vec::len);
    assert!(samples.iter().all(|sample| sample.len() == residue_count));
    (0..residue_count)
        .map(|residue| {
            let mut differences = samples
                .iter()
                .map(|sample| sample[residue])
                .collect::<Vec<_>>();
            let mut degree = 0;
            for order in 0..samples.len() {
                if differences.iter().any(|value| *value != F::ZERO) {
                    degree = order;
                }
                if differences.len() == 1 {
                    break;
                }
                differences = differences
                    .windows(2)
                    .map(|pair| pair[1].sub(pair[0]))
                    .collect();
            }
            degree
        })
        .collect()
}
#[test]
fn independently_interpolated_complete_air_degree_matches_registration() {
    const SAMPLE_COUNT: usize = 21;
    let challenges = challenges();
    let public = ZkX509DerStarkPublicTerminalsV1;
    let terminal_claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F(31), F(37), F(41), F(43)],
        node: [F(47), F(53), F(59), F(61)],
    };
    let mut maximum_degrees = vec![0_usize; ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1];
    // Independent affine directions make cancellation of a nonzero
    // leading homogeneous term fail closed across the complete evaluator,
    // while the final assertion separately proves that degree seven is
    // attained rather than merely budgeted.
    for seed in [3_u64, 5, 11, 17, 29, 43, 71, 101, 149, 211, 283, 367] {
        let samples = (0..SAMPLE_COUNT)
            .map(|point| {
                let point = F(u64::try_from(point).expect("sample point"));
                evaluate_zk_x509_der_stark_residues_v1(
                    &affine_row(seed, 1, point),
                    &affine_row(seed, 2, point),
                    &affine_row(seed, 3, point),
                    &affine_row(seed, 4, point),
                    &affine_row(seed, 5, point),
                    &affine_row(seed, 6, point),
                    challenges,
                    public,
                    terminal_claims,
                )
                .expect("total numeric evaluator")
            })
            .collect::<Vec<_>>();
        for (maximum, measured) in maximum_degrees
            .iter_mut()
            .zip(finite_difference_degrees(&samples))
        {
            *maximum = (*maximum).max(measured);
        }
    }
    let offenders = maximum_degrees
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, degree)| *degree > usize::from(ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1))
        .collect::<Vec<_>>();
    assert!(offenders.is_empty(), "high-degree residues: {offenders:?}");
    assert!(
        maximum_degrees
            .iter()
            .any(|degree| *degree == usize::from(ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1)),
        "registered degree must be attained"
    );
}
include!("der_stark_descriptor_tests.rs");

#[test]
fn rejected_der_binding_and_trace_drop_clear_owned_field_tables() {
    use super::super::private_table::inspection::observe_v1;

    let base = ZkX509DerStarkBaseV1 {
        private_shape: private_shape(),
        rows: vec![[F(17); ZK_X509_DER_STARK_BASE_WIDTH_V1]; 3],
    };
    let mut invalid_challenges = challenges();
    invalid_challenges.tuple[0][0] = F::ZERO;
    let (result, erasures) =
        observe_v1(|| build_zk_x509_der_stark_trace_v1(base, invalid_challenges));
    assert_eq!(result, Err(ZkX509DerStarkErrorV1::Challenge));
    assert!(erasures.iter().any(|erasure| {
        erasure.cells == 3 * ZK_X509_DER_STARK_BASE_WIDTH_V1
            && erasure.nonzero_before == erasure.cells
            && erasure.nonzero_after == 0
    }));
    let trace = ZkX509DerStarkTraceV1 {
        base: ZkX509DerStarkBaseV1 {
            private_shape: private_shape(),
            rows: vec![[F(19); ZK_X509_DER_STARK_BASE_WIDTH_V1]; 5],
        },
        aux_rows: vec![[F(23); ZK_X509_DER_STARK_AUX_WIDTH_V1]; 7],
    };
    assert_eq!(
        format!("{trace:?}"),
        "ZkX509DerStarkTraceV1 { <private material redacted> }"
    );
    let ((), erasures) = observe_v1(|| drop(trace));
    for cells in [
        5 * ZK_X509_DER_STARK_BASE_WIDTH_V1,
        7 * ZK_X509_DER_STARK_AUX_WIDTH_V1,
    ] {
        assert!(erasures.iter().any(|erasure| {
            erasure.cells == cells && erasure.nonzero_before == cells && erasure.nonzero_after == 0
        }));
    }
}
