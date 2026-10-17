// Lexically included by `zk_x509::stark::tests` to preserve the existing libtest paths.
fn decode_projection_fixture() -> ZkX509SegmentedStarkProofV1 {
    decode_zk_x509_segmented_stark_proof_v1(&projection_fixture().2, &projection_aggregate_layout())
        .expect("decode projection fixture")
}
fn assert_projection_rejected(proof: &ZkX509SegmentedStarkProofV1) {
    match encode_zk_x509_segmented_stark_proof_v1(proof, &projection_aggregate_layout()) {
        Ok(bytes) => assert!(
            verify_zk_x509_projection_segmented_stark_v1(&projection_fixture().0, &bytes).is_err(),
            "adversarial projection proof must reject"
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch) => {}
        Err(error) => panic!("unexpected adversarial projection encode failure: {error}"),
    }
}
#[derive(Debug)]
struct MaxValueRng;
impl RngCore for MaxValueRng {
    fn next_u32(&mut self) -> u32 {
        u32::MAX
    }
    fn next_u64(&mut self) -> u64 {
        u64::MAX
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        destination.fill(0xFF);
    }
}
#[test]
fn canonical_multiproof_matches_small_trees_and_rejects_every_frontier_mutation() {
    let leaves = (0_u8..16)
        .enumerate()
        .map(|(index, value)| {
            privacy_outer_digest_frame_v1(
                ZK_X509_DIGEST_CONTEXT_V1,
                b"iroha:privacy:zk-x509:test:multiproof-leaf:v1",
                b"leaf",
                0,
                u64::try_from(index).expect("test leaf index fits u64"),
                0,
                &[&[value]],
            )
            .expect("leaf")
        })
        .collect::<Vec<_>>();
    let tree = PrivacyOuterMerkleTreeV1::from_leaves(
        leaves.clone(),
        ZK_X509_DIGEST_CONTEXT_V1,
        b"iroha:privacy:zk-x509:test:multiproof-node:v1",
    )
    .expect("tree");
    for indices in [
        vec![0_usize],
        vec![1, 2, 7, 8, 15],
        (0_usize..16).collect::<Vec<_>>(),
    ] {
        let frontier = canonical_multiproof_frontier_v1(&tree, leaves.len(), &indices)
            .expect("canonical frontier");
        let opened = indices
            .iter()
            .copied()
            .map(|index| (index, leaves[index]))
            .collect::<BTreeMap<_, _>>();
        verify_canonical_multiproof_v1(
            b"iroha:privacy:zk-x509:test:multiproof-node:v1",
            &tree.root(),
            leaves.len(),
            &opened,
            &frontier,
        )
        .expect("valid multiproof");
        for position in 0..frontier.len() {
            let mut changed = frontier.clone();
            let mut words = changed[position].to_bytes();
            words[0] ^= 1;
            changed[position] = PrivacyOuterDigestV1::from_bytes(words);
            assert!(
                verify_canonical_multiproof_v1(
                    b"iroha:privacy:zk-x509:test:multiproof-node:v1",
                    &tree.root(),
                    leaves.len(),
                    &opened,
                    &changed,
                )
                .is_err(),
                "frontier hash {position} must be bound"
            );
        }
        if indices.len() == leaves.len() {
            assert!(frontier.is_empty());
        }
    }
    assert!(canonical_multiproof_frontier_v1(&tree, leaves.len(), &[2, 2]).is_err());
    assert!(canonical_multiproof_frontier_v1(&tree, leaves.len(), &[2, 1]).is_err());
    assert!(canonical_multiproof_frontier_v1(&tree, leaves.len(), &[16]).is_err());
}
#[test]
fn registered_degree_and_fri_capacity_boundaries_fail_closed() {
    let minimum_trace_size = 1_usize << MIN_TRACE_LOG2;
    let minimum_masked_degree = minimum_trace_size + MASK_DEGREE;
    let minimum_maximum_degree_quotient =
        usize::from(ZK_X509_MAX_CONSTRAINT_DEGREE_V1) * minimum_masked_degree - minimum_trace_size;
    let minimum_valid_lde_log2 = 14;
    let minimum_fri_rounds = minimum_valid_lde_log2 - TERMINAL_LOG2;
    let minimum_fri_degree = (TERMINAL_DEGREE_BOUND + 1) * (1_usize << minimum_fri_rounds) - 1;
    assert_eq!(
        checked_segment_degree_capacity_v1(
            MIN_TRACE_LOG2,
            minimum_valid_lde_log2,
            ZK_X509_MAX_CONSTRAINT_DEGREE_V1,
        )
        .expect("minimum secure maximum-degree domain"),
        (minimum_maximum_degree_quotient, minimum_fri_degree)
    );
    assert_eq!(minimum_maximum_degree_quotient, 12_801);
    assert_eq!(minimum_fri_degree, 2_303);
    assert!(
        checked_segment_degree_capacity_v1(
            MIN_TRACE_LOG2,
            minimum_valid_lde_log2 - 1,
            ZK_X509_MAX_CONSTRAINT_DEGREE_V1,
        )
        .is_err(),
        "the adjacent smaller LDE cannot hold the secure mask and quotient"
    );
    assert!(
        checked_segment_degree_capacity_v1(
            MIN_TRACE_LOG2,
            minimum_valid_lde_log2,
            ZK_X509_MAX_CONSTRAINT_DEGREE_V1 + 1,
        )
        .is_err()
    );
    assert!(checked_segment_degree_capacity_v1(MIN_TRACE_LOG2, minimum_valid_lde_log2, 1).is_err());
    assert!(
        checked_segment_degree_capacity_v1(
            MIN_TRACE_LOG2 - 1,
            minimum_valid_lde_log2,
            ZK_X509_MAX_CONSTRAINT_DEGREE_V1,
        )
        .is_err()
    );
    assert!(
        checked_segment_degree_capacity_v1(
            MIN_TRACE_LOG2,
            TERMINAL_LOG2 - 1,
            ZK_X509_MAX_CONSTRAINT_DEGREE_V1,
        )
        .is_err()
    );
    assert!(checked_segment_degree_capacity_v1(u8::MAX, u8::MAX, 4).is_err());
    let focused_io = SegmentLayoutV1::for_io(1).expect("minimum focused I/O layout");
    assert_eq!(focused_io.trace_log2, IO_MIN_SECURE_TRACE_LOG2_V1);
    assert_eq!(
        focused_io.lde_log2,
        IO_MIN_SECURE_TRACE_LOG2_V1 + BLOWUP_LOG2
    );
    assert_eq!(
        checked_segment_degree_capacity_v1(
            focused_io.trace_log2,
            focused_io.lde_log2,
            focused_io.constraint_degree,
        )
        .expect("focused I/O degree capacity"),
        (56_412, 18_431)
    );
    focused_io.validate().expect("valid focused I/O layout");
    let mut stale_io = focused_io;
    stale_io.trace_log2 -= 1;
    stale_io.lde_log2 -= 1;
    assert!(
        stale_io.validate().is_err(),
        "the smaller focused-I/O layout cannot carry the release mask"
    );
    assert!(
        checked_segment_degree_capacity_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            ZK_X509_SHA_BATCH_CONSTRAINT_DEGREE_V1,
        )
        .is_ok(),
        "the released log19 SHA registration requires the log22 MAIN domain"
    );
    assert!(
        checked_segment_degree_capacity_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1 - 1,
            ZK_X509_SHA_BATCH_CONSTRAINT_DEGREE_V1,
        )
        .is_err(),
        "the adjacent smaller SHA domain must fail closed"
    );
    assert!(
        checked_segment_degree_capacity_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1 + 1,
            ZK_X509_SHA_BATCH_CONSTRAINT_DEGREE_V1,
        )
        .is_err(),
        "unregistered domains larger than MAIN must fail closed"
    );
    let trace_size = ZK_X509_DER_STARK_TRACE_SIZE_V1;
    let expected_quotient = usize::from(ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1)
        * (trace_size + MASK_DEGREE)
        - trace_size;
    let expected_chunk_capacity = trace_size * 9 / 8 - 1;
    assert_eq!(
        checked_segment_degree_capacity_v1(
            ZK_X509_DER_STARK_TRACE_LOG2_V1,
            ZK_X509_DER_STARK_TRACE_LOG2_V1 + BLOWUP_LOG2,
            ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1,
        )
        .expect("DER degree capacity"),
        (expected_quotient, expected_chunk_capacity)
    );
    assert!(
        expected_quotient > expected_chunk_capacity,
        "the exact DER quotient must exercise multiple FRI chunks"
    );
    assert!(
        expected_quotient <= (expected_chunk_capacity + 1) * COMPOSITION_DEGREE_CHUNKS - 1,
        "all six authenticated chunks must cover the exact DER quotient"
    );
    let mut invalid = der_layout();
    invalid.constraint_degree = ZK_X509_MAX_CONSTRAINT_DEGREE_V1 + 1;
    assert!(invalid.validate().is_err());
    invalid = der_layout();
    invalid.trace_log2 = u8::MAX;
    invalid.lde_log2 = u8::MAX;
    assert!(invalid.validate().is_err());
    invalid = der_layout();
    invalid.lde_log2 = TERMINAL_LOG2 - 1;
    assert!(invalid.validate().is_err());
}
#[test]
fn interpolated_masked_degree_seven_quotient_attains_registered_bound() {
    const TRACE_LOG2: u8 = MIN_TRACE_LOG2;
    const TRACE_SIZE: usize = 1 << TRACE_LOG2;
    const TRACE_DEGREE: usize = TRACE_SIZE + MASK_DEGREE;
    let mut trace = vec![F::ZERO; TRACE_DEGREE + 1];
    trace[0] = F(7);
    trace[1] = F(11);
    trace[TRACE_DEGREE] = F::ONE;
    let multiply = |left: &[F], right: &[F]| {
        let mut product = vec![F::ZERO; left.len() + right.len() - 1];
        for (left_degree, left_coefficient) in left.iter().copied().enumerate() {
            for (right_degree, right_coefficient) in right.iter().copied().enumerate() {
                product[left_degree + right_degree] = product[left_degree + right_degree]
                    .add(left_coefficient.mul(right_coefficient));
            }
        }
        product
    };
    let mut constraint = trace.clone();
    for _ in 1..usize::from(ZK_X509_MAX_CONSTRAINT_DEGREE_V1) {
        constraint = multiply(&constraint, &trace);
    }
    // Subtract the exact remainder modulo X^N - 1 so this synthetic
    // degree-seven constraint vanishes on the native subgroup.
    let mut numerator = constraint.clone();
    let mut remainder = vec![F::ZERO; TRACE_SIZE];
    for (degree, coefficient) in constraint.iter().copied().enumerate() {
        remainder[degree % TRACE_SIZE] = remainder[degree % TRACE_SIZE].add(coefficient);
    }
    for (coefficient, remainder) in numerator.iter_mut().zip(remainder) {
        *coefficient = coefficient.sub(remainder);
    }
    let mut quotient = vec![F::ZERO; numerator.len() - TRACE_SIZE];
    for degree in (TRACE_SIZE..numerator.len()).rev() {
        let coefficient = numerator[degree];
        quotient[degree - TRACE_SIZE] = coefficient;
        numerator[degree] = numerator[degree].sub(coefficient);
        numerator[degree - TRACE_SIZE] = numerator[degree - TRACE_SIZE].add(coefficient);
    }
    assert!(numerator.iter().all(|coefficient| *coefficient == F::ZERO));
    let expected_degree = usize::from(ZK_X509_MAX_CONSTRAINT_DEGREE_V1) * TRACE_DEGREE - TRACE_SIZE;
    assert_eq!(
        quotient
            .iter()
            .rposition(|coefficient| *coefficient != F::ZERO),
        Some(expected_degree)
    );
    let interpolation_size = quotient.len().next_power_of_two();
    let interpolation_log2 =
        u8::try_from(interpolation_size.trailing_zeros()).expect("interpolation domain log");
    assert!(interpolation_size > expected_degree);
    quotient.resize(interpolation_size, F::ZERO);
    let interpolation_root =
        goldilocks_primitive_root_v1(interpolation_log2).expect("interpolation root");
    let mut evaluations = quotient.clone();
    crate::privacy_engines::transparent_stark::goldilocks_fft_v1(
        &mut evaluations,
        interpolation_root,
    )
    .expect("quotient evaluations");
    goldilocks_ifft_v1(&mut evaluations, interpolation_root).expect("quotient interpolation");
    let measured_degree = evaluations
        .iter()
        .rposition(|coefficient| *coefficient != F::ZERO)
        .expect("nonzero quotient");
    let (registered_quotient_degree, fri_input_degree) =
        checked_segment_degree_capacity_v1(TRACE_LOG2, 16, ZK_X509_MAX_CONSTRAINT_DEGREE_V1)
            .expect("degree capacity");
    assert_eq!(measured_degree, expected_degree);
    assert_eq!(measured_degree, registered_quotient_degree);
    assert!(
        measured_degree > fri_input_degree,
        "the exact quotient must exercise more than one composition chunk"
    );
    assert!(
        measured_degree <= (fri_input_degree + 1) * COMPOSITION_DEGREE_CHUNKS - 1,
        "the registered chunks must cover the exact quotient bound"
    );
}
#[test]
fn every_segment_constructor_binds_the_correct_degree_capacity_profile() {
    let main_segments = [
        SegmentLayoutV1::for_io(1).expect("focused I/O"),
        SegmentLayoutV1::for_full_io().expect("full I/O"),
        SegmentLayoutV1::for_der(1).expect("strict DER"),
        SegmentLayoutV1::for_rfc5280(1).expect("RFC 5280"),
        SegmentLayoutV1::for_projection().expect("projection"),
        SegmentLayoutV1::for_sha_segment(0, ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[0])
            .expect("SHA segment"),
    ];
    for segment in main_segments {
        segment.validate().expect("valid MAIN segment");
        assert!(
            checked_segment_degree_capacity_v1(
                segment.trace_log2,
                segment.main_capacity_lde_log2_v1(),
                segment.constraint_degree,
            )
            .is_ok()
        );
    }
    for role in [
        P256EcdsaRoleV1::CertificateOrCrl,
        P256EcdsaRoleV1::WalletOwnership,
    ] {
        let segments = canonical_p256_segment_layouts_v1(role).expect("P-256 segments");
        assert!(
            segments
                .iter()
                .any(|segment| segment.trace_log2 == ZK_X509_MAX_NATIVE_TRACE_LOG2_V1),
            "each P-256 role must carry the log19 host that justifies log22 capacity"
        );
        for segment in segments {
            segment.validate().expect("valid P-256 segment");
            assert_eq!(
                segment.main_capacity_lde_log2_v1(),
                ZK_X509_MAIN_COMMON_LDE_LOG2_V1
            );
            assert!(
                checked_segment_degree_capacity_v1(
                    segment.trace_log2,
                    segment.main_capacity_lde_log2_v1(),
                    segment.constraint_degree,
                )
                .is_ok()
            );
        }
    }
    let compact_ca = SegmentLayoutV1::for_ca_accumulator().expect("compact CA");
    compact_ca.validate().expect("valid compact-CA segment");
    assert_eq!(compact_ca.lde_log2, ZK_X509_CA_FRI_LDE_LOG2_V1);
    assert!(
        checked_compact_ca_degree_capacity_v1(
            compact_ca.trace_log2,
            compact_ca.lde_log2,
            compact_ca.constraint_degree,
        )
        .is_ok()
    );
    let ca_bound = checked_compact_ca_degree_capacity_v1(
        compact_ca.trace_log2,
        compact_ca.lde_log2,
        compact_ca.constraint_degree,
    )
    .unwrap();
    let main_bound = checked_segment_degree_capacity_v1(
        compact_ca.trace_log2,
        compact_ca.lde_log2,
        compact_ca.constraint_degree,
    )
    .unwrap();
    assert_ne!(
        ca_bound, main_bound,
        "CA must use its own mask and fixed-selector terms"
    );
    let wrong_main_padding = SegmentLayoutV1 {
        lde_log2: compact_ca.trace_log2 + BLOWUP_LOG2,
        ..compact_ca
    };
    assert!(
        wrong_main_padding.validate().is_err(),
        "the compact-CA constructor must never silently inherit MAIN parameters"
    );
}
#[test]
fn verifier_owned_segment_registration_is_exact_and_full_profile_stays_closed() {
    let layout = fixture_aggregate_layout();
    layout.validate().expect("canonical registered layout");
    assert!(layout.validate_full_profile_registration().is_err());
    assert_eq!(layout.trace_groups.len(), 1);
    assert_eq!(layout.trace_groups[0].column_chunks, 1);
    assert_eq!(layout.trace_groups[0].base_width, IO_BASE_WIDTH);
    assert_eq!(layout.trace_groups[0].aux_width, IO_AUX_WIDTH);
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::ByteMemory, 0)
        .expect("byte-memory registration");
    assert_eq!(registration.trace_group, 0);
    assert_eq!(registration.base_start, 0);
    assert_eq!(registration.base_end().expect("base end"), IO_BASE_WIDTH);
    assert_eq!(registration.aux_start, 0);
    assert_eq!(registration.aux_end().expect("aux end"), IO_AUX_WIDTH);
    assert_eq!(registration.segment.fixed_width, IO_FIXED_WIDTH);
    assert_eq!(registration.segment.constraint_count, IO_CONSTRAINT_COUNT);
    assert_eq!(registration.segment.constraint_degree, IO_CONSTRAINT_DEGREE);
    let mut mutations = Vec::new();
    let mut changed = layout.clone();
    changed.registered_segments.clear();
    mutations.push(changed);
    changed = layout.clone();
    changed
        .registered_segments
        .push(changed.registered_segments[0]);
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.adapter = SegmentAdapterIdV1::StrictDer;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.instance = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.active_rows = 0;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.base_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.aux_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.fixed_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.constraint_count -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.constraint_degree -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].trace_group = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].base_start = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].aux_start = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].column_chunks += 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.trace_groups[0].base_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.trace_groups[0].aux_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.trace_groups[0].column_chunks += 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.common_lde_log2 -= 1;
    mutations.push(changed);
    for (index, mutation) in mutations.iter().enumerate() {
        assert!(
            mutation.validate().is_err(),
            "registration mutation {index} must fail closed"
        );
    }
}
#[test]
fn full_main_complete_relation_proof_budget_fits_before_witness_or_entropy() {
    assert_eq!(validate_zk_x509_main_proof_budget_v1(), Ok(()));
    assert_eq!(136 * 5811 * 8, 6_322_368);
    assert!(136 * 5811 * 8 < super::super::profile::ZK_X509_MAX_PROOF_BYTES_V1 as usize);
}

/// Count the current direct-opening owners without trusting width-only sums.
/// This is a sizing audit, not a replacement proof or an admission path.
fn full_main_opening_partition_for_test_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<([usize; 3], [usize; 3]), &'static str> {
    const P256: usize = 0;
    const SHA: usize = 1;
    const RESIDUAL: usize = 2;
    let mut owners = layout
        .trace_groups
        .iter()
        .map(|group| (vec![None; group.base_width], vec![None; group.aux_width]))
        .collect::<Vec<(Vec<Option<usize>>, Vec<Option<usize>>)>>();
    let mut registrations = [0_usize; 3];
    let mut columns = [0_usize; 3];
    for registration in &layout.registered_segments {
        let family = match registration.segment.adapter {
            SegmentAdapterIdV1::P256Arithmetic
            | SegmentAdapterIdV1::P256Reduction
            | SegmentAdapterIdV1::P256LowS
            | SegmentAdapterIdV1::P256Window
            | SegmentAdapterIdV1::P256ValueBus => P256,
            SegmentAdapterIdV1::Sha256CallBus => SHA,
            SegmentAdapterIdV1::ByteMemory
            | SegmentAdapterIdV1::StrictDer
            | SegmentAdapterIdV1::Rfc5280
            | SegmentAdapterIdV1::Projection
            // The five log-8 scalar buses remain in MAIN. The proposed
            // receipt replaces the log-5/16/19 P-256 openings only, and
            // must still prove its links to these retained bus terminals.
            | SegmentAdapterIdV1::P256ScalarBitBus => RESIDUAL,
            SegmentAdapterIdV1::CaAccumulator => return Err("CA is not a MAIN registration"),
        };
        registrations[family] += 1;
        let group = owners
            .get_mut(registration.trace_group)
            .ok_or("registration has no trace group")?;
        for (slots, start, width) in [
            (
                &mut group.0,
                registration.base_start,
                registration.segment.base_width,
            ),
            (
                &mut group.1,
                registration.aux_start,
                registration.segment.aux_width,
            ),
        ] {
            let end = start.checked_add(width).ok_or("column range overflow")?;
            for owner in slots
                .get_mut(start..end)
                .ok_or("column outside its trace group")?
            {
                if owner.replace(family).is_some() {
                    return Err("overlapping trace column");
                }
                columns[family] += 1;
            }
        }
    }
    if owners
        .iter()
        .any(|(base, aux)| base.iter().chain(aux).any(Option::is_none))
    {
        return Err("unowned trace column");
    }
    Ok((registrations, columns))
}

#[test]
fn full_main_replacement_partition_covers_every_registration_and_opening() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    layout
        .validate_exact_full_profile_registration_v1()
        .expect("verifier-owned registration");
    assert_eq!(layout.registered_segments.len(), 49);
    let (registrations, columns) =
        full_main_opening_partition_for_test_v1(&layout).expect("complete MAIN partition");
    assert_eq!(registrations, [36, 4, 9]);
    assert_eq!(columns, [4_000, 668, 1_143]);
    let retained_scalar_bus_columns = layout
        .registered_segments
        .iter()
        .filter(|registration| registration.segment.adapter == SegmentAdapterIdV1::P256ScalarBitBus)
        .map(|registration| registration.segment.base_width + registration.segment.aux_width)
        .sum::<usize>();
    assert_eq!(retained_scalar_bus_columns, 190);
    assert_eq!(
        columns.iter().sum::<usize>(),
        layout
            .trace_groups
            .iter()
            .map(|group| group.base_width + group.aux_width)
            .sum::<usize>()
    );
    assert_eq!(columns.iter().sum::<usize>(), 5_811);

    let shared = layout.as_shared().unwrap();
    assert_eq!(shared.trace_commitment_count_v1(), 1);
    assert_eq!(
        aggregate::maximum_encoded_proof_with_deep_bytes_v1(AGGREGATE_PARAMETERS_V1, &shared)
            .unwrap(),
        7_908_768
    );
    assert_eq!(
        aggregate::exact_deep_opening_bytes_v1(AGGREGATE_PARAMETERS_V1, &shared).unwrap(),
        372_096
    );
    assert_eq!(
        usize::from(ZK_X509_FRI_QUERY_COUNT_V1) * columns.iter().sum::<usize>() * 8,
        6_322_368
    );
}

#[test]
fn full_main_replacement_partition_rejects_omitted_and_overlapping_columns() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let mut omitted = layout.clone();
    omitted.registered_segments.pop();
    assert_eq!(
        full_main_opening_partition_for_test_v1(&omitted),
        Err("unowned trace column")
    );
    let mut overlapping = layout.clone();
    overlapping
        .registered_segments
        .push(layout.registered_segments[0]);
    assert_eq!(
        full_main_opening_partition_for_test_v1(&overlapping),
        Err("overlapping trace column")
    );
}
#[test]
fn main_verifier_profile_is_pinned_and_rejects_substitution() {
    let mut profile =
        construct_zk_x509_main_verifier_profile_v1().expect("release-pinned MAIN profile");
    profile.compiled_profile_digest[0] ^= 1;
    assert!(validate_zk_x509_main_verifier_profile_v1(profile).is_err());
}
#[test]
fn der_registration_claim_order_and_every_shape_field_are_bound() {
    let layout = der_aggregate_layout();
    layout.validate().expect("canonical DER registration");
    assert!(layout.validate_full_profile_registration().is_err());
    assert_eq!(layout.common_lde_log2, ZK_X509_MAIN_COMMON_LDE_LOG2_V1);
    assert_eq!(layout.trace_groups.len(), 1);
    assert_eq!(
        layout.trace_groups[0].native_trace_log2,
        ZK_X509_DER_STARK_TRACE_LOG2_V1
    );
    assert_eq!(
        layout.trace_groups[0].column_chunks,
        ZK_X509_DER_STARK_BASE_WIDTH_V1
            .max(ZK_X509_DER_STARK_AUX_WIDTH_V1)
            .div_ceil(usize::from(ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1))
    );
    assert_eq!(
        layout.trace_groups[0].base_width,
        ZK_X509_DER_STARK_BASE_WIDTH_V1
    );
    assert_eq!(
        layout.trace_groups[0].aux_width,
        ZK_X509_DER_STARK_AUX_WIDTH_V1
    );
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::StrictDer, 0)
        .expect("DER registration");
    assert_eq!(registration.trace_group, 0);
    assert_eq!(registration.base_start, 0);
    assert_eq!(registration.aux_start, 0);
    assert_eq!(
        registration.segment.active_rows,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1
    );
    assert_eq!(
        registration.segment.trace_log2,
        ZK_X509_DER_STARK_TRACE_LOG2_V1
    );
    assert_eq!(
        registration.segment.lde_log2,
        ZK_X509_DER_STARK_TRACE_LOG2_V1 + BLOWUP_LOG2
    );
    assert_eq!(
        registration.segment.fixed_width,
        ZK_X509_DER_STARK_FIXED_WIDTH_V1
    );
    assert_eq!(
        registration.segment.constraint_count,
        ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1
    );
    assert_eq!(
        registration.segment.constraint_degree,
        ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1
    );
    let mut mutations = Vec::new();
    let mut changed = layout.clone();
    changed.registered_segments.clear();
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.adapter = SegmentAdapterIdV1::Rfc5280;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.instance = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.active_rows = 0;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.trace_log2 -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.lde_log2 -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.base_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.aux_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.fixed_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.constraint_count -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].segment.constraint_degree -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].trace_group = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].base_start = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].aux_start = 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.registered_segments[0].column_chunks += 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.trace_groups[0].native_trace_log2 -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.trace_groups[0].base_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.trace_groups[0].aux_width -= 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.trace_groups[0].column_chunks += 1;
    mutations.push(changed);
    changed = layout.clone();
    changed.common_lde_log2 -= 1;
    mutations.push(changed);
    for (index, mutation) in mutations.iter().enumerate() {
        assert!(
            mutation.validate().is_err(),
            "DER registration mutation {index} must fail closed"
        );
    }
    let sha = sha_word_layout();
    let ordered = AggregateProofLayoutV1::for_segments(&[der_layout(), sha])
        .expect("equal-log groups preserve adapter order");
    assert_eq!(ordered.trace_groups.len(), 2);
    assert_eq!(ordered.registered_segments[0].trace_group, 0);
    assert_eq!(ordered.registered_segments[1].trace_group, 1);
    assert_eq!(ordered.registered_segments[0].base_start, 0);
    assert_eq!(ordered.registered_segments[1].base_start, 0);
    assert!(AggregateProofLayoutV1::for_segments(&[sha, der_layout()]).is_err());
    assert!(AggregateProofLayoutV1::for_segments(&[der_layout(), der_layout()]).is_err());
    let claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F(101), F(103), F(107), F(109)],
        node: [F(113), F(127), F(131), F(137)],
    };
    let roots = vec![TraceGroupProofV1 {
        base_root: test_stark_digest_v1(0x31),
        aux_root: test_stark_digest_v1(0x53),
        base_frontier: Vec::new(),
        aux_frontier: Vec::new(),
    }];
    let challenge_state = |derive_after_aux| {
        let mut transcript = new_transcript_v1(&test_stark_digest_v1(0x71)).expect("transcript");
        absorb_aggregate_layout_v1(
            TEST_PROOF_INSTANCE_V1,
            &mut transcript,
            b"iroha:privacy:zk-x509:der-aggregate-layout:test:v1",
            &layout,
        )
        .expect("layout");
        aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &roots)
            .expect("base roots");
        if derive_after_aux {
            aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &roots)
                .expect("aux roots");
        }
        derive_der_challenges_v1(&mut transcript)
            .expect("DER challenges")
            .tuple[0][0]
    };
    assert_ne!(challenge_state(false), challenge_state(true));
    let transcript_state = |claims, claims_before_aux| {
        let mut transcript = new_transcript_v1(&test_stark_digest_v1(0x71)).expect("transcript");
        absorb_aggregate_layout_v1(
            TEST_PROOF_INSTANCE_V1,
            &mut transcript,
            b"iroha:privacy:zk-x509:der-aggregate-layout:test:v1",
            &layout,
        )
        .expect("layout");
        aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &roots)
            .expect("base roots");
        derive_der_challenges_v1(&mut transcript).expect("DER challenges");
        if claims_before_aux {
            absorb_der_terminal_claims_v1(&mut transcript, claims).expect("claims");
        }
        aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &roots)
            .expect("aux roots");
        if !claims_before_aux {
            absorb_der_terminal_claims_v1(&mut transcript, claims).expect("claims");
        }
        derive_constraint_alphas_v1(&mut transcript, &layout).expect("alphas")[0][0][0]
    };
    let canonical_alpha = transcript_state(claims, false);
    assert_ne!(canonical_alpha, transcript_state(claims, true));
    for index in 0..DER_PROOF_CLAIM_COUNT_V1 {
        let mut changed = claims;
        if index < ZK_X509_DER_STARK_BUS_LANES_V1 {
            changed.input_byte[index] = changed.input_byte[index].add(F::ONE);
        } else {
            changed.node[index - ZK_X509_DER_STARK_BUS_LANES_V1] =
                changed.node[index - ZK_X509_DER_STARK_BUS_LANES_V1].add(F::ONE);
        }
        assert_ne!(
            canonical_alpha,
            transcript_state(changed, false),
            "DER claim field {index} must alter composition challenges"
        );
    }
    assert_ne!(
        canonical_alpha,
        transcript_state(
            ZkX509DerStarkTerminalClaimsV1 {
                input_byte: claims.node,
                node: claims.input_byte,
            },
            false
        )
    );
    let mut noncanonical = claims;
    noncanonical.node[0] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
    let mut transcript = new_transcript_v1(&test_stark_digest_v1(0x71)).expect("transcript");
    assert!(absorb_der_terminal_claims_v1(&mut transcript, noncanonical).is_err());
    let aux = [F::ZERO; ZK_X509_DER_STARK_AUX_WIDTH_V1];
    let zero_claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F::ZERO; ZK_X509_DER_STARK_BUS_LANES_V1],
        node: [F::ZERO; ZK_X509_DER_STARK_BUS_LANES_V1],
    };
    assert_eq!(
        evaluate_der_terminal_claim_opening_v1(F::ONE, &aux, zero_claims).expect("claim opening"),
        [F::ZERO; 2 * ZK_X509_DER_STARK_BUS_LANES_V1]
    );
    let mut changed_claims = zero_claims;
    changed_claims.input_byte[2] = F::ONE;
    assert!(
        evaluate_der_terminal_claim_opening_v1(F::ONE, &aux, changed_claims)
            .expect("claim opening")
            .iter()
            .any(|residue| *residue != F::ZERO)
    );
}
#[test]
fn x5m1_main_envelope_is_canonical_bounded_and_adversarially_strict() {
    let aggregate = b"X5S1aggregate";
    let values = core::array::from_fn(|i| E::canonical([i as u64 + 1, 2, 3, 4]).unwrap());
    let encoded = encode_zk_x509_main_proof_envelope_v1(&values, aggregate).unwrap();
    assert_eq!(encoded.len(), 1002 + aggregate.len());
    let decoded = decode_zk_x509_main_proof_envelope_v1(&encoded).unwrap();
    assert_eq!(decoded.key_openings, values);
    assert_eq!(decoded.aggregate_proof, aggregate);
    assert_eq!(
        encode_zk_x509_main_proof_envelope_v1(&decoded.key_openings, decoded.aggregate_proof)
            .unwrap(),
        encoded
    );
    for index in 0..31 {
        for limb in 0..4 {
            let mut changed = encoded.clone();
            let offset = MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + 32 * index + 8 * limb;
            changed[offset..offset + 8].copy_from_slice(&0xffff_ffff_0000_0001_u64.to_be_bytes());
            assert!(matches!(
                decode_zk_x509_main_proof_envelope_v1(&changed),
                Err(ZkX509StarkErrorV1::NonCanonicalField)
            ));
        }
    }
    for length in 0..encoded.len() {
        assert!(decode_zk_x509_main_proof_envelope_v1(&encoded[..length]).is_err());
    }
    for offset in (0..6)
        .chain(MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1..MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1 + 8)
    {
        let mut changed = encoded.clone();
        changed[offset] ^= 1;
        assert!(decode_zk_x509_main_proof_envelope_v1(&changed).is_err());
    }
    // No retired public products, adapter-count or fixed-sidecar record is accepted.
    for size in [2, 64, 76, 256, 1024, 3340, 3418, 5580] {
        let mut retired = encoded.clone();
        retired.splice(6..6, vec![0; size]);
        assert!(decode_zk_x509_main_proof_envelope_v1(&retired).is_err());
    }
    let mut suffix = encoded;
    suffix.push(0);
    assert!(decode_zk_x509_main_proof_envelope_v1(&suffix).is_err());
    assert!(encode_zk_x509_main_proof_envelope_v1(&values, b"X5F1").is_err());
    let maximum =
        ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1 - ZK_X509_MAIN_PROOF_ENVELOPE_FIXED_BYTES_V1;
    let mut inner = vec![0; maximum];
    inner[..4].copy_from_slice(b"X5S1");
    let exact = encode_zk_x509_main_proof_envelope_v1(&values, &inner).unwrap();
    assert_eq!(exact.len(), ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1);
    assert!(decode_zk_x509_main_proof_envelope_v1(&exact).is_ok());
    inner.push(0);
    assert!(matches!(
        encode_zk_x509_main_proof_envelope_v1(&values, &inner),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
    assert!(matches!(
        decode_zk_x509_main_proof_envelope_v1(&vec![
            0;
            ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1 + 1
        ]),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
}
#[test]
fn der_statement_digest_and_x5p1_envelope_are_exact_and_fail_closed() {
    let shape = ZkX509DerStarkShapeV1;
    let digest = der_public_digest_v1(&shape).expect("DER public digest");
    // Independent SHA3-384 of the exact catalog/protocol/profile frame and
    // ordered DER descriptors plus the constant public registration label.
    // The MAIN profile label includes family 1 and public nonce [0x5a; 32].
    assert_eq!(
        hex::encode(digest.to_bytes()),
        "156c6dd358a46edb4840d5e4b66c529ff7f0a21af94e6eb267d76b94316b1bc5942bbf024b414971be062659f1b4bcb9"
    );
    let claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F(3), F(5), F(7), F(11)],
        node: [F(13), F(17), F(19), F(23)],
    };
    let aggregate = b"X5S1payload";
    let encoded = encode_der_segmented_proof_envelope_v1(claims, aggregate).expect("X5P1 envelope");
    assert_eq!(encoded.len(), DER_PROOF_ENVELOPE_BYTES_V1 + aggregate.len());
    assert_eq!(&encoded[..4], b"X5P1");
    assert_eq!(
        &encoded[DER_PROOF_ENVELOPE_BYTES_V1..],
        aggregate.as_slice()
    );
    let (decoded_claims, decoded_aggregate) =
        decode_der_segmented_proof_envelope_v1(&encoded).expect("decode X5P1");
    assert_eq!(decoded_claims, claims);
    assert_eq!(decoded_aggregate, aggregate);
    assert_eq!(
        encode_der_segmented_proof_envelope_v1(decoded_claims, decoded_aggregate)
            .expect("canonical re-encode"),
        encoded
    );
    for prefix_len in 0..encoded.len() {
        assert!(
            decode_der_segmented_proof_envelope_v1(&encoded[..prefix_len]).is_err(),
            "truncated prefix {prefix_len} must reject"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_der_segmented_proof_envelope_v1(&trailing).is_err());
    for offset in 0..12 {
        let mut changed = encoded.clone();
        changed[offset] ^= 1;
        assert!(
            decode_der_segmented_proof_envelope_v1(&changed).is_err(),
            "header byte {offset} must be exact"
        );
    }
    for claim_index in 0..DER_PROOF_CLAIM_COUNT_V1 {
        let start = 12 + claim_index * DER_PROOF_CLAIM_RECORD_BYTES_V1;
        for offset in start..start + 4 {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                decode_der_segmented_proof_envelope_v1(&changed).is_err(),
                "claim type/lane byte {offset} must be exact"
            );
        }
    }
    let mut reordered = encoded.clone();
    let first: [u8; DER_PROOF_CLAIM_RECORD_BYTES_V1] = reordered
        [12..12 + DER_PROOF_CLAIM_RECORD_BYTES_V1]
        .try_into()
        .expect("first claim");
    let second: [u8; DER_PROOF_CLAIM_RECORD_BYTES_V1] = reordered
        [12 + DER_PROOF_CLAIM_RECORD_BYTES_V1..12 + 2 * DER_PROOF_CLAIM_RECORD_BYTES_V1]
        .try_into()
        .expect("second claim");
    reordered[12..12 + DER_PROOF_CLAIM_RECORD_BYTES_V1].copy_from_slice(&second);
    reordered[12 + DER_PROOF_CLAIM_RECORD_BYTES_V1..12 + 2 * DER_PROOF_CLAIM_RECORD_BYTES_V1]
        .copy_from_slice(&first);
    assert!(decode_der_segmented_proof_envelope_v1(&reordered).is_err());
    let mut duplicated = encoded.clone();
    duplicated[12 + DER_PROOF_CLAIM_RECORD_BYTES_V1..12 + 2 * DER_PROOF_CLAIM_RECORD_BYTES_V1]
        .copy_from_slice(&first);
    assert!(decode_der_segmented_proof_envelope_v1(&duplicated).is_err());
    for offset in DER_PROOF_LENGTH_OFFSET_V1..DER_PROOF_ENVELOPE_BYTES_V1 {
        let mut changed = encoded.clone();
        changed[offset] ^= 1;
        assert!(
            decode_der_segmented_proof_envelope_v1(&changed).is_err(),
            "length byte {offset} must be exact"
        );
    }
    let mut noncanonical = encoded.clone();
    noncanonical[16..24].copy_from_slice(
        &crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1.to_be_bytes(),
    );
    assert!(matches!(
        decode_der_segmented_proof_envelope_v1(&noncanonical),
        Err(ZkX509StarkErrorV1::NonCanonicalField)
    ));
    assert!(encode_der_segmented_proof_envelope_v1(claims, &[]).is_err());
    let mut rejected_draft_magic = encoded.clone();
    rejected_draft_magic[..4].copy_from_slice(b"X5D2");
    assert!(decode_der_segmented_proof_envelope_v1(&rejected_draft_magic).is_err());
    // A valid envelope cannot make an invalid inner aggregate proof
    // verifier-visible as a different wire format.
    assert!(verify_zk_x509_der_segmented_stark_v1(&shape, &encoded).is_err());
}
#[test]
fn der_sampled_fixed_rows_match_reduced_full_lde_for_every_column_family() {
    let _guard = proof_guard();
    fn native_row(
        document_count: usize,
        parser_rows: usize,
        active_rows: usize,
        index: usize,
        trace_size: usize,
    ) -> [F; ZK_X509_DER_STARK_FIXED_WIDTH_V1] {
        assert!(index < trace_size);
        let mut row = [F::ZERO; ZK_X509_DER_STARK_FIXED_WIDTH_V1];
        row[FIX_FINAL_DOCUMENT] = F(u64::try_from(document_count - 1).expect("document"));
        row[FIX_FIRST_AGGREGATE] = F(u64::from(index == 0));
        row[FIX_LAST_AGGREGATE] = F(u64::from(index + 1 == trace_size));
        if index >= active_rows {
            row[FIX_PADDING] = F::ONE;
            return row;
        }
        row[DER_FIX_ACTIVE] = F::ONE;
        row[FIX_FIRST_ACTIVE] = F(u64::from(index == 0));
        row[DER_FIX_LAST_ACTIVE] = F(u64::from(index + 1 == active_rows));
        if index < parser_rows {
            row[FIX_PARSER] = F::ONE;
            row[FIX_FIRST_PARSER] = F(u64::from(index == 0));
            row[FIX_LAST_PARSER] = F(u64::from(index + 1 == parser_rows));
            row[FIX_PARSER_CONTINUE] = F(u64::from(index + 1 < parser_rows));
        } else {
            row[FIX_COMPARATOR] = F::ONE;
            row[FIX_FIRST_COMPARATOR] = F(u64::from(index == parser_rows));
            row[FIX_LAST_COMPARATOR] = F(u64::from(index + 1 == active_rows));
        }
        row
    }
    let trace_log2 = 5;
    let lde_log2 = trace_log2 + BLOWUP_LOG2;
    let trace_size = 1_usize << trace_log2;
    let lde_size = 1_usize << lde_log2;
    let lde_root = goldilocks_primitive_root_v1(lde_log2).expect("LDE root");
    for private_shape in [
        ZkX509DerStarkPrivateShapeV1 {
            document_lengths: vec![5],
            parser_rows: 7,
            comparator_rows: 4,
        },
        ZkX509DerStarkPrivateShapeV1 {
            document_lengths: vec![5],
            parser_rows: 7,
            comparator_rows: 0,
        },
        ZkX509DerStarkPrivateShapeV1 {
            document_lengths: vec![5, 17],
            parser_rows: 26,
            comparator_rows: 6,
        },
    ] {
        private_shape.validate().expect("private shape");
        let document_count = private_shape.document_lengths.len();
        let parser_rows = private_shape.parser_rows;
        let active_rows = private_shape.active_rows().expect("active rows");
        let columns = (0..ZK_X509_DER_STARK_FIXED_WIDTH_V1)
            .map(|column| {
                (0..trace_size)
                    .map(|index| {
                        native_row(document_count, parser_rows, active_rows, index, trace_size)
                            [column]
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut layout = der_layout();
        layout.active_rows = active_rows;
        layout.trace_log2 = trace_log2;
        layout.lde_log2 = lde_log2;
        let full_lde = fixed_lde_columns_v1(&columns, layout).expect("full fixed LDE");
        for index in 0..lde_size {
            let x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(index as u128));
            let sampled = der_fixed_row_at_point_for_shape_v1(
                document_count,
                parser_rows,
                active_rows,
                trace_log2,
                x,
            )
            .expect("sampled fixed row");
            for column in 0..ZK_X509_DER_STARK_FIXED_WIDTH_V1 {
                assert_eq!(
                    sampled[column], full_lde[column][index],
                    "shape={private_shape:?}, column={column}, LDE row={index}"
                );
            }
        }
        assert_eq!(
            checked_der_fixed_sampled_work_v1(active_rows, trace_size, QUERY_COUNT)
                .expect("sampled work"),
            (active_rows + usize::from(active_rows < trace_size)) * QUERY_COUNT
        );
    }
    for (document_count, parser_rows, active_rows) in
        [(1_usize, 1_usize, 1_usize), (1, 1, 5), (2, 31, 32)]
    {
        let columns = (0..ZK_X509_DER_STARK_FIXED_WIDTH_V1)
            .map(|column| {
                (0..trace_size)
                    .map(|index| {
                        native_row(document_count, parser_rows, active_rows, index, trace_size)
                            [column]
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut layout = der_layout();
        layout.active_rows = active_rows;
        layout.trace_log2 = trace_log2;
        layout.lde_log2 = lde_log2;
        let full_lde = fixed_lde_columns_v1(&columns, layout).expect("edge full fixed LDE");
        for index in 0..lde_size {
            let x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(index as u128));
            let sampled = der_fixed_row_at_point_for_shape_v1(
                document_count,
                parser_rows,
                active_rows,
                trace_log2,
                x,
            )
            .expect("edge sampled fixed row");
            for column in 0..ZK_X509_DER_STARK_FIXED_WIDTH_V1 {
                assert_eq!(
                    sampled[column], full_lde[column][index],
                    "documents={document_count}, parser={parser_rows}, active={active_rows}, \
                         column={column}, LDE row={index}"
                );
            }
        }
    }
    assert!(checked_der_fixed_sampled_work_v1(0, trace_size, 1).is_err());
    assert!(checked_der_fixed_sampled_work_v1(trace_size + 1, trace_size, 1).is_err());
    assert!(
        checked_der_fixed_sampled_work_v1(1, trace_size, DER_FIXED_MAX_SAMPLED_OPENINGS_V1 + 1,)
            .is_err()
    );
    assert!(
        checked_der_fixed_sampled_work_v1(
            usize::MAX,
            usize::MAX,
            DER_FIXED_MAX_SAMPLED_OPENINGS_V1,
        )
        .is_err()
    );
}
#[test]
fn malformed_der_wires_reject_before_sampled_fixed_evaluation() {
    let _guard = proof_guard();
    DER_FIXED_OPENING_EVALUATIONS_V1.store(0, std::sync::atomic::Ordering::SeqCst);
    let document = [0x30, 0x03, 0x02, 0x01, 0x01];
    let private_shape = build_zk_x509_der_stark_base_v1(&[&document])
        .expect("DER base")
        .private_shape
        .clone();
    private_shape.validate().expect("private DER shape");
    let shape = ZkX509DerStarkShapeV1;
    let claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F(3), F(5), F(7), F(11)],
        node: [F(13), F(17), F(19), F(23)],
    };
    let malformed_inner = encode_der_segmented_proof_envelope_v1(claims, b"X5S1malformed-inner")
        .expect("outer envelope");
    for malformed in [
        Vec::new(),
        b"X5D2draft".to_vec(),
        malformed_inner[..malformed_inner.len() - 1].to_vec(),
        malformed_inner,
    ] {
        assert!(verify_zk_x509_der_segmented_stark_v1(&shape, &malformed).is_err());
    }
    assert_eq!(
        DER_FIXED_OPENING_EVALUATIONS_V1.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "malformed proof parsing, shape, and commitment failures must not enter fixed evaluation"
    );
}
#[test]
fn der_opened_row_evaluator_binds_both_rows_fixed_schedule_claims_and_lane_mixes() {
    let layout = der_layout();
    let aggregate_layout = der_aggregate_layout();
    let query_index = 123_usize;
    let next_index = query_index + BLOWUP;
    let challenges = ZkX509DerStarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(
                |slot| F(u64::try_from(100 + lane * 20 + slot).expect("challenge")),
            )
        }),
        byte_lookup: [F(701), F(709), F(719), F(727)],
    };
    let public = ZkX509DerStarkPublicTerminalsV1;
    let claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F(743), F(751), F(757), F(761)],
        node: [F(769), F(773), F(787), F(797)],
    };
    let trace_groups = vec![aggregate::AggregateOpenedTraceGroupV1 {
        base_current: (0..ZK_X509_DER_STARK_BASE_WIDTH_V1)
            .map(|index| F(u64::try_from(index + 1).expect("base")))
            .collect(),
        base_next: (0..ZK_X509_DER_STARK_BASE_WIDTH_V1)
            .map(|index| F(u64::try_from(index + 211).expect("next base")))
            .collect(),
        aux_current: (0..ZK_X509_DER_STARK_AUX_WIDTH_V1)
            .map(|index| F(u64::try_from(index + 419).expect("aux")))
            .collect(),
        aux_next: (0..ZK_X509_DER_STARK_AUX_WIDTH_V1)
            .map(|index| F(u64::try_from(index + 911).expect("next aux")))
            .collect(),
    }];
    let fixed_current =
        core::array::from_fn(|index| F(u64::try_from(index + 1_301).expect("fixed")));
    let fixed_next =
        core::array::from_fn(|index| F(u64::try_from(index + 1_401).expect("next fixed")));
    let fixed_openings = BTreeMap::from([(query_index, fixed_current), (next_index, fixed_next)]);
    let alphas = (0..SECURITY_LANES)
        .map(|lane| {
            (0..ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1)
                .map(|index| {
                    extension_v1(F(
                        u64::try_from(2_003 + lane * 1_000 + index).expect("alpha")
                    ))
                })
                .collect()
        })
        .collect::<Vec<_>>();
    let mixes = (0..SECURITY_LANES)
        .map(|lane| FriMixV1 {
            base: (0..ZK_X509_DER_STARK_BASE_WIDTH_V1)
                .map(|index| {
                    extension_v1(F(
                        u64::try_from(5_003 + lane * 500 + index).expect("base mix")
                    ))
                })
                .collect(),
            base_next: (0..ZK_X509_DER_STARK_BASE_WIDTH_V1)
                .map(|index| {
                    extension_v1(F(
                        u64::try_from(6_003 + lane * 500 + index).expect("next base mix")
                    ))
                })
                .collect(),
            aux: (0..ZK_X509_DER_STARK_AUX_WIDTH_V1)
                .map(|index| {
                    extension_v1(F(
                        u64::try_from(7_003 + lane * 500 + index).expect("aux mix")
                    ))
                })
                .collect(),
            aux_next: (0..ZK_X509_DER_STARK_AUX_WIDTH_V1)
                .map(|index| {
                    extension_v1(F(
                        u64::try_from(8_003 + lane * 500 + index).expect("next aux mix")
                    ))
                })
                .collect(),
            composition: (0..COMPOSITION_DEGREE_CHUNKS)
                .map(|chunk| {
                    extension_v1(F(
                        u64::try_from(9_001 + lane * 10 + chunk).expect("composition mix")
                    ))
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let lde_root = goldilocks_primitive_root_v1(layout.lde_log2).expect("LDE root");
    let mut evaluator = DerOpenedRowEvaluatorV1 {
        aggregate_layout: &aggregate_layout,
        layout,
        fixed_openings: &fixed_openings,
        challenges,
        public,
        claims,
        alphas: &alphas,
        mixes: &mixes,
        lde_root,
    };
    for lane in 0..SECURITY_LANES {
        let composition_chunks = (0..COMPOSITION_DEGREE_CHUNKS)
            .map(|chunk| extension_v1(F(u64::try_from(11_001 + lane * 10 + chunk).expect("chunk"))))
            .collect::<Vec<_>>();
        let evaluated = aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            lane,
            &trace_groups,
            &composition_chunks,
        )
        .expect("opened DER row");
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(query_index as u128));
        let composition = der_quotient_value_v1(
            layout,
            x,
            &trace_groups[0].base_current,
            &trace_groups[0].base_next,
            &trace_groups[0].aux_current,
            &trace_groups[0].aux_next,
            &fixed_current,
            &fixed_next,
            challenges,
            public,
            claims,
            &alphas[lane],
        )
        .expect("direct quotient");
        let mixed_base = trace_groups[0]
            .base_current
            .iter()
            .zip(&mixes[lane].base)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        let mixed_aux = trace_groups[0]
            .aux_current
            .iter()
            .zip(&mixes[lane].aux)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        assert_eq!(evaluated.composition, composition);
        assert_eq!(
            evaluated.fri_base,
            mixed_base.add(mixed_aux).add(
                mix_opened_composition_chunks_v1(&composition_chunks, &mixes[lane])
                    .expect("composition mix"),
            )
        );
    }
    let missing_next = BTreeMap::from([(query_index, fixed_current)]);
    evaluator.fixed_openings = &missing_next;
    assert!(
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            0,
            &trace_groups,
            &[E::ZERO; COMPOSITION_DEGREE_CHUNKS],
        )
        .is_err()
    );
    evaluator.fixed_openings = &fixed_openings;
    assert!(
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            SECURITY_LANES,
            &trace_groups,
            &[E::ZERO; COMPOSITION_DEGREE_CHUNKS],
        )
        .is_err()
    );
    let mut wrong_width = trace_groups.clone();
    wrong_width[0].aux_next.pop();
    assert!(
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            0,
            &wrong_width,
            &[E::ZERO; COMPOSITION_DEGREE_CHUNKS],
        )
        .is_err()
    );
}
#[test]
fn der_retained_prover_resource_plan_and_production_source_exclude_trace_scratch() {
    let plan = der_retained_prover_allocation_plan_v1(der_layout()).expect("retained DER plan");
    assert_eq!(plan.quotient_coset_log2, 22);
    assert_eq!(plan.quotient_coset_rows, 1 << 22);
    assert_eq!(plan.quotient_next_stride, 8);
    assert_eq!(plan.maximum_quotient_degree, 3_158_433);
    assert_eq!(plan.retained_masked_coefficient_bytes, 1_144_802_304);
    assert_eq!(plan.quotient_trace_matrix_bytes, 9_596_567_552);
    assert_eq!(plan.encrypted_trace_scratch_bytes, 0);
    assert_eq!(plan.common_domain_trace_matrix_bytes, 0);
    let mut changed = der_layout();
    changed.lde_log2 -= 1;
    assert!(der_retained_prover_allocation_plan_v1(changed).is_err());
    changed = der_layout();
    changed.constraint_degree -= 1;
    assert!(der_retained_prover_allocation_plan_v1(changed).is_err());
    changed = der_layout();
    changed.trace_log2 -= 1;
    assert!(der_retained_prover_allocation_plan_v1(changed).is_err());
    let source = include_str!("../stark.rs");
    let start = source
        .find("fn build_zk_x509_der_segmented_stark_proof_v1_with_rng")
        .expect("DER builder source");
    let end = source[start..]
        .find("\n}\n")
        .map(|offset| start + offset + "\n}\n".len())
        .expect("DER builder end");
    let builder = &source[start..end];
    for forbidden in [
        "EncryptedFieldMatrixScratchV1",
        "EncryptedFieldMatrixScratchWriterV1",
        "commit_masked_trace_columns_retaining_encrypted_scratch_v1",
        "commit_encrypted_field_scratch_rows_v1",
        "der_fixed_lde_scratch_v1",
        "der_composition_lanes_from_scratches_v1",
        "der_fri_bases_from_scratches_v1",
        "evaluate_composition_chunks_at_deep_v1",
    ] {
        assert!(
            !builder.contains(forbidden),
            "production DER builder must not contain `{forbidden}`"
        );
    }
    for required in [
        "commit_masked_trace_polynomial_columns_v1",
        "der_composition_material_from_polynomials_v1",
        "evaluate_masked_trace_polynomial_columns_at_deep_v1",
        "evaluate_retained_composition_coefficients_at_deep_v1",
        "der_fri_bases_from_polynomials_v1",
        "replay_masked_trace_polynomial_columns_v1",
    ] {
        assert!(
            builder.contains(required),
            "production DER builder must contain `{required}`"
        );
    }
}
#[test]
fn main_key_join_opening_codec_is_canonical_exact_and_roundtrips() {
    let values = core::array::from_fn(|i| E::canonical([i as u64 + 1, 2, 3, 4]).unwrap());
    let wire = encode_zk_x509_main_proof_envelope_v1(&values, b"X5S1public-fixture").unwrap();
    let decoded = decode_zk_x509_main_proof_envelope_v1(&wire).unwrap();
    assert_eq!(decoded.key_openings, values);
    assert_eq!(
        encode_zk_x509_main_proof_envelope_v1(&decoded.key_openings, decoded.aggregate_proof)
            .unwrap(),
        wire
    );
    for i in 0..31 {
        for j in 0..4 {
            let mut changed = wire.clone();
            let offset = MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + 32 * i + 8 * j;
            changed[offset..offset + 8].copy_from_slice(
                &crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1.to_be_bytes(),
            );
            assert!(decode_zk_x509_main_proof_envelope_v1(&changed).is_err());
        }
    }
    for cut in 0..=31 * 32 {
        let mut changed = wire.clone();
        changed.drain(MAIN_PROOF_KEY_OPENINGS_OFFSET_V1..MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + cut);
        assert_eq!(
            decode_zk_x509_main_proof_envelope_v1(&changed).is_ok(),
            cut == 0
        );
    }
    let mut trailing = wire;
    trailing.push(0);
    assert!(decode_zk_x509_main_proof_envelope_v1(&trailing).is_err());
}

#[test]
fn main_key_join_wire_retains_all_coordinates_in_fixed_order_and_exact_count() {
    let values = core::array::from_fn(|index| {
        E::canonical(core::array::from_fn(|limb| (4 * index + limb + 1) as u64)).unwrap()
    });
    let aggregate = b"X5S1ordered-opening-fixture";
    let encoded = encode_zk_x509_main_proof_envelope_v1(&values, aggregate).unwrap();
    assert_eq!(
        MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1 - MAIN_PROOF_KEY_OPENINGS_OFFSET_V1,
        31 * 32
    );
    for (index, value) in values.iter().enumerate() {
        for (limb, coefficient) in value.coefficients().iter().enumerate() {
            let offset = MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + 32 * index + 8 * limb;
            assert_eq!(&encoded[offset..offset + 8], &coefficient.0.to_be_bytes());
        }
    }
    assert_eq!(
        decode_zk_x509_main_proof_envelope_v1(&encoded)
            .unwrap()
            .key_openings,
        values
    );
    for index in 0..30 {
        let mut swapped = encoded.clone();
        let offset = MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + 32 * index;
        swapped[offset..offset + 64].rotate_left(32);
        let mut expected = values;
        expected.swap(index, index + 1);
        let decoded = decode_zk_x509_main_proof_envelope_v1(&swapped).unwrap();
        assert_eq!(decoded.key_openings, expected);
        assert_ne!(decoded.key_openings, values);
        assert_eq!(
            encode_zk_x509_main_proof_envelope_v1(
                &decoded.key_openings,
                decoded.aggregate_proof
            )
            .unwrap(),
            swapped
        );
    }
    for index in 0..31 {
        let offset = MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + 32 * index;
        let mut missing = encoded.clone();
        missing.drain(offset..offset + 32);
        assert!(decode_zk_x509_main_proof_envelope_v1(&missing).is_err());
        let mut duplicate = encoded.clone();
        duplicate.splice(offset..offset, encoded[offset..offset + 32].iter().copied());
        assert!(decode_zk_x509_main_proof_envelope_v1(&duplicate).is_err());
    }
}

#[test]
fn main_claim_free_partition_is_exact_and_rejects_retired_terminal_frames() {
    assert_eq!(MAIN_KEY_OPENING_COUNT_V1, 31);
    assert_eq!(
        MAIN_KEY_OPENING_COUNT_V1,
        main_aggregate::main_key_joins::OPENINGS_V1
    );
    assert_eq!(MAIN_PROOF_KEY_OPENINGS_OFFSET_V1, 6);
    assert_eq!(MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1, 998);
    assert_eq!(ZK_X509_MAIN_PROOF_ENVELOPE_FIXED_BYTES_V1, 1_002);
    let aggregate = b"X5S1public partition";
    let values = [E::ZERO; 31];
    let encoded = encode_zk_x509_main_proof_envelope_v1(&values, aggregate).unwrap();
    assert_eq!(encoded.len(), 1_002 + aggregate.len());
    let decoded = decode_zk_x509_main_proof_envelope_v1(&encoded).unwrap();
    assert_eq!(decoded.key_openings, values);
    assert_eq!(decoded.aggregate_proof, aggregate);
    assert_eq!(
        encode_zk_x509_main_proof_envelope_v1(&decoded.key_openings, decoded.aggregate_proof)
            .unwrap(),
        encoded
    );

    // Frozen obsolete framing is rejection input only. No retired terminal codec
    // or intermediate product acceptance path is retained in the implementation.
    let mut retired_fields = vec![0; 2 + 76 + 3_340];
    retired_fields[..2].copy_from_slice(&2_u16.to_be_bytes());
    retired_fields[2..6].copy_from_slice(b"X5R1");
    retired_fields[6..8].copy_from_slice(&1_u16.to_be_bytes());
    retired_fields[12..14].copy_from_slice(&4_u16.to_be_bytes());
    retired_fields[78..82].copy_from_slice(b"X5Q1");
    retired_fields[82..84].copy_from_slice(&1_u16.to_be_bytes());
    retired_fields[88..90].copy_from_slice(&208_u16.to_be_bytes());
    let mut retired = encoded.clone();
    retired.splice(6..6, retired_fields);
    assert_eq!(retired.len(), 4_420 + aggregate.len());
    assert!(decode_zk_x509_main_proof_envelope_v1(&retired).is_err());
    for (frame, counts) in [
        (8, [0_u16, 3, 4, 5, 80, u16::MAX]),
        (84, [0_u16, 207, 208, 209, 304, u16::MAX]),
    ] {
        for count in counts {
            let mut wrong = retired.clone();
            wrong[frame + 10..frame + 12].copy_from_slice(&count.to_be_bytes());
            assert!(
                decode_zk_x509_main_proof_envelope_v1(&wrong).is_err(),
                "retired frame {frame}, count {count}"
            );
        }
    }
    for lane in 0..4 {
        let record = 8 + 12 + lane * 16;
        let mut exposed = retired.clone();
        exposed[record + 8..record + 16]
            .copy_from_slice(&[2_u64, 3, 5, 7][lane].to_be_bytes());
        assert!(decode_zk_x509_main_proof_envelope_v1(&exposed).is_err());
        let wrong_lane = u16::try_from((lane + 1) % 4).expect("four governed lanes fit u16");
        exposed[record + 4..record + 6].copy_from_slice(&wrong_lane.to_be_bytes());
        assert!(decode_zk_x509_main_proof_envelope_v1(&exposed).is_err());
    }
}
