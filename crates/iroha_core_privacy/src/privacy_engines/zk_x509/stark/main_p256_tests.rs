// Lexically included by `zk_x509::stark::tests` to preserve the existing libtest paths.
#[test]
fn main_log19_query_union_is_exact_sorted_unique_and_bounded() {
    let query_coordinates = main_log19_query_coordinates_fixture_v1();
    let schedule = MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&query_coordinates)
        .expect("canonical post-grinding query schedule");
    assert_eq!(schedule.pairs.len(), QUERY_COUNT);
    assert_eq!(schedule.indices.len(), QUERY_COUNT + 1);
    assert_eq!(schedule.indices.first(), Some(&0));
    assert_eq!(
        schedule.indices.last(),
        Some(
            &u64::try_from(QUERY_COUNT * P256_MAIN_LOG19_NEXT_STRIDE_V1)
                .expect("bounded last query"),
        )
    );
    assert!(schedule.indices.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        !schedule.indices.is_empty()
            && schedule.indices.len() <= ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1
    );
    for (slot, current) in query_coordinates.into_iter().enumerate() {
        assert_eq!(
            schedule.pairs[slot],
            (current, current + P256_MAIN_LOG19_NEXT_STRIDE_V1)
        );
    }
    assert_eq!(
        schedule.order_digest,
        main_log19_query_schedule_digest_v1(&schedule.pairs).expect("independent order digest"),
    );
    schedule.validate_v1().expect("self-validating schedule");
}
#[test]
fn main_log19_query_union_handles_wraparound_and_adversarial_residues() {
    let common_lde_size = 1_usize << ZK_X509_MAIN_COMMON_LDE_LOG2_V1;
    let wraparound = core::array::from_fn::<_, QUERY_COUNT, _>(|index| {
        common_lde_size - 1 - index * P256_MAIN_LOG19_NEXT_STRIDE_V1
    });
    let wrapped = MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&wraparound)
        .expect("wraparound query schedule");
    assert!(
        wrapped.pairs.iter().any(|(current, next)| next < current),
        "at least one next query must wrap modulo the common LDE",
    );
    assert!(wrapped.indices.windows(2).all(|pair| pair[0] < pair[1]));
    let adversarial = main_log19_adversarial_query_coordinates_fixture_v1();
    let schedule = MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&adversarial)
        .expect("adversarial residue schedule");
    assert_eq!(schedule.indices.len(), QUERY_COUNT * 2);
    assert!(schedule.indices.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        schedule
            .indices
            .iter()
            .all(|index| *index < u64::try_from(common_lde_size).expect("log22 fits u64"))
    );
}
#[test]
fn main_log19_query_union_rejects_wrong_count_duplicate_range_and_tampering() {
    let canonical = main_log19_adversarial_query_coordinates_fixture_v1();
    assert!(matches!(
        MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&canonical[..QUERY_COUNT - 1],),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut too_many = canonical.to_vec();
    too_many.push(7);
    assert!(matches!(
        MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&too_many),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut duplicate = canonical;
    duplicate[1] = duplicate[0];
    assert!(matches!(
        MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&duplicate),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut out_of_range = canonical;
    out_of_range[0] = 1_usize << ZK_X509_MAIN_COMMON_LDE_LOG2_V1;
    assert!(matches!(
        MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&out_of_range),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    out_of_range[0] = usize::MAX;
    assert!(matches!(
        MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&out_of_range),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut wrong_next = MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&canonical)
        .expect("canonical schedule");
    wrong_next.pairs[0].1 ^= 1;
    assert!(matches!(
        wrong_next.validate_v1(),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut reordered = MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&canonical)
        .expect("canonical schedule");
    reordered.pairs.swap(0, 1);
    assert!(matches!(
        reordered.validate_v1(),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut wrong_digest = MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&canonical)
        .expect("canonical schedule");
    let mut wrong_words = wrong_digest.order_digest.to_bytes();
    wrong_words[0] ^= 1;
    wrong_digest.order_digest = PrivacyOuterDigestV1::from_bytes(wrong_words);
    assert!(matches!(
        wrong_digest.validate_v1(),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut noncanonical_union =
        MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&canonical)
            .expect("canonical schedule");
    noncanonical_union.indices.swap(0, 1);
    assert!(matches!(
        noncanonical_union.validate_v1(),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
    let mut missing_union = MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(&canonical)
        .expect("canonical schedule");
    missing_union.indices.pop();
    assert!(matches!(
        missing_union.validate_v1(),
        Err(ZkX509StarkErrorV1::TraceOpening)
    ));
}
#[test]
fn main_log19_algebraic_openings_use_both_success_only_schedule_caches() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let query_coordinates = main_log19_query_coordinates_fixture_v1();
    let shape = ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: 0,
    };
    let derived =
        derive_zk_x509_main_fixed_openings_after_profile_validation_v1(shape, &query_coordinates)
            .expect("verifier-derived SHA and P-256 openings");
    let duplicate = derived.clone();
    let expected_indices = derived.query_schedule.indices.len();
    assert_eq!(expected_indices, QUERY_COUNT + 1);
    assert_eq!(
        derived.sha.query_indices_v1(),
        derived.query_schedule.indices.as_slice()
    );
    assert_eq!(
        derived.p256_log19.query_indices_v1(),
        derived.query_schedule.indices.as_slice()
    );
    assert_eq!(
        usize::from(derived.sha.width_v1()),
        ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1
    );
    assert_eq!(
        usize::from(derived.p256_log19.width_v1()),
        ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1
    );
    assert_eq!(
        derived.sha.schedule_digest_v1(),
        zk_x509_sha_fixed_algebraic_schedule_v1(shape)
            .expect("cached SHA schedule")
            .descriptor_digest_v1()
    );
    assert_eq!(
        derived.p256_log19.schedule_digest_v1(),
        zk_x509_p256_fixed_algebraic_schedule_v1()
            .expect("cached P-256 schedule")
            .descriptor_digest_v1()
    );
    let mut source = main_log19_source_fixture_v1(&layout);
    source
        .install_verifier_derived_fixed_openings_v1(derived)
        .expect("atomic verifier-derived installation");
    assert_eq!(source.cached_openings_v1(), expected_indices);
    assert_eq!(source.p256.cached_openings_v1(), expected_indices);
    assert!(
        source
            .public_fixed
            .as_ref()
            .is_some_and(|schedule| !schedule.segments.is_empty())
    );
    assert!(matches!(
        source.install_verifier_derived_fixed_openings_v1(duplicate),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
    assert_eq!(source.cached_openings_v1(), expected_indices);
    assert_eq!(source.p256.cached_openings_v1(), expected_indices);
}
#[test]
fn p256_terminal_registration_scrub_is_recursive_and_idempotent() {
    let mut terminal = p256_terminal_fixture(P256EcdsaRoleV1::WalletOwnership);
    zeroize_p256_terminal_registration_v1(&mut terminal);
    zeroize_p256_terminal_registration_v1(&mut terminal);
    assert!(terminal.cross_sources.is_empty());
    assert_eq!(terminal.sink, [F::ZERO; P256_CROSS_TRACE_LANES_V1]);
    assert!(
        [
            terminal.buses.value_execution,
            terminal.buses.value_sorted,
            terminal.buses.value_arithmetic_copy,
            terminal.buses.arithmetic_value_copy,
            terminal.buses.arithmetic_scalar,
            terminal.buses.window_scalar,
            terminal.buses.scalar_bus_arithmetic,
            terminal.buses.scalar_bus_window,
        ]
        .into_iter()
        .flatten()
        .all(|value| value == F::ZERO)
    );
}
#[test]
fn main_p256_log8_verifier_covers_five_buses_with_exact_local_air_parity() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed =
        P256MainVerifierFixedSourceV1::new_v1().expect("shared verifier-fixed P-256 source");
    let mut source = MainP256ScalarVerifierConstraintSourceV1::for_main_v1(
        &layout,
        &fixed,
        p256_main_provider_post_base_fixture_v1(),
    )
    .expect("closed log8 verifier source");
    assert!(core::ptr::eq(source.fixed, &raw const fixed));
    assert_eq!(source.registrations.len(), P256_SIGNATURE_COUNT_V1);
    let base = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1];
    let aux = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let common_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).expect("MAIN common root");
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        let registration = source.registrations[signature].main;
        let query_index = 17 + signature;
        let next_query_index = source
            .next_query_index_v1(registration, query_index)
            .expect("canonical scalar next query");
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(query_index as u128));
        let residues = source
            .constraint_residues_v1(registration, query_index, next_query_index, x, opening)
            .expect("scalar opened residues");
        assert_eq!(
            residues.len(),
            P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1
        );
        let fixed_opening = source.fixed_openings[signature]
            .get(&query_index)
            .expect("verifier-generated fixed opening");
        let expected = super::super::p256_scalar_bit_bus::evaluate_p256_scalar_bit_bus_stark_residues_over_field_v1(
            &base, &base, &aux, &aux, fixed_opening, source.challenges,
        ).expect("independent local scalar AIR");
        assert_eq!(residues, expected, "signature {signature} local AIR parity");
        // The eight source products are private joined-link obligations. Each
        // actual scalar endpoint still participates in the local recurrence.
        for column in super::super::p256_scalar_bit_bus::p256_scalar_bit_bus_terminal_columns_v1()
            .into_iter()
            .flatten()
        {
            let mut changed = aux;
            changed[column] = F::ONE;
            let changed_opening = RegisteredOpenedRowsV1 {
                base_current: &base,
                base_next: &base,
                aux_current: &changed,
                aux_next: &aux,
            };
            let actual = p256_scalar_opened_residues_v1(
                registration,
                changed_opening,
                fixed_opening,
                source.challenges,
            )
            .expect("mutated private scalar opening");
            let independent = super::super::p256_scalar_bit_bus::evaluate_p256_scalar_bit_bus_stark_residues_over_field_v1(
                &base, &base, &changed, &aux, fixed_opening, source.challenges,
            ).expect("independent mutated scalar AIR");
            assert_eq!(actual, independent);
            assert_ne!(
                actual, expected,
                "signature {signature}, private endpoint {column}"
            );
        }
        assert_eq!(source.fixed_openings[signature].len(), 2);
    }
    assert_eq!(
        source
            .fixed_openings
            .iter()
            .map(BTreeMap::len)
            .sum::<usize>(),
        P256_SIGNATURE_COUNT_V1 * 2
    );
}
#[test]
fn main_p256_log8_closed_provider_routes_only_the_concrete_verifier() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed =
        P256MainVerifierFixedSourceV1::new_v1().expect("shared verifier-fixed P-256 source");
    let mut scalar = MainP256ScalarVerifierConstraintSourceV1::for_main_v1(
        &layout,
        &fixed,
        p256_main_provider_post_base_fixture_v1(),
    )
    .expect("closed log8 verifier source");
    let registration = scalar.registrations[2].main;
    let query_index = 31;
    let next_query_index = scalar
        .next_query_index_v1(registration, query_index)
        .expect("canonical scalar next query");
    let root = goldilocks_primitive_root_v1(layout.common_lde_log2).expect("MAIN common root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
    let base = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1];
    let aux = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let mut log5 = MockMainTraceGroupSourceV1::default();
    let mut log15 = MockMainTraceGroupSourceV1::default();
    let mut log16 = MockMainTraceGroupSourceV1::default();
    let mut log18 = MockMainTraceGroupSourceV1::default();
    let mut log19 = MockMainTraceGroupSourceV1::default();
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        vec![
            MainOpenedGroupProviderV1::TestLog5(&mut log5),
            MainOpenedGroupProviderV1::P256Scalar(&mut scalar),
            MainOpenedGroupProviderV1::TestLog15(&mut log15),
            MainOpenedGroupProviderV1::TestLog16(&mut log16),
            MainOpenedGroupProviderV1::TestLog18(&mut log18),
            MainOpenedGroupProviderV1::TestLog19(&mut log19),
        ],
    )
    .expect("exact closed MAIN providers");
    let residues = providers
        .registered_constraint_residues_v1(registration, query_index, next_query_index, x, opening)
        .expect("production concrete log8 route");
    assert_eq!(
        residues.len(),
        P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1
    );
}
#[test]
fn main_p256_log8_verifier_rejects_adversarial_inputs_before_sampling() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed =
        P256MainVerifierFixedSourceV1::new_v1().expect("shared verifier-fixed P-256 source");
    let claims = p256_main_terminal_claims_fixture_v1();
    let mut source = MainP256ScalarVerifierConstraintSourceV1::for_main_v1(
        &layout,
        &fixed,
        p256_main_provider_post_base_fixture_v1(),
    )
    .expect("closed log8 verifier source");
    let registration = source.registrations[0].main;
    let query_index = 23;
    let next_query_index = source
        .next_query_index_v1(registration, query_index)
        .expect("canonical scalar next query");
    let root = goldilocks_primitive_root_v1(layout.common_lde_log2).expect("MAIN common root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
    let base = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1];
    let aux = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let wrong_registration = layout
        .registered_segment(SegmentAdapterIdV1::Projection, 0)
        .expect("projection registration");
    assert!(
        source
            .constraint_residues_v1(
                wrong_registration,
                query_index,
                next_query_index,
                x,
                opening,
            )
            .is_err()
    );
    assert!(
        source
            .constraint_residues_v1(registration, query_index, next_query_index ^ 1, x, opening,)
            .is_err()
    );
    assert!(
        source
            .constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x.add(F::ONE),
                opening,
            )
            .is_err()
    );
    let short_base = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1 - 1];
    let short_opening = RegisteredOpenedRowsV1 {
        base_current: &short_base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    assert!(
        source
            .constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x,
                short_opening,
            )
            .is_err()
    );
    let mut noncanonical_aux = aux;
    noncanonical_aux[0] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
    let noncanonical_opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &noncanonical_aux,
        aux_next: &aux,
    };
    assert!(
        source
            .constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x,
                noncanonical_opening,
            )
            .is_err()
    );
    assert!(
        source.fixed_openings.iter().all(BTreeMap::is_empty),
        "rejected requests must not consume verifier fixed-opening capacity"
    );
    let mut inconsistent = claims;
    inconsistent.certificate_or_crl[0]
        .buses
        .scalar_bus_arithmetic[0] = inconsistent.certificate_or_crl[0]
        .buses
        .scalar_bus_arithmetic[0]
        .add(F::ONE);
    assert!(
        main_p256_terminal_registrations_v1(&inconsistent).is_err(),
        "inconsistent private products must reject at their private owner boundary"
    );
}
#[test]
fn main_p256_log8_verifier_fixed_cache_is_bounded_per_signature() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed =
        P256MainVerifierFixedSourceV1::new_v1().expect("shared verifier-fixed P-256 source");
    let mut source = MainP256ScalarVerifierConstraintSourceV1::for_main_v1(
        &layout,
        &fixed,
        p256_main_provider_post_base_fixture_v1(),
    )
    .expect("closed log8 verifier source");
    let first = source.registrations[0];
    for pair in 0..(VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 / 2) {
        source
            .ensure_fixed_openings_v1(first, [pair * 2, pair * 2 + 1])
            .expect("bounded unique scalar fixed openings");
    }
    assert_eq!(
        source.fixed_openings[0].len(),
        VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1
    );
    let snapshot = source.fixed_openings[0].clone();
    assert!(
        source
            .ensure_fixed_openings_v1(
                first,
                [
                    VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1,
                    VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 + 1,
                ],
            )
            .is_err()
    );
    assert_eq!(source.fixed_openings[0], snapshot);
    let second = source.registrations[1];
    source
        .ensure_fixed_openings_v1(second, [0, 1])
        .expect("separate signature owns a separate bounded cache");
    assert_eq!(source.fixed_openings[1].len(), 2);
}
#[test]
fn main_p256_log8_shared_central_source_matches_prover_and_verifier() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let mut central = p256_main_base_source_fixture_v1();
    let first_registration =
        main_p256_scalar_registrations_v1(&layout).expect("five scalar registrations")[0];
    {
        let base_view = MainP256ScalarTraceGroupSourceV1::for_base_v1(&layout, &central)
            .expect("borrowed pre-X5B1 scalar view");
        let column = base_view
            .native_base_column_v1(first_registration.main, 0)
            .expect("challenge-independent scalar base column");
        let mut direct = vec![F::ZERO; first_registration.main.segment.trace_size()];
        central
            .fill_base_column_v1(first_registration.p256, 0, &mut direct)
            .expect("central scalar base column");
        assert_eq!(&*column, direct.as_slice());
        assert!(matches!(
            base_view.native_aux_column_v1(first_registration.main, 0),
            Err(ZkX509StarkErrorV1::TranscriptMismatch)
        ));
    }
    let post_base = p256_main_provider_post_base_fixture_v1();
    let bound = central
        .bind_v1(post_base)
        .expect("single opaque central P-256 phase transition");
    let mut trace = MainP256ScalarTraceGroupSourceV1::for_bound_v1(&layout, &bound)
        .expect("borrowed bound scalar view");
    let prover = MainP256ScalarProverConstraintSourceV1::for_main_v1(&layout, &bound)
        .expect("bound scalar prover source");
    let fixed =
        P256MainVerifierFixedSourceV1::new_v1().expect("shared verifier-fixed P-256 source");
    let mut verifier =
        MainP256ScalarVerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
            .expect("witness-free scalar verifier");
    let mut streamed_fixed = 0_usize;
    prover
        .stream_fixed_polynomials_v1(|registration, column, coefficients| {
            assert_eq!(
                registration.segment.adapter,
                SegmentAdapterIdV1::P256ScalarBitBus
            );
            assert!(column < P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1);
            assert_eq!(coefficients.len(), registration.segment.trace_size());
            streamed_fixed += 1;
            Ok(())
        })
        .expect("all scalar fixed polynomials");
    assert_eq!(
        streamed_fixed,
        P256_SIGNATURE_COUNT_V1 * P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1
    );
    let root = goldilocks_primitive_root_v1(layout.common_lde_log2).expect("MAIN common root");
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        let registration = verifier.registrations[signature].main;
        let query_index = 43 + signature;
        let next_query_index = verifier
            .next_query_index_v1(registration, query_index)
            .expect("canonical scalar next query");
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        let base_columns = (0..registration.segment.base_width)
            .map(|column| trace.native_base_column_v1(registration, column))
            .collect::<Result<Vec<_>, _>>()
            .expect("bound scalar base columns");
        let aux_columns = (0..registration.segment.aux_width)
            .map(|column| trace.native_aux_column_v1(registration, column))
            .collect::<Result<Vec<_>, _>>()
            .expect("bound scalar auxiliary columns");
        let evaluate = |columns: &[ZeroizingMainTraceColumnV1], index: usize| {
            columns
                .iter()
                .map(|column| {
                    evaluate_native_fixed_column_v1(
                        registration.segment,
                        layout.common_lde_log2,
                        index,
                        |row| column[row],
                    )
                })
                .collect::<Vec<_>>()
        };
        let base_current = evaluate(&base_columns, query_index);
        let base_next = evaluate(&base_columns, next_query_index);
        let aux_current = evaluate(&aux_columns, query_index);
        let aux_next = evaluate(&aux_columns, next_query_index);
        let opening = RegisteredOpenedRowsV1 {
            base_current: &base_current,
            base_next: &base_next,
            aux_current: &aux_current,
            aux_next: &aux_next,
        };
        let verifier_residues = verifier
            .constraint_residues_v1(registration, query_index, next_query_index, x, opening)
            .expect("witness-free verifier residues");
        let verifier_fixed = verifier.fixed_openings[signature]
            .get(&query_index)
            .expect("verifier-generated fixed opening");
        let prover_residues = prover
            .constraint_residues_v1(registration, opening, verifier_fixed)
            .expect("prover residues over identical openings");
        assert_eq!(
            verifier_residues, prover_residues,
            "signature {signature} prover/verifier scalar residues"
        );
        assert_eq!(
            verifier_residues.len(),
            P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1
        );
        let alphas = vec![E::ONE; registration.segment.constraint_count];
        assert_eq!(
            prover
                .composition_value_v1(registration, x, opening, verifier_fixed, &alphas,)
                .expect("scalar prover composition"),
            accumulator_quotient_value_v1(registration.segment, x, &prover_residues, &alphas,)
                .expect("direct scalar quotient")
        );
    }
    let mut routed = MainTraceGroupProviderV1::P256Scalar(&mut trace);
    assert_eq!(routed.native_trace_log2_v1(), 8);
    assert_eq!(
        routed
            .source_mut_v1()
            .native_aux_column_v1(first_registration.main, 0)
            .expect("closed production log8 trace route")
            .len(),
        first_registration.main.segment.trace_size()
    );
}
fn evaluate_native_fixed_column_v1(
    segment: SegmentLayoutV1,
    common_lde_log2: u8,
    index: usize,
    mut native_value: impl FnMut(usize) -> F,
) -> F {
    let trace_root = goldilocks_primitive_root_v1(segment.trace_log2).expect("native trace root");
    let common_root = goldilocks_primitive_root_v1(common_lde_log2).expect("common LDE root");
    let mut coefficients = (0..segment.trace_size())
        .map(|row| native_value(row))
        .collect::<Vec<_>>();
    goldilocks_ifft_v1(&mut coefficients, trace_root).expect("fixed-column interpolation");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(index as u128));
    coefficients
        .iter()
        .rev()
        .fold(F::ZERO, |value, coefficient| value.mul(x).add(*coefficient))
}
fn evaluate_main_p256_log5_zero_opening_v1(
    source: &mut MainP256Log5VerifierConstraintSourceV1<'_>,
    registration: RegisteredSegmentLayoutV1,
    query_index: usize,
) -> Result<Vec<F>, ZkX509StarkErrorV1> {
    let registration_index = source.binding_index_v1(registration)?;
    let next_query_index = source.next_query_index_v1(registration_index, query_index)?;
    let root = goldilocks_primitive_root_v1(source.common_lde_log2).expect("common MAIN LDE root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
    let base_current = vec![F::ZERO; registration.segment.base_width];
    let base_next = vec![F::ZERO; registration.segment.base_width];
    let aux_current = vec![F::ZERO; registration.segment.aux_width];
    let aux_next = vec![F::ZERO; registration.segment.aux_width];
    source.constraint_residues_v1(
        registration,
        query_index,
        next_query_index,
        x,
        RegisteredOpenedRowsV1 {
            base_current: &base_current,
            base_next: &base_next,
            aux_current: &aux_current,
            aux_next: &aux_next,
        },
    )
}
#[test]
fn main_p256_log5_registration_order_widths_and_fixed_ranges_are_exact() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let bindings =
        canonical_p256_main_log5_bindings_v1(&layout).expect("canonical log-five bindings");
    assert_eq!(bindings.len(), P256_MAIN_LOG5_REGISTRATION_COUNT_V1);
    assert_eq!(
        bindings
            .iter()
            .map(|binding| (
                binding.p256.signature_v1(),
                binding.p256.adapter_v1(),
                binding.p256.local_instance_v1(),
            ))
            .collect::<Vec<_>>(),
        [
            (0, P256MainAdapterV1::Reduction, 0),
            (0, P256MainAdapterV1::Reduction, 1),
            (1, P256MainAdapterV1::Reduction, 0),
            (1, P256MainAdapterV1::Reduction, 1),
            (2, P256MainAdapterV1::Reduction, 0),
            (2, P256MainAdapterV1::Reduction, 1),
            (3, P256MainAdapterV1::Reduction, 0),
            (3, P256MainAdapterV1::Reduction, 1),
            (4, P256MainAdapterV1::Reduction, 0),
            (4, P256MainAdapterV1::Reduction, 1),
            (4, P256MainAdapterV1::WalletLowS, 0),
        ]
    );
    let mut next_base = 0;
    let mut next_aux = 0;
    for binding in bindings.iter().copied() {
        assert_eq!(binding.main.base_start, next_base);
        assert_eq!(binding.main.aux_start, next_aux);
        assert_eq!(
            p256_main_registration_from_main_layout_v1(binding.main)
                .expect("shared MAIN-to-P256 mapping"),
            binding.p256
        );
        next_base = binding.main.base_end().expect("base end");
        next_aux = binding.main.aux_end().expect("aux end");
    }
    assert_eq!(next_base, P256_MAIN_LOG5_BASE_WIDTH_V1);
    assert_eq!(next_aux, P256_MAIN_LOG5_AUX_WIDTH_V1);
    let fixed = P256MainVerifierFixedSourceV1::new_v1().expect("verifier-owned P-256 fixed source");
    for binding in bindings.iter().copied() {
        let shape = binding.p256.shape_v1().expect("canonical P-256 shape");
        let mut output = vec![F::ZERO; shape.trace_size];
        fixed
            .fill_fixed_column_v1(binding.p256, shape.fixed_width - 1, &mut output)
            .expect("last fixed column");
        assert!(
            fixed
                .fill_fixed_column_v1(binding.p256, shape.fixed_width, &mut output)
                .is_err(),
            "registration {:?} accepted fixed column at its exclusive end",
            binding.p256
        );
        output.pop();
        assert!(
            fixed
                .fill_fixed_column_v1(binding.p256, 0, &mut output)
                .is_err(),
            "registration {:?} accepted a short fixed column",
            binding.p256
        );
    }
    let log5_index = layout
        .registered_segments
        .iter()
        .position(|registration| *registration == bindings[0].main)
        .expect("log-five registration position");
    let mutations: [fn(&mut RegisteredSegmentLayoutV1); 5] = [
        |registration: &mut RegisteredSegmentLayoutV1| {
            registration.base_start = registration.base_start.saturating_add(1);
        },
        |registration: &mut RegisteredSegmentLayoutV1| {
            registration.aux_start = registration.aux_start.saturating_add(1);
        },
        |registration: &mut RegisteredSegmentLayoutV1| {
            registration.segment.instance = registration.segment.instance.saturating_add(1);
        },
        |registration: &mut RegisteredSegmentLayoutV1| {
            registration.segment.base_width = registration.segment.base_width.saturating_add(1);
        },
        |registration: &mut RegisteredSegmentLayoutV1| {
            registration.segment.fixed_width = registration.segment.fixed_width.saturating_add(1);
        },
    ];
    for mutate in mutations {
        let mut forged = layout.clone();
        mutate(&mut forged.registered_segments[log5_index]);
        assert!(canonical_p256_main_log5_bindings_v1(&forged).is_err());
    }
}
#[test]
fn main_p256_log5_central_trace_views_and_prover_are_end_to_end_closed() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let bindings =
        canonical_p256_main_log5_bindings_v1(&layout).expect("canonical log-five bindings");
    let mut base_source = p256_main_base_source_fixture_v1();
    {
        let mut routed_view = MainP256Log5TraceGroupSourceV1::for_base_v1(&layout, &base_source)
            .expect("routed pre-X5B1 log-five view");
        let mut provider = MainTraceGroupProviderV1::Log5(&mut routed_view);
        assert_eq!(provider.native_trace_log2_v1(), 5);
        let routed = provider
            .source_mut_v1()
            .native_base_column_v1(bindings[0].main, 0)
            .expect("closed log-five trace-provider route");
        assert_eq!(routed.len(), bindings[0].main.segment.trace_size());
    }
    let mut base_parity = Vec::new();
    base_parity
        .try_reserve_exact(P256_MAIN_LOG5_REGISTRATION_COUNT_V1)
        .expect("bounded base-parity fixture");
    {
        let base_view = MainP256Log5TraceGroupSourceV1::for_base_v1(&layout, &base_source)
            .expect("pre-X5B1 log-five view");
        for binding in bindings.iter().copied() {
            let mut column = base_view
                .native_base_column_v1(binding.main, binding.main.segment.base_width - 1)
                .expect("last challenge-independent column");
            assert_eq!(column.len(), binding.main.segment.trace_size());
            column.zeroize_private_v1();
            assert!(column.is_empty());
            base_parity.push((
                binding.main,
                base_view
                    .native_base_column_v1(binding.main, binding.main.segment.base_width - 1)
                    .expect("retained zeroizing base-parity column"),
            ));
            assert!(
                base_view
                    .native_base_column_v1(binding.main, binding.main.segment.base_width)
                    .is_err()
            );
            assert!(matches!(
                base_view.native_aux_column_v1(binding.main, 0),
                Err(ZkX509StarkErrorV1::TranscriptMismatch)
            ));
            assert!(
                base_view
                    .native_aux_column_v1(binding.main, binding.main.segment.aux_width)
                    .is_err()
            );
        }
    }
    let post_base = p256_main_provider_post_base_fixture_v1();
    let mut bound = base_source
        .bind_v1(post_base)
        .expect("single central P-256 phase transition");
    {
        let bound_view = MainP256Log5TraceGroupSourceV1::for_bound_v1(&layout, &bound)
            .expect("post-X5B1 log-five view");
        let prover = MainP256Log5ProverConstraintSourceV1::for_main_v1(&layout, &bound)
            .expect("bound log-five prover");
        let mut streamed = 0;
        prover
            .stream_fixed_polynomials_v1(|registration, local_column, coefficients| {
                assert!(bindings.iter().any(|binding| binding.main == registration));
                assert!(local_column < registration.segment.fixed_width);
                assert_eq!(coefficients.len(), registration.segment.trace_size());
                streamed += 1;
                Ok(())
            })
            .expect("all verifier-owned log-five fixed polynomials");
        assert_eq!(
            streamed,
            10 * P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1 + P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1
        );
        for binding in bindings.iter().copied() {
            let before_binding = base_parity
                .iter()
                .find(|(registration, _)| *registration == binding.main)
                .expect("pre-bind base parity column");
            let after_binding = bound_view
                .native_base_column_v1(binding.main, binding.main.segment.base_width - 1)
                .expect("post-bind base parity column");
            assert_eq!(&*after_binding, &*before_binding.1);
            assert!(
                bound_view
                    .native_base_column_v1(binding.main, binding.main.segment.base_width)
                    .is_err()
            );
            assert!(
                bound_view
                    .native_aux_column_v1(binding.main, binding.main.segment.aux_width)
                    .is_err()
            );
            let mut invalid_fixed = vec![F::ZERO; binding.main.segment.trace_size()];
            assert!(
                bound
                    .fill_fixed_column_v1(
                        binding.p256,
                        binding.main.segment.fixed_width,
                        &mut invalid_fixed,
                    )
                    .is_err()
            );
            let mut base_columns = Vec::new();
            base_columns
                .try_reserve_exact(binding.main.segment.base_width)
                .expect("bounded test base columns");
            for column in 0..binding.main.segment.base_width {
                base_columns.push(
                    bound_view
                        .native_base_column_v1(binding.main, column)
                        .expect("bound base replay"),
                );
            }
            let mut aux_columns = Vec::new();
            aux_columns
                .try_reserve_exact(binding.main.segment.aux_width)
                .expect("bounded test auxiliary columns");
            for column in 0..binding.main.segment.aux_width {
                aux_columns.push(
                    bound_view
                        .native_aux_column_v1(binding.main, column)
                        .expect("bound auxiliary replay"),
                );
            }
            let mut fixed_columns = Vec::new();
            fixed_columns
                .try_reserve_exact(binding.main.segment.fixed_width)
                .expect("bounded test fixed columns");
            for column in 0..binding.main.segment.fixed_width {
                let mut values = vec![F::ZERO; binding.main.segment.trace_size()];
                bound
                    .fill_fixed_column_v1(binding.p256, column, &mut values)
                    .expect("verifier-owned fixed replay");
                fixed_columns.push(values);
            }
            for row in 0..binding.main.segment.trace_size() {
                let next = (row + 1) % binding.main.segment.trace_size();
                let base_current = base_columns
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>();
                let base_next = base_columns
                    .iter()
                    .map(|column| column[next])
                    .collect::<Vec<_>>();
                let aux_current = aux_columns
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>();
                let aux_next = aux_columns
                    .iter()
                    .map(|column| column[next])
                    .collect::<Vec<_>>();
                let fixed_row = fixed_columns
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>();
                let opening = RegisteredOpenedRowsV1 {
                    base_current: &base_current,
                    base_next: &base_next,
                    aux_current: &aux_current,
                    aux_next: &aux_next,
                };
                let residues = prover
                    .constraint_residues_v1(binding.main, opening, &fixed_row)
                    .expect("native log-five residues");
                assert_eq!(residues.len(), binding.main.segment.constraint_count);
                assert!(
                    residues.iter().all(|residue| *residue == F::ZERO),
                    "registration {:?}, native row {row}",
                    binding.p256,
                );
                let alphas = vec![E::ONE; binding.main.segment.constraint_count];
                assert_eq!(
                    prover
                        .composition_value_v1(
                            binding.main,
                            F(GOLDILOCKS_GENERATOR_V1),
                            opening,
                            &fixed_row,
                            &alphas,
                        )
                        .expect("zero native composition"),
                    E::ZERO
                );
            }
        }
    }
    for (_, column) in &mut base_parity {
        column.zeroize_private_v1();
    }
    base_parity.clear();
    bound.zeroize_private_v1();
    assert!(MainP256Log5TraceGroupSourceV1::for_bound_v1(&layout, &bound).is_err());
}
#[test]
fn main_p256_log5_verifier_fixed_sampling_is_exact_bounded_and_transactional() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed = P256MainVerifierFixedSourceV1::new_v1().expect("verifier-owned P-256 fixed source");
    let post_base = p256_main_provider_post_base_fixture_v1();
    {
        let mut routed =
            MainP256Log5VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
                .expect("routed log-five verifier source");
        let registration = routed.bindings[0].main;
        let query_index = 5;
        let next_query_index = routed
            .next_query_index_v1(0, query_index)
            .expect("routed next coordinate");
        let root = goldilocks_primitive_root_v1(layout.common_lde_log2).expect("common MAIN root");
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        let base = vec![F::ZERO; registration.segment.base_width];
        let aux = vec![F::ZERO; registration.segment.aux_width];
        let opening = RegisteredOpenedRowsV1 {
            base_current: &base,
            base_next: &base,
            aux_current: &aux,
            aux_next: &aux,
        };
        let mut provider = MainOpenedGroupProviderV1::Log5(&mut routed);
        assert_eq!(provider.native_trace_log2_v1(), 5);
        assert_eq!(
            provider
                .constraint_residues_v1(registration, query_index, next_query_index, x, opening,)
                .expect("closed log-five verifier-provider route")
                .len(),
            registration.segment.constraint_count
        );
    }
    let mut source =
        MainP256Log5VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
            .expect("canonical log-five verifier source");
    let bindings = source.bindings.clone();
    for (registration_index, binding) in bindings.iter().copied().enumerate() {
        let query_index = registration_index * 13 + 7;
        let next_query_index = source
            .next_query_index_v1(registration_index, query_index)
            .expect("canonical next coordinate");
        let residues =
            evaluate_main_p256_log5_zero_opening_v1(&mut source, binding.main, query_index)
                .expect("closed log-five residue evaluation");
        assert_eq!(residues.len(), binding.main.segment.constraint_count);
        assert_eq!(source.cached_openings_v1(registration_index), Some(2));
        let cache = &source.fixed_openings[registration_index];
        for index in [query_index, next_query_index] {
            let opened = cache.get(&index).expect("verifier-minted fixed opening");
            assert_eq!(opened.len(), binding.main.segment.fixed_width);
            for column in 0..binding.main.segment.fixed_width {
                assert_eq!(
                    opened[column],
                    evaluate_native_fixed_column_v1(
                        binding.main.segment,
                        layout.common_lde_log2,
                        index,
                        |row| {
                            fixed
                                .fixed_cell_v1(binding.p256, row, column)
                                .expect("verifier-owned native fixed cell")
                        },
                    ),
                    "registration {registration_index}, query {index}, fixed column {column}",
                );
            }
        }
    }
    let mut rejected =
        MainP256Log5VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
            .expect("fresh log-five verifier source");
    let canonical = rejected.bindings[0].main;
    let mut forged_slice = canonical;
    forged_slice.base_start = forged_slice.base_start.saturating_add(1);
    let mut forged_instance = canonical;
    forged_instance.segment.instance = forged_instance.segment.instance.saturating_add(1);
    let mut forged_adapter = canonical;
    forged_adapter.segment.adapter = SegmentAdapterIdV1::P256LowS;
    for forged in [forged_slice, forged_instance, forged_adapter] {
        assert!(evaluate_main_p256_log5_zero_opening_v1(&mut rejected, forged, 0).is_err());
        assert_eq!(rejected.cached_openings_v1(0), Some(0));
    }
    let registration_index = rejected
        .binding_index_v1(canonical)
        .expect("canonical registration");
    let query_index = 3;
    let next_query_index = rejected
        .next_query_index_v1(registration_index, query_index)
        .expect("canonical next coordinate");
    let root = goldilocks_primitive_root_v1(layout.common_lde_log2).expect("common MAIN root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
    let base = vec![F::ZERO; canonical.segment.base_width];
    let aux = vec![F::ZERO; canonical.segment.aux_width];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    assert!(
        rejected
            .constraint_residues_v1(
                canonical,
                query_index,
                (next_query_index + 1) % layout.common_lde_size(),
                x,
                opening,
            )
            .is_err()
    );
    assert_eq!(rejected.cached_openings_v1(0), Some(0));
    assert!(
        rejected
            .constraint_residues_v1(
                canonical,
                query_index,
                next_query_index,
                x.add(F::ONE),
                opening,
            )
            .is_err()
    );
    assert_eq!(rejected.cached_openings_v1(0), Some(0));
    let mut noncanonical = base.clone();
    noncanonical[0] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
    assert!(
        rejected
            .constraint_residues_v1(
                canonical,
                query_index,
                next_query_index,
                x,
                RegisteredOpenedRowsV1 {
                    base_current: &noncanonical,
                    base_next: &base,
                    aux_current: &aux,
                    aux_next: &aux,
                },
            )
            .is_err()
    );
    assert_eq!(rejected.cached_openings_v1(0), Some(0));
    let mut bounded =
        MainP256Log5VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
            .expect("fresh bounded log-five verifier source");
    let stride = 1_usize << (layout.common_lde_log2 - 5);
    for query in 0..(VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 / 2) {
        bounded
            .ensure_fixed_openings_v1(0, [query, query + stride])
            .expect("opening within the exact verifier bound");
    }
    assert_eq!(
        bounded.cached_openings_v1(0),
        Some(VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
    );
    assert!(
        bounded
            .ensure_fixed_openings_v1(
                0,
                [
                    VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 / 2,
                    VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 / 2 + stride,
                ],
            )
            .is_err()
    );
    assert_eq!(
        bounded.cached_openings_v1(0),
        Some(VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
    );
}
/// Mutate a private endpoint's real auxiliary column at the fixed last row.
/// This isolates the local recurrence; joined equality has its separate tests.
fn assert_p256_private_endpoint_local_recurrence_v1(
    registration: RegisteredSegmentLayoutV1,
    identity: P256MainRegistrationV1,
    fixed_source: &P256MainVerifierFixedSourceV1,
    challenges: P256AggregateChallengesV1,
    family: super::super::p256_aggregate_adapter::P256PrivateLinkFamilyV1,
) {
    let fixed = fixed_source
        .fixed_row_v1(identity, registration.segment.trace_size() - 1)
        .expect("verifier-owned final native row");
    let base = vec![F::ZERO; registration.segment.base_width];
    let aux = vec![F::ZERO; registration.segment.aux_width];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let baseline = p256_opened_residues_v1(registration, opening, &fixed, challenges)
        .expect("canonical-shaped local opening");
    assert_eq!(baseline.len(), registration.segment.constraint_count);
    let columns =
        super::super::p256_aggregate_adapter::p256_private_link_columns_v1(identity, family)
            .expect("fixed private endpoint columns");
    for column in columns {
        let mut changed = aux.clone();
        changed[column] = F::ONE;
        // Change both constant copies so the test isolates final-row binding,
        // rather than relying on the adjacent-row constancy constraint alone.
        let altered = RegisteredOpenedRowsV1 {
            base_current: &base,
            base_next: &base,
            aux_current: &changed,
            aux_next: &changed,
        };
        let residues = p256_opened_residues_v1(registration, altered, &fixed, challenges)
            .expect("canonical mutated private opening");
        assert_eq!(residues.len(), baseline.len());
        assert!(
            baseline
                .iter()
                .zip(&residues)
                .any(|(before, after)| *before == F::ZERO && *after != F::ZERO),
            "private endpoint {identity:?}/{family:?}/{column} escaped its local final-row relation"
        );
        changed[column] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
        assert!(
            p256_opened_residues_v1(
                registration,
                RegisteredOpenedRowsV1 {
                    base_current: &base,
                    base_next: &base,
                    aux_current: &changed,
                    aux_next: &aux,
                },
                &fixed,
                challenges
            )
            .is_err()
        );
    }
    assert!(
        p256_opened_residues_v1(
            registration,
            RegisteredOpenedRowsV1 {
                base_current: &base,
                base_next: &base,
                aux_current: &aux[..aux.len() - 1],
                aux_next: &aux,
            },
            &fixed,
            challenges
        )
        .is_err()
    );
}

#[test]
fn main_p256_log5_private_chain_forgeries_require_local_recurrences() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed = P256MainVerifierFixedSourceV1::new_v1().expect("verifier-owned P-256 fixed source");
    let post_base = p256_main_provider_post_base_fixture_v1();
    let canonical_claims = p256_main_terminal_claims_fixture_v1();
    for (registration_index, mut forged_claims) in [
        (0, canonical_claims),
        (P256_MAIN_LOG5_REGISTRATION_COUNT_V1 - 1, canonical_claims),
    ] {
        if registration_index == 0 {
            forged_claims.certificate_or_crl[0].cross_sources[2].terminal[0] = F::ONE;
            forged_claims.certificate_or_crl[0].cross_sources[3].start[0] = F::ONE;
        } else {
            forged_claims.wallet.cross_sources[4].terminal[0] = F::ONE;
            forged_claims.wallet.sink[0] = F::ONE;
        }
        main_p256_terminal_registrations_v1(&forged_claims)
            .expect("coordinated host-side chain remains equal");
        let verifier =
            MainP256Log5VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
                .expect("private log-five verifier source");
        let binding = verifier.bindings[registration_index];
        assert_p256_private_endpoint_local_recurrence_v1(
            binding.main,
            binding.p256,
            &fixed,
            verifier.challenges,
            super::super::p256_aggregate_adapter::P256PrivateLinkFamilyV1::ChainTerminal,
        );
    }
}
fn evaluate_main_p256_log16_zero_opening_v1(
    source: &mut MainP256Log16VerifierConstraintSourceV1<'_>,
    registration: RegisteredSegmentLayoutV1,
    query_index: usize,
) -> Result<Vec<F>, ZkX509StarkErrorV1> {
    let registration_index = source.binding_index_v1(registration)?;
    let next_query_index = source.next_query_index_v1(registration_index, query_index)?;
    let root = goldilocks_primitive_root_v1(source.common_lde_log2).expect("common MAIN LDE root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
    let base_current = vec![F::ZERO; registration.segment.base_width];
    let base_next = vec![F::ZERO; registration.segment.base_width];
    let aux_current = vec![F::ZERO; registration.segment.aux_width];
    let aux_next = vec![F::ZERO; registration.segment.aux_width];
    source.constraint_residues_v1(
        registration,
        query_index,
        next_query_index,
        x,
        RegisteredOpenedRowsV1 {
            base_current: &base_current,
            base_next: &base_next,
            aux_current: &aux_current,
            aux_next: &aux_next,
        },
    )
}
#[test]
fn main_p256_log16_registration_order_ranges_and_stride_are_exact() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let bindings =
        canonical_p256_main_log16_bindings_v1(&layout).expect("canonical log-sixteen bindings");
    assert_eq!(bindings.len(), P256_MAIN_LOG16_REGISTRATION_COUNT_V1);
    assert_eq!(
        bindings
            .iter()
            .map(|binding| (
                binding.p256.signature_v1(),
                binding.p256.adapter_v1(),
                binding.p256.local_instance_v1(),
            ))
            .collect::<Vec<_>>(),
        [
            (0, P256MainAdapterV1::WindowBatch, 0),
            (1, P256MainAdapterV1::WindowBatch, 0),
            (2, P256MainAdapterV1::WindowBatch, 0),
            (3, P256MainAdapterV1::WindowBatch, 0),
            (4, P256MainAdapterV1::WindowBatch, 0),
            (0, P256MainAdapterV1::BindingSink, 0),
            (1, P256MainAdapterV1::BindingSink, 0),
            (2, P256MainAdapterV1::BindingSink, 0),
            (3, P256MainAdapterV1::BindingSink, 0),
            (4, P256MainAdapterV1::BindingSink, 0),
        ]
    );
    assert_eq!(
        bindings
            .iter()
            .map(|binding| binding.main.base_start)
            .collect::<Vec<_>>(),
        [0, 61, 122, 183, 244, 305, 330, 355, 380, 405]
    );
    assert_eq!(
        bindings
            .iter()
            .map(|binding| binding.main.aux_start)
            .collect::<Vec<_>>(),
        [0, 37, 74, 111, 148, 185, 223, 261, 299, 337]
    );
    let mut next_base = 0;
    let mut next_aux = 0;
    for binding in bindings.iter().copied() {
        assert_eq!(binding.main.base_start, next_base);
        assert_eq!(binding.main.aux_start, next_aux);
        assert_eq!(
            p256_main_registration_from_main_layout_v1(binding.main)
                .expect("shared MAIN-to-P256 mapping"),
            binding.p256
        );
        next_base = binding.main.base_end().expect("base end");
        next_aux = binding.main.aux_end().expect("aux end");
    }
    assert_eq!(next_base, P256_MAIN_LOG16_BASE_WIDTH_V1);
    assert_eq!(next_aux, P256_MAIN_LOG16_AUX_WIDTH_V1);
    let group = layout.trace_groups[bindings[0].main.trace_group];
    assert_eq!(group.base_width, P256_MAIN_LOG16_BASE_WIDTH_V1);
    assert_eq!(group.aux_width, P256_MAIN_LOG16_AUX_WIDTH_V1);
    assert_eq!(group.column_chunks, P256_MAIN_LOG16_PHYSICAL_CHUNKS_V1);
    let fixed = P256MainVerifierFixedSourceV1::new_v1().expect("verifier-owned P-256 fixed source");
    for binding in bindings.iter().copied() {
        let shape = binding.p256.shape_v1().expect("canonical P-256 shape");
        assert!(
            fixed
                .fixed_cell_v1(binding.p256, shape.trace_size - 1, shape.fixed_width - 1)
                .is_ok()
        );
        assert!(
            fixed
                .fixed_cell_v1(binding.p256, shape.trace_size, 0)
                .is_err()
        );
        assert!(
            fixed
                .fixed_cell_v1(binding.p256, 0, shape.fixed_width)
                .is_err()
        );
    }
    let source = MainP256Log16VerifierConstraintSourceV1::for_main_v1(
        &layout,
        &fixed,
        p256_main_provider_post_base_fixture_v1(),
    )
    .expect("canonical log-sixteen verifier");
    assert_eq!(
        source
            .next_query_index_v1(0, 7)
            .expect("exact non-wrapping stride"),
        7 + P256_MAIN_LOG16_NEXT_STRIDE_V1
    );
    assert_eq!(
        source
            .next_query_index_v1(
                9,
                layout.common_lde_size() - P256_MAIN_LOG16_NEXT_STRIDE_V1 / 2,
            )
            .expect("exact wrapping stride"),
        P256_MAIN_LOG16_NEXT_STRIDE_V1 / 2
    );
    let window_position = layout
        .registered_segments
        .iter()
        .position(|registration| *registration == bindings[0].main)
        .expect("first window position");
    let sink_position = layout
        .registered_segments
        .iter()
        .position(|registration| *registration == bindings[5].main)
        .expect("first sink position");
    let mut forgeries = Vec::new();
    let mut forged = layout.clone();
    forged.registered_segments[window_position].base_start += 1;
    forgeries.push(forged);
    let mut forged = layout.clone();
    forged.registered_segments[window_position].aux_start += 1;
    forgeries.push(forged);
    let mut forged = layout.clone();
    forged.registered_segments[window_position]
        .segment
        .fixed_width += 1;
    forgeries.push(forged);
    let mut forged = layout.clone();
    forged.registered_segments[sink_position].segment.instance -= 1;
    forgeries.push(forged);
    let mut forged = layout.clone();
    forged
        .registered_segments
        .swap(window_position, sink_position);
    forgeries.push(forged);
    let mut forged = layout.clone();
    forged.trace_groups[bindings[0].main.trace_group].column_chunks += 1;
    forgeries.push(forged);
    for forged in &forgeries {
        assert!(
            canonical_p256_main_log16_bindings_v1(forged).is_err(),
            "every caller-shaped range or topology mutation must reject"
        );
    }
}
#[test]
fn main_p256_log16_borrowed_phases_prover_and_verifier_match() {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("main-p256-log16".to_owned())
            .stack_size(32 * 1024 * 1024)
            .spawn_scoped(scope, || {
                let layout =
                    AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
                let bindings = canonical_p256_main_log16_bindings_v1(&layout)
                    .expect("canonical log-sixteen bindings");
                let mut central = p256_main_base_source_fixture_v1();
                let selected = [0_usize, 7, 9];
                let mut base_parity = Vec::new();
                {
                    let mut routed_view =
                        MainP256Log16TraceGroupSourceV1::for_base_v1(&layout, &central)
                            .expect("routed pre-X5B1 log-sixteen view");
                    let mut routed = MainTraceGroupProviderV1::Log16(&mut routed_view);
                    assert_eq!(routed.native_trace_log2_v1(), 16);
                    assert_eq!(
                        routed
                            .source_mut_v1()
                            .native_base_column_v1(bindings[0].main, 0)
                            .expect("closed production log-sixteen trace route")
                            .len(),
                        bindings[0].main.segment.trace_size()
                    );
                }
                {
                    let base_view = MainP256Log16TraceGroupSourceV1::for_base_v1(&layout, &central)
                        .expect("borrowed pre-X5B1 log-sixteen view");
                    for index in selected {
                        let binding = bindings[index];
                        base_parity.push((
                            binding.main,
                            base_view
                                .native_base_column_v1(
                                    binding.main,
                                    binding.main.segment.base_width - 1,
                                )
                                .expect("challenge-independent base column"),
                        ));
                        assert!(matches!(
                            base_view.native_aux_column_v1(binding.main, 0),
                            Err(ZkX509StarkErrorV1::TranscriptMismatch)
                        ));
                        assert!(
                            base_view
                                .native_base_column_v1(
                                    binding.main,
                                    binding.main.segment.base_width,
                                )
                                .is_err()
                        );
                        assert!(
                            base_view
                                .native_aux_column_v1(binding.main, binding.main.segment.aux_width,)
                                .is_err()
                        );
                    }
                }
                let post_base = p256_main_provider_post_base_fixture_v1();
                let mut bound = central
                    .bind_v1(post_base)
                    .expect("single opaque central P-256 phase transition");
                {
                    let bound_view = MainP256Log16TraceGroupSourceV1::for_bound_v1(&layout, &bound)
                        .expect("borrowed bound log-sixteen view");
                    for (registration, before) in &base_parity {
                        assert_eq!(
                            &*bound_view
                                .native_base_column_v1(
                                    *registration,
                                    registration.segment.base_width - 1,
                                )
                                .expect("post-bind base replay"),
                            &**before
                        );
                        assert_eq!(
                            bound_view
                                .native_aux_column_v1(*registration, 0)
                                .expect("post-bind auxiliary replay")
                                .len(),
                            registration.segment.trace_size()
                        );
                    }
                    let prover =
                        MainP256Log16ProverConstraintSourceV1::for_main_v1(&layout, &bound)
                            .expect("bound log-sixteen prover source");
                    let mut streamed = 0_usize;
                    assert!(matches!(
                        prover.stream_fixed_polynomials_v1(
                            |registration, local_column, coefficients| {
                                assert_eq!(registration, bindings[0].main);
                                assert_eq!(local_column, 0);
                                assert_eq!(coefficients.len(), registration.segment.trace_size());
                                streamed += 1;
                                Err(ZkX509StarkErrorV1::ProfileMismatch)
                            },
                        ),
                        Err(ZkX509StarkErrorV1::ProfileMismatch)
                    ));
                    assert_eq!(streamed, 1);
                    let fixed = P256MainVerifierFixedSourceV1::new_v1()
                        .expect("independent witness-free fixed source");
                    let mut verifier = MainP256Log16VerifierConstraintSourceV1::for_main_v1(
                        &layout, &fixed, post_base,
                    )
                    .expect("witness-free log-sixteen verifier source");
                    let root = goldilocks_primitive_root_v1(layout.common_lde_log2)
                        .expect("common MAIN root");
                    for registration_index in [0_usize, 7] {
                        let registration = bindings[registration_index].main;
                        let query_index = 29 + registration_index;
                        let next_query_index = verifier
                            .next_query_index_v1(registration_index, query_index)
                            .expect("canonical +64 next coordinate");
                        let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
                        let base = vec![F::ZERO; registration.segment.base_width];
                        let aux = vec![F::ZERO; registration.segment.aux_width];
                        let opening = RegisteredOpenedRowsV1 {
                            base_current: &base,
                            base_next: &base,
                            aux_current: &aux,
                            aux_next: &aux,
                        };
                        let verifier_residues = verifier
                            .constraint_residues_v1(
                                registration,
                                query_index,
                                next_query_index,
                                x,
                                opening,
                            )
                            .expect("witness-free opened residues");
                        let verifier_fixed = verifier.fixed_openings[registration_index]
                            .get(&query_index)
                            .expect("verifier-generated current fixed opening");
                        let prover_residues = prover
                            .constraint_residues_v1(registration, opening, verifier_fixed)
                            .expect("bound prover residues");
                        assert_eq!(verifier_residues, prover_residues);
                        assert_eq!(
                            verifier_residues.len(),
                            registration.segment.constraint_count
                        );
                        let alphas = vec![E::ONE; registration.segment.constraint_count];
                        assert_eq!(
                            prover
                                .composition_value_v1(
                                    registration,
                                    x,
                                    opening,
                                    verifier_fixed,
                                    &alphas,
                                )
                                .expect("bound prover composition"),
                            accumulator_quotient_value_v1(
                                registration.segment,
                                x,
                                &verifier_residues,
                                &alphas,
                            )
                            .expect("direct residue quotient")
                        );
                    }
                    let registration = bindings[0].main;
                    let query_index = 29;
                    let next_query_index = verifier
                        .next_query_index_v1(0, query_index)
                        .expect("cached +64 next coordinate");
                    let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
                    let base = vec![F::ZERO; registration.segment.base_width];
                    let aux = vec![F::ZERO; registration.segment.aux_width];
                    let opening = RegisteredOpenedRowsV1 {
                        base_current: &base,
                        base_next: &base,
                        aux_current: &aux,
                        aux_next: &aux,
                    };
                    let mut routed = MainOpenedGroupProviderV1::Log16(&mut verifier);
                    assert_eq!(routed.native_trace_log2_v1(), 16);
                    assert_eq!(
                        routed
                            .constraint_residues_v1(
                                registration,
                                query_index,
                                next_query_index,
                                x,
                                opening,
                            )
                            .expect("closed production log-sixteen verifier route")
                            .len(),
                        registration.segment.constraint_count
                    );
                }
                for (_, column) in &mut base_parity {
                    column.zeroize_private_v1();
                }
                bound.zeroize_private_v1();
                assert!(MainP256Log16TraceGroupSourceV1::for_bound_v1(&layout, &bound).is_err());
            })
            .expect("spawn large-stack log-sixteen test")
            .join()
            .expect("large-stack log-sixteen test");
    });
}
#[test]
fn main_p256_log16_verifier_sampling_is_fixed_exact_and_transactional() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed = P256MainVerifierFixedSourceV1::new_v1().expect("verifier-owned P-256 fixed source");
    let post_base = p256_main_provider_post_base_fixture_v1();
    let mut rejected =
        MainP256Log16VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
            .expect("fresh log-sixteen verifier");
    let canonical = rejected.bindings[0].main;
    let query_index = 7;
    let next_query_index = rejected
        .next_query_index_v1(0, query_index)
        .expect("canonical +64 next coordinate");
    assert_eq!(
        next_query_index - query_index,
        P256_MAIN_LOG16_NEXT_STRIDE_V1
    );
    let root = goldilocks_primitive_root_v1(layout.common_lde_log2).expect("common MAIN root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
    let base = vec![F::ZERO; canonical.segment.base_width];
    let aux = vec![F::ZERO; canonical.segment.aux_width];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let mut forged_slice = canonical;
    forged_slice.base_start += 1;
    let wrong_registration = layout
        .registered_segment(SegmentAdapterIdV1::Projection, 0)
        .expect("wrong-log registration");
    for registration in [forged_slice, wrong_registration] {
        assert!(
            rejected
                .constraint_residues_v1(registration, query_index, next_query_index, x, opening,)
                .is_err()
        );
    }
    assert!(
        rejected
            .constraint_residues_v1(
                canonical,
                layout.common_lde_size(),
                next_query_index,
                x,
                opening,
            )
            .is_err()
    );
    assert!(
        rejected
            .constraint_residues_v1(canonical, query_index, next_query_index + 1, x, opening,)
            .is_err()
    );
    assert!(
        rejected
            .constraint_residues_v1(
                canonical,
                query_index,
                next_query_index,
                x.add(F::ONE),
                opening,
            )
            .is_err()
    );
    let short_base = vec![F::ZERO; canonical.segment.base_width - 1];
    assert!(
        rejected
            .constraint_residues_v1(
                canonical,
                query_index,
                next_query_index,
                x,
                RegisteredOpenedRowsV1 {
                    base_current: &short_base,
                    base_next: &base,
                    aux_current: &aux,
                    aux_next: &aux,
                },
            )
            .is_err()
    );
    let mut noncanonical_aux = aux.clone();
    noncanonical_aux[0] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
    assert!(
        rejected
            .constraint_residues_v1(
                canonical,
                query_index,
                next_query_index,
                x,
                RegisteredOpenedRowsV1 {
                    base_current: &base,
                    base_next: &base,
                    aux_current: &noncanonical_aux,
                    aux_next: &aux,
                },
            )
            .is_err()
    );
    assert!(
        rejected.fixed_openings.iter().all(BTreeMap::is_empty),
        "all malformed coordinates and rows must reject before sampling"
    );
    let bindings = rejected.bindings.clone();
    for registration_index in [0_usize, 7] {
        let binding = bindings[registration_index];
        let query_index = 17 + registration_index;
        let next_query_index = rejected
            .next_query_index_v1(registration_index, query_index)
            .expect("canonical +64 next coordinate");
        evaluate_main_p256_log16_zero_opening_v1(&mut rejected, binding.main, query_index)
            .expect("valid witness-free fixed sampling");
        assert_eq!(rejected.cached_openings_v1(registration_index), Some(2));
        let snapshot = rejected.fixed_openings[registration_index].clone();
        evaluate_main_p256_log16_zero_opening_v1(&mut rejected, binding.main, query_index)
            .expect("fixed-opening cache reuse");
        assert_eq!(rejected.fixed_openings[registration_index], snapshot);
        for local_column in [0, binding.main.segment.fixed_width - 1] {
            let mut native = vec![F::ZERO; binding.main.segment.trace_size()];
            fixed
                .fill_fixed_column_v1(binding.p256, local_column, &mut native)
                .expect("direct verifier-owned fixed column");
            for index in [query_index, next_query_index] {
                assert_eq!(
                    rejected.fixed_openings[registration_index][&index][local_column],
                    evaluate_native_fixed_column_v1(
                        binding.main.segment,
                        layout.common_lde_log2,
                        index,
                        |row| native[row],
                    ),
                    "registration {registration_index}, query {index}, fixed column \
                         {local_column}",
                );
            }
        }
    }
    assert_eq!(rejected.cached_openings_v1(0), Some(2));
    assert_eq!(rejected.cached_openings_v1(7), Some(2));
    assert!(
        rejected
            .fixed_openings
            .iter()
            .enumerate()
            .all(|(index, cache)| matches!(index, 0 | 7) || cache.is_empty())
    );
    let mut transactional =
        MainP256Log16VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
            .expect("fresh transactional log-sixteen verifier");
    transactional.bindings[0].main.segment.fixed_width += 1;
    assert!(
        transactional
            .ensure_fixed_openings_v1(0, [0, P256_MAIN_LOG16_NEXT_STRIDE_V1])
            .is_err()
    );
    assert_eq!(transactional.cached_openings_v1(0), Some(0));
    let mut bounded =
        MainP256Log16VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
            .expect("fresh bounded log-sixteen verifier");
    let width = bounded.bindings[0].main.segment.fixed_width;
    for index in 0..VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 {
        bounded.fixed_openings[0].insert(index, vec![F::ZERO; width]);
    }
    let full_cache = bounded.fixed_openings[0].clone();
    assert!(
        bounded
            .ensure_fixed_openings_v1(
                0,
                [
                    VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1,
                    VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 + 1,
                ],
            )
            .is_err()
    );
    assert_eq!(bounded.fixed_openings[0], full_cache);
    assert!(bounded.fixed_openings[1].is_empty());
}
#[test]
fn main_p256_log16_private_forgeries_require_window_and_sink_recurrences() {
    use super::super::p256_aggregate_adapter::P256PrivateLinkFamilyV1 as Family;
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let fixed = P256MainVerifierFixedSourceV1::new_v1().expect("verifier-owned P-256 fixed source");
    let post_base = p256_main_provider_post_base_fixture_v1();
    let canonical = p256_main_terminal_claims_fixture_v1();
    let verifier = MainP256Log16VerifierConstraintSourceV1::for_main_v1(&layout, &fixed, post_base)
        .expect("canonical log-sixteen verifier");
    for family in [Family::ChainTerminal, Family::WindowScalar] {
        let mut forged = canonical;
        if family == Family::ChainTerminal {
            forged.certificate_or_crl[0].cross_sources[1].terminal[0] = F::ONE;
            forged.certificate_or_crl[0].cross_sources[2].start[0] = F::ONE;
        } else {
            forged.certificate_or_crl[0].buses.window_scalar[0] = F::ONE;
            forged.certificate_or_crl[0].buses.scalar_bus_window[0] = F::ONE;
        }
        main_p256_terminal_registration_v1(&forged, 0).expect("coordinated private window owner");
        let binding = verifier.bindings[0];
        assert_p256_private_endpoint_local_recurrence_v1(
            binding.main,
            binding.p256,
            &fixed,
            verifier.challenges,
            family,
        );
    }
    let mut forged_sink = canonical;
    forged_sink.certificate_or_crl[0].cross_sources[3].terminal[0] = F::ONE;
    forged_sink.certificate_or_crl[0].sink[0] = F::ONE;
    main_p256_terminal_registration_v1(&forged_sink, 0).expect("coordinated private sink owner");
    let sink = verifier.bindings[P256_SIGNATURE_COUNT_V1];
    assert_p256_private_endpoint_local_recurrence_v1(
        sink.main,
        sink.p256,
        &fixed,
        verifier.challenges,
        Family::ChainTerminal,
    );
}
