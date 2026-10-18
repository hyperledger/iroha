// Lexically included by `zk_x509::stark::tests` to preserve the existing libtest paths.
fn test_stark_digest_v1(seed: u8) -> PrivacyOuterDigestV1 {
    PrivacyOuterDigestV1::from_bytes([seed; 48])
}

fn mutate_stark_digest_v1(digest: &mut PrivacyOuterDigestV1) {
    let mut words = digest.to_bytes();
    words[0] ^= 1;
    *digest = PrivacyOuterDigestV1::from_bytes(words);
}

#[test]
fn maximum_credential_bound_sources_preserve_joint_binding_and_terminal_handoffs() {
    use crate::privacy_engines::zk_x509::{
        main_assembly::build_zk_x509_main_trace_assembly_v1,
        relation::{
            ZkX509GovernanceV1,
            release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
        },
    };
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true)
        .expect("maximum signed credential");
    let trust_anchor = fixture.authoritative_state.trust_anchor();
    let crl = fixture.authoritative_state.crl_record();
    let assembly = build_zk_x509_main_trace_assembly_v1(
        &fixture.statement,
        ZkX509GovernanceV1 {
            trust_anchor: &trust_anchor,
            certificate_policy: fixture.authoritative_state.certificate_policy(),
            crl: &crl,
        },
        &fixture.witness,
    )
    .expect("actual maximum MAIN assembly");
    let mut obsolete_profile = assembly.verifier_profile;
    obsolete_profile.compiled_profile_digest =
        hex::decode("7cf3286b4560be90d2305b33c9aaea30a39e6841f4045cf68bca68895d1b6063")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(
        validate_zk_x509_main_verifier_profile_v1(obsolete_profile),
        Err(ZkX509StarkErrorV1::ProfileMismatch),
        "the broken RFC/SHA channel profile has no compatibility path",
    );
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let pre_aux = ZkX509CredentialMainPreAuxV1::fixture_for_test_v1(
        [0x81; 32],
        assembly.verifier_profile.compiled_profile_digest,
        core::array::from_fn(|index| test_stark_digest_v1(index as u8 + 1)),
    );
    let binding = derive_zk_x509_credential_pre_aux_binding_v1(
        pre_aux,
        test_stark_digest_v1(0x91),
        test_stark_digest_v1(0xA1),
        test_stark_digest_v1(0xB1),
    )
    .unwrap();
    let sha = core::array::from_fn(|segment| {
        ZkX509ShaBatchSegmentBaseSourceV1::new_v1(
            &assembly.sha_schedule,
            &assembly.sha_witnesses,
            segment,
        )
        .unwrap()
    });
    let p256 = P256MainBaseSourceV1::new_v1(&assembly).unwrap();
    let mut source = MainLog19BoundTraceGroupSourceV1::bind_from_phase_v1(
        &layout, &assembly, sha, p256, binding,
    )
    .expect("actual maximum BoundSources phase without mask/commitment work");
    assert_eq!(source.post_base, binding.main_post_base());
    assert_eq!(
        source.p256.post_base_v1().unwrap(),
        binding.main_post_base()
    );
    let der_last =
        super::super::der_stark::zk_x509_der_stark_aggregate_aux_row_v1(&source.der, (1 << 19) - 1)
            .expect("actual DER final native row");
    for (der_column, rfc_column) in super::super::der_stark::zk_x509_der_terminal_columns_v1()
        .into_iter()
        .zip(super::super::rfc5280_stark::zk_x509_rfc_der_terminal_columns_v1())
    {
        let rfc_values = ZeroizingMainTraceColumnV1(
            source
                .rfc
                .build_aux_column_v1(rfc_column)
                .expect("actual private RFC handoff column"),
        );
        assert_eq!(der_last[der_column], rfc_values[(1 << 19) - 1]);
    }
    let (bridges, consumers) = super::super::rfc5280_stark::zk_x509_rfc_sha_union_columns_v1();
    let mut bridge_values = zeroize::Zeroizing::new([[F::ZERO; 4]; 4]);
    let mut role_values = zeroize::Zeroizing::new([[F::ZERO; 4]; 4]);
    for index in 0..4 {
        for lane in 0..4 {
            let bridge = ZeroizingMainTraceColumnV1(
                source
                    .rfc
                    .build_aux_column_v1(bridges[index][lane])
                    .unwrap(),
            );
            assert_eq!(bridge.len(), 1 << 19);
            bridge_values[index][lane] = bridge[ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[index] - 1];
            assert!(
                bridge
                    .iter()
                    .all(|value| *value == bridge_values[index][lane])
            );
            let role = ZeroizingMainTraceColumnV1(
                source
                    .rfc
                    .build_aux_column_v1(consumers[index][lane])
                    .unwrap(),
            );
            assert_eq!(role.len(), 1 << 19);
            role_values[index][lane] = role[(1 << 19) - 1];
        }
        let mut endpoint = zeroize::Zeroizing::new([[F::ZERO; 4]; 4]);
        let mut seen = false;
        let returned = source.sha_aux[index]
            .for_each_aux_row_with_air_terminals_v1(|row, aux| {
                if row == ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[index] - 1 {
                    seen = true;
                    for stream in 0..4 {
                        endpoint[stream].copy_from_slice(&aux[62 + 4 * stream..66 + 4 * stream]);
                    }
                }
            })
            .unwrap();
        assert!(seen);
        assert_eq!(*endpoint, returned.segment.rfc_stream_products);
        for lane in 0..4 {
            let product = endpoint
                .iter()
                .fold(F::ONE, |value, stream| value.mul(stream[lane]));
            assert_eq!(
                bridge_values[index][lane], product,
                "private SHA endpoint {index}/{lane}"
            );
            assert_ne!(bridge_values[index][lane].add(F::ONE), product);
            // Every independently committed byte stream affects its equation.
            assert!(endpoint.iter().all(|stream| stream[lane] != F::ZERO));
            for selected in 0..4 {
                let changed = endpoint
                    .iter()
                    .enumerate()
                    .fold(F::ONE, |value, (stream, words)| {
                        value.mul(if stream == selected {
                            words[lane].add(F::ONE)
                        } else {
                            words[lane]
                        })
                    });
                assert_ne!(bridge_values[index][lane], changed);
            }
        }
    }
    for lane in 0..4 {
        let role = role_values
            .iter()
            .fold(F::ONE, |value, role| value.mul(role[lane]));
        let bridge = bridge_values
            .iter()
            .fold(F::ONE, |value, segment| value.mul(segment[lane]));
        assert_eq!(
            role, bridge,
            "private four-role/four-segment union lane {lane}"
        );
        assert!(role_values.iter().all(|role| role[lane] != F::ZERO));
        for selected in 0..4 {
            let changed = role_values
                .iter()
                .enumerate()
                .fold(F::ONE, |value, (index, words)| {
                    value.mul(if index == selected {
                        words[lane].add(F::ONE)
                    } else {
                        words[lane]
                    })
                });
            assert_ne!(changed, bridge);
        }
    }
}

#[test]
fn deterministic_projection_proof_roundtrips_and_has_a_protocol_kat() {
    let (statement, _, proof) = projection_fixture();
    verify_zk_x509_projection_segmented_stark_v1(statement, proof).expect("valid projection proof");
    assert!(proof.len() <= ZK_X509_MAX_PROOF_BYTES_V1 as usize);
    assert_eq!(&proof[..4], &PROOF_MAGIC_V1);
    let decoded = decode_projection_fixture();
    assert_eq!(
        exact_encoded_aggregate_proof_bytes_v1(&decoded, &projection_aggregate_layout())
            .expect("exact wire size"),
        proof.len()
    );
    assert!(
        proof.len()
            <= maximum_encoded_aggregate_proof_bytes_v1(&projection_aggregate_layout())
                .expect("maximum wire size")
    );
    assert_eq!(
        encode_zk_x509_segmented_stark_proof_v1(&decoded, &projection_aggregate_layout())
            .expect("canonical re-encode"),
        *proof
    );
    let indices = decoded
        .queries
        .iter()
        .map(|query| query.index)
        .collect::<BTreeSet<_>>();
    assert_eq!(indices.len(), QUERY_COUNT);
    let digest: [u8; 32] = Sha256::digest(proof).into();
    eprintln!(
        "zk-x509-native-projection-proof-sha256={}",
        hex::encode(digest)
    );
    assert_eq!(
        hex::encode(digest),
        "0dd4a27570de1f36d102a887c61929bb8f94776afeba6568720e7758ca49aa2a",
        "update only when the canonical projection proof protocol intentionally changes"
    );
}
#[test]
fn aggregate_proof_shape_rejects_empty_duplicate_and_reordered_group_material() {
    let mut changed = decode_fixture();
    changed.trace_groups.clear();
    assert_rejected(&changed);
    changed = decode_fixture();
    let duplicate_group = changed.trace_groups[0].clone();
    changed.trace_groups.push(duplicate_group);
    assert_rejected(&changed);
    let mut layout = fixture_aggregate_layout();
    layout.registered_segments.clear();
    assert!(layout.validate().is_err());
}
#[test]
fn deterministic_proof_roundtrips_and_has_unique_post_grinding_queries() {
    let (statement, proof) = fixture();
    verify_zk_x509_io_segmented_stark_v1(statement, proof).expect("valid proof");
    assert!(
        ZK_X509_SEGMENTED_STARK_DESCRIPTOR_V1
            .windows(b"sha3-384-opaque48-vector-row-merkle".len())
            .any(|window| window == b"sha3-384-opaque48-vector-row-merkle")
    );
    assert!(
        !ZK_X509_SEGMENTED_STARK_DESCRIPTOR_V1
            .windows(b"sha256-vector-row-merkle".len())
            .any(|window| window == b"sha256-vector-row-merkle")
    );
    assert!(proof.len() <= ZK_X509_MAX_PROOF_BYTES_V1 as usize);
    assert_eq!(&proof[..4], &PROOF_MAGIC_V1);
    let decoded = decode_fixture();
    assert_eq!(
        exact_encoded_aggregate_proof_bytes_v1(&decoded, &fixture_aggregate_layout())
            .expect("exact wire size"),
        proof.len()
    );
    assert!(
        proof.len()
            <= maximum_encoded_aggregate_proof_bytes_v1(&fixture_aggregate_layout())
                .expect("maximum wire size")
    );
    assert_eq!(
        encode_zk_x509_segmented_stark_proof_v1(&decoded, &fixture_aggregate_layout())
            .expect("canonical re-encode"),
        *proof
    );
    let indices = decoded
        .queries
        .iter()
        .map(|query| query.index)
        .collect::<BTreeSet<_>>();
    assert_eq!(indices.len(), QUERY_COUNT);
    let digest: [u8; 32] = Sha256::digest(proof).into();
    eprintln!("zk-x509-native-io-proof-sha256={}", hex::encode(digest));
    assert_eq!(
        hex::encode(digest),
        "165791adcb5b95e31ec00387bc9ea82577977ff7c96e26ed7829fe7a784b1f94",
        "update only when the canonical proof protocol intentionally changes"
    );
}
#[test]
fn witness_and_entropy_failures_are_rejected_before_emission() {
    let statement = fixture_statement();
    let mut changed = fixture_witnesses();
    changed[0].consumer_values[0][0] ^= 1;
    let mut rng = StdRng::from_seed([7; 32]);
    assert!(matches!(
        prove_zk_x509_io_segmented_stark_v1_with_rng(&statement, &changed, &mut rng),
        Err(ZkX509StarkErrorV1::IoWitness)
    ));
    let mut changed = fixture_witnesses();
    changed[1]
        .declaration
        .public_value
        .as_mut()
        .expect("public")[0] ^= 1;
    assert!(matches!(
        prove_zk_x509_io_segmented_stark_v1_with_rng(&statement, &changed, &mut rng),
        Err(ZkX509StarkErrorV1::WitnessStatementMismatch)
    ));
    assert!(matches!(
        prove_zk_x509_io_segmented_stark_v1_with_rng(
            &statement,
            &fixture_witnesses(),
            &mut MaxValueRng
        ),
        Err(ZkX509StarkErrorV1::RandomnessUnavailable)
    ));
}
#[test]
fn exact_wire_rejects_truncation_trailing_magic_version_and_counts() {
    let (statement, proof) = fixture();
    assert!(matches!(
        verify_zk_x509_io_segmented_stark_v1(statement, &[]),
        Err(ZkX509StarkErrorV1::MalformedProof)
    ));
    for length in [1, 4, 7, proof.len() / 4, proof.len() / 2, proof.len() - 1] {
        assert!(
            verify_zk_x509_io_segmented_stark_v1(statement, &proof[..length]).is_err(),
            "prefix length {length} must reject"
        );
    }
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(verify_zk_x509_io_segmented_stark_v1(statement, &trailing).is_err());
    let mut wrong_magic = proof.clone();
    wrong_magic[0] ^= 1;
    assert!(matches!(
        verify_zk_x509_io_segmented_stark_v1(statement, &wrong_magic),
        Err(ZkX509StarkErrorV1::MalformedProof)
    ));
    let mut wrong_version = proof.clone();
    wrong_version[5] ^= 1;
    assert!(matches!(
        verify_zk_x509_io_segmented_stark_v1(statement, &wrong_version),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let mut wrong_segments = proof.clone();
    wrong_segments[7] ^= 1;
    assert!(matches!(
        verify_zk_x509_io_segmented_stark_v1(statement, &wrong_segments),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert!(matches!(
        verify_zk_x509_io_segmented_stark_v1(
            statement,
            &vec![0_u8; ZK_X509_MAX_PROOF_BYTES_V1 as usize + 1]
        ),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
}
#[test]
fn every_committed_column_family_and_opening_family_is_bound() {
    let mut changed = decode_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].base_root);
    assert_rejected(&changed);
    changed = decode_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].aux_root);
    assert_rejected(&changed);
    for lane in 0..SECURITY_LANES {
        changed = decode_fixture();
        mutate_stark_digest_v1(&mut changed.composition_roots[lane]);
        assert_rejected(&changed);
        changed = decode_fixture();
        mutate_stark_digest_v1(&mut changed.fri_lanes[lane].roots[0]);
        assert_rejected(&changed);
        changed = decode_fixture();
        changed.queries[0].composition_values[lane][0][0] ^= 1;
        assert_rejected(&changed);
        changed = decode_fixture();
        mutate_stark_digest_v1(&mut changed.composition_frontiers[lane][0]);
        assert_rejected(&changed);
        changed = decode_fixture();
        changed.queries[0].fri_lanes[lane].rounds[0].low[0] ^= 1;
        assert_rejected(&changed);
        changed = decode_fixture();
        changed.queries[0].fri_lanes[lane].rounds[0].high[0] ^= 1;
        assert_rejected(&changed);
        changed = decode_fixture();
        mutate_stark_digest_v1(&mut changed.fri_lanes[lane].round_frontiers[0][0]);
        assert_rejected(&changed);
    }
    for column in 0..IO_BASE_WIDTH {
        changed = decode_fixture();
        changed.queries[0].trace_groups[0].base_current[column] ^= 1;
        assert_rejected(&changed);
        changed = decode_fixture();
        changed.queries[0].trace_groups[0].base_next[column] ^= 1;
        assert_rejected(&changed);
    }
    for column in 0..IO_AUX_WIDTH {
        changed = decode_fixture();
        changed.queries[0].trace_groups[0].aux_current[column] ^= 1;
        assert_rejected(&changed);
        changed = decode_fixture();
        changed.queries[0].trace_groups[0].aux_next[column] ^= 1;
        assert_rejected(&changed);
    }
    changed = decode_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].base_frontier[0]);
    assert_rejected(&changed);
    changed = decode_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].aux_frontier[0]);
    assert_rejected(&changed);
}
#[test]
fn every_deep_value_order_omission_and_replay_is_rejected() {
    let canonical = decode_fixture();
    for column in 0..canonical.deep.trace_groups[0].base_current.len() {
        let mut changed = canonical.clone();
        changed.deep.trace_groups[0].base_current[column][0] ^= 1;
        assert_rejected(&changed);
        let mut changed = canonical.clone();
        changed.deep.trace_groups[0].base_next[column][0] ^= 1;
        assert_rejected(&changed);
    }
    for column in 0..canonical.deep.trace_groups[0].aux_current.len() {
        let mut changed = canonical.clone();
        changed.deep.trace_groups[0].aux_current[column][0] ^= 1;
        assert_rejected(&changed);
        let mut changed = canonical.clone();
        changed.deep.trace_groups[0].aux_next[column][0] ^= 1;
        assert_rejected(&changed);
    }
    for lane in 0..canonical.deep.composition_values.len() {
        for chunk in 0..canonical.deep.composition_values[lane].len() {
            let mut changed = canonical.clone();
            changed.deep.composition_values[lane][chunk][0] ^= 1;
            assert_rejected(&changed);
        }
    }
    let mut reordered = canonical.clone();
    let group = &mut reordered.deep.trace_groups[0];
    core::mem::swap(&mut group.base_current, &mut group.base_next);
    assert_rejected(&reordered);
    let mut reordered = canonical.clone();
    let group = &mut reordered.deep.trace_groups[0];
    core::mem::swap(&mut group.aux_current, &mut group.aux_next);
    assert_rejected(&reordered);
    let mut omitted = canonical.clone();
    omitted.deep.trace_groups[0].base_current.pop();
    assert!(matches!(
        encode_zk_x509_segmented_stark_proof_v1(&omitted, &fixture_aggregate_layout()),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let mut duplicated = canonical.clone();
    let duplicate = duplicated.deep.trace_groups[0].aux_next[0];
    duplicated.deep.trace_groups[0].aux_next.push(duplicate);
    assert!(matches!(
        encode_zk_x509_segmented_stark_proof_v1(&duplicated, &fixture_aggregate_layout()),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let mut replay_rng = StdRng::from_seed([0xC7; 32]);
    let replay_bytes = prove_zk_x509_io_segmented_stark_v1_with_rng(
        &fixture().0,
        &fixture_witnesses(),
        &mut replay_rng,
    )
    .expect("independent masked proof");
    let replay =
        decode_zk_x509_segmented_stark_proof_v1(&replay_bytes, &fixture_aggregate_layout())
            .expect("independent proof decoding");
    let mut spliced = canonical;
    spliced.deep = replay.deep;
    assert_rejected(&spliced);
}
#[test]
fn every_projection_committed_column_and_opening_family_is_bound() {
    let mut changed = decode_projection_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].base_root);
    assert_projection_rejected(&changed);
    changed = decode_projection_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].aux_root);
    assert_projection_rejected(&changed);
    for lane in 0..SECURITY_LANES {
        changed = decode_projection_fixture();
        mutate_stark_digest_v1(&mut changed.composition_roots[lane]);
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        mutate_stark_digest_v1(&mut changed.fri_lanes[lane].roots[0]);
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        changed.queries[0].composition_values[lane][0][0] ^= 1;
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        mutate_stark_digest_v1(&mut changed.composition_frontiers[lane][0]);
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        changed.queries[0].fri_lanes[lane].rounds[0].low[0] ^= 1;
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        changed.queries[0].fri_lanes[lane].rounds[0].high[0] ^= 1;
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        mutate_stark_digest_v1(&mut changed.fri_lanes[lane].round_frontiers[0][0]);
        assert_projection_rejected(&changed);
    }
    for column in 0..ZK_X509_PROJECTION_BASE_WIDTH_V1 {
        changed = decode_projection_fixture();
        changed.queries[0].trace_groups[0].base_current[column] ^= 1;
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        changed.queries[0].trace_groups[0].base_next[column] ^= 1;
        assert_projection_rejected(&changed);
    }
    for column in 0..ZK_X509_PROJECTION_AUX_WIDTH_V1 {
        changed = decode_projection_fixture();
        changed.queries[0].trace_groups[0].aux_current[column] ^= 1;
        assert_projection_rejected(&changed);
        changed = decode_projection_fixture();
        changed.queries[0].trace_groups[0].aux_next[column] ^= 1;
        assert_projection_rejected(&changed);
    }
    changed = decode_projection_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].base_frontier[0]);
    assert_projection_rejected(&changed);
    changed = decode_projection_fixture();
    mutate_stark_digest_v1(&mut changed.trace_groups[0].aux_frontier[0]);
    assert_projection_rejected(&changed);
}
#[test]
fn invalid_projection_witnesses_and_entropy_fail_before_emission() {
    let (statement, witness) = crate::privacy_engines::zk_x509::projection_air::tests::fixture();
    let mut rng = StdRng::from_seed([0x31; 32]);
    let mut changed = witness.clone();
    changed.chain_spki_der[0][0] ^= 1;
    assert!(matches!(
        prove_zk_x509_projection_segmented_stark_v1_with_rng(&statement, &changed, &mut rng),
        Err(ZkX509StarkErrorV1::ProjectionWitness)
    ));
    let mut changed = witness.clone();
    changed.leaf_serial[0] ^= 1;
    assert!(matches!(
        prove_zk_x509_projection_segmented_stark_v1_with_rng(&statement, &changed, &mut rng),
        Err(ZkX509StarkErrorV1::ProjectionWitness)
    ));
    let mut changed = witness.clone();
    changed.disclosed_attribute_values[0][0] ^= 1;
    assert!(matches!(
        prove_zk_x509_projection_segmented_stark_v1_with_rng(&statement, &changed, &mut rng),
        Err(ZkX509StarkErrorV1::ProjectionWitness)
    ));
    let mut changed = witness.clone();
    changed.attribute_salts[0][0] ^= 1;
    assert!(matches!(
        prove_zk_x509_projection_segmented_stark_v1_with_rng(&statement, &changed, &mut rng),
        Err(ZkX509StarkErrorV1::ProjectionWitness)
    ));
    let mut changed = witness.clone();
    changed.chain_spki_der.pop();
    assert!(matches!(
        prove_zk_x509_projection_segmented_stark_v1_with_rng(&statement, &changed, &mut rng),
        Err(ZkX509StarkErrorV1::ProjectionWitness)
    ));
    assert!(matches!(
        prove_zk_x509_projection_segmented_stark_v1_with_rng(
            &statement,
            &witness,
            &mut MaxValueRng
        ),
        Err(ZkX509StarkErrorV1::RandomnessUnavailable)
    ));
}
#[test]
fn multiproof_frontiers_reject_nonminimal_duplicate_reordered_and_superfluous_siblings() {
    let mut changed = decode_fixture();
    changed.trace_groups[0].base_frontier.pop();
    assert_rejected(&changed);
    changed = decode_fixture();
    let duplicate = changed.trace_groups[0].base_frontier[0];
    changed.trace_groups[0].base_frontier.push(duplicate);
    assert_rejected(&changed);
    changed = decode_fixture();
    changed.trace_groups[0].base_frontier[1] = changed.trace_groups[0].base_frontier[0];
    assert_rejected(&changed);
    changed = decode_fixture();
    changed.trace_groups[0].base_frontier.swap(0, 1);
    assert_rejected(&changed);
    changed = decode_fixture();
    let superfluous = changed.trace_groups[0].aux_frontier[0];
    changed.trace_groups[0].aux_frontier.insert(0, superfluous);
    assert_rejected(&changed);
    changed = decode_fixture();
    changed.composition_frontiers[0].swap(0, 1);
    assert_rejected(&changed);
    changed = decode_fixture();
    changed.fri_lanes[0].round_frontiers[0].swap(0, 1);
    assert_rejected(&changed);
}
#[test]
fn query_reordering_duplication_grinding_and_composition_mutations_reject() {
    let mut changed = decode_fixture();
    changed.queries.swap(0, 1);
    assert_rejected(&changed);
    changed = decode_fixture();
    changed.queries[1] = changed.queries[0].clone();
    assert_rejected(&changed);
    changed = decode_fixture();
    changed.grinding_nonce ^= 1;
    assert_rejected(&changed);
    changed = decode_fixture();
    mutate_stark_digest_v1(&mut changed.composition_roots[0]);
    assert_rejected(&changed);
    changed = decode_fixture();
    mutate_stark_digest_v1(&mut changed.fri_lanes[0].roots[0]);
    assert_rejected(&changed);
}
#[test]
fn noncanonical_fields_and_terminal_high_degree_reject() {
    let mut changed = decode_fixture();
    changed.queries[0].trace_groups[0].base_current[0] =
        crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
    assert!(matches!(
        encode_zk_x509_segmented_stark_proof_v1(&changed, &fixture_aggregate_layout()),
        Err(ZkX509StarkErrorV1::NonCanonicalField)
    ));
    changed = decode_fixture();
    changed.deep.trace_groups[0].base_current[0][0] =
        crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
    assert!(matches!(
        encode_zk_x509_segmented_stark_proof_v1(&changed, &fixture_aggregate_layout()),
        Err(ZkX509StarkErrorV1::NonCanonicalField)
    ));
    changed = decode_fixture();
    changed.fri_lanes[0].terminal_values[TERMINAL_SIZE - 1][0] ^= 1;
    let terminal =
        aggregate::canonical_fp4_fields_v1(&changed.fri_lanes[0].terminal_values, TERMINAL_SIZE)
            .expect("canonical mutation");
    let tree =
        fri_tree_v1(0, fixture_aggregate_layout().fri_rounds(), &terminal).expect("terminal tree");
    changed.fri_lanes[0].roots[fixture_aggregate_layout().fri_rounds()] = tree.root();
    let bytes = encode_zk_x509_segmented_stark_proof_v1(&changed, &fixture_aggregate_layout())
        .expect("encode high-degree terminal");
    assert!(matches!(
        verify_zk_x509_io_segmented_stark_v1(&fixture().0, &bytes),
        Err(ZkX509StarkErrorV1::FriDegree)
    ));
}
#[test]
fn every_public_topology_and_public_byte_change_rejects_replay() {
    let proof = &fixture().1;
    let mut declarations = fixture().0.declarations.clone();
    declarations[1].public_value.as_mut().expect("public")[0] ^= 1;
    let statement = ZkX509IoStarkStatementV1::new(declarations).expect("valid changed public");
    assert!(verify_zk_x509_io_segmented_stark_v1(&statement, proof).is_err());
    let mut declarations = fixture().0.declarations.clone();
    declarations[0].producer.instance += 1;
    let statement = ZkX509IoStarkStatementV1::new(declarations).expect("valid changed producer");
    assert!(verify_zk_x509_io_segmented_stark_v1(&statement, proof).is_err());
    let mut declarations = fixture().0.declarations.clone();
    declarations[0].consumers[0].instance += 1;
    let statement = ZkX509IoStarkStatementV1::new(declarations).expect("valid changed consumer");
    assert!(verify_zk_x509_io_segmented_stark_v1(&statement, proof).is_err());
}
#[test]
fn every_projection_public_field_and_output_rejects_proof_replay() {
    let (baseline, _, proof) = projection_fixture();
    let mut mutations = Vec::<(&str, IrohaZkX509StarkP256StatementV1)>::new();
    let mut changed = baseline.clone();
    changed.context.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x92; 32])),
    );
    mutations.push(("context.network_id", changed));
    let mut changed = baseline.clone();
    changed.context.action_index += 1;
    mutations.push(("context.action_index", changed));
    let mut changed = baseline.clone();
    changed.context.transaction_intent_digest = PrivacyTransactionIntentDigestV1::new([0x81; 32]);
    mutations.push(("context.transaction_intent_digest", changed));
    let mut changed = baseline.clone();
    changed.context.parameter_id = PrivacyParameterIdV1::new([0x82; 32]);
    mutations.push(("context.parameter_id", changed));
    let mut changed = baseline.clone();
    changed.context.parameter_digest = PrivacyParameterDigestV1::new([0x83; 32]);
    mutations.push(("context.parameter_digest", changed));
    let mut changed = baseline.clone();
    changed.context.verifier_digest = PrivacyVerifierDigestV1::new([0x84; 32]);
    mutations.push(("context.verifier_digest", changed));
    let mut changed = baseline.clone();
    changed.context.statement_schema_digest = PrivacyStatementSchemaDigestV1::new([0x85; 32]);
    mutations.push(("context.statement_schema_digest", changed));
    let mut changed = baseline.clone();
    changed.context.engine_manifest_digest = PrivacyEngineManifestDigestV1::new([0x86; 32]);
    mutations.push(("context.engine_manifest_digest", changed));
    let mut changed = baseline.clone();
    changed.trust_anchor_id = PrivacyIssuerIdV1::new([0x87; 32]);
    mutations.push(("trust_anchor_id", changed));
    let mut changed = baseline.clone();
    changed.certificate_policy_id = PrivacyPolicyIdV1::new([0x88; 32]);
    mutations.push(("certificate_policy_id", changed));
    let mut changed = baseline.clone();
    changed.trust_anchor_record_digest = PrivacyZkX509TrustAnchorRecordDigestV1::new([0x89; 32]);
    mutations.push(("trust_anchor_record_digest", changed));
    let mut changed = baseline.clone();
    changed.trust_anchor_record_epoch += 1;
    mutations.push(("trust_anchor_record_epoch", changed));
    let mut changed = baseline.clone();
    changed.certificate_policy_record_digest =
        PrivacyZkX509CertificatePolicyRecordDigestV1::new([0x8A; 32]);
    mutations.push(("certificate_policy_record_digest", changed));
    let mut changed = baseline.clone();
    changed.certificate_policy_record_epoch += 1;
    mutations.push(("certificate_policy_record_epoch", changed));
    let mut changed = baseline.clone();
    changed.crl_record_digest = PrivacyZkX509CrlRecordDigestV1::new([0x8B; 32]);
    mutations.push(("crl_record_digest", changed));
    let mut changed = baseline.clone();
    changed.crl_record_epoch += 1;
    mutations.push(("crl_record_epoch", changed));
    let mut changed = baseline.clone();
    changed.subject_public_key_digest = PrivacyCertificateKeyDigestV1::new([0x8C; 32]);
    mutations.push(("subject_public_key_digest", changed));
    let mut changed = baseline.clone();
    changed.ca_membership_root = PrivacyRootV1::new([0x8D; 32]);
    mutations.push(("ca_membership_root", changed));
    let mut changed = baseline.clone();
    changed.ca_membership_root_epoch += 1;
    mutations.push(("ca_membership_root_epoch", changed));
    let mut changed = baseline.clone();
    changed.key_usage.digital_signature =
        (!changed.key_usage.digital_signature.is_required()).into();
    mutations.push(("key_usage.digital_signature", changed));
    let mut changed = baseline.clone();
    changed.key_usage.content_commitment =
        (!changed.key_usage.content_commitment.is_required()).into();
    mutations.push(("key_usage.content_commitment", changed));
    let mut changed = baseline.clone();
    changed.key_usage.key_encipherment = (!changed.key_usage.key_encipherment.is_required()).into();
    mutations.push(("key_usage.key_encipherment", changed));
    let mut changed = baseline.clone();
    changed.key_usage.key_agreement = (!changed.key_usage.key_agreement.is_required()).into();
    mutations.push(("key_usage.key_agreement", changed));
    let mut changed = baseline.clone();
    changed
        .extended_key_usages
        .insert(1, PrivacyX509ExtendedKeyUsageV1::DocumentSigning);
    mutations.push(("extended_key_usages", changed));
    for disclosure in 0..baseline.disclosed_attributes.len() {
        let mut changed = baseline.clone();
        changed.disclosed_attributes[disclosure].index = match disclosure {
            0 => 1,
            _ => 2,
        };
        mutations.push(("disclosed_attributes.index", changed));
        let mut changed = baseline.clone();
        changed.disclosed_attributes[disclosure].attribute_digest =
            PrivacyAttributeDigestV1::new([0x90 + disclosure as u8; 32]);
        mutations.push(("disclosed_attributes.attribute_digest", changed));
    }
    let mut changed = baseline.clone();
    changed.disclosed_attributes.clear();
    mutations.push(("disclosed_attributes.length", changed));
    let mut changed = baseline.clone();
    changed.presentation_not_before_unix_seconds += 1;
    mutations.push(("presentation_not_before_unix_seconds", changed));
    let mut changed = baseline.clone();
    changed.presentation_not_after_unix_seconds -= 1;
    mutations.push(("presentation_not_after_unix_seconds", changed));
    let mut changed = baseline.clone();
    changed.wallet_account = crate::privacy_engines::zk_x509::projection_air::tests::account(0xA1);
    mutations.push(("wallet_account", changed));
    let mut changed = baseline.clone();
    changed.wallet_challenge = PrivacyChallengeV1::new([0x96; 32]);
    mutations.push(("wallet_challenge", changed));
    let mut changed = baseline.clone();
    changed.certificate_nullifier = PrivacyNullifierV1::new([0x97; 32]);
    mutations.push(("certificate_nullifier", changed));
    for (field, statement) in mutations {
        assert!(
            verify_zk_x509_projection_segmented_stark_v1(&statement, proof).is_err(),
            "replaying a proof after mutating {field} must reject"
        );
    }
}
#[test]
fn compact_ca_registration_is_single_fixed_capacity_and_fail_closed() {
    assert_eq!(
        checked_compact_ca_degree_capacity_v1(
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        )
        .expect("canonical compact-CA capacity"),
        (3 * (4_096 + 2_099) + 2 * (4_096 - 1) - 4_096, 9_215)
    );
    assert_eq!(
        checked_compact_ca_degree_capacity_v1(
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            2,
        )
        .expect("lower-degree compact-CA capacity"),
        (2 * (4_096 + 2_099) + 2 * (4_096 - 1) - 4_096, 9_215)
    );
    for (trace_log2, lde_log2, constraint_degree) in [
        (
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1 - 1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        ),
        (
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1 + 1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        ),
        (
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1 - 1,
            ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        ),
        (
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1 + 1,
            ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        ),
        (
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            1,
        ),
        (
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            6,
        ),
    ] {
        assert!(
            checked_compact_ca_degree_capacity_v1(trace_log2, lde_log2, constraint_degree,)
                .is_err(),
            "invalid compact-CA capacity ({trace_log2}, {lde_log2}, \
                 {constraint_degree}) must fail closed"
        );
    }
    // Both numeric bounds can fit after reducing CA padding. They remain
    // different profiles; adapter validation owns the exact CA degree/domain.
    assert_ne!(
        checked_segment_degree_capacity_v1(
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        )
        .unwrap(),
        checked_compact_ca_degree_capacity_v1(
            ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        )
        .unwrap(),
    );
    let canonical_ca = SegmentLayoutV1::for_ca_accumulator().unwrap();
    for changed in [
        SegmentLayoutV1 {
            constraint_degree: 4,
            ..canonical_ca
        },
        SegmentLayoutV1 {
            lde_log2: canonical_ca.trace_log2 + BLOWUP_LOG2,
            ..canonical_ca
        },
    ] {
        assert!(
            changed.validate().is_err(),
            "CA must reject a foreign degree or MAIN padding"
        );
    }
    let layout = accumulator_aggregate_layout();
    layout
        .validate_accumulator_registration_v1()
        .expect("canonical compact-CA registration");
    assert_eq!(layout.parameters_v1(), CA_AGGREGATE_PARAMETERS_V1);
    assert_eq!(layout.common_lde_log2, ZK_X509_CA_FRI_LDE_LOG2_V1);
    assert_eq!(layout.fri_rounds(), 6);
    assert_eq!(layout.trace_groups.len(), 1);
    assert_eq!(layout.registered_segments.len(), 1);
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::CaAccumulator, 0)
        .expect("compact-CA registration");
    assert_eq!(registration.segment.active_rows, 13);
    assert_eq!(registration.segment.trace_log2, 12);
    assert_eq!(registration.segment.lde_log2, ZK_X509_CA_FRI_LDE_LOG2_V1);
    assert_eq!(registration.segment.base_width, 695);
    assert_eq!(registration.segment.aux_width, 128);
    assert_eq!(registration.segment.fixed_width, 80);
    assert_eq!(registration.segment.constraint_count, 1_363);
    assert_eq!(registration.segment.constraint_degree, 3);
    assert_eq!(registration.column_chunks, ZK_X509_CA_ACCUMULATOR_CHUNKS_V1);
    assert_eq!(
        layout.trace_groups[0].column_chunks,
        ZK_X509_CA_ACCUMULATOR_CHUNKS_V1
    );
    let mut mutations = Vec::new();
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.instance = 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.active_rows = 12;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.physical_chunks += 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.common_lde_log2 -= 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.common_lde_log2 += 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.lde_log2 -= 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.lde_log2 += 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.constraint_degree = 4;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.trace_log2 += 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].column_chunks += 1;
    changed.trace_groups[0].column_chunks += 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments[0].segment.adapter = SegmentAdapterIdV1::Projection;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed
        .registered_segments
        .push(changed.registered_segments[0]);
    mutations.push(changed);
    for (index, mutation) in mutations.iter().enumerate() {
        assert!(
            mutation.validate_accumulator_registration_v1().is_err(),
            "compact-CA mutation {index} must fail closed"
        );
    }
}
#[test]
fn main_provider_registry_is_exactly_six_closed_ordered_groups() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    {
        let mut a = MockMainTraceGroupSourceV1::default();
        let mut b = MockMainTraceGroupSourceV1::default();
        let mut c = MockMainTraceGroupSourceV1::default();
        let mut d = MockMainTraceGroupSourceV1::default();
        let mut e = MockMainTraceGroupSourceV1::default();
        assert!(matches!(
            MainTraceProviderSetV1::new_v1(
                &layout,
                vec![
                    MainTraceGroupProviderV1::TestLog5(&mut a),
                    MainTraceGroupProviderV1::TestLog8(&mut b),
                    MainTraceGroupProviderV1::Log15(&mut c),
                    MainTraceGroupProviderV1::TestLog16(&mut d),
                    MainTraceGroupProviderV1::Log18(&mut e),
                ],
            ),
            Err(ZkX509StarkErrorV1::ProfileMismatch)
        ));
    }
    {
        let mut a = MockMainTraceGroupSourceV1::default();
        let mut b = MockMainTraceGroupSourceV1::default();
        let mut c = MockMainTraceGroupSourceV1::default();
        let mut d = MockMainTraceGroupSourceV1::default();
        let mut e = MockMainTraceGroupSourceV1::default();
        let mut f = MockMainTraceGroupSourceV1::default();
        assert!(matches!(
            MainTraceProviderSetV1::new_v1(
                &layout,
                vec![
                    MainTraceGroupProviderV1::TestLog8(&mut a),
                    MainTraceGroupProviderV1::TestLog5(&mut b),
                    MainTraceGroupProviderV1::Log15(&mut c),
                    MainTraceGroupProviderV1::TestLog16(&mut d),
                    MainTraceGroupProviderV1::Log18(&mut e),
                    MainTraceGroupProviderV1::Log19(&mut f),
                ],
            ),
            Err(ZkX509StarkErrorV1::ProfileMismatch)
        ));
    }
    {
        let mut a = MockMainTraceGroupSourceV1::default();
        let mut b = MockMainTraceGroupSourceV1::default();
        let mut c = MockMainTraceGroupSourceV1::default();
        let mut d = MockMainTraceGroupSourceV1::default();
        let mut e = MockMainTraceGroupSourceV1::default();
        let mut f = MockMainTraceGroupSourceV1::default();
        assert!(matches!(
            MainTraceProviderSetV1::new_v1(
                &layout,
                vec![
                    MainTraceGroupProviderV1::TestLog5(&mut a),
                    MainTraceGroupProviderV1::TestLog5(&mut b),
                    MainTraceGroupProviderV1::Log15(&mut c),
                    MainTraceGroupProviderV1::TestLog16(&mut d),
                    MainTraceGroupProviderV1::Log18(&mut e),
                    MainTraceGroupProviderV1::Log19(&mut f),
                ],
            ),
            Err(ZkX509StarkErrorV1::ProfileMismatch)
        ));
    }
    {
        let mut a = MockMainTraceGroupSourceV1::default();
        let mut b = MockMainTraceGroupSourceV1::default();
        let mut c = MockMainTraceGroupSourceV1::default();
        let mut d = MockMainTraceGroupSourceV1::default();
        let mut e = MockMainTraceGroupSourceV1::default();
        let mut f = MockMainTraceGroupSourceV1::default();
        let mut g = MockMainTraceGroupSourceV1::default();
        assert!(matches!(
            MainTraceProviderSetV1::new_v1(
                &layout,
                vec![
                    MainTraceGroupProviderV1::TestLog5(&mut a),
                    MainTraceGroupProviderV1::TestLog8(&mut b),
                    MainTraceGroupProviderV1::Log15(&mut c),
                    MainTraceGroupProviderV1::TestLog16(&mut d),
                    MainTraceGroupProviderV1::Log18(&mut e),
                    MainTraceGroupProviderV1::Log19(&mut f),
                    MainTraceGroupProviderV1::Log19(&mut g),
                ],
            ),
            Err(ZkX509StarkErrorV1::ProfileMismatch)
        ));
    }
    {
        let mut changed = layout.clone();
        changed.common_lde_log2 -= 1;
        let mut a = MockMainTraceGroupSourceV1::default();
        let mut b = MockMainTraceGroupSourceV1::default();
        let mut c = MockMainTraceGroupSourceV1::default();
        let mut d = MockMainTraceGroupSourceV1::default();
        let mut e = MockMainTraceGroupSourceV1::default();
        let mut f = MockMainTraceGroupSourceV1::default();
        assert!(matches!(
            MainTraceProviderSetV1::new_v1(
                &changed,
                mock_main_group_providers_v1([&mut a, &mut b, &mut c, &mut d, &mut e, &mut f,]),
            ),
            Err(ZkX509StarkErrorV1::ProfileMismatch)
        ));
    }
    {
        let mut a = MockMainTraceGroupSourceV1::default();
        let mut b = MockMainTraceGroupSourceV1::default();
        let mut c = MockMainTraceGroupSourceV1::default();
        let mut d = MockMainTraceGroupSourceV1::default();
        let mut e = MockMainTraceGroupSourceV1::default();
        let mut f = MockMainTraceGroupSourceV1::default();
        assert!(matches!(
            MainOpenedProviderSetV1::new_v1(
                &layout,
                vec![
                    MainOpenedGroupProviderV1::TestLog5(&mut a),
                    MainOpenedGroupProviderV1::TestLog8(&mut b),
                    MainOpenedGroupProviderV1::TestLog16(&mut c),
                    MainOpenedGroupProviderV1::TestLog15(&mut d),
                    MainOpenedGroupProviderV1::TestLog18(&mut e),
                    MainOpenedGroupProviderV1::TestLog19(&mut f),
                ],
            ),
            Err(ZkX509StarkErrorV1::ProfileMismatch)
        ));
    }
}
#[test]
fn main_provider_routes_every_group_column_through_verifier_owned_slices() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let mut log5 = MockMainTraceGroupSourceV1::default();
    let mut log8 = MockMainTraceGroupSourceV1::default();
    let mut log15 = MockMainTraceGroupSourceV1::default();
    let mut log16 = MockMainTraceGroupSourceV1::default();
    let mut log18 = MockMainTraceGroupSourceV1::default();
    let mut log19 = MockMainTraceGroupSourceV1::default();
    let mut providers = MainTraceProviderSetV1::new_v1(
        &layout,
        mock_main_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("exact MAIN providers");
    for group_index in 0..FULL_PROFILE_TRACE_GROUPS_V1 {
        for kind in [MainTraceColumnKindV1::Base, MainTraceColumnKindV1::Aux] {
            let width = match kind {
                MainTraceColumnKindV1::Base => layout.trace_groups[group_index].base_width,
                MainTraceColumnKindV1::Aux => layout.trace_groups[group_index].aux_width,
            };
            if width == 0 {
                assert!(
                    providers
                        .native_group_column_v1(group_index, kind, 0)
                        .is_err()
                );
                continue;
            }
            for column_index in [0, width - 1] {
                let (registration, local_column) = providers
                    .registered_column_v1(group_index, kind, column_index)
                    .expect("verifier-owned slice");
                let column = providers
                    .native_group_column_v1(group_index, kind, column_index)
                    .expect("routed native column");
                assert_eq!(column.len(), registration.segment.trace_size());
                assert_eq!(
                    column[0],
                    mock_main_column_value_v1(
                        registration,
                        local_column,
                        0,
                        matches!(kind, MainTraceColumnKindV1::Aux),
                    )
                );
                assert_eq!(
                    *column.last().expect("nonempty native column"),
                    mock_main_column_value_v1(
                        registration,
                        local_column,
                        registration.segment.trace_size() - 1,
                        matches!(kind, MainTraceColumnKindV1::Aux),
                    )
                );
            }
        }
    }
    assert!(
        providers
            .native_group_column_v1(FULL_PROFILE_TRACE_GROUPS_V1, MainTraceColumnKindV1::Base, 0,)
            .is_err()
    );
    assert!(
        providers
            .native_group_column_v1(
                0,
                MainTraceColumnKindV1::Base,
                layout.trace_groups[0].base_width,
            )
            .is_err()
    );
    drop(providers);
    log19.short_base_column = true;
    let mut providers = MainTraceProviderSetV1::new_v1(
        &layout,
        mock_main_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("short-column adversary registry");
    assert!(
        providers
            .native_group_column_v1(5, MainTraceColumnKindV1::Base, 0)
            .is_err()
    );
    drop(providers);
    log19.short_base_column = false;
    log19.noncanonical_aux_column = true;
    let mut providers = MainTraceProviderSetV1::new_v1(
        &layout,
        mock_main_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("noncanonical-column adversary registry");
    assert!(
        providers
            .native_group_column_v1(5, MainTraceColumnKindV1::Aux, 0)
            .is_err()
    );
}
#[test]
fn main_projection_source_matches_every_direct_native_column() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::Projection, 0)
        .expect("projection registration");
    let (statement, witness) = crate::privacy_engines::zk_x509::projection_air::tests::fixture();
    let trace = build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
    let post_base = projection_provider_post_base_v1(&statement);
    let direct_aux =
        build_zk_x509_projection_aux_trace_v1(&trace.base, &trace.fixed, post_base.projection())
            .expect("direct projection aux");
    let mut projection = MainProjectionTraceGroupSourceV1::for_main_v1(&layout, &statement, &trace)
        .expect("production projection source");
    assert!(
        projection.native_aux_column_v1(registration, 0).is_err(),
        "auxiliary columns must remain unavailable before challenge binding"
    );
    for local_column in 0..ZK_X509_PROJECTION_BASE_WIDTH_V1 {
        assert_eq!(
            projection
                .native_base_column_v1(registration, local_column)
                .expect("production base column"),
            trace
                .base
                .rows
                .iter()
                .map(|row| row[local_column])
                .collect::<Vec<_>>(),
            "base column {local_column}"
        );
    }
    projection
        .bind_challenges_v1(post_base)
        .expect("bind projection challenges");
    for local_column in 0..ZK_X509_PROJECTION_AUX_WIDTH_V1 {
        assert_eq!(
            projection
                .native_aux_column_v1(registration, local_column)
                .expect("production aux column"),
            direct_aux
                .rows
                .iter()
                .map(|row| row[local_column])
                .collect::<Vec<_>>(),
            "aux column {local_column}"
        );
    }
    assert!(projection.bind_challenges_v1(post_base).is_err());
    assert!(
        projection
            .native_base_column_v1(registration, ZK_X509_PROJECTION_BASE_WIDTH_V1)
            .is_err()
    );
    assert!(
        projection
            .native_aux_column_v1(registration, ZK_X509_PROJECTION_AUX_WIDTH_V1)
            .is_err()
    );
    let io_registration = layout
        .registered_segment(SegmentAdapterIdV1::ByteMemory, 0)
        .expect("I/O registration");
    assert!(
        projection
            .native_base_column_v1(io_registration, 0)
            .is_err()
    );
    let mut log5 = MockMainTraceGroupSourceV1::default();
    let mut log8 = MockMainTraceGroupSourceV1::default();
    let mut log16 = MockMainTraceGroupSourceV1::default();
    let mut log18 = MockMainTraceGroupSourceV1::default();
    let mut log19 = MockMainTraceGroupSourceV1::default();
    let mut providers = MainTraceProviderSetV1::new_v1(
        &layout,
        vec![
            MainTraceGroupProviderV1::TestLog5(&mut log5),
            MainTraceGroupProviderV1::TestLog8(&mut log8),
            MainTraceGroupProviderV1::Log15(&mut projection),
            MainTraceGroupProviderV1::TestLog16(&mut log16),
            MainTraceGroupProviderV1::Log18(&mut log18),
            MainTraceGroupProviderV1::Log19(&mut log19),
        ],
    )
    .expect("production projection registry");
    for local_column in 0..ZK_X509_PROJECTION_BASE_WIDTH_V1 {
        assert_eq!(
            providers
                .native_group_column_v1(
                    registration.trace_group,
                    MainTraceColumnKindV1::Base,
                    registration.base_start + local_column,
                )
                .expect("routed production base column"),
            trace
                .base
                .rows
                .iter()
                .map(|row| row[local_column])
                .collect::<Vec<_>>()
        );
    }
    for local_column in 0..ZK_X509_PROJECTION_AUX_WIDTH_V1 {
        assert_eq!(
            providers
                .native_group_column_v1(
                    registration.trace_group,
                    MainTraceColumnKindV1::Aux,
                    registration.aux_start + local_column,
                )
                .expect("routed production aux column"),
            direct_aux
                .rows
                .iter()
                .map(|row| row[local_column])
                .collect::<Vec<_>>()
        );
    }
    drop(providers);
    assert!(
        projection
            .aux
            .as_ref()
            .is_some_and(|aux| { aux.rows.iter().flatten().any(|value| *value != F::ZERO) }),
        "the source holds challenge-bound auxiliary witness material"
    );
    projection.zeroize_private_buffers_v1();
    assert!(
        projection.aux.is_none(),
        "challenge-bound auxiliary copies are zeroized before release"
    );
    let mut changed_trace = trace.clone();
    changed_trace.fixed.rows.swap(0, 1);
    assert!(
        MainProjectionTraceGroupSourceV1::for_main_v1(&layout, &statement, &changed_trace).is_err(),
        "prover-native fixed material must equal the verifier compiler"
    );
}
#[test]
fn main_projection_fixed_rows_and_residues_match_direct_common_domain_adapter() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::Projection, 0)
        .expect("projection registration");
    let (statement, _) = crate::privacy_engines::zk_x509::projection_air::tests::fixture();
    let post_base = projection_provider_post_base_v1(&statement);
    let challenges = post_base.projection();
    let fixed_rows = compile_zk_x509_projection_stark_fixed_rows_v1(&statement)
        .expect("verifier projection fixed rows");
    let mut fixed_coefficients =
        transpose_array_rows_v1(&fixed_rows).expect("fixed native columns");
    let trace_root = goldilocks_primitive_root_v1(registration.segment.trace_log2)
        .expect("projection native root");
    for coefficients in &mut fixed_coefficients {
        goldilocks_ifft_v1(coefficients, trace_root).expect("fixed interpolation");
    }
    let common_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).expect("MAIN common LDE root");
    let evaluate_fixed = |index: usize| {
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(index as u128));
        fixed_coefficients
            .iter()
            .map(|coefficients| {
                coefficients
                    .iter()
                    .rev()
                    .fold(F::ZERO, |value, coefficient| value.mul(x).add(*coefficient))
            })
            .collect::<Vec<_>>()
    };
    let mut source =
        MainProjectionVerifierConstraintSourceV1::for_main_v1(&layout, &statement, post_base)
            .expect("verifier-safe projection source");
    let next_stride = layout.trace_groups[registration.trace_group]
        .next_stride(layout.common_lde_log2)
        .expect("projection next stride");
    for query_index in [
        0,
        1,
        (1_usize << registration.segment.lde_log2) - 1,
        layout.common_lde_size() - 1,
    ] {
        let next_query_index = (query_index + next_stride) % layout.common_lde_size();
        let fixed = source
            .verifier_fixed_opening_v1(registration, query_index, next_query_index)
            .expect("sampled projection fixed rows");
        let expected_current = evaluate_fixed(query_index);
        let expected_next = evaluate_fixed(next_query_index);
        assert_eq!(fixed.current.as_slice(), expected_current.as_slice());
        assert_eq!(fixed.next.as_slice(), expected_next.as_slice());
        let base_current = (0..registration.segment.base_width)
            .map(|column| F(u64::try_from(column + 3).expect("small base")))
            .collect::<Vec<_>>();
        let base_next = (0..registration.segment.base_width)
            .map(|column| F(u64::try_from(column + 37).expect("small base")))
            .collect::<Vec<_>>();
        let aux_current = (0..registration.segment.aux_width)
            .map(|column| F(u64::try_from(column + 71).expect("small aux")))
            .collect::<Vec<_>>();
        let aux_next = (0..registration.segment.aux_width)
            .map(|column| F(u64::try_from(column + 109).expect("small aux")))
            .collect::<Vec<_>>();
        let opening = RegisteredOpenedRowsV1 {
            base_current: &base_current,
            base_next: &base_next,
            aux_current: &aux_current,
            aux_next: &aux_next,
        };
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(query_index as u128));
        let production = source
            .constraint_residues_v1(registration, query_index, next_query_index, x, opening)
            .expect("production projection residues");
        let direct = projection_constraint_residues_v1(
            &base_current,
            &base_next,
            &aux_current,
            &aux_next,
            &fixed.current,
            challenges,
        )
        .expect("direct projection residues");
        assert_eq!(production, direct);
        assert!(
            source
                .constraint_residues_v1(
                    registration,
                    query_index,
                    next_query_index,
                    x.add(F::ONE),
                    opening,
                )
                .is_err(),
            "query coordinate and common-domain point cannot diverge"
        );
    }
    assert!(
        source
            .verifier_fixed_opening_v1(registration, layout.common_lde_size(), 0,)
            .is_err()
    );
    assert!(
        source
            .verifier_fixed_opening_v1(registration, 0, next_stride + 1)
            .is_err(),
        "the verifier-derived next stride cannot be caller-selected"
    );
    let io_registration = layout
        .registered_segment(SegmentAdapterIdV1::ByteMemory, 0)
        .expect("I/O registration");
    assert!(
        source
            .verifier_fixed_opening_v1(io_registration, 0, next_stride)
            .is_err()
    );
    let wrap_query = layout.common_lde_size() - next_stride;
    let wrap_fixed = source
        .verifier_fixed_opening_v1(registration, wrap_query, 0)
        .expect("wrapped verifier fixed rows");
    assert_eq!(wrap_fixed.next_query_index, 0);
    let expected_wrapped_next = evaluate_fixed(0);
    assert_eq!(wrap_fixed.next.as_slice(), expected_wrapped_next.as_slice());
    let base = vec![F::ZERO; registration.segment.base_width];
    let aux = vec![F::ZERO; registration.segment.aux_width];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let x = F(GOLDILOCKS_GENERATOR_V1);
    let cache_len = source.fixed_openings.len();
    let unseen_query = 73;
    let unseen_next = unseen_query + next_stride;
    assert!(
        source
            .constraint_residues_v1(registration, unseen_query, unseen_next, x, opening,)
            .is_err(),
        "a mismatched common-domain point is rejected before fixed sampling"
    );
    let malformed_query = unseen_query + 1;
    let malformed_next = malformed_query + next_stride;
    let malformed_x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(malformed_query as u128));
    let short_base = vec![F::ZERO; registration.segment.base_width - 1];
    let malformed_opening = RegisteredOpenedRowsV1 {
        base_current: &short_base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    assert!(
        source
            .constraint_residues_v1(
                registration,
                malformed_query,
                malformed_next,
                malformed_x,
                malformed_opening,
            )
            .is_err(),
        "malformed opened-row widths are rejected before fixed sampling"
    );
    assert!(
        source
            .constraint_residues_v1(io_registration, 0, next_stride, x, opening,)
            .is_err(),
        "the combined production route rejects a caller-spliced registration"
    );
    assert!(
        source
            .constraint_residues_v1(registration, 0, next_stride + 1, x, opening,)
            .is_err(),
        "the combined production route derives, rather than accepts, the next query"
    );
    assert!(
        source
            .constraint_residues_v1(registration, layout.common_lde_size(), 0, x, opening,)
            .is_err(),
        "the combined production route rejects an out-of-domain query"
    );
    assert_eq!(
        source.fixed_openings.len(),
        cache_len,
        "invalid points, openings, registrations, and queries cannot mutate the verifier cache"
    );
    for mutate_next in [false, true] {
        for column in 0..ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1 {
            let mut changed_fixed = source
                .verifier_fixed_opening_v1(registration, 0, next_stride)
                .expect("opaque fixed rows");
            let row = if mutate_next {
                &mut changed_fixed.next
            } else {
                &mut changed_fixed.current
            };
            row[column] = row[column].add(F::ONE);
            assert!(
                source
                    .constraint_residues_from_fixed_opening_v1(
                        registration,
                        0,
                        next_stride,
                        x,
                        opening,
                        &changed_fixed,
                    )
                    .is_err(),
                "{} fixed column {column} substitution must fail closed",
                if mutate_next { "next" } else { "current" }
            );
        }
    }
    let mut changed_registration = source
        .verifier_fixed_opening_v1(registration, 0, next_stride)
        .expect("opaque fixed rows");
    changed_registration.registration = io_registration;
    assert!(
        source
            .constraint_residues_from_fixed_opening_v1(
                registration,
                0,
                next_stride,
                x,
                opening,
                &changed_registration,
            )
            .is_err(),
        "a fixed opening is registration-tagged"
    );
    let mut changed_query = source
        .verifier_fixed_opening_v1(registration, 0, next_stride)
        .expect("opaque fixed rows");
    changed_query.query_index = 1;
    assert!(
        source
            .constraint_residues_from_fixed_opening_v1(
                registration,
                0,
                next_stride,
                x,
                opening,
                &changed_query,
            )
            .is_err(),
        "a fixed opening is query-tagged"
    );
}
#[test]
fn main_projection_verifier_cache_reuses_caps_and_rejects_the_273rd_opening() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::Projection, 0)
        .expect("projection registration");
    let (statement, _) = crate::privacy_engines::zk_x509::projection_air::tests::fixture();
    let post_base = projection_provider_post_base_v1(&statement);
    let mut source =
        MainProjectionVerifierConstraintSourceV1::for_main_v1(&layout, &statement, post_base)
            .expect("verifier projection source");
    let next_stride = layout.trace_groups[registration.trace_group]
        .next_stride(layout.common_lde_log2)
        .expect("projection next stride");
    let first = source
        .verifier_fixed_opening_v1(registration, 0, next_stride)
        .expect("first two sampled openings");
    assert_eq!(source.fixed_openings.len(), 2);
    let repeated = source
        .verifier_fixed_opening_v1(registration, 0, next_stride)
        .expect("cache reuse");
    assert_eq!(source.fixed_openings.len(), 2);
    assert_eq!(first.current, repeated.current);
    assert_eq!(first.next, repeated.next);
    let mut candidate = 1_usize;
    while source.fixed_openings.len() < VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 {
        if candidate != next_stride * 2 {
            source
                .fixed_openings
                .entry(candidate)
                .or_insert([F::ZERO; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1]);
        }
        candidate += 1;
    }
    assert_eq!(
        source.fixed_openings.len(),
        VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1
    );
    assert!(source.fixed_openings.contains_key(&next_stride));
    assert!(!source.fixed_openings.contains_key(&(next_stride * 2)));
    let base = vec![F::ZERO; registration.segment.base_width];
    let aux = vec![F::ZERO; registration.segment.aux_width];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let common_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).expect("MAIN common root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(next_stride as u128));
    assert!(
        source
            .constraint_residues_v1(registration, next_stride, next_stride * 2, x, opening,)
            .is_err(),
        "one new index beyond the exact 272-opening bound must fail before sampling"
    );
    assert_eq!(
        source.fixed_openings.len(),
        VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1,
        "a rejected opening cannot mutate the verifier cache"
    );
}
#[test]
fn main_projection_concrete_verifier_routes_through_the_closed_provider_set() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::Projection, 0)
        .expect("projection registration");
    let (statement, _) = crate::privacy_engines::zk_x509::projection_air::tests::fixture();
    let post_base = projection_provider_post_base_v1(&statement);
    let mut projection =
        MainProjectionVerifierConstraintSourceV1::for_main_v1(&layout, &statement, post_base)
            .expect("concrete projection verifier");
    let mut log5 = MockMainTraceGroupSourceV1::default();
    let mut log8 = MockMainTraceGroupSourceV1::default();
    let mut log16 = MockMainTraceGroupSourceV1::default();
    let mut log18 = MockMainTraceGroupSourceV1::default();
    let mut log19 = MockMainTraceGroupSourceV1::default();
    let next_stride = layout.trace_groups[registration.trace_group]
        .next_stride(layout.common_lde_log2)
        .expect("projection next stride");
    let query_index = 17;
    let next_query_index = query_index + next_stride;
    let common_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).expect("MAIN common root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(query_index as u128));
    let base = vec![F::ZERO; registration.segment.base_width];
    let aux = vec![F::ZERO; registration.segment.aux_width];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        vec![
            MainOpenedGroupProviderV1::TestLog5(&mut log5),
            MainOpenedGroupProviderV1::TestLog8(&mut log8),
            MainOpenedGroupProviderV1::Projection(&mut projection),
            MainOpenedGroupProviderV1::TestLog16(&mut log16),
            MainOpenedGroupProviderV1::TestLog18(&mut log18),
            MainOpenedGroupProviderV1::TestLog19(&mut log19),
        ],
    )
    .expect("closed provider set with concrete projection verifier");
    let residues = providers
        .registered_constraint_residues_v1(registration, query_index, next_query_index, x, opening)
        .expect("projection routed through concrete verifier variant");
    assert_eq!(residues.len(), registration.segment.constraint_count);
    drop(providers);
    assert_eq!(
        projection.fixed_openings.len(),
        2,
        "provider-set routing must mint verifier-owned fixed openings"
    );
    let mut forged = registration;
    forged.base_start += 1;
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        vec![
            MainOpenedGroupProviderV1::TestLog5(&mut log5),
            MainOpenedGroupProviderV1::TestLog8(&mut log8),
            MainOpenedGroupProviderV1::Projection(&mut projection),
            MainOpenedGroupProviderV1::TestLog16(&mut log16),
            MainOpenedGroupProviderV1::TestLog18(&mut log18),
            MainOpenedGroupProviderV1::TestLog19(&mut log19),
        ],
    )
    .expect("closed provider set");
    assert!(
        providers
            .registered_constraint_residues_v1(forged, query_index, next_query_index, x, opening,)
            .is_err(),
        "caller-spliced registration slices fail before provider dispatch"
    );
}
#[test]
fn main_projection_prover_streams_fixed_polynomials_without_verifier_cache() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let registration = layout
        .registered_segment(SegmentAdapterIdV1::Projection, 0)
        .expect("projection registration");
    let (statement, _) = crate::privacy_engines::zk_x509::projection_air::tests::fixture();
    let post_base = projection_provider_post_base_v1(&statement);
    let source =
        MainProjectionProverConstraintSourceV1::for_main_v1(&layout, &statement, post_base)
            .expect("streaming projection prover source");
    let fixed_rows =
        compile_zk_x509_projection_stark_fixed_rows_v1(&statement).expect("projection fixed rows");
    let mut expected = transpose_array_rows_v1(&fixed_rows).expect("fixed columns");
    let trace_root = goldilocks_primitive_root_v1(registration.segment.trace_log2)
        .expect("projection native root");
    for coefficients in &mut expected {
        goldilocks_ifft_v1(coefficients, trace_root).expect("fixed interpolation");
    }
    let mut seen = 0_usize;
    source
        .stream_fixed_polynomials_v1(|column, coefficients| {
            assert_eq!(coefficients, expected[column].as_slice());
            seen += 1;
            Ok(())
        })
        .expect("one-at-a-time fixed polynomial stream");
    assert_eq!(seen, ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1);
    let base = vec![F::ZERO; registration.segment.base_width];
    let aux = vec![F::ZERO; registration.segment.aux_width];
    let opening = RegisteredOpenedRowsV1 {
        base_current: &base,
        base_next: &base,
        aux_current: &aux,
        aux_next: &aux,
    };
    let fixed = fixed_rows[0];
    let alphas = vec![E::ONE; registration.segment.constraint_count];
    for _ in 0..=VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1 {
        source
            .composition_value_v1(
                registration,
                F(GOLDILOCKS_GENERATOR_V1),
                opening,
                &fixed,
                &alphas,
            )
            .expect("prover composition is independent of verifier cache capacity");
    }
    let mut copied = copied_array_column_v1(&fixed_rows, 0).expect("zeroizing copied fixed column");
    assert!(copied.iter().any(|value| *value != F::ZERO));
    copied.zeroize_private_v1();
    assert!(copied.is_empty());
}
#[test]
fn main_composition_and_opened_evaluator_share_one_exact_checked_path() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let trace_groups = mock_main_opened_groups_v1(&layout);
    let alphas = mock_main_alphas_v1(&layout);
    let mixes = mock_main_mixes_v1(&layout);
    let composition_chunks = (0..COMPOSITION_DEGREE_CHUNKS)
        .map(|index| E::from_base(F(u64::try_from(index + 71).expect("small chunk"))))
        .collect::<Vec<_>>();
    let query_index = 123_456;
    let lane = 0;
    let mut log5 = MockMainTraceGroupSourceV1::default();
    let mut log8 = MockMainTraceGroupSourceV1::default();
    let mut log15 = MockMainTraceGroupSourceV1::default();
    let mut log16 = MockMainTraceGroupSourceV1::default();
    let mut log18 = MockMainTraceGroupSourceV1::default();
    let mut log19 = MockMainTraceGroupSourceV1::default();
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        mock_main_opened_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("exact MAIN providers");
    let direct = main_opened_composition_value_v1(
        &mut providers,
        query_index,
        lane,
        &trace_groups,
        &alphas,
        &[E::ONE; 192],
    )
    .expect("direct MAIN row composition");
    let lde_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).expect("canonical MAIN LDE root");
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(query_index as u128));
    let independently_expected = layout
        .registered_segments
        .iter()
        .copied()
        .enumerate()
        .try_fold(E::ZERO, |sum, (index, registration)| {
            let opening = registered_opened_rows_v1(&layout, registration, &trace_groups)
                .expect("registered opening slice");
            let next_stride = layout.trace_groups[registration.trace_group]
                .next_stride(layout.common_lde_log2)
                .expect("registered next stride");
            let next_query_index = (query_index + next_stride) % layout.common_lde_size();
            let fixed = MainFixedOpenedRowsV1 {
                current: mock_main_fixed_row_v1(registration, query_index),
                next: mock_main_fixed_row_v1(registration, next_query_index),
            };
            let residue = mock_main_residue_value_v1(registration, query_index, x, opening, &fixed);
            accumulator_quotient_value_v1(
                registration.segment,
                x,
                &vec![residue; registration.segment.constraint_count],
                &alphas[index][lane],
            )
            .map(|value| sum.add(value))
        })
        .expect("independent registered quotient sum");
    let independently_expected = independently_expected.add(
        main_aggregate::main_link_composition_for_test_v1(
            &layout,
            &trace_groups,
            x,
            &[E::ONE; 192],
        )
        .unwrap(),
    );
    assert_eq!(direct, independently_expected);
    let evaluated = {
        let mut evaluator = MainOpenedRowEvaluatorV1 {
            providers: &mut providers,
            alphas: &alphas,
            link_alphas: &[E::ONE; 192],
            mixes: &mixes,
        };
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            lane,
            &trace_groups,
            &composition_chunks,
        )
        .expect("MAIN opened evaluation")
    };
    assert_eq!(evaluated.composition, direct);
    let mut expected_fri = E::ZERO;
    for (group, lanes) in trace_groups.iter().zip(&mixes) {
        let mix = &lanes[lane];
        expected_fri = expected_fri.add(
            group
                .base_current
                .iter()
                .zip(&mix.base)
                .fold(E::ZERO, |sum, (value, coefficient)| {
                    sum.add(coefficient.mul_base(*value))
                }),
        );
        expected_fri = expected_fri.add(
            group
                .aux_current
                .iter()
                .zip(&mix.aux)
                .fold(E::ZERO, |sum, (value, coefficient)| {
                    sum.add(coefficient.mul_base(*value))
                }),
        );
    }
    expected_fri = expected_fri.add(
        mix_opened_composition_chunks_v1(&composition_chunks, &mixes[0][lane])
            .expect("composition mix"),
    );
    assert_eq!(evaluated.fri_base, expected_fri);
    let mut changed_rows = trace_groups.clone();
    changed_rows[0].base_current[0] = changed_rows[0].base_current[0].add(F::ONE);
    assert_ne!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &changed_rows,
            &alphas,
            &[E::ONE; 192]
        )
        .expect("semantic row mutation"),
        direct
    );
    let mut short_rows = trace_groups.clone();
    short_rows[0].base_current.pop();
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &short_rows,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    let mut noncanonical_rows = trace_groups.clone();
    noncanonical_rows[0].base_current[0] =
        F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &noncanonical_rows,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &trace_groups[..FULL_PROFILE_TRACE_GROUPS_V1 - 1],
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            layout.common_lde_size(),
            lane,
            &trace_groups,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            SECURITY_LANES,
            &trace_groups,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    let mut short_alphas = alphas.clone();
    short_alphas[0][lane].pop();
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &trace_groups,
            &short_alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    let mut short_alpha_lanes = alphas.clone();
    short_alpha_lanes[0].pop();
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &trace_groups,
            &short_alpha_lanes,
            &[E::ONE; 192]
        )
        .is_err()
    );
    let mut short_mix = mixes.clone();
    short_mix[0][lane].base.pop();
    let mut evaluator = MainOpenedRowEvaluatorV1 {
        providers: &mut providers,
        alphas: &alphas,
        link_alphas: &[E::ONE; 192],
        mixes: &short_mix,
    };
    assert!(
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            lane,
            &trace_groups,
            &composition_chunks,
        )
        .is_err()
    );
    drop(evaluator);
    let mut short_mix_lanes = mixes.clone();
    short_mix_lanes[0].pop();
    let mut evaluator = MainOpenedRowEvaluatorV1 {
        providers: &mut providers,
        alphas: &alphas,
        link_alphas: &[E::ONE; 192],
        mixes: &short_mix_lanes,
    };
    assert!(
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            lane,
            &trace_groups,
            &composition_chunks,
        )
        .is_err()
    );
    drop(evaluator);
    let mut malformed_layout = layout.clone();
    malformed_layout.trace_groups.clear();
    assert!(validate_main_fri_mixes_v1(&malformed_layout, &[]).is_err());
    let mut inconsistent_mix = mixes.clone();
    inconsistent_mix[1][lane].composition[0] = inconsistent_mix[1][lane].composition[0].add(E::ONE);
    let mut evaluator = MainOpenedRowEvaluatorV1 {
        providers: &mut providers,
        alphas: &alphas,
        link_alphas: &[E::ONE; 192],
        mixes: &inconsistent_mix,
    };
    assert!(
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            lane,
            &trace_groups,
            &composition_chunks,
        )
        .is_err()
    );
    drop(evaluator);
    let mut evaluator = MainOpenedRowEvaluatorV1 {
        providers: &mut providers,
        alphas: &alphas,
        link_alphas: &[E::ONE; 192],
        mixes: &mixes,
    };
    assert!(
        aggregate::AggregateOpenedRowEvaluatorV1::evaluate_opened_row_v1(
            &mut evaluator,
            query_index,
            lane,
            &trace_groups,
            &composition_chunks[..COMPOSITION_DEGREE_CHUNKS - 1],
        )
        .is_err()
    );
    drop(evaluator);
    drop(providers);
    log5.short_residues = true;
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        mock_main_opened_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("short-residue adversary registry");
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &trace_groups,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    drop(providers);
    log5.short_residues = false;
    log5.noncanonical_residues = true;
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        mock_main_opened_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("noncanonical-residue adversary registry");
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &trace_groups,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    drop(providers);
    log5.noncanonical_residues = false;
    log5.short_fixed_row = true;
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        mock_main_opened_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("short-fixed-row adversary registry");
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &trace_groups,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
    drop(providers);
    log5.short_fixed_row = false;
    log5.noncanonical_fixed_row = true;
    let mut providers = MainOpenedProviderSetV1::new_v1(
        &layout,
        mock_main_opened_group_providers_v1([
            &mut log5, &mut log8, &mut log15, &mut log16, &mut log18, &mut log19,
        ]),
    )
    .expect("noncanonical-fixed-row adversary registry");
    assert!(
        main_opened_composition_value_v1(
            &mut providers,
            query_index,
            lane,
            &trace_groups,
            &alphas,
            &[E::ONE; 192]
        )
        .is_err()
    );
}
#[test]
fn main_base_commitment_session_mints_pre_aux_only_after_joined_commitment() {
    let root = test_stark_digest_v1(0x41);
    let mut session = main_base_commitment_session_fixture_v1();
    assert_eq!(session.root, None);
    let streamed = aggregate::StreamingRowCommitmentResultV1 {
        commitment: aggregate::StreamingMerkleCommitmentV1 {
            root,
            frontier: Vec::new(),
        },
        opened_rows: BTreeMap::new(),
    };
    session
        .accept_streaming_base_commitment_v1(&streamed)
        .expect("one streamed commitment binds all native MAIN columns");
    assert_eq!(session.root, Some(root));
    let pre_aux = session
        .finish_pre_aux_v1()
        .expect("complete joined base phase");
    assert_eq!(pre_aux.consensus_context_digest_for_test_v1(), [0xB1; 32]);
    assert_eq!(
        pre_aux.main_profile_digest_for_test_v1(),
        TEST_COMPILED_PROFILE_DIGEST_V1
    );
    assert_eq!(pre_aux.main_base_roots_for_test_v1(), [root]);
    derive_zk_x509_credential_pre_aux_binding_v1(
        pre_aux,
        test_stark_digest_v1(0xC1),
        test_stark_digest_v1(0xD1),
        test_stark_digest_v1(0xE1),
    )
    .expect("X5B1 begins only from the completed MAIN phase");
}
#[test]
fn main_base_commitment_session_rejects_omission_duplicate_zero_and_excess() {
    assert!(matches!(
        main_base_commitment_session_fixture_v1().complete_v1(),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
    let mut session = main_base_commitment_session_fixture_v1();
    assert!(matches!(
        session.accept_joined_base_root_v1(PrivacyOuterDigestV1::default()),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
    assert_eq!(session.root, None, "a rejected sentinel is transactional");
    let zero_streamed = aggregate::StreamingRowCommitmentResultV1 {
        commitment: aggregate::StreamingMerkleCommitmentV1 {
            root: PrivacyOuterDigestV1::default(),
            frontier: Vec::new(),
        },
        opened_rows: BTreeMap::new(),
    };
    assert!(matches!(
        session.accept_streaming_base_commitment_v1(&zero_streamed),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
    assert_eq!(session.root, None);
    let root = test_stark_digest_v1(1);
    session
        .accept_joined_base_root_v1(root)
        .expect("joined root");
    for duplicate_or_excess in [
        root,
        test_stark_digest_v1(2),
        PrivacyOuterDigestV1::default(),
    ] {
        assert!(matches!(
            session.accept_joined_base_root_v1(duplicate_or_excess),
            Err(ZkX509StarkErrorV1::TranscriptMismatch)
        ));
        assert_eq!(
            session.root,
            Some(root),
            "rejected replacement must preserve the committed root"
        );
    }
    session.complete_v1().expect("one root completes once");
}
#[test]
fn main_base_commitment_session_rejects_wrong_layout_profile_count_and_internal_state_tampering() {
    fn group(root: PrivacyOuterDigestV1) -> TraceGroupProofV1 {
        TraceGroupProofV1 {
            base_root: root,
            aux_root: PrivacyOuterDigestV1::default(),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        }
    }
    let unpinned_profile = unpinned_main_verifier_profile_fixture_v1();
    let canonical_layout =
        AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    assert!(matches!(
        ZkX509MainBaseCommitmentSessionV1::new_v1(
            TEST_PROOF_INSTANCE_V1,
            &canonical_layout,
            [0xB1; 32],
            unpinned_profile,
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let isolated =
        AggregateProofLayoutV1::for_segments(&[SegmentLayoutV1::for_full_io().expect("full I/O")])
            .expect("isolated I/O layout");
    assert!(matches!(
        ZkX509MainBaseCommitmentSessionV1::new_after_profile_validation_v1(
            TEST_PROOF_INSTANCE_V1,
            &isolated,
            [0xB1; 32],
            TEST_COMPILED_PROFILE_DIGEST_V1,
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let mut wrong_layout = layout.clone();
    wrong_layout.trace_groups.swap(0, 1);
    assert!(matches!(
        ZkX509MainBaseCommitmentSessionV1::new_after_profile_validation_v1(
            TEST_PROOF_INSTANCE_V1,
            &wrong_layout,
            [0xB1; 32],
            TEST_COMPILED_PROFILE_DIGEST_V1,
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert!(matches!(
        ZkX509MainBaseCommitmentSessionV1::new_after_profile_validation_v1(
            TEST_PROOF_INSTANCE_V1,
            &layout,
            [0_u8; 32],
            TEST_COMPILED_PROFILE_DIGEST_V1,
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert!(matches!(
        ZkX509MainBaseCommitmentSessionV1::new_after_profile_validation_v1(
            TEST_PROOF_INSTANCE_V1,
            &layout,
            [0xB1; 32],
            [0_u8; 32],
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let canonical_groups = vec![group(test_stark_digest_v1(1))];
    for wrong_count in [0, 2, FULL_PROFILE_TRACE_GROUPS_V1] {
        let mut groups = canonical_groups.clone();
        groups.resize(wrong_count, group(test_stark_digest_v1(0xFF)));
        let mut session = main_base_commitment_session_fixture_v1();
        assert!(matches!(
            session.accept_decoded_base_groups_v1(&groups),
            Err(ZkX509StarkErrorV1::TranscriptMismatch)
        ));
        assert_eq!(session.root, None);
    }
    let mut zero = main_base_commitment_session_fixture_v1();
    assert!(matches!(
        zero.accept_decoded_base_groups_v1(&[group(PrivacyOuterDigestV1::default())]),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
    assert_eq!(
        zero.root, None,
        "decoded zero root must fail transactionally"
    );
    let mut session = main_base_commitment_session_fixture_v1();
    session
        .accept_decoded_base_groups_v1(&canonical_groups)
        .expect("one decoded joined root");
    assert!(matches!(
        session.accept_decoded_base_groups_v1(&canonical_groups),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
    session
        .finish_pre_aux_v1()
        .expect("decoded canonical root mints pre-aux");
    let mut already_streamed = main_base_commitment_session_fixture_v1();
    already_streamed
        .accept_joined_base_root_v1(test_stark_digest_v1(0x11))
        .unwrap();
    assert!(matches!(
        already_streamed.accept_decoded_base_groups_v1(&canonical_groups),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
    assert_eq!(already_streamed.root, Some(test_stark_digest_v1(0x11)));
    let mut corrupted = main_base_commitment_session_fixture_v1();
    corrupted.root = Some(PrivacyOuterDigestV1::default());
    assert!(matches!(
        corrupted.accept_joined_base_root_v1(test_stark_digest_v1(0x22)),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert!(matches!(
        corrupted.complete_v1(),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let mut corrupted = main_base_commitment_session_fixture_v1();
    corrupted.consensus_context_digest = [0; 32];
    assert!(matches!(
        corrupted.accept_joined_base_root_v1(test_stark_digest_v1(0x11)),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let mut corrupted = main_base_commitment_session_fixture_v1();
    corrupted.main_profile_digest = [0; 32];
    assert!(matches!(
        corrupted.accept_joined_base_root_v1(test_stark_digest_v1(0x11)),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    let mut corrupted = main_base_commitment_session_fixture_v1();
    corrupted.layout.trace_groups.swap(0, 1);
    assert!(matches!(
        corrupted.accept_joined_base_root_v1(test_stark_digest_v1(0x11)),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    for group in 0..FULL_PROFILE_TRACE_GROUPS_V1 {
        let mut corrupted = main_base_commitment_session_fixture_v1();
        corrupted.layout.trace_groups[group].native_trace_log2 += 1;
        assert!(
            corrupted
                .accept_joined_base_root_v1(test_stark_digest_v1(0x11))
                .is_err(),
            "native domain substitution at group {group}"
        );
    }
}
#[test]
fn main_joined_row_order_and_base_aux_phase_are_domain_bound() {
    use aggregate::joined_trace::{JoinedTraceColumnKindV1, JoinedTraceCommitmentPlanV1};
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let shared = layout.as_shared().unwrap();
    let plan = JoinedTraceCommitmentPlanV1::new_v1(
        AGGREGATE_PARAMETERS_V1,
        &shared,
        JoinedTraceColumnKindV1::Base,
    )
    .unwrap();
    let mut rows = layout
        .trace_groups
        .iter()
        .enumerate()
        .map(|(group, shape)| {
            (0..shape.base_width)
                .map(|column| F((1 + group * 10_000 + column) as u64))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let hash = |rows: &[Vec<F>]| {
        plan.leaf_hash_v1(
            &main_domains_v1(TEST_PROOF_INSTANCE_V1),
            7,
            &rows.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
    };
    let canonical = hash(&rows).unwrap();
    rows[0].swap(0, 1);
    assert_ne!(
        hash(&rows).unwrap(),
        canonical,
        "native column order is committed"
    );
    rows[0].swap(0, 1);
    for group in 0..FULL_PROFILE_TRACE_GROUPS_V1 {
        let value = rows[group][0];
        rows[group][0] = value.add(F::ONE);
        assert_ne!(
            hash(&rows).unwrap(),
            canonical,
            "every logical native group is committed"
        );
        rows[group][0] = value;
    }
    let omitted = &rows[..rows.len() - 1];
    assert!(hash(omitted).is_err());
    let mut duplicated = rows.clone();
    duplicated.push(rows[0].clone());
    assert!(hash(&duplicated).is_err());
    let aux = JoinedTraceCommitmentPlanV1::new_v1(
        AGGREGATE_PARAMETERS_V1,
        &shared,
        JoinedTraceColumnKindV1::Aux,
    )
    .unwrap();
    let aux_rows = layout
        .trace_groups
        .iter()
        .map(|shape| vec![F::ONE; shape.aux_width])
        .collect::<Vec<_>>();
    let auxiliary = aux
        .leaf_hash_v1(
            &main_domains_v1(TEST_PROOF_INSTANCE_V1),
            7,
            &aux_rows.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .unwrap();
    assert_ne!(
        auxiliary, canonical,
        "base and auxiliary commitments have distinct phase domains"
    );
    let bind = |root| {
        let mut session = main_base_commitment_session_fixture_v1();
        session.accept_joined_base_root_v1(root).unwrap();
        derive_zk_x509_credential_pre_aux_binding_v1(
            session.finish_pre_aux_v1().unwrap(),
            test_stark_digest_v1(0xC1),
            test_stark_digest_v1(0xD1),
            test_stark_digest_v1(0xE1),
        )
        .unwrap()
    };
    assert_ne!(
        bind(canonical),
        bind(auxiliary),
        "a root from the wrong phase changes X5B1"
    );
}
fn tiny_main_mask_group_fixture_v1(seed: u8) -> main_aggregate::MainTraceMaskGroupV1 {
    let mut rng = StdRng::from_seed([seed; 32]);
    main_aggregate::MainTraceMaskGroupV1::sample_v1(2, 11, 1, &mut rng, |_| {
        Ok(ZeroizingMainTraceColumnV1(vec![F(u64::from(seed)); 4]))
    })
    .expect("tiny original-mask group")
}
#[test]
fn main_polynomial_set_fails_closed_on_count_shape_and_phase_lifecycle() {
    assert!(core::mem::needs_drop::<MainTracePolynomialSetV1>());
    assert!(core::mem::needs_drop::<
        ZkX509MainAwaitingCredentialBindingV1<'static>,
    >());
    assert!(core::mem::needs_drop::<ZkX509MainCompositionPhaseV1<'static>>());
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    for hostile_count in [
        FULL_PROFILE_TRACE_GROUPS_V1 - 1,
        FULL_PROFILE_TRACE_GROUPS_V1 + 1,
    ] {
        let polynomials = (0..hostile_count)
            .map(|index| {
                tiny_main_mask_group_fixture_v1(
                    u8::try_from(index + 1).expect("small hostile count"),
                )
            })
            .collect();
        assert!(matches!(
            MainTracePolynomialSetV1::from_ordered_v1(
                &layout,
                MainTraceColumnKindV1::Base,
                polynomials,
            ),
            Err(ZkX509StarkErrorV1::TranscriptMismatch)
        ));
    }
    // Six mask groups are still rejected when any native/commitment-domain
    // shape is not the verifier-fixed MAIN shape. The consuming constructor
    // owns the vector, so every original secret mask clears on failure.
    let wrong_shape = (0..FULL_PROFILE_TRACE_GROUPS_V1)
        .map(|index| {
            tiny_main_mask_group_fixture_v1(u8::try_from(index + 0x21).expect("six fixtures"))
        })
        .collect();
    assert!(matches!(
        MainTracePolynomialSetV1::from_ordered_v1(&layout, MainTraceColumnKindV1::Aux, wrong_shape,),
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    ));
}
#[test]
fn main_phase_source_retains_original_masks_and_authenticates_replay() {
    let source = include_str!("main_aggregate.rs");
    let replay_source = include_str!("main_trace_replay.rs");
    let helper_start = replay_source
        .find("fn sample_and_replay_batch_with_v1<")
        .expect("bounded first-pass sampler");
    let helper_end = replay_source[helper_start..]
        .find("fn replay_v1(")
        .map(|offset| helper_start + offset)
        .expect("test replay boundary");
    let helper = &replay_source[helper_start..helper_end];
    assert!(
        helper.contains("sample_trace_mask_v1(MASK_DEGREE, rng)") && helper.contains("self.masks"),
        "MAIN sampling retains each original independent mask"
    );
    assert!(
        helper.contains("drop(source)"),
        "source header allocation drops before inverse staging"
    );
    for forbidden in [
        "MaskedTracePolynomialSetV1::sample_columns_v1",
        "commit_masked_trace_columns_v1(",
        "commit_masked_trace_columns_retaining_encrypted_scratch_v1",
        "spill_replayed_masked_trace_columns_v1",
        "replay_masked_trace_columns_via_encrypted_scratch_v1",
    ] {
        assert!(
            !replay_source[..replay_source.find("\n#[cfg(test)]\nmod tests {").unwrap()]
                .contains(forbidden),
            "MAIN cannot substitute whole-matrix retention or a spool"
        );
    }
    let replay_start = replay_source
        .find("fn replay_batch_v1(")
        .expect("live original-mask batch replay");
    let replay_end = replay_source[replay_start..]
        .find("/// Six exact groups")
        .map(|offset| replay_start + offset)
        .expect("mask replay end");
    let replay = &replay_source[replay_start..replay_end];
    assert!(replay.contains("policy.inverse_with_v1(&mut batch, root"));
    let adapter = include_str!("main_bounded_transform.rs");
    let inverse_start = adapter
        .find("fn inverse_with_v1(")
        .expect("bounded inverse");
    let inverse_end = adapter[inverse_start..]
        .find("fn private_with_v1(")
        .map(|offset| inverse_start + offset)
        .expect("shared private adapter");
    assert!(adapter[inverse_start..inverse_end].contains("Direction::Inverse"));
    let inverse = replay.find("policy.inverse_with_v1").unwrap();
    let masking = replay
        .find("for (native, mask) in batch.iter_mut().zip(masks)")
        .unwrap();
    assert!(
        inverse < masking,
        "inverse completion must precede mask application"
    );
    assert!(replay.contains("mask.coefficients()"));
    assert!(replay.contains("coefficients[degree].sub(random)"));
    assert!(replay.contains("coefficients[native_rows + degree].add(random)"));
    assert!(!replay.contains("sample_trace_mask_v1"));
    assert!(
        !replay.contains("rng"),
        "replay cannot resample a committed mask"
    );
    assert!(replay_source.contains("masks: Vec<ReplayableTraceMaskV1>"));
    let phase_start = source
        .find("pub fn commit_zk_x509_main_base_phase_v1_with_rng")
        .expect("typed MAIN phase one");
    let phase_end = source[phase_start..]
        .find("/// Exact six-provider registry")
        .map(|offset| phase_start + offset)
        .expect("typed MAIN phase end");
    let phases = &source[phase_start..phase_end];
    let bound_start = phases
        .find("pub(crate) fn bind_credential_pre_aux_v1_with_rng")
        .expect("credential-bound phase");
    let base = &phases[..bound_start];
    let base_quarantine = base
        .find("goldilocks_transform_completion_uncertain_v1()")
        .expect("base quarantine gate");
    let preallocation = base
        .find("check_before_sources_v1")
        .expect("source preallocation gate");
    let source_shapes = base
        .find("check_source_shapes_v1")
        .expect("native source shape forecast");
    let p256_construction = base
        .find("P256MainBaseSourceV1::new_v1")
        .expect("P256 construction");
    let actual_capacities = base
        .find("check_native_sources_v1")
        .expect("actual source capacity gate");
    let base_entropy = base
        .find("sample_and_commit_joined_v1")
        .expect("first base mask sampling");
    assert!(
        base_quarantine < preallocation
            && preallocation < source_shapes
            && source_shapes < p256_construction
            && p256_construction < actual_capacities
            && actual_capacities < base_entropy,
        "source admission must precede bulk allocation, and actual capacity admission must precede entropy"
    );
    let bound = &phases[bound_start..];
    let aux_quarantine = bound
        .find("goldilocks_transform_completion_uncertain_v1()")
        .expect("auxiliary quarantine gate");
    let bound_preallocation = bound
        .find("check_before_sources_v1")
        .expect("bound source preallocation gate");
    let bound_construction = bound
        .find("projection.bind_challenges_v1")
        .expect("bound source construction");
    let bound_capacities = bound
        .find("check_native_sources_v1")
        .expect("bound capacity gate");
    let aux_entropy = bound
        .find("sample_and_commit_joined_v1")
        .expect("first auxiliary mask sampling");
    assert!(
        aux_quarantine < bound_preallocation
            && bound_preallocation < bound_construction
            && bound_construction < bound_capacities
            && bound_capacities < aux_entropy,
        "bound sources must be admitted before auxiliary entropy"
    );
    assert_eq!(
        phases
            .matches("MainTracePolynomialSetV1::sample_and_commit_joined_v1(")
            .count(),
        2,
        "both initial roots must consume the same bounded sample-and-commit path"
    );
    let initial = &replay_source[replay_source
        .find("fn sample_and_commit_joined_v1<")
        .unwrap()
        ..replay_source.find("fn commit_joined_batches_v1(").unwrap()];
    assert!(initial.contains("FULL_PROFILE_TRACE_GROUPS_V1"));
    assert!(initial.contains(".try_into()"));
    assert!(initial.contains("set.validate_v1(layout, kind)?"));
    assert!(initial.contains("MainTraceMaskGroupV1::empty_v1"));
    let provenance = phases
        .find("matches_main_pre_aux_v1")
        .expect("provenance check");
    let absorption = phases
        .find("absorb_zk_x509_credential_pre_aux_binding_v1")
        .expect("local binding absorption");
    let child_bind = phases
        .find("projection.bind_challenges_v1")
        .expect("child bind");
    assert!(
        provenance < absorption && provenance < child_bind,
        "cross-phase provenance must fail before transcript or child mutation"
    );
}
fn empty_main_composition_chunks_v1() -> Vec<Vec<Vec<E>>> {
    (0..SECURITY_LANES)
        .map(|_| (0..COMPOSITION_DEGREE_CHUNKS).map(|_| Vec::new()).collect())
        .collect()
}
#[test]
fn main_coefficient_accumulator_is_bounded_transactional_and_order_independent() {
    let coefficient_cap = 8;
    let value = |value| E::from_base(F(value));
    let mut first = empty_main_composition_chunks_v1();
    first[0][0] = vec![value(1), value(2), value(3)];
    first[0][2] = vec![value(9)];
    let mut second = empty_main_composition_chunks_v1();
    second[0][0] = vec![value(4), value(5)];
    second[0][1] = vec![value(7), value(8), value(9), value(10)];
    second[0][2] = vec![value(9).neg()];
    let mut first_then_second = empty_main_composition_chunks_v1();
    add_main_composition_coefficient_chunks_v1(&mut first_then_second, &first, coefficient_cap)
        .expect("first contribution");
    add_main_composition_coefficient_chunks_v1(&mut first_then_second, &second, coefficient_cap)
        .expect("second contribution");
    let mut second_then_first = empty_main_composition_chunks_v1();
    add_main_composition_coefficient_chunks_v1(&mut second_then_first, &second, coefficient_cap)
        .expect("second contribution first");
    add_main_composition_coefficient_chunks_v1(&mut second_then_first, &first, coefficient_cap)
        .expect("first contribution second");
    assert_eq!(first_then_second, second_then_first);
    assert_eq!(
        first_then_second[0][2],
        vec![E::ZERO],
        "exact cancellation must preserve the public contributor extent"
    );
    let canonical = first_then_second.clone();
    let mut wrong_lanes = second.clone();
    wrong_lanes.pop();
    assert!(matches!(
        add_main_composition_coefficient_chunks_v1(
            &mut first_then_second,
            &wrong_lanes,
            coefficient_cap,
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert_eq!(first_then_second, canonical);
    let mut wrong_chunks = second.clone();
    wrong_chunks[0].pop();
    assert!(matches!(
        add_main_composition_coefficient_chunks_v1(
            &mut first_then_second,
            &wrong_chunks,
            coefficient_cap,
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert_eq!(first_then_second, canonical);
    let mut oversized = second.clone();
    oversized[0][0].resize(coefficient_cap + 1, E::ONE);
    assert!(matches!(
        add_main_composition_coefficient_chunks_v1(
            &mut first_then_second,
            &oversized,
            coefficient_cap,
        ),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert_eq!(first_then_second, canonical);
    assert!(matches!(
        add_main_composition_coefficient_chunks_v1(&mut first_then_second, &second, 0,),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
    assert_eq!(first_then_second, canonical);
}
#[test]
fn main_coefficient_accumulator_geometry_is_independent_of_values_and_cancellation() {
    let coefficient_cap = 8;
    let public_extents = [[8, 5, 0, 3, 1, 7], [6, 8, 4, 0, 1, 2], [8, 8, 4, 3, 1, 7]];
    assert_eq!(COMPOSITION_DEGREE_CHUNKS, public_extents[0].len());
    let evaluate = |coefficients: &[E], point: E| {
        coefficients
            .iter()
            .rev()
            .fold(E::ZERO, |sum, coefficient| sum.mul(point).add(*coefficient))
    };
    let mut expected_geometry = None;
    // Equal public extents cover zero, dense and exact-cancellation secrets.
    for mode in 0..3 {
        let mut accumulator = ZeroizingExtensionLanesV1::new(
            empty_main_composition_chunks_v1(),
            zeroize_extension_lanes_v1,
        );
        for chunk in accumulator.iter_mut().flatten() {
            chunk.try_reserve_exact(coefficient_cap).unwrap();
        }
        let allocations: Vec<_> = accumulator
            .iter()
            .flatten()
            .map(|chunk| (chunk.as_ptr(), chunk.capacity()))
            .collect();
        let mut expected =
            vec![vec![vec![E::ZERO; coefficient_cap]; COMPOSITION_DEGREE_CHUNKS]; SECURITY_LANES];
        let mut retained_extents = [0; COMPOSITION_DEGREE_CHUNKS];
        let mut geometry = Vec::new();
        for (stage, extents) in public_extents.iter().enumerate() {
            let mut contribution = ZeroizingExtensionLanesV1::new(
                empty_main_composition_chunks_v1(),
                zeroize_extension_lanes_v1,
            );
            for lane in 0..SECURITY_LANES {
                for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
                    for degree in 0..extents[chunk] {
                        let coefficient = if mode == 0 {
                            E::ZERO
                        } else if mode == 2 && stage == 2 {
                            expected[lane][chunk][degree].neg()
                        } else {
                            let value = (stage * 100 + lane * 50 + chunk * 8 + degree + 1) as u64;
                            E::canonical([value, value + 1, value + 2, value + 3]).unwrap()
                        };
                        contribution[lane][chunk].push(coefficient);
                        expected[lane][chunk][degree] =
                            expected[lane][chunk][degree].add(coefficient);
                    }
                }
            }
            add_main_composition_coefficient_chunks_v1(
                &mut accumulator,
                &contribution,
                coefficient_cap,
            )
            .unwrap();
            for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
                retained_extents[chunk] = retained_extents[chunk].max(extents[chunk]);
            }
            for lane in 0..SECURITY_LANES {
                for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
                    assert_eq!(
                        accumulator[lane][chunk].as_slice(),
                        &expected[lane][chunk][..retained_extents[chunk]]
                    );
                    for point in [E::ZERO, E::ONE, E::from_base(F(53))] {
                        assert_eq!(
                            evaluate(&accumulator[lane][chunk], point),
                            evaluate(&expected[lane][chunk], point)
                        );
                    }
                }
            }
            assert_eq!(
                accumulator
                    .iter()
                    .flatten()
                    .map(|chunk| (chunk.as_ptr(), chunk.capacity()))
                    .collect::<Vec<_>>(),
                allocations
            );
            geometry.push(
                accumulator
                    .iter()
                    .flatten()
                    .map(|chunk| (chunk.len(), chunk.capacity()))
                    .collect::<Vec<_>>(),
            );
        }
        if mode == 2 {
            assert!(
                accumulator
                    .iter()
                    .flatten()
                    .flatten()
                    .all(|value| *value == E::ZERO)
            );
            assert!(accumulator.iter().flatten().any(|chunk| !chunk.is_empty()));
        }
        if let Some(expected_geometry) = &expected_geometry {
            assert_eq!(&geometry, expected_geometry);
        } else {
            expected_geometry = Some(geometry);
        }
    }
}
#[test]
fn composition_chunk_split_rejects_hidden_high_degree_coefficients() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let shared = layout.as_shared().expect("shared MAIN layout");
    let value = |value| E::from_base(F(value));
    let mut coefficients = vec![value(1), value(2), value(3), E::ZERO, E::ZERO, E::ZERO];
    let chunks =
        composition_coefficient_chunks_v1(&coefficients, 2, &shared).expect("zero high tail");
    assert_eq!(chunks.len(), COMPOSITION_DEGREE_CHUNKS);
    assert_eq!(chunks[0], coefficients);
    coefficients[5] = value(1);
    assert!(matches!(
        composition_coefficient_chunks_v1(&coefficients, 2, &shared),
        Err(ZkX509StarkErrorV1::ConstraintOpening)
    ));
    assert!(matches!(
        composition_coefficient_chunks_v1(&coefficients, usize::MAX, &shared),
        Err(ZkX509StarkErrorV1::ProfileMismatch)
    ));
}
#[test]
fn main_finish_verifier_and_consensus_source_use_only_the_closed_release_path() {
    let source = include_str!("main_aggregate.rs");
    let finish_start = source
        .find("fn finish_original_openings_v1")
        .expect("original MAIN FRI and query finalizer");
    let finish_end = source[finish_start..]
        .find("/// Exact six-provider registry")
        .map(|offset| finish_start + offset)
        .expect("MAIN finish end");
    let finish = &source[finish_start..finish_end];
    assert!(finish.contains("commit_joined_v1"));
    assert!(finish.contains("MainTraceReplaySourcesV1::Bound"));
    let base_replay = finish
        .find("let base_openings = self.base_polynomials.commit_joined_v1")
        .expect("base opening replay");
    let aux_replay = finish
        .find("let aux_openings = self.aux_polynomials.commit_joined_v1")
        .expect("auxiliary opening replay");
    let base_root_check = finish
        .find("base_openings.commitment.root != trace_group.base_root")
        .expect("base root equality");
    let aux_root_check = finish
        .find("aux_openings.commitment.root != trace_group.aux_root")
        .expect("auxiliary root equality");
    let publish = finish
        .find("trace_group.base_frontier =")
        .expect("opening publication");
    assert!(base_replay < base_root_check && aux_replay < base_root_check);
    assert!(base_root_check < publish && aux_root_check < publish);
    let joint_source = include_str!("main_joint.rs");
    let joint_start = joint_source
        .find("pub(crate) fn commit_joint_oracles_v1")
        .expect("mandatory joint composition owner");
    let joint_end = joint_source[joint_start..]
        .find("impl<'a> MainAwaitingJointPointV1")
        .map(|offset| joint_start + offset)
        .expect("joint point transition");
    let joint = &joint_source[joint_start..joint_end];
    assert!(joint.contains("main_composition_material_with_ca_v1("));
    assert!(joint.contains("MainTraceReplaySourcesV1::Bound"));
    assert!(joint.contains("Some(MainCaCompositionContributionV1"));
    assert!(joint_source.contains("self.oracles.phase.finish_original_openings_v1("));
    assert!(joint_source.contains("Some(MainCaDeepContributionV1"));
    assert!(!source.contains("fn finish_v1_with_rng"));
    assert!(!source.contains("fn composition_material_v1"));
    assert!(!source.contains("fn main_composition_material_from_polynomials_v1"));
    let combined_start = source
        .find("fn main_composition_material_with_ca_v1<R: TryRngCore>")
        .expect("canonical MAIN composition owner");
    let combined = &source[combined_start..];
    let links = combined
        .find(".accumulate_v1(")
        .expect("private endpoint contributions");
    let blind = combined
        .find(".blind_v1(lane, rng)")
        .expect("canonical quotient masks");
    let evaluate = combined
        .find("evaluate_main_composition_coefficient_chunks_v1(")
        .expect("masked coefficient evaluation");
    assert!(links < blind && blind < evaluate);
    assert!(!finish.contains("verify_opened_query_relations_with_deep_v1"));
    for forbidden in [
        "spill_replayed_masked_trace_columns_v1",
        "replay_masked_trace_columns_via_encrypted_scratch_v1",
        "EncryptedFieldMatrixScratch",
        "native_base_column_v1",
        "native_aux_column_v1",
    ] {
        assert!(
            !finish.contains(forbidden),
            "MAIN finish must not use {forbidden}"
        );
    }
    let verifier_source = include_str!("main_joint.rs");
    let verifier = &verifier_source[verifier_source
        .find("impl MainJointVerifierDeepV1")
        .unwrap()..];
    let grinding = verifier
        .find("verify_grinding_nonce_v1")
        .expect("grinding verification");
    let queries = verifier
        .find("let indices = query_indices_v1")
        .expect("post-grinding queries");
    let fixed = verifier
        .find("prepare_complete_oods_fixed_v1")
        .expect("verifier-derived fixed openings");
    let constraints = verifier
        .find("main_oods::verify_main_deep_constraints_with_ca_v1")
        .expect("complete MAIN out-of-domain relation");
    let authenticated_queries = verifier
        .find("verify_opened_query_relations_after_complete_oods_v1")
        .expect("current-row DEEP/FRI verification");
    assert!(
        grinding < queries
            && queries < fixed
            && fixed < constraints
            && constraints < authenticated_queries
    );
    assert!(!verifier.contains("verify_opened_query_relations_with_deep_v1"));
    let engine = include_str!("../engine.rs");
    let engine_production = &engine[..engine
        .find("\n#[cfg(test)]\nmod tests {")
        .expect("engine production/test boundary")];
    assert!(engine_production.contains("MainJointVerifierOraclesV1::new_v1"));
    assert!(engine_production.contains("CaJointVerifierOraclesV1::new_v1"));
    assert!(engine_production.contains(".bind_ca_openings_v1"));
    assert_eq!(engine_production.matches(".finish_v1(binding)").count(), 2);
    assert!(!engine_production.contains("ConsensusVerifierUnavailable"));
}
#[test]
fn main_local_transcript_separates_binding_before_base_after_aux_and_wrong_outer_root() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().expect("canonical MAIN layout");
    let base_roots = (0..ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1)
        .map(|index| TraceGroupProofV1 {
            base_root: test_stark_digest_v1(u8::try_from(index + 1).expect("root fixture byte")),
            aux_root: test_stark_digest_v1(u8::try_from(index + 0x41).expect("root fixture byte")),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        })
        .collect::<Vec<_>>();
    let pre_aux = ZkX509CredentialMainPreAuxV1::fixture_for_test_v1(
        [0x81; 32],
        TEST_COMPILED_PROFILE_DIGEST_V1,
        base_roots
            .iter()
            .map(|group| group.base_root)
            .collect::<Vec<_>>()
            .try_into()
            .expect("one joined MAIN root"),
    );
    let binding = derive_zk_x509_credential_pre_aux_binding_v1(
        pre_aux,
        test_stark_digest_v1(0x91),
        test_stark_digest_v1(0xA1),
        test_stark_digest_v1(0xB1),
    )
    .expect("canonical outer binding");
    let mut changed_pre_aux = pre_aux;
    mutate_stark_digest_v1(&mut changed_pre_aux.main_base_roots_mut_for_test_v1()[0]);
    let changed_binding = derive_zk_x509_credential_pre_aux_binding_v1(
        changed_pre_aux,
        test_stark_digest_v1(0x91),
        test_stark_digest_v1(0xA1),
        test_stark_digest_v1(0xB1),
    )
    .expect("binding under a hostile joined MAIN root");
    let alpha = |order: u8, binding: ZkX509CredentialPreAuxBindingV1| {
        let mut transcript = new_main_transcript_after_profile_validation_v1(
            TEST_PROOF_INSTANCE_V1,
            &[0x81; 32],
            TEST_COMPILED_PROFILE_DIGEST_V1,
        )
        .expect("test MAIN transcript");
        absorb_aggregate_layout_v1(
            TEST_PROOF_INSTANCE_V1,
            &mut transcript,
            MAIN_LAYOUT_DOMAIN_V1,
            &layout,
        )
        .expect("MAIN layout");
        if order == 1 {
            absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, binding)
                .expect("premature binding still frames distinctly");
        }
        aggregate::absorb_base_roots_v1(
            &mut transcript,
            &main_domains_v1(TEST_PROOF_INSTANCE_V1),
            &base_roots,
        )
        .expect("ordered base roots");
        if order == 0 {
            absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, binding)
                .expect("canonical binding");
        }
        aggregate::absorb_aux_roots_v1(
            &mut transcript,
            &main_domains_v1(TEST_PROOF_INSTANCE_V1),
            &base_roots,
        )
        .expect("ordered aux roots");
        if order == 2 {
            absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, binding)
                .expect("late binding still frames distinctly");
        }
        derive_constraint_alphas_v1(&mut transcript, &layout).expect("alphas")[0][0][0]
    };
    let canonical = alpha(0, binding);
    assert_ne!(
        canonical,
        alpha(1, binding),
        "binding-before-base must separate"
    );
    assert_ne!(
        canonical,
        alpha(2, binding),
        "binding-after-aux must separate"
    );
    assert_ne!(
        canonical,
        alpha(0, changed_binding),
        "changing only the outer-bound log19 root must separate"
    );
}
#[test]
fn full_profile_layout_is_constant_exact_and_rejects_registration_splices() {
    let sha_layout = AggregateProofLayoutV1::for_equal_log_buckets_v1(
        &canonical_sha_segment_layouts_v1().expect("canonical SHA slices"),
    )
    .expect("canonical SHA-only aggregate layout");
    let sha_shared_layout = sha_layout.as_shared().expect("shared SHA layout");
    assert_eq!(
            maximum_encoded_aggregate_proof_bytes_v1(&sha_layout)
                .expect("maximum SHA-only X5S1 size")
                .checked_sub(
                    aggregate::exact_deep_opening_bytes_v1(
                        AGGREGATE_PARAMETERS_V1,
                        &sha_shared_layout,
                    )
                    .expect("exact SHA DEEP bytes"),
                )
                .expect("SHA pre-DEEP size"),
            ZK_X509_SHA_MAX_ENCODED_PROOF_BYTES_V1,
        );
    let layout = AggregateProofLayoutV1::for_full_profile_v1()
        .expect("canonical fixed-capacity X5S1 layout");
    layout
        .validate_exact_full_profile_registration_v1()
        .expect("exact full registration");
    assert_eq!(
        layout.registered_segments.len(),
        FULL_PROFILE_LOGICAL_REGISTRATIONS_V1
    );
    assert_eq!(layout.trace_groups.len(), FULL_PROFILE_TRACE_GROUPS_V1);
    assert_eq!(
        layout
            .trace_groups
            .iter()
            .map(|group| group.column_chunks)
            .sum::<usize>(),
        FULL_PROFILE_PHYSICAL_CHUNKS_V1
    );
    assert_eq!(layout.common_lde_log2, ZK_X509_MAIN_COMMON_LDE_LOG2_V1);
    assert_eq!(
        layout
            .trace_groups
            .iter()
            .map(|group| group.native_trace_log2)
            .collect::<Vec<_>>(),
        vec![5, 8, 15, 16, 18, 19]
    );
    let maximum_encoded_bytes =
        maximum_encoded_aggregate_proof_bytes_v1(&layout).expect("maximum X5S1 size");
    let main_deep_bytes = aggregate::exact_deep_opening_bytes_v1(
        AGGREGATE_PARAMETERS_V1,
        &layout.as_shared().expect("shared full-profile layout"),
    )
    .expect("exact main DEEP bytes");
    assert_eq!(
        maximum_encoded_bytes
            .checked_sub(main_deep_bytes)
            .expect("main pre-DEEP size"),
        usize::try_from(ZK_X509_MAIN_PRE_DEEP_MAXIMUM_BYTES_V1)
            .expect("profile proof bound fits usize")
    );
    assert_eq!(maximum_encoded_bytes, 7_908_768);
    assert!(
        maximum_encoded_bytes
            < usize::try_from(ZK_X509_MAX_PROOF_BYTES_V1).expect("consensus proof cap fits usize"),
        "the complete joined MAIN opening schedule fits the unchanged release cap"
    );
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        let arithmetic = layout
            .registered_segment(
                SegmentAdapterIdV1::P256Arithmetic,
                p256_instance_v1(signature, 0).expect("instance"),
            )
            .expect("one arithmetic registration per signature");
        assert_eq!(
            p256_instance_parts_v1(arithmetic.segment.instance),
            Some((signature, 0))
        );
    }
    let mut mutations = Vec::new();
    let mut changed = layout.clone();
    changed.registered_segments.remove(0);
    mutations.push(changed);
    let mut changed = layout.clone();
    changed
        .registered_segments
        .push(changed.registered_segments[0]);
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.registered_segments.swap(0, 1);
    mutations.push(changed);
    let mut changed = layout.clone();
    let sha = changed
        .registered_segments
        .iter()
        .position(|registration| registration.segment.adapter == SegmentAdapterIdV1::Sha256CallBus)
        .expect("SHA registration");
    changed.registered_segments[sha].segment.instance = 4;
    mutations.push(changed);
    let mut changed = layout.clone();
    let der = changed
        .registered_segments
        .iter()
        .position(|registration| registration.segment.adapter == SegmentAdapterIdV1::StrictDer)
        .expect("DER registration");
    changed.registered_segments[der].segment.active_rows -= 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.trace_groups[5].column_chunks -= 1;
    mutations.push(changed);
    let mut changed = layout.clone();
    changed.common_lde_log2 = ZK_X509_MAIN_COMMON_LDE_LOG2_V1 - 1;
    mutations.push(changed);
    for (index, mutation) in mutations.iter().enumerate() {
        assert!(
            mutation
                .validate_exact_full_profile_registration_v1()
                .is_err(),
            "full-layout splice {index} must fail closed"
        );
    }
}
#[test]
fn projection_challenge_labels_are_explicit_and_pairwise_distinct() {
    let labels = ZK_X509_PROJECTION_CHALLENGE_LABELS_V1
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(labels.len(), ZK_X509_PROJECTION_COPY_LANES_V1 * 7);
    let unique = labels.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), labels.len());
}
