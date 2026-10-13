// BFV arithmetic conformance fixtures and STARK rejection profiles.
//
// Included lexically by `zk_stark::tests` through `zk_stark/tests.rs`.
fn bfv_test_public_digest(
    params: &StarkFriParamsV1,
    statement_hash: iroha_crypto::Hash,
) -> GoldilocksDigest384V1 {
    let statement_bytes: [u8; iroha_crypto::Hash::LENGTH] = statement_hash.into();
    stark_public_digest_v1(
        params,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
        &statement_bytes,
    )
    .expect("derive BFV six-lane public digest")
}
fn build_bfv_full_bootstrap_stark_test_prover_input_materials()
-> [iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1; 2] {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/soracloud/bfv_full_bootstrap_conformance_v1.norito"
    ));
    let materials: [iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1; 2] =
        norito::decode_canonical(bytes).expect("decode canonical two-slot arithmetic material");
    for (slot, material) in materials.iter().enumerate() {
        assert_eq!(
            material.proof_input_material.witness_material.slot_index, slot as u32,
            "conformance material retains both distinct execution statements",
        );
        iroha_crypto::validate_bfv_full_bootstrap_execution_prover_input_material_v1(material)
            .expect("conformance material satisfies every arithmetic and artifact relation");
    }
    assert_eq!(
        norito::encode_canonical(&materials).expect("re-encode canonical arithmetic material"),
        bytes.as_slice(),
        "conformance fixture has one exact encoding",
    );
    materials
}
// Strict arithmetic material validation and canonical proof construction are expensive.
// Sharing them prevents parallel test workers from reconstructing the same relation.
struct BfvFullBootstrapStarkTestFixture {
    material: iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1,
    envelope_bytes: std::sync::OnceLock<Vec<u8>>,
}
fn build_bfv_full_bootstrap_stark_test_fixtures() -> [BfvFullBootstrapStarkTestFixture; 2] {
    build_bfv_full_bootstrap_stark_test_prover_input_materials().map(|material| {
        BfvFullBootstrapStarkTestFixture {
            material,
            envelope_bytes: std::sync::OnceLock::new(),
        }
    })
}
fn bfv_full_bootstrap_stark_test_fixture_for_slot(
    slot_index: u32,
) -> &'static BfvFullBootstrapStarkTestFixture {
    static FIXTURES: std::sync::OnceLock<[BfvFullBootstrapStarkTestFixture; 2]> =
        std::sync::OnceLock::new();
    let slot_index = match slot_index {
        0 => 0,
        1 => 1,
        _ => panic!("BFV full-bootstrap STARK test fixture only supports slots 0 and 1"),
    };
    &FIXTURES.get_or_init(build_bfv_full_bootstrap_stark_test_fixtures)[slot_index]
}
fn bfv_full_bootstrap_stark_test_fixture() -> &'static BfvFullBootstrapStarkTestFixture {
    bfv_full_bootstrap_stark_test_fixture_for_slot(0)
}
fn bfv_full_bootstrap_stark_test_prover_input_material()
-> &'static iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1 {
    &bfv_full_bootstrap_stark_test_fixture().material
}
fn bfv_full_bootstrap_stark_test_prover_input_material_for_slot(
    slot_index: u32,
) -> &'static iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1 {
    &bfv_full_bootstrap_stark_test_fixture_for_slot(slot_index).material
}
fn bfv_full_bootstrap_stark_test_envelope_bytes() -> &'static [u8] {
    bfv_full_bootstrap_stark_test_envelope_bytes_for_slot(0)
}
fn bfv_full_bootstrap_stark_test_envelope_bytes_for_slot(slot_index: u32) -> &'static [u8] {
    let fixture = bfv_full_bootstrap_stark_test_fixture_for_slot(slot_index);
    fixture
        .envelope_bytes
        .get_or_init(|| {
            prove_stark_fri_bfv_full_bootstrap_air_envelope_bytes(&fixture.material)
                .expect("BFV full-bootstrap STARK AIR envelope")
        })
        .as_slice()
}
#[test]
fn bfv_full_bootstrap_six_lane_domain_tag_fits_native_bound() {
    let statement = iroha_crypto::Hash::new(b"bfv-native-air-domain-tag-statement");
    let params = bfv_full_bootstrap_stark_air_params_v1(statement);
    let label = iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_AIR_TRANSCRIPT_LABEL_V1;
    assert_eq!(params.domain_tag.len(), GoldilocksDigest384V1::BYTES * 2);
    assert_eq!(params.domain_tag.len(), MAX_DOMAIN_TAG_LEN);
    assert_eq!(
        StarkVerifierLimits::default().max_domain_tag_len,
        MAX_DOMAIN_TAG_LEN
    );
    assert!(validate_stark_prover_params(&params, label).is_ok());
    assert!(validate_stark_domain_tag(&params.domain_tag, MAX_DOMAIN_TAG_LEN - 1).is_err());
    let mut oversized = params;
    oversized.domain_tag.push('0');
    assert!(validate_stark_prover_params(&oversized, label).is_err());
}
#[test]
fn bfv_full_bootstrap_air_transcript_label_is_canonical_base_label() {
    let base = iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_AIR_TRANSCRIPT_LABEL_V1;
    assert!(bfv_full_bootstrap_stark_air_transcript_label_allowed_v1(
        base
    ));
    for label in [
        format!("{base}:0"),
        format!("{base}:1"),
        format!("{base}:00"),
        format!("{base}:01"),
        format!("{base}:0001"),
        format!(
            "{}:{}",
            base,
            BFV_FULL_BOOTSTRAP_STARK_AIR_TRANSCRIPT_LABEL_ATTEMPTS - 1
        ),
        format!(
            "{}:{}",
            base, BFV_FULL_BOOTSTRAP_STARK_AIR_TRANSCRIPT_LABEL_ATTEMPTS
        ),
        format!("{base}:+1"),
        format!("{base}:1 "),
        format!("{base}:1:2"),
        format!("{base}-1"),
    ] {
        assert!(
            !bfv_full_bootstrap_stark_air_transcript_label_allowed_v1(&label),
            "noncanonical BFV STARK transcript label must be rejected: {label:?}"
        );
    }
}
#[test]
fn bfv_full_bootstrap_air_prover_binds_statement_and_public_openings() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material();
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes();
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let env: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(bytes).expect("decode BFV STARK envelope");
    assert!(bfv_full_bootstrap_stark_air_transcript_label_allowed_v1(
        &env.transcript_label
    ));
    let compressed_bytes =
        norito::to_compressed_bytes(&env, Some(norito::CompressionConfig::default()))
            .expect("encode compressed BFV STARK envelope");
    assert_ne!(
        compressed_bytes, bytes,
        "compressed BFV STARK envelope bytes must differ from canonical v1 bytes"
    );
    // `bytes` is the trusted generated uncompressed frame. Default decode limits are derived
    // from the compressed frame size and intentionally reject this high-ratio expansion.
    let compressed_env: StarkVerifyEnvelopeV1 = norito::decode_from_bytes_with_limits(
        &compressed_bytes,
        norito::canonical_decode_limits(bytes.len()),
    )
    .expect("compressed BFV STARK envelope must remain structurally decodable");
    assert_eq!(
        norito::to_bytes(&compressed_env).expect("re-encode compressed BFV STARK envelope"),
        bytes,
        "compressed BFV STARK envelope must decode to the same typed proof as canonical bytes"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(&compressed_bytes, material)
            .expect("verification attempt must complete for this semantic fixture"),
        "artifact-bound BFV verifier must reject noncanonical compressed proof framing"
    );
    let expected_params =
        bfv_full_bootstrap_stark_air_params_v1(material.proof_input_material.statement_hash);
    assert!(bfv_full_bootstrap_stark_air_params_match_v1(
        &env.params,
        &expected_params
    ));
    let public_digest = bfv_test_public_digest(
        &expected_params,
        material.proof_input_material.statement_hash,
    );
    let witness = &material.proof_input_material.witness_material;
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding-only BFV verification must fail closed without the hidden trace"
    );
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_public_padding_structure_with_limits(
            bytes,
            &StarkVerifierLimits::default(),
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        )
        .expect("verification attempt must complete for this semantic fixture"),
        "full-material verification still needs the public-padding structural precheck"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            &compressed_bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject noncanonical compressed proof framing"
    );
    let expected_base_indices = bfv_full_bootstrap_expected_base_indices_v1(
        material.proof_input_material.statement_hash,
        material.arithmetic_trace_material_digest,
        usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_QUERIES_V1),
        material.arithmetic_trace_material.rows.len(),
    )
    .expect("derive BFV explicit public-padding base indices");
    let suffixed_label_bytes =
            prove_stark_fri_reserved_air_envelope_from_rows_and_composition_values_with_base_indices_bytes(
                expected_params.clone(),
                format!(
                    "{}:1",
                    iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_AIR_TRANSCRIPT_LABEL_V1
                ),
                iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1.to_owned(),
                public_digest,
                material.arithmetic_trace_material.rows.clone(),
                material
                    .arithmetic_air_evaluation_material
                    .composition_values
                    .clone(),
                &expected_base_indices,
            )
            .expect("build structurally valid suffixed-label explicit BFV AIR envelope");
    assert!(
            verify_stark_fri_air_envelope_from_rows_and_composition_values_with_base_indices_with_limits(
                &suffixed_label_bytes,
                &StarkVerifierLimits::default(),
                iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
                &public_digest,
                &material.arithmetic_trace_material.rows,
                &material
                    .arithmetic_air_evaluation_material
                    .composition_values,
                &expected_base_indices,
            ).expect("verification attempt must complete for this semantic fixture"),
            "suffixed-label envelope must remain a valid explicit-schedule AIR proof"
        );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            &suffixed_label_bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject suffixed-label alternate proof encodings"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(&suffixed_label_bytes, material)
            .expect("verification attempt must complete for this semantic fixture"),
        "artifact-bound BFV verifier must reject suffixed-label alternate proof encodings"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            iroha_crypto::Hash::prehashed([0_u8; iroha_crypto::Hash::LENGTH]),
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject zero statement hashes before envelope replay"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            material.proof_input_material.statement_hash,
            iroha_crypto::Hash::prehashed([0_u8; iroha_crypto::Hash::LENGTH]),
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject zero trace-material digests before envelope replay"
    );
    let placeholder_statement_hash =
        iroha_crypto::Hash::new(b"pending BFV full-bootstrap execution witness digest");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            placeholder_statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject placeholder statement hashes before envelope replay"
    );
    let placeholder_trace_material_digest =
        iroha_crypto::Hash::new(b"pending BFV full-bootstrap execution witness digest");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            material.proof_input_material.statement_hash,
            placeholder_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject placeholder trace-material digests before envelope replay"
    );
    let delayed_placeholder_statement_preimage = [
        b" \n\t".as_slice(),
        b"full-bootstrap material before placeholder: ".as_slice(),
        b"pending BFV full-bootstrap execution witness digest".as_slice(),
    ]
    .concat();
    let delayed_placeholder_statement_hash =
        iroha_crypto::Hash::new(&delayed_placeholder_statement_preimage);
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            delayed_placeholder_statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject leading-whitespace delayed placeholder statement hashes before envelope replay"
    );
    let separator_spelled_statement_preimages = [
        b"p-e-n-d-i-n-g BFV full-bootstrap execution witness digest".as_slice(),
        b"p.e.n.d.i.n.g BFV full-bootstrap execution witness digest".as_slice(),
        b"p_e_n_d_i_n_g BFV full-bootstrap execution witness digest".as_slice(),
    ];
    let separator_spelled_statement_hashes =
        separator_spelled_statement_preimages.map(iroha_crypto::Hash::new);
    for separator_spelled_statement_hash in separator_spelled_statement_hashes.iter().copied() {
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                bytes,
                separator_spelled_statement_hash,
                material.arithmetic_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "public-padding BFV verifier must reject separator-spelled placeholder statement hashes before envelope replay"
        );
    }
    let delayed_separator_spelled_statement_hashes =
        separator_spelled_statement_preimages.map(|preimage| {
            let delayed_preimage = [
                b" \n\t".as_slice(),
                b"full-bootstrap material before placeholder: ".as_slice(),
                preimage,
            ]
            .concat();
            iroha_crypto::Hash::new(&delayed_preimage)
        });
    for delayed_separator_spelled_statement_hash in
        delayed_separator_spelled_statement_hashes.iter().copied()
    {
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                bytes,
                delayed_separator_spelled_statement_hash,
                material.arithmetic_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "public-padding BFV verifier must reject delayed separator-spelled placeholder statement hashes before envelope replay"
        );
    }
    let delayed_placeholder_trace_material_digest =
        iroha_crypto::Hash::new(&delayed_placeholder_statement_preimage);
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            material.proof_input_material.statement_hash,
            delayed_placeholder_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject leading-whitespace delayed placeholder trace-material digests before envelope replay"
    );
    let separator_spelled_trace_material_preimages = separator_spelled_statement_preimages;
    let separator_spelled_trace_material_digests =
        separator_spelled_trace_material_preimages.map(iroha_crypto::Hash::new);
    for separator_spelled_trace_material_digest in
        separator_spelled_trace_material_digests.iter().copied()
    {
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                bytes,
                material.proof_input_material.statement_hash,
                separator_spelled_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "public-padding BFV verifier must reject separator-spelled placeholder trace-material digests before envelope replay"
        );
    }
    let delayed_separator_spelled_trace_material_digests =
        separator_spelled_trace_material_preimages.map(|preimage| {
            let delayed_preimage = [
                b" \n\t".as_slice(),
                b"full-bootstrap material before placeholder: ".as_slice(),
                preimage,
            ]
            .concat();
            iroha_crypto::Hash::new(&delayed_preimage)
        });
    for delayed_separator_spelled_trace_material_digest in
        delayed_separator_spelled_trace_material_digests
            .iter()
            .copied()
    {
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                bytes,
                material.proof_input_material.statement_hash,
                delayed_separator_spelled_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "public-padding BFV verifier must reject delayed separator-spelled placeholder trace-material digests before envelope replay"
        );
    }
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            u32::from(iroha_crypto::BFV_FULL_BOOTSTRAP_ARITHMETIC_TRACE_PRIVATE_ROW_COUNT_V1),
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject out-of-range public slot headers before envelope replay"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            iroha_crypto::Hash::new(b"stale BFV full-bootstrap public statement hash"),
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must bind the statement hash"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index.saturating_add(1),
            witness.bound_mode,
        ),
        "public-padding BFV verifier must bind the public slot index"
    );
    let alternate_bound_mode = match witness.bound_mode {
        iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1::ExactResidualMultiple => {
            iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1::BoundedNoise
        }
        iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1::BoundedNoise => {
            iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1::ExactResidualMultiple
        }
    };
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            alternate_bound_mode,
        ),
        "public-padding BFV verifier must bind the public bound mode"
    );
    let air = env.proof.air.as_ref().expect("BFV AIR section");
    let domain_size = 1_usize << usize::from(env.params.n_log2);
    let public_padding_context = StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
        statement_hash: &material.proof_input_material.statement_hash,
        trace_material_digest: &material.arithmetic_trace_material_digest,
        slot_index: witness.slot_index,
        bound_mode: witness.bound_mode,
    };
    assert!(
        stark_air_context_matches_statement(&env.params, air, domain_size, public_padding_context),
        "private BFV public-padding context must accept the canonical STARK parameter profile"
    );
    let mut stale_public_padding_params = env.params.clone();
    stale_public_padding_params.domain_tag = bfv_full_bootstrap_stark_air_params_v1(
        iroha_crypto::Hash::new(b"alternate BFV full-bootstrap context statement"),
    )
    .domain_tag;
    assert!(
        !stark_air_context_matches_statement(
            &stale_public_padding_params,
            air,
            domain_size,
            public_padding_context,
        ),
        "private BFV public-padding context must reject statement-bound domain-tag drift"
    );
    let zero_statement_hash = iroha_crypto::Hash::prehashed([0_u8; iroha_crypto::Hash::LENGTH]);
    let zero_public_digest = bfv_test_public_digest(&env.params, zero_statement_hash);
    let zero_statement_context = StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
        statement_hash: &zero_statement_hash,
        trace_material_digest: &material.arithmetic_trace_material_digest,
        slot_index: witness.slot_index,
        bound_mode: witness.bound_mode,
    };
    let mut zero_digest_air = air.clone();
    zero_digest_air.public_digest = zero_public_digest;
    assert!(
        !stark_air_context_matches_statement(
            &env.params,
            &zero_digest_air,
            domain_size,
            zero_statement_context,
        ),
        "private BFV public-padding context must reject zero statement hashes even when the AIR digest matches"
    );
    let zero_trace_digest = iroha_crypto::Hash::prehashed([0_u8; iroha_crypto::Hash::LENGTH]);
    let zero_trace_context = StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
        statement_hash: &material.proof_input_material.statement_hash,
        trace_material_digest: &zero_trace_digest,
        slot_index: witness.slot_index,
        bound_mode: witness.bound_mode,
    };
    assert!(
        !stark_air_context_matches_statement(&env.params, air, domain_size, zero_trace_context,),
        "private BFV public-padding context must reject zero trace-material digests even when the AIR digest matches"
    );
    let first_public_opening = air.openings.first().expect("BFV AIR public opening");
    assert!(
        stark_air_composition_value_for_context(
            &env.params,
            zero_statement_context,
            usize::try_from(first_public_opening.index).expect("opening index fits usize"),
            domain_size,
            &zero_public_digest,
            &first_public_opening.row,
            &first_public_opening.next_row,
        )
        .is_none(),
        "private BFV public-padding context must not replay openings under a zero statement hash"
    );
    let placeholder_public_digest = bfv_test_public_digest(&env.params, placeholder_statement_hash);
    let placeholder_statement_context =
        StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
            statement_hash: &placeholder_statement_hash,
            trace_material_digest: &material.arithmetic_trace_material_digest,
            slot_index: witness.slot_index,
            bound_mode: witness.bound_mode,
        };
    let mut placeholder_digest_air = air.clone();
    placeholder_digest_air.public_digest = placeholder_public_digest;
    assert!(
        !stark_air_context_matches_statement(
            &env.params,
            &placeholder_digest_air,
            domain_size,
            placeholder_statement_context,
        ),
        "private BFV public-padding context must reject placeholder statement hashes even when the AIR digest matches"
    );
    assert!(
        stark_air_composition_value_for_context(
            &env.params,
            placeholder_statement_context,
            usize::try_from(first_public_opening.index).expect("opening index fits usize"),
            domain_size,
            &placeholder_public_digest,
            &first_public_opening.row,
            &first_public_opening.next_row,
        )
        .is_none(),
        "private BFV public-padding context must not replay openings under a placeholder statement hash"
    );
    let placeholder_trace_context = StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
        statement_hash: &material.proof_input_material.statement_hash,
        trace_material_digest: &placeholder_trace_material_digest,
        slot_index: witness.slot_index,
        bound_mode: witness.bound_mode,
    };
    assert!(
        !stark_air_context_matches_statement(
            &env.params,
            air,
            domain_size,
            placeholder_trace_context,
        ),
        "private BFV public-padding context must reject placeholder trace-material digests even when the AIR digest matches"
    );
    assert!(
        stark_air_composition_value_for_context(
            &env.params,
            placeholder_trace_context,
            usize::try_from(first_public_opening.index).expect("opening index fits usize"),
            domain_size,
            &public_digest,
            &first_public_opening.row,
            &first_public_opening.next_row,
        )
        .is_none(),
        "private BFV public-padding context must not replay openings under a placeholder trace-material digest"
    );
    let delayed_placeholder_public_digest =
        bfv_test_public_digest(&env.params, delayed_placeholder_statement_hash);
    let delayed_placeholder_statement_context =
        StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
            statement_hash: &delayed_placeholder_statement_hash,
            trace_material_digest: &material.arithmetic_trace_material_digest,
            slot_index: witness.slot_index,
            bound_mode: witness.bound_mode,
        };
    let mut delayed_placeholder_digest_air = air.clone();
    delayed_placeholder_digest_air.public_digest = delayed_placeholder_public_digest;
    assert!(
        !stark_air_context_matches_statement(
            &env.params,
            &delayed_placeholder_digest_air,
            domain_size,
            delayed_placeholder_statement_context,
        ),
        "private BFV public-padding context must reject leading-whitespace delayed placeholder statement hashes even when the AIR digest matches"
    );
    assert!(
        stark_air_composition_value_for_context(
            &env.params,
            delayed_placeholder_statement_context,
            usize::try_from(first_public_opening.index).expect("opening index fits usize"),
            domain_size,
            &delayed_placeholder_public_digest,
            &first_public_opening.row,
            &first_public_opening.next_row,
        )
        .is_none(),
        "private BFV public-padding context must not replay openings under a leading-whitespace delayed placeholder statement hash"
    );
    for separator_spelled_statement_hash in separator_spelled_statement_hashes.iter().copied() {
        let separator_spelled_public_digest =
            bfv_test_public_digest(&env.params, separator_spelled_statement_hash);
        let separator_spelled_statement_context =
            StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
                statement_hash: &separator_spelled_statement_hash,
                trace_material_digest: &material.arithmetic_trace_material_digest,
                slot_index: witness.slot_index,
                bound_mode: witness.bound_mode,
            };
        let mut separator_spelled_digest_air = air.clone();
        separator_spelled_digest_air.public_digest = separator_spelled_public_digest;
        assert!(
            !stark_air_context_matches_statement(
                &env.params,
                &separator_spelled_digest_air,
                domain_size,
                separator_spelled_statement_context,
            ),
            "private BFV public-padding context must reject separator-spelled placeholder statement hashes even when the AIR digest matches"
        );
        assert!(
            stark_air_composition_value_for_context(
                &env.params,
                separator_spelled_statement_context,
                usize::try_from(first_public_opening.index).expect("opening index fits usize"),
                domain_size,
                &separator_spelled_public_digest,
                &first_public_opening.row,
                &first_public_opening.next_row,
            )
            .is_none(),
            "private BFV public-padding context must not replay openings under a separator-spelled placeholder statement hash"
        );
    }
    for delayed_separator_spelled_statement_hash in
        delayed_separator_spelled_statement_hashes.iter().copied()
    {
        let delayed_separator_spelled_public_digest =
            bfv_test_public_digest(&env.params, delayed_separator_spelled_statement_hash);
        let delayed_separator_spelled_statement_context =
            StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
                statement_hash: &delayed_separator_spelled_statement_hash,
                trace_material_digest: &material.arithmetic_trace_material_digest,
                slot_index: witness.slot_index,
                bound_mode: witness.bound_mode,
            };
        let mut delayed_separator_spelled_digest_air = air.clone();
        delayed_separator_spelled_digest_air.public_digest =
            delayed_separator_spelled_public_digest;
        assert!(
            !stark_air_context_matches_statement(
                &env.params,
                &delayed_separator_spelled_digest_air,
                domain_size,
                delayed_separator_spelled_statement_context,
            ),
            "private BFV public-padding context must reject delayed separator-spelled placeholder statement hashes even when the AIR digest matches"
        );
        assert!(
            stark_air_composition_value_for_context(
                &env.params,
                delayed_separator_spelled_statement_context,
                usize::try_from(first_public_opening.index).expect("opening index fits usize"),
                domain_size,
                &delayed_separator_spelled_public_digest,
                &first_public_opening.row,
                &first_public_opening.next_row,
            )
            .is_none(),
            "private BFV public-padding context must not replay openings under a delayed separator-spelled placeholder statement hash"
        );
    }
    let delayed_placeholder_trace_context =
        StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
            statement_hash: &material.proof_input_material.statement_hash,
            trace_material_digest: &delayed_placeholder_trace_material_digest,
            slot_index: witness.slot_index,
            bound_mode: witness.bound_mode,
        };
    assert!(
        !stark_air_context_matches_statement(
            &env.params,
            air,
            domain_size,
            delayed_placeholder_trace_context,
        ),
        "private BFV public-padding context must reject leading-whitespace delayed placeholder trace-material digests even when the AIR digest matches"
    );
    assert!(
        stark_air_composition_value_for_context(
            &env.params,
            delayed_placeholder_trace_context,
            usize::try_from(first_public_opening.index).expect("opening index fits usize"),
            domain_size,
            &public_digest,
            &first_public_opening.row,
            &first_public_opening.next_row,
        )
        .is_none(),
        "private BFV public-padding context must not replay openings under a leading-whitespace delayed placeholder trace-material digest"
    );
    for separator_spelled_trace_material_digest in
        separator_spelled_trace_material_digests.iter().copied()
    {
        let separator_spelled_trace_context =
            StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
                statement_hash: &material.proof_input_material.statement_hash,
                trace_material_digest: &separator_spelled_trace_material_digest,
                slot_index: witness.slot_index,
                bound_mode: witness.bound_mode,
            };
        assert!(
            !stark_air_context_matches_statement(
                &env.params,
                air,
                domain_size,
                separator_spelled_trace_context,
            ),
            "private BFV public-padding context must reject separator-spelled placeholder trace-material digests even when the AIR digest matches"
        );
        assert!(
            stark_air_composition_value_for_context(
                &env.params,
                separator_spelled_trace_context,
                usize::try_from(first_public_opening.index).expect("opening index fits usize"),
                domain_size,
                &public_digest,
                &first_public_opening.row,
                &first_public_opening.next_row,
            )
            .is_none(),
            "private BFV public-padding context must not replay openings under a separator-spelled placeholder trace-material digest"
        );
    }
    for delayed_separator_spelled_trace_material_digest in
        delayed_separator_spelled_trace_material_digests
            .iter()
            .copied()
    {
        let delayed_separator_spelled_trace_context =
            StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
                statement_hash: &material.proof_input_material.statement_hash,
                trace_material_digest: &delayed_separator_spelled_trace_material_digest,
                slot_index: witness.slot_index,
                bound_mode: witness.bound_mode,
            };
        assert!(
            !stark_air_context_matches_statement(
                &env.params,
                air,
                domain_size,
                delayed_separator_spelled_trace_context,
            ),
            "private BFV public-padding context must reject delayed separator-spelled placeholder trace-material digests even when the AIR digest matches"
        );
        assert!(
            stark_air_composition_value_for_context(
                &env.params,
                delayed_separator_spelled_trace_context,
                usize::try_from(first_public_opening.index).expect("opening index fits usize"),
                domain_size,
                &public_digest,
                &first_public_opening.row,
                &first_public_opening.next_row,
            )
            .is_none(),
            "private BFV public-padding context must not replay openings under a delayed separator-spelled placeholder trace-material digest"
        );
    }
    let opening_indices = air
        .openings
        .iter()
        .map(|opening| opening.index)
        .collect::<Vec<_>>();
    let opened_rows = air
        .openings
        .iter()
        .map(|opening| opening.row.clone())
        .collect::<Vec<_>>();
    let opened_next_rows = air
        .openings
        .iter()
        .map(|opening| opening.next_row.clone())
        .collect::<Vec<_>>();
    iroha_crypto::validate_bfv_full_bootstrap_arithmetic_trace_transcript_public_padding_openings_v1(
            &opening_indices,
            &opened_rows,
            &opened_next_rows,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            material.proof_input_material.witness_material.slot_index,
            material.proof_input_material.witness_material.bound_mode,
        )
        .expect("BFV transcript-bound public opening set");
    for opening in &air.openings {
        iroha_crypto::validate_bfv_full_bootstrap_arithmetic_trace_public_padding_opening_v1(
            opening.index,
            &opening.row,
            &opening.next_row,
            material.proof_input_material.statement_hash,
            material.proof_input_material.witness_material.slot_index,
            material.proof_input_material.witness_material.bound_mode,
        )
        .expect("BFV sampled opening is a canonical public padding row");
    }
    let mut duplicate_opening_env = env.clone();
    {
        let duplicate_air = duplicate_opening_env
            .proof
            .air
            .as_mut()
            .expect("BFV AIR section");
        duplicate_air.openings[1] = duplicate_air.openings[0].clone();
    }
    let duplicate_opening_bytes =
        norito::to_bytes(&duplicate_opening_env).expect("encode duplicate BFV AIR opening");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            &duplicate_opening_bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject duplicated sampled public openings"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(&duplicate_opening_bytes, material)
            .expect("verification attempt must complete for this semantic fixture"),
        "artifact-bound BFV verifier must reject duplicated sampled public openings"
    );
    let mut reordered_opening_env = env.clone();
    reordered_opening_env
        .proof
        .air
        .as_mut()
        .expect("BFV AIR section")
        .openings
        .swap(0, 1);
    let reordered_opening_bytes =
        norito::to_bytes(&reordered_opening_env).expect("encode reordered BFV AIR openings");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            &reordered_opening_bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject reordered public openings"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(&reordered_opening_bytes, material)
            .expect("verification attempt must complete for this semantic fixture"),
        "artifact-bound BFV verifier must reject reordered public openings"
    );
    let mut truncated_opening_env = env.clone();
    truncated_opening_env
        .proof
        .air
        .as_mut()
        .expect("BFV AIR section")
        .openings
        .pop();
    let truncated_opening_bytes =
        norito::to_bytes(&truncated_opening_env).expect("encode truncated BFV AIR openings");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            &truncated_opening_bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject truncated sampled public openings"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(&truncated_opening_bytes, material)
            .expect("verification attempt must complete for this semantic fixture"),
        "artifact-bound BFV verifier must reject truncated sampled public openings"
    );
    let generic_bfv_err = prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
        expected_params.clone(),
        "IROHA-TEST-BFV-GENERIC-AIR-REJECTED".to_owned(),
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1.to_owned(),
        public_digest,
        material.arithmetic_trace_material.rows.clone(),
        material
            .arithmetic_air_evaluation_material
            .composition_values
            .clone(),
    )
    .expect_err("generic explicit AIR builder must reject BFV circuit ids");
    assert!(
        generic_bfv_err.to_string().contains("BFV full-bootstrap"),
        "generic BFV AIR rejection must name the reserved family: {generic_bfv_err}"
    );
    let mut stale_domain = env.clone();
    stale_domain.params.domain_tag = bfv_full_bootstrap_stark_air_params_v1(
        iroha_crypto::Hash::new(b"alternate BFV full-bootstrap statement hash"),
    )
    .domain_tag;
    let stale_domain_bytes = norito::to_bytes(&stale_domain).expect("encode stale domain");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(&stale_domain_bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let mut stale_material = (*material).clone();
    stale_material.proof_input_material.statement_hash =
        iroha_crypto::Hash::new(b"stale BFV full-bootstrap statement hash");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, &stale_material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let mut tampered_opening = env;
    tampered_opening
        .proof
        .air
        .as_mut()
        .expect("BFV AIR section")
        .openings[0]
        .row[9] = 1;
    let tampered_opening_bytes =
        norito::to_bytes(&tampered_opening).expect("encode tampered opening");
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(&tampered_opening_bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
            &tampered_opening_bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "public-padding BFV verifier must reject drifted public row openings"
    );
}
#[test]
fn bfv_full_bootstrap_air_rejects_auxiliary_generic_composition_sidecars() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material();
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes();
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let mut sidecar_envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(bytes).expect("decode BFV STARK envelope");
    assert!(sidecar_envelope.proof.commits.comp_root.is_none());
    assert!(sidecar_envelope.proof.comp_values.is_none());
    attach_valid_auxiliary_composition_values(&mut sidecar_envelope);
    assert!(sidecar_envelope.proof.commits.comp_root.is_some());
    assert_eq!(
        sidecar_envelope.proof.comp_values.as_ref().map(Vec::len),
        Some(sidecar_envelope.proof.queries.len())
    );
    let mut comp_root_only = sidecar_envelope.clone();
    comp_root_only.proof.comp_values = None;
    let mut comp_values_only = sidecar_envelope.clone();
    comp_values_only.proof.commits.comp_root = None;
    let mut truncated_values = sidecar_envelope.clone();
    truncated_values
        .proof
        .comp_values
        .as_mut()
        .expect("composition values")
        .pop();
    let public_digest = bfv_test_public_digest(
        &sidecar_envelope.params,
        material.proof_input_material.statement_hash,
    );
    let witness = &material.proof_input_material.witness_material;
    for (case, envelope) in [
        ("paired auxiliary sidecars", sidecar_envelope),
        ("comp_root without comp_values", comp_root_only),
        ("comp_values without comp_root", comp_values_only),
        ("truncated comp_values", truncated_values),
    ] {
        let auxiliary_bytes =
            norito::to_bytes(&envelope).expect("encode auxiliary BFV STARK envelope");
        assert!(
            !verify_stark_fri_air_envelope_from_rows_and_composition_values(
                &auxiliary_bytes,
                iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
                &public_digest,
                &material.arithmetic_trace_material.rows,
                &material
                    .arithmetic_air_evaluation_material
                    .composition_values,
            )
            .expect("verification attempt must complete for this semantic fixture"),
            "caller-owned BFV explicit AIR must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_envelope(&auxiliary_bytes, material)
                .expect("verification attempt must complete for this semantic fixture"),
            "BFV native AIR verifier must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                &auxiliary_bytes,
                material.proof_input_material.statement_hash,
                material.arithmetic_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "BFV public-padding verifier must reject {case}"
        );
    }
}
#[test]
fn bfv_full_bootstrap_air_rejects_malformed_proof_and_air_bindings() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material();
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes();
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(bytes).expect("decode BFV STARK envelope");
    let public_digest = bfv_test_public_digest(
        &envelope.params,
        material.proof_input_material.statement_hash,
    );
    let witness = &material.proof_input_material.witness_material;
    let assert_rejected = |case: &str, envelope: &StarkVerifyEnvelopeV1| {
        let malformed_bytes =
            norito::to_bytes(envelope).expect("encode malformed BFV STARK envelope");
        assert!(
            !verify_stark_fri_air_envelope_from_rows_and_composition_values(
                &malformed_bytes,
                iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
                &public_digest,
                &material.arithmetic_trace_material.rows,
                &material
                    .arithmetic_air_evaluation_material
                    .composition_values,
            )
            .expect("verification attempt must complete for this semantic fixture"),
            "caller-owned BFV explicit AIR must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_envelope(&malformed_bytes, material)
                .expect("verification attempt must complete for this semantic fixture"),
            "BFV native AIR verifier must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                &malformed_bytes,
                material.proof_input_material.statement_hash,
                material.arithmetic_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "BFV public-padding verifier must reject {case}"
        );
    };
    let mut bad_proof_version = envelope.clone();
    bad_proof_version.proof.version = 2;
    assert_rejected("non-v1 proof version", &bad_proof_version);
    let mut bad_commit_version = envelope.clone();
    bad_commit_version.proof.commits.version = 2;
    assert_rejected("non-v1 commitment version", &bad_commit_version);
    let mut missing_air = envelope.clone();
    missing_air.proof.air = None;
    assert_rejected("missing AIR section", &missing_air);
    let mut foreign_air = envelope.clone();
    foreign_air
        .proof
        .air
        .as_mut()
        .expect("AIR section")
        .circuit_id = "stark/fri/poseidon-x7-goldilocks-6x64-v1:foreign-bfv-air".to_owned();
    assert_rejected("foreign AIR circuit id", &foreign_air);
    let mut drifted_composition_root = envelope.clone();
    mutate_test_digest(
        &mut drifted_composition_root
            .proof
            .air
            .as_mut()
            .expect("AIR section")
            .composition_root,
    );
    assert_rejected("AIR composition-root drift", &drifted_composition_root);
    let mut drifted_trace_root = envelope.clone();
    mutate_test_digest(
        &mut drifted_trace_root
            .proof
            .air
            .as_mut()
            .expect("AIR section")
            .trace_root,
    );
    assert_rejected("AIR trace-root drift", &drifted_trace_root);
    let mut drifted_fri_root = envelope.clone();
    mutate_test_digest(&mut drifted_fri_root.proof.commits.roots[0]);
    assert_rejected("FRI composition-root drift", &drifted_fri_root);
    let mut missing_query = envelope.clone();
    missing_query.proof.queries.pop();
    assert_rejected("missing FRI query chain", &missing_query);
    let mut reordered_query = envelope.clone();
    assert!(
        reordered_query.proof.queries.len() > 1,
        "BFV AIR test envelope has multiple FRI query chains"
    );
    reordered_query.proof.queries.swap(0, 1);
    assert_rejected("reordered FRI query chains", &reordered_query);
    let mut missing_opening = envelope;
    missing_opening
        .proof
        .air
        .as_mut()
        .expect("AIR section")
        .openings
        .pop();
    assert_rejected("missing AIR opening", &missing_opening);
}
#[test]
fn bfv_full_bootstrap_air_rejects_opening_path_and_sample_drift() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material();
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes();
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(bytes).expect("decode BFV STARK envelope");
    let public_digest = bfv_test_public_digest(
        &envelope.params,
        material.proof_input_material.statement_hash,
    );
    let witness = &material.proof_input_material.witness_material;
    let assert_rejected = |case: &str, envelope: &StarkVerifyEnvelopeV1| {
        let malformed_bytes =
            norito::to_bytes(envelope).expect("encode malformed BFV STARK envelope");
        assert!(
            !verify_stark_fri_air_envelope_from_rows_and_composition_values(
                &malformed_bytes,
                iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
                &public_digest,
                &material.arithmetic_trace_material.rows,
                &material
                    .arithmetic_air_evaluation_material
                    .composition_values,
            )
            .expect("verification attempt must complete for this semantic fixture"),
            "caller-owned BFV explicit AIR must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_envelope(&malformed_bytes, material)
                .expect("verification attempt must complete for this semantic fixture"),
            "BFV native AIR verifier must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                &malformed_bytes,
                material.proof_input_material.statement_hash,
                material.arithmetic_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "BFV public-padding verifier must reject {case}"
        );
    };
    let mut wrong_opening_index = envelope.clone();
    let opening_index = wrong_opening_index
        .proof
        .air
        .as_ref()
        .expect("AIR section")
        .openings[0]
        .index;
    wrong_opening_index
        .proof
        .air
        .as_mut()
        .expect("AIR section")
        .openings[0]
        .index = opening_index.wrapping_add(1);
    assert_rejected("opening index drift", &wrong_opening_index);
    let mut swapped_row_paths = envelope.clone();
    let opening = &mut swapped_row_paths
        .proof
        .air
        .as_mut()
        .expect("AIR section")
        .openings[0];
    core::mem::swap(&mut opening.row_path, &mut opening.next_row_path);
    assert_rejected("swapped row and next-row paths", &swapped_row_paths);
    let mut tampered_row_path = envelope.clone();
    mutate_test_digest(
        tampered_row_path
            .proof
            .air
            .as_mut()
            .expect("AIR section")
            .openings[0]
            .row_path
            .siblings
            .first_mut()
            .expect("row path sibling"),
    );
    assert_rejected("row Merkle path drift", &tampered_row_path);
    let mut tampered_next_row_path = envelope.clone();
    mutate_test_digest(
        tampered_next_row_path
            .proof
            .air
            .as_mut()
            .expect("AIR section")
            .openings[0]
            .next_row_path
            .siblings
            .first_mut()
            .expect("next-row path sibling"),
    );
    assert_rejected("next-row Merkle path drift", &tampered_next_row_path);
    let mut tampered_composition_path = envelope.clone();
    mutate_test_digest(
        tampered_composition_path
            .proof
            .air
            .as_mut()
            .expect("AIR section")
            .openings[0]
            .composition_path
            .siblings
            .first_mut()
            .expect("composition path sibling"),
    );
    assert_rejected(
        "composition-value Merkle path drift",
        &tampered_composition_path,
    );
    let mut tampered_composition_value = envelope.clone();
    tampered_composition_value
        .proof
        .air
        .as_mut()
        .expect("AIR section")
        .openings[0]
        .composition_value ^= 0x01;
    assert_rejected(
        "opened composition-value drift",
        &tampered_composition_value,
    );
    let mut tampered_fri_base_value = envelope.clone();
    let mut coefficients = tampered_fri_base_value.proof.queries[0][0]
        .y0
        .coefficients();
    coefficients[0] ^= 0x01;
    tampered_fri_base_value.proof.queries[0][0].y0 =
        GoldilocksFp4V1::new(coefficients).expect("mutated FRI value remains canonical");
    assert_rejected("FRI base value drift", &tampered_fri_base_value);
    let mut duplicated_opening = envelope;
    let air = duplicated_opening.proof.air.as_mut().expect("AIR section");
    assert!(air.openings.len() > 1, "BFV AIR test envelope has queries");
    air.openings[1] = air.openings[0].clone();
    assert_rejected("duplicated AIR opening", &duplicated_opening);
}
#[test]
fn bfv_full_bootstrap_air_verifier_limits_are_enforced() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material();
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes();
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
            bytes,
            &StarkVerifierLimits::default(),
            material,
        )
        .expect("verification attempt must complete for this semantic fixture")
    );
    let envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(bytes).expect("decode BFV STARK envelope");
    let air = envelope.proof.air.as_ref().expect("BFV AIR section");
    let witness = &material.proof_input_material.witness_material;
    let mut tight_envelope_bytes = StarkVerifierLimits::default();
    tight_envelope_bytes.max_envelope_bytes = bytes.len().saturating_sub(1);
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
            bytes,
            &tight_envelope_bytes,
            material,
        )
        .expect("verification attempt must complete for this semantic fixture"),
        "BFV native AIR verifier must honor envelope byte limits"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope_with_limits(
            bytes,
            &tight_envelope_bytes,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "BFV public-padding verifier must honor envelope byte limits"
    );
    let mut tight_transcript_label = StarkVerifierLimits::default();
    tight_transcript_label.max_transcript_label_len =
        envelope.transcript_label.len().saturating_sub(1);
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
            bytes,
            &tight_transcript_label,
            material,
        )
        .expect("verification attempt must complete for this semantic fixture"),
        "BFV native AIR verifier must honor transcript-label limits"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope_with_limits(
            bytes,
            &tight_transcript_label,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "BFV public-padding verifier must honor transcript-label limits"
    );
    let mut tight_queries = StarkVerifierLimits::default();
    tight_queries.max_queries = envelope.proof.queries.len().saturating_sub(1);
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
            bytes,
            &tight_queries,
            material,
        )
        .expect("verification attempt must complete for this semantic fixture"),
        "BFV native AIR verifier must honor query-count limits"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope_with_limits(
            bytes,
            &tight_queries,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "BFV public-padding verifier must honor query-count limits"
    );
    let mut tight_air_width = StarkVerifierLimits::default();
    tight_air_width.max_air_width = usize::from(air.trace_width).saturating_sub(1);
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
            bytes,
            &tight_air_width,
            material,
        )
        .expect("verification attempt must complete for this semantic fixture"),
        "BFV native AIR verifier must honor AIR width limits"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope_with_limits(
            bytes,
            &tight_air_width,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "BFV public-padding verifier must honor AIR width limits"
    );
    let mut tight_merkle_depth = StarkVerifierLimits::default();
    tight_merkle_depth.max_merkle_depth = usize::from(envelope.params.n_log2).saturating_sub(1);
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
            bytes,
            &tight_merkle_depth,
            material,
        )
        .expect("verification attempt must complete for this semantic fixture"),
        "BFV native AIR verifier must honor Merkle-depth limits"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope_with_limits(
            bytes,
            &tight_merkle_depth,
            material.proof_input_material.statement_hash,
            material.arithmetic_trace_material_digest,
            witness.slot_index,
            witness.bound_mode,
        ),
        "BFV public-padding verifier must honor Merkle-depth limits"
    );
}
#[test]
fn bfv_full_bootstrap_air_rejects_parameter_profile_drift() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material();
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes();
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(bytes).expect("decode BFV STARK envelope");
    let public_digest = bfv_test_public_digest(
        &envelope.params,
        material.proof_input_material.statement_hash,
    );
    let witness = &material.proof_input_material.witness_material;
    let assert_rejected = |case: &str, envelope: &StarkVerifyEnvelopeV1| {
        let malformed_bytes =
            norito::to_bytes(envelope).expect("encode parameter-drift BFV STARK envelope");
        assert!(
            !verify_stark_fri_air_envelope_from_rows_and_composition_values(
                &malformed_bytes,
                iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
                &public_digest,
                &material.arithmetic_trace_material.rows,
                &material
                    .arithmetic_air_evaluation_material
                    .composition_values,
            )
            .expect("verification attempt must complete for this semantic fixture"),
            "caller-owned BFV explicit AIR must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_envelope(&malformed_bytes, material)
                .expect("verification attempt must complete for this semantic fixture"),
            "BFV native AIR verifier must reject {case}"
        );
        assert!(
            !verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
                &malformed_bytes,
                material.proof_input_material.statement_hash,
                material.arithmetic_trace_material_digest,
                witness.slot_index,
                witness.bound_mode,
            ),
            "BFV public-padding verifier must reject {case}"
        );
    };
    let mut bad_version = envelope.clone();
    bad_version.params.version = 2;
    assert_rejected("STARK parameter version drift", &bad_version);
    let mut bad_domain_depth = envelope.clone();
    bad_domain_depth.params.n_log2 = bad_domain_depth.params.n_log2.saturating_add(1);
    assert_rejected("STARK domain-depth drift", &bad_domain_depth);
    let mut bad_blowup = envelope.clone();
    bad_blowup.params.blowup_log2 = bad_blowup.params.blowup_log2.saturating_add(1);
    assert_rejected("STARK blowup drift", &bad_blowup);
    let mut bad_fold_arity = envelope.clone();
    bad_fold_arity.params.fold_arity = 4;
    assert_rejected("STARK fold-arity drift", &bad_fold_arity);
    let mut bad_merkle_arity = envelope.clone();
    bad_merkle_arity.params.merkle_arity = 4;
    assert_rejected("STARK Merkle-arity drift", &bad_merkle_arity);
    let mut bad_query_count = envelope.clone();
    bad_query_count.params.queries = bad_query_count.params.queries.saturating_sub(1);
    assert_rejected("STARK query-count header drift", &bad_query_count);
    let mut stale_domain = envelope;
    stale_domain.params.domain_tag = bfv_full_bootstrap_stark_air_params_v1(
        iroha_crypto::Hash::new(b"alternate BFV full-bootstrap parameter profile"),
    )
    .domain_tag;
    assert_rejected("statement-bound domain-tag drift", &stale_domain);
}
#[test]
fn bfv_full_bootstrap_air_rejects_stale_prover_input_material() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material();
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes();
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let assert_rejected_material =
        |case: &str, material: iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1| {
            assert!(
                iroha_crypto::validate_bfv_full_bootstrap_execution_prover_input_material_v1(
                    &material
                )
                .is_err(),
                "mutated BFV prover input material must fail validation: {case}"
            );
            assert!(
                !verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, &material)
                    .expect("verification attempt must complete for this semantic fixture"),
                "BFV native AIR verifier must reject {case}"
            );
            assert!(
                prove_stark_fri_bfv_full_bootstrap_air_envelope_bytes(&material).is_err(),
                "BFV native AIR prover must reject {case}"
            );
        };
    let mut stale_version = (*material).clone();
    stale_version.version = stale_version.version.saturating_add(1);
    assert_rejected_material("stale prover input material version", stale_version);
    let mut stale_field_count = (*material).clone();
    stale_field_count.field_count = stale_field_count.field_count.saturating_add(1);
    assert_rejected_material("stale prover input material field count", stale_field_count);
    let mut stale_proof_input_version = (*material).clone();
    stale_proof_input_version.proof_input_material.version = stale_proof_input_version
        .proof_input_material
        .version
        .saturating_add(1);
    assert_rejected_material(
        "stale proof-input material version",
        stale_proof_input_version,
    );
    let mut stale_trace_digest = (*material).clone();
    stale_trace_digest.arithmetic_trace_material_digest =
        iroha_crypto::Hash::new(b"stale BFV arithmetic trace material digest");
    assert_rejected_material("stale arithmetic trace material digest", stale_trace_digest);
    let mut stale_air_evaluation_digest = (*material).clone();
    stale_air_evaluation_digest.arithmetic_air_evaluation_material_digest =
        iroha_crypto::Hash::new(b"stale BFV arithmetic AIR evaluation material digest");
    assert_rejected_material(
        "stale arithmetic AIR evaluation material digest",
        stale_air_evaluation_digest,
    );
    let mut drifted_trace_rows = (*material).clone();
    drifted_trace_rows.arithmetic_trace_material.rows[0][0] ^= 0x01;
    assert_rejected_material("drifted arithmetic trace rows", drifted_trace_rows);
    let mut drifted_composition_values = (*material).clone();
    drifted_composition_values
        .arithmetic_air_evaluation_material
        .composition_values[0] ^= 0x01;
    assert_rejected_material(
        "drifted arithmetic AIR composition values",
        drifted_composition_values,
    );
    let mut stale_public_opening_digest = (*material).clone();
    stale_public_opening_digest.public_opening_material_digest =
        iroha_crypto::Hash::new(b"stale BFV public opening material digest");
    assert_rejected_material(
        "stale public opening material digest",
        stale_public_opening_digest,
    );
    let alternate_material = bfv_full_bootstrap_stark_test_prover_input_material_for_slot(1);
    let mut retargeted_public_opening_material = (*material).clone();
    retargeted_public_opening_material.public_opening_material =
        alternate_material.public_opening_material.clone();
    retargeted_public_opening_material.public_opening_material_digest =
        alternate_material.public_opening_material_digest;
    assert_rejected_material(
        "retargeted public opening material",
        retargeted_public_opening_material,
    );
    let mut swapped_proof_keys = (*material).clone();
    core::mem::swap(
        &mut swapped_proof_keys.prover_key,
        &mut swapped_proof_keys.verifier_key,
    );
    assert_rejected_material("swapped BFV native proof keys", swapped_proof_keys);
}
#[test]
fn bfv_full_bootstrap_air_rejects_valid_cross_statement_material_replay() {
    let material = bfv_full_bootstrap_stark_test_prover_input_material_for_slot(0);
    let alternate_material = bfv_full_bootstrap_stark_test_prover_input_material_for_slot(1);
    iroha_crypto::validate_bfv_full_bootstrap_execution_prover_input_material_v1(
        alternate_material,
    )
    .expect("alternate BFV prover material is internally valid");
    assert_ne!(
        material.proof_input_material.statement_hash,
        alternate_material.proof_input_material.statement_hash,
        "alternate slot must bind a distinct BFV statement hash"
    );
    assert_ne!(
        material.arithmetic_trace_material_digest,
        alternate_material.arithmetic_trace_material_digest,
        "alternate slot must bind distinct trace material"
    );
    assert_ne!(
        material.arithmetic_air_evaluation_material_digest,
        alternate_material.arithmetic_air_evaluation_material_digest,
        "alternate slot must bind distinct AIR evaluation material"
    );
    let bytes = bfv_full_bootstrap_stark_test_envelope_bytes_for_slot(0);
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, material)
            .expect("verification attempt must complete for this semantic fixture")
    );
    let alternate_bytes = bfv_full_bootstrap_stark_test_envelope_bytes_for_slot(1);
    assert!(
        verify_stark_fri_bfv_full_bootstrap_air_envelope(alternate_bytes, alternate_material,)
            .expect("verification attempt must complete for this semantic fixture")
    );
    assert_ne!(
        bytes, alternate_bytes,
        "statement-specific BFV native AIR envelopes must differ"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(bytes, alternate_material)
            .expect("verification attempt must complete for this semantic fixture"),
        "valid BFV native AIR envelope must not replay against another valid statement package"
    );
    assert!(
        !verify_stark_fri_bfv_full_bootstrap_air_envelope(alternate_bytes, material)
            .expect("verification attempt must complete for this semantic fixture"),
        "alternate BFV native AIR envelope must not replay against the original statement package"
    );
}
#[test]
fn synthesized_envelope_rejects_unsupported_fold_arity() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 4,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:invalid".to_owned(),
    };
    let err = synthesize_stark_fri_envelope_bytes(params, "IROHA-TEST-STARK".to_owned())
        .expect_err("unsupported fold_arity must fail");
    assert!(
        err.to_string().contains("fold_arity"),
        "error should mention fold_arity, got: {err}"
    );
}
#[test]
fn synthesized_envelope_rejects_blowup_larger_than_domain() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 5,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:invalid-blowup-domain".to_owned(),
    };
    let err = synthesize_stark_fri_envelope_bytes(params, "IROHA-TEST-STARK".to_owned())
        .expect_err("blowup_log2 larger than n_log2 must fail");
    assert!(
        err.to_string().contains("blowup factor"),
        "error should mention blowup factor, got: {err}"
    );
}
#[test]
fn synthesized_envelope_rejects_tampered_domain_tag() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:tamper".to_owned(),
    };
    let bytes = prove_stark_fri_air_envelope_bytes(
        params,
        "IROHA-TEST-STARK".to_owned(),
        "stark/fri/poseidon-x7-goldilocks-6x64-v1:tamper".to_owned(),
        test_digest(0x33),
    )
    .expect("ok");
    let mut envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(&bytes).expect("decode synthesized envelope");
    envelope.params.domain_tag.push_str(":mutated");
    let tampered = norito::to_bytes(&envelope).expect("encode mutated envelope");
    assert!(
        !verify_stark_fri_envelope(&tampered)
            .expect("verification attempt must complete for this semantic fixture")
    );
}
#[test]
fn synthesized_envelope_rejects_malformed_payload() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:malformed".to_owned(),
    };
    let mut bytes =
        synthesize_stark_fri_envelope_bytes(params, "IROHA-TEST-STARK".to_owned()).expect("ok");
    bytes.truncate(bytes.len().saturating_sub(1));
    assert!(
        !verify_stark_fri_envelope(&bytes)
            .expect("verification attempt must complete for this semantic fixture")
    );
}
